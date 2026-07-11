// SPDX-License-Identifier: Apache-2.0

//! Root-confined manifest discovery and deterministic nearest-package selection.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use crate::inventory::{InventoryFile, MtimeHint, SourceCandidate};
use crate::project::ProjectPath;
use crate::{Cancellation, Deadline, NeverCancelled, Result};

use super::{
    ManifestInput, ManifestOutcome, ManifestParserKind, PackageAssignmentSet, PackageDiagnostic,
    PackageDiagnosticKind, SourcePackageAssignment,
};

/// Fixed same-directory precedence. The first parseable manifest wins; a failed
/// nearer candidate never prevents evaluating a later candidate or ancestor.
const MANIFEST_NAMES: &[&str] = &["Cargo.toml", "package.json", "go.mod", "pyproject.toml"];

/// Discover relevant manifests and select the nearest successfully parsed one
/// for every admitted source. `root` must be a canonical absolute project root;
/// traversal is root-inclusive and never escapes it.
pub trait PackageSourcePath {
    fn package_source_path(&self) -> &ProjectPath;
}

impl PackageSourcePath for InventoryFile {
    fn package_source_path(&self) -> &ProjectPath {
        &self.path
    }
}

impl PackageSourcePath for SourceCandidate {
    fn package_source_path(&self) -> &ProjectPath {
        &self.path
    }
}

/// Package discovery requires source paths, not source bytes.
pub fn assign_packages<T: PackageSourcePath>(
    root: &Path,
    files: &[T],
    max_manifest_bytes: usize,
) -> PackageAssignmentSet {
    let deadline = Deadline::new(None);
    // This cannot fail for an unbounded, never-cancelled deadline.
    assign_packages_checked(root, files, max_manifest_bytes, &deadline, &NeverCancelled)
        .unwrap_or_else(|_| PackageAssignmentSet {
            manifests: Vec::new(),
            assignments: Vec::new(),
            diagnostics: Vec::new(),
        })
}

/// Checked package assignment. Deadline/cancellation failures abort assignment
/// rather than being represented as manifest diagnostics.
pub fn assign_packages_checked<T: PackageSourcePath>(
    root: &Path,
    files: &[T],
    max_manifest_bytes: usize,
    deadline: &Deadline,
    cancellation: &dyn Cancellation,
) -> Result<PackageAssignmentSet> {
    deadline.check(cancellation)?;
    let candidates = candidate_paths(root, files, deadline, cancellation)?;
    let mut manifests = BTreeMap::new();
    let mut diagnostics = Vec::new();

    for path in candidates {
        deadline.check(cancellation)?;
        let Ok(relative_path) = path.strip_prefix(root) else {
            continue;
        };
        let Ok(relative) = path_utf8(relative_path) else {
            continue;
        };
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(parser) = ManifestParserKind::for_name(name) else {
            continue;
        };
        // Ignore absent candidates, while retaining dangling symlinks as a
        // diagnostic rather than treating them as ordinary absence.
        if fs::symlink_metadata(&path).is_err() {
            continue;
        }

        let (content_hash, outcome) =
            match read_manifest(&path, max_manifest_bytes, deadline, cancellation)? {
                Ok(bytes) => {
                    let content_hash = Some(blake3::hash(&bytes).to_hex().to_string());
                    match String::from_utf8(bytes) {
                        Ok(text) => match code2graph::package::from_manifest(name, &text) {
                            Some(package) => (content_hash, ManifestOutcome::Parsed(package)),
                            None => (
                                content_hash,
                                ManifestOutcome::Failed(PackageDiagnosticKind::Unparseable),
                            ),
                        },
                        Err(_) => (
                            content_hash,
                            ManifestOutcome::Failed(PackageDiagnosticKind::InvalidUtf8),
                        ),
                    }
                }
                Err(kind) => (None, ManifestOutcome::Failed(kind)),
            };
        let input = ManifestInput {
            path: relative,
            content_hash,
            parser,
            outcome,
        };
        if let ManifestOutcome::Failed(kind) = &input.outcome {
            diagnostics.push(PackageDiagnostic {
                path: input.path.clone(),
                kind: kind.clone(),
            });
        }
        manifests.insert(input.path.clone(), input);
    }

    let manifests: Vec<_> = manifests.into_values().collect();
    diagnostics.sort_by(|left, right| {
        (left.path.as_str(), left.kind.tag()).cmp(&(right.path.as_str(), right.kind.tag()))
    });
    let mut assignments: Vec<_> = files
        .iter()
        .map(|file| select_package(file.package_source_path(), &manifests))
        .collect();
    assignments.sort_by(|left, right| left.source_path.cmp(&right.source_path));

    deadline.check(cancellation)?;
    Ok(PackageAssignmentSet {
        manifests,
        assignments,
        diagnostics,
    })
}

fn candidate_paths<T: PackageSourcePath>(
    root: &Path,
    files: &[T],
    deadline: &Deadline,
    cancellation: &dyn Cancellation,
) -> Result<BTreeSet<PathBuf>> {
    let mut candidates = BTreeSet::new();
    for file in files {
        deadline.check(cancellation)?;
        let mut directory = root
            .join(file.package_source_path().as_str())
            .parent()
            .map(Path::to_path_buf);
        while let Some(current) = directory {
            deadline.check(cancellation)?;
            if current.strip_prefix(root).is_err() {
                break;
            }
            for name in MANIFEST_NAMES {
                candidates.insert(current.join(name));
            }
            if current == root {
                break;
            }
            directory = current.parent().map(Path::to_path_buf);
        }
    }
    Ok(candidates)
}

fn select_package(
    source_path: &crate::project::ProjectPath,
    manifests: &[ManifestInput],
) -> SourcePackageAssignment {
    let mut directory = source_path
        .as_str()
        .rsplit_once('/')
        .map(|(directory, _)| directory);
    loop {
        let current_directory = directory.unwrap_or("");
        for name in MANIFEST_NAMES {
            let path = if current_directory.is_empty() {
                (*name).to_owned()
            } else {
                format!("{current_directory}/{name}")
            };
            if let Some(input) = manifests.iter().find(|input| input.path == path)
                && let ManifestOutcome::Parsed(package) = &input.outcome
            {
                return SourcePackageAssignment {
                    source_path: source_path.clone(),
                    manifest_path: Some(input.path.clone()),
                    package: Some(package.clone()),
                };
            }
        }
        if current_directory.is_empty() {
            break;
        }
        directory = current_directory.rsplit_once('/').map(|(parent, _)| parent);
    }
    SourcePackageAssignment {
        source_path: source_path.clone(),
        manifest_path: None,
        package: None,
    }
}

fn path_utf8(path: &Path) -> std::result::Result<String, ()> {
    let value = path.to_str().ok_or(())?;
    #[cfg(windows)]
    {
        Ok(value.replace('\\', "/"))
    }
    #[cfg(not(windows))]
    {
        Ok(value.to_owned())
    }
}

/// Reads exactly one regular, non-symlink manifest up to `limit` bytes.
/// Metadata from the pathname and open handle must agree before and after the
/// read, preventing a replaced path or a symlink race from being accepted.
fn read_manifest(
    path: &Path,
    limit: usize,
    deadline: &Deadline,
    cancellation: &dyn Cancellation,
) -> Result<std::result::Result<Vec<u8>, PackageDiagnosticKind>> {
    deadline.check(cancellation)?;
    let path_before_metadata = match fs::symlink_metadata(path) {
        Ok(value) => value,
        Err(error) => return Ok(Err(read_error(error))),
    };
    if path_before_metadata.file_type().is_symlink() {
        return Ok(Err(PackageDiagnosticKind::Symlink));
    }
    if !path_before_metadata.is_file() {
        return Ok(Err(PackageDiagnosticKind::NotRegularFile));
    }
    if path_before_metadata.len() > limit as u64 {
        return Ok(Err(PackageDiagnosticKind::TooLarge { limit }));
    }
    let path_before = FileFingerprint::from_metadata(&path_before_metadata);
    deadline.check(cancellation)?;
    let mut file = match File::open(path) {
        Ok(value) => value,
        Err(error) => return Ok(Err(read_error(error))),
    };
    let handle_before_metadata = match file.metadata() {
        Ok(value) => value,
        Err(error) => return Ok(Err(read_error(error))),
    };
    if !handle_before_metadata.is_file()
        || FileFingerprint::from_metadata(&handle_before_metadata) != path_before
    {
        return Ok(Err(PackageDiagnosticKind::ChangedDuringRead));
    }
    let mut bytes = Vec::with_capacity(limit.saturating_add(1).min(65_536));
    if let Err(kind) = read_at_most(&mut file, limit, &mut bytes, deadline, cancellation)? {
        return Ok(Err(kind));
    }
    if bytes.len() > limit {
        return Ok(Err(PackageDiagnosticKind::TooLarge { limit }));
    }
    deadline.check(cancellation)?;
    let handle_after_metadata = match file.metadata() {
        Ok(value) => value,
        Err(error) => return Ok(Err(read_error(error))),
    };
    let path_after_metadata = match fs::symlink_metadata(path) {
        Ok(value) => value,
        Err(error) => return Ok(Err(read_error(error))),
    };
    if path_after_metadata.file_type().is_symlink()
        || !path_after_metadata.is_file()
        || FileFingerprint::from_metadata(&handle_before_metadata)
            != FileFingerprint::from_metadata(&handle_after_metadata)
        || FileFingerprint::from_metadata(&handle_after_metadata)
            != FileFingerprint::from_metadata(&path_after_metadata)
    {
        return Ok(Err(PackageDiagnosticKind::ChangedDuringRead));
    }
    Ok(Ok(bytes))
}

fn read_at_most(
    file: &mut File,
    limit: usize,
    bytes: &mut Vec<u8>,
    deadline: &Deadline,
    cancellation: &dyn Cancellation,
) -> Result<std::result::Result<(), PackageDiagnosticKind>> {
    let mut buffer = [0; 8192];
    loop {
        deadline.check(cancellation)?;
        let remaining = limit.saturating_add(1).saturating_sub(bytes.len());
        if remaining == 0 {
            break;
        }
        let chunk_len = buffer.len().min(remaining);
        let read = match file.read(&mut buffer[..chunk_len]) {
            Ok(read) => read,
            Err(error) => return Ok(Err(read_error(error))),
        };
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    Ok(Ok(()))
}

fn read_error(error: std::io::Error) -> PackageDiagnosticKind {
    PackageDiagnosticKind::ReadError {
        kind: error.kind().into(),
    }
}

#[derive(PartialEq, Eq)]
struct FileFingerprint {
    length: u64,
    mtime: Option<MtimeHint>,
    identity: Option<(u64, u64)>,
}

impl FileFingerprint {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            length: metadata.len(),
            mtime: mtime(metadata),
            identity: identity(metadata),
        }
    }
}

fn mtime(metadata: &Metadata) -> Option<MtimeHint> {
    let modified = metadata.modified().ok()?;
    match modified.duration_since(UNIX_EPOCH) {
        Ok(duration) => Some(MtimeHint {
            seconds_since_unix_epoch: i64::try_from(duration.as_secs()).ok()?,
            nanoseconds: duration.subsec_nanos(),
        }),
        Err(error) => {
            let duration = error.duration();
            let seconds = i64::try_from(duration.as_secs()).ok()?;
            if duration.subsec_nanos() == 0 {
                Some(MtimeHint {
                    seconds_since_unix_epoch: seconds.checked_neg()?,
                    nanoseconds: 0,
                })
            } else {
                Some(MtimeHint {
                    seconds_since_unix_epoch: seconds.checked_neg()?.checked_sub(1)?,
                    nanoseconds: 1_000_000_000 - duration.subsec_nanos(),
                })
            }
        }
    }
}

#[cfg(unix)]
fn identity(metadata: &Metadata) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    Some((metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
fn identity(_: &Metadata) -> Option<(u64, u64)> {
    None
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use code2graph::Language;
    use tempfile::tempdir;

    use super::*;

    fn file(path: &str) -> InventoryFile {
        InventoryFile {
            path: crate::project::ProjectPath::new(Path::new(path)).expect("path"),
            language: Language::Rust,
            bytes: vec![],
            text: String::new(),
            blake3: String::new(),
            mtime: None,
        }
    }

    fn assign(root: &Path, paths: &[&str]) -> PackageAssignmentSet {
        assign_packages(
            root,
            &paths.iter().map(|path| file(path)).collect::<Vec<_>>(),
            1024,
        )
    }

    #[test]
    fn selects_nearest_parseable_ancestor_with_fixed_same_directory_precedence() {
        let temp = tempdir().expect("temp");
        let root = temp.path();
        fs::create_dir_all(root.join("crates/a/src")).expect("dirs");
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname='root'\nversion='1'",
        )
        .expect("root");
        fs::write(root.join("crates/a/Cargo.toml"), "not = [toml").expect("bad cargo");
        fs::write(
            root.join("crates/a/package.json"),
            "{\"name\":\"npm\",\"version\":\"1\"}",
        )
        .expect("npm");
        fs::write(root.join("crates/a/go.mod"), "module example/go").expect("go");
        fs::write(
            root.join("crates/a/pyproject.toml"),
            "[project]\nname='pypi'",
        )
        .expect("pypi");

        let set = assign(root, &["crates/a/src/lib.rs", "other.rs"]);
        assert_eq!(
            set.assignments[0].manifest_path.as_deref(),
            Some("crates/a/package.json")
        );
        assert_eq!(
            set.assignments[0]
                .package
                .as_ref()
                .map(|value| value.name.as_str()),
            Some("npm")
        );
        assert_eq!(
            set.assignments[1].manifest_path.as_deref(),
            Some("Cargo.toml")
        );
        assert!(
            set.diagnostics
                .iter()
                .any(|item| item.path == "crates/a/Cargo.toml"
                    && item.kind == PackageDiagnosticKind::Unparseable)
        );

        fs::write(
            root.join("crates/a/Cargo.toml"),
            "[package]\nname='cargo'\nversion='1'",
        )
        .expect("cargo");
        let set = assign(root, &["crates/a/src/lib.rs"]);
        assert_eq!(
            set.assignments[0].manifest_path.as_deref(),
            Some("crates/a/Cargo.toml")
        );
    }

    #[test]
    fn metadata_candidates_and_materialized_files_have_identical_path_assignment() {
        let temp = tempdir().expect("temp");
        let root = temp.path();
        fs::create_dir_all(root.join("crate/src")).expect("dirs");
        fs::write(root.join("crate/Cargo.toml"), "[package]\nname='crate'").expect("manifest");
        let source_path =
            crate::project::ProjectPath::new(Path::new("crate/src/lib.rs")).expect("source path");
        let candidate = SourceCandidate {
            path: source_path,
            language: Some(Language::Rust),
            classification: crate::inventory::FileClassification::Enabled(Language::Rust),
            size_bytes: 999,
            mtime: None,
            identity: crate::inventory::StableIdentity {
                device: None,
                inode: None,
            },
            absolute_path: root.join("crate/src/lib.rs"),
        };
        let from_candidate = assign_packages(root, &[candidate], 1024);
        let from_file = assign(root, &["crate/src/lib.rs"]);
        assert_eq!(from_candidate.assignments, from_file.assignments);
        assert_eq!(from_candidate.manifests, from_file.manifests);
        assert_eq!(from_candidate.diagnostics, from_file.diagnostics);
    }

    #[test]
    fn unparseable_nearer_manifest_falls_back_to_a_parseable_ancestor() {
        let temp = tempdir().expect("temp");
        let root = temp.path();
        fs::create_dir_all(root.join("bad/src")).expect("dirs");
        fs::write(root.join("Cargo.toml"), "[package]\nname='root'").expect("root");
        fs::write(root.join("bad/Cargo.toml"), "not = [toml").expect("bad");

        let set = assign(root, &["bad/src/lib.rs"]);
        assert_eq!(
            set.assignments[0].manifest_path.as_deref(),
            Some("Cargo.toml")
        );
        assert_eq!(
            set.assignments[0]
                .package
                .as_ref()
                .map(|package| package.name.as_str()),
            Some("root")
        );
        assert!(set.diagnostics.iter().any(|diagnostic| {
            diagnostic.path == "bad/Cargo.toml"
                && diagnostic.kind == PackageDiagnosticKind::Unparseable
        }));
    }

    #[test]
    fn records_no_package_and_keeps_discovery_root_confined() {
        let temp = tempdir().expect("temp");
        let root = temp.path();
        let empty = assign(root, &["none.rs"]);
        assert!(empty.assignments[0].package.is_none());
        assert!(empty.manifests.is_empty());

        let candidates = candidate_paths(
            root,
            &[file("nested/file.rs")],
            &Deadline::new(None),
            &NeverCancelled,
        )
        .expect("candidate paths");
        assert!(
            candidates
                .iter()
                .all(|candidate| candidate.strip_prefix(root).is_ok())
        );
        assert!(candidates.contains(&root.join("Cargo.toml")));
    }

    #[test]
    fn fingerprints_include_parsed_content_failure_outcomes_and_assignments_deterministically() {
        let temp = tempdir().expect("temp");
        let root = temp.path();
        fs::write(root.join("Cargo.toml"), "[package]\nname='a'").expect("manifest");
        let first = assign(root, &["a.rs", "b.rs"]);
        let reordered = assign(root, &["b.rs", "a.rs"]);
        let first_fingerprint = crate::cache::PackageFingerprint::from_selection(
            first.manifest_fingerprint_records(),
            first.assignment_fingerprint_records(),
        );
        let reordered_fingerprint = crate::cache::PackageFingerprint::from_selection(
            reordered.manifest_fingerprint_records(),
            reordered.assignment_fingerprint_records(),
        );
        assert_eq!(first_fingerprint, reordered_fingerprint);

        fs::write(root.join("Cargo.toml"), "[package]\nname='b'").expect("manifest");
        let changed = assign(root, &["a.rs", "b.rs"]);
        let changed_fingerprint = crate::cache::PackageFingerprint::from_selection(
            changed.manifest_fingerprint_records(),
            changed.assignment_fingerprint_records(),
        );
        assert_ne!(first_fingerprint, changed_fingerprint);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_invalid_utf8_and_oversize_manifests_are_diagnostics() {
        use std::os::unix::fs::symlink;

        let temp = tempdir().expect("temp");
        let root = temp.path();
        fs::create_dir_all(root.join("src")).expect("dirs");
        fs::write(root.join("package.json"), [0xff]).expect("utf8");
        fs::write(root.join("go.mod"), "x".repeat(20)).expect("large");
        symlink("package.json", root.join("Cargo.toml")).expect("symlink");
        let set = assign_packages(root, &[file("src/lib.rs")], 10);
        assert!(
            set.diagnostics
                .iter()
                .any(|item| item.kind == PackageDiagnosticKind::Symlink)
        );
        assert!(
            set.diagnostics
                .iter()
                .any(|item| item.kind == PackageDiagnosticKind::InvalidUtf8)
        );
        assert!(
            set.diagnostics
                .iter()
                .any(|item| matches!(item.kind, PackageDiagnosticKind::TooLarge { .. }))
        );
    }
}
