// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::path::Path;
use std::time::UNIX_EPOCH;

use code2graph::{Language, LanguageAvailability};
use ignore::WalkBuilder;

use super::{
    FileClassification, InventoryCompleteness, InventoryFile, InventorySummary,
    MaterializedCandidate, MtimeHint, OmissionReason, OmittedFile, SourceCandidate,
    SourceDiscovery, SourceInventory, StableIdentity, StableIoErrorKind,
};
use crate::config::ResourceLimits;
use crate::error::Result;
use crate::project::{ProjectPath, ProjectSelection};
use crate::{Cancellation, Deadline, NeverCancelled};

const HARD: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "target",
    "dist",
    "build",
    "coverage",
    ".next",
    ".nuxt",
    ".svelte-kit",
    ".venv",
    "venv",
    "__pycache__",
];

/// Discovers source candidates from metadata only. It never opens, reads, or hashes a file.
pub fn discover_sources(
    selection: &ProjectSelection,
    limits: &ResourceLimits,
    include_hidden: bool,
) -> Result<SourceDiscovery> {
    let deadline = Deadline::new(None);
    discover_sources_checked(
        selection,
        limits,
        include_hidden,
        &deadline,
        &NeverCancelled,
    )
}

/// Checked variant of [`discover_sources`]. Cancellation and deadline expiry
/// abort discovery rather than being recorded as filesystem omissions.
pub fn discover_sources_checked(
    selection: &ProjectSelection,
    limits: &ResourceLimits,
    include_hidden: bool,
    deadline: &Deadline,
    cancellation: &dyn Cancellation,
) -> Result<SourceDiscovery> {
    deadline.check(cancellation)?;
    let root = &selection.canonical_root;
    let mut builder = WalkBuilder::new(root);
    builder
        .hidden(!include_hidden)
        .git_ignore(true)
        .ignore(true)
        .git_global(false)
        .git_exclude(false)
        .follow_links(false)
        .max_depth(Some(limits.max_depth as usize));
    builder.filter_entry(|entry| {
        !entry.file_type().is_some_and(|kind| kind.is_dir())
            || !entry
                .path()
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| HARD.contains(&name))
    });
    let mut candidates = Vec::new();
    let mut omitted = Vec::new();
    for result in builder.build() {
        deadline.check(cancellation)?;
        let entry = match result {
            Ok(entry) => entry,
            Err(error) => {
                if let Some(path) = error_path(&error)
                    .and_then(|path| path.strip_prefix(root).ok())
                    .and_then(|path| ProjectPath::new(path).ok())
                {
                    omitted.push(OmittedFile::traversal_directory(
                        path,
                        OmissionReason::ReadError {
                            kind: error
                                .io_error()
                                .map_or(StableIoErrorKind::Other, |error| error.kind().into()),
                        },
                    ));
                }
                continue;
            }
        };
        if entry.depth() == 0 {
            continue;
        }
        let Ok(relative) = entry.path().strip_prefix(root) else {
            continue;
        };
        let path = ProjectPath::new(relative)?;
        if matches!(
            path.as_str().rsplit('/').next(),
            Some(".gitignore" | ".ignore")
        ) {
            continue;
        }
        if !include_hidden
            && path
                .as_str()
                .split('/')
                .any(|component| component.starts_with('.'))
        {
            continue;
        }
        let metadata = match fs::symlink_metadata(entry.path()) {
            Ok(value) => value,
            Err(error) => {
                omitted.push(OmittedFile::new(
                    path,
                    OmissionReason::ReadError {
                        kind: error.kind().into(),
                    },
                ));
                continue;
            }
        };
        if metadata.file_type().is_symlink() {
            omitted.push(OmittedFile::new(
                path,
                if fs::metadata(entry.path()).is_ok_and(|m| m.is_dir()) {
                    OmissionReason::SymlinkDirectory
                } else {
                    OmissionReason::SymlinkFile
                },
            ));
        } else if !metadata.is_dir() && !metadata.is_file() {
            omitted.push(OmittedFile::new(path, OmissionReason::NotRegularFile));
        } else if metadata.is_file() {
            let classification = classify(&path);
            candidates.push(SourceCandidate {
                language: match classification {
                    FileClassification::Enabled(language) => Some(language),
                    _ => None,
                },
                classification,
                size_bytes: metadata.len(),
                mtime: mtime(&metadata),
                identity: identity(&metadata),
                path,
                absolute_path: entry.into_path(),
            });
        }
    }
    candidates.sort_by(|left, right| left.path.cmp(&right.path));
    sort_omissions(&mut omitted);
    Ok(SourceDiscovery {
        candidates,
        omitted,
    })
}

/// Materializes one metadata candidate using bounded reads and pre/post replacement checks.
pub fn materialize_candidate(
    candidate: &SourceCandidate,
    limits: &ResourceLimits,
) -> MaterializedCandidate {
    // An unbounded, never-cancelled wrapper preserves the historical API.
    materialize_candidate_unchecked(candidate, limits)
}

/// Checked variant of [`materialize_candidate`]. Timeout and cancellation are
/// returned to the caller and are never converted to omissions.
pub fn materialize_candidate_checked(
    candidate: &SourceCandidate,
    limits: &ResourceLimits,
    deadline: &Deadline,
    cancellation: &dyn Cancellation,
) -> Result<MaterializedCandidate> {
    deadline.check(cancellation)?;
    let result = materialize_candidate_inner(candidate, limits, Some((deadline, cancellation)))?;
    deadline.check(cancellation)?;
    Ok(result)
}

fn materialize_candidate_unchecked(
    candidate: &SourceCandidate,
    limits: &ResourceLimits,
) -> MaterializedCandidate {
    // The legacy API intentionally has no cancellation source.
    materialize_candidate_inner(candidate, limits, None)
        .expect("unchecked materialization cannot fail")
}

fn materialize_candidate_inner(
    candidate: &SourceCandidate,
    limits: &ResourceLimits,
    checked: Option<(&Deadline, &dyn Cancellation)>,
) -> Result<MaterializedCandidate> {
    let Some(language) = candidate.language else {
        return Ok(MaterializedCandidate::Omitted(OmittedFile::new(
            candidate.path.clone(),
            classification_omission(candidate.classification),
        )));
    };
    let read = match checked {
        Some((deadline, cancellation)) => {
            read_bounded_checked(candidate, limits.max_file_bytes, deadline, cancellation)?
        }
        None => read_bounded(candidate, limits.max_file_bytes),
    };
    Ok(match read {
        Ok((bytes, fingerprint)) => match String::from_utf8(bytes.clone()) {
            Ok(text) => MaterializedCandidate::File(InventoryFile {
                path: candidate.path.clone(),
                language,
                blake3: blake3::hash(&bytes).to_hex().to_string(),
                bytes,
                text,
                mtime: fingerprint.mtime,
            }),
            Err(_) => MaterializedCandidate::Omitted(OmittedFile::new(
                candidate.path.clone(),
                OmissionReason::InvalidUtf8,
            )),
        },
        Err(Failure::TooLarge) => MaterializedCandidate::Omitted(OmittedFile::new(
            candidate.path.clone(),
            OmissionReason::FileTooLarge {
                limit: limits.max_file_bytes,
            },
        )),
        Err(Failure::Changed) => MaterializedCandidate::Omitted(OmittedFile::new(
            candidate.path.clone(),
            OmissionReason::ChangedDuringRead,
        )),
        Err(Failure::Io(kind)) => MaterializedCandidate::Omitted(OmittedFile::new(
            candidate.path.clone(),
            OmissionReason::ReadError { kind },
        )),
    })
}

/// Builds the historical full inventory by composing metadata discovery and materialization.
pub fn build_inventory(
    selection: &ProjectSelection,
    limits: &ResourceLimits,
    include_hidden: bool,
) -> Result<SourceInventory> {
    let discovery = discover_sources(selection, limits, include_hidden)?;
    let mut files = Vec::new();
    let mut omitted = discovery.omitted;
    let mut total = 0usize;
    for candidate in discovery.candidates {
        if candidate.language.is_none() {
            omitted.push(OmittedFile::new(
                candidate.path,
                classification_omission(candidate.classification),
            ));
            continue;
        }
        if files.len() >= limits.max_files {
            omitted.push(OmittedFile::new(
                candidate.path,
                OmissionReason::FileCountLimit {
                    limit: limits.max_files,
                },
            ));
            continue;
        }
        match materialize_candidate(&candidate, limits) {
            MaterializedCandidate::File(file)
                if file.bytes.len() <= limits.max_total_bytes.saturating_sub(total) =>
            {
                total += file.bytes.len();
                files.push(file);
            }
            MaterializedCandidate::File(file) => omitted.push(OmittedFile::new(
                file.path,
                OmissionReason::TotalBytesLimit {
                    limit: limits.max_total_bytes,
                },
            )),
            MaterializedCandidate::Omitted(omission) => omitted.push(omission),
        }
    }
    sort_omissions(&mut omitted);
    let mut counts = BTreeMap::new();
    for item in &omitted {
        let entry = counts
            .entry(item.reason.tag())
            .or_insert((item.reason.clone(), 0usize));
        entry.1 += 1;
    }
    Ok(SourceInventory {
        completeness: if omitted
            .iter()
            .any(|omission| omission.impact == super::OmissionImpact::IncompleteSourceSet)
        {
            InventoryCompleteness::Partial
        } else {
            InventoryCompleteness::Complete
        },
        summary: InventorySummary {
            admitted_files: files.len(),
            admitted_bytes: total,
            omitted_files: omitted.len(),
            omission_reasons: counts.into_values().collect(),
        },
        files,
        omitted,
    })
}

fn sort_omissions(omitted: &mut [OmittedFile]) {
    omitted.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then_with(|| a.reason.tag().cmp(&b.reason.tag()))
    });
}
fn classify(path: &ProjectPath) -> FileClassification {
    match Language::from_path(path.as_str()) {
        Some(language) if language.availability() == LanguageAvailability::Enabled => {
            FileClassification::Enabled(language)
        }
        Some(language) => FileClassification::FeatureDisabled(language),
        None => FileClassification::UnrecognizedExtension,
    }
}

fn classification_omission(classification: FileClassification) -> OmissionReason {
    match classification {
        FileClassification::FeatureDisabled(language) => {
            OmissionReason::FeatureDisabled { language }
        }
        FileClassification::UnrecognizedExtension | FileClassification::Enabled(_) => {
            OmissionReason::UnrecognizedExtension
        }
    }
}
fn error_path(error: &ignore::Error) -> Option<&Path> {
    match error {
        ignore::Error::WithPath { path, .. } => Some(path.as_path()),
        ignore::Error::WithLineNumber { err, .. } | ignore::Error::WithDepth { err, .. } => {
            error_path(err)
        }
        ignore::Error::Partial(errors) => errors.iter().find_map(error_path),
        ignore::Error::Loop { child, .. } => Some(child.as_path()),
        _ => None,
    }
}
#[derive(PartialEq, Eq)]
struct Fingerprint {
    length: u64,
    mtime: Option<MtimeHint>,
    identity: StableIdentity,
}
impl Fingerprint {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            length: metadata.len(),
            mtime: mtime(metadata),
            identity: identity(metadata),
        }
    }
}
enum Failure {
    TooLarge,
    Changed,
    Io(StableIoErrorKind),
}
fn read_bounded(
    candidate: &SourceCandidate,
    limit: usize,
) -> std::result::Result<(Vec<u8>, Fingerprint), Failure> {
    read_bounded_inner(candidate, limit, None).expect("unchecked bounded read cannot be cancelled")
}

fn read_bounded_checked(
    candidate: &SourceCandidate,
    limit: usize,
    deadline: &Deadline,
    cancellation: &dyn Cancellation,
) -> Result<std::result::Result<(Vec<u8>, Fingerprint), Failure>> {
    read_bounded_inner(candidate, limit, Some((deadline, cancellation)))
}

fn read_bounded_inner(
    candidate: &SourceCandidate,
    limit: usize,
    checked: Option<(&Deadline, &dyn Cancellation)>,
) -> Result<std::result::Result<(Vec<u8>, Fingerprint), Failure>> {
    let check = || -> Result<()> {
        if let Some((deadline, cancellation)) = checked {
            deadline.check(cancellation)?;
        }
        Ok(())
    };
    check()?;
    let path = &candidate.absolute_path;
    let path_before_meta = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => return Ok(Err(io_fail(error))),
    };
    if path_before_meta.file_type().is_symlink() || !path_before_meta.is_file() {
        return Ok(Err(Failure::Changed));
    }
    let path_before = Fingerprint::from_metadata(&path_before_meta);
    let discovered = Fingerprint {
        length: candidate.size_bytes,
        mtime: candidate.mtime,
        identity: candidate.identity.clone(),
    };
    if path_before != discovered {
        return Ok(Err(Failure::Changed));
    }
    if path_before.length > limit as u64 {
        return Ok(Err(Failure::TooLarge));
    }
    check()?;
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) => return Ok(Err(io_fail(error))),
    };
    let handle_before_meta = match file.metadata() {
        Ok(metadata) => metadata,
        Err(error) => return Ok(Err(io_fail(error))),
    };
    if !handle_before_meta.is_file() {
        return Ok(Err(Failure::Changed));
    }
    let handle_before = Fingerprint::from_metadata(&handle_before_meta);
    if path_before != handle_before {
        return Ok(Err(Failure::Changed));
    }
    let mut bytes = Vec::with_capacity(limit.saturating_add(1).min(65536));
    let mut buffer = [0; 8192];
    loop {
        check()?;
        let remaining = limit.saturating_add(1).saturating_sub(bytes.len());
        if remaining == 0 {
            return Ok(Err(Failure::TooLarge));
        }
        let chunk_len = buffer.len().min(remaining);
        let count = match file.read(&mut buffer[..chunk_len]) {
            Ok(count) => count,
            Err(error) => return Ok(Err(io_fail(error))),
        };
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    if bytes.len() > limit {
        return Ok(Err(Failure::TooLarge));
    }
    check()?;
    let handle_after_metadata = match file.metadata() {
        Ok(metadata) => metadata,
        Err(error) => return Ok(Err(io_fail(error))),
    };
    let path_after_meta = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => return Ok(Err(io_fail(error))),
    };
    if path_after_meta.file_type().is_symlink()
        || !path_after_meta.is_file()
        || handle_before != Fingerprint::from_metadata(&handle_after_metadata)
        || Fingerprint::from_metadata(&handle_after_metadata)
            != Fingerprint::from_metadata(&path_after_meta)
    {
        return Ok(Err(Failure::Changed));
    }
    Ok(Ok((bytes, handle_before)))
}
fn io_fail(error: io::Error) -> Failure {
    Failure::Io(error.kind().into())
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
            Some(if duration.subsec_nanos() == 0 {
                MtimeHint {
                    seconds_since_unix_epoch: seconds.checked_neg()?,
                    nanoseconds: 0,
                }
            } else {
                MtimeHint {
                    seconds_since_unix_epoch: seconds.checked_neg()?.checked_sub(1)?,
                    nanoseconds: 1_000_000_000 - duration.subsec_nanos(),
                }
            })
        }
    }
}
#[cfg(unix)]
fn identity(metadata: &Metadata) -> StableIdentity {
    use std::os::unix::fs::MetadataExt;
    StableIdentity {
        device: Some(metadata.dev()),
        inode: Some(metadata.ino()),
    }
}
#[cfg(not(unix))]
fn identity(_: &Metadata) -> StableIdentity {
    StableIdentity {
        device: None,
        inode: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ResourceLimits;
    use crate::project::{ProjectSelection, SelectionProvenance};
    use std::fs;
    use tempfile::tempdir;

    fn selection(root: &Path) -> ProjectSelection {
        ProjectSelection {
            canonical_root: fs::canonicalize(root).expect("root"),
            canonical_source: None,
            provenance: SelectionProvenance::RootArgument,
        }
    }

    fn discover(root: &Path, limits: &ResourceLimits, hidden: bool) -> SourceDiscovery {
        discover_sources(&selection(root), limits, hidden).expect("discover")
    }

    fn inventory(root: &Path, limits: &ResourceLimits) -> SourceInventory {
        build_inventory(&selection(root), limits, false).expect("inventory")
    }

    fn paths(discovery: &SourceDiscovery) -> Vec<&str> {
        discovery
            .candidates
            .iter()
            .map(|candidate| candidate.path.as_str())
            .collect()
    }

    #[test]
    fn discovery_is_sorted_metadata_only_and_materialization_is_exact() {
        let directory = tempdir().expect("directory");
        fs::write(directory.path().join("z.rs"), b"z").expect("write");
        fs::write(directory.path().join("a.rs"), [0xff]).expect("write");
        let discovered = discover(directory.path(), &ResourceLimits::default(), false);
        assert_eq!(paths(&discovered), ["a.rs", "z.rs"]);
        assert!(discovered.omitted.is_empty());
        assert_eq!(discovered.candidates[0].size_bytes, 1);
        assert!(discovered.candidates[0].mtime.is_some());
        assert!(matches!(
            materialize_candidate(&discovered.candidates[0], &ResourceLimits::default()),
            MaterializedCandidate::Omitted(OmittedFile {
                reason: OmissionReason::InvalidUtf8,
                ..
            })
        ));
        let MaterializedCandidate::File(file) =
            materialize_candidate(&discovered.candidates[1], &ResourceLimits::default())
        else {
            panic!("valid source must materialize");
        };
        assert_eq!(file.bytes, b"z");
        assert_eq!(file.text, "z");
        assert_eq!(file.blake3, blake3::hash(b"z").to_hex().to_string());
        assert_eq!(file.mtime, discovered.candidates[1].mtime);
    }

    #[test]
    fn gitignore_ignore_negation_hidden_and_hard_directories_are_deterministic() {
        let directory = tempdir().expect("directory");
        fs::write(directory.path().join(".gitignore"), "git.rs\n").expect("gitignore");
        fs::write(
            directory.path().join(".ignore"),
            "*.rs\n!keep.rs\n!.hidden.rs\n",
        )
        .expect("ignore");
        for name in ["git.rs", "drop.rs", "keep.rs", ".hidden.rs"] {
            fs::write(directory.path().join(name), name).expect("source");
        }
        for hard in HARD {
            let path = directory.path().join(hard);
            fs::create_dir_all(&path).expect("hard directory");
            fs::write(path.join("inside.rs"), "x").expect("hard source");
        }
        assert_eq!(
            paths(&discover(
                directory.path(),
                &ResourceLimits::default(),
                false
            )),
            ["keep.rs"]
        );
        assert_eq!(
            paths(&discover(
                directory.path(),
                &ResourceLimits::default(),
                true
            )),
            [".hidden.rs", "keep.rs"]
        );
    }

    #[test]
    fn depth_limit_is_applied_from_the_project_root() {
        let directory = tempdir().expect("directory");
        fs::create_dir_all(directory.path().join("one/two")).expect("dirs");
        fs::write(directory.path().join("root.rs"), "r").expect("root file");
        fs::write(directory.path().join("one/nested.rs"), "n").expect("nested file");
        fs::write(directory.path().join("one/two/deep.rs"), "d").expect("deep file");
        let limits = ResourceLimits {
            max_depth: 1,
            ..ResourceLimits::default()
        };
        assert_eq!(
            paths(&discover(directory.path(), &limits, false)),
            ["root.rs"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_files_and_directories_are_omitted_without_following() {
        use std::os::unix::fs::symlink;
        let directory = tempdir().expect("directory");
        fs::write(directory.path().join("real.rs"), "x").expect("file");
        fs::create_dir(directory.path().join("real_dir")).expect("dir");
        symlink("real.rs", directory.path().join("linked.rs")).expect("file link");
        symlink("real_dir", directory.path().join("linked_dir")).expect("dir link");
        let discovered = discover(directory.path(), &ResourceLimits::default(), false);
        assert_eq!(paths(&discovered), ["real.rs"]);
        assert!(discovered.omitted.iter().any(|item| {
            item.path.as_str() == "linked.rs" && item.reason == OmissionReason::SymlinkFile
        }));
        assert!(discovered.omitted.iter().any(|item| {
            item.path.as_str() == "linked_dir" && item.reason == OmissionReason::SymlinkDirectory
        }));
    }

    #[test]
    fn classifications_cover_enabled_disabled_and_unknown_extensions() {
        let directory = tempdir().expect("directory");
        for language in Language::ALL {
            fs::write(
                directory
                    .path()
                    .join(format!("source.{}", language.extensions()[0])),
                "x",
            )
            .expect("source");
        }
        fs::write(directory.path().join("README.unknown"), "x").expect("unknown");
        let discovered = discover(directory.path(), &ResourceLimits::default(), false);
        for candidate in &discovered.candidates {
            let expected = match Language::from_path(candidate.path.as_str()) {
                Some(language) if language.availability() == LanguageAvailability::Enabled => {
                    FileClassification::Enabled(language)
                }
                Some(language) => FileClassification::FeatureDisabled(language),
                None => FileClassification::UnrecognizedExtension,
            };
            assert_eq!(candidate.classification, expected, "{}", candidate.path);
            assert_eq!(
                candidate.language,
                match expected {
                    FileClassification::Enabled(language) => Some(language),
                    _ => None,
                }
            );
        }
    }

    #[test]
    fn per_file_total_and_count_budgets_preserve_stable_reasons() {
        let directory = tempdir().expect("directory");
        fs::write(directory.path().join("a.rs"), "1234").expect("a");
        fs::write(directory.path().join("b.rs"), "12").expect("b");
        fs::write(directory.path().join("c.txt"), "ignored").expect("c");
        let per_file = inventory(
            directory.path(),
            &ResourceLimits {
                max_file_bytes: 3,
                ..ResourceLimits::default()
            },
        );
        assert_eq!(per_file.files[0].path.as_str(), "b.rs");
        assert!(matches!(
            per_file.omitted[0].reason,
            OmissionReason::FileTooLarge { limit: 3 }
        ));

        let aggregate = inventory(
            directory.path(),
            &ResourceLimits {
                max_total_bytes: 4,
                ..ResourceLimits::default()
            },
        );
        assert_eq!(aggregate.files[0].path.as_str(), "a.rs");
        assert!(
            aggregate
                .omitted
                .iter()
                .any(|item| matches!(item.reason, OmissionReason::TotalBytesLimit { limit: 4 }))
        );

        let count = inventory(
            directory.path(),
            &ResourceLimits {
                max_files: 0,
                ..ResourceLimits::default()
            },
        );
        assert!(count.omitted.iter().any(|item| {
            item.path.as_str() == "c.txt" && item.reason == OmissionReason::UnrecognizedExtension
        }));
        assert_eq!(
            count
                .omitted
                .iter()
                .filter(|item| matches!(item.reason, OmissionReason::FileCountLimit { limit: 0 }))
                .count(),
            2
        );
    }

    #[test]
    fn bounded_read_accepts_exact_limit_and_rejects_one_byte_more() {
        let directory = tempdir().expect("directory");
        fs::write(directory.path().join("exact.rs"), vec![b'x'; 8192]).expect("exact");
        fs::write(directory.path().join("over.rs"), vec![b'x'; 8193]).expect("over");
        let result = inventory(
            directory.path(),
            &ResourceLimits {
                max_file_bytes: 8192,
                ..ResourceLimits::default()
            },
        );
        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].path.as_str(), "exact.rs");
        assert_eq!(result.files[0].bytes.len(), 8192);
        assert!(result.omitted.iter().any(|item| {
            item.path.as_str() == "over.rs"
                && item.reason == OmissionReason::FileTooLarge { limit: 8192 }
        }));
    }

    #[test]
    fn replacement_since_discovery_and_read_errors_are_not_admitted() {
        let directory = tempdir().expect("directory");
        let changed = directory.path().join("changed.rs");
        let deleted = directory.path().join("deleted.rs");
        fs::write(&changed, "old").expect("changed");
        fs::write(&deleted, "old").expect("deleted");
        let discovered = discover(directory.path(), &ResourceLimits::default(), false);
        fs::write(&changed, "replacement with another size").expect("replace");
        fs::remove_file(&deleted).expect("delete");
        let changed = discovered
            .candidates
            .iter()
            .find(|candidate| candidate.path.as_str() == "changed.rs")
            .expect("changed candidate");
        let deleted = discovered
            .candidates
            .iter()
            .find(|candidate| candidate.path.as_str() == "deleted.rs")
            .expect("deleted candidate");
        assert!(matches!(
            materialize_candidate(changed, &ResourceLimits::default()),
            MaterializedCandidate::Omitted(OmittedFile {
                reason: OmissionReason::ChangedDuringRead,
                ..
            })
        ));
        assert!(matches!(
            materialize_candidate(deleted, &ResourceLimits::default()),
            MaterializedCandidate::Omitted(OmittedFile {
                reason: OmissionReason::ReadError {
                    kind: StableIoErrorKind::NotFound
                },
                ..
            })
        ));
    }

    #[test]
    fn composed_inventory_has_stable_order_hashes_summary_and_completeness() {
        let directory = tempdir().expect("directory");
        fs::write(directory.path().join("z.rs"), "z").expect("z");
        fs::write(directory.path().join("a.rs"), "a").expect("a");
        fs::write(directory.path().join("m.bin"), "m").expect("m");
        let result = inventory(directory.path(), &ResourceLimits::default());
        assert_eq!(
            result
                .files
                .iter()
                .map(|file| file.path.as_str())
                .collect::<Vec<_>>(),
            ["a.rs", "z.rs"]
        );
        assert_eq!(
            result.files[0].blake3,
            blake3::hash(b"a").to_hex().to_string()
        );
        assert_eq!(result.summary.admitted_files, 2);
        assert_eq!(result.summary.admitted_bytes, 2);
        assert_eq!(result.summary.omitted_files, 1);
        assert_eq!(result.completeness, InventoryCompleteness::Complete);
        assert_eq!(
            result.summary.omission_reasons,
            vec![(OmissionReason::UnrecognizedExtension, 1)]
        );
    }
}
