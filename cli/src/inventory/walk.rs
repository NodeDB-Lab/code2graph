// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use code2graph::{Language, LanguageAvailability};
use ignore::WalkBuilder;

use super::{
    FileClassification, InventoryCompleteness, InventoryFile, InventorySummary, MtimeHint,
    OmissionReason, OmittedFile, SourceInventory, StableIoErrorKind,
};
use crate::config::ResourceLimits;
use crate::error::Result;
use crate::project::{ProjectPath, ProjectSelection};

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
struct Candidate {
    path: ProjectPath,
    absolute: PathBuf,
    classification: FileClassification,
}

/// Builds an owned deterministic source inventory rooted at `selection`.
pub fn build_inventory(
    selection: &ProjectSelection,
    limits: &ResourceLimits,
    include_hidden: bool,
) -> Result<SourceInventory> {
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
        let is_hard_directory = entry.file_type().is_some_and(|kind| kind.is_dir())
            && entry
                .path()
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| HARD.contains(&name));
        !is_hard_directory
    });
    let mut candidates = Vec::new();
    let mut omitted = Vec::new();
    for result in builder.build() {
        let entry = match result {
            Ok(entry) => entry,
            Err(error) => {
                if let Some(path) = error_path(&error)
                    .and_then(|path| path.strip_prefix(root).ok())
                    .and_then(|path| ProjectPath::new(path).ok())
                {
                    omitted.push(OmittedFile {
                        path,
                        reason: OmissionReason::ReadError {
                            kind: error
                                .io_error()
                                .map_or(StableIoErrorKind::Other, |error| error.kind().into()),
                        },
                    });
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
        let metadata = match fs::symlink_metadata(entry.path()) {
            Ok(v) => v,
            Err(e) => {
                omitted.push(OmittedFile {
                    path,
                    reason: OmissionReason::ReadError {
                        kind: e.kind().into(),
                    },
                });
                continue;
            }
        };
        if metadata.file_type().is_symlink() {
            omitted.push(OmittedFile {
                path,
                reason: if fs::metadata(entry.path()).is_ok_and(|m| m.is_dir()) {
                    OmissionReason::SymlinkDirectory
                } else {
                    OmissionReason::SymlinkFile
                },
            });
            continue;
        }
        if metadata.is_dir() {
            continue;
        }
        if !metadata.is_file() {
            omitted.push(OmittedFile {
                path,
                reason: OmissionReason::NotRegularFile,
            });
            continue;
        }
        candidates.push(Candidate {
            classification: classify(&path),
            path,
            absolute: entry.into_path(),
        });
    }
    candidates.sort_by(|a, b| a.path.cmp(&b.path));
    let mut files = Vec::new();
    let mut total = 0usize;
    for candidate in candidates {
        let language = match candidate.classification {
            FileClassification::Enabled(l) => l,
            FileClassification::FeatureDisabled(language) => {
                omitted.push(OmittedFile {
                    path: candidate.path,
                    reason: OmissionReason::FeatureDisabled { language },
                });
                continue;
            }
            FileClassification::UnrecognizedExtension => {
                omitted.push(OmittedFile {
                    path: candidate.path,
                    reason: OmissionReason::UnrecognizedExtension,
                });
                continue;
            }
        };
        if files.len() >= limits.max_files {
            omitted.push(OmittedFile {
                path: candidate.path,
                reason: OmissionReason::FileCountLimit {
                    limit: limits.max_files,
                },
            });
            continue;
        }
        let (bytes, before) = match read_bounded(&candidate.absolute, limits.max_file_bytes) {
            Ok(x) => x,
            Err(Failure::TooLarge) => {
                omitted.push(OmittedFile {
                    path: candidate.path,
                    reason: OmissionReason::FileTooLarge {
                        limit: limits.max_file_bytes,
                    },
                });
                continue;
            }
            Err(Failure::Changed) => {
                omitted.push(OmittedFile {
                    path: candidate.path,
                    reason: OmissionReason::ChangedDuringRead,
                });
                continue;
            }
            Err(Failure::Io(kind)) => {
                omitted.push(OmittedFile {
                    path: candidate.path,
                    reason: OmissionReason::ReadError { kind },
                });
                continue;
            }
        };
        let text = match String::from_utf8(bytes.clone()) {
            Ok(v) => v,
            Err(_) => {
                omitted.push(OmittedFile {
                    path: candidate.path,
                    reason: OmissionReason::InvalidUtf8,
                });
                continue;
            }
        };
        if bytes.len() > limits.max_total_bytes.saturating_sub(total) {
            omitted.push(OmittedFile {
                path: candidate.path,
                reason: OmissionReason::TotalBytesLimit {
                    limit: limits.max_total_bytes,
                },
            });
            continue;
        }
        total += bytes.len();
        files.push(InventoryFile {
            path: candidate.path,
            language,
            blake3: blake3::hash(&bytes).to_hex().to_string(),
            bytes,
            text,
            mtime: before.mtime,
        });
    }
    omitted.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then_with(|| a.reason.tag().cmp(&b.reason.tag()))
    });
    let mut counts = BTreeMap::new();
    for item in &omitted {
        let entry = counts
            .entry(item.reason.tag())
            .or_insert((item.reason.clone(), 0usize));
        entry.1 += 1;
    }
    Ok(SourceInventory {
        completeness: if omitted.is_empty() {
            InventoryCompleteness::Complete
        } else {
            InventoryCompleteness::Partial
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
fn classify(path: &ProjectPath) -> FileClassification {
    match Language::from_path(path.as_str()) {
        Some(l) if l.availability() == LanguageAvailability::Enabled => {
            FileClassification::Enabled(l)
        }
        Some(l) => FileClassification::FeatureDisabled(l),
        None => FileClassification::UnrecognizedExtension,
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
        ignore::Error::Io(_)
        | ignore::Error::Glob { .. }
        | ignore::Error::UnrecognizedFileType(_)
        | ignore::Error::InvalidDefinition => None,
    }
}
#[derive(PartialEq, Eq)]
struct Fingerprint {
    length: u64,
    mtime: Option<MtimeHint>,
    identity: Option<(u64, u64)>,
}
impl Fingerprint {
    fn from_metadata(m: &Metadata) -> Self {
        Self {
            length: m.len(),
            mtime: mtime(m),
            identity: identity(m),
        }
    }
}
enum Failure {
    TooLarge,
    Changed,
    Io(StableIoErrorKind),
}
fn read_bounded(path: &Path, limit: usize) -> std::result::Result<(Vec<u8>, Fingerprint), Failure> {
    let path_before_meta = fs::symlink_metadata(path).map_err(io_fail)?;
    if path_before_meta.file_type().is_symlink() || !path_before_meta.is_file() {
        return Err(Failure::Changed);
    };
    let path_before = Fingerprint::from_metadata(&path_before_meta);
    let mut file = File::open(path).map_err(io_fail)?;
    let handle_before_meta = file.metadata().map_err(io_fail)?;
    if !handle_before_meta.is_file() {
        return Err(Failure::Changed);
    }
    let handle_before = Fingerprint::from_metadata(&handle_before_meta);
    if path_before != handle_before {
        return Err(Failure::Changed);
    }
    let mut bytes = Vec::with_capacity(limit.saturating_add(1).min(65536));
    let mut buf = [0; 8192];
    loop {
        let remaining = limit.saturating_add(1).saturating_sub(bytes.len());
        if remaining == 0 {
            return Err(Failure::TooLarge);
        }
        let chunk_len = buf.len().min(remaining);
        let n = file.read(&mut buf[..chunk_len]).map_err(io_fail)?;
        if n == 0 {
            break;
        }
        bytes.extend_from_slice(&buf[..n]);
    }
    if bytes.len() > limit {
        return Err(Failure::TooLarge);
    }
    let handle_after_meta = file.metadata().map_err(io_fail)?;
    if !handle_after_meta.is_file() {
        return Err(Failure::Changed);
    }
    let handle_after = Fingerprint::from_metadata(&handle_after_meta);
    let path_after_meta = fs::symlink_metadata(path).map_err(io_fail)?;
    if path_after_meta.file_type().is_symlink() || !path_after_meta.is_file() {
        return Err(Failure::Changed);
    }
    let path_after = Fingerprint::from_metadata(&path_after_meta);
    if handle_before != handle_after || handle_after != path_after {
        return Err(Failure::Changed);
    }
    Ok((bytes, handle_before))
}
fn io_fail(e: io::Error) -> Failure {
    Failure::Io(e.kind().into())
}
fn mtime(m: &Metadata) -> Option<MtimeHint> {
    let modified = m.modified().ok()?;
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
fn identity(m: &Metadata) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    Some((m.dev(), m.ino()))
}
#[cfg(not(unix))]
fn identity(_: &Metadata) -> Option<(u64, u64)> {
    None
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use code2graph::{Language, LanguageAvailability};
    use tempfile::tempdir;

    use super::{Failure, build_inventory, classify, error_path, read_bounded};
    use crate::config::ResourceLimits;
    use crate::inventory::{
        FileClassification, InventoryCompleteness, OmissionReason, StableIoErrorKind,
    };
    use crate::project::{ProjectPath, ProjectSelection, SelectionProvenance};

    fn selection(root: &Path) -> ProjectSelection {
        ProjectSelection {
            canonical_root: fs::canonicalize(root).unwrap(),
            canonical_source: None,
            provenance: SelectionProvenance::RootArgument,
        }
    }

    fn limits() -> ResourceLimits {
        ResourceLimits {
            max_files: 100,
            max_file_bytes: 1024,
            max_total_bytes: 4096,
            max_depth: 32,
            result_limit: 50,
            timeout: None,
        }
    }

    fn paths(inventory: &crate::inventory::SourceInventory) -> Vec<&str> {
        inventory
            .files
            .iter()
            .map(|file| file.path.as_str())
            .collect()
    }

    fn write(root: &Path, relative: &str, bytes: impl AsRef<[u8]>) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }

    #[test]
    fn nested_gitignore_and_ignore_negations_are_honored() {
        let directory = tempdir().unwrap();
        write(
            directory.path(),
            ".gitignore",
            b"ignored/*\n!ignored/keep.rs\n",
        );
        write(directory.path(), "ignored/drop.rs", b"drop");
        write(directory.path(), "ignored/keep.rs", b"keep");
        write(directory.path(), "nested/.ignore", b"*.rs\n!keep.rs\n");
        write(directory.path(), "nested/drop.rs", b"drop");
        write(directory.path(), "nested/keep.rs", b"keep");

        let inventory = build_inventory(&selection(directory.path()), &limits(), false).unwrap();
        assert_eq!(paths(&inventory), ["ignored/keep.rs", "nested/keep.rs"]);
        assert_eq!(inventory.completeness, InventoryCompleteness::Complete);
    }

    #[test]
    fn repository_info_exclude_is_deliberately_disabled() {
        let directory = tempdir().unwrap();
        write(directory.path(), ".git/info/exclude", b"kept.rs\n");
        write(directory.path(), "kept.rs", b"kept");
        let inventory = build_inventory(&selection(directory.path()), &limits(), false).unwrap();
        assert_eq!(paths(&inventory), ["kept.rs"]);
    }

    #[test]
    fn hidden_is_configurable_but_hard_directories_are_always_pruned() {
        let directory = tempdir().unwrap();
        write(directory.path(), "visible.rs", b"v");
        write(directory.path(), ".hidden.rs", b"h");
        write(directory.path(), ".secret/file.rs", b"s");
        write(directory.path(), "target/generated.rs", b"t");
        write(directory.path(), "node_modules/package.rs", b"n");

        let default = build_inventory(&selection(directory.path()), &limits(), false).unwrap();
        assert_eq!(paths(&default), ["visible.rs"]);
        let included = build_inventory(&selection(directory.path()), &limits(), true).unwrap();
        assert_eq!(
            paths(&included),
            [".hidden.rs", ".secret/file.rs", "visible.rs"]
        );
    }

    #[test]
    fn depth_counts_the_root_as_zero_and_files_by_component_depth() {
        let directory = tempdir().unwrap();
        write(directory.path(), "root.rs", b"0");
        write(directory.path(), "one/child.rs", b"1");
        write(directory.path(), "one/two/grandchild.rs", b"2");
        let mut bounded = limits();
        bounded.max_depth = 1;
        let inventory = build_inventory(&selection(directory.path()), &bounded, false).unwrap();
        assert_eq!(paths(&inventory), ["root.rs"]);

        bounded.max_depth = 2;
        let inventory = build_inventory(&selection(directory.path()), &bounded, false).unwrap();
        assert_eq!(paths(&inventory), ["one/child.rs", "root.rs"]);
    }

    #[test]
    fn candidates_are_globally_sorted_before_file_and_byte_budgets() {
        let directory = tempdir().unwrap();
        write(directory.path(), "z.rs", b"z");
        write(directory.path(), "a.rs", b"aaa");
        write(directory.path(), "m.rs", b"mm");
        let mut bounded = limits();
        bounded.max_files = 2;
        bounded.max_total_bytes = 4;
        let inventory = build_inventory(&selection(directory.path()), &bounded, false).unwrap();
        assert_eq!(paths(&inventory), ["a.rs", "z.rs"]);
        assert!(matches!(
            inventory.omitted[0].reason,
            OmissionReason::TotalBytesLimit { limit: 4 }
        ));
        assert_eq!(inventory.omitted[0].path.as_str(), "m.rs");
        assert_eq!(inventory.summary.admitted_bytes, 4);
    }

    #[test]
    fn exact_file_limit_is_admitted_and_one_extra_byte_is_rejected() {
        let directory = tempdir().unwrap();
        write(directory.path(), "exact.rs", b"1234");
        write(directory.path(), "over.rs", b"12345");
        let mut bounded = limits();
        bounded.max_file_bytes = 4;
        let inventory = build_inventory(&selection(directory.path()), &bounded, false).unwrap();
        assert_eq!(paths(&inventory), ["exact.rs"]);
        assert_eq!(inventory.files[0].bytes, b"1234");
        assert_eq!(inventory.files[0].text, "1234");
        assert_eq!(
            inventory.files[0].blake3,
            blake3::hash(b"1234").to_hex().to_string()
        );
        assert!(matches!(
            inventory.omitted[0].reason,
            OmissionReason::FileTooLarge { limit: 4 }
        ));
    }

    #[test]
    fn zero_sized_files_obey_file_count_not_total_byte_capacity() {
        let directory = tempdir().unwrap();
        write(directory.path(), "a.rs", b"");
        write(directory.path(), "b.rs", b"");
        let mut bounded = limits();
        bounded.max_files = 1;
        bounded.max_total_bytes = 0;
        let inventory = build_inventory(&selection(directory.path()), &bounded, false).unwrap();
        assert_eq!(paths(&inventory), ["a.rs"]);
        assert!(matches!(
            inventory.omitted[0].reason,
            OmissionReason::FileCountLimit { limit: 1 }
        ));
    }

    #[test]
    fn invalid_utf8_is_omitted_without_affecting_admitted_byte_budget() {
        let directory = tempdir().unwrap();
        write(directory.path(), "a.rs", [0xff]);
        write(directory.path(), "b.rs", b"ok");
        let mut bounded = limits();
        bounded.max_total_bytes = 2;
        let inventory = build_inventory(&selection(directory.path()), &bounded, false).unwrap();
        assert_eq!(paths(&inventory), ["b.rs"]);
        assert!(matches!(
            inventory.omitted[0].reason,
            OmissionReason::InvalidUtf8
        ));
        assert_eq!(inventory.summary.admitted_bytes, 2);
    }

    #[test]
    fn classification_distinguishes_unknown_enabled_and_feature_disabled() {
        assert_eq!(
            classify(&ProjectPath::new(Path::new("notes.unknown")).unwrap()),
            FileClassification::UnrecognizedExtension
        );
        for language in Language::ALL {
            let path = format!("source.{}", language.extensions()[0]);
            let classification = classify(&ProjectPath::new(Path::new(&path)).unwrap());
            let expected = match language.availability() {
                LanguageAvailability::Enabled => FileClassification::Enabled(*language),
                LanguageAvailability::FeatureDisabled => {
                    FileClassification::FeatureDisabled(*language)
                }
            };
            assert_eq!(classification, expected, "{language:?}");
        }
    }

    #[test]
    fn omissions_and_reason_counts_have_stable_path_and_tag_order() {
        let directory = tempdir().unwrap();
        write(directory.path(), "z.txt", b"unknown");
        write(directory.path(), "b.rs", [0xff]);
        write(directory.path(), "a.rs", b"too long");
        let mut bounded = limits();
        bounded.max_file_bytes = 3;
        let inventory = build_inventory(&selection(directory.path()), &bounded, false).unwrap();
        assert_eq!(
            inventory
                .omitted
                .iter()
                .map(|item| item.path.as_str())
                .collect::<Vec<_>>(),
            ["a.rs", "b.rs", "z.txt"]
        );
        assert_eq!(
            inventory
                .summary
                .omission_reasons
                .iter()
                .map(|(reason, count)| (reason.tag(), *count))
                .collect::<Vec<_>>(),
            [
                ("file-too-large".to_owned(), 1),
                ("invalid-utf8".to_owned(), 1),
                ("unrecognized-extension".to_owned(), 1),
            ]
        );
        assert_eq!(inventory.completeness, InventoryCompleteness::Partial);
    }

    #[test]
    fn io_error_kind_tags_are_stable_and_exhaustive_for_public_variants() {
        let cases = [
            (StableIoErrorKind::NotFound, "not-found"),
            (StableIoErrorKind::PermissionDenied, "permission-denied"),
            (StableIoErrorKind::AlreadyExists, "already-exists"),
            (StableIoErrorKind::InvalidInput, "invalid-input"),
            (StableIoErrorKind::InvalidData, "invalid-data"),
            (StableIoErrorKind::TimedOut, "timed-out"),
            (StableIoErrorKind::Interrupted, "interrupted"),
            (StableIoErrorKind::UnexpectedEof, "unexpected-eof"),
            (StableIoErrorKind::WouldBlock, "would-block"),
            (StableIoErrorKind::WriteZero, "write-zero"),
            (StableIoErrorKind::Other, "other"),
        ];
        for (kind, tag) in cases {
            assert_eq!(kind.as_str(), tag);
        }
    }

    #[test]
    fn ignore_error_path_walks_nested_public_variants_deterministically() {
        use ignore::Error;

        let nested = Error::Partial(vec![
            Error::WithLineNumber {
                line: 12,
                err: Box::new(Error::WithPath {
                    path: Path::new("nested/ignored.rs").to_path_buf(),
                    err: Box::new(Error::InvalidDefinition),
                }),
            },
            Error::Loop {
                ancestor: Path::new("ancestor").to_path_buf(),
                child: Path::new("child/looped.rs").to_path_buf(),
            },
        ]);
        assert_eq!(error_path(&nested).unwrap(), Path::new("nested/ignored.rs"));
        assert_eq!(
            error_path(&Error::Loop {
                ancestor: Path::new("ancestor").to_path_buf(),
                child: Path::new("child/looped.rs").to_path_buf(),
            })
            .unwrap(),
            Path::new("child/looped.rs")
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_files_and_directories_are_reported_and_never_followed() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().unwrap();
        write(directory.path(), "real.rs", b"real");
        write(directory.path(), "outside/secret.rs", b"secret");
        symlink(
            directory.path().join("real.rs"),
            directory.path().join("link.rs"),
        )
        .unwrap();
        symlink(
            directory.path().join("outside"),
            directory.path().join("linked-dir"),
        )
        .unwrap();
        let inventory = build_inventory(&selection(directory.path()), &limits(), false).unwrap();
        assert_eq!(paths(&inventory), ["outside/secret.rs", "real.rs"]);
        assert!(matches!(
            inventory.omitted[0].reason,
            OmissionReason::SymlinkFile
        ));
        assert_eq!(inventory.omitted[0].path.as_str(), "link.rs");
        assert!(matches!(
            inventory.omitted[1].reason,
            OmissionReason::SymlinkDirectory
        ));
        assert_eq!(inventory.omitted[1].path.as_str(), "linked-dir");
    }

    #[cfg(unix)]
    #[test]
    fn read_validation_rejects_a_symlink_before_opening_it() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().unwrap();
        write(directory.path(), "real.rs", b"real");
        let link = directory.path().join("link.rs");
        symlink(directory.path().join("real.rs"), &link).unwrap();
        assert!(matches!(read_bounded(&link, 10), Err(Failure::Changed)));
    }
}
