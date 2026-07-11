// SPDX-License-Identifier: Apache-2.0

//! Authoritative-source conversion for position selectors.

use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use crate::{
    Cancellation, CliError, Deadline, ProjectPath, ProjectSelection, Result, SourcePosition,
};

use super::SelectorContext;

/// Resolves a human position through current source bytes proven to match the
/// loaded snapshot from which the queried spans were produced.
pub(super) fn resolve_position(
    context: &SelectorContext<'_>,
    position: &SourcePosition,
) -> Result<code2graph::SymbolId> {
    context.deadline.check(context.cancellation)?;
    let project_path = ProjectPath::new(Path::new(&position.file))?;
    if context
        .index
        .symbols_in_file(project_path.as_str())
        .is_empty()
    {
        return Err(CliError::NoMatch);
    }
    let expected_hash = context
        .snapshot
        .files
        .iter()
        .find(|file| file.path == project_path.as_str())
        .map(|file| file.content_hash)
        .ok_or_else(|| {
            CliError::Index("position source is absent from the loaded snapshot".into())
        })?;
    let path = contained_regular_file(
        context.selection,
        &project_path,
        context.deadline,
        context.cancellation,
    )?;
    let source = read_utf8_bounded(
        &path,
        context.max_file_bytes,
        context.deadline,
        context.cancellation,
    )?;
    if *blake3::hash(source.as_bytes()).as_bytes() != expected_hash {
        return Err(CliError::Index(
            "current position source does not match the loaded snapshot".into(),
        ));
    }
    let byte = source_byte(&source, position, context.deadline, context.cancellation)?;
    context.deadline.check(context.cancellation)?;
    context
        .index
        .symbol_at_byte(project_path.as_str(), byte)
        .map(|symbol| symbol.id.clone())
        .ok_or(CliError::NoMatch)
}

fn contained_regular_file(
    selection: &ProjectSelection,
    path: &ProjectPath,
    deadline: &Deadline,
    cancellation: &dyn Cancellation,
) -> Result<PathBuf> {
    let mut candidate = selection.canonical_root.clone();
    for component in Path::new(path.as_str()).components() {
        let Component::Normal(component) = component else {
            return Err(CliError::ProjectRelativePath {
                path: PathBuf::from(path.as_str()),
                reason: "path must contain only normal components".into(),
            });
        };
        deadline.check(cancellation)?;
        candidate.push(component);
        let metadata = fs::symlink_metadata(&candidate).map_err(|error| CliError::ProjectPath {
            path: candidate.clone(),
            reason: error.to_string(),
        })?;
        if metadata.file_type().is_symlink() {
            return Err(CliError::ProjectSymlink { path: candidate });
        }
    }
    let canonical = fs::canonicalize(&candidate).map_err(|error| CliError::ProjectPath {
        path: candidate.clone(),
        reason: error.to_string(),
    })?;
    if !canonical.starts_with(&selection.canonical_root) {
        return Err(CliError::ProjectPathOutsideRoot {
            root: selection.canonical_root.clone(),
            path: canonical,
        });
    }
    let metadata = fs::metadata(&canonical).map_err(|error| CliError::ProjectPath {
        path: canonical.clone(),
        reason: error.to_string(),
    })?;
    if !metadata.is_file() {
        return Err(CliError::ProjectPath {
            path: canonical,
            reason: "position source must be a regular file".into(),
        });
    }
    Ok(canonical)
}

fn read_utf8_bounded(
    path: &Path,
    max_file_bytes: usize,
    deadline: &Deadline,
    cancellation: &dyn Cancellation,
) -> Result<String> {
    deadline.check(cancellation)?;
    let mut file = File::open(path).map_err(|error| CliError::ProjectPath {
        path: path.to_path_buf(),
        reason: error.to_string(),
    })?;
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        deadline.check(cancellation)?;
        let read = file
            .read(&mut chunk)
            .map_err(|error| CliError::ProjectPath {
                path: path.to_path_buf(),
                reason: error.to_string(),
            })?;
        if read == 0 {
            break;
        }
        let remaining = max_file_bytes.saturating_sub(bytes.len());
        if read > remaining {
            return Err(CliError::Usage(format!(
                "position source exceeds --max-file-bytes ({max_file_bytes})"
            )));
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    deadline.check(cancellation)?;
    String::from_utf8(bytes).map_err(|_| CliError::Usage("position source must be UTF-8".into()))
}

fn source_byte(
    source: &str,
    position: &SourcePosition,
    deadline: &Deadline,
    cancellation: &dyn Cancellation,
) -> Result<usize> {
    deadline.check(cancellation)?;
    if position.line == 0 || position.column == 0 {
        return Err(CliError::Usage(
            "position line and column are 1-based and must be nonzero".into(),
        ));
    }
    let (start, end) = source_line(source, position.line, deadline, cancellation)?;
    let line = &source[start..end];
    if line.is_empty() {
        if position.column == 1 {
            return Ok(start);
        }
        return Err(CliError::Usage("position column is out of range".into()));
    }
    let column_index = usize::try_from(position.column - 1)
        .map_err(|_| CliError::Usage("position column is out of range".into()))?;
    for (scalar_index, (offset, _)) in line.char_indices().enumerate() {
        if scalar_index % 1024 == 0 {
            deadline.check(cancellation)?;
        }
        if scalar_index == column_index {
            return Ok(start + offset);
        }
    }
    Err(CliError::Usage("position column is out of range".into()))
}

fn source_line(
    source: &str,
    requested_line: u32,
    deadline: &Deadline,
    cancellation: &dyn Cancellation,
) -> Result<(usize, usize)> {
    let mut line = 1_u32;
    let mut start = 0;
    for (offset, byte) in source.bytes().enumerate() {
        if offset % 8192 == 0 {
            deadline.check(cancellation)?;
        }
        if byte == b'\n' {
            let end = if offset > start && source.as_bytes()[offset - 1] == b'\r' {
                offset - 1
            } else {
                offset
            };
            if line == requested_line {
                return Ok((start, end));
            }
            line = line.saturating_add(1);
            start = offset + 1;
        }
    }
    deadline.check(cancellation)?;
    if line == requested_line {
        Ok((start, source.len()))
    } else {
        Err(CliError::Usage("position line is out of range".into()))
    }
}

#[cfg(test)]
fn source_lines(source: &str) -> Vec<(usize, usize)> {
    let mut lines = Vec::new();
    let mut start = 0;
    for (offset, byte) in source.bytes().enumerate() {
        if byte == b'\n' {
            let end = if offset > start && source.as_bytes()[offset - 1] == b'\r' {
                offset - 1
            } else {
                offset
            };
            lines.push((start, end));
            start = offset + 1;
        }
    }
    lines.push((start, source.len()));
    lines
}

#[cfg(test)]
mod tests {
    use std::fs;

    use code2graph::{
        ByteSpan, CodeGraph, Descriptor, FileFacts, Symbol, SymbolId, SymbolKind, Visibility,
    };
    use code2graph_query::GraphIndex;
    use tempfile::tempdir;

    use super::{resolve_position, source_byte, source_lines};
    use crate::cache::{
        CacheCompleteness, CandidateFileRecord, CandidateId, CompatibilityFingerprint,
        CompatibilityRecord, LanguageFeatureFingerprint, LoadedSnapshot, PackageFingerprint,
        ProjectInputDigest,
    };
    use crate::selector::SelectorContext;
    use crate::{Deadline, NeverCancelled, ProjectSelection, SelectionProvenance, SourcePosition};

    fn position(line: u32, column: u32) -> SourcePosition {
        SourcePosition {
            file: "src/a.rs".into(),
            line,
            column,
        }
    }

    fn symbol(name: &str, start: usize, end: usize) -> Symbol {
        Symbol {
            id: SymbolId::global("rust", vec![Descriptor::Term(name.into())]),
            name: name.into(),
            kind: SymbolKind::Function,
            visibility: Visibility::Public,
            entry_points: Vec::new(),
            file: "src/a.rs".into(),
            line: 1,
            span: ByteSpan { start, end },
            signature: name.into(),
        }
    }

    fn snapshot(bytes: &[u8], symbols: Vec<Symbol>) -> LoadedSnapshot {
        let language = LanguageFeatureFingerprint::current();
        let package = PackageFingerprint::from_normalized(["position-test"]);
        let compatibility = CompatibilityFingerprint::new(language, package);
        let hash = *blake3::hash(bytes).as_bytes();
        let input = ProjectInputDigest::from_inputs([("src/a.rs", "rust", hash)]);
        LoadedSnapshot {
            candidate_id: CandidateId::new(compatibility, input, CacheCompleteness::Complete, &[]),
            compatibility: CompatibilityRecord {
                id: compatibility,
                language_fingerprint: language,
                package_fingerprint: package,
                created_at_ns: 0,
            },
            input_digest: input,
            completeness: CacheCompleteness::Complete,
            omissions: Vec::new(),
            created_at_ns: 0,
            inventory_file_count: 1,
            inventory_total_bytes: bytes.len() as u64,
            files: vec![CandidateFileRecord {
                path: "src/a.rs".into(),
                language: "rust".into(),
                content_hash: hash,
                size_bytes: bytes.len() as u64,
                mtime: None,
                package_assignment: "none".into(),
                facts: FileFacts {
                    file: "src/a.rs".into(),
                    lang: "rust".into(),
                    symbols,
                    references: Vec::new(),
                    scopes: Vec::new(),
                    bindings: Vec::new(),
                    ffi_exports: Vec::new(),
                },
                subgraph: None,
            }],
            tier_graphs: Vec::new(),
        }
    }

    #[test]
    fn converts_unicode_crlf_and_empty_lines_without_counting_terminators() {
        let source = "aé\r\n\nxyz";
        assert_eq!(source_lines(source), vec![(0, 3), (5, 5), (6, 9)]);
        let deadline = Deadline::new(None);
        assert_eq!(
            source_byte(source, &position(1, 2), &deadline, &NeverCancelled).unwrap(),
            1
        );
        assert_eq!(
            source_byte(source, &position(2, 1), &deadline, &NeverCancelled).unwrap(),
            5
        );
        assert_eq!(
            source_byte(source, &position(3, 3), &deadline, &NeverCancelled).unwrap(),
            8
        );
        assert!(source_byte(source, &position(1, 3), &deadline, &NeverCancelled).is_err());
        assert!(source_byte(source, &position(4, 1), &deadline, &NeverCancelled).is_err());
    }

    struct Cancelled;

    impl crate::Cancellation for Cancelled {
        fn is_cancelled(&self) -> bool {
            true
        }
    }

    #[test]
    fn terminal_newline_exposes_an_empty_eof_line() {
        let deadline = Deadline::new(None);
        assert_eq!(
            source_byte("x\n", &position(2, 1), &deadline, &NeverCancelled).unwrap(),
            2
        );
    }

    #[test]
    fn position_resolution_uses_scalar_columns_and_half_open_eof_boundaries() {
        let directory = tempdir().unwrap();
        fs::create_dir(directory.path().join("src")).unwrap();
        let bytes = "éx\r\n\n".as_bytes();
        fs::write(directory.path().join("src/a.rs"), bytes).unwrap();
        let first = symbol("first", 0, 2);
        let second = symbol("second", 2, 3);
        let index = GraphIndex::from_graph(CodeGraph {
            symbols: vec![second.clone(), first.clone()],
            edges: Vec::new(),
        })
        .unwrap();
        let snapshot = snapshot(bytes, vec![first.clone(), second.clone()]);
        let selection = ProjectSelection {
            canonical_root: fs::canonicalize(directory.path()).unwrap(),
            canonical_source: None,
            provenance: SelectionProvenance::CurrentDirectory,
        };
        let deadline = Deadline::new(None);
        let context = SelectorContext {
            index: &index,
            selection: &selection,
            snapshot: &snapshot,
            max_file_bytes: 64,
            deadline: &deadline,
            cancellation: &NeverCancelled,
        };

        assert_eq!(
            resolve_position(&context, &position(1, 1)).unwrap(),
            first.id
        );
        assert_eq!(
            resolve_position(&context, &position(1, 2)).unwrap(),
            second.id
        );
        assert!(matches!(
            resolve_position(&context, &position(2, 1)),
            Err(crate::CliError::NoMatch)
        ));
        assert!(matches!(
            resolve_position(&context, &position(3, 1)),
            Err(crate::CliError::NoMatch)
        ));
    }

    #[test]
    fn position_rejects_malformed_paths_stale_source_and_resource_limits() {
        let directory = tempdir().unwrap();
        fs::create_dir(directory.path().join("src")).unwrap();
        let original = b"x";
        fs::write(directory.path().join("src/a.rs"), original).unwrap();
        let definition = symbol("x", 0, 1);
        let index = GraphIndex::from_graph(CodeGraph {
            symbols: vec![definition.clone()],
            edges: Vec::new(),
        })
        .unwrap();
        let snapshot = snapshot(original, vec![definition]);
        let selection = ProjectSelection {
            canonical_root: fs::canonicalize(directory.path()).unwrap(),
            canonical_source: None,
            provenance: SelectionProvenance::CurrentDirectory,
        };
        let deadline = Deadline::new(None);
        let context = SelectorContext {
            index: &index,
            selection: &selection,
            snapshot: &snapshot,
            max_file_bytes: 64,
            deadline: &deadline,
            cancellation: &NeverCancelled,
        };
        for file in ["", ".", "../a.rs", "src/../a.rs", "/tmp/a.rs"] {
            let malformed = SourcePosition {
                file: file.into(),
                line: 1,
                column: 1,
            };
            assert!(matches!(
                resolve_position(&context, &malformed),
                Err(crate::CliError::ProjectRelativePath { .. })
            ));
        }

        fs::write(directory.path().join("src/a.rs"), b"y").unwrap();
        assert!(matches!(
            resolve_position(&context, &position(1, 1)),
            Err(crate::CliError::Index(_))
        ));
        let bounded = SelectorContext {
            max_file_bytes: 0,
            ..context
        };
        assert!(matches!(
            resolve_position(&bounded, &position(1, 1)),
            Err(crate::CliError::Usage(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn position_rejects_symlinked_source_components() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().unwrap();
        let outside = tempdir().unwrap();
        fs::write(outside.path().join("a.rs"), b"x").unwrap();
        symlink(outside.path(), directory.path().join("src")).unwrap();
        let definition = symbol("x", 0, 1);
        let index = GraphIndex::from_graph(CodeGraph {
            symbols: vec![definition.clone()],
            edges: Vec::new(),
        })
        .unwrap();
        let snapshot = snapshot(b"x", vec![definition]);
        let selection = ProjectSelection {
            canonical_root: fs::canonicalize(directory.path()).unwrap(),
            canonical_source: None,
            provenance: SelectionProvenance::CurrentDirectory,
        };
        let deadline = Deadline::new(None);
        let context = SelectorContext {
            index: &index,
            selection: &selection,
            snapshot: &snapshot,
            max_file_bytes: 64,
            deadline: &deadline,
            cancellation: &NeverCancelled,
        };
        assert!(matches!(
            resolve_position(&context, &position(1, 1)),
            Err(crate::CliError::ProjectSymlink { .. })
        ));
    }

    #[test]
    fn conversion_honors_deadline_and_cancellation() {
        assert!(matches!(
            source_byte(
                "x",
                &position(1, 1),
                &Deadline::new(Some(std::time::Duration::ZERO)),
                &NeverCancelled
            ),
            Err(crate::CliError::Timeout)
        ));
        assert!(matches!(
            source_byte("x", &position(1, 1), &Deadline::new(None), &Cancelled),
            Err(crate::CliError::Cancelled)
        ));
    }
}
