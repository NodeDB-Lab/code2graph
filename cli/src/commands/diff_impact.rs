// SPDX-License-Identifier: Apache-2.0

//! Derives bounded-impact seeds from a git diff and reuses the per-seed impact
//! pipeline (`append_seed_impact` / `default_impact_role`) unchanged.

use std::collections::HashSet;
use std::path::Path;
use std::process::Command;

use code2graph::{ByteSpan, Confidence, EdgeKey, RefRole, SymbolId};
use code2graph_query::{EdgeFilter, GraphRead};

use super::impact::{append_seed_impact, default_impact_role};
use super::shared::query_envelope;
use crate::commands::QueryCommandContext;
use crate::result::{ImpactOutput, OutputEnvelope};
use crate::selector::read_utf8_bounded;
use crate::{CliError, ProjectPath, Result};

pub(crate) struct DiffImpactCommandRequest {
    pub base: Option<String>,
    pub role: Option<RefRole>,
    pub depth: u32,
    pub max_nodes: usize,
    pub min_confidence: Confidence,
}

/// Runs `git diff` against the project root, derives seed symbols from the
/// changed line ranges, and traverses each seed exactly like `execute_impact`.
pub(crate) fn execute_diff_impact<R>(
    context: &QueryCommandContext<'_, R>,
    request: DiffImpactCommandRequest,
) -> Result<OutputEnvelope<Vec<ImpactOutput>>>
where
    R: GraphRead,
    R::Error: Into<CliError>,
{
    context.deadline.check(context.cancellation)?;
    let diff_text = run_git_diff(
        &context.loaded.selection.canonical_root,
        request.base.as_deref(),
    )?;
    let changed_files = parse_diff(&diff_text);

    let mut seeds: Vec<SymbolId> = Vec::new();
    let mut seen: HashSet<SymbolId> = HashSet::new();

    for (file, line_ranges) in &changed_files {
        context.deadline.check(context.cancellation)?;
        // A path git reports that we cannot validate as project-relative (or
        // that no longer exists as a regular file, e.g. it was deleted) is
        // skipped rather than erroring: it honestly contributes zero seeds.
        let Ok(project_path) = ProjectPath::new(Path::new(file)) else {
            continue;
        };
        let full_path = context
            .loaded
            .selection
            .canonical_root
            .join(project_path.as_str());
        let Ok(source) = read_utf8_bounded(
            &full_path,
            context.max_file_bytes,
            context.deadline,
            context.cancellation,
        ) else {
            continue;
        };
        let line_starts = line_starts(&source);
        let total_len = source.len();
        let changed_byte_ranges: Vec<(usize, usize)> = line_ranges
            .iter()
            .filter_map(|&(start_line, end_line)| {
                line_range_to_byte_range(&line_starts, total_len, start_line, end_line)
            })
            .collect();
        if changed_byte_ranges.is_empty() {
            // NOTE: a file with no mappable changed ranges (e.g. every hunk
            // header pointed past the current file length) is skipped, not
            // an error: it contributes zero seeds honestly.
            continue;
        }

        let mut after: Option<SymbolId> = None;
        loop {
            context.deadline.check(context.cancellation)?;
            let page = context
                .index
                .symbols_in_file(project_path.as_str(), after.as_ref(), 256)
                .map_err(Into::into)?;
            for symbol in page.items {
                if changed_byte_ranges
                    .iter()
                    .any(|&(start, end)| byte_ranges_overlap(symbol.span, start, end))
                    && seen.insert(symbol.id.clone())
                {
                    seeds.push(symbol.id);
                }
            }
            match page.next {
                Some(next) => after = Some(next),
                None => break,
            }
        }
        // A changed file with no indexed symbols at all (not indexed, deleted,
        // or a non-source file) is honestly skipped above: it never reaches
        // this point with any seed contributed, and no error is raised.
    }

    let mut rows: Vec<(ImpactOutput, EdgeKey)> = Vec::new();
    let mut truncated = false;
    for seed in &seeds {
        context.deadline.check(context.cancellation)?;
        let implicit_role = default_impact_role(context.index, seed)?;
        let filter = EdgeFilter {
            role: request.role.or(implicit_role),
            min_confidence: request.min_confidence,
            provenance: None,
        };
        truncated |= append_seed_impact(
            context.index,
            seed,
            filter,
            request.depth,
            request.max_nodes,
            &mut rows,
        )?;
    }
    rows.sort_by(|(left, left_edge), (right, right_edge)| {
        (&left.seed, left.depth, &left.symbol, left_edge).cmp(&(
            &right.seed,
            right.depth,
            &right.symbol,
            right_edge,
        ))
    });
    let results = rows.into_iter().map(|(row, _)| row).collect::<Vec<_>>();
    let total = results.len();
    let mut envelope = query_envelope(context.loaded, results);
    envelope.total = total;
    envelope.returned = envelope.results.len();
    envelope.truncated = truncated;
    Ok(envelope)
}

fn run_git_diff(root: &Path, base: Option<&str>) -> Result<String> {
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(root)
        .arg("diff")
        .arg("--relative")
        .arg("--unified=0");
    if let Some(base) = base {
        command.arg(base);
    }
    let output = command
        .output()
        .map_err(|error| CliError::Fatal(format!("failed to spawn `git diff`: {error}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(CliError::Fatal(format!(
            "`git diff` failed: {}",
            stderr.trim()
        )));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| CliError::Fatal("`git diff` produced non-UTF-8 output".into()))
}

/// One file's changed new-side line ranges, 1-based and half-open (`[start, end)`).
type FileLineRanges = (String, Vec<(u32, u32)>);

/// Parses a `--unified=0` diff into per-file changed new-side line ranges.
/// Malformed or unrecognized hunk headers are skipped, never panicked on.
fn parse_diff(diff: &str) -> Vec<FileLineRanges> {
    let mut files: Vec<FileLineRanges> = Vec::new();
    let mut current: Option<FileLineRanges> = None;
    for line in diff.lines() {
        if let Some(path) = line.strip_prefix("+++ ") {
            if let Some(finished) = current.take() {
                files.push(finished);
            }
            if path == "/dev/null" {
                continue;
            }
            let path = path.strip_prefix("b/").unwrap_or(path).to_owned();
            current = Some((path, Vec::new()));
        } else if line.starts_with("@@ ")
            && let Some((_, ranges)) = current.as_mut()
            && let Some(range) = parse_hunk_header(line)
        {
            ranges.push(range);
        }
    }
    if let Some(finished) = current.take() {
        files.push(finished);
    }
    files
}

/// Parses one `@@ -a,b +c,d @@` header into the new-side changed range.
/// A pure deletion (`d == 0`) collapses to a one-line point at `c` (clamped
/// to at least line 1) so the enclosing symbol is still selected.
fn parse_hunk_header(line: &str) -> Option<(u32, u32)> {
    let rest = line.strip_prefix("@@ ")?;
    let end_marker = rest.find(" @@")?;
    let body = &rest[..end_marker];
    let mut parts = body.split_whitespace();
    let _old_side = parts.next()?;
    let new_side = parts.next()?.strip_prefix('+')?;
    let (start_text, count_text) = match new_side.split_once(',') {
        Some((start, count)) => (start, count),
        None => (new_side, "1"),
    };
    let start: u32 = start_text.parse().ok()?;
    let count: u32 = count_text.parse().ok()?;
    if count == 0 {
        let point = start.max(1);
        Some((point, point + 1))
    } else {
        Some((start, start + count))
    }
}

/// Byte offset of the start of every line (1-indexed by position). The file
/// lacking a trailing newline is handled by the caller via `total_len` rather
/// than an implicit final entry here.
fn line_starts(source: &str) -> Vec<usize> {
    let mut starts = vec![0_usize];
    for (offset, byte) in source.bytes().enumerate() {
        if byte == b'\n' {
            starts.push(offset + 1);
        }
    }
    starts
}

/// Maps a 1-based half-open line range to a half-open byte range. Returns
/// `None` when the range starts past the end of the known lines rather than
/// panicking or fabricating an out-of-bounds byte offset.
fn line_range_to_byte_range(
    line_starts: &[usize],
    total_len: usize,
    start_line: u32,
    end_line: u32,
) -> Option<(usize, usize)> {
    if start_line == 0 {
        return None;
    }
    let start_index = usize::try_from(start_line - 1).ok()?;
    let end_index = usize::try_from(end_line.saturating_sub(1)).ok()?;
    let start_byte = (*line_starts.get(start_index)?).min(total_len);
    let end_byte = line_starts
        .get(end_index)
        .copied()
        .unwrap_or(total_len)
        .max(start_byte);
    Some((start_byte, end_byte))
}

/// Half-open byte-span overlap: `span.start < changeEnd && changeStart < span.end`.
fn byte_ranges_overlap(span: ByteSpan, changed_start: usize, changed_end: usize) -> bool {
    span.start < changed_end && changed_start < span.end
}

#[cfg(test)]
mod tests {
    use code2graph::ByteSpan;

    use super::{
        byte_ranges_overlap, line_range_to_byte_range, line_starts, parse_diff, parse_hunk_header,
    };

    #[test]
    fn hunk_header_parses_common_and_edge_forms() {
        assert_eq!(parse_hunk_header("@@ -1,3 +1,4 @@"), Some((1, 5)));
        assert_eq!(parse_hunk_header("@@ -5 +5 @@"), Some((5, 6)));
        // Pure deletion: new-side count is zero, point at the anchor line.
        assert_eq!(parse_hunk_header("@@ -10,2 +9,0 @@"), Some((9, 10)));
        // Deletion anchored at the very start of the file clamps to line 1.
        assert_eq!(parse_hunk_header("@@ -1,2 +0,0 @@"), Some((1, 2)));
    }

    #[test]
    fn hunk_header_parsing_never_panics_on_malformed_input() {
        for malformed in [
            "@@ garbage @@",
            "@@ -a,b +c,d @@",
            "@@ -1,3",
            "not a hunk header",
            "@@  @@",
            "@@ -1,3 +x @@",
        ] {
            assert_eq!(parse_hunk_header(malformed), None, "{malformed}");
        }
    }

    #[test]
    fn multi_file_diff_parses_per_file_ranges_and_handles_deleted_files() {
        let diff = "\
diff --git a/src/a.rs b/src/a.rs
--- a/src/a.rs
+++ b/src/a.rs
@@ -1,3 +1,4 @@
@@ -10,0 +12,2 @@
diff --git a/src/b.rs b/src/b.rs
--- a/src/b.rs
+++ /dev/null
@@ -1,5 +0,0 @@
diff --git a/src/c.rs b/src/c.rs
--- /dev/null
+++ b/src/c.rs
@@ -0,0 +1,3 @@
";
        let parsed = parse_diff(diff);
        assert_eq!(parsed.len(), 2, "the deleted file contributes no section");
        assert_eq!(parsed[0].0, "src/a.rs");
        assert_eq!(parsed[0].1, vec![(1, 5), (12, 14)]);
        assert_eq!(parsed[1].0, "src/c.rs");
        assert_eq!(parsed[1].1, vec![(1, 4)]);
    }

    #[test]
    fn empty_diff_parses_to_no_files() {
        assert!(parse_diff("").is_empty());
    }

    #[test]
    fn line_range_maps_to_bytes_across_crlf_and_missing_final_newline() {
        let source = "one\r\ntwo\r\nthree";
        let starts = line_starts(source);
        // Line 1 = "one\r", line 2 = "two\r", line 3 = "three" (no trailing newline).
        assert_eq!(starts, vec![0, 5, 10]);
        assert_eq!(
            line_range_to_byte_range(&starts, source.len(), 1, 2),
            Some((0, 5))
        );
        assert_eq!(
            line_range_to_byte_range(&starts, source.len(), 3, 4),
            Some((10, 15))
        );
        assert_eq!(
            line_range_to_byte_range(&starts, source.len(), 2, 4),
            Some((5, 15))
        );
        // A start line past the end of the file maps to nothing, not a panic.
        assert_eq!(line_range_to_byte_range(&starts, source.len(), 9, 10), None);
        // Line zero is never valid (lines are 1-based).
        assert_eq!(line_range_to_byte_range(&starts, source.len(), 0, 1), None);
    }

    #[test]
    fn byte_overlap_matches_half_open_semantics() {
        let span = ByteSpan { start: 10, end: 20 };
        assert!(byte_ranges_overlap(span, 5, 11), "overlaps at the start");
        assert!(byte_ranges_overlap(span, 19, 25), "overlaps at the end");
        assert!(byte_ranges_overlap(span, 10, 20), "identical range");
        assert!(
            !byte_ranges_overlap(span, 0, 10),
            "touches but does not overlap"
        );
        assert!(
            !byte_ranges_overlap(span, 20, 30),
            "touches but does not overlap"
        );
        assert!(!byte_ranges_overlap(span, 0, 5), "entirely before");
        assert!(!byte_ranges_overlap(span, 25, 30), "entirely after");
    }
}
