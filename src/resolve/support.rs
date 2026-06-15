// SPDX-License-Identifier: Apache-2.0

//! Shared helpers used by more than one resolver.
//!
//! Resolver-internal utilities that don't belong to any single tier. Kept here
//! so Tier-A and Tier-B share one definition of caller attribution.

use crate::graph::types::Symbol;
use crate::symbol::SymbolId;

/// Index (into `symbols`) of the innermost symbol whose span contains `byte`,
/// considering only the symbols listed in `file_indices`. `None` if no symbol
/// encloses the byte. Innermost = smallest containing span.
pub(crate) fn enclosing_symbol_index(
    symbols: &[Symbol],
    file_indices: &[usize],
    byte: usize,
) -> Option<usize> {
    file_indices
        .iter()
        .copied()
        .filter(|&i| symbols[i].span.contains(byte))
        .min_by_key(|&i| symbols[i].span.len())
}

/// Normalise a raw import path string into a sequence of non-empty, non-anchor
/// segment slices.
///
/// Splits on `.`, `/`, and `:` (so `pkg.models`, `std::io`, `./svc`, and
/// `com/example` all decompose correctly). Filters out empty segments and the
/// path-anchor keywords `"."`, `".."`, `"crate"`, `"self"`, and `"super"`.
/// Returns `&str` slices into the original string — no new allocations.
pub(crate) fn normalize_from_path(path: &str) -> Vec<&str> {
    path.split(['.', '/', ':'])
        .filter(|s| !s.is_empty() && !matches!(*s, "." | ".." | "crate" | "self" | "super"))
        .collect()
}

/// Returns `true` iff `segs` is non-empty and the candidate's namespace chain
/// (as returned by [`SymbolId::namespaces_iter`]) **ends with** `segs`.
///
/// Example: candidate namespaces `["com", "example"]` with `segs = ["example"]`
/// → true. With `segs = ["com", "example"]` → true. With `segs = ["other"]` → false.
pub(crate) fn namespaces_end_with(candidate: &SymbolId, segs: &[&str]) -> bool {
    if segs.is_empty() {
        return false;
    }
    let n = candidate.namespaces_iter().count();
    if segs.len() > n {
        return false;
    }
    candidate
        .namespaces_iter()
        .skip(n - segs.len())
        .zip(segs.iter())
        .all(|(a, b)| a == *b)
}
