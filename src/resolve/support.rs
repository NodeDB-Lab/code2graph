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
/// Generic over the segment string type (`&str`, `String`, …) so callers can
/// match against borrowed path slices or owned segment vectors without an
/// intermediate `Vec<&str>` conversion.
///
/// Example: candidate namespaces `["com", "example"]` with `segs = ["example"]`
/// → true. With `segs = ["com", "example"]` → true. With `segs = ["other"]` → false.
pub(crate) fn namespaces_end_with<S: AsRef<str>>(candidate: &SymbolId, segs: &[S]) -> bool {
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
        .all(|(a, b)| a == b.as_ref())
}

/// Whether `candidate`'s **enclosing descriptor chain** (every descriptor except
/// the leaf, all kinds — namespaces *and* types) ends with `segs`.
///
/// This is the type-aware counterpart of [`namespaces_end_with`], used only for
/// explicitly-qualified calls where the qualifier may name an enclosing *type*
/// (a Ruby `module`/Kotlin `object`/class) rather than a namespace — e.g.
/// `Alpha.compute` resolving to `…/Alpha#compute().` where `Alpha` is a `Type`
/// descriptor. Callers OR this with [`namespaces_end_with`], so it only ever
/// *adds* matches; the call site's uniqueness check preserves precision.
pub(crate) fn enclosing_path_ends_with<S: AsRef<str>>(candidate: &SymbolId, segs: &[S]) -> bool {
    if segs.is_empty() {
        return false;
    }
    let names: Vec<&str> = candidate.descriptor_names_iter().collect();
    // Drop the leaf: the qualifier names a *container*, never the called member.
    let containers = match names.split_last() {
        Some((_leaf, rest)) if !rest.is_empty() => rest,
        _ => return false,
    };
    if segs.len() > containers.len() {
        return false;
    }
    containers[containers.len() - segs.len()..]
        .iter()
        .zip(segs.iter())
        .all(|(a, b)| *a == b.as_ref())
}
