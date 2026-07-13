// SPDX-License-Identifier: Apache-2.0

//! Shared helpers used by more than one resolver.
//!
//! Resolver-internal utilities that don't belong to any single tier. Kept here
//! so Tier-A and Tier-B share one definition of caller attribution.

use std::collections::{HashMap, HashSet};

use crate::graph::types::{FileFacts, Symbol};
use crate::symbol::SymbolId;

/// Deduplicate `files` by their `file` key, keeping the **last** occurrence of
/// each key and preserving the original slice order otherwise.
///
/// A file path identifies a unique source, so two [`FileFacts`] with the same
/// `file` are competing versions of one file — last-wins matches the
/// [`IncrementalGraph`] store's upsert semantics (re-upserting a key replaces
/// it). Applying this at the batch resolver entry points keeps batch output
/// identical to the incremental store on duplicate keys and stops the resolver
/// from emitting two [`Symbol`]s with the SAME [`SymbolId`] (a duplicate
/// identity, since the id derives from the file path plus descriptors).
///
/// Deterministic and independent of `HashMap` iteration order: the map only
/// records the last index per key; the kept set and its order come from the
/// in-order slice walk.
///
/// [`IncrementalGraph`]: crate::resolve::IncrementalGraph
/// [`SymbolId`]: crate::symbol::SymbolId
pub(crate) fn dedup_files_last_wins(files: &[FileFacts]) -> Vec<&FileFacts> {
    let mut last: HashMap<&str, usize> = HashMap::new();
    for (i, f) in files.iter().enumerate() {
        last.insert(f.file.as_str(), i);
    }
    files
        .iter()
        .enumerate()
        .filter(|(i, f)| last[f.file.as_str()] == *i)
        .map(|(_, f)| f)
        .collect()
}

/// Keep only the first occurrence of each [`SymbolId`] in `symbols`, in place.
///
/// A `CodeGraph` must contain exactly one node per `SymbolId`: a Go/Java
/// package can span multiple files, each emitting the same namespace-only
/// package symbol. Call this before building any index that references
/// `symbols` by position.
pub(crate) fn retain_first_symbol_by_id(symbols: &mut Vec<Symbol>) {
    let mut seen = HashSet::with_capacity(symbols.len());
    symbols.retain(|s| seen.insert(s.id.clone()));
}

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

#[cfg(all(test, feature = "rust"))]
mod tests {
    use super::*;
    use crate::extract::{Extractor, RustExtractor};

    #[test]
    fn dedup_keeps_last_occurrence_in_slice_order() {
        // Same path `a` appears twice (v1, v2) with `b` between; the kept set must
        // be `[b, a(v2)]` — `b` in place, the LAST `a` standing in for the first.
        let a_v1 = RustExtractor
            .extract("pub fn one() {}", "src/a.rs")
            .unwrap();
        let b = RustExtractor
            .extract("pub fn two() {}", "src/b.rs")
            .unwrap();
        let a_v2 = RustExtractor
            .extract("pub fn three() {}", "src/a.rs")
            .unwrap();

        let files = vec![a_v1, b, a_v2];
        let kept = dedup_files_last_wins(&files);

        // Two distinct keys survive, order-stable: `src/b.rs` then `src/a.rs`.
        let kept_keys: Vec<&str> = kept.iter().map(|f| f.file.as_str()).collect();
        assert_eq!(kept_keys, vec!["src/b.rs", "src/a.rs"]);

        // The surviving `src/a.rs` is the LAST version (v2 → defines `three`).
        let a_kept = kept
            .iter()
            .find(|f| f.file == "src/a.rs")
            .expect("src/a.rs must survive");
        assert!(
            a_kept
                .symbols
                .iter()
                .any(|s| s.id.to_scip_string().ends_with("three().")),
            "last-wins must keep v2 (defines `three`), got: {:?}",
            a_kept
                .symbols
                .iter()
                .map(|s| s.id.to_scip_string())
                .collect::<Vec<_>>()
        );
    }
}
