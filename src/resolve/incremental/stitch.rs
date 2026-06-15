// SPDX-License-Identifier: Apache-2.0

//! Cross-file (stitch) Tier-B resolution.
//!
//! The per-file phase defers every cross-file reference as a [`PendingRef`].
//! This phase resolves them against a [`GlobalIndex`] — a leaf-name → SymbolIds
//! map that owns its ids so a future incremental store can maintain it across
//! edits. Each pending ref becomes at most one [`Confidence::Exact`] edge, only
//! when its `(name, segs)` lookup has a UNIQUE match — Tier-B never fakes
//! precision (zero or ambiguous → no edge).

use std::collections::HashMap;

use crate::graph::types::{Confidence, Edge, Provenance, Symbol};
use crate::symbol::SymbolId;

use super::super::namespaces_end_with;
use super::subgraph::PendingRef;

/// Global definition index: leaf name → the SymbolIds sharing that name.
/// Mirrors the `by_name` map the batch resolver builds, but owns SymbolIds so
/// it can be maintained incrementally (next unit adds add/remove).
pub(crate) struct GlobalIndex {
    by_name: HashMap<String, Vec<SymbolId>>,
}

impl GlobalIndex {
    /// An empty index (incremental path: grown by [`insert_symbols`]).
    ///
    /// [`insert_symbols`]: GlobalIndex::insert_symbols
    pub(crate) fn new() -> Self {
        Self {
            by_name: HashMap::new(),
        }
    }

    /// Build from the full symbol set (batch path).
    pub(crate) fn from_symbols(symbols: &[Symbol]) -> Self {
        let mut idx = Self::new();
        idx.insert_symbols(symbols);
        idx
    }

    /// Add `symbols` to the index: each symbol with a leaf name is pushed under
    /// that name. The incremental store calls this whenever a file's subgraph is
    /// (re)built — same mapping [`from_symbols`] uses, applied incrementally.
    ///
    /// [`from_symbols`]: GlobalIndex::from_symbols
    pub(crate) fn insert_symbols(&mut self, symbols: &[Symbol]) {
        for s in symbols {
            if let Some(n) = s.id.leaf_name() {
                self.by_name
                    .entry(n.to_string())
                    .or_default()
                    .push(s.id.clone());
            }
        }
    }

    /// Remove `symbols` from the index: for each symbol with a leaf name, drop
    /// ONE entry equal to its id from that name's bucket. The incremental store
    /// calls this before re-building a changed file's subgraph, so the index
    /// reflects only the current file set.
    ///
    /// Order within a bucket is irrelevant — [`unique_match`] is order-independent
    /// and returns `None` on ambiguity — so removal uses `swap_remove`. A bucket
    /// that empties is dropped so the map never leaks empty keys.
    ///
    /// [`unique_match`]: GlobalIndex::unique_match
    pub(crate) fn remove_symbols(&mut self, symbols: &[Symbol]) {
        for s in symbols {
            if let Some(n) = s.id.leaf_name() {
                if let Some(bucket) = self.by_name.get_mut(n) {
                    if let Some(pos) = bucket.iter().position(|id| id == &s.id) {
                        bucket.swap_remove(pos);
                    }
                    if bucket.is_empty() {
                        self.by_name.remove(n);
                    }
                }
            }
        }
    }

    /// The UNIQUE SymbolId whose leaf name is `name` and whose namespace chain
    /// ends with `segs`; `None` if zero or two-or-more candidates match (never
    /// fake precision).
    fn unique_match(&self, name: &str, segs: &[String]) -> Option<&SymbolId> {
        self.by_name.get(name).and_then(|cands| {
            let mut it = cands.iter().filter(|id| namespaces_end_with(id, segs));
            match (it.next(), it.next()) {
                (Some(only), None) => Some(only), // exactly one match
                _ => None,                        // zero or ambiguous → no edge
            }
        })
    }
}

impl Default for GlobalIndex {
    fn default() -> Self {
        Self::new()
    }
}

/// Resolve all pending cross-file refs into edges via the global index. One
/// [`Confidence::Exact`] [`Provenance::ScopeGraph`] edge per unique match.
pub(crate) fn stitch(pending: &[PendingRef], index: &GlobalIndex) -> Vec<Edge> {
    let mut edges = Vec::new();
    for p in pending {
        if let Some(matched_id) = index.unique_match(&p.name, &p.segs) {
            edges.push(Edge {
                from: p.from.clone(),
                to: matched_id.clone(),
                role: p.role,
                confidence: Confidence::Exact,
                provenance: Provenance::ScopeGraph,
                occ: p.occ.clone(),
            });
        }
    }
    edges
}

#[cfg(test)]
mod tests {
    use super::super::subgraph::build_subgraph;
    use super::*;
    use crate::extract::{Extractor, RustExtractor};

    /// Insert-then-remove returns the index to a not-matching state: a name that
    /// resolved uniquely before insertion no longer does after the matching
    /// symbol is removed. This guards the incremental-maintenance contract the
    /// store relies on.
    #[test]
    fn insert_then_remove_restores_no_match() {
        // `conf::Config` defines the only `Config`; `app` imports it.
        let conf = RustExtractor
            .extract("pub struct Config {}", "src/conf.rs")
            .unwrap();
        let app = RustExtractor
            .extract("use conf::Config;\npub fn run() {}", "src/app.rs")
            .unwrap();

        let conf_sub = build_subgraph(&conf);
        let app_sub = build_subgraph(&app);

        // With conf indexed, the import resolves to exactly one edge.
        let mut index = GlobalIndex::new();
        index.insert_symbols(&conf_sub.symbols);
        let edges = stitch(&app_sub.pending, &index);
        assert_eq!(
            edges.len(),
            1,
            "import must resolve while conf::Config is indexed"
        );

        // Remove conf's symbols → the name no longer matches anything.
        index.remove_symbols(&conf_sub.symbols);
        let edges = stitch(&app_sub.pending, &index);
        assert!(
            edges.is_empty(),
            "after removing conf::Config the import must resolve to no edge"
        );
    }
}
