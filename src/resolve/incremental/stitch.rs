// SPDX-License-Identifier: Apache-2.0

//! Cross-file (stitch) Tier-B resolution.
//!
//! The per-file phase defers every cross-file reference as a [`PendingRef`].
//! This phase resolves them against a [`GlobalIndex`] — a leaf-name → SymbolIds
//! map that owns its ids so a future incremental store can maintain it across
//! edits. Each pending ref becomes at most one edge, carrying the ref's own
//! [`Confidence`](crate::graph::types::Confidence), only when its `(name, segs)`
//! lookup has a UNIQUE match — Tier-B never fakes precision (zero or ambiguous →
//! no edge).

use std::collections::HashMap;

use crate::graph::types::{Edge, Provenance, RefRole, Symbol, SymbolKind};
use crate::symbol::SymbolId;

use super::super::namespaces_end_with;
use super::subgraph::PendingRef;

/// Global definition index: leaf name → the SymbolIds sharing that name.
/// Mirrors the `by_name` map the batch resolver builds, but owns SymbolIds so
/// it can be maintained incrementally (next unit adds add/remove).
#[derive(Default)]
pub(crate) struct GlobalIndex {
    by_name: HashMap<String, Vec<SymbolId>>,
    /// Module-name → the module SymbolIds sharing that name. Kept separate from
    /// `by_name` because module symbols have a `Namespace`-only id (no leaf
    /// name, so they never land in `by_name`) and because a `ModuleRef` must
    /// resolve ONLY to a module — never to a same-named function, and vice
    /// versa. Keyed by the module's `name` field (the last `Namespace` segment).
    modules_by_name: HashMap<String, Vec<SymbolId>>,
}

impl GlobalIndex {
    /// An empty index (incremental path: grown by [`insert_symbols`]).
    ///
    /// [`insert_symbols`]: GlobalIndex::insert_symbols
    pub(crate) fn new() -> Self {
        Self {
            by_name: HashMap::new(),
            modules_by_name: HashMap::new(),
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
            // Module symbols are ALSO indexed by module name in a separate index
            // so a `ModuleRef` can match ONLY modules. They additionally keep
            // their normal `by_name` entry below (when they carry a leaf name, as
            // some languages' module symbols do) so non-`ModuleRef` references
            // that target a module — e.g. an HCL `module.vpc.id` TypeRef — still
            // resolve.
            if s.kind == SymbolKind::Module {
                self.modules_by_name
                    .entry(s.name.clone())
                    .or_default()
                    .push(s.id.clone());
            }
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
            // Mirror `insert_symbols`: a module symbol is dropped from
            // `modules_by_name` AND (if it carried a leaf name) from `by_name`.
            if s.kind == SymbolKind::Module {
                if let Some(bucket) = self.modules_by_name.get_mut(&s.name) {
                    if let Some(pos) = bucket.iter().position(|id| id == &s.id) {
                        bucket.swap_remove(pos);
                    }
                    if bucket.is_empty() {
                        self.modules_by_name.remove(&s.name);
                    }
                }
            }
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

    /// Like [`unique_match`](GlobalIndex::unique_match) but over the module
    /// index: the UNIQUE [`SymbolKind::Module`] symbol named `name` whose
    /// namespace chain ends with `segs`. `None` if zero or two-or-more candidates
    /// match — a `ModuleRef` to an ambiguous module name yields no edge.
    fn unique_module_match(&self, name: &str, segs: &[String]) -> Option<&SymbolId> {
        self.modules_by_name.get(name).and_then(|cands| {
            // Empty `segs` = match by module name alone (no namespace-suffix
            // constraint); `namespaces_end_with` returns `false` for empty segs,
            // so accept all candidates in that case and let uniqueness decide.
            let mut it = cands
                .iter()
                .filter(|id| segs.is_empty() || namespaces_end_with(id, segs));
            match (it.next(), it.next()) {
                (Some(only), None) => Some(only), // exactly one match
                _ => None,                        // zero or ambiguous → no edge
            }
        })
    }
}

/// Resolve all pending cross-file refs into edges via the global index. One
/// [`Provenance::ScopeGraph`] edge per unique match, stamped with the pending
/// ref's own [`Confidence`](crate::graph::types::Confidence) (Exact for
/// explicit written paths, Scoped for an
/// unqualified same-namespace cross-file match).
pub(crate) fn stitch(pending: &[PendingRef], index: &GlobalIndex) -> Vec<Edge> {
    let mut edges = Vec::new();
    for p in pending {
        // ModuleRefs resolve ONLY against the module index; everything else
        // resolves ONLY against the leaf-name index. This keeps the two kinds of
        // match disjoint — a ModuleRef can never bind a function, nor a Call a module.
        let matched = match p.role {
            RefRole::ModuleRef => index.unique_module_match(&p.name, &p.segs),
            _ => index.unique_match(&p.name, &p.segs),
        };
        if let Some(matched_id) = matched {
            edges.push(Edge {
                from: p.from.clone(),
                to: matched_id.clone(),
                role: p.role,
                confidence: p.confidence,
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

        // With conf indexed, the `Config` import resolves to exactly one edge.
        // (The `use conf::Config;` path also yields a `ModuleRef` for the `conf`
        // segment, which resolves to conf's module symbol — so we filter to the
        // Import role to assert the import contract specifically.)
        use crate::graph::types::RefRole;
        let mut index = GlobalIndex::new();
        index.insert_symbols(&conf_sub.symbols);
        let edges = stitch(&app_sub.pending, &index);
        assert_eq!(
            edges.iter().filter(|e| e.role == RefRole::Import).count(),
            1,
            "import must resolve while conf::Config is indexed"
        );

        // Remove conf's symbols → neither the import nor the module ref matches.
        index.remove_symbols(&conf_sub.symbols);
        let edges = stitch(&app_sub.pending, &index);
        assert!(
            edges.is_empty(),
            "after removing conf's symbols, nothing must resolve"
        );
    }

    /// `lib.rs` with `mod util;` and `util.rs` defining an item: the ModuleRef
    /// resolves to EXACTLY ONE ScopeGraph edge targeting util's module symbol.
    #[test]
    fn module_ref_resolves_to_module_symbol() {
        let lib = RustExtractor
            .extract("mod util;\npub fn run() {}", "src/lib.rs")
            .unwrap();
        let util = RustExtractor
            .extract("pub fn helper() {}", "src/util.rs")
            .unwrap();

        let lib_sub = build_subgraph(&lib);
        let util_sub = build_subgraph(&util);

        let mut index = GlobalIndex::new();
        index.insert_symbols(&lib_sub.symbols);
        index.insert_symbols(&util_sub.symbols);

        let edges = stitch(&lib_sub.pending, &index);
        assert_eq!(edges.len(), 1, "mod util; must resolve to exactly one edge");
        let edge = &edges[0];
        assert_eq!(edge.role, RefRole::ModuleRef);
        assert_eq!(edge.provenance, Provenance::ScopeGraph);

        // Target must be util.rs's module symbol (Namespace-only, named "util").
        let util_module = util_sub
            .symbols
            .iter()
            .find(|s| s.kind == SymbolKind::Module)
            .expect("util.rs has a module symbol");
        assert_eq!(edge.to, util_module.id);
    }

    /// Precision: a ModuleRef whose name also matches a FUNCTION (not a module)
    /// in another file must NOT resolve to that function — no false edge.
    #[test]
    fn module_ref_does_not_resolve_to_function() {
        // `lib.rs` declares `mod config;` but NO file defines a `config` module;
        // instead another file defines a *function* named `config`.
        let lib = RustExtractor
            .extract("mod config;\npub fn run() {}", "src/lib.rs")
            .unwrap();
        let other = RustExtractor
            .extract("pub fn config() {}", "src/other.rs")
            .unwrap();

        let lib_sub = build_subgraph(&lib);
        let other_sub = build_subgraph(&other);

        let mut index = GlobalIndex::new();
        index.insert_symbols(&lib_sub.symbols);
        index.insert_symbols(&other_sub.symbols);

        let edges = stitch(&lib_sub.pending, &index);
        // The only module named "config" is lib.rs's own decl — but a ModuleRef
        // resolves against OTHER files' module symbols; there is no `config`
        // module symbol from another file, and the `config` function must never match.
        for e in &edges {
            assert_ne!(
                e.role,
                RefRole::ModuleRef,
                "ModuleRef(config) must not resolve to the `config` function"
            );
        }
    }

    /// Ambiguity: two distinct modules both named `util` → a ModuleRef to `util`
    /// resolves to no edge (Tier-B never fakes precision).
    #[test]
    fn module_ref_ambiguous_name_no_edge() {
        let lib = RustExtractor
            .extract("mod util;\npub fn run() {}", "src/lib.rs")
            .unwrap();
        // Two files whose module symbols are both named "util".
        let util_a = RustExtractor
            .extract("pub fn a() {}", "src/a/util.rs")
            .unwrap();
        let util_b = RustExtractor
            .extract("pub fn b() {}", "src/b/util.rs")
            .unwrap();

        let lib_sub = build_subgraph(&lib);
        let a_sub = build_subgraph(&util_a);
        let b_sub = build_subgraph(&util_b);

        let mut index = GlobalIndex::new();
        index.insert_symbols(&lib_sub.symbols);
        index.insert_symbols(&a_sub.symbols);
        index.insert_symbols(&b_sub.symbols);

        let module_refs = stitch(&lib_sub.pending, &index)
            .into_iter()
            .filter(|e| e.role == RefRole::ModuleRef)
            .count();
        assert_eq!(
            module_refs, 0,
            "two modules named `util` → ModuleRef must resolve to no edge"
        );
    }
}
