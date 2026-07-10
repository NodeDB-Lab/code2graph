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

use std::collections::{HashMap, HashSet};

use crate::graph::types::{Edge, Provenance, RefRole, Symbol, SymbolKind};
use crate::symbol::SymbolId;

use super::super::{enclosing_path_ends_with, namespaces_end_with};
use super::subgraph::PendingRef;

/// Global definition index: leaf name → the SymbolIds sharing that name.
/// Mirrors the `by_name` map the batch resolver builds, but owns SymbolIds so
/// it can be maintained incrementally (next unit adds add/remove).
#[derive(Default)]
pub(crate) struct GlobalIndex {
    by_name: HashMap<String, HashSet<SymbolId>>,
    /// Module-name → the module SymbolIds sharing that name. Kept separate from
    /// `by_name` because module symbols have a `Namespace`-only id (no leaf
    /// name, so they never land in `by_name`) and because a `ModuleRef` must
    /// resolve ONLY to a module — never to a same-named function, and vice
    /// versa. Keyed by the module's `name` field (the last `Namespace` segment).
    modules_by_name: HashMap<String, HashSet<SymbolId>>,
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
            // A module belongs exclusively to the module target domain. Ordinary
            // calls/reads/writes/imports must never become ambiguous because a
            // same-named module exists.
            if s.kind == SymbolKind::Module {
                self.modules_by_name
                    .entry(s.name.clone())
                    .or_default()
                    .insert(s.id.clone());
            } else if let Some(n) = s.id.leaf_name() {
                self.by_name
                    .entry(n.to_string())
                    .or_default()
                    .insert(s.id.clone());
            }
        }
    }

    /// Remove `symbols` from the index: for each symbol with a leaf name, drop
    /// ONE entry equal to its id from that name's bucket. The incremental store
    /// calls this before re-building a changed file's subgraph, so the index
    /// reflects only the current file set.
    ///
    /// Order within a bucket is irrelevant — [`unique_match`] is order-independent
    /// and returns `None` on ambiguity — so hash-set removal is O(1). A bucket
    /// that empties is dropped so the map never leaks empty keys.
    ///
    /// [`unique_match`]: GlobalIndex::unique_match
    pub(crate) fn remove_symbols(&mut self, symbols: &[Symbol]) {
        for s in symbols {
            // Mirror `insert_symbols`: modules live only in `modules_by_name`.
            if s.kind == SymbolKind::Module {
                if let Some(bucket) = self.modules_by_name.get_mut(&s.name) {
                    bucket.remove(&s.id);
                    if bucket.is_empty() {
                        self.modules_by_name.remove(&s.name);
                    }
                }
            }
            if s.kind != SymbolKind::Module {
                if let Some(n) = s.id.leaf_name() {
                    if let Some(bucket) = self.by_name.get_mut(n) {
                        bucket.remove(&s.id);
                        if bucket.is_empty() {
                            self.by_name.remove(n);
                        }
                    }
                }
            }
        }
    }

    /// The UNIQUE SymbolId whose leaf name is `name` and whose namespace chain
    /// ends with `segs`; `None` if zero or two-or-more candidates match (never
    /// fake precision). Empty `segs` matches by name alone (used by cross-artifact
    /// `TypeRef`s, whose target may live in a different artifact's namespace) —
    /// uniqueness still decides, so precision is preserved.
    fn unique_match(&self, name: &str, segs: &[String]) -> Option<&SymbolId> {
        self.by_name.get(name).and_then(|cands| {
            let mut it = cands
                .iter()
                .filter(|id| segs.is_empty() || namespaces_end_with(id, segs));
            match (it.next(), it.next()) {
                (Some(only), None) => Some(only), // exactly one match
                _ => None,                        // zero or ambiguous → no edge
            }
        })
    }

    /// Like [`unique_match`](GlobalIndex::unique_match) but for an EXPLICITLY
    /// qualified call: the qualifier may name an enclosing *type* (a Ruby
    /// `module`, Kotlin `object`, or class — a `Type` descriptor) as well as a
    /// namespace, so candidates match when their chain ends with `segs` by EITHER
    /// the namespace-only rule OR the full enclosing-descriptor rule. The `||`
    /// only widens the candidate set; uniqueness still decides, so a type-qualified
    /// call to an ambiguous name yields no edge (precision is never faked).
    fn unique_qualified_match(&self, name: &str, segs: &[String]) -> Option<&SymbolId> {
        self.by_name.get(name).and_then(|cands| {
            let mut it = cands
                .iter()
                .filter(|id| namespaces_end_with(id, segs) || enclosing_path_ends_with(id, segs));
            match (it.next(), it.next()) {
                (Some(only), None) => Some(only),
                _ => None,
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
            // HCL and similar DSLs use type-like references to modules. Prefer
            // a unique module target, then retain ordinary type lookup.
            RefRole::TypeRef => index
                .unique_module_match(&p.name, &p.segs)
                .or_else(|| index.unique_match(&p.name, &p.segs)),
            _ if p.qualified => index.unique_qualified_match(&p.name, &p.segs),
            _ => index.unique_match(&p.name, &p.segs),
        };
        if let Some(matched_id) = matched {
            // A definition never links to itself (parity with Tier-A, which skips
            // `i == from_idx`). An unqualified same-namespace ref whose unique
            // match is the caller's own id (e.g. a recursive free function)
            // would otherwise produce a `from == to` self-edge.
            if *matched_id == p.from {
                continue;
            }
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

    /// A pending ref whose unique match is the caller's OWN id must NOT produce a
    /// `from == to` self-edge — parity with Tier-A, which skips `i == from_idx`.
    /// This is reachable for unqualified same-namespace recursion: a definition
    /// deferred to stitch whose only same-name candidate in its namespace is
    /// itself.
    #[test]
    fn pending_ref_to_own_id_yields_no_self_edge() {
        use crate::graph::types::{Confidence, Occurrence};

        // A single-file recursive free function: `Run` in `package main` calls
        // `Run`. Its own definition is the sole same-name target in the namespace.
        let recurse = RustExtractor
            .extract("pub fn recurse() { recurse() }", "src/main.rs")
            .unwrap();
        let sub = build_subgraph(&recurse);

        // The caller's own SymbolId (the `recurse` definition).
        let own_id = sub
            .symbols
            .iter()
            .find(|s| s.id.leaf_name() == Some("recurse"))
            .map(|s| s.id.clone())
            .expect("recurse must be defined");

        // Index only this file's symbols, then hand stitch a pending ref whose
        // unique match IS the caller — exactly what an unqualified same-namespace
        // self-recursive deferral produces.
        let mut index = GlobalIndex::new();
        index.insert_symbols(&sub.symbols);
        let pending = vec![PendingRef {
            from: own_id.clone(),
            name: "recurse".to_string(),
            segs: Vec::new(),
            role: RefRole::Call,
            occ: Occurrence {
                file: "src/main.rs".to_string(),
                line: 1,
                col: 0,
                byte: 20,
            },
            confidence: Confidence::Scoped,
            qualified: false,
        }];

        let edges = stitch(&pending, &index);
        assert!(
            edges.iter().all(|e| e.from != e.to),
            "stitch must not emit a from == to self-edge"
        );
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

    #[test]
    fn callable_lookup_stays_unique_when_a_module_has_the_same_name() {
        let lib = RustExtractor
            .extract(
                "mod helper;\nuse helper::helper;\npub fn run() { helper(); }",
                "src/lib.rs",
            )
            .unwrap();
        let helper = RustExtractor
            .extract("pub fn helper() {}", "src/helper.rs")
            .unwrap();
        let lib_sub = build_subgraph(&lib);
        let helper_sub = build_subgraph(&helper);

        let mut index = GlobalIndex::new();
        index.insert_symbols(&lib_sub.symbols);
        index.insert_symbols(&helper_sub.symbols);
        let edges = stitch(&lib_sub.pending, &index);

        let calls: Vec<_> = edges
            .iter()
            .filter(|edge| edge.role == RefRole::Call)
            .collect();
        assert_eq!(
            calls.len(),
            1,
            "a unique callable must not become ambiguous because of a same-named module"
        );
        let callable = helper_sub
            .symbols
            .iter()
            .find(|symbol| symbol.kind == SymbolKind::Function && symbol.name == "helper")
            .expect("helper function extracted");
        assert_eq!(calls[0].to, callable.id);

        let module_refs: Vec<_> = edges
            .iter()
            .filter(|edge| edge.role == RefRole::ModuleRef)
            .collect();
        assert!(
            !module_refs.is_empty(),
            "the module reference must still resolve"
        );
        let module = helper_sub
            .symbols
            .iter()
            .find(|symbol| symbol.kind == SymbolKind::Module)
            .expect("helper module extracted");
        assert!(module_refs.iter().all(|edge| edge.to == module.id));
    }
}
