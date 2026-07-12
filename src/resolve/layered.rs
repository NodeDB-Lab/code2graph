// SPDX-License-Identifier: Apache-2.0

//! [`LayeredResolver`] — unions multiple resolvers into one dense-by-default
//! graph, deduplicating edges by confidence so the highest-precision resolution
//! always wins, while distinct provenances at the same confidence tier are both
//! preserved.

use std::collections::{HashMap, HashSet};

use crate::graph::types::{CodeGraph, Confidence, Edge, FileFacts, RefRole, Symbol};

use super::{
    ConformanceResolver, ExternalResolver, FfiBridgeResolver, NormalizedNameResolver, Resolver,
    ScopeGraphResolver, SymbolTableResolver,
};

/// A resolver that runs a stack of inner resolvers in order and merges their
/// outputs into a single [`CodeGraph`].
///
/// **Symbol dedup**: symbols that appear in multiple layers are deduplicated by
/// structural [`SymbolId`](crate::symbol::SymbolId) identity; the first occurrence
/// wins and insertion order is preserved.
///
/// **Edge dedup**: edges sharing the same `(from, to, role, file, byte)` key are
/// treated as the "same fact" resolved at potentially different confidence or by
/// different analysis passes.  The rule is:
/// - Only edges at the *maximum* confidence for that key are kept.
/// - Among those max-confidence edges, distinct [`Provenance`](crate::graph::Provenance) values are all
///   kept (provenance is orthogonal to confidence).
/// - Exact duplicates (same key **and** same provenance) are collapsed to one.
///
/// The output order is deterministic: first-seen order across the flattened
/// in-order edge list (layer 0 first, layer 1 next, …).
pub struct LayeredResolver {
    layers: Vec<Box<dyn Resolver>>,
}

impl LayeredResolver {
    /// Build a `LayeredResolver` from an arbitrary ordered list of inner resolvers.
    pub fn new(layers: Vec<Box<dyn Resolver>>) -> Self {
        Self { layers }
    }

    /// The default dense stack:
    /// 1. [`SymbolTableResolver`] — fast, broad, recall-first.
    /// 2. [`ScopeGraphResolver`] — scope-precise, emits `Exact`/`Scoped`.
    /// 3. [`FfiBridgeResolver`] — cross-language FFI edges.
    /// 4. [`ConformanceResolver`] — inherited/implemented-member recall over the
    ///    type hierarchy (additive `Scoped` edges, `Provenance::Conformance`).
    /// 5. [`ExternalResolver`] — SCA reachability: import-backed calls into
    ///    dependency code become edges to minted external symbols
    ///    (`NameOnly`, `Provenance::External`). More grounded than case-fold
    ///    heuristics; placed before `NormalizedNameResolver`.
    /// 6. [`NormalizedNameResolver`] — case-folded name matching, lowest-tier
    ///    recall (`Heuristic`). Adds only references that differ from the
    ///    definition by case; exact-case matches are already covered above.
    pub fn default_dense() -> Self {
        Self::new(vec![
            Box::new(SymbolTableResolver),
            Box::new(ScopeGraphResolver),
            Box::new(FfiBridgeResolver),
            Box::new(ConformanceResolver),
            Box::new(ExternalResolver),
            Box::new(NormalizedNameResolver),
        ])
    }
}

impl Resolver for LayeredResolver {
    fn resolve(&self, files: &[FileFacts]) -> crate::Result<CodeGraph> {
        crate::validate_file_facts(files)?;
        // ── 1. Run every layer ──────────────────────────────────────────────
        let graphs: Vec<CodeGraph> = self
            .layers
            .iter()
            .map(|r| r.resolve(files))
            .collect::<crate::Result<_>>()?;

        // ── 2. Symbol union — dedup by complete structural identity ────────
        let mut seen_syms: HashSet<crate::symbol::SymbolId> = HashSet::new();
        let mut symbols: Vec<Symbol> = Vec::new();
        for g in &graphs {
            for sym in &g.symbols {
                if seen_syms.insert(sym.id.clone()) {
                    symbols.push(sym.clone());
                }
            }
        }

        // ── 3. Edge union — confidence-preferring dedup ─────────────────────
        //
        // The dedup key uses structural SymbolIds so language/file context is
        // not erased by the standard SCIP presentation string.
        // `Occurrence` is `Eq` but not `Hash`, so we decompose it by hand.
        // `RefRole` is `Hash + Eq`; `Provenance` is `Hash + Eq`.

        type ResolutionKey = (
            crate::symbol::SymbolId,
            crate::symbol::SymbolId,
            RefRole,
            String,
            usize,
        );

        // Flatten all edges in layer order (layer 0 first) and compute each
        // edge's key once, shared across both passes.
        let all_edges: Vec<_> = graphs.iter().flat_map(|g| g.edges.iter()).collect();
        let keys: Vec<ResolutionKey> = all_edges
            .iter()
            .map(|e| {
                (
                    e.from.clone(),
                    e.to.clone(),
                    e.role,
                    e.occ.file.clone(),
                    e.occ.byte,
                )
            })
            .collect();

        // Pass 1: find max Confidence per key.
        let mut max_conf: HashMap<ResolutionKey, Confidence> = HashMap::new();
        for (key, e) in keys.iter().zip(all_edges.iter()) {
            if let Some(c) = max_conf.get_mut(key) {
                *c = (*c).max(e.confidence);
            } else {
                max_conf.insert(key.clone(), e.confidence);
            }
        }

        // Pass 2: iterate in original order; keep an edge iff:
        //   - its confidence equals the max for its key, AND
        //   - (key, provenance) has not already been emitted (exact-dupe guard).
        let mut seen_key_prov: HashSet<crate::graph::EdgeKey> = HashSet::new();
        let mut edges: Vec<Edge> = Vec::new();
        for (e, key) in all_edges.into_iter().zip(keys) {
            // Every key was inserted in pass 1; the `else` branch is unreachable
            // in practice but avoids any `.unwrap()` in non-test code.
            let Some(&max) = max_conf.get(&key) else {
                continue;
            };
            if e.confidence < max {
                continue;
            }
            // Same confidence: keep each distinct provenance once.
            if seen_key_prov.insert(e.key()) {
                edges.push(e.clone());
            }
        }

        Ok(CodeGraph { symbols, edges })
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::types::{
        ByteSpan, CodeGraph, Confidence, Edge, FileFacts, Occurrence, Provenance, RefRole, Symbol,
        SymbolKind, Visibility,
    };
    use crate::symbol::{Descriptor, SymbolId};

    // ── helpers shared across stub-based tests ────────────────────────────

    fn make_id(ns: &str, name: &str) -> SymbolId {
        SymbolId::global(
            "rust",
            vec![
                Descriptor::Namespace(ns.into()),
                Descriptor::Term(name.into()),
            ],
        )
    }

    fn make_symbol(ns: &str, name: &str) -> Symbol {
        Symbol {
            id: make_id(ns, name),
            name: name.into(),
            kind: SymbolKind::Function,
            visibility: Visibility::Public,
            entry_points: Vec::new(),
            file: format!("src/{ns}.rs"),
            line: 1,
            span: ByteSpan { start: 0, end: 10 },
            signature: format!("pub fn {name}()"),
        }
    }

    fn make_edge(
        from_ns: &str,
        from_name: &str,
        to_ns: &str,
        to_name: &str,
        confidence: Confidence,
        provenance: Provenance,
        byte: usize,
    ) -> Edge {
        Edge {
            from: make_id(from_ns, from_name),
            to: make_id(to_ns, to_name),
            role: RefRole::Call,
            confidence,
            provenance,
            occ: Occurrence {
                file: "src/caller.rs".into(),
                line: 1,
                col: 0,
                byte,
            },
        }
    }

    /// A stub `Resolver` that always returns a pre-canned `CodeGraph`.
    struct StubResolver(CodeGraph);

    impl Resolver for StubResolver {
        fn resolve(&self, _files: &[FileFacts]) -> crate::Result<CodeGraph> {
            Ok(self.0.clone())
        }
    }

    fn stub(graph: CodeGraph) -> Box<dyn Resolver> {
        Box::new(StubResolver(graph))
    }

    // ── Test 1: superset (real extractors) ───────────────────────────────────

    /// A `LayeredResolver::default_dense()` is a superset of `ScopeGraphResolver`
    /// for the same inputs: every edge produced by `ScopeGraphResolver` (matched
    /// by structural source/target identity and role) also appears in the layered output.
    #[cfg(feature = "rust")]
    #[test]
    fn layered_is_superset_of_scope_graph() {
        use crate::extract::{Extractor, RustExtractor};
        use crate::resolve::ScopeGraphResolver;

        let lib = RustExtractor
            .extract("pub fn helper() -> u32 { 1 }", "src/util.rs")
            .unwrap();
        let main = RustExtractor
            .extract("pub fn run() -> u32 { helper() }", "src/main.rs")
            .unwrap();

        let files = [lib, main];
        let scope_graph = ScopeGraphResolver.resolve(&files).unwrap();
        let layered = LayeredResolver::default_dense().resolve(&files).unwrap();

        for sg_edge in &scope_graph.edges {
            let found = layered.edges.iter().any(|le| {
                le.from == sg_edge.from && le.to == sg_edge.to && le.role == sg_edge.role
            });
            assert!(
                found,
                "layered graph is missing ScopeGraph edge: {} → {} ({:?})",
                sg_edge.from, sg_edge.to, sg_edge.role
            );
        }
    }

    // ── Test 2: confidence-preferring collision ───────────────────────────────

    /// When two stub resolvers emit the same (from, to, role, file, byte) edge at
    /// different confidence levels, the layered output keeps only the higher one.
    #[test]
    fn higher_confidence_wins_lower_is_dropped() {
        let low_edge = make_edge(
            "a",
            "run",
            "b",
            "helper",
            Confidence::NameOnly,
            Provenance::SymbolTable,
            10,
        );
        let high_edge = make_edge(
            "a",
            "run",
            "b",
            "helper",
            Confidence::Exact,
            Provenance::ScopeGraph,
            10,
        );

        let g1 = CodeGraph {
            symbols: vec![make_symbol("a", "run"), make_symbol("b", "helper")],
            edges: vec![low_edge],
        };
        let g2 = CodeGraph {
            symbols: vec![],
            edges: vec![high_edge],
        };

        let resolver = LayeredResolver::new(vec![stub(g1), stub(g2)]);
        let merged = resolver.resolve(&[]).unwrap();

        let call_edges: Vec<_> = merged
            .edges
            .iter()
            .filter(|e| e.role == RefRole::Call)
            .collect();

        // Exactly one edge: the Exact one.
        assert_eq!(
            call_edges.len(),
            1,
            "expected 1 edge after confidence dedup, got {}: {:?}",
            call_edges.len(),
            call_edges
                .iter()
                .map(|e| format!("{:?}/{:?}", e.confidence, e.provenance))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            call_edges[0].confidence,
            Confidence::Exact,
            "surviving edge must be the Exact one"
        );

        // The NameOnly edge for the same key must NOT be present.
        let has_name_only = merged
            .edges
            .iter()
            .any(|e| e.confidence == Confidence::NameOnly);
        assert!(
            !has_name_only,
            "strictly-lower-confidence NameOnly edge should be dropped"
        );
    }

    // ── Test 3: distinct provenance kept at same confidence ──────────────────

    /// Two stub resolvers emit the same edge key at the same (highest) confidence
    /// but different `Provenance` values: both must survive.
    #[test]
    fn same_confidence_different_provenance_both_kept() {
        let e1 = make_edge(
            "a",
            "run",
            "b",
            "helper",
            Confidence::Exact,
            Provenance::ScopeGraph,
            20,
        );
        let e2 = make_edge(
            "a",
            "run",
            "b",
            "helper",
            Confidence::Exact,
            Provenance::FfiBridge,
            20,
        );

        let g1 = CodeGraph {
            symbols: vec![],
            edges: vec![e1],
        };
        let g2 = CodeGraph {
            symbols: vec![],
            edges: vec![e2],
        };

        let resolver = LayeredResolver::new(vec![stub(g1), stub(g2)]);
        let merged = resolver.resolve(&[]).unwrap();

        let call_edges: Vec<_> = merged
            .edges
            .iter()
            .filter(|e| e.role == RefRole::Call)
            .collect();
        assert_eq!(
            call_edges.len(),
            2,
            "expected 2 edges (distinct provenance at same confidence); got {}: {:?}",
            call_edges.len(),
            call_edges
                .iter()
                .map(|e| format!("{:?}/{:?}", e.confidence, e.provenance))
                .collect::<Vec<_>>()
        );

        let provenances: HashSet<Provenance> = call_edges.iter().map(|e| e.provenance).collect();
        assert!(
            provenances.contains(&Provenance::ScopeGraph),
            "ScopeGraph provenance must be present"
        );
        assert!(
            provenances.contains(&Provenance::FfiBridge),
            "FfiBridge provenance must be present"
        );
    }

    // ── Test 4: symbol dedup ─────────────────────────────────────────────────

    /// Symbols that appear in multiple layers appear exactly once in the merged
    /// output (deduplicated by structural identity; first-seen wins).
    #[test]
    fn symbols_with_matching_descriptors_in_different_languages_both_survive() {
        let rust = make_symbol("util", "helper");
        let mut python = make_symbol("util", "helper");
        python.id = SymbolId::global(
            "python",
            vec![
                Descriptor::Namespace("util".into()),
                Descriptor::Term("helper".into()),
            ],
        );
        python.file = "util.py".into();

        let resolver = LayeredResolver::new(vec![
            stub(CodeGraph {
                symbols: vec![rust],
                edges: vec![],
            }),
            stub(CodeGraph {
                symbols: vec![python],
                edges: vec![],
            }),
        ]);
        let merged = resolver.resolve(&[]).unwrap();

        assert_eq!(
            merged.symbols.len(),
            2,
            "layer merging must deduplicate structural identities, not display strings"
        );
    }

    #[test]
    fn symbols_deduplicated_across_layers() {
        let sym_a = make_symbol("util", "helper");
        let sym_b = make_symbol("main", "run");

        let g1 = CodeGraph {
            symbols: vec![sym_a.clone(), sym_b.clone()],
            edges: vec![],
        };
        // Layer 2 repeats `helper` and adds a new symbol.
        let sym_c = make_symbol("extra", "other");
        let g2 = CodeGraph {
            symbols: vec![sym_a.clone(), sym_c.clone()],
            edges: vec![],
        };

        let resolver = LayeredResolver::new(vec![stub(g1), stub(g2)]);
        let merged = resolver.resolve(&[]).unwrap();

        // Should have 3 unique symbols: helper, run, other.
        assert_eq!(
            merged.symbols.len(),
            3,
            "expected 3 unique symbols, got {}: {:?}",
            merged.symbols.len(),
            merged
                .symbols
                .iter()
                .map(|s| s.id.to_scip_string())
                .collect::<Vec<_>>()
        );

        let scip_strings: HashSet<String> = merged
            .symbols
            .iter()
            .map(|s| s.id.to_scip_string())
            .collect();
        assert!(
            scip_strings.contains(&sym_a.id.to_scip_string()),
            "helper must be present"
        );
        assert!(
            scip_strings.contains(&sym_b.id.to_scip_string()),
            "run must be present"
        );
        assert!(
            scip_strings.contains(&sym_c.id.to_scip_string()),
            "other must be present"
        );
    }

    // ── Test 5: exact duplicate edge collapsed ────────────────────────────────

    /// The same edge at the same confidence and same provenance emitted by two
    /// layers produces exactly one copy in the output.
    #[test]
    fn exact_duplicate_edge_collapsed_to_one() {
        let e = make_edge(
            "a",
            "run",
            "b",
            "helper",
            Confidence::Scoped,
            Provenance::SymbolTable,
            5,
        );

        let g1 = CodeGraph {
            symbols: vec![],
            edges: vec![e.clone()],
        };
        let g2 = CodeGraph {
            symbols: vec![],
            edges: vec![e],
        };

        let resolver = LayeredResolver::new(vec![stub(g1), stub(g2)]);
        let merged = resolver.resolve(&[]).unwrap();

        assert_eq!(
            merged.edges.len(),
            1,
            "exact duplicate edge must be collapsed to one"
        );
    }
}
