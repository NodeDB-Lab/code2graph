// SPDX-License-Identifier: Apache-2.0

//! Tier-B scope-aware resolver (**in progress**).
//!
//! This resolver walks each file's lexical scopes to bind references the way the
//! language's name-resolution rules would. It resolves three binding kinds:
//!
//! * **Local/param bindings** — a reference that resolves to a local variable or
//!   parameter within the file's scopes produces a [`Confidence::Scoped`] edge
//!   whose target is a synthesized [`SymbolId::Local`].
//! * **Same-file top-level definitions** — a reference whose name walks out to a
//!   scope-0 [`BindingKind::Definition`] binding produces a [`Confidence::Scoped`]
//!   edge directly to that definition's [`SymbolId`], eliminating Tier-A's
//!   name-only fan-out across files.
//! * **Imports (cross-file)** — a reference that walks out to a
//!   [`BindingKind::Import`] binding is resolved across files: when the import's
//!   path (the imported-from module, as written) **uniquely** matches one global
//!   definition's namespace suffix, it produces a single [`Confidence::Exact`]
//!   edge to that definition — turning Tier-A's ambiguous import fan-out into one
//!   precise edge. An import whose path matches no definition, or matches two or
//!   more ambiguously, yields **no** edge (Tier-B never fakes precision; Tier-A
//!   still provides recall via fan-out for those cases).
//!
//! A reference with `scope: None` (every extractor except Rust, for now) or a
//! name that binds to nothing simply yields no edge.

use std::collections::HashMap;

use crate::graph::types::{
    Binding, BindingKind, BindingTarget, CodeGraph, Confidence, Edge, FileFacts, Scope, ScopeId,
    Symbol,
};
use crate::symbol::SymbolId;

use super::Resolver;
use super::{enclosing_symbol_index, namespaces_end_with, normalize_from_path};

/// Scope-aware resolver. See module docs.
#[derive(Debug, Default, Clone, Copy)]
pub struct ScopeGraphResolver;

impl Resolver for ScopeGraphResolver {
    fn resolve(&self, files: &[FileFacts]) -> CodeGraph {
        // Flatten symbols exactly like Tier-A — these are the returned graph's
        // symbols. Synthesized Local targets are edge targets only (SCIP-style);
        // they are never added here.
        let symbols: Vec<Symbol> = files
            .iter()
            .flat_map(|f| f.symbols.iter().cloned())
            .collect();

        // file path → indices into `symbols`, for caller attribution.
        let mut syms_by_file: HashMap<&str, Vec<usize>> = HashMap::new();
        for (i, s) in symbols.iter().enumerate() {
            syms_by_file.entry(s.file.as_str()).or_default().push(i);
        }

        // Global leaf-name → indices into `symbols`, for cross-file import
        // resolution (mirrors Tier-A's `by_name`).
        let mut by_name: HashMap<&str, Vec<usize>> = HashMap::new();
        for (i, s) in symbols.iter().enumerate() {
            if let Some(n) = s.id.leaf_name() {
                by_name.entry(n).or_default().push(i);
            }
        }

        let mut edges: Vec<Edge> = Vec::new();
        for f in files {
            // Per-file binding index (scope → its bindings), built before the
            // reference loop so it borrows `f.bindings` independently of the
            // separate immutable borrow of `f.references`.
            let mut bindings_by_scope: HashMap<ScopeId, Vec<&Binding>> = HashMap::new();
            for b in &f.bindings {
                bindings_by_scope.entry(b.scope).or_default().push(b);
            }

            for r in &f.references {
                // No scope info on the reference → no Tier-B edge.
                let Some(start) = r.scope else { continue };

                let Some(binding) =
                    scope_walk(&r.name, r.occ.byte, start, &f.scopes, &bindings_by_scope)
                else {
                    continue; // name binds to nothing visible — no edge
                };

                // The caller: innermost symbol in this file enclosing the ref.
                // Hoisted here so every arm can use it without recomputation.
                let Some(from_idx) = syms_by_file
                    .get(f.file.as_str())
                    .and_then(|idxs| enclosing_symbol_index(&symbols, idxs, r.occ.byte))
                else {
                    continue; // unattributable reference — skip, like Tier-A
                };

                match binding.kind {
                    BindingKind::Local | BindingKind::Param => {
                        // Stable, unique id for the local: file + scope + name +
                        // intro byte distinguishes shadowing bindings of one name.
                        let local_id = format!(
                            "{}@{}:{}@{}",
                            f.file, binding.scope, binding.name, binding.intro
                        );
                        let to = SymbolId::local(f.file.clone(), local_id);

                        edges.push(Edge {
                            from: symbols[from_idx].id.clone(),
                            to,
                            role: r.role,
                            confidence: Confidence::Scoped,
                            occ: r.occ.clone(),
                        });
                    }
                    BindingKind::Definition => {
                        // Same-file definition: resolve to the bound symbol's identity, precisely.
                        if let BindingTarget::Def(target_id) = &binding.target {
                            edges.push(Edge {
                                from: symbols[from_idx].id.clone(),
                                to: target_id.clone(),
                                role: r.role,
                                confidence: Confidence::Scoped,
                                occ: r.occ.clone(),
                            });
                        }
                        // (A Definition binding always carries Def(_); the `if let` is defensive.)
                    }
                    BindingKind::Import => {
                        if let BindingTarget::Import(from_path) = &binding.target {
                            let segs = normalize_from_path(from_path);
                            if !segs.is_empty() {
                                // Among global symbols sharing the imported name, find the
                                // UNIQUE one whose namespace chain ends with the import path
                                // segments.
                                if let Some(&to_idx) =
                                    by_name.get(binding.name.as_str()).and_then(|cands| {
                                        let mut it = cands.iter().filter(|&&i| {
                                            namespaces_end_with(&symbols[i].id, &segs)
                                        });
                                        let first = it.next();
                                        match (first, it.next()) {
                                            (Some(only), None) => Some(only), // exactly one match
                                            _ => None, // zero or ambiguous → no edge
                                        }
                                    })
                                {
                                    edges.push(Edge {
                                        from: symbols[from_idx].id.clone(),
                                        to: symbols[to_idx].id.clone(),
                                        role: r.role,
                                        confidence: Confidence::Exact,
                                        occ: r.occ.clone(),
                                    });
                                }
                            }
                        }
                        // No from_path, empty segs, or non-unique match → no edge
                        // (Tier-B never fakes precision; Tier-A still provides recall
                        // via fan-out for those).
                    }
                }
            }
        }

        CodeGraph { symbols, edges }
    }
}

/// Walk lexical scopes outward from `start` looking for the binding that the
/// name resolves to. Returns the winning binding (caller dispatches on kind).
///
/// The walk goes outward only (child → parent), so a reference never sees
/// bindings in sibling or child scopes — block visibility falls out for free.
fn scope_walk<'b>(
    name: &str,
    ref_byte: usize,
    start: ScopeId,
    scopes: &[Scope],
    bindings_by_scope: &HashMap<ScopeId, Vec<&'b Binding>>,
) -> Option<&'b Binding> {
    let mut current = start;
    loop {
        if let Some(cands) = bindings_by_scope.get(&current) {
            // Visible candidates in THIS scope, matching the name. On shadowing
            // (multiple matches), the latest introduction wins.
            let winner = cands
                .iter()
                .copied()
                .filter(|b| b.name == name && is_visible(b, ref_byte))
                .max_by_key(|b| b.intro);
            if let Some(b) = winner {
                return Some(b);
            }
        }
        match scopes.get(current).and_then(|s| s.parent) {
            Some(p) => current = p,
            None => return None, // reached root with no match
        }
    }
}

/// Visibility: `let` locals are position-gated (must be introduced before use);
/// params, definitions, and imports are visible scope-wide.
fn is_visible(b: &Binding, ref_byte: usize) -> bool {
    match b.kind {
        BindingKind::Local => b.intro <= ref_byte,
        BindingKind::Param | BindingKind::Definition | BindingKind::Import => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::Extractor;
    use crate::extract::PythonExtractor;
    use crate::extract::RustExtractor;

    /// All edges whose target renders as a `local …` SCIP string.
    fn local_edges(graph: &CodeGraph) -> Vec<&Edge> {
        graph
            .edges
            .iter()
            .filter(|e| e.to.to_scip_string().starts_with("local "))
            .collect()
    }

    #[test]
    fn resolves_local_binding() {
        // `helper` binds to the `let helper`; `make()` binds to nothing → no edge.
        let facts = RustExtractor
            .extract(
                "pub fn run() { let helper = make(); helper() }",
                "src/main.rs",
            )
            .unwrap();
        let graph = ScopeGraphResolver.resolve(&[facts]);

        let locals = local_edges(&graph);
        assert_eq!(
            locals.len(),
            1,
            "expected exactly one local edge, got {:?}",
            locals.len()
        );
        let e = locals[0];
        assert_eq!(e.confidence, Confidence::Scoped);
        assert!(
            e.from.to_scip_string().ends_with("run()."),
            "from was: {}",
            e.from.to_scip_string()
        );
    }

    #[test]
    fn shadowing_latest_binding_wins() {
        // `val` is ≥ MIN_REF_LEN so the `val()` call is captured.
        let src = "pub fn run() { let val = make(); let val = other(); val() }";
        let facts = RustExtractor.extract(src, "src/main.rs").unwrap();

        // Expected: the SECOND `let val` (greater intro byte) wins. Compute both
        // intro bytes from the source so the assertion is grounded.
        let first_let = src.find("let val").unwrap();
        let second_let = src[first_let + 1..].find("let val").unwrap() + first_let + 1;
        assert!(second_let > first_let);

        let graph = ScopeGraphResolver.resolve(&[facts]);
        let locals = local_edges(&graph);
        assert_eq!(
            locals.len(),
            1,
            "expected one local edge, got {:?}",
            locals.len()
        );

        // The synthesized local id encodes the winning binding's intro byte. The
        // intro is the name position; both `let x` lines have `x` after `let `.
        let second_intro = second_let + "let ".len();
        let id = locals[0].to.to_scip_string();
        assert!(
            id.ends_with(&format!("@{}", second_intro)),
            "local id {id} should encode the second binding intro {second_intro}"
        );
    }

    #[test]
    fn resolves_param_binding() {
        // `callback` is a parameter; `callback()` resolves to it (tree-sitter
        // doesn't typecheck). Name length ≥ MIN_REF_LEN so the call is captured.
        let facts = RustExtractor
            .extract("pub fn run(callback: u32) { callback() }", "src/main.rs")
            .unwrap();
        let graph = ScopeGraphResolver.resolve(&[facts]);

        let locals = local_edges(&graph);
        assert_eq!(
            locals.len(),
            1,
            "expected one local edge, got {:?}",
            locals.len()
        );
        assert_eq!(locals[0].confidence, Confidence::Scoped);
    }

    #[test]
    fn unbound_name_produces_no_edge() {
        let facts = RustExtractor
            .extract("pub fn run() { nothing_here() }", "src/main.rs")
            .unwrap();
        let graph = ScopeGraphResolver.resolve(&[facts]);
        assert!(
            local_edges(&graph).is_empty(),
            "unbound name must not bind to a local"
        );
    }

    #[test]
    fn non_scope_language_is_graceful_noop() {
        // Python refs carry scope: None → no local edges, no panic.
        let facts = PythonExtractor
            .extract("def f():\n    pass\n", "src/m.py")
            .unwrap();
        let sym_count = facts.symbols.len();
        let graph = ScopeGraphResolver.resolve(&[facts]);
        assert_eq!(graph.symbols.len(), sym_count);
        assert!(local_edges(&graph).is_empty());
    }

    #[test]
    fn block_local_not_visible_to_outer_ref() {
        // `let val` lives in the inner block; `val()` is in the function scope
        // and must NOT see it (outward walk skips child scopes). Name ≥ MIN_REF_LEN
        // so the call IS captured — otherwise this would pass for the wrong reason.
        let facts = RustExtractor
            .extract(
                "pub fn run() { { let val = make(); } val() }",
                "src/main.rs",
            )
            .unwrap();
        let graph = ScopeGraphResolver.resolve(&[facts]);
        assert!(
            local_edges(&graph).is_empty(),
            "outer ref must not bind to a block-scoped local"
        );
    }

    #[test]
    fn ignores_role_noise_only_local_edges_counted() {
        // Sanity: `helper` has no definition or local in this file, so it binds to
        // nothing — the call yields no edge at all, and in particular no local edge.
        let facts = RustExtractor
            .extract("pub fn run() { helper() }", "src/main.rs")
            .unwrap();
        let graph = ScopeGraphResolver.resolve(&[facts]);
        assert!(
            local_edges(&graph).is_empty(),
            "unbound name must not produce a local edge"
        );
    }

    // ── U6: Definition arm ────────────────────────────────────────────────────

    #[test]
    fn resolves_same_file_definition() {
        // `helper()` call inside `run()` must resolve to the top-level `helper`
        // definition in the same file — NOT to a synthesized local.
        let facts = RustExtractor
            .extract(
                "pub fn helper() {} pub fn run() { helper() }",
                "src/main.rs",
            )
            .unwrap();
        let graph = ScopeGraphResolver.resolve(&[facts]);

        // Exactly one edge whose source is `run` and target is the real `helper`.
        let def_edges: Vec<&Edge> = graph
            .edges
            .iter()
            .filter(|e| {
                e.from.to_scip_string().ends_with("run().")
                    && e.to.to_scip_string().ends_with("helper().")
                    && !e.to.to_scip_string().starts_with("local ")
            })
            .collect();

        assert_eq!(
            def_edges.len(),
            1,
            "expected exactly one run→helper definition edge, got {:?}",
            def_edges
                .iter()
                .map(|e| format!("{} → {}", e.from.to_scip_string(), e.to.to_scip_string()))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            def_edges[0].confidence,
            Confidence::Scoped,
            "definition edge must carry Scoped confidence"
        );
        // No local edge must be produced for `helper`.
        assert!(
            local_edges(&graph).is_empty(),
            "definition call must not produce a local edge"
        );
    }

    #[test]
    fn same_file_definition_wins_over_cross_file_fan_out() {
        // Three files each with a `helper` function. `caller.rs` also has `run`
        // calling `helper`. Tier-A would fan out to all three helpers; Tier-B
        // (Definition binding) picks only caller.rs's own `helper`.
        let facts_a = RustExtractor
            .extract("pub fn helper() {}", "src/a.rs")
            .unwrap();
        let facts_b = RustExtractor
            .extract("pub fn helper() {}", "src/b.rs")
            .unwrap();
        let facts_caller = RustExtractor
            .extract(
                "pub fn helper() {} pub fn run() { helper() }",
                "src/caller.rs",
            )
            .unwrap();

        let graph = ScopeGraphResolver.resolve(&[facts_a, facts_b, facts_caller]);

        // Collect all edges whose `from` ends with `run().`.
        let run_edges: Vec<&Edge> = graph
            .edges
            .iter()
            .filter(|e| e.from.to_scip_string().ends_with("run()."))
            .collect();

        assert_eq!(
            run_edges.len(),
            1,
            "expected exactly one edge from run, not a cross-file fan-out; got: {:?}",
            run_edges
                .iter()
                .map(|e| e.to.to_scip_string())
                .collect::<Vec<_>>()
        );

        let edge = run_edges[0];
        assert_eq!(edge.confidence, Confidence::Scoped);

        // The resolved target must be caller.rs's OWN helper, not a.rs/b.rs.
        // SCIP ids carry the file-derived namespace as a path segment, so
        // caller.rs's helper renders as `…caller/helper().` while the decoys
        // render as `…a/helper().` / `…b/helper().`. Asserting the `caller/`
        // segment positively pins the correct file and fails on a wrong pick.
        let to_scip = edge.to.to_scip_string();
        assert!(
            to_scip.ends_with("caller/helper()."),
            "run→helper edge must target caller.rs's own helper, got: {to_scip}"
        );
    }

    #[test]
    fn local_shadows_same_name_definition() {
        // `process` is both a top-level function and a `let` binding inside `run`.
        // The LOCAL `process` must shadow the Definition — innermost scope wins.
        let src = "pub fn process() {} pub fn run() { let process = make(); process() }";
        let facts = RustExtractor.extract(src, "src/main.rs").unwrap();
        let graph = ScopeGraphResolver.resolve(&[facts]);

        // Exactly one edge from `run`.
        let run_edges: Vec<&Edge> = graph
            .edges
            .iter()
            .filter(|e| e.from.to_scip_string().ends_with("run()."))
            .collect();

        assert_eq!(
            run_edges.len(),
            1,
            "expected exactly one edge from run, got {:?}",
            run_edges
                .iter()
                .map(|e| e.to.to_scip_string())
                .collect::<Vec<_>>()
        );

        let to_scip = run_edges[0].to.to_scip_string();
        assert!(
            to_scip.starts_with("local "),
            "let-binding must shadow top-level definition: target should be a local, got: {to_scip}"
        );
    }

    // ── U7: Import arm (cross-file import resolution) ─────────────────────────

    /// All Import-role edges in the graph.
    fn import_edges(graph: &CodeGraph) -> Vec<&Edge> {
        graph
            .edges
            .iter()
            .filter(|e| e.role == crate::graph::types::RefRole::Import)
            .collect()
    }

    #[test]
    fn resolves_unique_cross_file_import_exact() {
        // `src/conf.rs` defines `Config` (namespace chain ["conf"]).
        // `src/app.rs` does `use conf::Config;` → from_path "conf" → segs ["conf"]
        // which uniquely suffix-matches conf::Config. Expect exactly one Import
        // edge, Confidence::Exact, targeting conf/Config#.
        let conf = RustExtractor
            .extract("pub struct Config {}", "src/conf.rs")
            .unwrap();
        let app = RustExtractor
            .extract("use conf::Config;\npub fn run() {}", "src/app.rs")
            .unwrap();

        let graph = ScopeGraphResolver.resolve(&[conf, app]);

        let imports = import_edges(&graph);
        assert_eq!(
            imports.len(),
            1,
            "expected exactly one Import edge, got: {:?}",
            imports
                .iter()
                .map(|e| e.to.to_scip_string())
                .collect::<Vec<_>>()
        );
        let e = imports[0];
        assert_eq!(
            e.confidence,
            Confidence::Exact,
            "cross-file import edge must be Exact"
        );
        assert!(
            e.to.to_scip_string().ends_with("conf/Config#"),
            "import edge must target conf::Config, got: {}",
            e.to.to_scip_string()
        );
        assert!(
            e.from.to_scip_string().ends_with("app/"),
            "import edge source should be app's module symbol, got: {}",
            e.from.to_scip_string()
        );
    }

    #[test]
    fn ambiguous_import_becomes_precise_single_exact_edge() {
        // Two files define `Config` in DIFFERENT namespaces:
        //   src/conf.rs   → ["conf"]
        //   src/other.rs  → ["other"]   (the decoy)
        // The importer does `use conf::Config;` → from_path "conf".
        // Tier-A would fan out to BOTH; Tier-B emits exactly ONE Exact edge to
        // conf::Config and NOT to the decoy.
        let conf = RustExtractor
            .extract("pub struct Config {}", "src/conf.rs")
            .unwrap();
        let other = RustExtractor
            .extract("pub struct Config {}", "src/other.rs")
            .unwrap();
        let app = RustExtractor
            .extract("use conf::Config;\npub fn run() {}", "src/app.rs")
            .unwrap();

        let graph = ScopeGraphResolver.resolve(&[conf, other, app]);

        let imports = import_edges(&graph);
        assert_eq!(
            imports.len(),
            1,
            "expected exactly one precise Import edge (not a fan-out), got: {:?}",
            imports
                .iter()
                .map(|e| e.to.to_scip_string())
                .collect::<Vec<_>>()
        );
        let e = imports[0];
        assert_eq!(e.confidence, Confidence::Exact);
        assert!(
            e.to.to_scip_string().ends_with("conf/Config#"),
            "must resolve to conf::Config, got: {}",
            e.to.to_scip_string()
        );
        // Explicitly assert the decoy was NOT targeted.
        assert!(
            !e.to.to_scip_string().ends_with("other/Config#"),
            "must NOT resolve to the decoy other::Config"
        );
    }

    #[test]
    fn unmatched_import_yields_no_edge() {
        // Importer's from_path ("missing") matches no definition's namespace
        // suffix → Tier-B emits no Import edge (honest no-op).
        let conf = RustExtractor
            .extract("pub struct Config {}", "src/conf.rs")
            .unwrap();
        let app = RustExtractor
            .extract("use missing::Config;\npub fn run() {}", "src/app.rs")
            .unwrap();

        let graph = ScopeGraphResolver.resolve(&[conf, app]);

        assert!(
            import_edges(&graph).is_empty(),
            "import whose path matches no definition must yield no Tier-B edge"
        );
    }
}
