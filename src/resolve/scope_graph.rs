// SPDX-License-Identifier: Apache-2.0

//! Tier-B scope-aware resolver — precise resolution via lexical scopes (Rust-first).
//!
//! This resolver walks each file's lexical scopes to bind references the way the
//! language's name-resolution rules would. It resolves four binding kinds:
//!
//! * **Path-qualified calls** — a reference with a written qualifier
//!   (`mod_a::process()`, `a::b::f()`) is resolved as a **path lookup**, entirely
//!   bypassing the lexical-scope walk. The qualifier segments are matched against
//!   the namespace suffix of every globally known definition sharing the call's
//!   leaf name. If exactly one definition matches, a [`Confidence::Exact`] edge is
//!   emitted. Zero matches or two-or-more matches yield **no** edge — Tier-B never
//!   fakes precision.
//! * **Local/param bindings** — a reference that resolves to a local variable or
//!   parameter within the file's scopes produces a [`Confidence::Exact`] edge
//!   whose target is a synthesized [`SymbolId::Local`]. Local/param resolution is
//!   the most certain kind: the inner-first scope walk guarantees the binding is
//!   lexically pinned with no confounders (a local always shadows any same-name
//!   import or definition in an outer scope).
//! * **Same-file top-level definitions** — a reference whose name walks out to a
//!   scope-0 [`BindingKind::Definition`] binding produces a [`Confidence::Scoped`]
//!   edge directly to that definition's [`SymbolId`], eliminating Tier-A's
//!   name-only fan-out across files. This is [`Confidence::Scoped`] (not `Exact`)
//!   because a same-name import also lives at module scope (scope 0); the walk
//!   breaks the tie by byte-order, which is not the language's real resolution
//!   rule — so this resolution is genuinely confoundable.
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
//!
//! ## Confidence contract
//!
//! | Resolution kind                                      | [`Confidence`]  |
//! |------------------------------------------------------|-----------------|
//! | Local variable / parameter                           | `Exact`         |
//! | Same-file top-level definition                       | `Scoped`        |
//! | Cross-file import (unique path-suffix match)         | `Exact`         |
//! | Path-qualified call (unique namespace-suffix match)  | `Exact`         |
//! | Ambiguous or unresolved                              | no edge emitted |
//!
//! Tier-B never emits `NameOnly` edges; it either resolves with honest
//! confidence or emits nothing (Tier-A still provides recall via fan-out for
//! those cases).

use std::collections::HashMap;

use crate::graph::types::{
    Binding, BindingKind, BindingTarget, CodeGraph, Confidence, Edge, FileFacts, Provenance, Scope,
    ScopeId, Symbol,
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
                // Caller attribution — needed by both the qualified and unqualified paths.
                let Some(from_idx) = syms_by_file
                    .get(f.file.as_str())
                    .and_then(|idxs| enclosing_symbol_index(&symbols, idxs, r.occ.byte))
                else {
                    continue; // unattributable reference — skip, like Tier-A
                };

                // QUALIFIED CALL: explicit written path → unique global namespace-suffix match.
                // Bypasses scope_walk entirely (this is a path lookup, not lexical resolution).
                //
                // KNOWN LIMITATION: only MODULE-qualified calls resolve
                // (`mod_a::process` — where `mod_a` appears as a Namespace descriptor in the
                // target's SCIP id path). `Type::assoc_fn()` does NOT resolve because:
                //   (1) `namespaces_end_with` matches only `Namespace` descriptors, not the
                //       `Type` descriptor used for structs/enums/traits; and
                //   (2) associated functions inside `impl` blocks are not yet extracted as
                //       top-level symbols.
                // This is an intentional, documented gap — resolving it requires type-member
                // extraction work that is out of scope for this unit. It is NOT a silent miss.
                // Do NOT widen `namespaces_end_with` to paper over it.
                if let Some(qual) = &r.qualifier {
                    let segs = normalize_from_path(qual);
                    if !segs.is_empty() {
                        if let Some(to_idx) =
                            unique_suffix_match(&by_name, &symbols, r.name.as_str(), &segs)
                        {
                            edges.push(Edge {
                                from: symbols[from_idx].id.clone(),
                                to: symbols[to_idx].id.clone(),
                                role: r.role,
                                confidence: Confidence::Exact,
                                provenance: Provenance::ScopeGraph,
                                occ: r.occ.clone(),
                            });
                        }
                    }
                    continue; // qualified ref handled (edge or honest no-op) — never fall through
                }

                // UNQUALIFIED: existing lexical scope_walk path (needs r.scope).
                // No scope info on the reference → no Tier-B edge.
                let Some(start) = r.scope else { continue };

                let Some(binding) =
                    scope_walk(&r.name, r.occ.byte, start, &f.scopes, &bindings_by_scope)
                else {
                    continue; // name binds to nothing visible — no edge
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
                            confidence: Confidence::Exact,
                            provenance: Provenance::ScopeGraph,
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
                                provenance: Provenance::ScopeGraph,
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
                                if let Some(to_idx) = unique_suffix_match(
                                    &by_name,
                                    &symbols,
                                    binding.name.as_str(),
                                    &segs,
                                ) {
                                    edges.push(Edge {
                                        from: symbols[from_idx].id.clone(),
                                        to: symbols[to_idx].id.clone(),
                                        role: r.role,
                                        confidence: Confidence::Exact,
                                        provenance: Provenance::ScopeGraph,
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

/// The unique index into `symbols` whose leaf name is `name` and whose
/// namespace chain ends with `segs`, or `None` if zero or more than one
/// candidate matches (Tier-B never fakes precision).
fn unique_suffix_match(
    by_name: &HashMap<&str, Vec<usize>>,
    symbols: &[Symbol],
    name: &str,
    segs: &[&str],
) -> Option<usize> {
    by_name.get(name).and_then(|cands| {
        let mut it = cands
            .iter()
            .filter(|&&i| namespaces_end_with(&symbols[i].id, segs));
        match (it.next(), it.next()) {
            (Some(&only), None) => Some(only), // exactly one match
            _ => None,                         // zero or ambiguous → no edge
        }
    })
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
        assert_eq!(e.confidence, Confidence::Exact);
        // The scope-aware resolver stamps every edge with ScopeGraph provenance.
        assert_eq!(e.provenance, Provenance::ScopeGraph);
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
        assert_eq!(locals[0].confidence, Confidence::Exact);
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

    // ── U8b: Qualified-call resolution ────────────────────────────────────────

    /// Edges from `run` (the caller) that are NOT local edges and NOT Import edges.
    fn call_edges_from_run(graph: &CodeGraph) -> Vec<&Edge> {
        graph
            .edges
            .iter()
            .filter(|e| {
                e.from.to_scip_string().ends_with("run().")
                    && !e.to.to_scip_string().starts_with("local ")
                    && e.role != crate::graph::types::RefRole::Import
            })
            .collect()
    }

    #[test]
    fn qualified_call_unique_match_emits_exact_edge() {
        // `src/mod_a.rs` defines `process` → namespace chain ["mod_a"]
        //   → SCIP id ends with `mod_a/process().`
        // `src/mod_b.rs` defines `process` → namespace chain ["mod_b"]
        //   → SCIP id ends with `mod_b/process().`
        // `src/caller.rs` defines `run` which calls `mod_a::process()`.
        //   qualifier = Some("mod_a"), name = "process"
        //   normalize_from_path("mod_a") = ["mod_a"]
        //   Only mod_a/process satisfies namespaces_end_with → ONE Exact edge.
        // Tier-A would fan out to both; this verifies the qualifier disambiguates.
        let mod_a = RustExtractor
            .extract("pub fn process() {}", "src/mod_a.rs")
            .unwrap();
        let mod_b = RustExtractor
            .extract("pub fn process() {}", "src/mod_b.rs")
            .unwrap();
        let caller = RustExtractor
            .extract("pub fn run() { mod_a::process() }", "src/caller.rs")
            .unwrap();

        let graph = ScopeGraphResolver.resolve(&[mod_a, mod_b, caller]);

        let run_edges = call_edges_from_run(&graph);
        assert_eq!(
            run_edges.len(),
            1,
            "expected exactly one edge from run (qualifier disambiguates), got: {:?}",
            run_edges
                .iter()
                .map(|e| format!(
                    "{} → {} ({:?})",
                    e.from.to_scip_string(),
                    e.to.to_scip_string(),
                    e.confidence
                ))
                .collect::<Vec<_>>()
        );

        let edge = run_edges[0];
        assert_eq!(
            edge.confidence,
            Confidence::Exact,
            "qualified-call edge must carry Exact confidence"
        );
        assert!(
            edge.to.to_scip_string().ends_with("mod_a/process()."),
            "edge must target mod_a::process, got: {}",
            edge.to.to_scip_string()
        );
        assert!(
            !edge.to.to_scip_string().ends_with("mod_b/process()."),
            "edge must NOT target mod_b::process (the decoy)"
        );
    }

    #[test]
    fn qualified_call_unmatched_qualifier_yields_no_edge() {
        // `process` is defined in namespace ["conf"] but the caller writes
        // `missing::process()` → qualifier "missing" does not suffix-match ["conf"]
        // → no edge (honest no-op).
        let conf = RustExtractor
            .extract("pub fn process() {}", "src/conf.rs")
            .unwrap();
        let caller = RustExtractor
            .extract("pub fn run() { missing::process() }", "src/caller.rs")
            .unwrap();

        let graph = ScopeGraphResolver.resolve(&[conf, caller]);

        let run_edges = call_edges_from_run(&graph);
        assert!(
            run_edges.is_empty(),
            "unmatched qualifier must yield no edge, got: {:?}",
            run_edges
                .iter()
                .map(|e| e.to.to_scip_string())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn unqualified_call_still_resolves_via_scope_walk() {
        // Regression: restructuring the loop must not break unqualified resolution.
        // `helper()` has no qualifier → falls through to scope_walk → finds the
        // same-file Definition binding → Scoped edge.
        let facts = RustExtractor
            .extract(
                "pub fn helper() {} pub fn run() { helper() }",
                "src/main.rs",
            )
            .unwrap();
        let graph = ScopeGraphResolver.resolve(&[facts]);

        let run_edges: Vec<&Edge> = graph
            .edges
            .iter()
            .filter(|e| {
                e.from.to_scip_string().ends_with("run().")
                    && e.to.to_scip_string().ends_with("helper().")
                    && !e.to.to_scip_string().starts_with("local ")
            })
            .collect();

        assert_eq!(
            run_edges.len(),
            1,
            "unqualified helper() must still resolve via scope_walk, got: {:?}",
            run_edges
                .iter()
                .map(|e| e.to.to_scip_string())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            run_edges[0].confidence,
            Confidence::Scoped,
            "unqualified same-file call must carry Scoped confidence"
        );
    }

    #[test]
    fn typeref_resolves_to_same_file_definition() {
        use crate::graph::types::RefRole;

        // One file: `Config` is a top-level struct (Definition binding at scope 0);
        // `run` mentions `Config` as a parameter type → TypeRef reference.
        // The scope_walk finds the Definition binding → Scoped edge.
        let facts = RustExtractor
            .extract(
                "pub struct Config {}\npub fn run(cfg: Config) {}",
                "src/main.rs",
            )
            .unwrap();
        let graph = ScopeGraphResolver.resolve(&[facts]);

        // Filter to TypeRef-role edges only.
        let typeref_edges: Vec<&Edge> = graph
            .edges
            .iter()
            .filter(|e| e.role == RefRole::TypeRef)
            .collect();

        assert_eq!(
            typeref_edges.len(),
            1,
            "expected exactly one TypeRef edge, got {:?}: {:?}",
            typeref_edges.len(),
            typeref_edges
                .iter()
                .map(|e| format!(
                    "{} → {} ({:?})",
                    e.from.to_scip_string(),
                    e.to.to_scip_string(),
                    e.confidence
                ))
                .collect::<Vec<_>>()
        );

        let e = typeref_edges[0];
        assert!(
            e.from.to_scip_string().ends_with("run()."),
            "TypeRef edge from must end with 'run().', got: {}",
            e.from.to_scip_string()
        );
        assert!(
            e.to.to_scip_string().ends_with("Config#"),
            "TypeRef edge to must end with 'Config#', got: {}",
            e.to.to_scip_string()
        );
        assert_eq!(
            e.confidence,
            Confidence::Scoped,
            "same-file definition resolution must carry Scoped confidence, got: {:?}",
            e.confidence
        );
    }

    #[test]
    fn nested_qualifier_resolves_to_nested_namespace() {
        // `src/a/b.rs` → namespaces ["a", "b"] → SCIP id ends with `a/b/process().`
        // Caller writes `a::b::process()` → qualifier "a::b"
        //   normalize_from_path("a::b") = ["a", "b"] (splits on ':')
        //   namespaces_end_with matches ["a", "b"] against ["a", "b"] → true → Exact edge.
        let nested = RustExtractor
            .extract("pub fn process() {}", "src/a/b.rs")
            .unwrap();
        let caller = RustExtractor
            .extract("pub fn run() { a::b::process() }", "src/caller.rs")
            .unwrap();

        let graph = ScopeGraphResolver.resolve(&[nested, caller]);

        let run_edges = call_edges_from_run(&graph);
        assert_eq!(
            run_edges.len(),
            1,
            "nested qualifier a::b::process() must resolve to src/a/b.rs::process, got: {:?}",
            run_edges
                .iter()
                .map(|e| e.to.to_scip_string())
                .collect::<Vec<_>>()
        );
        let edge = run_edges[0];
        assert_eq!(edge.confidence, Confidence::Exact);
        assert!(
            edge.to.to_scip_string().ends_with("a/b/process()."),
            "nested-namespace edge must target a/b/process, got: {}",
            edge.to.to_scip_string()
        );
    }

    // ── Confidence contract (single source of truth) ──────────────────────────

    /// Lock the full confidence contract in one place.
    ///
    /// | Kind                                   | Expected confidence |
    /// |----------------------------------------|---------------------|
    /// | Local variable / parameter             | `Exact`             |
    /// | Same-file top-level definition         | `Scoped`            |
    /// | Cross-file import (unique path-suffix) | `Exact`             |
    /// | Path-qualified call (unique ns-suffix) | `Exact`             |
    #[test]
    fn confidence_contract_per_resolution_kind() {
        // ── 1. Local binding → Exact ─────────────────────────────────────────
        {
            let facts = RustExtractor
                .extract(
                    "pub fn run() { let buffer = make(); buffer() }",
                    "src/main.rs",
                )
                .unwrap();
            let graph = ScopeGraphResolver.resolve(&[facts]);
            let locals = local_edges(&graph);
            assert_eq!(locals.len(), 1, "expected one local edge for 'buffer'");
            assert_eq!(
                locals[0].confidence,
                Confidence::Exact,
                "local binding must be Exact"
            );
        }

        // ── 2. Param binding → Exact ─────────────────────────────────────────
        {
            let facts = RustExtractor
                .extract("pub fn run(handler: u32) { handler() }", "src/main.rs")
                .unwrap();
            let graph = ScopeGraphResolver.resolve(&[facts]);
            let locals = local_edges(&graph);
            assert_eq!(locals.len(), 1, "expected one local edge for 'handler'");
            assert_eq!(
                locals[0].confidence,
                Confidence::Exact,
                "param binding must be Exact"
            );
        }

        // ── 3. Same-file definition → Scoped ────────────────────────────────
        {
            let facts = RustExtractor
                .extract(
                    "pub fn compute() {} pub fn run() { compute() }",
                    "src/main.rs",
                )
                .unwrap();
            let graph = ScopeGraphResolver.resolve(&[facts]);
            let def_edges: Vec<&Edge> = graph
                .edges
                .iter()
                .filter(|e| {
                    e.from.to_scip_string().ends_with("run().")
                        && e.to.to_scip_string().ends_with("compute().")
                        && !e.to.to_scip_string().starts_with("local ")
                })
                .collect();
            assert_eq!(
                def_edges.len(),
                1,
                "expected one definition edge for 'compute'"
            );
            assert_eq!(
                def_edges[0].confidence,
                Confidence::Scoped,
                "same-file definition must be Scoped"
            );
        }

        // ── 4. Cross-file import (unique path-suffix match) → Exact ─────────
        {
            let service = RustExtractor
                .extract("pub struct Service {}", "src/service.rs")
                .unwrap();
            let app = RustExtractor
                .extract("use service::Service;\npub fn run() {}", "src/app.rs")
                .unwrap();
            let graph = ScopeGraphResolver.resolve(&[service, app]);
            let imports = import_edges(&graph);
            assert_eq!(imports.len(), 1, "expected one import edge for 'Service'");
            assert_eq!(
                imports[0].confidence,
                Confidence::Exact,
                "cross-file import must be Exact"
            );
        }

        // ── 5. Path-qualified call (unique namespace-suffix match) → Exact ───
        {
            let util = RustExtractor
                .extract("pub fn validate() {}", "src/util.rs")
                .unwrap();
            let caller = RustExtractor
                .extract("pub fn run() { util::validate() }", "src/caller.rs")
                .unwrap();
            let graph = ScopeGraphResolver.resolve(&[util, caller]);
            let run_edges = call_edges_from_run(&graph);
            assert_eq!(
                run_edges.len(),
                1,
                "expected one qualified-call edge for 'util::validate'"
            );
            assert_eq!(
                run_edges[0].confidence,
                Confidence::Exact,
                "qualified call must be Exact"
            );
            assert!(
                run_edges[0]
                    .to
                    .to_scip_string()
                    .ends_with("util/validate()."),
                "qualified call must target util::validate, got: {}",
                run_edges[0].to.to_scip_string()
            );
        }
    }
}
