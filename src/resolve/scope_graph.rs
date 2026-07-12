// SPDX-License-Identifier: Apache-2.0

//! Tier-B scope-aware resolver — precise resolution via lexical scopes.
//!
//! The resolver itself is language-agnostic; it resolves whatever scope/binding
//! facts an extractor emits. Scope-aware extractors today: Rust, Python, and
//! TypeScript/JavaScript.
//!
//! This resolver walks each file's lexical scopes to bind references the way the
//! language's name-resolution rules would. It resolves four binding kinds:
//!
//! * **Path-qualified calls** — a reference with a written qualifier
//!   (`mod_a::process()`, `Alpha.compute()`) is resolved as a **path lookup**,
//!   entirely bypassing the lexical-scope walk. The qualifier segments are matched
//!   against the **namespace suffix** of every globally known definition sharing
//!   the call's leaf name, and also against the **enclosing-descriptor chain**
//!   (all descriptor kinds — namespaces *and* types such as a Ruby `module` or
//!   class) so a type-qualified call like `Alpha.compute` resolves to a method
//!   nested inside a `Type` descriptor, not only to one inside a `Namespace`. If
//!   exactly one definition matches either rule, a [`Confidence::Exact`] edge is
//!   emitted. Zero matches or two-or-more matches yield **no** edge — Tier-B never
//!   fakes precision.
//! * **Local/param bindings** — a reference that resolves to a local variable or
//!   parameter within the file's scopes produces a [`Confidence::Exact`] edge
//!   whose target is a synthesized local [`SymbolId`]. Local/param resolution is
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
//! A reference with `scope: None` (from extractors without scope extraction) or
//! a name that binds to nothing simply yields no edge.
//!
//! ## Confidence contract
//!
//! | Resolution kind                                      | [`Confidence`]  |
//! |------------------------------------------------------|-----------------|
//! | Local variable / parameter                           | `Exact`         |
//! | Same-file top-level definition                       | `Scoped`        |
//! | Cross-file import (unique path-suffix match)         | `Exact`         |
//! | Path-qualified call (unique namespace- or type-suffix match) | `Exact`  |
//! | Ambiguous or unresolved                              | no edge emitted |
//!
//! Tier-B never emits `NameOnly` edges; it either resolves with honest
//! confidence or emits nothing (Tier-A still provides recall via fan-out for
//! those cases).
//!
//! [`Confidence`]: crate::graph::Confidence
//! [`Confidence::Exact`]: crate::graph::Confidence::Exact
//! [`Confidence::Scoped`]: crate::graph::Confidence::Scoped
//! [`SymbolId`]: crate::symbol::SymbolId
//! [`BindingKind::Definition`]: crate::graph::types::BindingKind::Definition
//! [`BindingKind::Import`]: crate::graph::types::BindingKind::Import

use crate::graph::types::{CodeGraph, Edge, FileFacts, Symbol};

use super::incremental::{FileSubgraph, GlobalIndex, build_subgraph, stitch};
use super::{Resolver, dedup_files_last_wins};

/// Scope-aware resolver. See module docs.
#[derive(Debug, Default, Clone, Copy)]
pub struct ScopeGraphResolver;

impl Resolver for ScopeGraphResolver {
    fn resolve(&self, files: &[FileFacts]) -> crate::Result<CodeGraph> {
        crate::validate_file_facts(files)?;
        // A file path identifies a unique source: on duplicate `file` keys, keep
        // the LAST version (matching the IncrementalGraph store's upsert), so
        // batch output never diverges from the store and never emits duplicate
        // symbol identities.
        let files = dedup_files_last_wins(files);

        // Build one isolated subgraph per file. This is the SAME resolution code
        // path the future incremental store wraps — both derive everything
        // (symbols, intra-file edges, cross-file pending refs) from
        // `build_subgraph`, so the two paths never drift.
        let subs: Vec<FileSubgraph> = files.iter().copied().map(build_subgraph).collect();

        // The returned graph's symbols are the per-file symbols, concatenated in
        // file order (synthesized Local edge targets are never added here).
        let symbols: Vec<Symbol> = subs
            .iter()
            .flat_map(|s| s.symbols.iter().cloned())
            .collect();

        // Global definition and public re-export index for the cross-file
        // stitch phase. Re-export aliases remain neutral file facts until this
        // resolver follows them to a unique terminal definition.
        let index = GlobalIndex::from_subgraphs(&subs);

        // Intra-file edges first (all files, in order), then the stitched
        // cross-file edges. Tests assert edge sets, not positional order.
        let mut edges: Vec<Edge> = Vec::new();
        let mut all_pending = Vec::new();
        for sub in subs {
            edges.extend(sub.intra_edges);
            all_pending.extend(sub.pending);
        }
        edges.extend(stitch(&all_pending, &index));

        Ok(CodeGraph { symbols, edges })
    }
}

#[cfg(all(
    test,
    any(
        feature = "rust",
        feature = "python",
        feature = "typescript",
        feature = "go",
        feature = "ruby"
    )
))]
mod tests {
    use super::*;
    #[cfg(any(
        feature = "rust",
        feature = "python",
        feature = "typescript",
        feature = "go",
        feature = "ruby"
    ))]
    use crate::extract::Extractor;
    #[cfg(feature = "python")]
    use crate::extract::PythonExtractor;
    #[cfg(feature = "rust")]
    use crate::extract::RustExtractor;
    #[cfg(feature = "rust")]
    use crate::graph::types::Confidence;
    #[cfg(any(
        feature = "rust",
        feature = "python",
        feature = "typescript",
        feature = "go"
    ))]
    use crate::graph::types::Provenance;

    /// Python: an import disambiguates an otherwise-ambiguous cross-file call —
    /// the scope tier binds the call to the imported definition alone, where the
    /// name tier would fan out to every same-named def.
    #[cfg(feature = "rust")]
    #[test]
    fn rejects_malformed_facts_at_checked_boundary() {
        let mut facts = RustExtractor.extract("fn run() {}", "src/a.rs").unwrap();
        facts.scopes[0].parent = Some(0);
        assert!(ScopeGraphResolver.resolve(&[facts]).is_err());
    }

    #[cfg(feature = "python")]
    #[test]
    fn python_import_disambiguates_ambiguous_call() {
        use crate::graph::types::RefRole;
        let alpha = PythonExtractor
            .extract("def process():\n    pass\n", "alpha.py")
            .unwrap();
        let beta = PythonExtractor
            .extract("def process():\n    pass\n", "beta.py")
            .unwrap();
        let main = PythonExtractor
            .extract(
                "from alpha import process\n\ndef run():\n    process()\n",
                "main.py",
            )
            .unwrap();

        let graph = ScopeGraphResolver.resolve(&[alpha, beta, main]).unwrap();
        let calls: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.role == RefRole::Call)
            .collect();
        assert_eq!(
            calls.len(),
            1,
            "expected exactly one call edge (no fan-out)"
        );
        assert_eq!(calls[0].provenance, Provenance::ScopeGraph);
        assert!(
            calls[0].to.to_scip_string().contains("alpha"),
            "call must bind to alpha's process, got {}",
            calls[0].to.to_scip_string()
        );
    }

    /// TypeScript: an import disambiguates an ambiguous cross-file call, exactly
    /// as for Python — the scope tier binds to the imported definition alone.
    #[cfg(feature = "typescript")]
    #[test]
    fn typescript_import_disambiguates_ambiguous_call() {
        use crate::extract::TypeScriptExtractor;
        use crate::graph::types::RefRole;
        let alpha = TypeScriptExtractor
            .extract("export function process() {}\n", "alpha.ts")
            .unwrap();
        let beta = TypeScriptExtractor
            .extract("export function process() {}\n", "beta.ts")
            .unwrap();
        let main = TypeScriptExtractor
            .extract(
                "import { process } from \"./alpha\";\n\nexport function run() {\n  process();\n}\n",
                "main.ts",
            )
            .unwrap();

        let graph = ScopeGraphResolver.resolve(&[alpha, beta, main]).unwrap();
        let calls: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.role == RefRole::Call)
            .collect();
        assert_eq!(
            calls.len(),
            1,
            "expected exactly one call edge (no fan-out)"
        );
        assert_eq!(calls[0].provenance, Provenance::ScopeGraph);
        assert!(
            calls[0].to.to_scip_string().contains("alpha"),
            "call must bind to alpha's process, got {}",
            calls[0].to.to_scip_string()
        );
    }

    /// All edges whose target renders as a `local …` SCIP string.
    #[cfg(any(feature = "rust", feature = "python"))]
    fn local_edges(graph: &CodeGraph) -> Vec<&Edge> {
        graph
            .edges
            .iter()
            .filter(|e| e.to.to_scip_string().starts_with("local "))
            .collect()
    }

    #[cfg(feature = "rust")]
    #[test]
    fn resolves_local_binding() {
        // `helper` binds to the `let helper`; `make()` binds to nothing → no edge.
        let facts = RustExtractor
            .extract(
                "pub fn run() { let helper = make(); helper() }",
                "src/main.rs",
            )
            .unwrap();
        let graph = ScopeGraphResolver.resolve(&[facts]).unwrap();

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

    #[cfg(feature = "rust")]
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

        let graph = ScopeGraphResolver.resolve(&[facts]).unwrap();
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

    #[cfg(feature = "rust")]
    #[test]
    fn resolves_param_binding() {
        // `callback` is a parameter; `callback()` resolves to it (tree-sitter
        // doesn't typecheck). Name length ≥ MIN_REF_LEN so the call is captured.
        let facts = RustExtractor
            .extract("pub fn run(callback: u32) { callback() }", "src/main.rs")
            .unwrap();
        let graph = ScopeGraphResolver.resolve(&[facts]).unwrap();

        let locals = local_edges(&graph);
        assert_eq!(
            locals.len(),
            1,
            "expected one local edge, got {:?}",
            locals.len()
        );
        assert_eq!(locals[0].confidence, Confidence::Exact);
    }

    #[cfg(feature = "rust")]
    #[test]
    fn unbound_name_produces_no_edge() {
        let facts = RustExtractor
            .extract("pub fn run() { nothing_here() }", "src/main.rs")
            .unwrap();
        let graph = ScopeGraphResolver.resolve(&[facts]).unwrap();
        assert!(
            local_edges(&graph).is_empty(),
            "unbound name must not bind to a local"
        );
    }

    #[cfg(feature = "python")]
    #[test]
    fn non_scope_language_is_graceful_noop() {
        // Python refs carry scope: None → no local edges, no panic.
        let facts = PythonExtractor
            .extract("def f():\n    pass\n", "src/m.py")
            .unwrap();
        let sym_count = facts.symbols.len();
        let graph = ScopeGraphResolver.resolve(&[facts]).unwrap();
        assert_eq!(graph.symbols.len(), sym_count);
        assert!(local_edges(&graph).is_empty());
    }

    #[cfg(feature = "rust")]
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
        let graph = ScopeGraphResolver.resolve(&[facts]).unwrap();
        assert!(
            local_edges(&graph).is_empty(),
            "outer ref must not bind to a block-scoped local"
        );
    }

    #[cfg(feature = "rust")]
    #[test]
    fn ignores_role_noise_only_local_edges_counted() {
        // Sanity: `helper` has no definition or local in this file, so it binds to
        // nothing — the call yields no edge at all, and in particular no local edge.
        let facts = RustExtractor
            .extract("pub fn run() { helper() }", "src/main.rs")
            .unwrap();
        let graph = ScopeGraphResolver.resolve(&[facts]).unwrap();
        assert!(
            local_edges(&graph).is_empty(),
            "unbound name must not produce a local edge"
        );
    }

    // ── U6: Definition arm ────────────────────────────────────────────────────

    #[cfg(feature = "rust")]
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
        let graph = ScopeGraphResolver.resolve(&[facts]).unwrap();

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

    #[cfg(feature = "rust")]
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

        let graph = ScopeGraphResolver
            .resolve(&[facts_a, facts_b, facts_caller])
            .unwrap();

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

    #[cfg(feature = "rust")]
    #[test]
    fn local_shadows_same_name_definition() {
        // `process` is both a top-level function and a `let` binding inside `run`.
        // The LOCAL `process` must shadow the Definition — innermost scope wins.
        let src = "pub fn process() {} pub fn run() { let process = make(); process() }";
        let facts = RustExtractor.extract(src, "src/main.rs").unwrap();
        let graph = ScopeGraphResolver.resolve(&[facts]).unwrap();

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
    #[cfg(feature = "rust")]
    fn import_edges(graph: &CodeGraph) -> Vec<&Edge> {
        graph
            .edges
            .iter()
            .filter(|e| e.role == crate::graph::types::RefRole::Import)
            .collect()
    }

    #[cfg(feature = "rust")]
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

        let graph = ScopeGraphResolver.resolve(&[conf, app]).unwrap();

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

    /// Code→SQL, baseline: a Rust `TypeRef` naming a SQL table symbol resolves
    /// through the stitch phase as an ordinary ScopeGraph edge (the globally
    /// unique cross-namespace TypeRef path already covered in `subgraph.rs`'s
    /// tests). This establishes the pre-marker baseline the next test overrides.
    #[cfg(all(feature = "rust", feature = "sql"))]
    #[test]
    fn code_to_sql_typeref_edge_is_scope_graph_by_default() {
        use crate::extract::SqlExtractor;
        use crate::graph::types::RefRole;

        let schema = SqlExtractor
            .extract("CREATE TABLE users (id INT);", "db/schema.sql")
            .unwrap();
        let rust_file = RustExtractor
            .extract("pub fn run(u: users) {}", "src/app.rs")
            .unwrap();

        let graph = ScopeGraphResolver.resolve(&[schema, rust_file]).unwrap();

        let edges_to_sql_table: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.role == RefRole::TypeRef && e.to.to_scip_string().ends_with("users#"))
            .collect();

        assert_eq!(
            edges_to_sql_table.len(),
            1,
            "expected one Code→SQL TypeRef edge to 'users#', got {:?}",
            edges_to_sql_table
                .iter()
                .map(|e| format!(
                    "{} → {} ({:?}/{:?})",
                    e.from.to_scip_string(),
                    e.to.to_scip_string(),
                    e.role,
                    e.confidence
                ))
                .collect::<Vec<_>>()
        );
        let e = edges_to_sql_table[0];
        assert_eq!(
            e.provenance,
            Provenance::ScopeGraph,
            "without a cross_artifact marker, the edge stays ScopeGraph provenance"
        );
    }

    /// Code→SQL, marked cross-artifact: the same `users` TypeRef reference as
    /// [`code_to_sql_typeref_edge_is_scope_graph_by_default`], but with
    /// `cross_artifact: true` set on the source reference (as a future
    /// SQL-in-string extractor would set it). The scope-graph resolver must
    /// override both provenance and confidence — `Provenance::CrossArtifact` and
    /// `Confidence::NameOnly` — exactly as `SymbolTableResolver` already does,
    /// even though the match is otherwise globally unique (which would
    /// otherwise earn `Confidence::Scoped`).
    #[cfg(all(feature = "rust", feature = "sql"))]
    #[test]
    fn cross_artifact_reference_yields_cross_artifact_provenance_and_name_only_confidence() {
        use crate::extract::SqlExtractor;
        use crate::graph::types::RefRole;

        let schema = SqlExtractor
            .extract("CREATE TABLE users (id INT);", "db/schema.sql")
            .unwrap();
        let mut rust_file = RustExtractor
            .extract("pub fn run(u: users) {}", "src/app.rs")
            .unwrap();

        let marked = rust_file
            .references
            .iter_mut()
            .find(|r| r.role == RefRole::TypeRef && r.name == "users")
            .expect("Rust extractor must emit a TypeRef ref for 'users'");
        marked.cross_artifact = true;

        let graph = ScopeGraphResolver.resolve(&[schema, rust_file]).unwrap();

        let edges_to_sql_table: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.role == RefRole::TypeRef && e.to.to_scip_string().ends_with("users#"))
            .collect();

        assert_eq!(
            edges_to_sql_table.len(),
            1,
            "expected one Code→SQL TypeRef edge to 'users#', got {:?}",
            edges_to_sql_table
                .iter()
                .map(|e| format!(
                    "{} → {} ({:?}/{:?})",
                    e.from.to_scip_string(),
                    e.to.to_scip_string(),
                    e.role,
                    e.confidence
                ))
                .collect::<Vec<_>>()
        );
        let e = edges_to_sql_table[0];
        assert_eq!(
            e.confidence,
            Confidence::NameOnly,
            "cross-artifact ref must be forced to NameOnly regardless of unique match"
        );
        assert_eq!(
            e.provenance,
            Provenance::CrossArtifact,
            "cross-artifact ref must be attributed to Provenance::CrossArtifact"
        );
    }

    #[cfg(feature = "go")]
    #[test]
    fn go_same_package_cross_file_call_resolves_scoped() {
        // Go same-package call with NO import: `Run` in main.go calls `Helper`
        // in util.go, both `package main`. They share namespace ["main"], so the
        // unbound call is deferred and stitched to the unique same-namespace
        // `Helper`. Confidence is Scoped (not Exact — no explicit written path).
        use crate::extract::GoExtractor;
        use crate::graph::types::RefRole;
        let util = GoExtractor
            .extract("package main\nfunc Helper() {}\n", "util.go")
            .unwrap();
        let main = GoExtractor
            .extract("package main\nfunc Run() {\n\tHelper()\n}\n", "main.go")
            .unwrap();

        let graph = ScopeGraphResolver.resolve(&[util, main]).unwrap();

        let edges: Vec<&Edge> = graph
            .edges
            .iter()
            .filter(|e| {
                e.role == RefRole::Call
                    && e.from.to_scip_string().ends_with("main/Run().")
                    && e.to.to_scip_string().ends_with("main/Helper().")
            })
            .collect();
        assert_eq!(
            edges.len(),
            1,
            "expected exactly one Run→Helper cross-file edge, got: {:?}",
            graph
                .edges
                .iter()
                .map(|e| format!("{} → {}", e.from.to_scip_string(), e.to.to_scip_string()))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            edges[0].confidence,
            Confidence::Scoped,
            "same-package cross-file call must be Scoped"
        );
        assert_eq!(edges[0].provenance, Provenance::ScopeGraph);
    }

    #[cfg(feature = "rust")]
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

        let graph = ScopeGraphResolver.resolve(&[conf, other, app]).unwrap();

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

    #[cfg(feature = "rust")]
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

        let graph = ScopeGraphResolver.resolve(&[conf, app]).unwrap();

        assert!(
            import_edges(&graph).is_empty(),
            "import whose path matches no definition must yield no Tier-B edge"
        );
    }

    #[cfg(feature = "rust")]
    #[test]
    fn same_file_recursion_emits_no_self_edge() {
        // A recursive free function calls itself unqualified. The call binds to
        // the function's own same-file Definition; Tier-B's intra-file Definition
        // arm must NOT link the definition to itself — parity with Tier-A, which
        // skips the caller's own definition (`i == from_idx`).
        let facts = RustExtractor
            .extract(
                "pub fn countdown(n: u32) { countdown(n - 1) }",
                "src/rec.rs",
            )
            .unwrap();

        let graph = ScopeGraphResolver.resolve(&[facts]).unwrap();

        let self_edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.from == e.to)
            .map(|e| e.from.to_scip_string())
            .collect();
        assert!(
            self_edges.is_empty(),
            "recursion must not produce a from==to self-edge, got: {self_edges:?}"
        );
    }

    // ── U8b: Qualified-call resolution ────────────────────────────────────────

    /// Edges from `run` (the caller) that are NOT local edges and NOT Import edges.
    #[cfg(any(feature = "rust", feature = "ruby"))]
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

    #[cfg(feature = "rust")]
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

        let graph = ScopeGraphResolver.resolve(&[mod_a, mod_b, caller]).unwrap();

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

    #[cfg(feature = "ruby")]
    #[test]
    fn type_qualified_call_resolves_to_enclosing_type_member() {
        // A qualifier may name an enclosing TYPE, not just a namespace. Ruby's
        // `Alpha.compute` targets `…/Alpha#compute().` where `Alpha` is a `Type`
        // descriptor (a module). Two modules define `compute`; the qualifier must
        // disambiguate to `Alpha`'s, exactly as a namespace qualifier would — and
        // Tier-B must invent no edge for the same-named decoy.
        use crate::extract::RubyExtractor;
        let alpha = RubyExtractor
            .extract(
                "module Alpha\n  def self.compute\n    1\n  end\nend\n",
                "alpha.rb",
            )
            .unwrap();
        let beta = RubyExtractor
            .extract(
                "module Beta\n  def self.compute\n    2\n  end\nend\n",
                "beta.rb",
            )
            .unwrap();
        let main = RubyExtractor
            .extract("def run\n  Alpha.compute\nend\n", "main.rb")
            .unwrap();

        let graph = ScopeGraphResolver.resolve(&[alpha, beta, main]).unwrap();
        let call_edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| {
                e.role == crate::graph::types::RefRole::Call
                    && e.from.to_scip_string().ends_with("run().")
            })
            .collect();
        assert_eq!(
            call_edges.len(),
            1,
            "type qualifier must disambiguate to exactly one edge, got: {:?}",
            call_edges
                .iter()
                .map(|e| e.to.to_scip_string())
                .collect::<Vec<_>>()
        );
        assert!(
            call_edges[0]
                .to
                .to_scip_string()
                .ends_with("Alpha#compute()."),
            "must target Alpha#compute, got: {}",
            call_edges[0].to.to_scip_string()
        );
        assert_eq!(call_edges[0].confidence, Confidence::Exact);
    }

    #[cfg(feature = "rust")]
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

        let graph = ScopeGraphResolver.resolve(&[conf, caller]).unwrap();

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

    #[cfg(feature = "rust")]
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
        let graph = ScopeGraphResolver.resolve(&[facts]).unwrap();

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

    #[cfg(feature = "rust")]
    #[test]
    fn transitive_rust_pub_use_resolves_qualified_type_reference() {
        use crate::graph::types::RefRole;

        let definition = RustExtractor
            .extract("pub struct FusionParams {}", "src/api/variants.rs")
            .unwrap();
        let inner_reexport = RustExtractor
            .extract(
                "pub use super::variants::FusionParams as Params;",
                "src/api/graph_parse/mod.rs",
            )
            .unwrap();
        let outer_reexport = RustExtractor
            .extract(
                "pub use graph_parse::Params as FusionParams;",
                "src/api/mod.rs",
            )
            .unwrap();
        let consumer = RustExtractor
            .extract(
                "pub struct Request { params: crate::api::FusionParams }",
                "src/client.rs",
            )
            .unwrap();

        let graph = ScopeGraphResolver
            .resolve(&[definition, inner_reexport, outer_reexport, consumer])
            .unwrap();
        assert!(graph.edges.iter().any(|edge| {
            edge.role == RefRole::TypeRef
                && edge
                    .to
                    .to_scip_string()
                    .ends_with("api/variants/FusionParams#")
        }));
    }

    #[cfg(feature = "rust")]
    #[test]
    fn crate_root_reexport_resolves_without_synthetic_lib_namespace() {
        use crate::graph::types::RefRole;

        let definition = RustExtractor
            .extract("pub struct Thing {}", "src/variants.rs")
            .unwrap();
        let root = RustExtractor
            .extract("pub use variants::Thing;", "src/lib.rs")
            .unwrap();
        let consumer = RustExtractor
            .extract("pub struct Use { value: crate::Thing }", "src/use.rs")
            .unwrap();
        let graph = ScopeGraphResolver
            .resolve(&[definition, root, consumer])
            .unwrap();
        assert!(graph.edges.iter().any(|edge| {
            edge.role == RefRole::TypeRef && edge.to.to_scip_string().ends_with("variants/Thing#")
        }));
    }

    #[cfg(feature = "rust")]
    #[test]
    fn repeated_super_and_inline_module_reexports_keep_their_module_paths() {
        use crate::graph::types::RefRole;

        let definition = RustExtractor
            .extract("pub struct Thing {}", "src/variants.rs")
            .unwrap();
        let nested = RustExtractor
            .extract(
                "pub use super::super::variants::Thing;",
                "src/api/nested/mod.rs",
            )
            .unwrap();
        let inline = RustExtractor
            .extract(
                "pub mod public { pub use crate::variants::Thing; }",
                "src/lib.rs",
            )
            .unwrap();
        let consumer = RustExtractor
            .extract(
                "pub struct Use { a: crate::api::nested::Thing, b: crate::public::Thing }",
                "src/use.rs",
            )
            .unwrap();
        let graph = ScopeGraphResolver
            .resolve(&[definition, nested, inline, consumer])
            .unwrap();
        assert_eq!(
            graph
                .edges
                .iter()
                .filter(|edge| {
                    edge.role == RefRole::TypeRef
                        && edge.to.to_scip_string().ends_with("variants/Thing#")
                })
                .count(),
            2
        );
    }

    #[test]
    fn cyclic_or_ambiguous_rust_pub_use_emits_no_type_edge() {
        use crate::graph::types::RefRole;

        let cycle_a = RustExtractor
            .extract("pub use super::cycle_b::Thing;", "src/cycle_a.rs")
            .unwrap();
        let cycle_b = RustExtractor
            .extract("pub use super::cycle_a::Thing;", "src/cycle_b.rs")
            .unwrap();
        let cycle_consumer = RustExtractor
            .extract(
                "pub struct Use { value: crate::cycle_a::Thing }",
                "src/cycle_use.rs",
            )
            .unwrap();
        let cycle_graph = ScopeGraphResolver
            .resolve(&[cycle_a, cycle_b, cycle_consumer])
            .unwrap();
        assert!(
            !cycle_graph
                .edges
                .iter()
                .any(|edge| edge.role == RefRole::TypeRef),
            "cyclic aliases must not produce a precise type edge"
        );

        let first = RustExtractor
            .extract("pub struct Thing {}", "src/first.rs")
            .unwrap();
        let second = RustExtractor
            .extract("pub struct Thing {}", "src/second.rs")
            .unwrap();
        let aliases = RustExtractor
            .extract(
                "pub use super::first::Thing; pub use super::second::Thing;",
                "src/api/mod.rs",
            )
            .unwrap();
        let consumer = RustExtractor
            .extract("pub struct Use { value: crate::api::Thing }", "src/use.rs")
            .unwrap();
        let ambiguous_graph = ScopeGraphResolver
            .resolve(&[first, second, aliases, consumer])
            .unwrap();
        assert!(
            !ambiguous_graph
                .edges
                .iter()
                .any(|edge| edge.role == RefRole::TypeRef),
            "ambiguous aliases must not produce a precise type edge"
        );
    }

    #[test]
    fn scoped_struct_field_type_resolves_across_files() {
        use crate::graph::types::RefRole;

        let provider = RustExtractor
            .extract("pub struct FusionParams {}", "src/params.rs")
            .unwrap();
        let consumer = RustExtractor
            .extract(
                "pub struct Graph { params: crate::params::FusionParams }",
                "src/graph.rs",
            )
            .unwrap();
        let graph = ScopeGraphResolver.resolve(&[provider, consumer]).unwrap();
        assert!(graph.edges.iter().any(|edge| {
            edge.role == RefRole::TypeRef
                && edge.to.to_scip_string().ends_with("params/FusionParams#")
        }));
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
        let graph = ScopeGraphResolver.resolve(&[facts]).unwrap();

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

    #[cfg(feature = "rust")]
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

        let graph = ScopeGraphResolver.resolve(&[nested, caller]).unwrap();

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
    #[cfg(feature = "rust")]
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
            let graph = ScopeGraphResolver.resolve(&[facts]).unwrap();
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
            let graph = ScopeGraphResolver.resolve(&[facts]).unwrap();
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
            let graph = ScopeGraphResolver.resolve(&[facts]).unwrap();
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
            let graph = ScopeGraphResolver.resolve(&[service, app]).unwrap();
            let imports = import_edges(&graph);
            assert_eq!(imports.len(), 1, "expected one import edge for 'Service'");
            assert_eq!(
                imports[0].confidence,
                Confidence::Exact,
                "cross-file import must be Exact"
            );
        }

        // ── 5. Path-qualified call (unique namespace- or type-suffix match) → Exact ───
        {
            let util = RustExtractor
                .extract("pub fn validate() {}", "src/util.rs")
                .unwrap();
            let caller = RustExtractor
                .extract("pub fn run() { util::validate() }", "src/caller.rs")
                .unwrap();
            let graph = ScopeGraphResolver.resolve(&[util, caller]).unwrap();
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
