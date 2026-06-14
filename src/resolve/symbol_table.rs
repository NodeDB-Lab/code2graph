// SPDX-License-Identifier: Apache-2.0

//! Tier A resolver: fast, broad, name/scope based.
//!
//! Builds a `leaf-name → definitions` table across all files, attributes each
//! reference to the symbol whose span encloses it (the caller), and links it to
//! every definition sharing the callee's name. An ambiguous name that fans out
//! to several definitions tags each edge [`Confidence::NameOnly`]; a name with a
//! single global candidate is tagged [`Confidence::Scoped`]. Additionally, an
//! import reference whose `from_path` uniquely matches exactly one candidate's
//! module namespace suffix is tagged [`Confidence::Scoped`] while all other
//! fan-out edges for that reference stay [`Confidence::NameOnly`] (recall
//! preserved — no edges are dropped). This is the recall-first baseline that
//! works for every language without per-language binding rules — no edges are
//! dropped, only the confidence varies. A precise resolver tags its edges
//! [`Confidence::Exact`] instead.
//!
//! It returns neutral [`Edge`]s and never writes to storage.

use std::collections::HashMap;

use crate::graph::types::{CodeGraph, Confidence, Edge, FileFacts, Provenance, RefRole, Symbol};

use super::Resolver;
use super::{enclosing_symbol_index, namespaces_end_with, normalize_from_path};

/// Name-table resolver. See module docs.
#[derive(Debug, Default, Clone, Copy)]
pub struct SymbolTableResolver;

impl Resolver for SymbolTableResolver {
    fn resolve(&self, files: &[FileFacts]) -> CodeGraph {
        // leaf name → indices into the flattened symbol list
        let mut symbols: Vec<Symbol> = Vec::new();
        for f in files {
            symbols.extend(f.symbols.iter().cloned());
        }

        let mut by_name: HashMap<&str, Vec<usize>> = HashMap::new();
        for (i, s) in symbols.iter().enumerate() {
            if let Some(name) = s.id.leaf_name() {
                by_name.entry(name).or_default().push(i);
            }
        }

        // Per-file symbol index for caller attribution (span containment).
        let mut by_file: HashMap<&str, Vec<usize>> = HashMap::new();
        for (i, s) in symbols.iter().enumerate() {
            by_file.entry(s.file.as_str()).or_default().push(i);
        }

        let mut edges: Vec<Edge> = Vec::new();
        for f in files {
            let file_syms = by_file.get(f.file.as_str());
            for r in &f.references {
                // The caller: innermost symbol in this file whose span holds the ref.
                let Some(from_idx) =
                    file_syms.and_then(|idxs| enclosing_symbol_index(&symbols, idxs, r.occ.byte))
                else {
                    continue; // reference not inside any extracted symbol — unattributable
                };

                let Some(targets) = by_name.get(r.name.as_str()) else {
                    continue; // unresolved: no definition with this name
                };

                // Count non-self candidates first to determine confidence,
                // then iterate the same filtered set to emit edges — no
                // intermediate Vec needed.
                let non_self_count = targets.iter().filter(|&&i| i != from_idx).count();

                // Import-path disambiguation (Win-2): when this is an Import
                // reference with a non-empty `from_path`, find the single
                // non-self candidate whose namespace chain ends with the
                // normalised path segments.  If exactly one matches, that
                // candidate's edge is promoted to Scoped; all others remain
                // NameOnly.  Recall is preserved — no edges are dropped.
                let import_bound: Option<usize> = if r.role == RefRole::Import {
                    r.from_path.as_deref().and_then(|p| {
                        let segs = normalize_from_path(p);
                        if segs.is_empty() {
                            return None;
                        }
                        let mut matched = targets.iter().copied().filter(|&i| {
                            i != from_idx && namespaces_end_with(&symbols[i].id, &segs)
                        });
                        let first = matched.next()?;
                        // Promote only when exactly one candidate matches.
                        if matched.next().is_none() {
                            Some(first)
                        } else {
                            None
                        }
                    })
                } else {
                    None
                };

                for &to_idx in targets.iter().filter(|&&i| i != from_idx) {
                    // Decide per-edge confidence:
                    // - If Win-2 fired (import_bound == Some(to_idx)): Scoped
                    //   for the matched target, NameOnly for all others.
                    // - Otherwise fall back to Win-1: Scoped iff unique candidate.
                    let confidence = if import_bound == Some(to_idx) {
                        Confidence::Scoped
                    } else if import_bound.is_some() {
                        // Win-2 fired but this is not the matched target.
                        Confidence::NameOnly
                    } else if non_self_count == 1 {
                        Confidence::Scoped
                    } else {
                        Confidence::NameOnly
                    };

                    edges.push(Edge {
                        from: symbols[from_idx].id.clone(),
                        to: symbols[to_idx].id.clone(),
                        role: r.role,
                        confidence,
                        provenance: Provenance::SymbolTable,
                        occ: r.occ.clone(),
                    });
                }
            }
        }

        CodeGraph { symbols, edges }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::Extractor;
    use crate::extract::JavaExtractor;
    use crate::extract::RustExtractor;

    #[test]
    fn resolves_cross_file_call() {
        let lib = RustExtractor
            .extract("pub fn helper() -> u32 { 1 }", "src/util.rs")
            .unwrap();
        let main = RustExtractor
            .extract("pub fn run() -> u32 { helper() }", "src/main.rs")
            .unwrap();

        let graph = SymbolTableResolver.resolve(&[lib, main]);

        // one Call edge: run → helper
        let calls: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.role == RefRole::Call)
            .collect();
        assert_eq!(calls.len(), 1);
        let e = calls[0];
        assert!(e.from.to_scip_string().ends_with("run()."));
        assert!(e.to.to_scip_string().ends_with("util/helper()."));
        assert_eq!(e.confidence, Confidence::Scoped);
        // Provenance records the deriving analysis, independent of confidence.
        assert_eq!(e.provenance, Provenance::SymbolTable);
        assert_eq!(e.occ.file, "src/main.rs");
    }

    #[test]
    fn unresolved_calls_produce_no_edge() {
        let main = RustExtractor
            .extract("pub fn run() { nonexistent_fn() }", "src/main.rs")
            .unwrap();
        let graph = SymbolTableResolver.resolve(&[main]);
        assert!(graph.edges.is_empty());
    }

    #[test]
    fn resolves_cross_file_inheritance() {
        let base = JavaExtractor
            .extract("package p; public class Base {}", "src/p/Base.java")
            .unwrap();
        let sub = JavaExtractor
            .extract(
                "package p; public class Sub extends Base {}",
                "src/p/Sub.java",
            )
            .unwrap();

        let graph = SymbolTableResolver.resolve(&[base, sub]);

        // exactly one IsImplementation edge: Sub → Base
        let inherits: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.role == RefRole::IsImplementation)
            .collect();
        assert_eq!(inherits.len(), 1);
        let e = inherits[0];
        assert!(
            e.from.to_scip_string().ends_with("p/Sub#"),
            "from was: {}",
            e.from.to_scip_string()
        );
        assert!(
            e.to.to_scip_string().ends_with("p/Base#"),
            "to was: {}",
            e.to.to_scip_string()
        );
        assert_eq!(e.confidence, Confidence::Scoped);
        assert_eq!(e.occ.file, "src/p/Sub.java");
    }

    #[test]
    fn resolves_cross_file_rust_trait_impl_inheritance() {
        // File A defines the trait.
        let greet = RustExtractor
            .extract("pub trait Greet {}", "src/greet.rs")
            .unwrap();
        // File B defines the struct + its trait impl.
        let p = RustExtractor
            .extract("pub struct P;\nimpl Greet for P {}", "src/p.rs")
            .unwrap();

        let graph = SymbolTableResolver.resolve(&[greet, p]);

        // Exactly one IsImplementation edge: P → Greet
        let inherits: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.role == RefRole::IsImplementation)
            .collect();
        assert_eq!(
            inherits.len(),
            1,
            "expected 1 IsImplementation edge, got {:?}",
            inherits.len()
        );
        let e = inherits[0];
        assert!(
            e.from.to_scip_string().ends_with("p/P#") || e.from.to_scip_string().ends_with("P#"),
            "unexpected from: {}",
            e.from.to_scip_string()
        );
        assert!(
            e.to.to_scip_string().ends_with("greet/Greet#")
                || e.to.to_scip_string().ends_with("Greet#"),
            "unexpected to: {}",
            e.to.to_scip_string()
        );
        assert_eq!(e.confidence, Confidence::Scoped);
        assert_eq!(e.occ.file, "src/p.rs");
    }

    #[test]
    fn resolves_cross_file_python_import_edge() {
        use crate::extract::PythonExtractor;

        // File A: src/pkg/models.py defines class Config.
        let a = PythonExtractor
            .extract("class Config:\n    pass\n", "src/pkg/models.py")
            .unwrap();

        // File B: src/app.py imports Config from pkg.models.
        let b = PythonExtractor
            .extract("from pkg.models import Config\n", "src/app.py")
            .unwrap();

        let graph = SymbolTableResolver.resolve(&[a, b]);

        // Exactly one Import edge: module(app) → Config
        let imports: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.role == RefRole::Import)
            .collect();
        assert_eq!(
            imports.len(),
            1,
            "expected one Import edge, got {:?}",
            imports.len()
        );
        let e = imports[0];
        assert!(
            e.from.to_scip_string().ends_with("app/"),
            "from (module) was: {}",
            e.from.to_scip_string()
        );
        assert!(
            e.to.to_scip_string().ends_with("Config#"),
            "to was: {}",
            e.to.to_scip_string()
        );
        assert_eq!(e.confidence, Confidence::Scoped);
    }

    #[test]
    fn resolves_import_edge_from_module() {
        use crate::graph::types::{Occurrence, Reference};

        // File A defines `Config`.
        let a = RustExtractor
            .extract("pub struct Config {}", "src/conf.rs")
            .unwrap();

        // File B's module imports it. The extractor gives B a module symbol
        // spanning the whole file; we inject an Import reference whose byte sits
        // in the leading comment — inside the module span but not inside any
        // smaller symbol — so the resolver attributes the edge's source to the
        // module, exactly as a real top-level `use`/`import` would.
        let mut b = RustExtractor
            .extract("// uses Config\npub fn run() {}", "src/app.rs")
            .unwrap();
        b.references.push(Reference {
            name: "Config".to_owned(),
            occ: Occurrence {
                file: "src/app.rs".to_owned(),
                line: 1,
                col: 0,
                byte: 0,
            },
            role: RefRole::Import,
            source_module: None,
            from_path: None,
            qualifier: None,
            scope: None,
        });

        let graph = SymbolTableResolver.resolve(&[a, b]);

        // Exactly one Import edge: module(app) → Config
        let imports: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.role == RefRole::Import)
            .collect();
        assert_eq!(imports.len(), 1, "expected one Import edge");
        let e = imports[0];
        assert!(
            e.from.to_scip_string().ends_with("app/"),
            "from (module) was: {}",
            e.from.to_scip_string()
        );
        assert!(
            e.to.to_scip_string().ends_with("conf/Config#"),
            "to was: {}",
            e.to.to_scip_string()
        );
        assert_eq!(e.confidence, Confidence::Scoped);
    }

    #[test]
    fn ambiguous_name_fan_out_stays_name_only() {
        // Two files each define a function with the same leaf name "process".
        // A third file calls "process" — the resolver must emit edges to BOTH
        // definitions and tag them NameOnly (ambiguous fan-out, not Scoped).
        let a = RustExtractor
            .extract("pub fn process() -> u32 { 1 }", "src/mod_a.rs")
            .unwrap();
        let b = RustExtractor
            .extract("pub fn process() -> u32 { 2 }", "src/mod_b.rs")
            .unwrap();
        let caller = RustExtractor
            .extract("pub fn run() { process() }", "src/main.rs")
            .unwrap();

        let graph = SymbolTableResolver.resolve(&[a, b, caller]);

        // Filter to Call edges only (exclude any IsImplementation/Import noise).
        let calls: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.role == RefRole::Call)
            .collect();

        // Recall preserved: both definitions must be reachable.
        assert_eq!(
            calls.len(),
            2,
            "expected 2 fan-out edges, got {}",
            calls.len()
        );

        // Every fan-out edge must stay NameOnly — not promoted to Scoped.
        for e in &calls {
            assert_eq!(
                e.confidence,
                Confidence::NameOnly,
                "ambiguous fan-out edge should be NameOnly, got {:?}",
                e.confidence
            );
        }

        // Both targets should be the two "process" definitions.
        let targets: std::collections::HashSet<String> =
            calls.iter().map(|e| e.to.to_scip_string()).collect();
        assert!(
            targets.iter().any(|s| s.ends_with("mod_a/process().")),
            "missing mod_a target; got: {:?}",
            targets
        );
        assert!(
            targets.iter().any(|s| s.ends_with("mod_b/process().")),
            "missing mod_b target; got: {:?}",
            targets
        );
    }

    // ── Win-2: import-path disambiguation ────────────────────────────────────

    /// Two classes named `Config` in different Java packages; importer of one
    /// package gets `Scoped` for the matching def and `NameOnly` for the other.
    ///
    /// We use Java because its `package` declaration drives namespace derivation
    /// cleanly: `package com.example;` → namespaces `["com","example"]`, and
    /// `import com.example.Config` → `from_path = "com.example"`.  The suffix
    /// match is exact and unambiguous.
    #[test]
    fn import_disambiguation_promotes_matching_package() {
        // File 1: com.example package defines Config.
        let a = JavaExtractor
            .extract(
                "package com.example;\npublic class Config {}",
                "src/com/example/Config.java",
            )
            .unwrap();

        // File 2: com.other package also defines Config (the decoy).
        let b = JavaExtractor
            .extract(
                "package com.other;\npublic class Config {}",
                "src/com/other/Config.java",
            )
            .unwrap();

        // File 3: imports Config specifically from com.example.
        let c = JavaExtractor
            .extract(
                "package app;\nimport com.example.Config;\npublic class App {}",
                "src/app/App.java",
            )
            .unwrap();

        let graph = SymbolTableResolver.resolve(&[a, b, c]);

        let imports: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.role == RefRole::Import)
            .collect();

        // Recall preserved: BOTH Config defs must produce an edge.
        assert_eq!(
            imports.len(),
            2,
            "expected 2 Import edges (recall preserved), got {}: {:?}",
            imports.len(),
            imports
                .iter()
                .map(|e| e.to.to_scip_string())
                .collect::<Vec<_>>()
        );

        // Find the two edges by their SCIP `to` strings.
        let example_edge = imports
            .iter()
            .find(|e| e.to.to_scip_string().contains("com/example/Config"))
            .expect("expected edge to com.example.Config");
        let other_edge = imports
            .iter()
            .find(|e| e.to.to_scip_string().contains("com/other/Config"))
            .expect("expected edge to com.other.Config");

        // The matched package gets Scoped; the decoy stays NameOnly.
        assert_eq!(
            example_edge.confidence,
            Confidence::Scoped,
            "com.example.Config should be Scoped (from_path match), got {:?}",
            example_edge.confidence
        );
        assert_eq!(
            other_edge.confidence,
            Confidence::NameOnly,
            "com.other.Config should be NameOnly (no from_path match), got {:?}",
            other_edge.confidence
        );
    }

    /// Negative: `from_path` that matches no candidate's namespace leaves all
    /// edges at their existing Win-1 confidence (NameOnly for ambiguous fan-out).
    #[test]
    fn import_disambiguation_no_match_leaves_fan_out_name_only() {
        // Two classes named `Config` in unrelated packages.
        let a = JavaExtractor
            .extract(
                "package com.alpha;\npublic class Config {}",
                "src/com/alpha/Config.java",
            )
            .unwrap();
        let b = JavaExtractor
            .extract(
                "package com.beta;\npublic class Config {}",
                "src/com/beta/Config.java",
            )
            .unwrap();

        // Importer whose from_path matches neither package ("com.gamma" is external).
        let c = JavaExtractor
            .extract(
                "package app;\nimport com.gamma.Config;\npublic class App {}",
                "src/app/App.java",
            )
            .unwrap();

        let graph = SymbolTableResolver.resolve(&[a, b, c]);

        let imports: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.role == RefRole::Import)
            .collect();

        // Recall preserved: still two edges even though no path matches.
        assert_eq!(
            imports.len(),
            2,
            "expected 2 Import edges, got {}",
            imports.len()
        );

        // No promotion — both stay NameOnly (Win-1: non-unique candidate).
        for e in &imports {
            assert_eq!(
                e.confidence,
                Confidence::NameOnly,
                "unmatched import fan-out should stay NameOnly, got {:?} for {}",
                e.confidence,
                e.to.to_scip_string()
            );
        }
    }

    #[test]
    fn typeref_produces_typeref_edge() {
        // File A defines `Config`; file B uses it as a parameter type.
        // Tier-A resolves cross-file by name: one global candidate → Scoped (Win-1).
        // The key assertion is that `r.role` is copied onto the edge as TypeRef.
        let a = RustExtractor
            .extract("pub struct Config {}", "src/conf.rs")
            .unwrap();
        let b = RustExtractor
            .extract("pub fn run(cfg: Config) {}", "src/app.rs")
            .unwrap();

        let graph = SymbolTableResolver.resolve(&[a, b]);

        // Filter to TypeRef-role edges only.
        let typeref_edges: Vec<_> = graph
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
            e.to.to_scip_string().ends_with("Config#"),
            "TypeRef edge to must end with 'Config#' (the struct def), got: {}",
            e.to.to_scip_string()
        );
        assert_eq!(
            e.confidence,
            Confidence::Scoped,
            "single global candidate → Win-1 Scoped, got: {:?}",
            e.confidence
        );
    }

    // ── SQL cross-artifact resolution tests ──────────────────────────────────

    /// Intra-SQL: a query file referencing a table defined in a schema file
    /// resolves to a TypeRef edge pointing at the table's SCIP symbol, Scoped
    /// (unique global candidate → Win-1).
    #[test]
    fn intra_sql_typeref_edge_from_query_to_table() {
        use crate::extract::SqlExtractor;

        // File A: defines the `users` table.
        let schema = SqlExtractor
            .extract("CREATE TABLE users (id INT);", "db/schema.sql")
            .unwrap();
        // File B: SELECT from `users` → emits a TypeRef reference.
        let query = SqlExtractor
            .extract("SELECT * FROM users;", "db/query.sql")
            .unwrap();

        let graph = SymbolTableResolver.resolve(&[schema, query]);

        // Expect exactly one TypeRef edge whose `to` ends with `users#`.
        let typeref_edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.role == RefRole::TypeRef && e.to.to_scip_string().ends_with("users#"))
            .collect();

        assert_eq!(
            typeref_edges.len(),
            1,
            "expected one intra-SQL TypeRef edge to 'users#', got {:?}: {:?}",
            typeref_edges.len(),
            graph
                .edges
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

        let e = typeref_edges[0];
        // Unique global candidate → Win-1 Scoped.
        assert_eq!(
            e.confidence,
            Confidence::Scoped,
            "unique table candidate should be Scoped, got {:?}",
            e.confidence
        );
        assert_eq!(e.occ.file, "db/query.sql");
    }

    /// Code→SQL: a Rust file referencing the type name `users` resolves to the
    /// SQL `users` table definition.  Confidence is Scoped when `users` is the
    /// only global candidate (Win-1).
    #[test]
    fn code_to_sql_typeref_edge_rust_to_table() {
        use crate::extract::SqlExtractor;

        // SQL file: defines the `users` table.
        let schema = SqlExtractor
            .extract("CREATE TABLE users (id INT);", "db/schema.sql")
            .unwrap();

        // Rust file: references `users` as a type name in a function signature.
        // `users` is ≥3 chars so it passes the MIN_REF_LEN filter.
        let rust_file = RustExtractor
            .extract("pub fn run(u: users) {}", "src/app.rs")
            .unwrap();

        // Sanity-check: the Rust extractor must have captured a TypeRef for `users`.
        assert!(
            rust_file
                .references
                .iter()
                .any(|r| r.role == RefRole::TypeRef && r.name == "users"),
            "Rust extractor must emit a TypeRef ref for 'users'; refs: {:?}",
            rust_file.references
        );

        let graph = SymbolTableResolver.resolve(&[schema, rust_file]);

        // The edge must resolve to the SQL table's SCIP string (ends with `users#`).
        let edges_to_sql_table: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.role == RefRole::TypeRef && e.to.to_scip_string().ends_with("users#"))
            .collect();

        assert_eq!(
            edges_to_sql_table.len(),
            1,
            "expected one Code→SQL TypeRef edge to 'users#', got {:?}: {:?}",
            edges_to_sql_table.len(),
            graph
                .edges
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
            Confidence::Scoped,
            "unique global candidate → Scoped (Win-1), got {:?}",
            e.confidence
        );
        assert_eq!(e.occ.file, "src/app.rs");
    }

    // ── HCL cross-artifact resolution tests ──────────────────────────────────

    /// Intra-HCL: `resource "aws_subnet" "main" {}` defined in the same file as
    /// `resource "aws_instance" "web" { subnet_id = aws_subnet.main.id }`.
    /// The traversal emits a TypeRef ref (name `main`, qualifier `aws_subnet`).
    /// With `aws_subnet/main#` as the sole global candidate for name `main`,
    /// Win-1 fires → Confidence::Scoped.
    #[test]
    fn intra_hcl_typeref_edge_from_instance_to_subnet() {
        use crate::extract::HclExtractor;

        // One file defines both resources.
        let hcl = HclExtractor
            .extract(
                r#"
resource "aws_subnet" "main" {}
resource "aws_instance" "web" { subnet_id = aws_subnet.main.id }
"#,
                // File stem deliberately NOT "main": the per-file module symbol is
                // named after the file stem and would otherwise collide in `by_name`
                // with the `aws_subnet."main"` resource (honest NameOnly fan-out).
                "infra/network.tf",
            )
            .unwrap();

        let graph = SymbolTableResolver.resolve(&[hcl]);

        // Expect exactly one TypeRef edge whose `to` ends with `aws_subnet/main#`.
        let typeref_edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| {
                e.role == RefRole::TypeRef && e.to.to_scip_string().ends_with("aws_subnet/main#")
            })
            .collect();

        assert_eq!(
            typeref_edges.len(),
            1,
            "expected one intra-HCL TypeRef edge to 'aws_subnet/main#', got {:?}: {:?}",
            typeref_edges.len(),
            graph
                .edges
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

        let e = typeref_edges[0];
        // `main` is the only global candidate → Win-1 → Scoped.
        assert_eq!(
            e.confidence,
            Confidence::Scoped,
            "unique subnet candidate should be Scoped (Win-1), got {:?}",
            e.confidence
        );
        // `from` should be the aws_instance/web symbol.
        assert!(
            e.from.to_scip_string().ends_with("aws_instance/web#"),
            "edge `from` should be 'aws_instance/web#', got: {}",
            e.from.to_scip_string()
        );
        assert_eq!(e.occ.file, "infra/network.tf");
    }

    /// Intra-HCL: `module "vpc" {}` defined alongside
    /// `resource "aws_instance" "web" { x = module.vpc.id }`.
    /// Traversal → name `vpc`, qualifier `module`; `module/vpc#` is the sole
    /// candidate → Win-1 → Scoped.
    #[test]
    fn intra_hcl_typeref_edge_from_resource_to_module() {
        use crate::extract::HclExtractor;

        let hcl = HclExtractor
            .extract(
                r#"
module "vpc" { source = "./vpc" }
resource "aws_instance" "web" { vpc_id = module.vpc.id }
"#,
                "infra/main.tf",
            )
            .unwrap();

        let graph = SymbolTableResolver.resolve(&[hcl]);

        let typeref_edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| {
                e.role == RefRole::TypeRef && e.to.to_scip_string().ends_with("module/vpc#")
            })
            .collect();

        assert_eq!(
            typeref_edges.len(),
            1,
            "expected one TypeRef edge to 'module/vpc#', got {:?}: {:?}",
            typeref_edges.len(),
            graph
                .edges
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

        let e = typeref_edges[0];
        assert_eq!(
            e.confidence,
            Confidence::Scoped,
            "unique module/vpc candidate should be Scoped (Win-1), got {:?}",
            e.confidence
        );
        assert!(
            e.from.to_scip_string().ends_with("aws_instance/web#"),
            "edge `from` should be 'aws_instance/web#', got: {}",
            e.from.to_scip_string()
        );
    }

    /// Regression: single-candidate import (Win-1) remains Scoped with Win-2 in place.
    #[test]
    fn import_disambiguation_single_candidate_stays_scoped() {
        // Identical to the existing Python single-candidate test, using Java.
        let a = JavaExtractor
            .extract(
                "package com.example;\npublic class Config {}",
                "src/com/example/Config.java",
            )
            .unwrap();
        let b = JavaExtractor
            .extract(
                "package app;\nimport com.example.Config;\npublic class App {}",
                "src/app/App.java",
            )
            .unwrap();

        let graph = SymbolTableResolver.resolve(&[a, b]);

        let imports: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.role == RefRole::Import)
            .collect();

        assert_eq!(imports.len(), 1, "expected exactly one Import edge");
        // Win-2 fires (unique path match) → Scoped.
        assert_eq!(
            imports[0].confidence,
            Confidence::Scoped,
            "single-candidate import should be Scoped"
        );
    }
}
