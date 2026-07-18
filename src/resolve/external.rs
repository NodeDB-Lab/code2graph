// SPDX-License-Identifier: Apache-2.0

//! SCA-reachability resolver: unresolved calls into dependency code.
//!
//! [`ExternalResolver`] is the software-composition-analysis (SCA) substrate.
//! When a call site references a name that was imported from an external module
//! (i.e. the import is backed by a `from_path` pointing outside the analyzed
//! file set), this resolver mints a synthetic **external target** symbol and
//! emits a `RefRole::Call` edge from the enclosing function to that target,
//! tagged `Confidence::NameOnly` and `Provenance::External`.
//!
//! The resulting graph answers: *"is the vulnerable dependency function actually
//! called in this codebase?"* — a reachability question, not a vulnerability
//! judgement. code2graph emits the structural fact; the consumer applies SCA
//! policy on top.
//!
//! # Honesty guard
//!
//! An external edge is emitted **only** when the call name is both:
//! 1. **Not** defined in the analyzed file set (not internally resolvable), and
//! 2. **Present** in the file's import map — an `Import` reference with a
//!    non-empty `from_path` that names the dependency module.
//!
//! A call to a name with no import evidence is silently skipped. This prevents
//! typos, builtins, and dynamically-injected names from being fanned out to
//! phantom external symbols.
//!
//! # Minted symbol shape
//!
//! The external target's `SymbolId` is:
//! ```text
//! codegraph . . . <pkg_seg_1>/…/<pkg_seg_N>/name.
//! ```
//! where `<pkg_seg_i>` are the normalized segments of `from_path` (split on
//! `.`, `/`, `:`, anchors and empty segments stripped) and `name` is the
//! leaf call name. For example, `from requests import get` + `get()` produces:
//! ```text
//! codegraph . . . requests/get.
//! ```
//! The package coordinate is intentionally left empty (the `global` constructor
//! defaults to an unknown package); a consumer with access to a lockfile or
//! advisory database can enrich it via `SymbolId::with_package`.
//!
//! External target symbols are **not** added to the `symbols` vec of the
//! returned `CodeGraph` — they appear only as edge `to` endpoints, so the
//! symbol list remains the internally-extracted definitions.

use std::collections::{HashMap, HashSet};
use std::iter::once;

use crate::graph::types::{CodeGraph, Confidence, Edge, FileFacts, Provenance, RefRole, Symbol};
use crate::symbol::{Descriptor, SymbolId};

use super::{Resolver, dedup_files_last_wins, enclosing_symbol_index, normalize_from_path};

/// SCA-reachability resolver. See module docs.
#[derive(Debug, Default, Clone, Copy)]
pub struct ExternalResolver;

impl Resolver for ExternalResolver {
    fn resolve(&self, files: &[FileFacts]) -> crate::Result<CodeGraph> {
        crate::validate_file_facts(files)?;
        let files = dedup_files_last_wins(files);
        // ── 1. Flatten all symbols, mirroring NormalizedNameResolver's layout ──
        let symbols: Vec<Symbol> = files
            .iter()
            .flat_map(|f| f.symbols.iter().cloned())
            .collect();

        // ── 2. Per-file symbol index for enclosing-symbol attribution ──────────
        let mut by_file: HashMap<&str, Vec<usize>> = HashMap::new();
        for (i, s) in symbols.iter().enumerate() {
            by_file.entry(s.file.as_str()).or_default().push(i);
        }

        // ── 3. Global set of internally-known leaf names ───────────────────────
        // A name is "internally resolvable" iff at least one extracted symbol has
        // that leaf name. Any call to such a name is already handled (or
        // deliberately deferred) by the precise resolvers; we must not shadow it.
        let mut known_names: HashSet<&str> = HashSet::new();
        for s in &symbols {
            if let Some(leaf) = s.id.leaf_name() {
                known_names.insert(leaf);
            }
        }

        // ── 4. Emit external edges ─────────────────────────────────────────────
        let mut edges: Vec<Edge> = Vec::new();
        for f in files {
            let file_syms = by_file.get(f.file.as_str());
            let lang = f.lang.as_str();

            // Build a per-file import map: imported name → from_path.
            // Only Import refs with a non-empty from_path participate.
            // First occurrence wins on duplicate names (deterministic).
            let mut import_map: HashMap<&str, &str> = HashMap::new();
            for r in &f.references {
                if r.role != RefRole::Import {
                    continue;
                }
                let Some(fp) = r.from_path.as_deref() else {
                    continue;
                };
                if fp.is_empty() {
                    continue;
                }
                import_map.entry(r.name.as_str()).or_insert(fp);
            }

            // Walk call references; emit an external edge for each one that is
            // import-backed and not internally resolvable.
            for r in &f.references {
                // v1 scope: Call refs only.
                if r.role != RefRole::Call {
                    continue;
                }

                // Attribute the reference to its enclosing symbol (the caller).
                let Some(from_idx) =
                    file_syms.and_then(|idxs| enclosing_symbol_index(&symbols, idxs, r.occ.byte))
                else {
                    continue; // reference not enclosed by any extracted symbol
                };

                // If the name is internally resolvable, skip — let the precise
                // resolvers handle it; we must not emit a spurious External edge.
                if known_names.contains(r.name.as_str()) {
                    continue;
                }

                // Honesty guard: the call must be backed by an import.
                let Some(&from_path) = import_map.get(r.name.as_str()) else {
                    continue; // not import-backed → typo / builtin / dynamic
                };

                // Mint the external target symbol: namespaced by normalized
                // from_path segments, leaf is the called name as a Term.
                let descriptors: Vec<Descriptor> = normalize_from_path(from_path)
                    .into_iter()
                    .map(|seg| Descriptor::Namespace(seg.to_owned()))
                    .chain(once(Descriptor::Term(r.name.clone())))
                    .collect();
                let to = SymbolId::global(lang, descriptors);

                edges.push(Edge {
                    from: symbols[from_idx].id.clone(),
                    to,
                    role: RefRole::Call,
                    confidence: Confidence::NameOnly,
                    provenance: Provenance::External,
                    occ: r.occ.clone(),
                });
            }
        }

        Ok(CodeGraph { symbols, edges })
    }
}

#[cfg(all(test, any(feature = "python", feature = "rust")))]
mod tests {
    use super::*;
    #[cfg(any(feature = "python", feature = "rust"))]
    use crate::extract::Extractor;
    #[cfg(feature = "python")]
    use crate::extract::PythonExtractor;
    #[cfg(feature = "rust")]
    use crate::extract::RustExtractor;
    #[cfg(feature = "rust")]
    use crate::graph::types::{Occurrence, Reference};

    // ── Test 1: Python reachability happy path ────────────────────────────────

    /// `from requests import get` + `get()` → exactly one External Call edge
    /// whose `to` ends with `requests/get.`, `Confidence::NameOnly`,
    /// `Provenance::External`, and `from` is the `run` symbol.
    #[cfg(feature = "python")]
    #[test]
    fn python_import_backed_call_emits_external_edge() {
        let file = PythonExtractor
            .extract(
                "from requests import get\n\ndef run():\n    get()\n",
                "src/client.py",
            )
            .unwrap();

        let graph = ExternalResolver.resolve(&[file]).unwrap();

        let ext_edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.provenance == Provenance::External && e.role == RefRole::Call)
            .collect();

        assert_eq!(
            ext_edges.len(),
            1,
            "expected exactly one External Call edge, got {}: {:?}",
            ext_edges.len(),
            ext_edges
                .iter()
                .map(|e| format!(
                    "{} → {} ({:?}/{:?})",
                    e.from.to_scip_string(),
                    e.to.to_scip_string(),
                    e.confidence,
                    e.provenance
                ))
                .collect::<Vec<_>>()
        );

        let e = ext_edges[0];
        assert!(
            e.to.to_scip_string().ends_with("requests/get."),
            "external target must end with `requests/get.`, got: {}",
            e.to.to_scip_string()
        );
        assert_eq!(
            e.confidence,
            Confidence::NameOnly,
            "external edge must be NameOnly, got {:?}",
            e.confidence
        );
        assert_eq!(
            e.provenance,
            Provenance::External,
            "provenance must be External, got {:?}",
            e.provenance
        );
        assert!(
            e.from.to_scip_string().ends_with("run().") || e.from.to_scip_string().contains("run"),
            "edge `from` must be the `run` symbol, got: {}",
            e.from.to_scip_string()
        );
    }

    // ── Test 2: Honesty guard ─────────────────────────────────────────────────

    /// A call to `mystery()` with no import of `mystery` must produce ZERO
    /// external edges. Non-import-backed unresolved calls are silently skipped.
    #[cfg(feature = "python")]
    #[test]
    fn non_import_backed_call_emits_nothing() {
        let file = PythonExtractor
            .extract("def run():\n    mystery()\n", "src/client.py")
            .unwrap();

        let graph = ExternalResolver.resolve(&[file]).unwrap();

        let ext_edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.provenance == Provenance::External)
            .collect();

        assert!(
            ext_edges.is_empty(),
            "non-import-backed call must not produce an External edge; got {:?}",
            ext_edges
                .iter()
                .map(|e| format!(
                    "{} → {} ({:?}/{:?})",
                    e.from.to_scip_string(),
                    e.to.to_scip_string(),
                    e.confidence,
                    e.provenance
                ))
                .collect::<Vec<_>>()
        );
    }

    // ── Test 3: Internal resolution is not shadowed ───────────────────────────

    /// When a called name IS defined in the analyzed set, no External edge is
    /// emitted for it — the precise resolvers handle it.
    ///
    /// Two Rust files: `pub fn helper(){}` in `src/util.rs`, and a caller in
    /// `src/main.rs` that imports `helper` via `use util::helper` (injected as an
    /// Import ref) and calls it. `ExternalResolver` must emit zero External edges
    /// because `helper` appears in the global by_name set.
    #[cfg(feature = "rust")]
    #[test]
    fn internally_defined_name_not_shadowed_by_external_edge() {
        let lib = RustExtractor
            .extract("pub fn helper() -> u32 { 1 }", "src/util.rs")
            .unwrap();
        // Extract a real caller symbol so enclosing_symbol_index can attribute the ref.
        let mut caller = RustExtractor
            .extract("pub fn run() -> u32 { 0 }", "src/main.rs")
            .unwrap();

        // Inject an Import ref for `helper` (as if `use util::helper;`).
        caller.references.push(Reference {
            name: "helper".to_owned(),
            occ: Occurrence {
                file: "src/main.rs".to_owned(),
                line: 1,
                col: 0,
                byte: 0,
            },
            role: RefRole::Import,
            source_module: None,
            from_path: Some("util".to_owned()),
            is_reexport: false,
            imported_name: None,
            qualifier: None,
            scope: None,
            type_ref_ctx: None,
            cross_artifact: false,
            self_receiver: false,
        });
        // Inject a Call ref for `helper` inside the `run` span.
        caller.references.push(Reference {
            name: "helper".to_owned(),
            occ: Occurrence {
                file: "src/main.rs".to_owned(),
                line: 1,
                col: 22,
                byte: 22,
            },
            role: RefRole::Call,
            source_module: None,
            from_path: None,
            is_reexport: false,
            imported_name: None,
            qualifier: None,
            scope: None,
            type_ref_ctx: None,
            cross_artifact: false,
            self_receiver: false,
        });

        let graph = ExternalResolver.resolve(&[lib, caller]).unwrap();

        let helper_ext: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| {
                e.provenance == Provenance::External && e.to.to_scip_string().contains("helper")
            })
            .collect();

        assert!(
            helper_ext.is_empty(),
            "internally-defined `helper` must not produce an External edge; got {:?}",
            helper_ext
                .iter()
                .map(|e| e.to.to_scip_string())
                .collect::<Vec<_>>()
        );
    }

    // ── Test 4: Rust direct-import call ──────────────────────────────────────

    /// A single Rust file with `use serde_json::from_str;` (Import ref with
    /// `from_path = "serde_json"`) and a call to `from_str()` → one External
    /// Call edge ending `serde_json/from_str.`.
    ///
    /// Because the real Rust extractor may or may not emit a Call ref for the
    /// bare name when `use` is at the top level, we inject the import and call
    /// refs explicitly — the same technique used in the symbol-table and
    /// conformance tests.
    #[cfg(feature = "rust")]
    #[test]
    fn rust_use_import_call_emits_external_edge() {
        // Extract a real Rust file for symbols so we have a containing span.
        let mut file = RustExtractor
            .extract("pub fn run() {}", "src/main.rs")
            .unwrap();

        // Inject Import ref: `use serde_json::from_str;`
        file.references.push(Reference {
            name: "from_str".to_owned(),
            occ: Occurrence {
                file: "src/main.rs".to_owned(),
                line: 1,
                col: 0,
                byte: 0,
            },
            role: RefRole::Import,
            source_module: None,
            from_path: Some("serde_json".to_owned()),
            is_reexport: false,
            imported_name: None,
            qualifier: None,
            scope: None,
            type_ref_ctx: None,
            cross_artifact: false,
            self_receiver: false,
        });
        // Inject Call ref: `from_str()` inside `run`'s span.
        let run_span_start = file
            .symbols
            .iter()
            .find(|s| s.name == "run")
            .expect("run symbol")
            .span
            .start;
        file.references.push(Reference {
            name: "from_str".to_owned(),
            occ: Occurrence {
                file: "src/main.rs".to_owned(),
                line: 1,
                col: 10,
                byte: run_span_start,
            },
            role: RefRole::Call,
            source_module: None,
            from_path: None,
            is_reexport: false,
            imported_name: None,
            qualifier: None,
            scope: None,
            type_ref_ctx: None,
            cross_artifact: false,
            self_receiver: false,
        });

        let graph = ExternalResolver.resolve(&[file]).unwrap();

        let ext_edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.provenance == Provenance::External && e.role == RefRole::Call)
            .collect();

        assert_eq!(
            ext_edges.len(),
            1,
            "expected exactly one External Call edge for `from_str`, got {}: {:?}",
            ext_edges.len(),
            ext_edges
                .iter()
                .map(|e| format!("{} → {}", e.from.to_scip_string(), e.to.to_scip_string()))
                .collect::<Vec<_>>()
        );
        assert!(
            ext_edges[0]
                .to
                .to_scip_string()
                .ends_with("serde_json/from_str."),
            "external target must end with `serde_json/from_str.`, got: {}",
            ext_edges[0].to.to_scip_string()
        );
    }

    // ── Test 5: Determinism ───────────────────────────────────────────────────

    /// Resolving the same input twice yields identical edge vectors (same SCIP
    /// strings in the same order).
    #[cfg(feature = "python")]
    #[test]
    fn deterministic_on_repeated_resolution() {
        let file = PythonExtractor
            .extract(
                "from requests import get\n\ndef run():\n    get()\n",
                "src/client.py",
            )
            .unwrap();

        let input = [file];
        let g1 = ExternalResolver.resolve(&input).unwrap();
        let g2 = ExternalResolver.resolve(&input).unwrap();

        let scips1: Vec<_> = g1
            .edges
            .iter()
            .map(|e| {
                format!(
                    "{} → {} ({:?})",
                    e.from.to_scip_string(),
                    e.to.to_scip_string(),
                    e.role
                )
            })
            .collect();
        let scips2: Vec<_> = g2
            .edges
            .iter()
            .map(|e| {
                format!(
                    "{} → {} ({:?})",
                    e.from.to_scip_string(),
                    e.to.to_scip_string(),
                    e.role
                )
            })
            .collect();

        assert_eq!(
            scips1, scips2,
            "repeated resolution must yield identical edges"
        );
    }
}
