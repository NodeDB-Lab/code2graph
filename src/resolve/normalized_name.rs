// SPDX-License-Identifier: Apache-2.0

//! Lowest-tier recall resolver: case-folded name matching.
//!
//! [`NormalizedNameResolver`] adds a [`Confidence::Heuristic`] edge for every
//! reference whose ASCII-lowercased name matches at least one definition's
//! ASCII-lowercased leaf name, **but only when the written name and the
//! definition's leaf name differ in case**. Exact-case matches are already
//! covered by [`SymbolTableResolver`] at higher confidence; this resolver
//! exists solely to extend recall across case boundaries.
//!
//! Boundary: case folding only — no edit-distance, no phonetic or LSH matching.
//!
//! [`SymbolTableResolver`]: super::SymbolTableResolver

use std::collections::HashMap;

use crate::graph::types::{CodeGraph, Confidence, Edge, FileFacts, Provenance, Symbol};

use super::{Resolver, dedup_files_last_wins, enclosing_symbol_index};

/// Case-fold resolver. See module docs.
#[derive(Debug, Default, Clone, Copy)]
pub struct NormalizedNameResolver;

impl Resolver for NormalizedNameResolver {
    fn resolve(&self, files: &[FileFacts]) -> crate::Result<CodeGraph> {
        crate::validate_file_facts(files)?;
        let files = dedup_files_last_wins(files);
        // Flatten all symbols across files, mirroring SymbolTableResolver's layout.
        let symbols: Vec<Symbol> = files
            .iter()
            .flat_map(|f| f.symbols.iter().cloned())
            .collect();

        // Per-file symbol indices for enclosing-symbol attribution.
        let mut by_file: HashMap<&str, Vec<usize>> = HashMap::new();
        for (i, s) in symbols.iter().enumerate() {
            by_file.entry(s.file.as_str()).or_default().push(i);
        }

        // Map ASCII-lowercased leaf name → list of symbol indices.
        let mut by_lower_name: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, s) in symbols.iter().enumerate() {
            if let Some(name) = s.id.leaf_name() {
                by_lower_name
                    .entry(name.to_ascii_lowercase())
                    .or_default()
                    .push(i);
            }
        }

        let mut edges: Vec<Edge> = Vec::new();
        for f in files.iter().copied() {
            let file_syms = by_file.get(f.file.as_str());
            for r in &f.references {
                // Attribute the reference to its enclosing symbol (the caller).
                let Some(from_idx) =
                    file_syms.and_then(|idxs| enclosing_symbol_index(&symbols, idxs, r.occ.byte))
                else {
                    continue; // reference not enclosed by any extracted symbol
                };

                let ref_lower = r.name.to_ascii_lowercase();
                let Some(candidates) = by_lower_name.get(&ref_lower) else {
                    continue; // no definition whose lowercase leaf name matches
                };

                for &to_idx in candidates {
                    // Never emit a self-edge.
                    if to_idx == from_idx {
                        continue;
                    }
                    // Skip if the definition's leaf name is an exact-case match:
                    // that edge is SymbolTableResolver's responsibility, not ours.
                    let def_leaf = match symbols[to_idx].id.leaf_name() {
                        Some(n) => n,
                        None => continue,
                    };
                    if def_leaf == r.name.as_str() {
                        continue;
                    }
                    edges.push(Edge {
                        from: symbols[from_idx].id.clone(),
                        to: symbols[to_idx].id.clone(),
                        role: r.role,
                        confidence: Confidence::Heuristic,
                        provenance: Provenance::NormalizedName,
                        occ: r.occ.clone(),
                    });
                }
            }
        }

        Ok(CodeGraph { symbols, edges })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "rust")]
    use crate::extract::{Extractor, RustExtractor};
    #[cfg(feature = "rust")]
    use crate::graph::types::{Occurrence, RefRole, Reference};

    /// A case-differing reference resolves to a `Heuristic`/`NormalizedName` edge.
    ///
    /// `fn process()` is defined in one file; a reference written `Process` (upper
    /// P) appears in another. The resolver must produce exactly one edge pointing
    /// at `process`, tagged `Confidence::Heuristic` + `Provenance::NormalizedName`.
    #[cfg(feature = "rust")]
    #[test]
    fn case_differing_reference_resolves_at_heuristic() {
        // File A: defines `process`.
        let lib = RustExtractor
            .extract("pub fn process() -> u32 { 1 }", "src/util.rs")
            .unwrap();
        // We need at least one symbol in the caller file so `enclosing_symbol_index`
        // can attribute the reference. Use a module-level wrapper.
        let mut caller = RustExtractor
            .extract("pub fn run() -> u32 { 0 }", "src/main.rs")
            .unwrap();

        // Inject a Call reference with name "Process" (case-differing from "process").
        caller.references.push(Reference {
            name: "Process".to_owned(),
            occ: Occurrence {
                file: "src/main.rs".to_owned(),
                line: 1,
                col: 22,
                byte: 22, // inside "pub fn run() -> u32 { … }" span
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

        let graph = NormalizedNameResolver.resolve(&[lib, caller]).unwrap();

        let call_edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.role == RefRole::Call)
            .collect();

        assert_eq!(
            call_edges.len(),
            1,
            "expected exactly one Call edge from case-differing reference, got {}: {:?}",
            call_edges.len(),
            call_edges
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

        let e = call_edges[0];
        assert!(
            e.to.to_scip_string().ends_with("util/process()."),
            "edge `to` must point at `process` in util, got: {}",
            e.to.to_scip_string()
        );
        assert_eq!(
            e.confidence,
            Confidence::Heuristic,
            "case-fold edge must be Heuristic, got {:?}",
            e.confidence
        );
        assert_eq!(
            e.provenance,
            Provenance::NormalizedName,
            "provenance must be NormalizedName, got {:?}",
            e.provenance
        );
    }

    /// An exact-case match must NOT be emitted by this resolver.
    ///
    /// `NormalizedNameResolver` only adds recall that `SymbolTableResolver` does
    /// not cover. When the reference name and the definition leaf name are
    /// identical in case, the resolver must produce no edge.
    #[cfg(feature = "rust")]
    #[test]
    fn exact_case_match_not_emitted() {
        let lib = RustExtractor
            .extract("pub fn process() -> u32 { 1 }", "src/util.rs")
            .unwrap();
        let mut caller = RustExtractor
            .extract("pub fn run() -> u32 { 0 }", "src/main.rs")
            .unwrap();

        // Reference with exact-case name "process" — identical to the definition leaf.
        caller.references.push(Reference {
            name: "process".to_owned(),
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

        let graph = NormalizedNameResolver.resolve(&[lib, caller]).unwrap();

        assert!(
            graph.edges.is_empty(),
            "exact-case match must not produce a NormalizedName edge; got {:?}",
            graph
                .edges
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

    /// A reference with no case-folded match produces no edge at all.
    #[cfg(feature = "rust")]
    #[test]
    fn no_match_emits_nothing() {
        let lib = RustExtractor
            .extract("pub fn process() -> u32 { 1 }", "src/util.rs")
            .unwrap();
        let mut caller = RustExtractor
            .extract("pub fn run() -> u32 { 0 }", "src/main.rs")
            .unwrap();

        // "totally_unknown" has no case-folded match anywhere.
        caller.references.push(Reference {
            name: "totally_unknown".to_owned(),
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

        let graph = NormalizedNameResolver.resolve(&[lib, caller]).unwrap();

        assert!(
            graph.edges.is_empty(),
            "reference with no case-folded match must produce no edge"
        );
    }

    /// `Confidence::Heuristic` is strictly less than `Confidence::NameOnly`,
    /// locking the new ordering so the C1 confidence tests still hold.
    #[test]
    fn heuristic_is_lowest_confidence() {
        assert!(
            Confidence::Heuristic < Confidence::NameOnly,
            "Heuristic must be the lowest Confidence tier"
        );
        assert!(
            Confidence::Heuristic < Confidence::Scoped,
            "Heuristic < Scoped"
        );
        assert!(
            Confidence::Heuristic < Confidence::Exact,
            "Heuristic < Exact"
        );
    }
}
