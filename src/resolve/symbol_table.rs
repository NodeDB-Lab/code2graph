// SPDX-License-Identifier: Apache-2.0

//! Tier A resolver: fast, broad, name/scope based.
//!
//! Builds a `leaf-name → definitions` table across all files, attributes each
//! reference to the symbol whose span encloses it (the caller), and links it to
//! every definition sharing the callee's name. Matches are tagged
//! [`Confidence::NameOnly`] — this is the recall-first baseline that works for
//! every language without per-language binding rules. A precise resolver tags
//! its edges [`Confidence::Scoped`]/[`Confidence::Exact`] instead.
//!
//! It returns neutral [`Edge`]s and never writes to storage.

use std::collections::HashMap;

use crate::graph::types::{CodeGraph, Confidence, Edge, EdgeKind, FileFacts, Symbol};

use super::Resolver;

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
                let Some(from_idx) = file_syms.and_then(|idxs| {
                    idxs.iter()
                        .copied()
                        .filter(|&i| symbols[i].span.contains(r.occ.byte))
                        .min_by_key(|&i| symbols[i].span.len())
                }) else {
                    continue; // reference not inside any extracted symbol — unattributable
                };

                let Some(targets) = by_name.get(r.name.as_str()) else {
                    continue; // unresolved: no definition with this name
                };

                for &to_idx in targets {
                    if to_idx == from_idx {
                        continue; // skip self-reference
                    }
                    edges.push(Edge {
                        from: symbols[from_idx].id.clone(),
                        to: symbols[to_idx].id.clone(),
                        kind: EdgeKind::Calls,
                        confidence: Confidence::NameOnly,
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
    use crate::extract::RustExtractor;
    use crate::extract::Extractor;

    #[test]
    fn resolves_cross_file_call() {
        let lib = RustExtractor
            .extract("pub fn helper() -> u32 { 1 }", "src/util.rs")
            .unwrap();
        let main = RustExtractor
            .extract("pub fn run() -> u32 { helper() }", "src/main.rs")
            .unwrap();

        let graph = SymbolTableResolver.resolve(&[lib, main]);

        // one Calls edge: run → helper
        let calls: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.kind == EdgeKind::Calls)
            .collect();
        assert_eq!(calls.len(), 1);
        let e = calls[0];
        assert!(e.from.to_scip_string().ends_with("run()."));
        assert!(e.to.to_scip_string().ends_with("util/helper()."));
        assert_eq!(e.confidence, Confidence::NameOnly);
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
}
