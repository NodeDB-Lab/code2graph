// SPDX-License-Identifier: Apache-2.0

//! Read-only lookup operations over [`super::GraphIndex`].

use code2graph::{Symbol, SymbolId};

use super::GraphIndex;

impl GraphIndex {
    /// Return every locally-defined symbol in structural-ID order.
    ///
    /// Consumers that enumerate definitions must use this validated index rather
    /// than the original graph vector, which may have been decoded from cache.
    pub fn symbols(&self) -> impl Iterator<Item = &Symbol> {
        self.definitions.values()
    }

    /// Whether this graph knows a structural ID, including endpoint-only IDs.
    pub fn contains_id(&self, id: &SymbolId) -> bool {
        self.known_ids.contains(id)
    }

    /// Look up one locally-defined symbol by its structural identity.
    pub fn symbol(&self, id: &SymbolId) -> Option<&Symbol> {
        self.definitions.get(id)
    }

    /// Look up all definitions with an exact bare name in structural-ID order.
    pub fn symbols_named(&self, name: &str) -> Vec<&Symbol> {
        self.definitions_by_name
            .get(name)
            .map_or_else(Vec::new, |ids| {
                ids.iter()
                    .filter_map(|id| self.definitions.get(id))
                    .collect()
            })
    }

    /// Look up all definitions with a SCIP display string in structural-ID order.
    ///
    /// The display string is not used as identity: it can map to multiple global
    /// languages or local files.
    pub fn symbols_with_scip(&self, scip: &str) -> Vec<&Symbol> {
        self.definitions_by_scip
            .get(scip)
            .map_or_else(Vec::new, |ids| {
                ids.iter()
                    .filter_map(|id| self.definitions.get(id))
                    .collect()
            })
    }

    /// Return every structural ID with a SCIP display string, including endpoints
    /// that have no locally-defined symbol.
    pub fn ids_with_scip(&self, scip: &str) -> Vec<&SymbolId> {
        self.ids_by_scip
            .get(scip)
            .map_or_else(Vec::new, |ids| ids.iter().collect())
    }

    /// Look up all definitions in a file in structural-ID order.
    pub fn symbols_in_file(&self, file: &str) -> Vec<&Symbol> {
        self.definitions_by_file
            .get(file)
            .map_or_else(Vec::new, |ids| {
                ids.iter()
                    .filter_map(|id| self.definitions.get(id))
                    .collect()
            })
    }

    /// Find the innermost non-empty definition span containing `byte` in `file`.
    ///
    /// Spans are half-open. Equal spans resolve by structural identity after the
    /// specified start/end tie-breaks, making results insertion-order independent.
    pub fn symbol_at_byte(&self, file: &str, byte: usize) -> Option<&Symbol> {
        self.definitions_by_file
            .get(file)
            .into_iter()
            .flatten()
            .filter_map(|id| self.definitions.get(id))
            .filter(|symbol| !symbol.span.is_empty() && symbol.span.contains(byte))
            .min_by(|left, right| {
                left.span
                    .len()
                    .cmp(&right.span.len())
                    .then_with(|| right.span.start.cmp(&left.span.start))
                    .then_with(|| left.span.end.cmp(&right.span.end))
                    .then_with(|| left.id.cmp(&right.id))
            })
    }
}

#[cfg(test)]
mod tests {
    use code2graph::{
        ByteSpan, CodeGraph, Confidence, Descriptor, Edge, Occurrence, Provenance, RefRole, Symbol,
        SymbolId, SymbolKind, Visibility,
    };

    use crate::{GraphIndex, QueryError};

    fn global(language: &str, name: &str) -> SymbolId {
        SymbolId::global(
            language,
            vec![
                Descriptor::Namespace("pkg".into()),
                Descriptor::Term(name.into()),
            ],
        )
    }

    fn symbol(id: SymbolId, name: &str, file: &str, start: usize, end: usize) -> Symbol {
        Symbol {
            id,
            name: name.into(),
            kind: SymbolKind::Function,
            visibility: Visibility::Public,
            entry_points: Vec::new(),
            file: file.into(),
            line: 1,
            span: ByteSpan { start, end },
            signature: format!("fn {name}()"),
        }
    }

    fn edge(from: SymbolId, to: SymbolId, byte: usize) -> Edge {
        Edge {
            from,
            to,
            role: RefRole::Call,
            confidence: Confidence::Exact,
            provenance: Provenance::ScopeGraph,
            occ: Occurrence {
                file: "src/caller.rs".into(),
                line: 1,
                col: 0,
                byte,
            },
        }
    }

    #[test]
    fn indexes_display_collisions_and_endpoint_only_ids_structurally() {
        let rust = global("rust", "shared");
        let python = global("python", "shared");
        let external_a = SymbolId::local("vendor/a.rs", "remote");
        let external_b = SymbolId::local("vendor/b.rs", "remote");
        let display = rust.to_scip_string();
        let external_display = external_a.to_scip_string();
        assert_eq!(external_display, external_b.to_scip_string());
        let index = GraphIndex::from_graph(CodeGraph {
            symbols: vec![
                symbol(rust.clone(), "shared", "src/rust.rs", 0, 10),
                symbol(python.clone(), "shared", "src/python.py", 0, 10),
            ],
            edges: vec![
                edge(rust.clone(), external_a.clone(), 4),
                edge(python.clone(), external_b.clone(), 8),
            ],
        })
        .expect("valid graph");

        assert_eq!(index.symbols().count(), 2);
        assert_eq!(index.symbols_with_scip(&display).len(), 2);
        assert_eq!(index.ids_with_scip(&display), vec![&python, &rust]);
        assert!(index.contains_id(&external_a));
        assert!(index.contains_id(&external_b));
        assert!(index.symbol(&external_a).is_none());
        assert!(index.symbol(&external_b).is_none());
        assert_eq!(
            index.ids_with_scip(&external_display),
            vec![&external_a, &external_b]
        );
        assert!(index.symbols_named("remote").is_empty());
        assert!(index.symbols_in_file("vendor/a.rs").is_empty());
    }

    #[test]
    fn rejects_duplicate_structural_symbol_and_edge_keys() {
        let id = global("rust", "one");
        let duplicate_symbols = CodeGraph {
            symbols: vec![
                symbol(id.clone(), "one", "src/a.rs", 0, 1),
                symbol(id.clone(), "one", "src/a.rs", 0, 1),
            ],
            edges: vec![],
        };
        assert!(
            matches!(GraphIndex::from_graph(duplicate_symbols), Err(QueryError::DuplicateSymbolId(found)) if found == id)
        );

        let target = global("rust", "two");
        let repeated = edge(id.clone(), target, 3);
        let duplicate_edges = CodeGraph {
            symbols: vec![],
            edges: vec![
                repeated.clone(),
                Edge {
                    confidence: Confidence::NameOnly,
                    ..repeated
                },
            ],
        };
        assert!(matches!(
            GraphIndex::from_graph(duplicate_edges),
            Err(QueryError::DuplicateEdgeKey(_))
        ));
    }

    #[test]
    fn name_file_and_plural_display_lookups_are_ordered() {
        let a = global("rust", "same");
        let b = global("python", "same");
        let c = global("go", "other");
        let index = GraphIndex::from_graph(CodeGraph {
            symbols: vec![
                symbol(a.clone(), "same", "src/shared", 0, 3),
                symbol(b.clone(), "same", "src/shared", 4, 8),
                symbol(c.clone(), "other", "src/other", 0, 1),
            ],
            edges: vec![],
        })
        .expect("valid graph");

        assert_eq!(
            index
                .symbols_named("same")
                .iter()
                .map(|s| &s.id)
                .collect::<Vec<_>>(),
            vec![&b, &a]
        );
        assert_eq!(
            index
                .symbols_in_file("src/shared")
                .iter()
                .map(|s| &s.id)
                .collect::<Vec<_>>(),
            vec![&b, &a]
        );
        assert_eq!(
            index
                .symbols_with_scip(&a.to_scip_string())
                .iter()
                .map(|s| &s.id)
                .collect::<Vec<_>>(),
            vec![&b, &a]
        );
        assert!(index.symbols_named("missing").is_empty());
    }

    #[test]
    fn shuffled_input_has_identical_lookup_and_adjacency_order() {
        let a = global("rust", "same");
        let b = global("python", "same");
        let external = SymbolId::local("vendor/api.rs", "remote");
        let a_edge = edge(a.clone(), external.clone(), 4);
        let b_edge = edge(b.clone(), external.clone(), 2);
        let first = CodeGraph {
            symbols: vec![
                symbol(a.clone(), "same", "src/a", 0, 1),
                symbol(b.clone(), "same", "src/b", 0, 1),
            ],
            edges: vec![a_edge.clone(), b_edge.clone()],
        };
        let second = CodeGraph {
            symbols: first.symbols.iter().cloned().rev().collect(),
            edges: first.edges.iter().cloned().rev().collect(),
        };
        let left = GraphIndex::from_graph(first).expect("valid graph");
        let right = GraphIndex::from_graph(second).expect("valid graph");

        assert_eq!(
            left.ids_with_scip(&a.to_scip_string()),
            right.ids_with_scip(&a.to_scip_string())
        );
        assert_eq!(
            left.symbols_named("same")
                .iter()
                .map(|s| &s.id)
                .collect::<Vec<_>>(),
            right
                .symbols_named("same")
                .iter()
                .map(|s| &s.id)
                .collect::<Vec<_>>()
        );
        let expected_outgoing = vec![a_edge.key()];
        let mut expected_incoming = vec![a_edge.key(), b_edge.key()];
        expected_incoming.sort();
        assert_eq!(left.outgoing.get(&a), Some(&expected_outgoing));
        assert_eq!(left.incoming.get(&external), Some(&expected_incoming));
        assert_eq!(left.outgoing.get(&a), right.outgoing.get(&a));
        assert_eq!(left.incoming.get(&external), right.incoming.get(&external));
    }

    #[test]
    fn symbol_at_byte_uses_half_open_innermost_and_stable_ties() {
        let outer = symbol(global("rust", "outer"), "outer", "src/a", 0, 20);
        let inner = symbol(global("rust", "inner"), "inner", "src/a", 5, 10);
        let overlap = symbol(global("rust", "overlap"), "overlap", "src/a", 1, 11);
        let equal_a = symbol(global("rust", "equal_a"), "equal_a", "src/a", 12, 16);
        let equal_b = symbol(global("python", "equal_b"), "equal_b", "src/a", 12, 16);
        let empty = symbol(global("rust", "empty"), "empty", "src/a", 8, 8);
        let equal_expected = if equal_a.id < equal_b.id {
            equal_a.id.clone()
        } else {
            equal_b.id.clone()
        };
        let index = GraphIndex::from_graph(CodeGraph {
            symbols: vec![
                outer.clone(),
                inner.clone(),
                overlap.clone(),
                equal_b,
                empty,
                equal_a,
            ],
            edges: vec![],
        })
        .expect("valid graph");

        assert_eq!(
            index.symbol_at_byte("src/a", 2).map(|s| &s.id),
            Some(&overlap.id)
        );
        assert_eq!(
            index.symbol_at_byte("src/a", 5).map(|s| &s.id),
            Some(&inner.id)
        );
        assert_eq!(
            index.symbol_at_byte("src/a", 11).map(|s| &s.id),
            Some(&outer.id)
        );
        assert!(index.symbol_at_byte("src/a", 20).is_none());
        assert_eq!(
            index.symbol_at_byte("src/a", 8).map(|s| &s.id),
            Some(&inner.id)
        );
        assert_eq!(
            index.symbol_at_byte("src/a", 13).map(|s| &s.id),
            Some(&equal_expected)
        );
    }
}
