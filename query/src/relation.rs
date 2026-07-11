// SPDX-License-Identifier: Apache-2.0

//! Relationship filtering and adjacency traversal over [`GraphIndex`].

use code2graph::{Confidence, Edge, Provenance, RefRole, SymbolId};

use crate::GraphIndex;

/// Conjunctive constraints for an adjacency traversal.
///
/// A filter always declares its minimum confidence explicitly; it has no
/// default because choosing a resolution threshold is consumer policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdgeFilter {
    /// Require this relationship role when present.
    pub role: Option<RefRole>,
    /// Keep edges at or above this resolution-confidence threshold.
    pub min_confidence: Confidence,
    /// Require this resolver provenance when present.
    pub provenance: Option<Provenance>,
}

impl EdgeFilter {
    /// Create a filter with an explicit minimum confidence threshold.
    pub const fn new(min_confidence: Confidence) -> Self {
        Self {
            role: None,
            min_confidence,
            provenance: None,
        }
    }

    /// Require one reference role in addition to the other constraints.
    pub const fn with_role(mut self, role: RefRole) -> Self {
        self.role = Some(role);
        self
    }

    /// Require one resolver provenance in addition to the other constraints.
    pub const fn with_provenance(mut self, provenance: Provenance) -> Self {
        self.provenance = Some(provenance);
        self
    }

    fn matches(&self, edge: &Edge) -> bool {
        edge.confidence >= self.min_confidence
            && self.role.is_none_or(|role| edge.role == role)
            && self
                .provenance
                .is_none_or(|provenance| edge.provenance == provenance)
    }
}

impl GraphIndex {
    /// Return edges entering `id` that satisfy every `filter` constraint.
    ///
    /// Both definitions and endpoint-only identities are traversable. Unknown
    /// identities return an empty result. Results are in stable full-edge order,
    /// beginning with [`code2graph::EdgeKey`].
    pub fn incoming(&self, id: &SymbolId, filter: EdgeFilter) -> Vec<&Edge> {
        self.adjacent(&self.incoming, id, filter)
    }

    /// Return edges leaving `id` that satisfy every `filter` constraint.
    ///
    /// Both definitions and endpoint-only identities are traversable. Unknown
    /// identities return an empty result. Results are in stable full-edge order,
    /// beginning with [`code2graph::EdgeKey`].
    pub fn outgoing(&self, id: &SymbolId, filter: EdgeFilter) -> Vec<&Edge> {
        self.adjacent(&self.outgoing, id, filter)
    }

    fn adjacent(
        &self,
        adjacency: &std::collections::BTreeMap<SymbolId, Vec<code2graph::EdgeKey>>,
        id: &SymbolId,
        filter: EdgeFilter,
    ) -> Vec<&Edge> {
        adjacency.get(id).map_or_else(Vec::new, |keys| {
            // `from_graph` sorts every adjacency list by lossless `EdgeKey`.
            // Filtering retains that complete, insertion-independent order.
            keys.iter()
                .filter_map(|key| self.edges.get(key))
                .filter(|edge| filter.matches(edge))
                .collect()
        })
    }
}

#[cfg(test)]
mod tests {
    use code2graph::{
        ByteSpan, CodeGraph, Confidence, Descriptor, Edge, Occurrence, Provenance, RefRole, Symbol,
        SymbolId, SymbolKind, Visibility,
    };

    use crate::{EdgeFilter, GraphIndex};

    fn id(name: &str) -> SymbolId {
        SymbolId::global(
            "rust",
            vec![
                Descriptor::Namespace("pkg".into()),
                Descriptor::Term(name.into()),
            ],
        )
    }

    fn edge(
        from: SymbolId,
        to: SymbolId,
        role: RefRole,
        confidence: Confidence,
        provenance: Provenance,
        byte: usize,
    ) -> Edge {
        Edge {
            from,
            to,
            role,
            confidence,
            provenance,
            occ: Occurrence {
                file: "src/caller.rs".into(),
                line: 1,
                col: byte as u32,
                byte,
            },
        }
    }

    fn definition(id: SymbolId) -> Symbol {
        Symbol {
            id,
            name: "defined".into(),
            kind: SymbolKind::Function,
            visibility: Visibility::Public,
            entry_points: Vec::new(),
            file: "src/defined.rs".into(),
            line: 1,
            span: ByteSpan { start: 0, end: 1 },
            signature: "fn defined()".into(),
        }
    }

    #[test]
    fn filters_conjoin_role_confidence_and_provenance() {
        let source = id("source");
        let target = id("target");
        let call_exact = edge(
            source.clone(),
            target.clone(),
            RefRole::Call,
            Confidence::Exact,
            Provenance::ScopeGraph,
            1,
        );
        let call_name_only = edge(
            source.clone(),
            target.clone(),
            RefRole::Call,
            Confidence::NameOnly,
            Provenance::SymbolTable,
            2,
        );
        let import_exact = edge(
            source.clone(),
            target.clone(),
            RefRole::Import,
            Confidence::Exact,
            Provenance::ScopeGraph,
            3,
        );
        let index = GraphIndex::from_graph(CodeGraph {
            symbols: vec![],
            edges: vec![
                call_name_only.clone(),
                import_exact.clone(),
                call_exact.clone(),
            ],
        })
        .expect("valid graph");

        assert_eq!(
            index
                .outgoing(&source, EdgeFilter::new(Confidence::Exact))
                .iter()
                .map(|edge| edge.key())
                .collect::<Vec<_>>(),
            vec![call_exact.key(), import_exact.key()]
        );
        assert_eq!(
            index
                .outgoing(
                    &source,
                    EdgeFilter::new(Confidence::Heuristic).with_role(RefRole::Call)
                )
                .iter()
                .map(|edge| edge.key())
                .collect::<Vec<_>>(),
            vec![call_exact.key(), call_name_only.key()]
        );
        assert_eq!(
            index
                .outgoing(
                    &source,
                    EdgeFilter::new(Confidence::Heuristic).with_provenance(Provenance::ScopeGraph)
                )
                .iter()
                .map(|edge| edge.key())
                .collect::<Vec<_>>(),
            vec![call_exact.key(), import_exact.key()]
        );
        assert_eq!(
            index
                .outgoing(
                    &source,
                    EdgeFilter::new(Confidence::Exact)
                        .with_role(RefRole::Call)
                        .with_provenance(Provenance::ScopeGraph)
                )
                .iter()
                .map(|edge| edge.key())
                .collect::<Vec<_>>(),
            vec![call_exact.key()]
        );
    }

    #[test]
    fn inverse_endpoint_only_and_absent_traversals_are_correct() {
        let source = id("source");
        let endpoint_only = SymbolId::local("vendor/api.rs", "remote");
        let relation = edge(
            source.clone(),
            endpoint_only.clone(),
            RefRole::Call,
            Confidence::Scoped,
            Provenance::ScopeGraph,
            4,
        );
        let index = GraphIndex::from_graph(CodeGraph {
            symbols: vec![],
            edges: vec![relation.clone()],
        })
        .expect("valid graph");
        let filter = EdgeFilter::new(Confidence::Scoped);

        assert_eq!(
            index
                .outgoing(&source, filter)
                .iter()
                .map(|edge| edge.key())
                .collect::<Vec<_>>(),
            vec![relation.key()]
        );
        assert_eq!(
            index
                .incoming(&endpoint_only, filter)
                .iter()
                .map(|edge| edge.key())
                .collect::<Vec<_>>(),
            vec![relation.key()]
        );
        assert!(index.outgoing(&id("missing"), filter).is_empty());
        assert!(index.incoming(&id("missing"), filter).is_empty());
    }

    #[test]
    fn traverses_both_directions_for_definitions_and_endpoint_only_ids() {
        let defined = id("defined");
        let endpoint_only = SymbolId::local("vendor/api.rs", "remote");
        let to_endpoint = edge(
            defined.clone(),
            endpoint_only.clone(),
            RefRole::Call,
            Confidence::Exact,
            Provenance::ScopeGraph,
            1,
        );
        let from_endpoint = edge(
            endpoint_only.clone(),
            defined.clone(),
            RefRole::Call,
            Confidence::Exact,
            Provenance::ScopeGraph,
            2,
        );
        let index = GraphIndex::from_graph(CodeGraph {
            symbols: vec![definition(defined.clone())],
            edges: vec![to_endpoint.clone(), from_endpoint.clone()],
        })
        .expect("valid graph");
        let filter = EdgeFilter::new(Confidence::Exact);

        for (id, outgoing, incoming) in [
            (&defined, to_endpoint.key(), from_endpoint.key()),
            (&endpoint_only, from_endpoint.key(), to_endpoint.key()),
        ] {
            assert_eq!(
                index
                    .outgoing(id, filter)
                    .iter()
                    .map(|edge| edge.key())
                    .collect::<Vec<_>>(),
                vec![outgoing]
            );
            assert_eq!(
                index
                    .incoming(id, filter)
                    .iter()
                    .map(|edge| edge.key())
                    .collect::<Vec<_>>(),
                vec![incoming]
            );
        }
    }

    #[test]
    fn preserves_parallel_evidence_and_is_deterministic_after_shuffling() {
        let source = id("source");
        let target = id("target");
        let occurrence_a = edge(
            source.clone(),
            target.clone(),
            RefRole::Call,
            Confidence::Scoped,
            Provenance::ScopeGraph,
            8,
        );
        let occurrence_b = edge(
            source.clone(),
            target.clone(),
            RefRole::Call,
            Confidence::Scoped,
            Provenance::ScopeGraph,
            2,
        );
        let provenance_b = edge(
            source.clone(),
            target.clone(),
            RefRole::Call,
            Confidence::NameOnly,
            Provenance::SymbolTable,
            2,
        );
        let first = CodeGraph {
            symbols: vec![],
            edges: vec![
                occurrence_a.clone(),
                occurrence_b.clone(),
                provenance_b.clone(),
            ],
        };
        let second = CodeGraph {
            symbols: vec![],
            edges: first.edges.iter().cloned().rev().collect(),
        };
        let left = GraphIndex::from_graph(first).expect("valid graph");
        let right = GraphIndex::from_graph(second).expect("valid graph");
        let filter = EdgeFilter::new(Confidence::Heuristic);
        let left_keys: Vec<_> = left
            .outgoing(&source, filter)
            .iter()
            .map(|edge| edge.key())
            .collect();
        let right_keys: Vec<_> = right
            .outgoing(&source, filter)
            .iter()
            .map(|edge| edge.key())
            .collect();

        assert_eq!(left_keys, right_keys);
        assert_eq!(
            left_keys,
            vec![provenance_b.key(), occurrence_b.key(), occurrence_a.key()],
            "full EdgeKey order is stable"
        );
        assert_eq!(left_keys.len(), 3, "all parallel evidence is retained");
        assert_eq!(
            left.incoming(&target, filter)
                .iter()
                .map(|edge| edge.key())
                .collect::<Vec<_>>(),
            left_keys,
            "every outgoing edge is the corresponding target's incoming edge"
        );
        assert_eq!(
            right
                .incoming(&target, filter)
                .iter()
                .map(|edge| edge.key())
                .collect::<Vec<_>>(),
            left_keys,
            "incoming order is also insertion-independent"
        );
    }
}
