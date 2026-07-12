// SPDX-License-Identifier: Apache-2.0

//! Storage-neutral, fallible, bounded graph reads.
//!
//! The contract intentionally returns owned facts: a database adapter can decode
//! one bounded cursor page without materializing a whole graph in memory. Results
//! must use the same structural ordering as [`GraphIndex`].

use std::convert::Infallible;

use code2graph::{Edge, EdgeKey, Symbol, SymbolId};

use crate::{EdgeFilter, GraphIndex};

/// A bounded ordered page with an exclusive cursor for the next page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphPage<T, C> {
    /// Ordered items, never more than the requested page size.
    pub items: Vec<T>,
    /// Exclusive cursor to pass to the next request, if more items remain.
    pub next: Option<C>,
}

/// Storage-neutral ordered graph access.
///
/// Callers must use a nonzero page limit, and implementations treat `after` as
/// exclusive. Database-backed adapters belong at the consumer boundary; this
/// crate remains storage-free.
pub trait GraphRead {
    /// Backend failure type.
    type Error;

    /// Locally defined symbol for one structural identity.
    fn symbol(&self, id: &SymbolId) -> Result<Option<Symbol>, Self::Error>;
    /// Whether a structural identity is known as a definition or edge endpoint.
    fn contains_id(&self, id: &SymbolId) -> Result<bool, Self::Error>;
    /// All definitions, ordered by structural ID.
    fn symbols(
        &self,
        after: Option<&SymbolId>,
        limit: usize,
    ) -> Result<GraphPage<Symbol, SymbolId>, Self::Error>;
    /// Definitions with an exact bare name, ordered by structural ID.
    fn symbols_named(
        &self,
        name: &str,
        after: Option<&SymbolId>,
        limit: usize,
    ) -> Result<GraphPage<Symbol, SymbolId>, Self::Error>;
    /// Definitions with a SCIP display, ordered by structural ID.
    fn symbols_with_scip(
        &self,
        scip: &str,
        after: Option<&SymbolId>,
        limit: usize,
    ) -> Result<GraphPage<Symbol, SymbolId>, Self::Error>;
    /// Known IDs with a SCIP display, ordered structurally.
    fn ids_with_scip(
        &self,
        scip: &str,
        after: Option<&SymbolId>,
        limit: usize,
    ) -> Result<GraphPage<SymbolId, SymbolId>, Self::Error>;
    /// Definitions in one file, ordered by structural ID.
    fn symbols_in_file(
        &self,
        file: &str,
        after: Option<&SymbolId>,
        limit: usize,
    ) -> Result<GraphPage<Symbol, SymbolId>, Self::Error>;
    /// Innermost definition containing a byte position in one file.
    fn symbol_at_byte(&self, file: &str, byte: usize) -> Result<Option<Symbol>, Self::Error>;
    /// All matching edges in stable full-edge order.
    fn edges(
        &self,
        filter: EdgeFilter,
        after: Option<&EdgeKey>,
        limit: usize,
    ) -> Result<GraphPage<Edge, EdgeKey>, Self::Error>;
    /// Matching edges whose occurrence belongs to one file in stable full-edge order.
    fn edges_in_file(
        &self,
        file: &str,
        filter: EdgeFilter,
        after: Option<&EdgeKey>,
        limit: usize,
    ) -> Result<GraphPage<Edge, EdgeKey>, Self::Error>;
    /// Matching incoming edges in stable full-edge order.
    fn incoming(
        &self,
        id: &SymbolId,
        filter: EdgeFilter,
        after: Option<&EdgeKey>,
        limit: usize,
    ) -> Result<GraphPage<Edge, EdgeKey>, Self::Error>;
    /// Matching outgoing edges in stable full-edge order.
    fn outgoing(
        &self,
        id: &SymbolId,
        filter: EdgeFilter,
        after: Option<&EdgeKey>,
        limit: usize,
    ) -> Result<GraphPage<Edge, EdgeKey>, Self::Error>;
}

fn page_by<T: Clone, C: Ord + Clone>(
    values: impl IntoIterator<Item = (C, T)>,
    after: Option<&C>,
    limit: usize,
) -> GraphPage<T, C> {
    assert!(limit > 0, "GraphRead callers must use nonzero page limits");
    let mut values: Vec<_> = values
        .into_iter()
        .filter(|(cursor, _)| after.is_none_or(|after| cursor > after))
        .collect();
    let has_more = values.len() > limit;
    values.truncate(limit);
    let next = has_more.then(|| values.last().expect("non-empty page").0.clone());
    GraphPage {
        items: values.into_iter().map(|(_, value)| value).collect(),
        next,
    }
}

impl GraphRead for GraphIndex {
    type Error = Infallible;

    fn symbol(&self, id: &SymbolId) -> Result<Option<Symbol>, Self::Error> {
        Ok(self.symbol(id).cloned())
    }

    fn contains_id(&self, id: &SymbolId) -> Result<bool, Self::Error> {
        Ok(self.contains_id(id))
    }

    fn symbols(
        &self,
        after: Option<&SymbolId>,
        limit: usize,
    ) -> Result<GraphPage<Symbol, SymbolId>, Self::Error> {
        Ok(page_by(
            self.symbols()
                .map(|symbol| (symbol.id.clone(), symbol.clone())),
            after,
            limit,
        ))
    }

    fn symbols_named(
        &self,
        name: &str,
        after: Option<&SymbolId>,
        limit: usize,
    ) -> Result<GraphPage<Symbol, SymbolId>, Self::Error> {
        Ok(page_by(
            self.symbols_named(name)
                .into_iter()
                .map(|symbol| (symbol.id.clone(), symbol.clone())),
            after,
            limit,
        ))
    }

    fn symbols_with_scip(
        &self,
        scip: &str,
        after: Option<&SymbolId>,
        limit: usize,
    ) -> Result<GraphPage<Symbol, SymbolId>, Self::Error> {
        Ok(page_by(
            self.symbols_with_scip(scip)
                .into_iter()
                .map(|symbol| (symbol.id.clone(), symbol.clone())),
            after,
            limit,
        ))
    }

    fn ids_with_scip(
        &self,
        scip: &str,
        after: Option<&SymbolId>,
        limit: usize,
    ) -> Result<GraphPage<SymbolId, SymbolId>, Self::Error> {
        Ok(page_by(
            self.ids_with_scip(scip)
                .into_iter()
                .map(|id| (id.clone(), id.clone())),
            after,
            limit,
        ))
    }

    fn symbols_in_file(
        &self,
        file: &str,
        after: Option<&SymbolId>,
        limit: usize,
    ) -> Result<GraphPage<Symbol, SymbolId>, Self::Error> {
        Ok(page_by(
            self.symbols_in_file(file)
                .into_iter()
                .map(|symbol| (symbol.id.clone(), symbol.clone())),
            after,
            limit,
        ))
    }

    fn symbol_at_byte(&self, file: &str, byte: usize) -> Result<Option<Symbol>, Self::Error> {
        Ok(self.symbol_at_byte(file, byte).cloned())
    }

    fn edges(
        &self,
        filter: EdgeFilter,
        after: Option<&EdgeKey>,
        limit: usize,
    ) -> Result<GraphPage<Edge, EdgeKey>, Self::Error> {
        Ok(page_by(
            self.edges
                .values()
                .filter(|edge| filter.matches(edge))
                .map(|edge| (edge.key(), edge.clone())),
            after,
            limit,
        ))
    }

    fn edges_in_file(
        &self,
        file: &str,
        filter: EdgeFilter,
        after: Option<&EdgeKey>,
        limit: usize,
    ) -> Result<GraphPage<Edge, EdgeKey>, Self::Error> {
        Ok(page_by(
            self.edges
                .values()
                .filter(|edge| filter.matches(edge) && edge.occ.file == file)
                .map(|edge| (edge.key(), edge.clone())),
            after,
            limit,
        ))
    }

    fn incoming(
        &self,
        id: &SymbolId,
        filter: EdgeFilter,
        after: Option<&EdgeKey>,
        limit: usize,
    ) -> Result<GraphPage<Edge, EdgeKey>, Self::Error> {
        Ok(page_by(
            self.incoming(id, filter)
                .into_iter()
                .map(|edge| (edge.key(), edge.clone())),
            after,
            limit,
        ))
    }

    fn outgoing(
        &self,
        id: &SymbolId,
        filter: EdgeFilter,
        after: Option<&EdgeKey>,
        limit: usize,
    ) -> Result<GraphPage<Edge, EdgeKey>, Self::Error> {
        Ok(page_by(
            self.outgoing(id, filter)
                .into_iter()
                .map(|edge| (edge.key(), edge.clone())),
            after,
            limit,
        ))
    }
}

#[cfg(test)]
mod tests {
    use code2graph::{
        CodeGraph, Confidence, Descriptor, Edge, Occurrence, Provenance, RefRole, SymbolId,
    };

    use crate::{EdgeFilter, GraphIndex, GraphRead};

    fn id(name: &str) -> SymbolId {
        SymbolId::global("rust", vec![Descriptor::Term(name.into())])
    }

    fn edge(from: &SymbolId, to: &SymbolId, byte: usize) -> Edge {
        Edge {
            from: from.clone(),
            to: to.clone(),
            role: RefRole::Call,
            confidence: Confidence::Scoped,
            provenance: Provenance::ScopeGraph,
            occ: Occurrence {
                file: "src/lib.rs".into(),
                line: 1,
                col: 0,
                byte,
            },
        }
    }

    #[test]
    fn in_memory_read_contract_pages_symbols_edges_and_positions() {
        use code2graph::{ByteSpan, Symbol, SymbolKind, Visibility};

        let first = id("first");
        let second = id("second");
        let target = id("target");
        let symbol = |id: SymbolId, name: &str, start, end| Symbol {
            id,
            name: name.into(),
            kind: SymbolKind::Function,
            visibility: Visibility::Public,
            entry_points: vec![],
            file: "src/lib.rs".into(),
            line: 1,
            span: ByteSpan { start, end },
            signature: name.into(),
        };
        let index = GraphIndex::from_graph(CodeGraph {
            symbols: vec![
                symbol(first.clone(), "first", 0, 10),
                symbol(second.clone(), "second", 2, 4),
            ],
            edges: vec![edge(&first, &target, 1), edge(&second, &target, 2)],
        })
        .expect("index");
        let first_page = GraphRead::symbols(&index, None, 1).expect("page");
        assert_eq!(first_page.items.len(), 1);
        assert!(first_page.next.is_some());
        let edge_page = GraphRead::edges_in_file(
            &index,
            "src/lib.rs",
            EdgeFilter::new(Confidence::Scoped),
            None,
            1,
        )
        .expect("edges");
        assert_eq!(edge_page.items.len(), 1);
        assert!(edge_page.next.is_some());
        assert_eq!(
            GraphRead::symbol_at_byte(&index, "src/lib.rs", 3)
                .expect("position")
                .expect("symbol")
                .id,
            second
        );
    }

    #[test]
    fn in_memory_read_contract_pages_adjacency_in_index_order() {
        let target = id("target");
        let graph = GraphIndex::from_graph(CodeGraph {
            symbols: vec![],
            edges: vec![
                edge(&id("second"), &target, 2),
                edge(&id("first"), &target, 1),
            ],
        })
        .expect("index");
        let first = GraphRead::incoming(
            &graph,
            &target,
            EdgeFilter::new(Confidence::Scoped),
            None,
            1,
        )
        .expect("infallible");
        let second = GraphRead::incoming(
            &graph,
            &target,
            EdgeFilter::new(Confidence::Scoped),
            first.next.as_ref(),
            1,
        )
        .expect("infallible");
        let expected: Vec<_> = graph
            .incoming(&target, EdgeFilter::new(Confidence::Scoped))
            .into_iter()
            .map(Edge::key)
            .collect();
        assert_eq!(
            [first.items[0].key(), second.items[0].key()],
            [expected[0].clone(), expected[1].clone()]
        );
        assert!(second.next.is_none());
    }
}
