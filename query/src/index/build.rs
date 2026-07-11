// SPDX-License-Identifier: Apache-2.0

//! Construction of the immutable structural graph index.

use std::collections::{BTreeMap, BTreeSet};

use code2graph::{CodeGraph, Edge, EdgeKey, Symbol, SymbolId};

use crate::{QueryError, Result, order};

/// An immutable, storage-free index over one resolved graph.
///
/// All primary keys are structural identities. SCIP strings are secondary display
/// keys only, because one display can correspond to multiple structural IDs.
#[derive(Debug, Clone, Default)]
pub struct GraphIndex {
    pub(crate) definitions: BTreeMap<SymbolId, Symbol>,
    pub(crate) edges: BTreeMap<EdgeKey, Edge>,
    pub(crate) known_ids: BTreeSet<SymbolId>,
    pub(crate) definitions_by_name: BTreeMap<String, Vec<SymbolId>>,
    pub(crate) ids_by_scip: BTreeMap<String, Vec<SymbolId>>,
    pub(crate) definitions_by_scip: BTreeMap<String, Vec<SymbolId>>,
    pub(crate) definitions_by_file: BTreeMap<String, Vec<SymbolId>>,
    pub(crate) outgoing: BTreeMap<SymbolId, Vec<EdgeKey>>,
    pub(crate) incoming: BTreeMap<SymbolId, Vec<EdgeKey>>,
}

impl GraphIndex {
    /// Build an index, rejecting duplicate definition and edge structural keys.
    ///
    /// Edge endpoints need not have a local definition. They remain known IDs and
    /// are included in the SCIP-display index for consumers that represent
    /// external or otherwise absent symbols.
    pub fn from_graph(graph: CodeGraph) -> Result<Self> {
        let mut index = Self::default();
        for symbol in graph.symbols {
            let id = symbol.id.clone();
            if index.definitions.contains_key(&id) {
                return Err(QueryError::DuplicateSymbolId(id));
            }

            let scip = id.to_scip_string();
            index.known_ids.insert(id.clone());
            index
                .definitions_by_name
                .entry(symbol.name.clone())
                .or_default()
                .push(id.clone());
            index
                .definitions_by_scip
                .entry(scip.clone())
                .or_default()
                .push(id.clone());
            index
                .definitions_by_file
                .entry(symbol.file.clone())
                .or_default()
                .push(id.clone());
            index.ids_by_scip.entry(scip).or_default().push(id.clone());
            index.definitions.insert(id, symbol);
        }

        for edge in graph.edges {
            let key = edge.key();
            if index.edges.contains_key(&key) {
                return Err(QueryError::DuplicateEdgeKey(key));
            }

            for id in [&edge.from, &edge.to] {
                if index.known_ids.insert(id.clone()) {
                    index
                        .ids_by_scip
                        .entry(id.to_scip_string())
                        .or_default()
                        .push(id.clone());
                }
            }
            index
                .outgoing
                .entry(edge.from.clone())
                .or_default()
                .push(key.clone());
            index
                .incoming
                .entry(edge.to.clone())
                .or_default()
                .push(key.clone());
            index.edges.insert(key, edge);
        }

        for ids in index.definitions_by_name.values_mut() {
            ids.sort_by(order::cmp_symbol_ids);
        }
        for ids in index.ids_by_scip.values_mut() {
            ids.sort_by(order::cmp_symbol_ids);
        }
        for ids in index.definitions_by_scip.values_mut() {
            ids.sort_by(order::cmp_symbol_ids);
        }
        for ids in index.definitions_by_file.values_mut() {
            ids.sort_by(order::cmp_symbol_ids);
        }
        for keys in index.outgoing.values_mut() {
            keys.sort_by(order::cmp_edge_keys);
        }
        for keys in index.incoming.values_mut() {
            keys.sort_by(order::cmp_edge_keys);
        }

        Ok(index)
    }
}
