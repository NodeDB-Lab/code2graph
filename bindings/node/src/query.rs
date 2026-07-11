// SPDX-License-Identifier: Apache-2.0

//! Owned native graph-index query surface.

use code2graph_query::{GraphIndex as NativeGraphIndex, ImpactOptions};
use napi_derive::napi;
use serde_json::{Value, json};

use crate::convert::{code_graph, edge_filter, positive_limit, symbol_id, to_napi_err};

/// An owned, storage-free index over a resolved graph.
#[napi]
pub struct GraphIndex {
    inner: NativeGraphIndex,
}

#[napi]
impl GraphIndex {
    /// Construct an index from a lossless `CodeGraph` serde object.
    #[napi(constructor)]
    pub fn new(graph: Value) -> napi::Result<Self> {
        let graph = code_graph(graph)?;
        let inner = NativeGraphIndex::from_graph(graph).map_err(to_napi_err)?;
        Ok(Self { inner })
    }

    /// Return the exact locally-defined symbol for a lossless structural ID.
    #[napi]
    pub fn symbol(&self, id: Value) -> napi::Result<Option<Value>> {
        let id = symbol_id(id)?;
        self.inner
            .symbol(&id)
            .map(serde_json::to_value)
            .transpose()
            .map_err(to_napi_err)
    }

    /// Return all locally-defined symbols with an exact bare name.
    #[napi]
    pub fn symbols_named(&self, name: String) -> napi::Result<Value> {
        serde_json::to_value(self.inner.symbols_named(&name)).map_err(to_napi_err)
    }

    /// Return every structural ID with this SCIP display string, including endpoints.
    #[napi]
    pub fn ids_with_scip(&self, scip: String) -> napi::Result<Value> {
        serde_json::to_value(self.inner.ids_with_scip(&scip)).map_err(to_napi_err)
    }

    /// Return stable incoming edges after applying all supplied filters, then `limit`.
    #[napi]
    pub fn incoming(
        &self,
        id: Value,
        limit: u32,
        role: Option<String>,
        min_confidence: Option<String>,
        provenance: Option<String>,
    ) -> napi::Result<Value> {
        let id = symbol_id(id)?;
        let filter = edge_filter(role, min_confidence, provenance)?;
        let limit = positive_limit(limit)?;
        serde_json::to_value(
            self.inner
                .incoming(&id, filter)
                .into_iter()
                .take(limit)
                .collect::<Vec<_>>(),
        )
        .map_err(to_napi_err)
    }

    /// Return stable outgoing edges after applying all supplied filters, then `limit`.
    #[napi]
    pub fn outgoing(
        &self,
        id: Value,
        limit: u32,
        role: Option<String>,
        min_confidence: Option<String>,
        provenance: Option<String>,
    ) -> napi::Result<Value> {
        let id = symbol_id(id)?;
        let filter = edge_filter(role, min_confidence, provenance)?;
        let limit = positive_limit(limit)?;
        serde_json::to_value(
            self.inner
                .outgoing(&id, filter)
                .into_iter()
                .take(limit)
                .collect::<Vec<_>>(),
        )
        .map_err(to_napi_err)
    }

    /// Return bounded reverse-reachability rows and whether a bound omitted a match.
    #[napi]
    pub fn impact(
        &self,
        id: Value,
        max_depth: u32,
        limit: u32,
        role: Option<String>,
        min_confidence: Option<String>,
        provenance: Option<String>,
    ) -> napi::Result<Value> {
        let id = symbol_id(id)?;
        let options = ImpactOptions {
            filter: edge_filter(role, min_confidence, provenance)?,
            max_depth,
            max_nodes: positive_limit(limit)?,
        };
        let result = self.inner.impact(&id, options);
        let steps = result
            .steps
            .into_iter()
            .map(|step| {
                json!({
                    "symbol": step.symbol,
                    "parent": step.parent,
                    "depth": step.depth,
                    "path_confidence": step.path_confidence,
                    "via": step.via,
                })
            })
            .collect::<Vec<_>>();
        Ok(json!({
            "steps": steps,
            "truncated": result.truncated,
        }))
    }
}

#[cfg(test)]
mod tests {
    use code2graph_core::{
        CodeGraph, Confidence, Descriptor, Edge, Occurrence, Provenance, RefRole, SymbolId,
    };

    use super::GraphIndex;

    fn id(name: &str) -> SymbolId {
        SymbolId::global("rust", vec![Descriptor::Term(name.into())])
    }

    fn edge(from: SymbolId, to: SymbolId, byte: usize) -> Edge {
        Edge {
            from,
            to,
            role: RefRole::Call,
            confidence: Confidence::Exact,
            provenance: Provenance::ScopeGraph,
            occ: Occurrence {
                file: "src/a.rs".into(),
                line: 1,
                col: 0,
                byte,
            },
        }
    }

    #[test]
    fn preserves_endpoint_ids_direction_and_bounded_impact_output() {
        let seed = SymbolId::local("vendor/api.rs", "remote");
        let caller = id("caller");
        let graph = CodeGraph {
            symbols: vec![],
            edges: vec![edge(caller.clone(), seed.clone(), 1)],
        };
        let index =
            GraphIndex::new(serde_json::to_value(graph).expect("graph json")).expect("index");
        let incoming = index
            .incoming(
                serde_json::to_value(&seed).unwrap(),
                1,
                Some("Call".into()),
                None,
                None,
            )
            .expect("incoming");
        assert_eq!(incoming.as_array().unwrap().len(), 1);
        let outgoing = index
            .outgoing(serde_json::to_value(&seed).unwrap(), 1, None, None, None)
            .expect("outgoing");
        assert!(outgoing.as_array().unwrap().is_empty());
        let impact = index
            .impact(serde_json::to_value(&seed).unwrap(), 1, 1, None, None, None)
            .expect("impact");
        assert_eq!(
            impact["steps"][0]["symbol"],
            serde_json::to_value(caller).unwrap()
        );
        assert!(impact.get("visited").is_none());
    }
}
