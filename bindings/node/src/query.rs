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
