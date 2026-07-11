// SPDX-License-Identifier: Apache-2.0

//! Owned native graph-index query surface.

use code2graph_query::{GraphIndex as NativeGraphIndex, ImpactOptions};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pythonize::pythonize;
use serde_json::json;

use crate::convert::{code_graph, edge_filter, positive_limit, symbol_id};

/// An owned, storage-free index over a resolved graph.
#[pyclass]
pub struct GraphIndex {
    inner: NativeGraphIndex,
}

#[pymethods]
impl GraphIndex {
    /// Construct an index from a lossless `CodeGraph` serde dictionary.
    #[new]
    fn new(graph: &Bound<'_, PyAny>) -> PyResult<Self> {
        let graph = code_graph(graph)?;
        let inner = NativeGraphIndex::from_graph(graph)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(Self { inner })
    }

    /// Return the exact locally-defined symbol for a lossless structural ID.
    fn symbol<'py>(
        &self,
        py: Python<'py>,
        id: &Bound<'py, PyAny>,
    ) -> PyResult<Option<Bound<'py, PyAny>>> {
        let id = symbol_id(id)?;
        self.inner
            .symbol(&id)
            .map(|symbol| pythonize(py, symbol).map_err(Into::into))
            .transpose()
    }

    /// Return all locally-defined symbols with an exact bare name.
    fn symbols_named<'py>(&self, py: Python<'py>, name: &str) -> PyResult<Bound<'py, PyAny>> {
        pythonize(py, &self.inner.symbols_named(name)).map_err(Into::into)
    }

    /// Return every structural ID with this SCIP display string, including endpoints.
    fn ids_with_scip<'py>(&self, py: Python<'py>, scip: &str) -> PyResult<Bound<'py, PyAny>> {
        pythonize(py, &self.inner.ids_with_scip(scip)).map_err(Into::into)
    }

    /// Return stable incoming edges after applying all supplied filters, then `limit`.
    #[pyo3(signature = (id, limit, role = None, min_confidence = None, provenance = None))]
    fn incoming<'py>(
        &self,
        py: Python<'py>,
        id: &Bound<'py, PyAny>,
        limit: u32,
        role: Option<&str>,
        min_confidence: Option<&str>,
        provenance: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let id = symbol_id(id)?;
        let filter = edge_filter(role, min_confidence, provenance)?;
        let limit = positive_limit(limit)?;
        let edges = self
            .inner
            .incoming(&id, filter)
            .into_iter()
            .take(limit)
            .collect::<Vec<_>>();
        pythonize(py, &edges).map_err(Into::into)
    }

    /// Return stable outgoing edges after applying all supplied filters, then `limit`.
    #[pyo3(signature = (id, limit, role = None, min_confidence = None, provenance = None))]
    fn outgoing<'py>(
        &self,
        py: Python<'py>,
        id: &Bound<'py, PyAny>,
        limit: u32,
        role: Option<&str>,
        min_confidence: Option<&str>,
        provenance: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let id = symbol_id(id)?;
        let filter = edge_filter(role, min_confidence, provenance)?;
        let limit = positive_limit(limit)?;
        let edges = self
            .inner
            .outgoing(&id, filter)
            .into_iter()
            .take(limit)
            .collect::<Vec<_>>();
        pythonize(py, &edges).map_err(Into::into)
    }

    /// Return bounded reverse-reachability rows and whether a bound omitted a match.
    #[pyo3(signature = (id, max_depth, limit, role = None, min_confidence = None, provenance = None))]
    #[expect(
        clippy::too_many_arguments,
        reason = "the public Python signature mirrors the Node binding's explicit filter fields"
    )]
    fn impact<'py>(
        &self,
        py: Python<'py>,
        id: &Bound<'py, PyAny>,
        max_depth: u32,
        limit: u32,
        role: Option<&str>,
        min_confidence: Option<&str>,
        provenance: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
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
        let value = json!({
            "steps": steps,
            "truncated": result.truncated,
        });
        pythonize(py, &value).map_err(Into::into)
    }
}
