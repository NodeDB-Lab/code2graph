// SPDX-License-Identifier: Apache-2.0

//! Strict binding-input conversion helpers.

use code2graph_core::{CodeGraph, Confidence, Provenance, RefRole, SymbolId};
use code2graph_query::EdgeFilter;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use pythonize::depythonize;

pub(crate) fn symbol_id(value: &Bound<'_, PyAny>) -> PyResult<SymbolId> {
    if !value.is_instance_of::<PyDict>() {
        return Err(PyValueError::new_err(
            "symbol id must be a lossless SymbolId serde dict, not a SCIP string",
        ));
    }
    depythonize(value).map_err(|error| PyValueError::new_err(error.to_string()))
}

pub(crate) fn code_graph(value: &Bound<'_, PyAny>) -> PyResult<CodeGraph> {
    if !value.is_instance_of::<PyDict>() {
        return Err(PyValueError::new_err(
            "graph must be a CodeGraph serde dict",
        ));
    }
    let value: serde_json::Value =
        depythonize(value).map_err(|error| PyValueError::new_err(error.to_string()))?;
    for (collection, field) in [("symbols", "id"), ("edges", "from"), ("edges", "to")] {
        if let Some(items) = value.get(collection).and_then(serde_json::Value::as_array) {
            for item in items {
                if let Some(id) = item.get(field) {
                    if !id.is_object() {
                        return Err(PyValueError::new_err(format!(
                            "graph {collection}.{field} must be a lossless SymbolId serde dict, not a SCIP string"
                        )));
                    }
                }
            }
        }
    }
    serde_json::from_value(value).map_err(|error| PyValueError::new_err(error.to_string()))
}

pub(crate) fn edge_filter(
    role: Option<&str>,
    min_confidence: Option<&str>,
    provenance: Option<&str>,
) -> PyResult<EdgeFilter> {
    let confidence = match min_confidence.unwrap_or("Heuristic") {
        "Heuristic" => Confidence::Heuristic,
        "NameOnly" => Confidence::NameOnly,
        "Scoped" => Confidence::Scoped,
        "Exact" => Confidence::Exact,
        value => {
            return Err(PyValueError::new_err(format!(
                "invalid min_confidence {value:?}; expected Heuristic, NameOnly, Scoped, or Exact"
            )));
        }
    };
    let role = match role {
        None => None,
        Some("Call") => Some(RefRole::Call),
        Some("IsImplementation") => Some(RefRole::IsImplementation),
        Some("Import") => Some(RefRole::Import),
        Some("ModuleRef") => Some(RefRole::ModuleRef),
        Some("TypeRef") => Some(RefRole::TypeRef),
        Some("Read") => Some(RefRole::Read),
        Some("Write") => Some(RefRole::Write),
        Some(value) => {
            return Err(PyValueError::new_err(format!(
                "invalid role {value:?}; expected a canonical RefRole string"
            )));
        }
    };
    let provenance = match provenance {
        None => None,
        Some("SymbolTable") => Some(Provenance::SymbolTable),
        Some("ScopeGraph") => Some(Provenance::ScopeGraph),
        Some("FfiBridge") => Some(Provenance::FfiBridge),
        Some("Conformance") => Some(Provenance::Conformance),
        Some("NormalizedName") => Some(Provenance::NormalizedName),
        Some("External") => Some(Provenance::External),
        Some(value) => {
            return Err(PyValueError::new_err(format!(
                "invalid provenance {value:?}; expected SymbolTable, ScopeGraph, FfiBridge, Conformance, NormalizedName, or External"
            )));
        }
    };
    let filter = EdgeFilter::new(confidence);
    let filter = role.map_or(filter, |role| filter.with_role(role));
    Ok(provenance.map_or(filter, |provenance| filter.with_provenance(provenance)))
}

pub(crate) fn positive_limit(limit: u32) -> PyResult<usize> {
    if limit == 0 {
        return Err(PyValueError::new_err("limit must be a positive u32"));
    }
    Ok(limit as usize)
}

#[cfg(test)]
mod tests {
    use super::{edge_filter, positive_limit};

    #[test]
    fn filters_are_canonical_and_limits_are_positive() {
        assert!(edge_filter(Some("call"), None, None).is_err());
        assert!(edge_filter(None, Some("exact"), None).is_err());
        assert!(edge_filter(None, None, Some("scope_graph")).is_err());
        assert!(edge_filter(Some("Call"), Some("Exact"), Some("ScopeGraph")).is_ok());
        assert!(positive_limit(0).is_err());
        assert_eq!(positive_limit(1).expect("positive"), 1);
    }
}
