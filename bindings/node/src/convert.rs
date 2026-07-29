// SPDX-License-Identifier: Apache-2.0

//! Strict binding-input conversion helpers.

use code2graph_core::{CodeGraph, Confidence, Provenance, RefRole, SymbolId};
use code2graph_query::EdgeFilter;
use serde_json::Value;

pub(crate) fn to_napi_err(error: impl std::fmt::Display) -> napi::Error {
    napi::Error::from_reason(error.to_string())
}

pub(crate) fn symbol_id(value: Value) -> napi::Result<SymbolId> {
    if !value.is_object() {
        return Err(napi::Error::from_reason(
            "symbol id must be a lossless SymbolId serde object, not a SCIP string",
        ));
    }
    serde_json::from_value(value).map_err(to_napi_err)
}

pub(crate) fn code_graph(value: Value) -> napi::Result<CodeGraph> {
    if !value.is_object() {
        return Err(napi::Error::from_reason(
            "graph must be a CodeGraph serde object",
        ));
    }
    for (collection, field) in [("symbols", "id"), ("edges", "from"), ("edges", "to")] {
        if let Some(items) = value.get(collection).and_then(Value::as_array) {
            for item in items {
                if let Some(id) = item.get(field) {
                    if !id.is_object() {
                        return Err(napi::Error::from_reason(format!(
                            "graph {collection}.{field} must be a lossless SymbolId serde object, not a SCIP string"
                        )));
                    }
                }
            }
        }
    }
    serde_json::from_value(value).map_err(to_napi_err)
}

pub(crate) fn edge_filter(
    role: Option<String>,
    min_confidence: Option<String>,
    provenance: Option<String>,
) -> napi::Result<EdgeFilter> {
    let confidence = match min_confidence.as_deref().unwrap_or("Heuristic") {
        "Heuristic" => Confidence::Heuristic,
        "NameOnly" => Confidence::NameOnly,
        "Scoped" => Confidence::Scoped,
        "Exact" => Confidence::Exact,
        value => {
            return Err(napi::Error::from_reason(format!(
                "invalid min_confidence {value:?}; expected Heuristic, NameOnly, Scoped, or Exact"
            )));
        }
    };
    let role = match role.as_deref() {
        None => None,
        Some("Call") => Some(RefRole::Call),
        Some("IsImplementation") => Some(RefRole::IsImplementation),
        Some("Import") => Some(RefRole::Import),
        Some("ModuleRef") => Some(RefRole::ModuleRef),
        Some("TypeRef") => Some(RefRole::TypeRef),
        Some("Read") => Some(RefRole::Read),
        Some("Write") => Some(RefRole::Write),
        Some(value) => {
            return Err(napi::Error::from_reason(format!(
                "invalid role {value:?}; expected a canonical RefRole string"
            )));
        }
    };
    let provenance = match provenance.as_deref() {
        None => None,
        Some("SymbolTable") => Some(Provenance::SymbolTable),
        Some("ScopeGraph") => Some(Provenance::ScopeGraph),
        Some("FfiBridge") => Some(Provenance::FfiBridge),
        Some("Conformance") => Some(Provenance::Conformance),
        Some("LocalType") => Some(Provenance::LocalType),
        Some("NormalizedName") => Some(Provenance::NormalizedName),
        Some("External") => Some(Provenance::External),
        Some("CrossArtifact") => Some(Provenance::CrossArtifact),
        Some(value) => {
            return Err(napi::Error::from_reason(format!(
                "invalid provenance {value:?}; expected SymbolTable, ScopeGraph, FfiBridge, Conformance, LocalType, NormalizedName, External, or CrossArtifact"
            )));
        }
    };
    let filter = EdgeFilter::new(confidence);
    let filter = role.map_or(filter, |role| filter.with_role(role));
    Ok(provenance.map_or(filter, |provenance| filter.with_provenance(provenance)))
}

pub(crate) fn positive_limit(limit: u32) -> napi::Result<usize> {
    if limit == 0 {
        return Err(napi::Error::from_reason("limit must be a positive u32"));
    }
    Ok(limit as usize)
}
