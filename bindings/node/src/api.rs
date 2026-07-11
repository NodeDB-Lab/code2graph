// SPDX-License-Identifier: Apache-2.0

//! Extraction and resolution entry points.

use code2graph_core::{
    FileFacts, Language, Resolver, ScopeGraphResolver, SymbolTableResolver, extract_path,
};
use napi_derive::napi;
use serde_json::Value;

use crate::convert::to_napi_err;

/// Extract symbols and references from a single source file.
#[napi]
pub fn extract(file: String, source: String) -> napi::Result<Value> {
    let facts = extract_path(&file, &source).map_err(to_napi_err)?;
    serde_json::to_value(&facts).map_err(to_napi_err)
}

/// Resolve extracted facts into a code graph.
#[napi]
pub fn build_graph(files: Value, tier: Option<String>) -> napi::Result<Value> {
    let facts: Vec<FileFacts> = serde_json::from_value(files).map_err(to_napi_err)?;
    let graph = match tier.as_deref().unwrap_or("name") {
        "name" => SymbolTableResolver.resolve(&facts).map_err(to_napi_err)?,
        "scope" => ScopeGraphResolver.resolve(&facts).map_err(to_napi_err)?,
        other => {
            return Err(napi::Error::from_reason(format!(
                "unknown tier {other:?}; expected \"name\" or \"scope\""
            )));
        }
    };
    serde_json::to_value(&graph).map_err(to_napi_err)
}

/// Return the canonical language tag for a file path, or `null` if unrecognized.
#[napi]
pub fn language_of(path: String) -> Option<String> {
    Language::from_path(&path).map(|language| language.as_str().to_string())
}
