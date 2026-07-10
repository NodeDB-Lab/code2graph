// SPDX-License-Identifier: Apache-2.0

//! Node.js / Bun bindings for code2graph.
//!
//! Exposes extraction and resolution to JS/TS. Results are returned as plain
//! JS objects produced from the crate's lossless, versioned serde representation.
//! See [`extract`] and [`build_graph`].

use code2graph_core::{
    FileFacts, Language, Resolver, ScopeGraphResolver, SymbolTableResolver, extract_path,
};
use napi_derive::napi;
use serde_json::Value;

fn to_napi_err(e: impl std::fmt::Display) -> napi::Error {
    napi::Error::from_reason(e.to_string())
}

/// Extract symbols and references from a single source file.
///
/// `file` is a project-relative path used to infer the language; `source` is
/// its contents. Returns a JS object mirroring `FileFacts`.
#[napi]
pub fn extract(file: String, source: String) -> napi::Result<Value> {
    let facts = extract_path(&file, &source).map_err(to_napi_err)?;
    serde_json::to_value(&facts).map_err(to_napi_err)
}

/// Resolve extracted facts into a code graph.
///
/// `files` is a JS array of objects as returned by [`extract`]. `tier` selects
/// the resolver: `"name"` (default) uses Tier A (`NameOnly`); `"scope"` uses
/// Tier B (`Scoped`/`Exact`). Returns a JS object mirroring `CodeGraph`.
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

/// Return the canonical language tag for a file path, or `null` if the
/// extension is not recognized (e.g. `"src/main.rs"` -> `"rust"`).
#[napi]
pub fn language_of(path: String) -> Option<String> {
    Language::from_path(&path).map(|l| l.as_str().to_string())
}
