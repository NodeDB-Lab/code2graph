// SPDX-License-Identifier: Apache-2.0

//! Extraction and resolution entry points.

use code2graph_core::{
    BindingRules, FileFacts, Language, QueryBindingRule, Resolver, ScopeGraphResolver,
    SymbolTableResolver, extract_path, extract_path_with_bindings,
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

/// A custom query-binding rule: `construct` (e.g. "mydb::sql") in `lang` carries
/// embedded SQL in argument `sqlArg`.
#[napi(object)]
pub struct QueryBindingRuleInput {
    pub lang: String,
    pub construct: String,
    pub sql_arg: u32,
}

/// Extract facts AND cross-artifact code→SQL references. Applies the built-in
/// query-binding rules (sqlx/diesel/knex/execute/…); `customRules` (optional)
/// registers project-specific constructs on top of the defaults.
#[napi]
pub fn extract_with_bindings(
    file: String,
    source: String,
    custom_rules: Option<Vec<QueryBindingRuleInput>>,
) -> napi::Result<Value> {
    let mut rules = BindingRules::with_defaults();
    for raw in custom_rules.unwrap_or_default() {
        let lang = Language::from_tag(&raw.lang).ok_or_else(|| {
            napi::Error::from_reason(format!("unknown language tag {:?}", raw.lang))
        })?;
        rules.register(QueryBindingRule {
            lang,
            construct: raw.construct,
            sql_arg: raw.sql_arg as usize,
        });
    }
    let facts = extract_path_with_bindings(&file, &source, &rules).map_err(to_napi_err)?;
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
