// SPDX-License-Identifier: Apache-2.0

//! Extraction, resolution, and module registration entry points.

use code2graph_core::{
    BindingRules, FileFacts, Language, QueryBindingRule, Resolver, ScopeGraphResolver,
    SymbolTableResolver, extract_path, extract_path_with_bindings,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pythonize::{depythonize, pythonize};

use crate::query::GraphIndex;

#[pyfunction]
fn extract<'py>(py: Python<'py>, file: &str, source: &str) -> PyResult<Bound<'py, PyAny>> {
    let facts =
        extract_path(file, source).map_err(|error| PyValueError::new_err(error.to_string()))?;
    pythonize(py, &facts).map_err(Into::into)
}

#[derive(serde::Deserialize)]
struct QueryBindingRuleRaw {
    lang: String,
    construct: String,
    sql_arg: usize,
}

/// Extract facts AND cross-artifact code→SQL references. Applies the built-in
/// query-binding rules (sqlx/diesel/knex/execute/…); `custom_rules` (optional)
/// registers project-specific constructs on top of the defaults.
#[pyfunction]
#[pyo3(signature = (file, source, custom_rules = None))]
fn extract_with_bindings<'py>(
    py: Python<'py>,
    file: &str,
    source: &str,
    custom_rules: Option<&Bound<'py, PyAny>>,
) -> PyResult<Bound<'py, PyAny>> {
    let mut rules = BindingRules::with_defaults();
    if let Some(list) = custom_rules {
        let raw: Vec<QueryBindingRuleRaw> =
            depythonize(list).map_err(|e| PyValueError::new_err(e.to_string()))?;
        for r in raw {
            let lang = Language::from_tag(&r.lang).ok_or_else(|| {
                PyValueError::new_err(format!("unknown language tag {:?}", r.lang))
            })?;
            rules.register(QueryBindingRule {
                lang,
                construct: r.construct,
                sql_arg: r.sql_arg,
            });
        }
    }
    let facts = extract_path_with_bindings(file, source, &rules)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    pythonize(py, &facts).map_err(Into::into)
}

#[pyfunction]
#[pyo3(signature = (files, tier = "name"))]
fn build_graph<'py>(
    py: Python<'py>,
    files: &Bound<'py, PyAny>,
    tier: &str,
) -> PyResult<Bound<'py, PyAny>> {
    let facts: Vec<FileFacts> =
        depythonize(files).map_err(|error| PyValueError::new_err(error.to_string()))?;
    let graph = match tier {
        "name" => SymbolTableResolver
            .resolve(&facts)
            .map_err(|error| PyValueError::new_err(error.to_string()))?,
        "scope" => ScopeGraphResolver
            .resolve(&facts)
            .map_err(|error| PyValueError::new_err(error.to_string()))?,
        other => {
            return Err(PyValueError::new_err(format!(
                "unknown tier {other:?}; expected \"name\" or \"scope\""
            )));
        }
    };
    pythonize(py, &graph).map_err(Into::into)
}

#[pyfunction]
fn language_of(path: &str) -> Option<&'static str> {
    code2graph_core::Language::from_path(path).map(code2graph_core::Language::as_str)
}

#[pymodule]
pub fn code2graph(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(extract, m)?)?;
    m.add_function(wrap_pyfunction!(extract_with_bindings, m)?)?;
    m.add_function(wrap_pyfunction!(build_graph, m)?)?;
    m.add_function(wrap_pyfunction!(language_of, m)?)?;
    m.add_class::<GraphIndex>()?;
    Ok(())
}
