// SPDX-License-Identifier: Apache-2.0

//! Python bindings for code2graph.
//!
//! Exposes the extraction and resolution API to Python. Results are returned as
//! native Python objects (dicts/lists) produced from the crate's serde
//! lossless, versioned serde representation. See [`extract`] for per-file
//! extraction and [`build_graph`] for cross-file
//! resolution into a `CodeGraph`.

use code2graph_core::{FileFacts, Resolver, ScopeGraphResolver, SymbolTableResolver, extract_path};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pythonize::{depythonize, pythonize};

/// Extract symbols and references from a single source file.
///
/// `file` is a project-relative path used to infer the language; `source` is its
/// contents. Returns a dict mirroring `FileFacts` (symbols, references, scopes,
/// bindings, ffi_exports).
#[pyfunction]
fn extract<'py>(py: Python<'py>, file: &str, source: &str) -> PyResult<Bound<'py, PyAny>> {
    let facts = extract_path(file, source).map_err(|e| PyValueError::new_err(e.to_string()))?;
    pythonize(py, &facts).map_err(Into::into)
}

/// Resolve extracted facts into a code graph.
///
/// `files` is a list of dicts as returned by [`extract`] (each mirrors
/// `FileFacts`). `tier` selects the resolver: `"name"` (default) uses the
/// fast, recall-first symbol-table resolver (Tier A, `NameOnly` confidence);
/// `"scope"` uses the scope-graph resolver (Tier B, `Scoped`/`Exact`). Returns
/// a dict mirroring `CodeGraph` (symbols + edges), each edge carrying a
/// `confidence` and `provenance`.
#[pyfunction]
#[pyo3(signature = (files, tier = "name"))]
fn build_graph<'py>(
    py: Python<'py>,
    files: &Bound<'py, PyAny>,
    tier: &str,
) -> PyResult<Bound<'py, PyAny>> {
    let facts: Vec<FileFacts> =
        depythonize(files).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let graph = match tier {
        "name" => SymbolTableResolver
            .resolve(&facts)
            .map_err(|e| PyValueError::new_err(e.to_string()))?,
        "scope" => ScopeGraphResolver
            .resolve(&facts)
            .map_err(|e| PyValueError::new_err(e.to_string()))?,
        other => {
            return Err(PyValueError::new_err(format!(
                "unknown tier {other:?}; expected \"name\" or \"scope\""
            )));
        }
    };
    pythonize(py, &graph).map_err(Into::into)
}

/// Return the canonical language tag for a file path, or `None` if the
/// extension is not recognized (e.g. `"src/main.rs"` -> `"rust"`).
#[pyfunction]
fn language_of(path: &str) -> Option<&'static str> {
    code2graph_core::Language::from_path(path).map(code2graph_core::Language::as_str)
}

#[pymodule]
fn code2graph(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(extract, m)?)?;
    m.add_function(wrap_pyfunction!(build_graph, m)?)?;
    m.add_function(wrap_pyfunction!(language_of, m)?)?;
    Ok(())
}
