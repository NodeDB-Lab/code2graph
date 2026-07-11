// SPDX-License-Identifier: Apache-2.0
//! Python (PyO3) ABI spec. `#[pyfunction]` exports under the function name; a
//! `#[pyfunction(name = "…")]` or `#[pyo3(name = "…")]` attribute overrides it.
use crate::graph::types::FfiAbi;

pub(crate) const SPEC: super::spec::AbiSpec = super::spec::AbiSpec {
    abi: FfiAbi::Python,
    consumers: &["python"],
    #[cfg(feature = "rust")]
    rust_attr_markers: &["pyfunction"],
    #[cfg(feature = "rust")]
    rust_name_override_markers: &["pyfunction", "pyo3"],
    #[cfg(any(feature = "rust", feature = "c"))]
    name_prefix: None,
};
