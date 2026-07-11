// SPDX-License-Identifier: Apache-2.0
//! Node.js native addon (napi-rs) ABI spec. `#[napi]` exports under the function
//! name; `#[napi(js_name = "…")]` overrides the JS-facing name.
use crate::graph::types::FfiAbi;

pub(crate) const SPEC: super::spec::AbiSpec = super::spec::AbiSpec {
    abi: FfiAbi::NodeApi,
    consumers: &["javascript", "typescript"],
    #[cfg(feature = "rust")]
    rust_attr_markers: &["napi"],
    #[cfg(feature = "rust")]
    rust_name_override_markers: &["napi"],
    #[cfg(any(feature = "rust", feature = "c"))]
    name_prefix: None,
};
