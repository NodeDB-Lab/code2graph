// SPDX-License-Identifier: Apache-2.0
//! WebAssembly/JS (wasm-bindgen) ABI spec. `#[wasm_bindgen]` exports under the
//! function name; `#[wasm_bindgen(js_name = "…")]` overrides the JS-facing name.
use crate::graph::types::FfiAbi;

pub(crate) const SPEC: super::spec::AbiSpec = super::spec::AbiSpec {
    abi: FfiAbi::Wasm,
    consumers: &["javascript", "typescript"],
    #[cfg(feature = "rust")]
    rust_attr_markers: &["wasm_bindgen"],
    #[cfg(feature = "rust")]
    rust_name_override_markers: &["wasm_bindgen"],
    #[cfg(any(feature = "rust", feature = "c"))]
    name_prefix: None,
};
