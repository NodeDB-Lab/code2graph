// SPDX-License-Identifier: Apache-2.0
//! C ABI spec. `#[no_mangle]` exports under the function name; `#[export_name =
//! "…"]` (with or without `#[no_mangle]`) overrides it — both mark a C export.
use crate::graph::types::FfiAbi;

pub(crate) const SPEC: super::spec::AbiSpec = super::spec::AbiSpec {
    abi: FfiAbi::C,
    consumers: &["c", "cpp"],
    #[cfg(feature = "rust")]
    rust_attr_markers: &["no_mangle", "export_name"],
    #[cfg(feature = "rust")]
    rust_name_override_markers: &["export_name"],
    #[cfg(any(feature = "rust", feature = "c"))]
    name_prefix: None,
};
