// SPDX-License-Identifier: Apache-2.0
//! C ABI spec. `#[no_mangle]` exports under the function name; `#[export_name =
//! "…"]` (with or without `#[no_mangle]`) overrides it — both mark a C export.
use crate::graph::types::FfiAbi;

pub(crate) const SPEC: super::spec::AbiSpec = super::spec::AbiSpec {
    abi: FfiAbi::C,
    consumers: &["c", "cpp"],
    rust_attr_markers: &["no_mangle", "export_name"],
    rust_name_override_markers: &["export_name"],
    name_prefix: None,
};
