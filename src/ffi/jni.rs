// SPDX-License-Identifier: Apache-2.0
//! Java Native Interface ABI spec. Produced by name, not by a Rust attribute:
//! any export whose final name follows the `Java_<pkg>_<Class>_<method>`
//! mangling is re-classified to JNI so it bridges to Java, not C, call sites.
use crate::graph::types::FfiAbi;

pub(crate) const SPEC: super::spec::AbiSpec = super::spec::AbiSpec {
    abi: FfiAbi::Jni,
    consumers: &["java"],
    rust_attr_markers: &[],
    rust_name_override_markers: &[],
    name_prefix: Some("Java_"),
};
