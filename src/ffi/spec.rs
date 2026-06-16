// SPDX-License-Identifier: Apache-2.0
//! `AbiSpec` registry and the lookups the producers/consumer use.
use crate::graph::types::FfiAbi;

/// Everything per-ABI in one place. Add an ABI = add a sibling file with one of
/// these consts + a line in `SPECS`.
pub(crate) struct AbiSpec {
    pub abi: FfiAbi,
    /// Language tags (`Language::as_str`) whose call sites may consume this ABI.
    pub consumers: &'static [&'static str],
    /// Rust attribute substrings that MARK a fn as exported under this ABI
    /// (substring match against each `attribute_item`'s text). Empty for ABIs
    /// not produced directly from a Rust attribute (e.g. JNI, which arrives via
    /// the `name_prefix` rule).
    pub rust_attr_markers: &'static [&'static str],
    /// Rust attribute substrings that carry a quoted export-name override.
    pub rust_name_override_markers: &'static [&'static str],
    /// If set, ANY export whose final name starts with this prefix is
    /// re-classified to THIS abi (the `Java_` → `Jni` rule).
    pub name_prefix: Option<&'static str>,
}

pub(crate) const SPECS: &[AbiSpec] = &[
    super::c::SPEC,
    super::python::SPEC,
    super::wasm::SPEC,
    super::node_api::SPEC,
    super::jni::SPEC,
];

/// Consumer matrix lookup (replaces `FfiAbi::consumers`).
pub(crate) fn consumers(abi: FfiAbi) -> &'static [&'static str] {
    SPECS
        .iter()
        .find(|s| s.abi == abi)
        .map_or(&[], |s| s.consumers)
}

/// Final-name re-classification (e.g. `Java_*` → `Jni`). Returns `base` if no
/// prefix rule matches.
fn reclassify_by_name(base: FfiAbi, name: &str) -> FfiAbi {
    c_name_export_abi(name).unwrap_or(base)
}

/// C-side by-name export classification (the `c.rs` `Java_` filter generalized).
pub(crate) fn c_name_export_abi(name: &str) -> Option<FfiAbi> {
    SPECS
        .iter()
        .find(|s| s.name_prefix.is_some_and(|p| name.starts_with(p)))
        .map(|s| s.abi)
}

/// Classify a Rust fn's FFI exports from its accumulated attribute texts.
/// Returns `(abi, export_name)` pairs in `SPECS` order — multi-ABI capable,
/// reproducing the prior inline classifier exactly.
pub(crate) fn rust_exports(attr_texts: &[&str], fn_name: &str) -> Vec<(FfiAbi, String)> {
    let mut out = Vec::new();
    for spec in SPECS {
        if spec.rust_attr_markers.is_empty() {
            continue;
        }
        let enabled = attr_texts
            .iter()
            .any(|t| spec.rust_attr_markers.iter().any(|m| t.contains(m)));
        if !enabled {
            continue;
        }
        // The producer walks attributes bottom-up; the prior inline classifier
        // overwrote the override on each match, so the LAST matching attribute in
        // walk order wins. `.rev().find_map(...)` reproduces that precisely.
        let name = attr_texts
            .iter()
            .rev()
            .filter(|t| {
                spec.rust_name_override_markers
                    .iter()
                    .any(|m| t.contains(m))
            })
            .find_map(|t| first_quoted(t))
            .map(str::to_owned)
            .unwrap_or_else(|| fn_name.to_owned());
        out.push((reclassify_by_name(spec.abi, &name), name));
    }
    out
}

/// The contents of the first double-quoted span in `s`, if any.
fn first_quoted(s: &str) -> Option<&str> {
    let start = s.find('"')? + 1;
    let rest = &s[start..];
    let end = rest.find('"')?;
    Some(&rest[..end])
}
