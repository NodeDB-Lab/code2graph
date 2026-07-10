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
        let enabled = attr_texts.iter().any(|t| {
            spec.rust_attr_markers
                .iter()
                .any(|marker| exact_rust_attribute(t, marker))
        });
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
                    .any(|marker| exact_rust_attribute_assignment(t, marker))
            })
            .find_map(|t| attribute_assignment_value(t))
            .map(str::to_owned)
            .unwrap_or_else(|| fn_name.to_owned());
        out.push((reclassify_by_name(spec.abi, &name), name));
    }
    out
}

/// Match an unconditional outer attribute by its exact top-level path.
/// `cfg_attr` is excluded because its condition is unavailable in a build-free extractor.
fn exact_rust_attribute(text: &str, marker: &str) -> bool {
    let body = text
        .trim()
        .strip_prefix("#[")
        .and_then(|s| s.strip_suffix(']'))
        .map(str::trim);
    let Some(body) = body else {
        return false;
    };
    body == marker
        || body
            .split_once('=')
            .is_some_and(|(key, _)| key.trim() == marker)
        || body
            .strip_prefix("unsafe(")
            .and_then(|s| s.strip_suffix(')'))
            .is_some_and(|inner| inner.trim() == marker)
        || body
            .strip_prefix(marker)
            .is_some_and(|tail| tail.starts_with('('))
}

fn exact_rust_attribute_assignment(text: &str, marker: &str) -> bool {
    let body = text
        .trim()
        .strip_prefix("#[")
        .and_then(|s| s.strip_suffix(']'))
        .map(str::trim);
    body.is_some_and(|body| {
        body.split_once('=')
            .is_some_and(|(key, _)| key.trim() == marker)
            || body
                .strip_prefix(marker)
                .is_some_and(|tail| tail.starts_with('('))
            || body
                .split_once('(')
                .and_then(|(_, args)| args.strip_suffix(')'))
                .is_some_and(|args| {
                    args.split(',').any(|arg| {
                        arg.split_once('=')
                            .is_some_and(|(key, _)| key.trim() == marker)
                    })
                })
    })
}

fn attribute_assignment_value(text: &str) -> Option<&str> {
    // Attribute texts are `#[key = "value"]`; retain only the exact quoted RHS.
    let body = text.trim().strip_prefix("#[")?.strip_suffix(']')?.trim();
    let value = if let Some((_, args)) = body.split_once('(') {
        args.strip_suffix(')')?
            .split(',')
            .find_map(|arg| arg.split_once('=').map(|(_, value)| value))?
    } else {
        let (_, value) = body.split_once('=')?;
        value
    };
    value.trim().strip_prefix('"')?.strip_suffix('"')
}
