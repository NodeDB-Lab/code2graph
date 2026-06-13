// SPDX-License-Identifier: Apache-2.0

//! Shared, language-agnostic helpers reused by every per-language extractor.
//!
//! These are pure tree-sitter utilities (text slicing, signature previews,
//! a generic call-reference query runner). Per-language modules pull them in
//! via `super::` re-exports; nothing here is part of the public API.

use tree_sitter::{Language as TsLanguage, Node, Query, QueryCursor, StreamingIterator};

use crate::error::{CodegraphError, Result};
use crate::graph::types::{ByteSpan, Occurrence, RefRole, Reference, Symbol, SymbolKind};
use crate::lang::Language;
use crate::symbol::{Descriptor, SymbolId};

/// UTF-8 text of a node's byte range (lossy fallback on invalid UTF-8).
pub(crate) fn node_text<'a>(node: &Node, bytes: &'a [u8]) -> &'a str {
    std::str::from_utf8(&bytes[node.start_byte()..node.end_byte()]).unwrap_or("<invalid utf8>")
}

/// One-line signature: text up to the first top-level `{` or `:`, whitespace-collapsed;
/// falls back to the first line. Shared by extractors that want a declaration preview.
pub(crate) fn one_line_signature(text: &str, stop: &[char]) -> String {
    let mut depth = 0i32;
    let mut end = text.len();
    let mut found = false;
    for (i, c) in text.char_indices() {
        if depth == 0 && stop.contains(&c) {
            end = i;
            found = true;
            break;
        }
        match c {
            '{' | '(' | '[' => depth += 1,
            '}' | ')' | ']' => depth -= 1,
            _ => {}
        }
    }
    let sig = if found {
        &text[..end]
    } else {
        text.lines().next().unwrap_or(text)
    };
    sig.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Minimum callee-name length to record as a reference (drops `ok`, `id`, …).
pub(crate) const MIN_REF_LEN: usize = 3;

/// UTF-8 text of the first direct child of `node` whose kind is `kind`.
pub(crate) fn child_text(node: &Node, kind: &str, bytes: &[u8]) -> Option<String> {
    node.children(&mut node.walk())
        .find(|c| c.kind() == kind)
        .map(|c| node_text(&c, bytes).to_owned())
}

/// UTF-8 text of the child of `node` at the named `field`.
pub(crate) fn field_text(node: &Node, field: &str, bytes: &[u8]) -> Option<String> {
    node.child_by_field_name(field)
        .map(|n| node_text(&n, bytes).to_owned())
}

/// The file's **module symbol** — a first-class node for the compilation unit.
///
/// Its identity is the file's namespace path (the same segments the extractor
/// derives for the symbols it contains), rendered as `Namespace` descriptors with
/// [`SymbolKind::Module`]. It spans the whole file, so any top-level reference
/// (e.g. an `import`) is attributed to it by the resolver's span-containment rule.
/// Every file gets exactly one; when the namespace path is empty (a root file),
/// the file stem is used so the identity stays stable and unique.
pub(crate) fn module_symbol(
    lang: Language,
    namespaces: &[String],
    file: &str,
    source_len: usize,
) -> Symbol {
    let mut descriptors: Vec<Descriptor> = namespaces
        .iter()
        .cloned()
        .map(Descriptor::Namespace)
        .collect();
    if descriptors.is_empty() {
        let stem = file.rsplit('/').next().unwrap_or(file);
        let stem = stem.split('.').next().unwrap_or(stem);
        if !stem.is_empty() {
            descriptors.push(Descriptor::Namespace(stem.to_owned()));
        }
    }
    let name = descriptors
        .last()
        .map_or_else(String::new, |d| d.name().to_owned());
    Symbol {
        id: SymbolId::global(lang.as_str(), descriptors),
        name,
        kind: SymbolKind::Module,
        file: file.to_owned(),
        line: 1,
        span: ByteSpan {
            start: 0,
            end: source_len,
        },
        signature: String::new(),
    }
}

/// Whether `node` has a `static` storage-class specifier among its direct children.
/// Shared by the C-family extractors (C, C++), whose grammars spell internal linkage
/// the same way.
pub(crate) fn is_static(node: &Node, bytes: &[u8]) -> bool {
    node.children(&mut node.walk())
        .any(|c| c.kind() == "storage_class_specifier" && node_text(&c, bytes) == "static")
}

/// Run a tree-sitter call-reference query and collect its `@callee` captures as
/// [`Reference`]s with [`RefRole::Call`]. The query must expose a capture named
/// `callee`; captures shorter than [`MIN_REF_LEN`] are dropped. Shared by every
/// extractor — only the query string and grammar differ per language.
pub(crate) fn collect_call_references(
    root: &Node,
    ts_lang: &TsLanguage,
    query_src: &str,
    lang: Language,
    bytes: &[u8],
    file: &str,
) -> Result<Vec<Reference>> {
    let query = Query::new(ts_lang, query_src).map_err(|e| CodegraphError::Query {
        lang: lang.as_str().to_owned(),
        msg: e.to_string(),
    })?;
    let callee_idx =
        query
            .capture_index_for_name("callee")
            .ok_or_else(|| CodegraphError::Query {
                lang: lang.as_str().to_owned(),
                msg: "missing @callee capture".to_owned(),
            })?;

    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&query, *root, bytes);
    let mut refs = Vec::new();
    while let Some(m) = matches.next() {
        for cap in m.captures.iter().filter(|c| c.index == callee_idx) {
            let name = node_text(&cap.node, bytes).to_owned();
            if name.len() < MIN_REF_LEN {
                continue;
            }
            refs.push(Reference {
                name,
                occ: Occurrence {
                    file: file.to_owned(),
                    line: (cap.node.start_position().row + 1) as u32,
                    col: cap.node.start_position().column as u32,
                    byte: cap.node.start_byte(),
                },
                role: RefRole::Call,
            });
        }
    }
    Ok(refs)
}

#[cfg(test)]
mod tests {
    use crate::extract::Extractor as _;
    use crate::extract::RustExtractor;
    use crate::graph::types::SymbolKind;

    #[test]
    fn emits_module_symbol() {
        let facts = RustExtractor
            .extract("pub fn f() {}", "src/util.rs")
            .unwrap();
        let module_syms: Vec<_> = facts
            .symbols
            .iter()
            .filter(|s| s.kind == SymbolKind::Module)
            .collect();
        assert_eq!(module_syms.len(), 1, "expected exactly one Module symbol");
        assert_eq!(
            module_syms[0].name, "util",
            "module name should be the file stem"
        );
    }
}
