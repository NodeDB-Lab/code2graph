// SPDX-License-Identifier: Apache-2.0

//! Shared, language-agnostic helpers reused by every per-language extractor.
//!
//! These are pure tree-sitter utilities (text slicing, signature previews,
//! a generic call-reference query runner). Per-language modules pull them in
//! via `super::` re-exports; nothing here is part of the public API.

use tree_sitter::{Language as TsLanguage, Node, Query, QueryCursor, StreamingIterator};

use crate::error::{CodegraphError, Result};
use crate::graph::types::{
    Binding, BindingKind, BindingTarget, ByteSpan, Occurrence, RefRole, Reference, Scope, ScopeId,
    ScopeKind, Symbol, SymbolKind, TypeRefContext,
};
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

/// The bare leaf name of a (possibly qualified, possibly generic) type-name text.
///
/// Strips a generic argument list (`Foo<T>` → `Foo`) then takes the final segment
/// after `sep` (`a::b::Foo` → `Foo` with `sep = "::"`). `sep` is the language's
/// path separator — `"::"` (Rust, C++, Ruby), `"."` (Java, Kotlin, Swift, TS,
/// Solidity), or `"\\"` (PHP). Stripping generics is harmless for languages that
/// have none, so one helper serves them all.
pub(crate) fn simple_type_name<'a>(text: &'a str, sep: &str) -> &'a str {
    let base = text.split_once('<').map_or(text, |(b, _)| b);
    base.rsplit_once(sep).map_or(base, |(_, a)| a).trim()
}

/// Build an [`Occurrence`] from a tree-sitter node and file path.
#[inline]
pub(crate) fn node_occurrence(node: &Node, file: &str) -> Occurrence {
    Occurrence {
        file: file.to_owned(),
        line: (node.start_position().row + 1) as u32,
        col: node.start_position().column as u32,
        byte: node.start_byte(),
    }
}

/// Push a [`Reference`] for `name` at `node`'s position with the given `role`.
///
/// Shared by the inheritance and import passes (only the `role` and how `name` is
/// derived differ per language). Empty names are skipped. Unlike
/// [`collect_call_references`], no [`MIN_REF_LEN`] filter applies — short type
/// names (e.g. `IO`) are legitimate.
///
/// Sets `source_module: None`; use [`push_import_ref`] for [`RefRole::Import`]
/// references that carry the importing module's SCIP identity.
pub(crate) fn push_ref(
    out: &mut Vec<Reference>,
    name: &str,
    node: &Node,
    file: &str,
    role: RefRole,
) {
    if name.is_empty() {
        return;
    }
    out.push(Reference {
        name: name.to_owned(),
        occ: node_occurrence(node, file),
        role,
        source_module: None,
        from_path: None,
        qualifier: None,
        scope: None,
        type_ref_ctx: None,
    });
}

/// Push an [`RefRole::Import`] [`Reference`] for `name` at `node`'s position,
/// carrying `module_id` as the SCIP identity of the importing file's module
/// symbol, and `from_path` as the raw module path string written in the source
/// (e.g. `"std::io"`, `"./svc"`, `"pkg.models"`).
///
/// Like [`push_ref`] but sets `source_module: Some(module_id)` and hard-codes
/// `role: RefRole::Import`. Empty names are skipped.
pub(crate) fn push_import_ref(
    out: &mut Vec<Reference>,
    name: &str,
    node: &Node,
    file: &str,
    module_id: &str,
    from_path: &str,
) {
    if name.is_empty() {
        return;
    }
    out.push(Reference {
        name: name.to_owned(),
        occ: node_occurrence(node, file),
        role: RefRole::Import,
        source_module: Some(module_id.to_owned()),
        from_path: if from_path.is_empty() {
            None
        } else {
            Some(from_path.to_owned())
        },
        qualifier: None,
        scope: None,
        type_ref_ctx: None,
    });
}

/// Push a [`RefRole::TypeRef`] [`Reference`] for `name` at `node`'s position,
/// carrying the sub-type position context `ctx` as [`TypeRefContext`].
///
/// Like [`push_ref`] with `role = RefRole::TypeRef`, but always sets
/// `type_ref_ctx: Some(ctx)`. No minimum-length filter is applied — type names
/// can be short (e.g. `IO`). Empty names are skipped.
pub(crate) fn push_type_ref(
    out: &mut Vec<Reference>,
    name: &str,
    node: &Node,
    file: &str,
    ctx: TypeRefContext,
) {
    if name.is_empty() {
        return;
    }
    out.push(Reference {
        name: name.to_owned(),
        occ: node_occurrence(node, file),
        role: RefRole::TypeRef,
        source_module: None,
        from_path: None,
        qualifier: None,
        scope: None,
        type_ref_ctx: Some(ctx),
    });
}

/// Strip a single layer of surrounding `"` or `` ` `` from a quoted identifier or
/// string literal. Returns the inner slice. If the text is not wrapped in a matching
/// pair of those delimiters, returns it unchanged. Does not panic on any input.
///
/// Used by SQL (both `"` and `` ` `` are valid identifier quoting) and HCL
/// (`"` only, but the superset is safe — HCL has no backtick syntax). Config
/// extractors may reuse this as well.
pub(crate) fn unquote(text: &str) -> &str {
    let b = text.as_bytes();
    if b.len() >= 2 {
        let (first, last) = (b[0], b[b.len() - 1]);
        if (first == b'"' && last == b'"') || (first == b'`' && last == b'`') {
            return &text[1..text.len() - 1];
        }
    }
    text
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
    // Optional: queries that have no `@qualifier` capture (every language except
    // Rust after unit 8a) return `None` here, keeping qualifier `None` everywhere
    // for those languages → zero behavior change.
    let qualifier_idx = query.capture_index_for_name("qualifier");

    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&query, *root, bytes);
    let mut refs = Vec::new();
    while let Some(m) = matches.next() {
        // Resolve this match's qualifier once (at most one `@qualifier` per match).
        let qualifier = qualifier_idx.and_then(|qi| {
            m.captures
                .iter()
                .find(|c| c.index == qi)
                .map(|c| node_text(&c.node, bytes).to_owned())
        });
        for cap in m.captures.iter().filter(|c| c.index == callee_idx) {
            let name = node_text(&cap.node, bytes).to_owned();
            if name.len() < MIN_REF_LEN {
                continue;
            }
            refs.push(Reference {
                name,
                occ: node_occurrence(&cap.node, file),
                role: RefRole::Call,
                source_module: None,
                from_path: None,
                qualifier: qualifier.clone(),
                scope: None,
                type_ref_ctx: None,
            });
        }
    }
    Ok(refs)
}

// ── Tier-B scope / binding helpers (language-agnostic) ──────────────────────
//
// The scope tree and binding collection are driven by per-language tree walks
// (each extractor knows its own grammar's scope-opening node kinds), but these
// primitives — pushing scopes, locating the innermost scope for a byte, and
// emitting the grammar-independent binding kinds — are identical across
// languages and live here so every scope-aware extractor shares one definition.

/// `ByteSpan` covering the whole extent of `node`.
pub(crate) fn node_span(node: &Node) -> ByteSpan {
    ByteSpan {
        start: node.start_byte(),
        end: node.end_byte(),
    }
}

/// Push a [`Scope`] and return its [`ScopeId`] (its index). Callers must push a
/// parent before its children so that index order matches nesting depth (relied
/// on by [`innermost_scope`] for tie-breaking).
pub(crate) fn push_scope(
    scopes: &mut Vec<Scope>,
    parent: Option<ScopeId>,
    span: ByteSpan,
    kind: ScopeKind,
) -> ScopeId {
    let id = scopes.len();
    scopes.push(Scope { parent, span, kind });
    id
}

/// Return the [`ScopeId`] of the innermost scope whose span contains `byte`.
///
/// Ties on span length resolve to the higher index: a parent scope is always
/// pushed before its children, so the larger index is the more deeply nested
/// scope. Returns `None` only when no scope contains the byte (in practice the
/// file-root scope at index 0 spans the whole file).
pub(crate) fn innermost_scope(byte: usize, scopes: &[Scope]) -> Option<ScopeId> {
    scopes
        .iter()
        .enumerate()
        .filter(|(_, s)| s.span.contains(byte))
        .min_by_key(|(id, s)| (s.span.len(), std::cmp::Reverse(*id)))
        .map(|(id, _)| id)
}

/// Attach each reference to the innermost scope that contains its byte offset.
pub(crate) fn attach_reference_scopes(refs: &mut [Reference], scopes: &[Scope]) {
    for r in refs {
        r.scope = innermost_scope(r.occ.byte, scopes);
    }
}

/// Push a single [`Binding`] with `target = BindingTarget::Local`, computing its
/// `scope` via [`innermost_scope`] (defaulting to the file root, scope 0).
#[inline]
pub(crate) fn push_binding(
    out: &mut Vec<Binding>,
    name: String,
    intro: usize,
    kind: BindingKind,
    scopes: &[Scope],
) {
    let scope = innermost_scope(intro, scopes).unwrap_or(0);
    out.push(Binding {
        scope,
        name,
        intro,
        kind,
        target: BindingTarget::Local,
    });
}

/// Emit a [`BindingKind::Definition`] binding for each top-level definition.
///
/// Each binds in the file-root scope (`scopes[0]`); `intro` is the definition's
/// start byte and `target` points at its extracted [`SymbolId`].
pub(crate) fn definition_bindings(defs: &[Symbol]) -> Vec<Binding> {
    defs.iter()
        .map(|d| Binding {
            scope: 0,
            name: d.name.clone(),
            intro: d.span.start,
            kind: BindingKind::Definition,
            target: BindingTarget::Def(d.id.clone()),
        })
        .collect()
}

/// Emit a [`BindingKind::Import`] binding for each [`RefRole::Import`] reference.
///
/// The binding's target carries the imported-from path as written (empty when
/// unavailable); `scope` is resolved via [`innermost_scope`], defaulting to the
/// file root (0).
pub(crate) fn import_bindings(refs: &[Reference], scopes: &[Scope]) -> Vec<Binding> {
    refs.iter()
        .filter(|r| r.role == RefRole::Import)
        .map(|r| Binding {
            scope: innermost_scope(r.occ.byte, scopes).unwrap_or(0),
            name: r.name.clone(),
            intro: r.occ.byte,
            kind: BindingKind::Import,
            target: BindingTarget::Import(r.from_path.clone().unwrap_or_default()),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::extract::Extractor as _;
    use crate::extract::RustExtractor;
    use crate::graph::types::SymbolKind;

    #[test]
    fn unquote_removes_double_quotes() {
        assert_eq!(super::unquote(r#""my table""#), "my table");
    }

    #[test]
    fn unquote_removes_backticks() {
        assert_eq!(super::unquote("`my_table`"), "my_table");
    }

    #[test]
    fn unquote_bare_and_empty_unchanged() {
        assert_eq!(super::unquote("users"), "users");
        assert_eq!(super::unquote(""), "");
    }

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
