// SPDX-License-Identifier: Apache-2.0

//! Shared, language-agnostic helpers reused by every per-language extractor.
//!
//! These are pure tree-sitter utilities (text slicing, signature previews,
//! a generic call-reference query runner). Per-language modules pull them in
//! via `super::` re-exports; nothing here is part of the public API.

// This is the shared extractor toolkit; which helpers are live depends on the
// set of enabled language features, so unused-in-this-build helpers are expected.
#![allow(dead_code)]

use tree_sitter::{Language as TsLanguage, Node, Query, QueryCursor, StreamingIterator};

use crate::error::{CodegraphError, Result};
use crate::graph::types::{
    Binding, BindingKind, BindingTarget, ByteSpan, Occurrence, RefRole, Reference, Scope, ScopeId,
    ScopeKind, Symbol, SymbolKind, TypeRefContext, Visibility,
};
use crate::lang::Language;
use crate::symbol::{Descriptor, SymbolId};

/// The invariant per-extraction context threaded through an extractor's helpers:
/// the source bytes, the file path, and the language tag. These three do not
/// change during a single file's extraction (unlike the namespace/descriptor
/// prefix, which is extended as the walk descends — so that stays a separate
/// per-scope argument and is deliberately NOT part of this struct).
pub(crate) struct ExtractCtx<'a> {
    pub bytes: &'a [u8],
    pub file: &'a str,
    pub lang: Language,
}

/// Build a [`Symbol`] from the extraction context plus the per-symbol facts.
/// `span_node` provides the span (its byte range) and 1-based line. `signature`
/// is precomputed by the caller (stop-chars vary per language; some callers — e.g.
/// the TS exported-decl case — take the span from a wrapper node but the signature
/// from the inner declaration, so signature stays a caller-supplied `String`).
pub(crate) fn make_symbol(
    ctx: &ExtractCtx,
    span_node: &Node,
    name: String,
    kind: SymbolKind,
    visibility: Visibility,
    descriptors: Vec<Descriptor>,
    signature: String,
) -> Symbol {
    Symbol {
        id: SymbolId::global(ctx.lang.as_str(), descriptors),
        name,
        kind,
        visibility,
        entry_points: Vec::new(),
        file: ctx.file.to_owned(),
        line: (span_node.start_position().row + 1) as u32,
        span: ByteSpan {
            start: span_node.start_byte(),
            end: span_node.end_byte(),
        },
        signature,
    }
}

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
/// The module name a file's [`module_symbol`] is identified by: the leaf of the
/// namespace path, or the file stem when the path is empty (e.g. crate-root
/// files like `lib.rs`/`main.rs`). Extractors that need to reference a file's own
/// module (e.g. a Rust `crate::` anchor) derive the name through this so it
/// matches the symbol exactly and resolves against the Tier-B module index.
pub(crate) fn module_name(namespaces: &[String], file: &str) -> String {
    if let Some(leaf) = namespaces.last() {
        return leaf.clone();
    }
    let stem = file.rsplit('/').next().unwrap_or(file);
    stem.split('.').next().unwrap_or(stem).to_owned()
}

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
    let name = module_name(namespaces, file);
    if descriptors.is_empty() && !name.is_empty() {
        descriptors.push(Descriptor::Namespace(name.clone()));
    }
    Symbol {
        id: SymbolId::global(lang.as_str(), descriptors),
        name,
        kind: SymbolKind::Module,
        visibility: Visibility::Public,
        entry_points: Vec::new(),
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
        is_reexport: false,
        imported_name: None,
        qualifier: None,
        scope: None,
        type_ref_ctx: None,
        cross_artifact: false,
        self_receiver: false,
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
        is_reexport: false,
        imported_name: None,
        qualifier: None,
        scope: None,
        type_ref_ctx: None,
        cross_artifact: false,
        self_receiver: false,
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
        is_reexport: false,
        imported_name: None,
        qualifier: None,
        scope: None,
        type_ref_ctx: Some(ctx),
        cross_artifact: false,
        self_receiver: false,
    });
}

/// Build the descriptor path for one member of a type (class/impl/trait/…
/// body): `namespaces.map(Namespace) ++ [Type(type_name), leaf]`.
///
/// Shared by every per-language extractor that emits members (methods,
/// fields, associated consts) qualified under an enclosing type — the shape
/// is identical across languages, only how `leaf` is built differs.
pub(crate) fn member_descriptors(
    namespaces: &[String],
    type_name: &str,
    leaf: Descriptor,
) -> Vec<Descriptor> {
    let mut descriptors: Vec<Descriptor> = namespaces
        .iter()
        .cloned()
        .map(Descriptor::Namespace)
        .collect();
    descriptors.push(Descriptor::Type(type_name.to_owned()));
    descriptors.push(leaf);
    descriptors
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
/// Run `self_call_query` and mark every already-collected [`RefRole::Call`]
/// reference whose occurrence byte matches a captured `self.<name>()` /
/// `this.<name>()` callee with `self_receiver = true`. A NEUTRAL SYNTACTIC
/// FACT: it records that the receiver was written as the `self`/`this`
/// keyword — the resolver, not the extractor, maps it to the enclosing type.
/// `qualifier` is left untouched (already `None` for a field-expression
/// callee).
///
/// Byte-offset correlation is exact: both `self_call_query` and the query
/// that produced `references` capture the identical callee identifier node,
/// so a reference dropped by the main call query's length filter simply
/// finds no match here — a harmless no-op, never a false mark.
///
/// Correlation goes through a `byte -> index` map built once up front (O(n))
/// rather than a linear scan of `references` per self-call match, which would
/// be O(self-calls × total references) on a file with many `self.foo()` sites.
///
/// `expected_receiver_text` gates the mark by the *text* of an `@receiver`
/// capture: some grammars parse the receiver keyword as a plain node
/// indistinguishable from an ordinary receiver (PHP's `$this` is a
/// `variable_name`; Scala's `this` is an `identifier`), so the query cannot
/// select it structurally. Pass `Some("$this")` / `Some("this")` there and have
/// the query capture the receiver node as `@receiver`; only matches whose
/// `@receiver` text equals the expected string are marked. Pass `None` for
/// grammars with a dedicated receiver-keyword node (Rust `self`, Ruby `self`,
/// C++/Swift/…), where the query is already structurally exact.
pub(crate) fn mark_self_receiver_calls(
    root: &Node,
    ts_lang: &TsLanguage,
    self_call_query: &str,
    lang: Language,
    bytes: &[u8],
    references: &mut [Reference],
    expected_receiver_text: Option<&str>,
) -> Result<()> {
    let query = Query::new(ts_lang, self_call_query).map_err(|e| CodegraphError::Query {
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
    let receiver_idx = query.capture_index_for_name("receiver");
    // A text gate requires the query to actually capture the receiver.
    if expected_receiver_text.is_some() && receiver_idx.is_none() {
        return Err(CodegraphError::Query {
            lang: lang.as_str().to_owned(),
            msg: "expected_receiver_text set but query has no @receiver capture".to_owned(),
        });
    }
    let call_ref_by_byte: std::collections::HashMap<usize, usize> = references
        .iter()
        .enumerate()
        .filter(|(_, r)| r.role == RefRole::Call)
        .map(|(i, r)| (r.occ.byte, i))
        .collect();
    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&query, *root, bytes);
    while let Some(m) = matches.next() {
        // When a text gate is set, the `@receiver` node's text must match
        // exactly, else this match is an ordinary receiver, not the keyword.
        if let Some(expected) = expected_receiver_text {
            let receiver_matches = m
                .captures
                .iter()
                .find(|c| Some(c.index) == receiver_idx)
                .and_then(|c| c.node.utf8_text(bytes).ok())
                == Some(expected);
            if !receiver_matches {
                continue;
            }
        }
        for cap in m.captures.iter().filter(|c| c.index == callee_idx) {
            let byte = cap.node.start_byte();
            if let Some(&idx) = call_ref_by_byte.get(&byte) {
                references[idx].self_receiver = true;
                // A `self`/`this` receiver is a keyword, not a resolvable type
                // path. Some grammars' main call query captures it as a
                // qualifier (e.g. Kotlin's `navigation_expression` receiver);
                // clear it so self-receiver refs uniformly carry `qualifier =
                // None`, matching the resolver invariant (the owning type is
                // derived from the enclosing member, never from this receiver).
                references[idx].qualifier = None;
            }
        }
    }
    Ok(())
}

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
    // Optional generic marker capture: a query may tag the callee's receiver as
    // the `self`/`this` keyword by including a `@self_receiver` capture on the
    // match. Queries without it (every language until their extractor opts in)
    // return `None` here, keeping `self_receiver` `false` everywhere → zero
    // behavior change.
    let self_receiver_idx = query.capture_index_for_name("self_receiver");

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
        let self_receiver =
            self_receiver_idx.is_some_and(|si| m.captures.iter().any(|c| c.index == si));
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
                is_reexport: false,
                imported_name: None,
                qualifier: qualifier.clone(),
                scope: None,
                type_ref_ctx: None,
                cross_artifact: false,
                self_receiver,
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

// ── Embedded-language offset remap ──────────────────────────────────────────

/// Convert a byte offset to a 1-based (line, 0-based col) pair by scanning the
/// bytes of the containing file.  Used when remapping inner-block offsets back
/// into the enclosing document.
pub(crate) fn byte_to_line_col(bytes: &[u8], byte: usize) -> (u32, u32) {
    let safe = byte.min(bytes.len());
    let prefix = &bytes[..safe];
    let line = 1 + prefix.iter().filter(|&&b| b == b'\n').count() as u32;
    let col = prefix.iter().rev().take_while(|&&b| b != b'\n').count() as u32;
    (line, col)
}

/// Shift all byte offsets in `facts` by `delta` so that positions are expressed
/// relative to the enclosing file (`embedding_bytes`) rather than the inner
/// script/template block.  Also overwrites `facts.file` and `facts.lang`.
///
/// Scope indices (`Binding.scope`, `Reference.scope`) are Vec indices — they
/// are NOT shifted here; the caller handles cross-block scope-index fixup when
/// merging multiple blocks.
pub(crate) fn shift_offsets(
    facts: &mut crate::graph::types::FileFacts,
    delta: usize,
    file: &str,
    lang: &str,
    embedding_bytes: &[u8],
) {
    facts.file = file.to_owned();
    facts.lang = lang.to_owned();

    for sym in &mut facts.symbols {
        sym.file = file.to_owned();
        sym.span.start += delta;
        sym.span.end += delta;
        sym.line = byte_to_line_col(embedding_bytes, sym.span.start).0;
    }

    for scope in &mut facts.scopes {
        scope.span.start += delta;
        scope.span.end += delta;
    }

    for r in &mut facts.references {
        r.occ.file = file.to_owned();
        r.occ.byte += delta;
        let (line, col) = byte_to_line_col(embedding_bytes, r.occ.byte);
        r.occ.line = line;
        r.occ.col = col;
    }

    for b in &mut facts.bindings {
        b.intro += delta;
    }
}

/// Given an argument node believed to hold embedded SQL, parse its
/// `content_kind` child (the grammar's raw-string-content node kind — e.g.
/// `"string_content"` for Rust/Python, `"string_fragment"` for TS/JS) with the
/// SQL extractor and emit a [`RefRole::TypeRef`] reference (`cross_artifact:
/// true`) for each entity use-site found, anchored at the entity's position
/// within the original source. Shared by every per-language query-binding scan
/// so the emit logic is defined exactly once.
#[cfg(feature = "sql")]
pub(crate) fn emit_embedded_sql_refs(
    arg: &Node,
    content_kind: &str,
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Reference>,
) {
    let Some(content) = arg
        .children(&mut arg.walk())
        .find(|c| c.kind() == content_kind)
    else {
        return;
    };
    let content_start = content.start_byte();

    for entity in super::collect_sql_entity_references(node_text(&content, bytes)) {
        let abs = content_start + entity.rel_byte;
        let (line, col) = byte_to_line_col(bytes, abs);
        out.push(Reference {
            name: entity.name,
            occ: Occurrence {
                file: file.to_owned(),
                line,
                col,
                byte: abs,
            },
            role: RefRole::TypeRef,
            source_module: None,
            from_path: None,
            is_reexport: false,
            imported_name: None,
            qualifier: entity.qualifier,
            scope: None,
            type_ref_ctx: None,
            cross_artifact: true,
            self_receiver: false,
        });
    }
}

#[cfg(test)]
mod tests {
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

    #[cfg(feature = "rust")]
    #[test]
    fn make_symbol_from_extract_ctx() {
        use crate::graph::types::{SymbolKind, Visibility};
        use crate::lang::Language;
        use crate::symbol::Descriptor;
        use tree_sitter::Parser;

        let ts_lang = crate::grammar::rust();
        let mut parser = Parser::new();
        parser.set_language(&ts_lang).unwrap();
        let src = b"fn f() {}";
        let tree = parser.parse(src, None).unwrap();
        // The function_item node is the first named child of the source_file root.
        let root = tree.root_node();
        let fn_node = root.named_child(0).unwrap();
        assert_eq!(fn_node.kind(), "function_item");

        let ctx = super::ExtractCtx {
            bytes: src,
            file: "src/lib.rs",
            lang: Language::Rust,
        };
        let sym = super::make_symbol(
            &ctx,
            &fn_node,
            "f".to_owned(),
            SymbolKind::Function,
            Visibility::Private,
            vec![Descriptor::Term("f".to_owned())],
            "fn f()".to_owned(),
        );

        assert_eq!(sym.file, "src/lib.rs");
        assert_eq!(sym.name, "f");
        assert_eq!(sym.kind, SymbolKind::Function);
        assert_eq!(sym.visibility, Visibility::Private);
        assert_eq!(sym.signature, "fn f()");
        assert_eq!(sym.line, 1, "first line is 1-based");
        assert_eq!(sym.span.start, fn_node.start_byte());
        assert_eq!(sym.span.end, fn_node.end_byte());
    }

    #[cfg(feature = "rust")]
    #[test]
    fn emits_module_symbol() {
        use crate::extract::Extractor as _;
        use crate::extract::RustExtractor;
        use crate::graph::types::SymbolKind;

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
