// SPDX-License-Identifier: Apache-2.0

//! Rust extractor — one tree-sitter pass yielding definitions and references.
//!
//! Definitions: fully-public top-level items (`pub fn/struct/enum/trait/type/
//! const/static/mod`) plus `impl` blocks. Qualified identity follows the module
//! path derived from the file path (`src/auth/session.rs` → namespaces
//! `auth`,`session`). References: callee identifiers of `call_expression` nodes.
//!
//! Emits neutral [`FileFacts`] — no storage entries, no source bodies.

use tree_sitter::{Language as TsLanguage, Node, Parser, Query, QueryCursor, StreamingIterator};

use crate::error::{CodegraphError, Result};
use crate::graph::types::{
    Binding, BindingKind, BindingTarget, ByteSpan, FfiAbi, FfiExport, FileFacts, RefRole,
    Reference, Scope, ScopeId, ScopeKind, Symbol, SymbolKind,
};
use crate::lang::Language;
use crate::symbol::{Descriptor, SymbolId};

use super::{
    Extractor, child_text, collect_call_references, node_occurrence, node_text, one_line_signature,
};

/// Tree-sitter query capturing call-callee identifiers (and optional qualifier).
const CALL_QUERY: &str = r#"
(call_expression
  function: [
    (identifier) @callee
    (field_expression field: (field_identifier) @callee)
    (scoped_identifier path: (_) @qualifier name: (identifier) @callee)
  ]
)
"#;

/// Tree-sitter query capturing type-position nodes for [`RefRole::TypeRef`] extraction.
///
/// Field names verified against `tree-sitter-rust-0.23.3/src/node-types.json`:
/// - `parameter` has field `type: _type`
/// - `function_item` has field `return_type: _type`
/// - `field_declaration` has field `type: _type`
/// - `ordered_field_declaration_list` has field `type: _type` (multiple = true, for tuple structs)
const TYPE_QUERY: &str = r#"
(parameter type: (_) @ty)
(function_item return_type: (_) @ty)
(field_declaration type: (_) @ty)
(ordered_field_declaration_list type: (_) @ty)
"#;

/// Extracts Rust symbols and references.
pub struct RustExtractor;

impl Extractor for RustExtractor {
    fn lang(&self) -> Language {
        Language::Rust
    }

    fn extract(&self, source: &str, file: &str) -> Result<FileFacts> {
        let ts_language = TsLanguage::from(tree_sitter_rust::LANGUAGE);
        let mut parser = Parser::new();
        parser
            .set_language(&ts_language)
            .map_err(|_| CodegraphError::Parse {
                path: file.to_owned(),
            })?;
        let tree = parser
            .parse(source, None)
            .ok_or_else(|| CodegraphError::Parse {
                path: file.to_owned(),
            })?;

        let root = tree.root_node();
        let bytes = source.as_bytes();
        let namespaces = rust_namespaces(file);

        let defs = collect_symbols(&root, bytes, file, &namespaces);
        let def_bindings = definition_bindings(&defs);
        let ffi_exports = collect_ffi_exports(&root, bytes, &defs);
        let mut symbols = defs;
        let mod_sym = super::module_symbol(Language::Rust, &namespaces, file, source.len());
        let module_id = mod_sym.id.to_scip_string();
        symbols.push(mod_sym);
        let mut references =
            collect_call_references(&root, &ts_language, CALL_QUERY, Language::Rust, bytes, file)?;
        collect_inheritance(&root, bytes, file, &mut references);
        collect_imports(&root, bytes, file, &mut references, &module_id);
        collect_type_references(&root, &ts_language, bytes, file, &mut references)?;

        let scopes = collect_scopes(&root, source.len());
        attach_reference_scopes(&mut references, &scopes);
        let mut bindings = collect_bindings(&root, bytes, &scopes);
        bindings.extend(def_bindings);
        bindings.extend(import_bindings(&references, &scopes));

        Ok(FileFacts {
            file: file.to_owned(),
            lang: Language::Rust.as_str().to_owned(),
            symbols,
            references,
            scopes,
            bindings,
            ffi_exports,
        })
    }
}

/// Derive the Rust module path (namespace descriptors) from a file path.
fn rust_namespaces(file: &str) -> Vec<String> {
    let p = file.strip_suffix(".rs").unwrap_or(file);
    let p = p.strip_prefix("src/").unwrap_or(p);
    let mut segs: Vec<String> = p
        .split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    if let Some(last) = segs.last() {
        if matches!(last.as_str(), "mod" | "lib" | "main") {
            segs.pop();
        }
    }
    segs
}

fn collect_symbols(root: &Node, bytes: &[u8], file: &str, namespaces: &[String]) -> Vec<Symbol> {
    let mut out = Vec::new();
    for child in root.children(&mut root.walk()) {
        let (kind, leaf) = match child.kind() {
            "function_item" if is_fully_pub(&child, bytes) => {
                let Some(name) = child_text(&child, "identifier", bytes) else {
                    continue;
                };
                (
                    SymbolKind::Function,
                    Descriptor::Method {
                        name: name.clone(),
                        disambiguator: String::new(),
                    },
                )
            }
            "struct_item" if is_fully_pub(&child, bytes) => {
                let Some(name) = child_text(&child, "type_identifier", bytes) else {
                    continue;
                };
                (SymbolKind::Struct, Descriptor::Type(name))
            }
            "enum_item" if is_fully_pub(&child, bytes) => {
                let Some(name) = child_text(&child, "type_identifier", bytes) else {
                    continue;
                };
                (SymbolKind::Enum, Descriptor::Type(name))
            }
            "trait_item" if is_fully_pub(&child, bytes) => {
                let Some(name) = child_text(&child, "type_identifier", bytes) else {
                    continue;
                };
                (SymbolKind::Trait, Descriptor::Type(name))
            }
            "type_item" if is_fully_pub(&child, bytes) => {
                let Some(name) = child_text(&child, "type_identifier", bytes) else {
                    continue;
                };
                (SymbolKind::TypeAlias, Descriptor::Type(name))
            }
            "const_item" if is_fully_pub(&child, bytes) => {
                let Some(name) = child_text(&child, "identifier", bytes) else {
                    continue;
                };
                (SymbolKind::Const, Descriptor::Term(name))
            }
            "static_item" if is_fully_pub(&child, bytes) => {
                let Some(name) = child_text(&child, "identifier", bytes) else {
                    continue;
                };
                (SymbolKind::Static, Descriptor::Term(name))
            }
            "mod_item" if is_fully_pub(&child, bytes) => {
                let Some(name) = child_text(&child, "identifier", bytes) else {
                    continue;
                };
                (SymbolKind::Module, Descriptor::Namespace(name))
            }
            "impl_item" => {
                let name = impl_type_name(&child, bytes);
                (SymbolKind::Impl, Descriptor::Type(name))
            }
            _ => continue,
        };

        let mut descriptors: Vec<Descriptor> = namespaces
            .iter()
            .cloned()
            .map(Descriptor::Namespace)
            .collect();
        descriptors.push(leaf.clone());

        out.push(Symbol {
            id: SymbolId::global(Language::Rust.as_str(), descriptors),
            name: leaf.name().to_owned(),
            kind,
            file: file.to_owned(),
            line: (child.start_position().row + 1) as u32,
            span: ByteSpan {
                start: child.start_byte(),
                end: child.end_byte(),
            },
            signature: one_line_signature(node_text(&child, bytes), &['{']),
        });
    }
    out
}

/// True if the node's first `visibility_modifier` child is bare `pub`.
fn is_fully_pub(node: &Node, bytes: &[u8]) -> bool {
    node.children(&mut node.walk())
        .find(|c| c.kind() == "visibility_modifier")
        .map(|c| node_text(&c, bytes).trim() == "pub")
        .unwrap_or(false)
}

/// Collect cross-language export markers from top-level functions.
///
/// Detected today:
/// - **C ABI** — `#[no_mangle]` / `#[unsafe(no_mangle)]` (exported under the
///   function name) and `#[export_name = "…"]` (name override). A plain
///   `extern "C"` *without* such a marker is mangled and intentionally not an
///   export.
/// - **Python ABI** — PyO3 `#[pyfunction]` (exported under the function name, or
///   a `#[pyo3(name = "…")]` / `#[pyfunction(name = "…")]` override).
///
/// Only functions extracted as symbols (the public ones) are bridged; each
/// export is matched to its symbol by definition span, so the SCIP identity is
/// exactly the one the resolver will see. A function may export under more than
/// one ABI.
fn collect_ffi_exports(root: &Node, bytes: &[u8], defs: &[Symbol]) -> Vec<FfiExport> {
    let mut out = Vec::new();
    for child in root.children(&mut root.walk()) {
        if child.kind() != "function_item" {
            continue;
        }
        let Some(sym) = defs
            .iter()
            .find(|s| s.kind == SymbolKind::Function && s.span.start == child.start_byte())
        else {
            continue; // not a (public) extracted symbol — no identity to bridge
        };
        for (abi, export_name) in fn_ffi_exports(&child, bytes, &sym.name) {
            out.push(FfiExport {
                symbol: sym.id.clone(),
                abi,
                export_name,
            });
        }
    }
    out
}

/// The FFI exports a function declares, derived from its attributes.
///
/// In tree-sitter-rust an item's outer attributes are its **preceding siblings**
/// (not children), so we walk back over the run of `attribute_item` nodes.
/// Detection reads attribute text, so it is robust to spelling variants
/// (`#[no_mangle]` vs `#[unsafe(no_mangle)]`).
fn fn_ffi_exports(func: &Node, bytes: &[u8], fn_name: &str) -> Vec<(FfiAbi, String)> {
    let mut c_no_mangle = false;
    let mut c_override: Option<String> = None;
    let mut py = false;
    let mut py_override: Option<String> = None;

    let mut sib = func.prev_sibling();
    while let Some(node) = sib {
        if node.kind() != "attribute_item" {
            break;
        }
        let text = node_text(&node, bytes);
        // C ABI markers.
        if text.contains("export_name") {
            c_override = first_quoted(text).map(str::to_owned);
        } else if text.contains("no_mangle") {
            c_no_mangle = true;
        }
        // Python (PyO3) markers — independent of the C markers above.
        if text.contains("pyfunction") {
            py = true;
            if let Some(v) = first_quoted(text) {
                py_override = Some(v.to_owned()); // `#[pyfunction(name = "…")]`
            }
        } else if text.contains("pyo3") {
            if let Some(v) = first_quoted(text) {
                py_override = Some(v.to_owned()); // `#[pyo3(name = "…")]`
            }
        }
        sib = node.prev_sibling();
    }

    let mut out = Vec::new();
    if let Some(name) = c_override {
        out.push((FfiAbi::C, name));
    } else if c_no_mangle {
        out.push((FfiAbi::C, fn_name.to_owned()));
    }
    if py {
        out.push((
            FfiAbi::Python,
            py_override.unwrap_or_else(|| fn_name.to_owned()),
        ));
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

/// Display name for an `impl` block: the last type identifier before the body.
fn impl_type_name(node: &Node, bytes: &[u8]) -> String {
    let mut names = Vec::new();
    for child in node.children(&mut node.walk()) {
        match child.kind() {
            "type_identifier" | "generic_type" | "scoped_type_identifier" => {
                names.push(node_text(&child, bytes).to_owned());
            }
            "declaration_list" => break,
            _ => {}
        }
    }
    names.last().cloned().unwrap_or_else(|| "impl".to_owned())
}

/// Recursively walk `node` collecting `Inherit` references for every
/// `impl_item` (trait implementation) and `trait_item` (supertrait bound) in
/// the tree (including items inside `mod` blocks).
fn collect_inheritance(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    match node.kind() {
        "impl_item" => {
            // Only trait impls have a `trait` field; inherent impls do not.
            if let Some(trait_node) = node.child_by_field_name("trait") {
                super::push_ref(
                    out,
                    super::simple_type_name(node_text(&trait_node, bytes), "::"),
                    &trait_node,
                    file,
                    RefRole::IsImplementation,
                );
            }
        }
        "trait_item" => {
            // `bounds` field is a `trait_bounds` node listing supertraits.
            if let Some(bounds) = node.child_by_field_name("bounds") {
                for child in bounds.children(&mut bounds.walk()) {
                    match child.kind() {
                        "type_identifier" | "generic_type" | "scoped_type_identifier" => {
                            super::push_ref(
                                out,
                                super::simple_type_name(node_text(&child, bytes), "::"),
                                &child,
                                file,
                                RefRole::IsImplementation,
                            );
                        }
                        _ => {}
                    }
                }
            }
        }
        _ => {}
    }

    // Recurse into all children so items inside `mod` blocks are covered.
    for child in node.children(&mut node.walk()) {
        collect_inheritance(&child, bytes, file, out);
    }
}

/// Recursively collect leaf import names from a use-tree node and push an
/// [`RefRole::Import`] reference for each one.
///
/// `prefix` is the accumulated path prefix from enclosing `scoped_use_list`
/// nodes (e.g. `"std::collections"` when processing the list in
/// `use std::collections::{HashMap, BTreeMap}`). It is threaded downward so
/// bare `identifier` leaves inside a `use_list` can report their `from_path`.
///
/// The leaf is always the concrete identifier being imported:
/// - `identifier`         → `from_path = prefix` (the received prefix).
/// - `scoped_identifier`  → `from_path` = its own `path` field (authoritative).
/// - `use_as_clause`      → recurse into the `path` field (alias ignored), passing `prefix` through.
/// - `scoped_use_list`    → compute `new_prefix` from the node's `path` field, then recurse into `list`.
/// - `use_list`           → recurse each named child, passing `prefix` through.
/// - `use_wildcard` / `crate` / `self` / `super` / anything else → skip.
fn collect_use_leaves(
    node: &Node,
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Reference>,
    module_id: &str,
    prefix: &str,
) {
    match node.kind() {
        "identifier" => {
            // Bare leaf inside a use_list — from_path is the enclosing prefix.
            super::push_import_ref(
                out,
                super::node_text(node, bytes),
                node,
                file,
                module_id,
                prefix,
            );
        }
        "scoped_identifier" => {
            // The node's `path` field is the authoritative from-path.
            let from_path = node
                .child_by_field_name("path")
                .map_or("", |n| super::node_text(&n, bytes));
            if let Some(name_node) = node.child_by_field_name("name") {
                super::push_import_ref(
                    out,
                    super::node_text(&name_node, bytes),
                    &name_node,
                    file,
                    module_id,
                    from_path,
                );
            }
        }
        "use_as_clause" => {
            // Alias is ignored; recurse into the path child, passing prefix through.
            if let Some(path_node) = node.child_by_field_name("path") {
                collect_use_leaves(&path_node, bytes, file, out, module_id, prefix);
            }
        }
        "scoped_use_list" => {
            // Compute a fresh prefix from this node's `path` field, then recurse
            // into the list with that prefix so bare identifiers inside the list
            // can report the correct from_path.
            let new_prefix = node
                .child_by_field_name("path")
                .map_or("", |n| super::node_text(&n, bytes));
            if let Some(list_node) = node.child_by_field_name("list") {
                collect_use_leaves(&list_node, bytes, file, out, module_id, new_prefix);
            }
        }
        "use_list" => {
            for child in node.named_children(&mut node.walk()) {
                collect_use_leaves(&child, bytes, file, out, module_id, prefix);
            }
        }
        // use_wildcard, crate, self, super, metavariable → skip
        _ => {}
    }
}

/// Walk the full tree and emit [`RefRole::Import`] references for every
/// `use_declaration`. Recurses into `mod` blocks and function bodies so nested
/// `use` items are also captured.
fn collect_imports(
    node: &Node,
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Reference>,
    module_id: &str,
) {
    if node.kind() == "use_declaration" {
        if let Some(arg) = node.child_by_field_name("argument") {
            collect_use_leaves(&arg, bytes, file, out, module_id, "");
        }
        // No need to recurse further inside a use_declaration.
        return;
    }
    for child in node.children(&mut node.walk()) {
        collect_imports(&child, bytes, file, out, module_id);
    }
}

// ── Type reference capture ────────────────────────────────────────────────────

/// Reduce a (possibly compound) type node to its base named type.
///
/// Returns `(bare_name, qualifier)` for the type forms we handle in v1.
/// Returns `None` for forms we defer (tuple, array, pointer, slice, fn pointer,
/// lifetime-only, etc.) — they produce no [`RefRole::TypeRef`] reference.
///
/// Recursion depth is bounded by type nesting depth (a handful of levels at
/// most); no panic paths, no `unwrap`.
///
/// **Primitive types are skipped** (`primitive_type` matches `None`): they
/// never resolve to a user-defined [`Symbol`], so capturing them adds noise
/// with zero benefit. E.g. `u32`, `bool`, `i64` produce no TypeRef ref.
fn base_type_name(node: &Node, bytes: &[u8]) -> Option<(String, Option<String>)> {
    match node.kind() {
        "type_identifier" => Some((node_text(node, bytes).to_owned(), None)),
        // Primitive types (u8, i32, bool, str, …) — skip to reduce noise.
        "primitive_type" => None,
        "scoped_type_identifier" => {
            // Grammar-verified fields: `name: type_identifier`, `path: ...`
            let name = node
                .child_by_field_name("name")
                .map(|n| node_text(&n, bytes).to_owned())?;
            let qual = node
                .child_by_field_name("path")
                .map(|n| node_text(&n, bytes).to_owned());
            Some((name, qual))
        }
        // Vec<Config> → base name "Vec"; the Config inside type_arguments is
        // deferred in v1 (not captured here).
        "generic_type" => node
            .child_by_field_name("type")
            .and_then(|t| base_type_name(&t, bytes)),
        // &Config / &mut Config → descend through the `type` field (grammar-verified).
        "reference_type" => node
            .child_by_field_name("type")
            .and_then(|t| base_type_name(&t, bytes)),
        // Defer: tuple_type, array_type, pointer_type, slice_type, abstract_type,
        // dynamic_type, fn types, macro_invocation types, etc.
        _ => None,
    }
}

/// Run [`TYPE_QUERY`] over the tree and push one [`RefRole::TypeRef`]
/// [`Reference`] per resolved base named type.
///
/// Mirrors [`collect_call_references`] in structure (Query + QueryCursor).
/// `primitive_type` nodes are deferred by [`base_type_name`] — they produce
/// no reference. All other unrecognised type forms (tuples, slices, …) are
/// also silently skipped per the v1 boundary.
fn collect_type_references(
    root: &Node,
    ts_lang: &TsLanguage,
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Reference>,
) -> Result<()> {
    let query = Query::new(ts_lang, TYPE_QUERY).map_err(|e| CodegraphError::Query {
        lang: "rust".to_owned(),
        msg: e.to_string(),
    })?;
    let ty_idx = query
        .capture_index_for_name("ty")
        .ok_or_else(|| CodegraphError::Query {
            lang: "rust".to_owned(),
            msg: "missing @ty capture".to_owned(),
        })?;

    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&query, *root, bytes);
    while let Some(m) = matches.next() {
        for cap in m.captures.iter().filter(|c| c.index == ty_idx) {
            if let Some((name, qualifier)) = base_type_name(&cap.node, bytes) {
                out.push(Reference {
                    name,
                    occ: node_occurrence(&cap.node, file),
                    role: RefRole::TypeRef,
                    source_module: None,
                    from_path: None,
                    qualifier,
                    scope: None, // filled in by attach_reference_scopes
                });
            }
        }
    }
    Ok(())
}

// ── Scope tree ───────────────────────────────────────────────────────────────

/// Append a new scope to `scopes` and return its [`ScopeId`].
fn push_scope(
    scopes: &mut Vec<Scope>,
    parent: Option<ScopeId>,
    span: ByteSpan,
    kind: ScopeKind,
) -> ScopeId {
    let id = scopes.len();
    scopes.push(Scope { parent, span, kind });
    id
}

/// `ByteSpan` covering the whole extent of `node`.
fn node_span(node: &Node) -> ByteSpan {
    ByteSpan {
        start: node.start_byte(),
        end: node.end_byte(),
    }
}

/// DFS that builds the scope tree for one file.
///
/// The file-root scope (`scopes[0]`) must already be pushed before calling
/// this for the root node's children. `scope_dfs` is called once per node:
/// it inspects `node`'s own kind, opens a new scope for `node` when
/// appropriate, and then recurses into whichever children carry nested scopes.
///
/// `parent_id` is the [`ScopeId`] of the innermost scope already open when
/// this node is visited; new scopes opened for `node` itself use it as their
/// parent.
fn scope_dfs(node: &Node, parent_id: ScopeId, scopes: &mut Vec<Scope>) {
    match node.kind() {
        "function_item" | "closure_expression" => {
            let fn_id = push_scope(
                scopes,
                Some(parent_id),
                node_span(node),
                ScopeKind::Function,
            );
            // Recurse into body's children to avoid double-opening the block.
            if let Some(body) = node.child_by_field_name("body") {
                for child in body.children(&mut body.walk()) {
                    scope_dfs(&child, fn_id, scopes);
                }
            } else {
                for child in node.children(&mut node.walk()) {
                    scope_dfs(&child, fn_id, scopes);
                }
            }
        }
        "mod_item" | "impl_item" | "trait_item" | "struct_item" | "enum_item" => {
            if let Some(body) = node.child_by_field_name("body") {
                let kind = if node.kind() == "mod_item" {
                    ScopeKind::Module
                } else {
                    ScopeKind::Type
                };
                let body_id = push_scope(scopes, Some(parent_id), node_span(&body), kind);
                for child in body.children(&mut body.walk()) {
                    scope_dfs(&child, body_id, scopes);
                }
            } else {
                // No body (e.g. `mod foo;` declaration) — recurse with the same parent.
                for child in node.children(&mut node.walk()) {
                    scope_dfs(&child, parent_id, scopes);
                }
            }
        }
        "block" => {
            let block_id = push_scope(scopes, Some(parent_id), node_span(node), ScopeKind::Block);
            for child in node.children(&mut node.walk()) {
                scope_dfs(&child, block_id, scopes);
            }
        }
        // Macro bodies are not reliable AST — skip entirely.
        "macro_definition" | "macro_invocation" => {}
        // All other nodes: open no scope, recurse children with the same parent.
        _ => {
            for child in node.children(&mut node.walk()) {
                scope_dfs(&child, parent_id, scopes);
            }
        }
    }
}

/// Build and return the full lexical scope tree for `source_len` bytes.
///
/// `scopes[0]` is always the file-root `Module` scope spanning `[0, source_len)`.
fn collect_scopes(root: &Node, source_len: usize) -> Vec<Scope> {
    let mut scopes = Vec::new();
    // Push the file-root scope first (index 0).
    push_scope(
        &mut scopes,
        None,
        ByteSpan {
            start: 0,
            end: source_len,
        },
        ScopeKind::Module,
    );
    // DFS from each top-level child of source_file with parent = 0.
    for child in root.children(&mut root.walk()) {
        scope_dfs(&child, 0, &mut scopes);
    }
    scopes
}

/// Return the [`ScopeId`] of the innermost scope whose span contains `byte`.
///
/// Ties on span length resolve to the higher index: `collect_scopes` always
/// pushes a parent before its children, so the larger index is the more deeply
/// nested scope.  Returns `None` only when `scopes` is empty (which cannot
/// happen in practice because the file-root scope is always index 0).
fn innermost_scope(byte: usize, scopes: &[Scope]) -> Option<ScopeId> {
    scopes
        .iter()
        .enumerate()
        .filter(|(_, s)| s.span.contains(byte))
        .min_by_key(|(id, s)| (s.span.len(), std::cmp::Reverse(*id)))
        .map(|(id, _)| id)
}

/// Attach each reference to the innermost scope that contains its byte offset.
fn attach_reference_scopes(refs: &mut [Reference], scopes: &[Scope]) {
    for r in refs {
        r.scope = innermost_scope(r.occ.byte, scopes);
    }
}

/// Resolve the bare identifier node for a pattern, unwrapping one level of
/// `mut_pattern` or `ref_pattern` if necessary.
///
/// Returns `None` for destructuring patterns (`tuple_pattern`,
/// `tuple_struct_pattern`, `struct_pattern`, slice patterns, …).
///
/// # NOTE
/// Destructuring-pattern bindings (tuple, tuple-struct, struct, slice, or-
/// pattern branches, etc.) are a known gap — this unit handles only simple
/// identifiers and single-level `mut`/`ref` wrappers.  A later unit should
/// walk the pattern recursively and emit a `Binding` for each bound leaf name.
fn resolve_pattern_ident<'tree>(pattern: &Node<'tree>) -> Option<Node<'tree>> {
    match pattern.kind() {
        "identifier" => Some(*pattern),
        "mut_pattern" | "ref_pattern" => {
            // The inner pattern is a named child (no field name); find the
            // first child that is itself an identifier.
            pattern
                .named_children(&mut pattern.walk())
                .find(|c| c.kind() == "identifier")
        }
        // Destructuring patterns — not handled in this unit (see NOTE above).
        _ => None,
    }
}

/// Push a single [`Binding`] with `target = BindingTarget::Local`, computing
/// `scope` via [`innermost_scope`].
#[inline]
fn push_binding(
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

/// Walk `node` recursively, collecting parameter and local-variable [`Binding`]s.
///
/// Covers:
/// - `function_item` / `closure_expression` parameters: `parameter` children
///   of the `parameters`/`closure_parameters` node, plus `self_parameter`.
/// - `let_declaration` bindings: the `pattern` field.
///
/// All emitted bindings have `target = BindingTarget::Local`.
///
/// `intro` is always the start byte of the **identifier token** (the bound
/// name) — a neutral positional fact; visibility is the resolver's concern.
fn collect_bindings(root: &Node, bytes: &[u8], scopes: &[Scope]) -> Vec<Binding> {
    let mut out = Vec::new();
    collect_bindings_dfs(root, bytes, scopes, &mut out);
    out
}

fn collect_bindings_dfs(node: &Node, bytes: &[u8], scopes: &[Scope], out: &mut Vec<Binding>) {
    match node.kind() {
        "function_item" | "closure_expression" => {
            // Both node kinds expose their parameter list via the "parameters"
            // field (function_item → `parameters` node; closure_expression →
            // `closure_parameters` node).
            if let Some(params_node) = node.child_by_field_name("parameters") {
                collect_params(&params_node, bytes, scopes, out);
            }
            // Recurse into the body (and any other children).
            for child in node.children(&mut node.walk()) {
                collect_bindings_dfs(&child, bytes, scopes, out);
            }
        }
        "let_declaration" => {
            if let Some(pattern_node) = node.child_by_field_name("pattern") {
                if let Some(ident_node) = resolve_pattern_ident(&pattern_node) {
                    let intro = ident_node.start_byte();
                    let name = node_text(&ident_node, bytes).to_owned();
                    push_binding(out, name, intro, BindingKind::Local, scopes);
                }
                // NOTE: destructuring patterns (tuple, struct, slice, …) are
                // not handled in this unit — see `resolve_pattern_ident`.
            }
            // Recurse into children (e.g. the value expression may contain
            // closures with their own params).
            for child in node.children(&mut node.walk()) {
                collect_bindings_dfs(&child, bytes, scopes, out);
            }
        }
        _ => {
            for child in node.children(&mut node.walk()) {
                collect_bindings_dfs(&child, bytes, scopes, out);
            }
        }
    }
}

/// Emit a [`Binding`] for each parameter in a `parameters` or
/// `closure_parameters` node.
fn collect_params(params_node: &Node, bytes: &[u8], scopes: &[Scope], out: &mut Vec<Binding>) {
    for child in params_node.named_children(&mut params_node.walk()) {
        match child.kind() {
            "parameter" => {
                if let Some(pattern_node) = child.child_by_field_name("pattern") {
                    // `pattern` field can be `self` (the keyword node) or any `_pattern`.
                    if pattern_node.kind() == "self" {
                        // `fn f(self)` — typed self, no `&`.
                        let intro = pattern_node.start_byte();
                        push_binding(out, "self".to_owned(), intro, BindingKind::Param, scopes);
                    } else if let Some(ident_node) = resolve_pattern_ident(&pattern_node) {
                        let intro = ident_node.start_byte();
                        let name = node_text(&ident_node, bytes).to_owned();
                        push_binding(out, name, intro, BindingKind::Param, scopes);
                    }
                    // NOTE: destructuring patterns in params not handled — see
                    // `resolve_pattern_ident`.
                }
            }
            "self_parameter" => {
                // `&self`, `&mut self`, or `self` with a lifetime — the `self`
                // keyword is a named child (no field).
                if let Some(self_node) = child
                    .named_children(&mut child.walk())
                    .find(|c| c.kind() == "self")
                {
                    let intro = self_node.start_byte();
                    push_binding(out, "self".to_owned(), intro, BindingKind::Param, scopes);
                }
            }
            // Bare `identifier` directly inside `closure_parameters` (e.g.
            // `|x| …` where `x` has no explicit type annotation).
            "identifier" => {
                let intro = child.start_byte();
                let name = node_text(&child, bytes).to_owned();
                push_binding(out, name, intro, BindingKind::Param, scopes);
            }
            _ => {}
        }
    }
}

/// Emit a [`BindingKind::Definition`] binding for each top-level definition.
///
/// `collect_symbols` only captures top-level items, so each binds in the file
/// root scope (`scopes[0]`). Definitions nested in `mod`/`impl` blocks are not
/// yet captured as symbols, so they get no binding here — revisit when
/// nested-definition extraction lands.
fn definition_bindings(defs: &[Symbol]) -> Vec<Binding> {
    defs.iter()
        .map(|d| Binding {
            scope: 0, // top-level defs bind in the file root scope
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
/// unavailable). `scope` is resolved via [`innermost_scope`] on the reference's
/// byte offset, defaulting to the file root scope (0) when no scope contains it.
fn import_bindings(refs: &[Reference], scopes: &[Scope]) -> Vec<Binding> {
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
    use super::*;

    #[test]
    fn extracts_defs_with_scip_ids() {
        let src = r#"
pub fn validate_token(tok: &str) -> bool { helper() }
fn private_helper() {}
pub struct Config { pub value: u32 }
"#;
        let facts = RustExtractor.extract(src, "src/auth/session.rs").unwrap();
        let names: Vec<&str> = facts.symbols.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"validate_token"));
        assert!(names.contains(&"Config"));
        assert!(!names.contains(&"private_helper")); // not `pub`

        let vt = facts
            .symbols
            .iter()
            .find(|s| s.name == "validate_token")
            .unwrap();
        assert_eq!(
            vt.id.to_scip_string(),
            "codegraph . . . auth/session/validate_token()."
        );
        assert_eq!(vt.kind, SymbolKind::Function);
    }

    #[test]
    fn extracts_call_references() {
        let src = "pub fn main() { validate_token(\"t\"); helper(); }";
        let facts = RustExtractor.extract(src, "src/main.rs").unwrap();
        let names: Vec<&str> = facts.references.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"validate_token"));
        assert!(names.contains(&"helper"));
    }

    #[test]
    fn trait_impl_emits_inherit_ref_and_inherent_impl_does_not() {
        // Trait impl → one Inherit ref named "Display".
        let src_trait_impl = r#"
use std::fmt;
pub struct Point;
impl fmt::Display for Point {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { Ok(()) }
}
"#;
        let facts = RustExtractor
            .extract(src_trait_impl, "src/point.rs")
            .unwrap();
        let inherit_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            inherit_names.contains(&"Display"),
            "expected 'Display' in {inherit_names:?}"
        );

        // Inherent impl → no Inherit ref.
        let src_inherent = "pub struct Point; impl Point { pub fn new() -> Self { Point } }";
        let facts2 = RustExtractor.extract(src_inherent, "src/point.rs").unwrap();
        let inherit2: Vec<&str> = facts2
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            inherit2.is_empty(),
            "expected no Inherit refs, got {inherit2:?}"
        );
    }

    #[test]
    fn supertrait_bounds_emit_inherit_refs() {
        let src = "pub trait Foo: Bar + Baz {}";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let inherit_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            inherit_names.contains(&"Bar"),
            "expected 'Bar' in {inherit_names:?}"
        );
        assert!(
            inherit_names.contains(&"Baz"),
            "expected 'Baz' in {inherit_names:?}"
        );
    }

    #[test]
    fn scoped_trait_path_emits_leaf_name() {
        // `impl std::fmt::Display for Point {}` → leaf name "Display"
        let src = r#"
pub struct Point;
impl std::fmt::Display for Point {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { Ok(()) }
}
"#;
        let facts = RustExtractor.extract(src, "src/point.rs").unwrap();
        let inherit_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            inherit_names.contains(&"Display"),
            "expected 'Display' in {inherit_names:?}"
        );
    }

    // ── Import reference tests ────────────────────────────────────────────────

    #[test]
    fn import_scoped_identifier_emits_leaf() {
        // `use a::b::Config;` → one Import ref `Config`
        let src = "use a::b::Config;";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(
            import_names,
            vec!["Config"],
            "expected ['Config'], got {import_names:?}"
        );
    }

    #[test]
    fn import_use_list_emits_all_leaves() {
        // `use std::collections::{HashMap, HashSet};` → Import refs `HashMap` and `HashSet`
        let src = "use std::collections::{HashMap, HashSet};";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let mut import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        import_names.sort_unstable();
        assert_eq!(
            import_names,
            vec!["HashMap", "HashSet"],
            "expected ['HashMap', 'HashSet'], got {import_names:?}"
        );
    }

    #[test]
    fn import_use_as_clause_emits_real_leaf_not_alias() {
        // `use a::b as c;` → Import ref `b` (not `c`)
        let src = "use a::b as c;";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(
            import_names,
            vec!["b"],
            "expected ['b'], got {import_names:?}"
        );
    }

    #[test]
    fn import_wildcard_emits_nothing() {
        // `use a::*;` → NO Import refs
        let src = "use a::*;";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            import_names.is_empty(),
            "expected no Import refs, got {import_names:?}"
        );
    }

    #[test]
    fn import_simple_scoped_path_emits_leaf() {
        // `use std::io::Result;` → Import ref `Result`
        let src = "use std::io::Result;";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(
            import_names,
            vec!["Result"],
            "expected ['Result'], got {import_names:?}"
        );
    }

    #[test]
    fn import_refs_carry_source_module() {
        // `use std::io::Result;` in src/net/client.rs → Import ref carries
        // the module SCIP id of net/client.
        let src = "use std::io::Result;";
        let file = "src/net/client.rs";
        let facts = RustExtractor.extract(src, file).unwrap();

        let namespaces = rust_namespaces(file);
        let expected_module_id =
            crate::extract::module_symbol(Language::Rust, &namespaces, file, src.len())
                .id
                .to_scip_string();

        let import_refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .collect();
        assert!(!import_refs.is_empty(), "expected at least one Import ref");
        for r in &import_refs {
            assert_eq!(
                r.source_module,
                Some(expected_module_id.clone()),
                "Import ref '{}' should carry source_module = {:?}",
                r.name,
                expected_module_id
            );
        }
    }

    // --- from_path tests ---

    #[test]
    fn import_scoped_identifier_carries_from_path() {
        // `use std::io::Result;` → from_path == "std::io"
        let src = "use std::io::Result;";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let r = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Import && r.name == "Result")
            .expect("expected Import ref for 'Result'");
        assert_eq!(
            r.from_path,
            Some("std::io".to_owned()),
            "from_path should be 'std::io', got {:?}",
            r.from_path
        );
    }

    #[test]
    fn import_use_list_leaves_carry_prefix_as_from_path() {
        // `use std::collections::{HashMap, BTreeMap};`
        // Both leaf refs must have from_path == "std::collections".
        let src = "use std::collections::{HashMap, BTreeMap};";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let import_refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .collect();
        assert_eq!(
            import_refs.len(),
            2,
            "expected 2 Import refs, got {:?}",
            import_refs.iter().map(|r| &r.name).collect::<Vec<_>>()
        );
        for r in &import_refs {
            assert_eq!(
                r.from_path,
                Some("std::collections".to_owned()),
                "from_path for '{}' should be 'std::collections', got {:?}",
                r.name,
                r.from_path
            );
        }
    }

    // ── Scope tree tests ──────────────────────────────────────────────────────

    #[test]
    fn scope_fn_with_call_has_function_scope_and_ref_attaches_to_it() {
        // A function containing a call: assert root Module scope (index 0) and a
        // Function scope; the call reference's scope should be Some(fn_scope_id),
        // not Some(0) (the root).
        let src = "pub fn greet() { helper(); }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();

        // scopes[0] must be the file-root Module.
        assert!(!facts.scopes.is_empty(), "scopes must not be empty");
        assert_eq!(
            facts.scopes[0].kind,
            ScopeKind::Module,
            "scopes[0] must be Module"
        );
        assert_eq!(facts.scopes[0].parent, None, "root scope has no parent");

        // There must be at least one Function scope.
        let fn_scope_pos = facts
            .scopes
            .iter()
            .position(|s| s.kind == ScopeKind::Function)
            .expect("expected a Function scope");

        // The call reference to `helper` must be attributed to the Function scope,
        // not the root.
        let helper_ref = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Call && r.name == "helper")
            .expect("expected a Call ref for 'helper'");
        assert_eq!(
            helper_ref.scope,
            Some(fn_scope_pos),
            "helper call should be attributed to the Function scope ({}), got {:?}",
            fn_scope_pos,
            helper_ref.scope
        );
    }

    #[test]
    fn nested_block_scope_parent_chains_correctly() {
        // A function whose body contains an inner bare `{ }` block:
        //   fn outer() { { inner_call(); } }
        // Scopes expected: root Module (0), Function (1), Block (2).
        // A ref inside the block must attribute to the Block scope,
        // and the Block scope's parent must be the Function scope.
        let src = "fn outer() { { inner_call(); } }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();

        let fn_scope_id = facts
            .scopes
            .iter()
            .position(|s| s.kind == ScopeKind::Function)
            .expect("expected a Function scope");
        let block_scope_id = facts
            .scopes
            .iter()
            .position(|s| s.kind == ScopeKind::Block)
            .expect("expected a Block scope");

        // Block's parent must be the Function scope.
        assert_eq!(
            facts.scopes[block_scope_id].parent,
            Some(fn_scope_id),
            "Block scope parent should be the Function scope"
        );

        // The call ref inside the block must attribute to the Block scope (innermost).
        let inner_ref = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Call && r.name == "inner_call")
            .expect("expected a Call ref for 'inner_call'");
        assert_eq!(
            inner_ref.scope,
            Some(block_scope_id),
            "inner_call should attribute to the Block scope ({}), got {:?}",
            block_scope_id,
            inner_ref.scope
        );
    }

    #[test]
    fn empty_source_produces_exactly_one_root_scope() {
        // Empty source → collect_scopes returns exactly one scope (the file root),
        // does not panic.
        let ts_language = tree_sitter::Language::from(tree_sitter_rust::LANGUAGE);
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&ts_language).unwrap();
        let tree = parser.parse("", None).unwrap();
        let root = tree.root_node();

        let scopes = collect_scopes(&root, 0);
        assert_eq!(
            scopes.len(),
            1,
            "empty source should produce exactly one scope"
        );
        assert_eq!(scopes[0].kind, ScopeKind::Module);
        assert_eq!(scopes[0].parent, None);
    }

    // ── Binding tests ─────────────────────────────────────────────────────────

    #[test]
    fn fn_params_emit_param_bindings() {
        // `fn f(a: u32, b: u32) { }` → two Param bindings named `a` and `b`,
        // both attributed to the Function scope, both targeting Local.
        let src = "fn f(a: u32, b: u32) { }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();

        let fn_scope_id = facts
            .scopes
            .iter()
            .position(|s| s.kind == ScopeKind::Function)
            .expect("expected a Function scope");

        let mut param_names: Vec<(&str, ScopeId)> = facts
            .bindings
            .iter()
            .filter(|b| b.kind == BindingKind::Param)
            .map(|b| (b.name.as_str(), b.scope))
            .collect();
        param_names.sort_by_key(|(n, _)| *n);

        assert_eq!(
            param_names,
            vec![("a", fn_scope_id), ("b", fn_scope_id)],
            "expected Param bindings for a and b in the Function scope, got {param_names:?}"
        );
        for b in facts
            .bindings
            .iter()
            .filter(|b| b.kind == BindingKind::Param)
        {
            assert_eq!(
                b.target,
                BindingTarget::Local,
                "param binding target must be Local"
            );
        }
    }

    #[test]
    fn self_parameter_emits_param_binding() {
        // `impl S { fn m(&self) {} }` → a Param binding named `"self"`.
        let src = "pub struct S; impl S { fn m(&self) {} }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();

        let self_binding = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Param && b.name == "self")
            .expect("expected a Param binding named 'self'");
        assert_eq!(self_binding.target, BindingTarget::Local);
        // The scope must be a Function scope.
        assert_eq!(
            facts.scopes[self_binding.scope].kind,
            ScopeKind::Function,
            "self binding should be in a Function scope"
        );
    }

    #[test]
    fn let_binding_emits_local_binding() {
        // `fn f() { let x = 1; }` → a Local binding for `x` in the Function scope.
        let src = "fn f() { let x = 1; }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();

        let fn_scope_id = facts
            .scopes
            .iter()
            .position(|s| s.kind == ScopeKind::Function)
            .expect("expected a Function scope");

        let x_binding = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Local && b.name == "x")
            .expect("expected a Local binding for 'x'");

        assert_eq!(
            x_binding.scope, fn_scope_id,
            "x should be in the Function scope"
        );
        assert_eq!(x_binding.target, BindingTarget::Local);

        // intro must equal the start byte of the `x` identifier in the source.
        let expected_intro = src.find('x').expect("'x' not in src");
        assert_eq!(
            x_binding.intro, expected_intro,
            "intro should point at the 'x' token"
        );
    }

    #[test]
    fn shadowing_produces_two_local_bindings_with_different_intros() {
        // `fn f() { let x = 1; let x = 2; }` → two Local bindings both named
        // `x` with DIFFERENT intro offsets (the neutral fact enabling later
        // shadowing resolution).
        let src = "fn f() { let x = 1; let x = 2; }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();

        let x_bindings: Vec<_> = facts
            .bindings
            .iter()
            .filter(|b| b.kind == BindingKind::Local && b.name == "x")
            .collect();

        assert_eq!(
            x_bindings.len(),
            2,
            "expected exactly two Local bindings for 'x', got {}",
            x_bindings.len()
        );
        assert_ne!(
            x_bindings[0].intro, x_bindings[1].intro,
            "shadowed bindings must have different intro offsets"
        );
    }

    #[test]
    fn nested_block_let_binding_attributes_to_inner_block_scope() {
        // `fn f() { { let y = 1; } }` → the `y` Local binding's scope is the
        // inner Block scope, not the Function scope.
        let src = "fn f() { { let y = 1; } }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();

        let block_scope_id = facts
            .scopes
            .iter()
            .position(|s| s.kind == ScopeKind::Block)
            .expect("expected a Block scope");

        let y_binding = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Local && b.name == "y")
            .expect("expected a Local binding for 'y'");

        assert_eq!(
            y_binding.scope, block_scope_id,
            "y should be attributed to the inner Block scope ({}), got {}",
            block_scope_id, y_binding.scope
        );
    }

    #[test]
    fn impl_block_with_method_nests_type_then_function_scope() {
        // `impl Foo { fn bar() { call(); } }`
        // Expected nesting: root Module (0) → Type (impl body) → Function (method)
        // A call inside the method attributes to the Function scope (innermost).
        let src = "pub struct Foo; impl Foo { pub fn bar(&self) { call(); } }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();

        let type_scope_id = facts
            .scopes
            .iter()
            .position(|s| s.kind == ScopeKind::Type)
            .expect("expected a Type scope for the impl body");
        let fn_scope_id = facts
            .scopes
            .iter()
            .position(|s| s.kind == ScopeKind::Function)
            .expect("expected a Function scope for the method");

        // Type scope's parent must be the root (0).
        assert_eq!(
            facts.scopes[type_scope_id].parent,
            Some(0),
            "impl body Type scope parent should be root (0)"
        );
        // Function scope's parent must be the Type scope.
        assert_eq!(
            facts.scopes[fn_scope_id].parent,
            Some(type_scope_id),
            "method Function scope parent should be the Type scope"
        );

        // The call ref must attribute to the Function scope (innermost).
        let call_ref = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Call && r.name == "call")
            .expect("expected a Call ref for 'call'");
        assert_eq!(
            call_ref.scope,
            Some(fn_scope_id),
            "call() should attribute to the Function scope ({}), got {:?}",
            fn_scope_id,
            call_ref.scope
        );
    }

    // ── Definition binding tests ──────────────────────────────────────────────

    #[test]
    fn pub_fn_emits_definition_binding() {
        // `pub fn foo() {}` → a Definition binding: name "foo", scope 0,
        // kind Definition, target Def(_).
        let src = "pub fn foo() {}";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();

        let b = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Definition && b.name == "foo")
            .expect("expected a Definition binding named 'foo'");
        assert_eq!(b.scope, 0, "top-level def must bind in scope 0");
        assert!(
            matches!(b.target, BindingTarget::Def(_)),
            "Definition binding target must be Def(_), got {:?}",
            b.target
        );
    }

    #[test]
    fn pub_struct_emits_definition_binding_in_root_scope() {
        // `pub struct Bar {}` → a Definition binding named "Bar" in scope 0
        // (not in the struct body's Type scope).
        let src = "pub struct Bar {}";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();

        let b = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Definition && b.name == "Bar")
            .expect("expected a Definition binding named 'Bar'");
        assert_eq!(b.scope, 0, "struct def must bind in root scope 0");
        assert!(
            matches!(b.target, BindingTarget::Def(_)),
            "Definition binding target must be Def(_)"
        );
    }

    #[test]
    fn use_stmt_emits_import_binding() {
        // `use std::io::Result;` → an Import binding: name "Result",
        // kind Import, target Import("std::io").
        let src = "use std::io::Result;";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();

        let b = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Import && b.name == "Result")
            .expect("expected an Import binding named 'Result'");
        assert_eq!(
            b.target,
            BindingTarget::Import("std::io".to_owned()),
            "import binding target should be Import(\"std::io\"), got {:?}",
            b.target
        );
    }

    #[test]
    fn module_file_symbol_does_not_produce_definition_binding() {
        // The synthetic module symbol pushed last in `extract` must NOT get a
        // Definition binding. Here we have exactly one real top-level def
        // (`pub fn foo`), so there must be exactly one Definition binding and
        // its name must be "foo", not the file-stem "lib".
        let src = "pub fn foo() {}";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();

        let def_bindings: Vec<_> = facts
            .bindings
            .iter()
            .filter(|b| b.kind == BindingKind::Definition)
            .collect();
        assert_eq!(
            def_bindings.len(),
            1,
            "expected exactly one Definition binding, got {}: {:?}",
            def_bindings.len(),
            def_bindings.iter().map(|b| &b.name).collect::<Vec<_>>()
        );
        assert_eq!(
            def_bindings[0].name, "foo",
            "the sole Definition binding must be 'foo', not the module stem"
        );
    }

    // ── qualifier capture tests (unit 8a) ────────────────────────────────────

    #[test]
    fn qualified_call_single_segment_captures_qualifier() {
        // `mod_a::process()` → leaf "process", qualifier Some("mod_a")
        let src = "pub fn caller() { mod_a::process(); }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let r = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Call && r.name == "process")
            .expect("expected a Call ref for 'process'");
        assert_eq!(
            r.qualifier,
            Some("mod_a".to_owned()),
            "qualifier should be 'mod_a', got {:?}",
            r.qualifier
        );
    }

    #[test]
    fn qualified_call_nested_segments_captures_full_qualifier() {
        // `a::b::process()` → leaf "process", qualifier Some("a::b")
        let src = "pub fn caller() { a::b::process(); }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let r = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Call && r.name == "process")
            .expect("expected a Call ref for 'process'");
        assert_eq!(
            r.qualifier,
            Some("a::b".to_owned()),
            "qualifier should be 'a::b', got {:?}",
            r.qualifier
        );
    }

    #[test]
    fn unqualified_call_has_no_qualifier() {
        // `helper()` → qualifier None
        let src = "pub fn caller() { helper(); }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let r = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Call && r.name == "helper")
            .expect("expected a Call ref for 'helper'");
        assert_eq!(
            r.qualifier, None,
            "unqualified call should have qualifier == None, got {:?}",
            r.qualifier
        );
    }

    #[test]
    fn method_call_via_field_expression_has_no_qualifier() {
        // `obj.method()` — field_expression arm → leaf "method", qualifier None
        // (obj is the receiver, not a qualifier)
        let src = "pub fn caller(obj: Foo) { obj.method(); }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let r = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Call && r.name == "method")
            .expect("expected a Call ref for 'method'");
        assert_eq!(
            r.qualifier, None,
            "method call via field_expression should have qualifier == None, got {:?}",
            r.qualifier
        );
    }

    #[test]
    fn combined_def_and_use_emit_both_kinds_and_locals_still_work() {
        // A file with a top-level def + a `use` + a local let:
        // → a Definition binding for `foo`
        // → an Import binding for `Result`
        // → a Param binding (from prior unit) for the function param
        // → a Local binding for the let variable
        let src = "use std::io::Result;\npub fn foo(x: u32) { let y = 1; }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();

        // Definition binding present.
        assert!(
            facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Definition && b.name == "foo"),
            "expected a Definition binding for 'foo'"
        );
        // Import binding present.
        assert!(
            facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Import && b.name == "Result"),
            "expected an Import binding for 'Result'"
        );
        // Param binding from prior unit still works.
        assert!(
            facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Param && b.name == "x"),
            "expected a Param binding for 'x' (regression check)"
        );
        // Local binding from prior unit still works.
        assert!(
            facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Local && b.name == "y"),
            "expected a Local binding for 'y' (regression check)"
        );
    }

    // ── TypeRef tests ─────────────────────────────────────────────────────────

    fn type_refs(facts: &crate::graph::FileFacts) -> Vec<&Reference> {
        facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::TypeRef)
            .collect()
    }

    #[test]
    fn typeref_param_and_return_types_captured() {
        // `fn validate(cfg: Config) -> Outcome {}` → TypeRef refs for `Config` (param)
        // and `Outcome` (return type).
        let src = "fn validate(cfg: Config) -> Outcome {}";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let names: Vec<&str> = type_refs(&facts).iter().map(|r| r.name.as_str()).collect();
        assert!(
            names.contains(&"Config"),
            "expected TypeRef for 'Config' in {names:?}"
        );
        assert!(
            names.contains(&"Outcome"),
            "expected TypeRef for 'Outcome' in {names:?}"
        );
        for r in type_refs(&facts) {
            assert_eq!(
                r.role,
                RefRole::TypeRef,
                "role should be TypeRef, got {:?}",
                r.role
            );
        }
    }

    #[test]
    fn typeref_struct_field_type_captured() {
        // `struct Holder { item: Widget }` → TypeRef ref named `Widget`.
        let src = "struct Holder { item: Widget }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let names: Vec<&str> = type_refs(&facts).iter().map(|r| r.name.as_str()).collect();
        assert!(
            names.contains(&"Widget"),
            "expected TypeRef for 'Widget' in {names:?}"
        );
    }

    #[test]
    fn typeref_generic_base_type_captured_inner_deferred() {
        // `fn f(v: Vec<Config>) {}` → TypeRef ref for `Vec` (the base generic type).
        // `Config` inside the type_arguments is NOT captured (v1 boundary).
        let src = "fn f(v: Vec<Config>) {}";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let names: Vec<&str> = type_refs(&facts).iter().map(|r| r.name.as_str()).collect();
        assert!(
            names.contains(&"Vec"),
            "expected TypeRef for 'Vec' (base generic) in {names:?}"
        );
        assert!(
            !names.contains(&"Config"),
            "Config inside generic args should NOT be captured in v1 (got {names:?})"
        );
    }

    #[test]
    fn typeref_scoped_type_emits_leaf_and_qualifier() {
        // `fn f(r: std::io::Result) {}` → TypeRef ref `name == "Result"`,
        // `qualifier == Some("std::io")`.
        let src = "fn f(r: std::io::Result) {}";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let r = type_refs(&facts)
            .into_iter()
            .find(|r| r.name == "Result")
            .expect("expected a TypeRef ref named 'Result'");
        assert_eq!(
            r.qualifier,
            Some("std::io".to_owned()),
            "qualifier should be 'std::io', got {:?}",
            r.qualifier
        );
    }

    #[test]
    fn typeref_reference_type_descends_through_borrow() {
        // `fn f(c: &Config) {}` → TypeRef ref named `Config` (descended through `&`).
        let src = "fn f(c: &Config) {}";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let names: Vec<&str> = type_refs(&facts).iter().map(|r| r.name.as_str()).collect();
        assert!(
            names.contains(&"Config"),
            "expected TypeRef for 'Config' through '&' in {names:?}"
        );
    }

    #[test]
    fn typeref_primitive_type_not_captured() {
        // Primitives (u32, bool, i64, …) are skipped — they never resolve to a
        // user-defined Symbol, so capturing them only adds noise.
        let src = "fn f(n: u32, b: bool) -> i64 { 0 }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let names: Vec<&str> = type_refs(&facts).iter().map(|r| r.name.as_str()).collect();
        assert!(
            !names.contains(&"u32"),
            "primitive 'u32' should NOT be captured as TypeRef (got {names:?})"
        );
        assert!(
            !names.contains(&"bool"),
            "primitive 'bool' should NOT be captured as TypeRef (got {names:?})"
        );
        assert!(
            !names.contains(&"i64"),
            "primitive 'i64' should NOT be captured as TypeRef (got {names:?})"
        );
    }

    #[test]
    fn typeref_empty_fn_no_types_emits_no_typeref() {
        // `fn f() {}` with no type annotations → zero TypeRef refs.
        let src = "fn f() {}";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let trefs = type_refs(&facts);
        assert!(
            trefs.is_empty(),
            "fn with no types should produce no TypeRef refs, got {:?}",
            trefs.iter().map(|r| &r.name).collect::<Vec<_>>()
        );
    }
}
