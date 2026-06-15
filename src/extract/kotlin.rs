// SPDX-License-Identifier: Apache-2.0

//! Kotlin extractor — one tree-sitter pass yielding definitions and references.
//!
//! Definitions: declarations whose visibility is not `private`. Qualified
//! identity follows the `package_header` declaration, falling back to a
//! path-derived namespace when none is present.
//!
//! Covered declaration kinds:
//! - `class_declaration` (class/data class/sealed class/annotation class → Class;
//!   with `enum_class_body` → Enum; with `interface` keyword → Interface)
//! - `object_declaration` (singleton object → Class)
//! - `companion_object` (companion object → Class, nested under outer type)
//! - `function_declaration` (top-level → Function; inside type body → Method)
//! - `property_declaration` (`val` → Const, `var` → Static)
//! - `type_alias` (TypeAlias; name from the `type` field)
//! - `enum_entry` (inside `enum_class_body` → Const)
//! - `secondary_constructor` (inside class body → Method with name "constructor")
//!
//! Skipped in v0: `primary_constructor` (implicitly part of the class signature),
//! `anonymous_initializer` (no logical name).
//!
//! References: callee identifiers captured by two call patterns:
//! - free call `foo()` → `(call_expression (identifier) @callee)`
//! - member call `x.foo()` → `(call_expression (navigation_expression (identifier) @callee))`
//!
//! Emits neutral [`FileFacts`] — no storage entries, no source bodies.

use tree_sitter::{Language as TsLanguage, Node, Parser};

use crate::error::{CodegraphError, Result};
use crate::graph::types::{
    Binding, BindingKind, ByteSpan, FileFacts, RefRole, Reference, Scope, ScopeId, ScopeKind,
    Symbol, SymbolKind,
};
use crate::lang::Language;
use crate::symbol::{Descriptor, SymbolId};

use super::{
    Extractor, MIN_REF_LEN, attach_reference_scopes, child_text, collect_call_references,
    definition_bindings, field_text, import_bindings, innermost_scope, node_span, node_text,
    one_line_signature, push_binding, push_ref, push_scope,
};

/// Tree-sitter query capturing call-callee identifiers.
///
/// Pattern 1: free call `foo()` — identifier is a direct child of call_expression.
/// Pattern 2: member call `x.foo()` — navigation_expression inside call_expression
///            has an identifier child that is the callee.
const CALL_QUERY: &str = r#"
[
  (call_expression (identifier) @callee)
  (call_expression (navigation_expression (identifier) @callee))
]
"#;

/// Extracts Kotlin symbols and references.
pub struct KotlinExtractor;

impl Extractor for KotlinExtractor {
    fn lang(&self) -> Language {
        Language::Kotlin
    }

    fn extract(&self, source: &str, file: &str) -> Result<FileFacts> {
        let ts_language = TsLanguage::from(tree_sitter_kotlin_ng::LANGUAGE);
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
        let ns_strings = kotlin_namespaces(&root, bytes, file);
        let ns_descriptors: Vec<Descriptor> = ns_strings
            .iter()
            .cloned()
            .map(Descriptor::Namespace)
            .collect();

        let mut defs = Vec::new();
        collect_decls(root, &ns_descriptors, false, bytes, file, &mut defs);
        let def_bindings = definition_bindings(&defs);
        let mut symbols = defs;
        symbols.push(super::module_symbol(
            Language::Kotlin,
            &ns_strings,
            file,
            source.len(),
        ));

        let mut references = collect_call_references(
            &root,
            &ts_language,
            CALL_QUERY,
            Language::Kotlin,
            bytes,
            file,
        )?;
        collect_inheritance(&root, bytes, file, &mut references);
        collect_imports(&root, bytes, file, &mut references);
        collect_read_references(&root, bytes, file, &mut references);
        collect_write_references(&root, bytes, file, &mut references);

        let scopes = collect_scopes(&root, source.len());
        attach_reference_scopes(&mut references, &scopes);
        let mut bindings = collect_bindings(&root, bytes, &scopes);
        bindings.extend(def_bindings);
        bindings.extend(import_bindings(&references, &scopes));

        Ok(FileFacts {
            file: file.to_owned(),
            lang: Language::Kotlin.as_str().to_owned(),
            symbols,
            references,
            scopes,
            bindings,
            ffi_exports: Vec::new(),
        })
    }
}

// ── Namespace derivation ─────────────────────────────────────────────────────

/// Namespace descriptors for a Kotlin source file.
///
/// If a `package_header` is present, its `qualified_identifier` text is split on
/// `.` → e.g. `package com.example` → `["com", "example"]`.
///
/// Fallback (no package declaration): strip `.kt`/`.kts`, strip a leading
/// `src/`, split on `/` — e.g. `src/com/example/Auth.kt` →
/// `["com", "example", "Auth"]`.
fn kotlin_namespaces(root: &Node, bytes: &[u8], file: &str) -> Vec<String> {
    for child in root.children(&mut root.walk()) {
        if child.kind() != "package_header" {
            continue;
        }
        for pkg_child in child.children(&mut child.walk()) {
            if pkg_child.kind() == "qualified_identifier" || pkg_child.kind() == "identifier" {
                let text = node_text(&pkg_child, bytes);
                return text
                    .split('.')
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect();
            }
        }
    }

    // Fallback: derive from path.
    let p = file
        .strip_suffix(".kts")
        .or_else(|| file.strip_suffix(".kt"))
        .unwrap_or(file);
    let p = p.strip_prefix("src/").unwrap_or(p);
    p.split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

// ── Visibility gate ──────────────────────────────────────────────────────────

/// Returns `true` if a declaration should be emitted (not `private`).
///
/// Scans the `modifiers` child for a `visibility_modifier`. If the modifier text
/// is `"private"` the symbol is suppressed; everything else (public, internal,
/// protected, or no modifier at all → implicit public/internal) is emitted.
/// Recall-first, matches the project stance.
fn is_visible(node: &Node, bytes: &[u8]) -> bool {
    for child in node.children(&mut node.walk()) {
        if child.kind() != "modifiers" {
            continue;
        }
        for modifier in child.children(&mut child.walk()) {
            if modifier.kind() == "visibility_modifier" {
                return node_text(&modifier, bytes) != "private";
            }
        }
        // modifiers node present but no visibility_modifier → implicit → emit
        return true;
    }
    // No modifiers node → implicit → emit
    true
}

// ── Symbol builder ───────────────────────────────────────────────────────────

/// Build a [`Symbol`] and push it onto `out`.
fn push_symbol(
    out: &mut Vec<Symbol>,
    node: &Node,
    name: String,
    kind: SymbolKind,
    descriptors: Vec<Descriptor>,
    bytes: &[u8],
    file: &str,
) {
    out.push(Symbol {
        id: SymbolId::global(Language::Kotlin.as_str(), descriptors),
        name,
        kind,
        file: file.to_owned(),
        line: (node.start_position().row + 1) as u32,
        span: ByteSpan {
            start: node.start_byte(),
            end: node.end_byte(),
        },
        signature: one_line_signature(node_text(node, bytes), &['{', '\n']),
    });
}

/// Emit a Type symbol for `type_name` and recurse into its body for members.
///
/// Shared tail of `handle_class`, `handle_object`, and `handle_companion`:
/// all three build the same `type_descriptors` vec, push the symbol, then
/// recurse into the body. Both `class_body` and `enum_class_body` are treated
/// as bodies — an `enum_class_body` only ever appears under a class, so checking
/// for it unconditionally is harmless for objects/companions.
fn emit_type_and_body(
    out: &mut Vec<Symbol>,
    node: Node,
    type_name: String,
    kind: SymbolKind,
    prefix: &[Descriptor],
    bytes: &[u8],
    file: &str,
) {
    let mut type_descriptors = prefix.to_vec();
    type_descriptors.push(Descriptor::Type(type_name.clone()));
    push_symbol(
        out,
        &node,
        type_name,
        kind,
        type_descriptors.clone(),
        bytes,
        file,
    );

    let mut body_cursor = node.walk();
    for body_child in node.children(&mut body_cursor) {
        if matches!(body_child.kind(), "class_body" | "enum_class_body") {
            collect_decls(body_child, &type_descriptors, true, bytes, file, out);
        }
    }
}

// ── Declaration collection ───────────────────────────────────────────────────

/// Collect definitions from a container node (source_file or a type body).
///
/// `prefix` is the descriptor list up to (but not including) the current level.
/// Top-level: prefix = package Namespace descriptors.
/// Type members: prefix = package Namespaces + Type(name).
/// `inside_type` drives Function vs Method for function_declaration.
fn collect_decls(
    container: Node,
    prefix: &[Descriptor],
    inside_type: bool,
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    let mut cursor = container.walk();
    for child in container.children(&mut cursor) {
        match child.kind() {
            "class_declaration" => handle_class(child, prefix, bytes, file, out),
            "object_declaration" => handle_object(child, prefix, bytes, file, out),
            "companion_object" => handle_companion(child, prefix, bytes, file, out),
            "function_declaration" => handle_function(child, prefix, inside_type, bytes, file, out),
            "property_declaration" => handle_property(child, prefix, bytes, file, out),
            "type_alias" => handle_typealias(child, prefix, bytes, file, out),
            "enum_entry" => handle_enum_entry(child, prefix, bytes, file, out),
            "secondary_constructor" => {
                handle_secondary_constructor(child, prefix, bytes, file, out)
            }
            _ => {}
        }
    }
}

/// Handle `class_declaration` — covers class/data class/sealed class/annotation
/// class (→ Class), interface (→ Interface), and enum class (→ Enum).
fn handle_class(
    node: Node,
    prefix: &[Descriptor],
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    if !is_visible(&node, bytes) {
        return;
    }
    let name_node = match node.child_by_field_name("name") {
        Some(n) => n,
        None => return,
    };
    let type_name = node_text(&name_node, bytes).to_owned();

    // Determine kind: enum_class_body → Enum; "interface" keyword before name → Interface; else Class.
    let sym_kind = if node
        .children(&mut node.walk())
        .any(|c| c.kind() == "enum_class_body")
    {
        SymbolKind::Enum
    } else {
        // Scan text from node start up to the name node start for "interface".
        let prefix_text = std::str::from_utf8(&bytes[node.start_byte()..name_node.start_byte()])
            .unwrap_or_default();
        if prefix_text.split_whitespace().any(|w| w == "interface") {
            SymbolKind::Interface
        } else {
            SymbolKind::Class
        }
    };

    emit_type_and_body(out, node, type_name, sym_kind, prefix, bytes, file);
}

/// Handle `object_declaration` (singleton object → SymbolKind::Class).
fn handle_object(
    node: Node,
    prefix: &[Descriptor],
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    if !is_visible(&node, bytes) {
        return;
    }
    let type_name = match field_text(&node, "name", bytes) {
        Some(n) => n,
        None => return,
    };

    emit_type_and_body(out, node, type_name, SymbolKind::Class, prefix, bytes, file);
}

/// Handle `companion_object` (nested companion → SymbolKind::Class).
///
/// The `name` field may be absent (anonymous `companion object`); in that case
/// the conventional name "Companion" is used.
fn handle_companion(
    node: Node,
    prefix: &[Descriptor],
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    if !is_visible(&node, bytes) {
        return;
    }
    let type_name = field_text(&node, "name", bytes).unwrap_or_else(|| "Companion".to_owned());

    emit_type_and_body(out, node, type_name, SymbolKind::Class, prefix, bytes, file);
}

/// Handle `function_declaration`.
///
/// `inside_type` → SymbolKind::Method; otherwise SymbolKind::Function.
fn handle_function(
    node: Node,
    prefix: &[Descriptor],
    inside_type: bool,
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    if !is_visible(&node, bytes) {
        return;
    }
    let name = match field_text(&node, "name", bytes) {
        Some(n) => n,
        None => return,
    };
    let kind = if inside_type {
        SymbolKind::Method
    } else {
        SymbolKind::Function
    };
    let mut descriptors = prefix.to_vec();
    descriptors.push(Descriptor::Method {
        name: name.clone(),
        disambiguator: String::new(),
    });
    push_symbol(out, &node, name, kind, descriptors, bytes, file);
}

/// Handle `property_declaration`.
///
/// The name lives inside a `variable_declaration` child (→ its `identifier`
/// child). `val` → Const; `var` → Static. Multi-variable destructuring
/// (`multi_variable_declaration`) is skipped gracefully.
fn handle_property(
    node: Node,
    prefix: &[Descriptor],
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    if !is_visible(&node, bytes) {
        return;
    }

    // Find name from variable_declaration → identifier.
    let var_name: Option<String> = {
        let mut found = None;
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "variable_declaration" {
                // identifier is a direct child of variable_declaration
                let mut vc = child.walk();
                for vc_child in child.children(&mut vc) {
                    if vc_child.kind() == "identifier" {
                        found = Some(node_text(&vc_child, bytes).to_owned());
                        break;
                    }
                }
                break;
            }
            // multi_variable_declaration → skip
            if child.kind() == "multi_variable_declaration" {
                return;
            }
        }
        found
    };
    let var_name = match var_name {
        Some(n) => n,
        None => return,
    };

    // val vs var: scan anonymous token children for kind "var".
    let is_var = node.children(&mut node.walk()).any(|c| c.kind() == "var");
    let kind = if is_var {
        SymbolKind::Static
    } else {
        SymbolKind::Const
    };

    let mut descriptors = prefix.to_vec();
    descriptors.push(Descriptor::Term(var_name.clone()));
    push_symbol(out, &node, var_name, kind, descriptors, bytes, file);
}

/// Handle `type_alias`.
///
/// The alias name is in the `type` field (grammar quirk).
fn handle_typealias(
    node: Node,
    prefix: &[Descriptor],
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    if !is_visible(&node, bytes) {
        return;
    }
    let name = match field_text(&node, "type", bytes) {
        Some(n) => n,
        None => return,
    };
    let mut descriptors = prefix.to_vec();
    descriptors.push(Descriptor::Type(name.clone()));
    push_symbol(
        out,
        &node,
        name,
        SymbolKind::TypeAlias,
        descriptors,
        bytes,
        file,
    );
}

/// Handle `enum_entry` (cases inside `enum_class_body`).
///
/// The entry name is in an `identifier` child.
fn handle_enum_entry(
    node: Node,
    prefix: &[Descriptor],
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    if !is_visible(&node, bytes) {
        return;
    }
    // enum_entry has an identifier child (the case name).
    let name = match child_text(&node, "identifier", bytes) {
        Some(n) => n,
        None => return,
    };
    let mut descriptors = prefix.to_vec();
    descriptors.push(Descriptor::Term(name.clone()));
    push_symbol(
        out,
        &node,
        name,
        SymbolKind::Const,
        descriptors,
        bytes,
        file,
    );
}

/// Handle `secondary_constructor` inside a class body.
///
/// Emitted as `Method { name: "constructor", disambiguator: "" }`.
fn handle_secondary_constructor(
    node: Node,
    prefix: &[Descriptor],
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    if !is_visible(&node, bytes) {
        return;
    }
    let mut descriptors = prefix.to_vec();
    descriptors.push(Descriptor::Method {
        name: "constructor".to_owned(),
        disambiguator: String::new(),
    });
    push_symbol(
        out,
        &node,
        "constructor".to_owned(),
        SymbolKind::Method,
        descriptors,
        bytes,
        file,
    );
}

// ── Edge richness: Read / Write ──────────────────────────────────────────────

/// Returns `true` when `node` (an `identifier`) is in a Kotlin position that is
/// already captured by another collector and must NOT also be emitted as a Read.
///
/// Skipped positions:
/// - Free call callee: an `identifier` that is a direct child of `call_expression`
///   before the `value_arguments` node — already [`RefRole::Call`].
/// - Member call callee: an `identifier` that is the last named child of a
///   `navigation_expression` inside a `call_expression` — already [`RefRole::Call`].
///   The receiver identifier (the first in the pair) is NOT skipped.
/// - Member access name (non-call): the last `identifier` child of
///   `navigation_expression` — it is the member name (`foo` in `obj.foo`), not a
///   local variable read. The receiver is kept as a Read.
/// - Declaration names: `function_declaration`, `class_declaration`,
///   `object_declaration`, `companion_object` → their `name:` field identifier.
/// - Variable binding: `variable_declaration` child identifier (the bound name in
///   `val x`, `var x`, loop variable, lambda param).
/// - Parameter name: `identifier` child of `parameter` (the first child).
/// - Import path: inside an `import` node — already [`RefRole::Import`].
/// - Type positions: `user_type` / `type` node descendants are distinct
///   `identifier` nodes inside type syntax; skip all children of `user_type`.
/// - Type alias name: `type_alias` `type:` field.
/// - Qualified identifier in `import` or `package_header`.
/// - Assignment LHS: handled by [`collect_write_references`].
fn is_non_read_position(node: &Node) -> bool {
    let parent = match node.parent() {
        Some(p) => p,
        None => return true, // root — not a read
    };
    match parent.kind() {
        // Free call callee: `foo()` — identifier is a direct child of call_expression.
        // The CALL_QUERY already captures it as Call; skip here.
        "call_expression" => {
            // The callee is the first child of call_expression (before value_arguments).
            // It is always the identifier we want to skip.
            parent.named_children(&mut parent.walk()).next().as_ref() == Some(node)
        }
        // Navigation expression: `a.foo` or `a.foo()`.
        // The member name is the LAST identifier among the direct children.
        // The receiver (`a`) may also be a direct identifier child — it IS a Read.
        "navigation_expression" => {
            let last_ident = parent
                .named_children(&mut parent.walk())
                .filter(|c| c.kind() == "identifier")
                .last();
            last_ident.as_ref() == Some(node)
        }
        // Declaration names.
        "function_declaration"
        | "class_declaration"
        | "object_declaration"
        | "companion_object" => parent.child_by_field_name("name").as_ref() == Some(node),
        // Type alias name (the `type:` field is the alias name, e.g. `typealias Foo = ...`).
        "type_alias" => parent.child_by_field_name("type").as_ref() == Some(node),
        // Variable binding: the bound identifier in `val x` / `var x` / loop var /
        // lambda param. variable_declaration's first identifier child is the name.
        "variable_declaration" => {
            // The first identifier child is the bound name; the second (if any) is
            // inside the type annotation and would be kind "type" → not identifier.
            parent
                .named_children(&mut parent.walk())
                .find(|c| c.kind() == "identifier")
                .as_ref()
                == Some(node)
        }
        // Parameter name: first identifier in `parameter` (name comes before the type).
        "parameter" | "class_parameter" => {
            parent
                .named_children(&mut parent.walk())
                .find(|c| c.kind() == "identifier")
                .as_ref()
                == Some(node)
        }
        // Import path — already Import refs.
        "import" | "qualified_identifier" => true,
        // Package header — not a reference.
        "package_header" => true,
        // Inside `user_type` (type reference like `List<String>`, `MyClass`) —
        // type identifiers are a distinct position, not value reads.
        "user_type" => true,
        // Inside `type` node descendants.
        "type_identifier" => true,
        // Assignment LHS — handled by collect_write_references.
        "assignment" => parent.child_by_field_name("left").as_ref() == Some(node),
        _ => false,
    }
}

/// Recursively walk `node` and emit [`RefRole::Read`] references for bare
/// `identifier` nodes used in value/expression positions.
///
/// Skips identifiers that are:
/// - Call callees (already [`RefRole::Call`]).
/// - Navigation member names (`foo` in `a.foo` — member position).
/// - Declaration names (`function_declaration` / `class_declaration` /
///   `object_declaration` / `companion_object` `name:` field).
/// - Variable binding names (`variable_declaration` first identifier).
/// - Parameter names (`parameter` first identifier).
/// - Import path identifiers (already [`RefRole::Import`]).
/// - Type positions (inside `user_type`).
/// - Assignment LHS (handled by [`collect_write_references`]).
///
/// Applies [`MIN_REF_LEN`] (same threshold as calls).
fn collect_read_references(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    if node.kind() == "identifier" {
        let name = node_text(node, bytes);
        if name.len() >= MIN_REF_LEN && !is_non_read_position(node) {
            push_ref(out, name, node, file, RefRole::Read);
        }
        // identifiers have no meaningful children; return early.
        return;
    }
    for child in node.children(&mut node.walk()) {
        collect_read_references(&child, bytes, file, out);
    }
}

/// Recursively walk `node` and emit [`RefRole::Write`] references for the
/// bare-identifier LHS of `assignment` nodes (e.g. `x = 5`, `x += 1`).
///
/// In the Kotlin grammar, both simple assignment (`x = 5`) and compound
/// assignment (`x += 1`, `x -= 1`, `x *= 1`, `x /= 1`, `x %= 1`) share the
/// same `assignment` node kind — the operator field distinguishes them.
///
/// Property declarations (`val x = 5` / `var x = 5`) are
/// `property_declaration` nodes, not `assignment` nodes; they are correctly
/// excluded — only `assignment` nodes with a bare-identifier LHS are handled.
///
/// Member / subscript LHS (`obj.prop = …`, `arr[i] = …`) are not covered in
/// v1 — only bare `identifier` LHS nodes. Applies [`MIN_REF_LEN`].
fn collect_write_references(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    if node.kind() == "assignment" {
        if let Some(lhs) = node.child_by_field_name("left") {
            if lhs.kind() == "identifier" {
                let name = node_text(&lhs, bytes);
                if name.len() >= MIN_REF_LEN {
                    push_ref(out, name, &lhs, file, RefRole::Write);
                }
            }
        }
    }
    for child in node.children(&mut node.walk()) {
        collect_write_references(&child, bytes, file, out);
    }
}

// ── Scope tree (Tier-B) ──────────────────────────────────────────────────────

/// Build the lexical scope tree for one Kotlin file.
///
/// `scopes[0]` is always the file-root `Module` scope spanning `[0, source_len)`.
/// Kotlin opens scopes for class/object/companion declarations (`Type`), function
/// and lambda bodies (`Function`), and bare blocks that are not a function body
/// (`Block`).
fn collect_scopes(root: &Node, source_len: usize) -> Vec<Scope> {
    let mut scopes = Vec::new();
    push_scope(
        &mut scopes,
        None,
        ByteSpan {
            start: 0,
            end: source_len,
        },
        ScopeKind::Module,
    );
    for child in root.children(&mut root.walk()) {
        scope_dfs(&child, 0, &mut scopes);
    }
    scopes
}

/// DFS opening scopes for Kotlin declaration nodes.
///
/// Uses the "peel-the-body" pattern so the body block does not re-open a
/// redundant scope on top of the declaration scope.
fn scope_dfs(node: &Node, parent_id: ScopeId, scopes: &mut Vec<Scope>) {
    match node.kind() {
        "class_declaration" | "object_declaration" | "companion_object" => {
            let type_id = push_scope(scopes, Some(parent_id), node_span(node), ScopeKind::Type);
            // Peel the body: recurse its children directly so the body node
            // itself does not re-open a scope.
            for child in node.children(&mut node.walk()) {
                if matches!(child.kind(), "class_body" | "enum_class_body") {
                    for body_child in child.children(&mut child.walk()) {
                        scope_dfs(&body_child, type_id, scopes);
                    }
                }
            }
        }
        "function_declaration" | "anonymous_function" => {
            let fn_id = push_scope(
                scopes,
                Some(parent_id),
                node_span(node),
                ScopeKind::Function,
            );
            // Find the function_body child and peel it.
            for child in node.children(&mut node.walk()) {
                if child.kind() == "function_body" {
                    // function_body is either a `block` or `= expression`.
                    // If it is a block, peel its children; otherwise recurse
                    // the expression directly.
                    let mut found_block = false;
                    for body_child in child.children(&mut child.walk()) {
                        if body_child.kind() == "block" {
                            found_block = true;
                            for block_child in body_child.children(&mut body_child.walk()) {
                                scope_dfs(&block_child, fn_id, scopes);
                            }
                        }
                    }
                    if !found_block {
                        // Expression body (`= expr`): recurse children of function_body.
                        for body_child in child.children(&mut child.walk()) {
                            scope_dfs(&body_child, fn_id, scopes);
                        }
                    }
                }
            }
        }
        "secondary_constructor" => {
            let fn_id = push_scope(
                scopes,
                Some(parent_id),
                node_span(node),
                ScopeKind::Function,
            );
            // secondary_constructor has a `block` child for its body.
            for child in node.children(&mut node.walk()) {
                if child.kind() == "block" {
                    for block_child in child.children(&mut child.walk()) {
                        scope_dfs(&block_child, fn_id, scopes);
                    }
                }
            }
        }
        "lambda_literal" => {
            let fn_id = push_scope(
                scopes,
                Some(parent_id),
                node_span(node),
                ScopeKind::Function,
            );
            // Lambda body is not separated into a named body node; all children
            // (including lambda_parameters and statements) are direct children.
            for child in node.children(&mut node.walk()) {
                scope_dfs(&child, fn_id, scopes);
            }
        }
        "block" => {
            // A bare block NOT already consumed as a function body (e.g. if/when
            // branch bodies, standalone blocks).
            let block_id = push_scope(scopes, Some(parent_id), node_span(node), ScopeKind::Block);
            for child in node.children(&mut node.walk()) {
                scope_dfs(&child, block_id, scopes);
            }
        }
        _ => {
            for child in node.children(&mut node.walk()) {
                scope_dfs(&child, parent_id, scopes);
            }
        }
    }
}

// ── Bindings (Tier-B) ────────────────────────────────────────────────────────

/// Collect parameter and local-variable [`Binding`]s for one Kotlin file.
///
/// Covers:
/// - `function_declaration` / `anonymous_function` / `secondary_constructor`
///   parameters (from `function_value_parameters`) → [`BindingKind::Param`].
/// - `lambda_literal` parameters (from `lambda_parameters` →
///   `variable_declaration`) → [`BindingKind::Param`].
/// - `property_declaration` with `variable_declaration` inside a `Function` or
///   `Block` scope → [`BindingKind::Local`]. Class-level properties (in `Type`
///   scopes) are excluded by the scope-kind guard.
/// - `for_statement` loop variable (`variable_declaration` direct child) →
///   [`BindingKind::Local`].
///
/// Class properties at `Type` scope level are covered by [`definition_bindings`]
/// as [`BindingKind::Definition`] and intentionally excluded here.
fn collect_bindings(root: &Node, bytes: &[u8], scopes: &[Scope]) -> Vec<Binding> {
    let mut out = Vec::new();
    collect_bindings_dfs(root, bytes, scopes, &mut out);
    out
}

fn collect_bindings_dfs(node: &Node, bytes: &[u8], scopes: &[Scope], out: &mut Vec<Binding>) {
    match node.kind() {
        "function_declaration" | "anonymous_function" | "secondary_constructor" => {
            // Collect params from function_value_parameters child.
            for child in node.children(&mut node.walk()) {
                if child.kind() == "function_value_parameters" {
                    collect_params(&child, bytes, scopes, out);
                }
            }
            // Recurse into all children to pick up body bindings.
            for child in node.children(&mut node.walk()) {
                collect_bindings_dfs(&child, bytes, scopes, out);
            }
        }
        "lambda_literal" => {
            // Lambda params live in a `lambda_parameters` child; each param is a
            // `variable_declaration` whose first `identifier` child is the name.
            for child in node.children(&mut node.walk()) {
                if child.kind() == "lambda_parameters" {
                    for param in child.children(&mut child.walk()) {
                        if param.kind() == "variable_declaration" {
                            if let Some(ident) = param
                                .children(&mut param.walk())
                                .find(|c| c.kind() == "identifier")
                            {
                                let name = node_text(&ident, bytes);
                                let intro = ident.start_byte();
                                push_binding(
                                    out,
                                    name.to_owned(),
                                    intro,
                                    BindingKind::Param,
                                    scopes,
                                );
                            }
                        }
                    }
                }
            }
            for child in node.children(&mut node.walk()) {
                collect_bindings_dfs(&child, bytes, scopes, out);
            }
        }
        "property_declaration" => {
            // Emit Local only when inside a Function or Block scope.
            // Class-level properties sit in a Type scope and are excluded by this
            // guard — they are captured by definition_bindings as Definition.
            for child in node.children(&mut node.walk()) {
                if child.kind() == "variable_declaration" {
                    if let Some(ident) = child
                        .children(&mut child.walk())
                        .find(|c| c.kind() == "identifier")
                    {
                        let intro = ident.start_byte();
                        let sid = innermost_scope(intro, scopes).unwrap_or(0);
                        if matches!(scopes[sid].kind, ScopeKind::Function | ScopeKind::Block) {
                            let name = node_text(&ident, bytes);
                            push_binding(out, name.to_owned(), intro, BindingKind::Local, scopes);
                        }
                    }
                    break;
                }
            }
            for child in node.children(&mut node.walk()) {
                collect_bindings_dfs(&child, bytes, scopes, out);
            }
        }
        "for_statement" => {
            // The loop variable is a `variable_declaration` direct child.
            for child in node.children(&mut node.walk()) {
                if child.kind() == "variable_declaration" {
                    if let Some(ident) = child
                        .children(&mut child.walk())
                        .find(|c| c.kind() == "identifier")
                    {
                        let intro = ident.start_byte();
                        let sid = innermost_scope(intro, scopes).unwrap_or(0);
                        if matches!(scopes[sid].kind, ScopeKind::Function | ScopeKind::Block) {
                            let name = node_text(&ident, bytes);
                            push_binding(out, name.to_owned(), intro, BindingKind::Local, scopes);
                        }
                    }
                    break;
                }
            }
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

/// Emit a [`BindingKind::Param`] for each named parameter in a Kotlin
/// `function_value_parameters` node.
///
/// Each named child of kind `"parameter"` has an `identifier` child (the param
/// name) as its first named child. `class_parameter` (primary constructor params)
/// is intentionally not handled here.
fn collect_params(params: &Node, bytes: &[u8], scopes: &[Scope], out: &mut Vec<Binding>) {
    for child in params.named_children(&mut params.walk()) {
        if child.kind() == "parameter" {
            if let Some(ident) = child
                .children(&mut child.walk())
                .find(|c| c.kind() == "identifier")
            {
                let name = node_text(&ident, bytes);
                let intro = ident.start_byte();
                push_binding(out, name.to_owned(), intro, BindingKind::Param, scopes);
            }
        }
    }
}

// ── Inheritance extraction ───────────────────────────────────────────────────

/// Pre-order search returning the first descendant (or self) whose kind is
/// `user_type`. Covers all three `delegation_specifier` sub-forms uniformly:
/// - `constructor_invocation` → `type` child is a `user_type`
/// - `explicit_delegation`    → `type` child is a `user_type`
/// - bare `type`              → directly contains a `user_type`
fn first_user_type<'a>(node: &Node<'a>) -> Option<Node<'a>> {
    if node.kind() == "user_type" {
        return Some(*node);
    }
    for child in node.children(&mut node.walk()) {
        if let Some(found) = first_user_type(&child) {
            return Some(found);
        }
    }
    None
}

/// Recursively walk the tree collecting `Inherit` references for every
/// `class_declaration` and `object_declaration` that has a `delegation_specifiers`
/// child.
fn collect_inheritance(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    if matches!(node.kind(), "class_declaration" | "object_declaration") {
        for child in node.children(&mut node.walk()) {
            if child.kind() == "delegation_specifiers" {
                for spec in child.children(&mut child.walk()) {
                    if spec.kind() == "delegation_specifier" {
                        if let Some(user_type_node) = first_user_type(&spec) {
                            super::push_ref(
                                out,
                                super::simple_type_name(node_text(&user_type_node, bytes), "."),
                                &user_type_node,
                                file,
                                RefRole::IsImplementation,
                            );
                        }
                    }
                }
            }
        }
    }

    // Recurse into all children so nested classes are covered.
    for child in node.children(&mut node.walk()) {
        collect_inheritance(&child, bytes, file, out);
    }
}

// ── Import extraction ────────────────────────────────────────────────────────

/// Recursively walk the tree collecting `Import` references for every
/// `import` node that is not a wildcard (`import com.x.*`).
///
/// For each qualifying `import` node the first child of kind
/// `qualified_identifier` or `identifier` provides the full import path;
/// [`super::simple_type_name`] extracts the leaf name (e.g. `com.x.Foo` → `Foo`).
/// Wildcards are detected by a `*` in the raw node text and silently dropped.
fn collect_imports(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    if node.kind() == "import" {
        let raw = node_text(node, bytes);
        if !raw.contains('*') {
            // Find the first child that carries the import path.
            for child in node.children(&mut node.walk()) {
                if matches!(child.kind(), "qualified_identifier" | "identifier") {
                    let leaf = super::simple_type_name(node_text(&child, bytes), ".");
                    super::push_ref(out, leaf, &child, file, RefRole::Import);
                    break;
                }
            }
        }
        // Don't recurse into an import node's children further.
        return;
    }

    for child in node.children(&mut node.walk()) {
        collect_imports(&child, bytes, file, out);
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn extract(src: &str, path: &str) -> FileFacts {
        KotlinExtractor.extract(src, path).unwrap()
    }

    fn by_name(facts: &FileFacts, name: &str) -> Option<Symbol> {
        facts.symbols.iter().find(|s| s.name == name).cloned()
    }

    // Test 1: class with public fun + private fun; visibility gate
    #[test]
    fn class_visibility_gate() {
        let src = r#"package com.ex
class Session {
    fun open() {}
    private fun secret() {}
}
"#;
        let facts = extract(src, "src/com/ex/Session.kt");

        let session = by_name(&facts, "Session").unwrap();
        assert_eq!(session.kind, SymbolKind::Class);
        assert_eq!(
            session.id.to_scip_string(),
            "codegraph . . . com/ex/Session#"
        );

        let open = by_name(&facts, "open").unwrap();
        assert_eq!(open.kind, SymbolKind::Method);
        assert_eq!(
            open.id.to_scip_string(),
            "codegraph . . . com/ex/Session#open()."
        );

        // private method must NOT be emitted
        assert!(by_name(&facts, "secret").is_none());
    }

    // Test 2: interface → SymbolKind::Interface
    #[test]
    fn interface_kind() {
        let src = r#"package com.ex
interface Readable {
    fun read(): String
}
"#;
        let facts = extract(src, "src/com/ex/Readable.kt");

        let readable = by_name(&facts, "Readable").unwrap();
        assert_eq!(readable.kind, SymbolKind::Interface);
        assert_eq!(
            readable.id.to_scip_string(),
            "codegraph . . . com/ex/Readable#"
        );
    }

    // Test 3: enum class with entries → Enum + Const
    #[test]
    fn enum_class_with_entries() {
        let src = r#"package com.ex
enum class Direction {
    NORTH,
    SOUTH,
    EAST,
    WEST
}
"#;
        let facts = extract(src, "src/com/ex/Direction.kt");

        let dir = by_name(&facts, "Direction").unwrap();
        assert_eq!(dir.kind, SymbolKind::Enum);
        assert_eq!(dir.id.to_scip_string(), "codegraph . . . com/ex/Direction#");

        for entry in &["NORTH", "SOUTH", "EAST", "WEST"] {
            let sym = by_name(&facts, entry).unwrap();
            assert_eq!(sym.kind, SymbolKind::Const);
            assert_eq!(
                sym.id.to_scip_string(),
                format!("codegraph . . . com/ex/Direction#{entry}.")
            );
        }
    }

    // Test 4: object declaration → SymbolKind::Class (singleton)
    #[test]
    fn object_singleton() {
        let src = r#"package com.ex
object Registry {
    fun register() {}
}
"#;
        let facts = extract(src, "src/com/ex/Registry.kt");

        let reg = by_name(&facts, "Registry").unwrap();
        assert_eq!(reg.kind, SymbolKind::Class);
        assert_eq!(reg.id.to_scip_string(), "codegraph . . . com/ex/Registry#");

        let register = by_name(&facts, "register").unwrap();
        assert_eq!(register.kind, SymbolKind::Method);
        assert_eq!(
            register.id.to_scip_string(),
            "codegraph . . . com/ex/Registry#register()."
        );
    }

    // Test 5: val → Const, var → Static
    #[test]
    fn val_and_var_properties() {
        let src = r#"package com.ex
class Config {
    val maxRetries: Int = 3
    var timeout: Long = 5000
}
"#;
        let facts = extract(src, "src/com/ex/Config.kt");

        let max = by_name(&facts, "maxRetries").unwrap();
        assert_eq!(max.kind, SymbolKind::Const);
        assert_eq!(
            max.id.to_scip_string(),
            "codegraph . . . com/ex/Config#maxRetries."
        );

        let timeout = by_name(&facts, "timeout").unwrap();
        assert_eq!(timeout.kind, SymbolKind::Static);
        assert_eq!(
            timeout.id.to_scip_string(),
            "codegraph . . . com/ex/Config#timeout."
        );
    }

    // Test 6: top-level fun → SymbolKind::Function under namespace
    #[test]
    fn top_level_function() {
        let src = r#"package com.ex
fun greet(name: String): String {
    return "Hello $name"
}
"#;
        let facts = extract(src, "src/com/ex/Greeting.kt");

        let greet = by_name(&facts, "greet").unwrap();
        assert_eq!(greet.kind, SymbolKind::Function);
        assert_eq!(greet.id.to_scip_string(), "codegraph . . . com/ex/greet().");
    }

    // Test 7: typealias → SymbolKind::TypeAlias (name from `type` field)
    #[test]
    fn type_alias() {
        let src = r#"package com.ex
typealias StringList = List<String>
"#;
        let facts = extract(src, "src/com/ex/Aliases.kt");

        let alias = by_name(&facts, "StringList").unwrap();
        assert_eq!(alias.kind, SymbolKind::TypeAlias);
        assert_eq!(
            alias.id.to_scip_string(),
            "codegraph . . . com/ex/StringList#"
        );
    }

    // Test 8: call references captured (free call + member call)
    #[test]
    fn call_references_captured() {
        let src = r#"package com.ex
fun main() {
    foo()
    val x = SomeClass()
    x.bar()
}
"#;
        let facts = extract(src, "src/com/ex/Main.kt");
        let names: Vec<&str> = facts.references.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"foo"), "expected 'foo' in {names:?}");
        assert!(names.contains(&"bar"), "expected 'bar' in {names:?}");
    }

    #[test]
    fn lang_tag() {
        let facts = extract("fun foo() {}", "src/Foo.kt");
        assert_eq!(facts.lang, "kotlin");
    }

    // Test 10: class with superclass call + interface → both Inherit refs
    #[test]
    fn class_inherits_base_and_interface() {
        let src = "class Sub : Base(), Iface { }";
        let facts = extract(src, "src/Sub.kt");
        let inherit_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            inherit_names.contains(&"Base"),
            "expected 'Base' in {inherit_names:?}"
        );
        assert!(
            inherit_names.contains(&"Iface"),
            "expected 'Iface' in {inherit_names:?}"
        );
    }

    // Test 11: dotted parent name → leaf only
    #[test]
    fn class_inherits_dotted_name_simplified() {
        let src = "class C : com.x.Base() { }";
        let facts = extract(src, "src/C.kt");
        let inherit_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            inherit_names.contains(&"Base"),
            "expected 'Base' in {inherit_names:?}"
        );
    }

    // Test 12: object declaration inherits interface → Inherit ref
    #[test]
    fn object_inherits_service() {
        let src = "object O : Service { }";
        let facts = extract(src, "src/O.kt");
        let inherit_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            inherit_names.contains(&"Service"),
            "expected 'Service' in {inherit_names:?}"
        );
    }

    // Test 13: qualified import → Import ref with leaf name only
    #[test]
    fn import_qualified_emits_leaf() {
        let src = "import com.example.Service\nclass C";
        let facts = extract(src, "src/C.kt");
        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(
            import_names,
            vec!["Service"],
            "expected exactly ['Service'], got {import_names:?}"
        );
    }

    // Test 14: simple (unqualified) import → Import ref
    #[test]
    fn import_simple_emits_name() {
        let src = "import Foo\nclass C";
        let facts = extract(src, "src/C.kt");
        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(
            import_names,
            vec!["Foo"],
            "expected exactly ['Foo'], got {import_names:?}"
        );
    }

    // Test 15: wildcard import → NO Import refs
    #[test]
    fn import_wildcard_skipped() {
        let src = "import com.example.*\nclass C";
        let facts = extract(src, "src/C.kt");
        let import_refs: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            import_refs.is_empty(),
            "expected no Import refs for wildcard, got {import_refs:?}"
        );
    }

    // ── Tier-B scope / binding tests ─────────────────────────────────────────

    // Test B1: function params → Param bindings in a Function scope.
    #[test]
    fn func_params_emit_param_bindings() {
        let src = "fun f(a: Int, b: String) {}";
        let facts = extract(src, "src/F.kt");

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
            "expected Param bindings for a and b, got {param_names:?}"
        );
    }

    // Test B2: local val inside function → Local binding in Function scope.
    #[test]
    fn local_val_emits_local_binding() {
        let src = "fun f() { val x = 1 }";
        let facts = extract(src, "src/F.kt");

        let x = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Local && b.name == "x")
            .expect("expected a Local binding for 'x'");
        assert!(
            matches!(
                facts.scopes[x.scope].kind,
                ScopeKind::Function | ScopeKind::Block
            ),
            "x should be in a Function or Block scope, got {:?}",
            facts.scopes[x.scope].kind
        );
    }

    // Test B3: local var inside function → Local binding.
    #[test]
    fn local_var_emits_local_binding() {
        let src = "fun f() { var y = 2 }";
        let facts = extract(src, "src/F.kt");

        let y = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Local && b.name == "y")
            .expect("expected a Local binding for 'y'");
        assert!(
            matches!(
                facts.scopes[y.scope].kind,
                ScopeKind::Function | ScopeKind::Block
            ),
            "y should be in a Function or Block scope, got {:?}",
            facts.scopes[y.scope].kind
        );
    }

    // Test B4: for-loop variable → Local binding.
    #[test]
    fn for_loop_var_emits_local_binding() {
        let src = "fun f(xs: List<Int>) { for (x in xs) {} }";
        let facts = extract(src, "src/F.kt");

        let x = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Local && b.name == "x")
            .expect("expected a Local binding for for-loop 'x'");
        assert!(
            matches!(
                facts.scopes[x.scope].kind,
                ScopeKind::Function | ScopeKind::Block
            ),
            "for-loop x should be in a Function or Block scope, got {:?}",
            facts.scopes[x.scope].kind
        );
    }

    // Test B5: class property is NOT a Local but IS a Definition.
    #[test]
    fn class_property_not_local_but_is_definition() {
        let src = "class C { val count: Int = 0 }";
        let facts = extract(src, "src/C.kt");

        assert!(
            !facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Local && b.name == "count"),
            "class property 'count' must NOT be a Local binding"
        );
        assert!(
            facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Definition && b.name == "count"),
            "class property 'count' must have a Definition binding"
        );
    }

    // Test B6: nested class+fun produces Module → Type → Function scope chain.
    #[test]
    fn nested_class_fun_scope_chain() {
        let src = "class C { fun f() {} }";
        let facts = extract(src, "src/C.kt");

        assert_eq!(
            facts.scopes[0].kind,
            ScopeKind::Module,
            "scopes[0] must be Module"
        );

        let type_scope_id = facts
            .scopes
            .iter()
            .position(|s| s.kind == ScopeKind::Type)
            .expect("expected a Type scope");
        let fn_scope_id = facts
            .scopes
            .iter()
            .position(|s| s.kind == ScopeKind::Function)
            .expect("expected a Function scope");

        assert_eq!(
            facts.scopes[type_scope_id].parent,
            Some(0),
            "Type scope parent should be Module (0)"
        );
        assert_eq!(
            facts.scopes[fn_scope_id].parent,
            Some(type_scope_id),
            "Function scope parent should be the Type scope"
        );
    }

    // Test B7: lambda params → Param binding in a Function scope (the lambda's).
    #[test]
    fn lambda_params_emit_param_bindings() {
        let src = "fun f() { val g = { a: Int -> a + 1 } }";
        let facts = extract(src, "src/F.kt");

        let a = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Param && b.name == "a")
            .expect("expected a Param binding for lambda param 'a'");
        assert_eq!(
            facts.scopes[a.scope].kind,
            ScopeKind::Function,
            "lambda param 'a' should be in a Function scope"
        );
    }

    // Test B8: object declaration with method → Type scope + nested Function scope.
    #[test]
    fn object_members_produce_type_and_function_scopes() {
        let src = "object Reg { fun get() {} }";
        let facts = extract(src, "src/Reg.kt");

        let type_scope_id = facts
            .scopes
            .iter()
            .position(|s| s.kind == ScopeKind::Type)
            .expect("expected a Type scope for the object");
        let fn_scope_id = facts
            .scopes
            .iter()
            .position(|s| s.kind == ScopeKind::Function)
            .expect("expected a Function scope for the method");

        assert_eq!(
            facts.scopes[type_scope_id].parent,
            Some(0),
            "object Type scope should be nested under Module"
        );
        assert_eq!(
            facts.scopes[fn_scope_id].parent,
            Some(type_scope_id),
            "method Function scope should be nested under the Type scope"
        );
    }

    // Test B9: same-file call ref has scope attached (non-zero = innermost scope).
    #[test]
    fn same_file_call_ref_has_scope() {
        let src = "fun greet() {}\nfun main() { greet() }";
        let facts = extract(src, "src/Greet.kt");

        // greet should be defined
        assert!(
            by_name(&facts, "greet").is_some(),
            "expected 'greet' Definition"
        );

        // The greet() call reference should have scope set to Some(non-zero).
        let greet_ref = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Call && r.name == "greet")
            .expect("expected a Call ref for 'greet'");
        assert!(
            greet_ref.scope.is_some() && greet_ref.scope != Some(0),
            "greet() call ref should be in a non-root scope, got {:?}",
            greet_ref.scope
        );
    }

    // Test B10: import binding.
    #[test]
    fn import_emits_import_binding() {
        let src = "import com.example.Service\nclass C";
        let facts = extract(src, "src/C.kt");

        assert!(
            facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Import && b.name == "Service"),
            "expected an Import binding named 'Service', got {:?}",
            facts
                .bindings
                .iter()
                .filter(|b| b.kind == BindingKind::Import)
                .map(|b| b.name.as_str())
                .collect::<Vec<_>>()
        );
    }

    // ── Edge richness: Read / Write tests ────────────────────────────────────

    // Test R1: read at use site — `return base` emits Read for "base"; the
    // declaration `val base = 1` must NOT emit a Read for "base".
    #[test]
    fn read_at_use_not_declaration() {
        let src = "fun f(): Int { val base = 1; return base }";
        let facts = extract(src, "src/F.kt");
        let read_refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Read && r.name == "base")
            .collect();
        assert!(
            !read_refs.is_empty(),
            "expected at least one Read ref for 'base', got none"
        );
        // The use in `return base` is at a higher byte offset than the `val base` decl.
        // In "fun f(): Int { val base = 1; return base }" the `return` starts after byte 30.
        let use_ref = read_refs
            .iter()
            .find(|r| r.occ.byte > 30)
            .expect("Read ref for 'base' should be at the return site (byte > 30)");
        assert!(
            use_ref.occ.byte > 30,
            "Read ref should be at the use site, not the declaration"
        );
    }

    // Test R2: write — `cnt = 5` emits Write "cnt"; the declaration `var cnt = 0` must not.
    #[test]
    fn write_emitted_for_assignment() {
        let src = "fun f() { var cnt = 0; cnt = 5 }";
        let facts = extract(src, "src/F.kt");
        let write_refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Write && r.name == "cnt")
            .collect();
        assert!(
            !write_refs.is_empty(),
            "expected at least one Write ref for 'cnt', got none — all refs: {:?}",
            facts
                .references
                .iter()
                .map(|r| (&r.name, r.role))
                .collect::<Vec<_>>()
        );
    }

    // Test R3: call callee must NOT also be a Read.
    #[test]
    fn call_not_also_read() {
        let src = "fun f() { helper() }";
        let facts = extract(src, "src/F.kt");
        let call_refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Call && r.name == "helper")
            .collect();
        assert!(!call_refs.is_empty(), "expected a Call ref for 'helper'");
        let read_refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Read && r.name == "helper")
            .collect();
        assert!(
            read_refs.is_empty(),
            "helper() must NOT produce a Read ref; got: {read_refs:?}"
        );
    }

    // Test R4: navigation member must NOT be a Read; receiver must be a Read.
    #[test]
    fn navigation_member_not_read_receiver_is_read() {
        // `use(obj.field)` — `obj` is a Read (receiver), `field` is NOT a Read.
        let src = "fun f(obj: C) { use(obj.field) }";
        let facts = extract(src, "src/F.kt");
        let field_reads: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Read && r.name == "field")
            .collect();
        assert!(
            field_reads.is_empty(),
            "member 'field' in navigation expression must NOT be a Read ref; got: {field_reads:?}"
        );
        // `obj` is the receiver — it should be a Read.
        let obj_reads: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Read && r.name == "obj")
            .collect();
        assert!(
            !obj_reads.is_empty(),
            "receiver 'obj' should be a Read ref; got none"
        );
    }
}
