// SPDX-License-Identifier: Apache-2.0

//! PHP extractor — one tree-sitter pass yielding definitions and references.
//!
//! Definitions: top-level functions, classes, interfaces, traits, and enums,
//! plus ALL their members (methods, properties, constants), tagged with their
//! real `Visibility`. Namespace identity comes from the `namespace` declaration
//! when present; otherwise it falls back to path-derived segments (strips
//! `.php`, strips leading `src/`, splits on `/`). Interface members are treated
//! as implicitly public. Enum *cases* are not captured in v0 — a deliberate
//! limitation; they require a separate `SymbolKind` and are left for a future
//! pass.
//!
//! PHP supports two namespace forms:
//! - **Statement form**: `namespace App;` followed by sibling declarations.
//! - **Block form**: `namespace App { ... }` with declarations inside a
//!   `compound_statement` body.
//!
//! Both are handled: definitions are collected from the program root and,
//! recursively, from any `namespace_definition` that carries a `body` field.
//!
//! References: callee identifiers of `function_call_expression` (bare calls)
//! and `member_call_expression` (method calls).

use tree_sitter::{Node, Parser};

use crate::error::{CodegraphError, Result};
use crate::graph::types::{
    Binding, BindingKind, ByteSpan, FileFacts, RefRole, Reference, Scope, ScopeId, ScopeKind,
    Symbol, SymbolKind, TypeRefContext, Visibility,
};
use crate::lang::Language;
use crate::symbol::Descriptor;

use super::{
    ExtractCtx, Extractor, MIN_REF_LEN, attach_reference_scopes, child_text,
    collect_call_references, definition_bindings, field_text, import_bindings, innermost_scope,
    make_symbol, node_span, node_text, one_line_signature, push_binding, push_ref, push_scope,
    push_type_ref,
};

/// Tree-sitter query capturing call-callee identifiers.
const CALL_QUERY: &str = r#"
[
  (function_call_expression
    function: (name) @callee)
  (member_call_expression
    name: (name) @callee)
]
"#;

/// Extracts PHP symbols and references.
pub struct PhpExtractor;

impl Extractor for PhpExtractor {
    fn lang(&self) -> Language {
        Language::Php
    }

    fn extract(&self, source: &str, file: &str) -> Result<FileFacts> {
        let ts_language = crate::grammar::php();
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
        let namespaces = php_namespaces(&root, bytes, file);

        let ctx = ExtractCtx {
            bytes,
            file,
            lang: Language::Php,
        };
        let mut defs = Vec::new();
        collect_defs(&root, &namespaces, &ctx, &mut defs);
        let def_bindings = definition_bindings(&defs);
        let mut symbols = defs;
        symbols.push(super::module_symbol(
            Language::Php,
            &namespaces,
            file,
            source.len(),
        ));

        let mut references =
            collect_call_references(&root, &ts_language, CALL_QUERY, Language::Php, bytes, file)?;
        collect_inheritance(&root, bytes, file, &mut references);
        collect_imports(&root, bytes, file, &mut references);
        collect_type_references(&root, bytes, file, &mut references);
        collect_read_references(&root, bytes, file, &mut references);
        collect_write_references(&root, bytes, file, &mut references);

        let scopes = collect_scopes(&root, source.len());
        attach_reference_scopes(&mut references, &scopes);
        let mut bindings = collect_bindings(&root, bytes, &scopes);
        bindings.extend(def_bindings);
        bindings.extend(import_bindings(&references, &scopes));

        Ok(FileFacts {
            file: file.to_owned(),
            lang: Language::Php.as_str().to_owned(),
            symbols,
            references,
            scopes,
            bindings,
            ffi_exports: Vec::new(),
        })
    }
}

/// Derive namespace descriptors from the `namespace` declaration, falling back
/// to path-derived segments when no declaration is present.
///
/// With a namespace: `App\Auth` → `["App", "Auth"]`.
/// Without: `src/app/helpers.php` → `["app", "helpers"]`.
fn php_namespaces(root: &Node, bytes: &[u8], file: &str) -> Vec<String> {
    for child in root.children(&mut root.walk()) {
        if child.kind() != "namespace_definition" {
            continue;
        }
        // The `name` field is a `namespace_name` node whose raw text is the
        // backslash-delimited namespace string, e.g. `App\Auth`.
        if let Some(ns_text) = field_text(&child, "name", bytes) {
            let parts: Vec<String> = ns_text
                .split('\\')
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect();
            if !parts.is_empty() {
                return parts;
            }
        }
    }

    // Fallback: derive from file path (strips `.php`, strips leading `src/`).
    let p = file.strip_suffix(".php").unwrap_or(file);
    let p = p.strip_prefix("src/").unwrap_or(p);
    p.split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Collect top-level definitions from `container` (either the program root or
/// the `compound_statement` body of a block-form namespace).
///
/// Handles both PHP namespace forms:
/// - Statement form: `namespace App;` — the declarations are siblings of the
///   `namespace_definition` node under the program root.
/// - Block form: `namespace App { ... }` — the `namespace_definition` has a
///   `body` field; we recurse into it.
fn collect_defs(container: &Node, namespaces: &[String], ctx: &ExtractCtx, out: &mut Vec<Symbol>) {
    let bytes = ctx.bytes;
    let base_descriptors: Vec<Descriptor> = namespaces
        .iter()
        .cloned()
        .map(Descriptor::Namespace)
        .collect();
    for child in container.children(&mut container.walk()) {
        match child.kind() {
            "function_definition" => {
                let Some(name) = field_text(&child, "name", bytes) else {
                    continue;
                };
                let mut descriptors = base_descriptors.clone();
                descriptors.push(Descriptor::Method {
                    name: name.clone(),
                    disambiguator: crate::symbol::MethodDisambiguator::empty(),
                });
                // Top-level functions have no visibility modifier concept; they
                // are effectively public within their namespace.
                push_symbol(
                    out,
                    ctx,
                    &child,
                    name,
                    SymbolKind::Function,
                    Visibility::Public,
                    descriptors,
                );
            }
            kind @ ("class_declaration"
            | "interface_declaration"
            | "trait_declaration"
            | "enum_declaration") => {
                let Some(type_name) = field_text(&child, "name", bytes) else {
                    continue;
                };
                let type_sym_kind = match kind {
                    "class_declaration" => SymbolKind::Class,
                    "interface_declaration" => SymbolKind::Interface,
                    "trait_declaration" => SymbolKind::Trait,
                    "enum_declaration" => SymbolKind::Enum,
                    _ => unreachable!(),
                };
                let mut type_descriptors = base_descriptors.clone();
                type_descriptors.push(Descriptor::Type(type_name.clone()));
                // Top-level type declarations have no visibility modifier; they
                // are effectively public within their namespace.
                push_symbol(
                    out,
                    ctx,
                    &child,
                    type_name,
                    type_sym_kind,
                    Visibility::Public,
                    type_descriptors.clone(),
                );

                // Interface members are implicitly public.
                let implicit_public = kind == "interface_declaration";

                if let Some(body) = child.child_by_field_name("body") {
                    collect_members(&body, &type_descriptors, implicit_public, ctx, out);
                }
            }
            "namespace_definition" => {
                // Block-form namespace: recurse into the compound_statement body.
                if let Some(body) = child.child_by_field_name("body") {
                    collect_defs(&body, namespaces, ctx, out);
                }
                // Statement-form namespace has no body; its sibling declarations
                // are already visited in the outer loop.
            }
            _ => {}
        }
    }
}

/// Collect ALL method, property, and constant declarations from a type body,
/// tagging each with its real `Visibility`.
fn collect_members(
    body: &Node,
    type_descriptors: &[Descriptor],
    implicit_public: bool,
    ctx: &ExtractCtx,
    out: &mut Vec<Symbol>,
) {
    let bytes = ctx.bytes;
    for member in body.children(&mut body.walk()) {
        match member.kind() {
            "method_declaration" => {
                let Some(name) = field_text(&member, "name", bytes) else {
                    continue;
                };
                let vis = if implicit_public {
                    Visibility::Public
                } else {
                    read_visibility(&member, bytes)
                };
                let mut descriptors = type_descriptors.to_vec();
                descriptors.push(Descriptor::Method {
                    name: name.clone(),
                    disambiguator: crate::symbol::MethodDisambiguator::empty(),
                });
                push_symbol(
                    out,
                    ctx,
                    &member,
                    name,
                    SymbolKind::Method,
                    vis,
                    descriptors,
                );
            }
            "property_declaration" => {
                let vis = if implicit_public {
                    Visibility::Public
                } else {
                    read_visibility(&member, bytes)
                };
                // A property_declaration may contain one or more property_element
                // children; each property_element's `name` field is a
                // `variable_name` node whose text includes the leading `$`.
                for elem in member.children(&mut member.walk()) {
                    if elem.kind() != "property_element" {
                        continue;
                    }
                    let Some(raw_name) = field_text(&elem, "name", bytes) else {
                        continue;
                    };
                    // Strip the leading `$` from the variable name.
                    let name = if let Some(stripped) = raw_name.strip_prefix('$') {
                        stripped.to_owned()
                    } else {
                        raw_name
                    };
                    let mut descriptors = type_descriptors.to_vec();
                    descriptors.push(Descriptor::Term(name.clone()));
                    push_symbol(
                        out,
                        ctx,
                        &member,
                        name,
                        SymbolKind::Static,
                        vis,
                        descriptors,
                    );
                }
            }
            "const_declaration" => {
                let vis = if implicit_public {
                    Visibility::Public
                } else {
                    read_visibility(&member, bytes)
                };
                // A const_declaration contains one or more const_element children;
                // each const_element has a child of kind `name`.
                for elem in member.children(&mut member.walk()) {
                    if elem.kind() != "const_element" {
                        continue;
                    }
                    // const_element has no named field for its name — get by kind.
                    let Some(name) = child_text(&elem, "name", bytes) else {
                        continue;
                    };
                    let mut descriptors = type_descriptors.to_vec();
                    descriptors.push(Descriptor::Term(name.clone()));
                    push_symbol(out, ctx, &member, name, SymbolKind::Const, vis, descriptors);
                }
            }
            _ => {}
        }
    }
}

/// Read the explicit visibility of `node`, falling back to `Public` when no
/// `visibility_modifier` child is present (PHP's implicit default).
///
/// Maps modifier text to [`Visibility`]:
/// - `"private"`   → [`Visibility::Private`]
/// - `"protected"` → [`Visibility::Protected`]
/// - `"public"`    → [`Visibility::Public`]
/// - anything else → [`Visibility::Public`] (e.g. future modifiers)
/// - absent        → [`Visibility::Public`] (PHP implicit default for class
///   members; free functions and classes have no modifier concept and are
///   effectively public-scoped)
fn read_visibility(node: &Node, bytes: &[u8]) -> Visibility {
    for child in node.children(&mut node.walk()) {
        if child.kind() == "visibility_modifier" {
            return match node_text(&child, bytes) {
                "private" => Visibility::Private,
                "protected" => Visibility::Protected,
                _ => Visibility::Public,
            };
        }
    }
    // No visibility_modifier present → PHP implicit default is public.
    Visibility::Public
}

/// Recursively walk `node` collecting `Import` references for every
/// `namespace_use_clause` in the tree.
///
/// Handles both the flat form (`use App\Models\User;`) and the grouped form
/// (`use App\Models\{User, Post};`) — the recursive walk reaches
/// `namespace_use_clause` nodes inside `namespace_use_group` automatically.
///
/// For each clause the leaf name is derived from the `qualified_name` or `name`
/// child via [`super::simple_type_name`] with `"\\"` as the separator; any
/// `alias` field is ignored.
fn collect_imports(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    if node.kind() == "namespace_use_clause" {
        // Find the child node that holds the fully-qualified name.
        for child in node.children(&mut node.walk()) {
            if matches!(child.kind(), "qualified_name" | "name") {
                let leaf = super::simple_type_name(node_text(&child, bytes), "\\");
                super::push_ref(out, leaf, &child, file, RefRole::Import);
                break;
            }
        }
    }

    // Recurse into all children so grouped use-clauses are reached.
    for child in node.children(&mut node.walk()) {
        collect_imports(&child, bytes, file, out);
    }
}

/// Recursively walk `node` collecting `Inherit` references for every
/// `class_declaration` and `interface_declaration` in the tree (including nested
/// and namespaced classes).
///
/// For each such node, the following named children are inspected:
/// - `base_clause` — `class extends Parent` (single parent) or
///   `interface extends A, B` (multiple parents).
/// - `class_interface_clause` — `class implements A, B` (multiple interfaces).
///
/// Within those clause nodes, children of kind `name`, `qualified_name`, or
/// `relative_name` are the actual parent/interface type nodes.
fn collect_inheritance(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    if matches!(node.kind(), "class_declaration" | "interface_declaration") {
        for child in node.children(&mut node.walk()) {
            if matches!(child.kind(), "base_clause" | "class_interface_clause") {
                for type_node in child.children(&mut child.walk()) {
                    if matches!(
                        type_node.kind(),
                        "name" | "qualified_name" | "relative_name"
                    ) {
                        super::push_ref(
                            out,
                            super::simple_type_name(node_text(&type_node, bytes), "\\"),
                            &type_node,
                            file,
                            RefRole::IsImplementation,
                        );
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

// ── Edge richness: Read / Write ─────────────────────────────────────────────

/// Extract the bare variable name (without `$`) from a `variable_name` node.
///
/// Tries `child_text(node, "name", bytes)` first (matches the grammar's `name`
/// child kind). Falls back to stripping the leading `$` from the full text,
/// mirroring `collect_bindings_dfs` and `collect_foreach_var`.
fn var_bare_name(node: &Node, bytes: &[u8]) -> String {
    child_text(node, "name", bytes)
        .unwrap_or_else(|| node_text(node, bytes).trim_start_matches('$').to_owned())
}

/// Returns `true` when a `variable_name` node is in a position that must NOT
/// be emitted as a [`RefRole::Read`]:
///
/// - LHS of an `assignment_expression` (field `left`) — Write, not Read.
/// - `name:` field of `simple_parameter`, `variadic_parameter`, or
///   `property_promotion_parameter` — that is a binding declaration.
/// - Direct `variable_name` child that is the loop-var binding inside a
///   `foreach_statement` — those are bindings; they will be reached via
///   `collect_foreach_var`. Detection: the node is a direct named child of
///   `foreach_statement` AND is not the first named child (the iterable).
fn is_non_read_var_position(node: &Node) -> bool {
    let parent = match node.parent() {
        Some(p) => p,
        None => return true,
    };
    match parent.kind() {
        // Assignment LHS → Write, not Read.
        "assignment_expression" => parent.child_by_field_name("left").as_ref() == Some(node),
        // Parameter binding declarations.
        "simple_parameter" | "variadic_parameter" | "property_promotion_parameter" => {
            parent.child_by_field_name("name").as_ref() == Some(node)
        }
        // foreach loop-var: the first named child is the iterable (a Read); any
        // subsequent non-body named child is a loop-var binding — skip as Read.
        "foreach_statement" => {
            let first = parent.named_children(&mut parent.walk()).next();
            let body = parent.child_by_field_name("body");
            // It's a binding if it's NOT the iterable (first named child) and NOT the body.
            first.as_ref() != Some(node) && body.as_ref() != Some(node)
        }
        _ => false,
    }
}

/// Recursively walk `node` and emit [`RefRole::Read`] for every `variable_name`
/// node that appears in a value/expression position.
///
/// The bare name (without `$`) is extracted via [`var_bare_name`] and checked
/// against [`MIN_REF_LEN`]. Positions skipped:
/// - Assignment LHS (field `left` of `assignment_expression`) — emitted as Write.
/// - Parameter declaration names (`simple_parameter` / `variadic_parameter` /
///   `property_promotion_parameter` `name:` field).
/// - foreach loop-variable bindings (the non-iterable named children of
///   `foreach_statement`).
///
/// `$this`, superglobals, and other special variables are emitted; they will
/// simply not resolve to any definition, which is correct and honest.
fn collect_read_references(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    if node.kind() == "variable_name" {
        let name = var_bare_name(node, bytes);
        if name.len() >= MIN_REF_LEN && !is_non_read_var_position(node) {
            push_ref(out, &name, node, file, RefRole::Read);
        }
        // variable_name has no meaningful children; return early.
        return;
    }
    for child in node.children(&mut node.walk()) {
        collect_read_references(&child, bytes, file, out);
    }
}

/// Recursively walk `node` and emit [`RefRole::Write`] for the `variable_name`
/// on the left side of an `assignment_expression`.
///
/// Member / subscript LHS (`$obj->prop = …`, `$arr[$i] = …`) are not covered
/// in v1 — only bare `variable_name` nodes. Applies [`MIN_REF_LEN`] to the
/// bare name (without `$`).
fn collect_write_references(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    if node.kind() == "assignment_expression" {
        if let Some(lhs) = node.child_by_field_name("left") {
            if lhs.kind() == "variable_name" {
                let name = var_bare_name(&lhs, bytes);
                if name.len() >= MIN_REF_LEN {
                    push_ref(out, &name, &lhs, file, RefRole::Write);
                }
            }
        }
    }
    for child in node.children(&mut node.walk()) {
        collect_write_references(&child, bytes, file, out);
    }
}

// ── Edge richness: TypeRef ───────────────────────────────────────────────────

/// Resolve a PHP type node to its leaf name node(s) and emit a
/// [`RefRole::TypeRef`] reference for each user-defined type encountered.
///
/// PHP type grammar (tree-sitter-php):
/// - `named_type` — wraps a `name` (simple) or `qualified_name` (namespaced).
/// - `primitive_type` — `int`, `string`, `bool`, `void`, `float`, `array`,
///   `callable`, `iterable`, `never`, `null`, `true`, `false` — SKIPPED.
/// - `union_type` — `A|B` — recurse each named child.
/// - `intersection_type` — `A&B` — recurse each named child.
/// - `optional_type` — `?T` (nullable shorthand) — recurse the named child.
/// - `name` / `qualified_name` (bare leaves in some grammar versions) — emit.
fn type_leaf(
    type_node: &Node,
    bytes: &[u8],
    file: &str,
    ctx: TypeRefContext,
    out: &mut Vec<Reference>,
) {
    match type_node.kind() {
        // Primitive types: int, string, bool, void, float, array, callable,
        // iterable, never, null, true, false — skip entirely.
        "primitive_type" => {}
        // `named_type` wraps either a `name` or a `qualified_name`.
        "named_type" => {
            for child in type_node.named_children(&mut type_node.walk()) {
                type_leaf(&child, bytes, file, ctx, out);
            }
        }
        // Union `A|B`, intersection `A&B`, optional `?T` — recurse each arm.
        "union_type" | "intersection_type" | "optional_type" => {
            for child in type_node.named_children(&mut type_node.walk()) {
                type_leaf(&child, bytes, file, ctx, out);
            }
        }
        // Simple unqualified name — emit directly.
        "name" => {
            let name = node_text(type_node, bytes);
            push_type_ref(out, name, type_node, file, ctx);
        }
        // Fully-qualified name like `App\Models\User` — emit the last segment.
        "qualified_name" => {
            let raw = node_text(type_node, bytes);
            let leaf = raw.rsplit('\\').next().unwrap_or(raw).trim();
            if !leaf.is_empty() {
                push_type_ref(out, leaf, type_node, file, ctx);
            }
        }
        // Relative name `namespace\Foo` — same strategy.
        "relative_name" => {
            let raw = node_text(type_node, bytes);
            let leaf = raw.rsplit('\\').next().unwrap_or(raw).trim();
            if !leaf.is_empty() {
                push_type_ref(out, leaf, type_node, file, ctx);
            }
        }
        _ => {}
    }
}

/// Recursively walk `node` and emit [`RefRole::TypeRef`] references for every
/// user-defined type that appears in a typed annotation position.
///
/// Covered positions (tree-sitter-php grammar):
/// - `simple_parameter` / `property_promotion_parameter` `type:` field → `ParameterType`
/// - `function_definition` / `method_declaration` `return_type:` field → `ReturnType`
/// - `property_declaration` `type:` field → `Field`
///
/// Primitive types (`int`, `string`, `bool`, `void`, …) are skipped via
/// [`type_leaf`]. No minimum-length filter is applied — short class names (e.g.
/// `IO`) are legitimate type references.
fn collect_type_references(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    match node.kind() {
        // Function / method parameters: `function f(Config $c)` or
        // constructor promotion: `public function __construct(public Config $c)`.
        "simple_parameter" | "property_promotion_parameter" => {
            if let Some(type_node) = node.child_by_field_name("type") {
                type_leaf(&type_node, bytes, file, TypeRefContext::ParameterType, out);
            }
        }
        // Function / method return types: `function f(): Config`.
        "function_definition" | "method_declaration" => {
            if let Some(ret_node) = node.child_by_field_name("return_type") {
                // The `return_type` field in tree-sitter-php is the type node
                // directly (no wrapping annotation node).
                type_leaf(&ret_node, bytes, file, TypeRefContext::ReturnType, out);
            }
            // Recurse into body so nested function definitions are covered.
            for child in node.children(&mut node.walk()) {
                collect_type_references(&child, bytes, file, out);
            }
            return; // avoid double-recurse
        }
        // Typed property declarations: `public Config $conf;`
        "property_declaration" => {
            if let Some(type_node) = node.child_by_field_name("type") {
                type_leaf(&type_node, bytes, file, TypeRefContext::Field, out);
            }
        }
        _ => {}
    }

    for child in node.children(&mut node.walk()) {
        collect_type_references(&child, bytes, file, out);
    }
}

// ── Scope tree (Tier-B) ──────────────────────────────────────────────────────

/// Build the lexical scope tree for one PHP file.
///
/// `scopes[0]` is always the file-root `Module` scope spanning `[0, source_len)`.
/// PHP opens scopes for:
/// - `namespace_definition` (block form) → `Type` scope
/// - Type declarations (`class_declaration`, `interface_declaration`,
///   `trait_declaration`, `enum_declaration`) → `Type` scope
/// - Function / method / closure / arrow-function definitions → `Function` scope
/// - Bare `compound_statement` not already peeled as a function body → `Block`
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

/// DFS opening scopes for PHP declaration nodes.
///
/// Uses the "peel-the-body" pattern so the body block does not double-open
/// an extra scope.  Arrow functions are an exception: their body is a bare
/// expression, so we recurse the whole node's children under the new scope.
fn scope_dfs(node: &Node, parent_id: ScopeId, scopes: &mut Vec<Scope>) {
    match node.kind() {
        "namespace_definition" => {
            // Block-form namespace: `namespace App { ... }` — open a Type scope
            // and recurse the compound_statement body's CHILDREN.
            // Statement-form namespace has no `body` field; recurse children
            // under the same parent (no new scope).
            if let Some(body) = node.child_by_field_name("body") {
                let ns_id = push_scope(scopes, Some(parent_id), node_span(node), ScopeKind::Type);
                for child in body.children(&mut body.walk()) {
                    scope_dfs(&child, ns_id, scopes);
                }
            } else {
                for child in node.children(&mut node.walk()) {
                    scope_dfs(&child, parent_id, scopes);
                }
            }
        }
        "class_declaration"
        | "interface_declaration"
        | "trait_declaration"
        | "enum_declaration" => {
            let type_id = push_scope(scopes, Some(parent_id), node_span(node), ScopeKind::Type);
            // Peel the body (declaration_list / enum_declaration_list).
            if let Some(body) = node.child_by_field_name("body") {
                for child in body.children(&mut body.walk()) {
                    scope_dfs(&child, type_id, scopes);
                }
            }
        }
        "function_definition" | "method_declaration" | "anonymous_function" => {
            let fn_id = push_scope(
                scopes,
                Some(parent_id),
                node_span(node),
                ScopeKind::Function,
            );
            // Abstract methods have no body — handle None.
            if let Some(body) = node.child_by_field_name("body") {
                for child in body.children(&mut body.walk()) {
                    scope_dfs(&child, fn_id, scopes);
                }
            }
        }
        "arrow_function" => {
            // Arrow function body is an `expression`, not a compound_statement.
            // Recurse the whole node's children under the new Function scope.
            let fn_id = push_scope(
                scopes,
                Some(parent_id),
                node_span(node),
                ScopeKind::Function,
            );
            for child in node.children(&mut node.walk()) {
                scope_dfs(&child, fn_id, scopes);
            }
        }
        "compound_statement" => {
            // A bare block NOT already consumed as a function/method body.
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

/// Collect parameter and local-variable [`Binding`]s for one PHP file.
///
/// Covers:
/// - `function_definition` / `method_declaration` / `anonymous_function` /
///   `arrow_function` parameters → [`BindingKind::Param`].
/// - `assignment_expression` with a `variable_name` on the left → [`BindingKind::Local`]
///   (only when the innermost scope is `Function` or `Block`).
/// - `foreach_statement` loop variables → [`BindingKind::Local`] (same guard).
///
/// Class properties (which live in a `Type` scope) are intentionally excluded
/// from `Local` — they are covered by `definition_bindings` as `Definition`.
fn collect_bindings(root: &Node, bytes: &[u8], scopes: &[Scope]) -> Vec<Binding> {
    let mut out = Vec::new();
    collect_bindings_dfs(root, bytes, scopes, &mut out);
    out
}

fn collect_bindings_dfs(node: &Node, bytes: &[u8], scopes: &[Scope], out: &mut Vec<Binding>) {
    match node.kind() {
        "function_definition" | "method_declaration" | "anonymous_function" | "arrow_function" => {
            if let Some(params) = node.child_by_field_name("parameters") {
                collect_params(&params, bytes, scopes, out);
            }
            for child in node.children(&mut node.walk()) {
                collect_bindings_dfs(&child, bytes, scopes, out);
            }
        }
        "assignment_expression" => {
            if let Some(left) = node.child_by_field_name("left") {
                if left.kind() == "variable_name" {
                    let name = child_text(&left, "name", bytes).unwrap_or_else(|| {
                        node_text(&left, bytes).trim_start_matches('$').to_owned()
                    });
                    if !name.is_empty() {
                        let intro = left.start_byte();
                        if let Some(sid) = innermost_scope(intro, scopes) {
                            if matches!(scopes[sid].kind, ScopeKind::Function | ScopeKind::Block) {
                                push_binding(out, name, intro, BindingKind::Local, scopes);
                            }
                        }
                    }
                }
            }
            for child in node.children(&mut node.walk()) {
                collect_bindings_dfs(&child, bytes, scopes, out);
            }
        }
        "foreach_statement" => {
            let body = node.child_by_field_name("body");
            // named_children: the iterable is always the FIRST named child;
            // remaining non-body children are the loop variable(s).
            // `expression`, `pair`, `list_literal`, and `by_ref` are the grammar
            // child types, but concrete kinds may be `variable_name`, `pair`, etc.
            let mut first_seen = false;
            for child in node.named_children(&mut node.walk()) {
                // Skip the body node.
                if let Some(ref b) = body {
                    if child == *b {
                        continue;
                    }
                }
                // Skip the first named child (the iterable expression).
                if !first_seen {
                    first_seen = true;
                    continue;
                }
                // Remaining children are the value (and optionally key) vars.
                collect_foreach_var(&child, bytes, scopes, out);
            }
            // Recurse children for nested bindings inside the body.
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

/// Recursively find `variable_name` leaves in a foreach loop-var node and emit
/// `Local` bindings for each (applying the Function|Block scope guard).
///
/// Handles simple vars (`$item`), `by_ref` (`&$item`), `pair` (`$k => $v`),
/// and `list_literal` destructuring.
fn collect_foreach_var(node: &Node, bytes: &[u8], scopes: &[Scope], out: &mut Vec<Binding>) {
    if node.kind() == "variable_name" {
        let name = child_text(node, "name", bytes)
            .unwrap_or_else(|| node_text(node, bytes).trim_start_matches('$').to_owned());
        if !name.is_empty() {
            let intro = node.start_byte();
            if let Some(sid) = innermost_scope(intro, scopes) {
                if matches!(scopes[sid].kind, ScopeKind::Function | ScopeKind::Block) {
                    push_binding(out, name, intro, BindingKind::Local, scopes);
                }
            }
        }
        return;
    }
    for child in node.named_children(&mut node.walk()) {
        collect_foreach_var(&child, bytes, scopes, out);
    }
}

/// Emit a [`BindingKind::Param`] for each named parameter in a PHP
/// `formal_parameters` node.
///
/// Handles `simple_parameter`, `variadic_parameter`, and
/// `property_promotion_parameter` (constructor promotion). For
/// `property_promotion_parameter`, the `name` field may be a `by_ref` node
/// wrapping the `variable_name` — we descend one level in that case.
/// Binding names are stored WITHOUT the leading `$`.
fn collect_params(params: &Node, bytes: &[u8], scopes: &[Scope], out: &mut Vec<Binding>) {
    for child in params.named_children(&mut params.walk()) {
        match child.kind() {
            "simple_parameter" | "variadic_parameter" | "property_promotion_parameter" => {
                let Some(name_node) = child.child_by_field_name("name") else {
                    continue;
                };
                // For property_promotion_parameter, `name` may be `by_ref` (e.g.
                // `public int &$x`) which wraps the actual `variable_name`.
                let var_node = if name_node.kind() == "by_ref" {
                    name_node
                        .named_children(&mut name_node.walk())
                        .find(|c| c.kind() == "variable_name")
                } else if name_node.kind() == "variable_name" {
                    Some(name_node)
                } else {
                    None
                };
                let Some(var) = var_node else {
                    continue;
                };
                let name = child_text(&var, "name", bytes)
                    .unwrap_or_else(|| node_text(&var, bytes).trim_start_matches('$').to_owned());
                if name.is_empty() {
                    continue;
                }
                let intro = var.start_byte();
                push_binding(out, name, intro, BindingKind::Param, scopes);
            }
            _ => {}
        }
    }
}

/// Build a [`Symbol`] and push it onto `out`.
fn push_symbol(
    out: &mut Vec<Symbol>,
    ctx: &ExtractCtx,
    node: &Node,
    name: String,
    kind: SymbolKind,
    visibility: Visibility,
    descriptors: Vec<Descriptor>,
) {
    let signature = one_line_signature(node_text(node, ctx.bytes), &['{', ';']);
    out.push(make_symbol(
        ctx,
        node,
        name,
        kind,
        visibility,
        descriptors,
        signature,
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_namespaced_defs() {
        let src = r#"<?php
namespace App\Auth;

function format_id($x) { return helper($x); }

class Session {
    const MAX = 3;
    public $token;
    private $secret;
    public function validate($t) { return $this->check($t); }
    private function internal() {}
}

interface Reader {
    function read();
}
"#;
        let facts = PhpExtractor.extract(src, "src/app/Session.php").unwrap();

        let by_name = |n: &str| facts.symbols.iter().find(|s| s.name == n).cloned();

        // Top-level function.
        let format_id = by_name("format_id").unwrap();
        assert_eq!(format_id.kind, SymbolKind::Function);
        assert_eq!(
            format_id.id.to_scip_string(),
            "codegraph . . . App/Auth/format_id()."
        );

        // Class symbol.
        let session = by_name("Session").unwrap();
        assert_eq!(session.kind, SymbolKind::Class);
        assert_eq!(
            session.id.to_scip_string(),
            "codegraph . . . App/Auth/Session#"
        );

        // Class constant.
        let max = by_name("MAX").unwrap();
        assert_eq!(max.kind, SymbolKind::Const);
        assert_eq!(
            max.id.to_scip_string(),
            "codegraph . . . App/Auth/Session#MAX."
        );

        // Public property.
        let token = by_name("token").unwrap();
        assert_eq!(token.kind, SymbolKind::Static);
        assert_eq!(
            token.id.to_scip_string(),
            "codegraph . . . App/Auth/Session#token."
        );
        assert_eq!(token.visibility, Visibility::Public);

        // Private property IS now emitted, tagged Private.
        let secret = by_name("secret").unwrap();
        assert_eq!(secret.kind, SymbolKind::Static);
        assert_eq!(secret.visibility, Visibility::Private);

        // Public method.
        let validate = by_name("validate").unwrap();
        assert_eq!(validate.kind, SymbolKind::Method);
        assert_eq!(
            validate.id.to_scip_string(),
            "codegraph . . . App/Auth/Session#validate()."
        );
        assert_eq!(validate.visibility, Visibility::Public);

        // Private method IS now emitted, tagged Private.
        let internal = by_name("internal").unwrap();
        assert_eq!(internal.kind, SymbolKind::Method);
        assert_eq!(internal.visibility, Visibility::Private);

        // Interface symbol.
        let reader = by_name("Reader").unwrap();
        assert_eq!(reader.kind, SymbolKind::Interface);
        assert_eq!(
            reader.id.to_scip_string(),
            "codegraph . . . App/Auth/Reader#"
        );

        // Interface method — implicitly public, no `public` modifier.
        let read = by_name("read").unwrap();
        assert_eq!(read.kind, SymbolKind::Method);
        assert_eq!(
            read.id.to_scip_string(),
            "codegraph . . . App/Auth/Reader#read()."
        );

        assert_eq!(facts.lang, "php");
    }

    #[test]
    fn path_fallback_without_namespace() {
        let src = r#"<?php
function format_date($d) {}
"#;
        let facts = PhpExtractor.extract(src, "src/helpers.php").unwrap();
        let by_name = |n: &str| facts.symbols.iter().find(|s| s.name == n).cloned();

        let format_date = by_name("format_date").unwrap();
        assert_eq!(format_date.kind, SymbolKind::Function);
        assert_eq!(
            format_date.id.to_scip_string(),
            "codegraph . . . helpers/format_date()."
        );
    }

    #[test]
    fn extracts_class_extends_and_implements() {
        let src = "<?php\nclass Foo extends Bar implements Baz {}";
        let facts = PhpExtractor.extract(src, "src/Foo.php").unwrap();

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
    fn extracts_interface_extends_reference() {
        let src = "<?php\ninterface I extends J {}";
        let facts = PhpExtractor.extract(src, "src/I.php").unwrap();

        let inherit_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            inherit_names.contains(&"J"),
            "expected 'J' in {inherit_names:?}"
        );
    }

    #[test]
    fn strips_namespace_from_parent_name() {
        let src = r"<?php
class C extends \App\Base {}";
        let facts = PhpExtractor.extract(src, "src/C.php").unwrap();

        let inherit_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            inherit_names.contains(&"Base"),
            "expected 'Base' (leaf of \\App\\Base) in {inherit_names:?}"
        );
    }

    #[test]
    fn import_simple_use_statement() {
        let src = "<?php\nuse App\\Models\\User;";
        let facts = PhpExtractor.extract(src, "src/Foo.php").unwrap();

        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            import_names.contains(&"User"),
            "expected 'User' in {import_names:?}"
        );
        assert_eq!(import_names.len(), 1);
    }

    #[test]
    fn import_aliased_use_statement_uses_real_name() {
        let src = "<?php\nuse App\\Models\\User as U;";
        let facts = PhpExtractor.extract(src, "src/Foo.php").unwrap();

        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            import_names.contains(&"User"),
            "expected 'User' (real name, not alias) in {import_names:?}"
        );
        // Alias 'U' must not appear as an import reference.
        assert!(
            !import_names.contains(&"U"),
            "alias 'U' must not appear in {import_names:?}"
        );
        assert_eq!(import_names.len(), 1);
    }

    #[test]
    fn import_grouped_use_statement() {
        let src = "<?php\nuse App\\Models\\{User, Post};";
        let facts = PhpExtractor.extract(src, "src/Foo.php").unwrap();

        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            import_names.contains(&"User"),
            "expected 'User' in {import_names:?}"
        );
        assert!(
            import_names.contains(&"Post"),
            "expected 'Post' in {import_names:?}"
        );
        assert_eq!(import_names.len(), 2);
    }

    #[test]
    fn extracts_call_references() {
        let src = r#"<?php
function run() {
    validate("t");
    $obj->process($data);
}
"#;
        let facts = PhpExtractor.extract(src, "src/main.php").unwrap();
        let names: Vec<&str> = facts.references.iter().map(|r| r.name.as_str()).collect();
        assert!(
            names.contains(&"validate"),
            "expected 'validate' in {names:?}"
        );
        assert!(
            names.contains(&"process"),
            "expected 'process' in {names:?}"
        );
    }

    // ── Tier-B scope / binding tests ─────────────────────────────────────────

    #[test]
    fn func_params_emit_param_bindings() {
        // `function greet(string $name, int $age) {}` → Param `name`, `age`.
        let src = "<?php\nfunction greet(string $name, int $age) {}\n";
        let facts = PhpExtractor.extract(src, "src/greet.php").unwrap();

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
            vec![("age", fn_scope_id), ("name", fn_scope_id)],
            "expected Param bindings for age and name, got {param_names:?}"
        );
    }

    #[test]
    fn assignment_local_in_function() {
        // `function f(): int { $r = 42; return $r; }` → Local `r` (not a Param).
        let src = "<?php\nfunction f(): int { $r = 42; return $r; }\n";
        let facts = PhpExtractor.extract(src, "src/f.php").unwrap();

        let r = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Local && b.name == "r")
            .expect("expected a Local binding for 'r'");
        assert_eq!(
            facts.scopes[r.scope].kind,
            ScopeKind::Function,
            "Local 'r' should be in a Function scope"
        );
        assert!(
            !facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Param && b.name == "r"),
            "'r' must not be a Param binding"
        );
    }

    #[test]
    fn foreach_value_is_local() {
        // `function run(array $items) { foreach ($items as $item) {} }`
        // → Param `items`, Local `item`.
        let src = "<?php\nfunction run(array $items) { foreach ($items as $item) {} }\n";
        let facts = PhpExtractor.extract(src, "src/run.php").unwrap();

        assert!(
            facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Param && b.name == "items"),
            "expected Param binding for 'items'"
        );
        assert!(
            facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Local && b.name == "item"),
            "expected Local binding for 'item'"
        );
    }

    #[test]
    fn class_property_is_definition_not_local() {
        // `class Foo { public string $bar; }` → NO Local `bar`; Definition `bar` exists.
        let src = "<?php\nclass Foo { public string $bar; }\n";
        let facts = PhpExtractor.extract(src, "src/Foo.php").unwrap();

        assert!(
            !facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Local && b.name == "bar"),
            "class property 'bar' must NOT be a Local binding"
        );
        assert!(
            facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Definition && b.name == "bar"),
            "expected a Definition binding for 'bar'"
        );
    }

    #[test]
    fn nesting_class_method_produces_correct_scopes() {
        // `class S { public function h() { $x = 1; } }`
        // → Type scope (class body) + Function scope (method); Local `x` in Function.
        let src = "<?php\nclass S { public function h() { $x = 1; } }\n";
        let facts = PhpExtractor.extract(src, "src/S.php").unwrap();

        assert_eq!(
            facts.scopes[0].kind,
            ScopeKind::Module,
            "scopes[0] must be Module"
        );

        let type_scope_id = facts
            .scopes
            .iter()
            .position(|s| s.kind == ScopeKind::Type)
            .expect("expected a Type scope for the class");
        let fn_scope_id = facts
            .scopes
            .iter()
            .position(|s| s.kind == ScopeKind::Function)
            .expect("expected a Function scope for the method");

        assert_eq!(
            facts.scopes[type_scope_id].parent,
            Some(0),
            "Type scope parent must be Module (0)"
        );
        assert_eq!(
            facts.scopes[fn_scope_id].parent,
            Some(type_scope_id),
            "Function scope parent must be the Type scope"
        );

        let x = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Local && b.name == "x")
            .expect("expected a Local binding for 'x'");
        assert_eq!(
            facts.scopes[x.scope].kind,
            ScopeKind::Function,
            "Local 'x' must be in a Function scope"
        );
    }

    #[test]
    fn namespace_body_type_scope_local_in_function() {
        // `namespace App { function init() { $v = 1; } }`
        // → Type scope for namespace; Local `v` in Function scope (NOT in Type scope).
        let src = "<?php\nnamespace App { function init() { $v = 1; } }\n";
        let facts = PhpExtractor.extract(src, "src/App.php").unwrap();

        let v = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Local && b.name == "v")
            .expect("expected a Local binding for 'v'");
        assert_eq!(
            facts.scopes[v.scope].kind,
            ScopeKind::Function,
            "Local 'v' must be in a Function scope, not the namespace Type scope"
        );
    }

    #[test]
    fn closure_and_arrow_params() {
        // `function f() { $g = function(int $x) { return $x; }; $h = fn(int $y) => $y; }`
        // → Param `x` and `y`.
        let src = "<?php\nfunction f() { $g = function(int $x) { return $x; }; $h = fn(int $y) => $y; }\n";
        let facts = PhpExtractor.extract(src, "src/f.php").unwrap();

        let params: Vec<&str> = facts
            .bindings
            .iter()
            .filter(|b| b.kind == BindingKind::Param)
            .map(|b| b.name.as_str())
            .collect();
        assert!(params.contains(&"x"), "expected Param 'x', got {params:?}");
        assert!(params.contains(&"y"), "expected Param 'y', got {params:?}");
    }

    #[test]
    fn constructor_promoted_param_is_param_not_local() {
        // `class Box { public function __construct(public int $size) {} }`
        // → Param `size`, not Local.
        let src = "<?php\nclass Box { public function __construct(public int $size) {} }\n";
        let facts = PhpExtractor.extract(src, "src/Box.php").unwrap();

        assert!(
            facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Param && b.name == "size"),
            "expected Param binding for 'size'"
        );
        assert!(
            !facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Local && b.name == "size"),
            "'size' must not be a Local binding"
        );
    }

    #[test]
    fn same_file_call_ref_has_non_zero_scope() {
        // `function helper(): int { return 0; }` called from `run()`.
        // The `helper` Call ref must have scope == Some(non-zero).
        let src = "<?php\nfunction helper(): int { return 0; }\nfunction run(): int { return helper(); }\n";
        let facts = PhpExtractor.extract(src, "src/main.php").unwrap();

        assert!(
            facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Definition && b.name == "helper"),
            "expected a Definition binding for 'helper'"
        );

        let helper_ref = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Call && r.name == "helper")
            .expect("expected a Call ref for 'helper'");
        let scope_id = helper_ref
            .scope
            .expect("helper() Call ref must have a scope attached");
        assert_ne!(
            scope_id, 0,
            "helper() Call ref scope must not be the module root"
        );
    }

    // ── Edge richness: Read / Write ──────────────────────────────────────────

    #[test]
    fn php_read_ref_at_use_not_at_declaration() {
        // `function f() { $base = 1; return $base; }`
        // The assignment LHS `$base` is a Write (not a Read).
        // The `$base` in `return $base` is a Read.
        // Bare name must be "base" (no `$`), length >= MIN_REF_LEN (3).
        let src = "<?php\nfunction f() { $base = 1; return $base; }\n";
        let facts = PhpExtractor.extract(src, "src/f.php").unwrap();

        let read_refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Read && r.name == "base")
            .collect();
        assert!(
            !read_refs.is_empty(),
            "expected at least one Read ref for 'base', got none; all refs: {:?}",
            facts
                .references
                .iter()
                .map(|r| (&r.name, r.role))
                .collect::<Vec<_>>()
        );
        // At least one Read ref must be at the use site (after the assignment).
        // In the source "<?php\nfunction f() { $base = 1; return $base; }\n"
        // the assignment ends at roughly byte 30; the return use is after that.
        let use_ref = read_refs.iter().find(|r| r.occ.byte > 20);
        assert!(
            use_ref.is_some(),
            "expected a Read ref for 'base' at the return site (byte > 20); refs: {read_refs:?}"
        );
    }

    #[test]
    fn php_write_ref_for_assignment() {
        // `function f() { $cnt = 0; $cnt = 5; }` → at least one Write ref "cnt".
        let src = "<?php\nfunction f() { $cnt = 0; $cnt = 5; }\n";
        let facts = PhpExtractor.extract(src, "src/f.php").unwrap();

        let write_refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Write && r.name == "cnt")
            .collect();
        assert!(
            !write_refs.is_empty(),
            "expected at least one Write ref for 'cnt', got none; all refs: {:?}",
            facts
                .references
                .iter()
                .map(|r| (&r.name, r.role))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn php_function_call_not_a_read() {
        // `helper()` is a bare function call — its name node is `name` kind, NOT
        // `variable_name`, so collect_read_references must not emit a Read for it.
        let src = "<?php\nfunction f() { helper(); }\n";
        let facts = PhpExtractor.extract(src, "src/f.php").unwrap();

        let read_refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Read && r.name == "helper")
            .collect();
        assert!(
            read_refs.is_empty(),
            "helper() must NOT produce a Read ref; got: {read_refs:?}"
        );
        // The Call ref should exist.
        let call_refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Call && r.name == "helper")
            .collect();
        assert!(
            !call_refs.is_empty(),
            "expected a Call ref for 'helper'; all refs: {:?}",
            facts
                .references
                .iter()
                .map(|r| (&r.name, r.role))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn php_param_decl_not_a_read_but_use_is() {
        // `function f(int $val) { return $val; }`
        // The `$val` in the parameter list is a binding, NOT a Read.
        // The `$val` in `return $val` IS a Read.
        let src = "<?php\nfunction f(int $val) { return $val; }\n";
        let facts = PhpExtractor.extract(src, "src/f.php").unwrap();

        let read_refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Read && r.name == "val")
            .collect();
        // At least one Read ref must exist (the use in the return).
        assert!(
            !read_refs.is_empty(),
            "expected at least one Read ref for 'val' at the return site"
        );
        // None of the Read refs should be at the parameter declaration byte.
        // The `$val` parameter appears early in the source (roughly bytes 20–24).
        // The return use is further along (after the `{`).
        let decl_read = read_refs.iter().find(|r| r.occ.byte < 25);
        assert!(
            decl_read.is_none(),
            "param declaration '$val' must NOT be a Read ref; found one at byte {:?}",
            decl_read.map(|r| r.occ.byte)
        );
    }

    // ── TypeRef tests ────────────────────────────────────────────────────────

    #[test]
    fn php_param_type_ref_emitted() {
        // `function f(Config $c) {}` → TypeRef "Config" with ParameterType ctx.
        let src = "<?php\nfunction f(Config $c) {}\n";
        let facts = PhpExtractor.extract(src, "src/f.php").unwrap();
        let r = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::TypeRef && r.name == "Config")
            .expect("expected TypeRef ref for 'Config'");
        assert_eq!(
            r.type_ref_ctx,
            Some(TypeRefContext::ParameterType),
            "expected ParameterType ctx, got {:?}",
            r.type_ref_ctx
        );
    }

    #[test]
    fn php_return_type_ref_emitted() {
        // `function f(): Config { return x(); }` → TypeRef "Config" with ReturnType ctx.
        let src = "<?php\nfunction f(): Config { return x(); }\n";
        let facts = PhpExtractor.extract(src, "src/f.php").unwrap();
        let r = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::TypeRef && r.name == "Config")
            .expect("expected TypeRef ref for 'Config'");
        assert_eq!(
            r.type_ref_ctx,
            Some(TypeRefContext::ReturnType),
            "expected ReturnType ctx, got {:?}",
            r.type_ref_ctx
        );
    }

    #[test]
    fn php_typed_property_type_ref_emitted() {
        // `class C { public Config $conf; }` → TypeRef "Config" with Field ctx.
        let src = "<?php\nclass C { public Config $conf; }\n";
        let facts = PhpExtractor.extract(src, "src/C.php").unwrap();
        let r = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::TypeRef && r.name == "Config")
            .expect("expected TypeRef ref for 'Config'");
        assert_eq!(
            r.type_ref_ctx,
            Some(TypeRefContext::Field),
            "expected Field ctx, got {:?}",
            r.type_ref_ctx
        );
    }

    #[test]
    fn php_primitive_param_type_not_emitted() {
        // `function f(int $n) {}` → NO TypeRef for "int" (primitive_type).
        let src = "<?php\nfunction f(int $n) {}\n";
        let facts = PhpExtractor.extract(src, "src/f.php").unwrap();
        let prim_refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::TypeRef && r.name == "int")
            .collect();
        assert!(
            prim_refs.is_empty(),
            "primitive 'int' must NOT produce a TypeRef; got: {prim_refs:?}"
        );
    }

    // ── Visibility tests ──────────────────────────────────────────────────────

    #[test]
    fn visibility_public_method_tagged_public() {
        // `public function` → Visibility::Public.
        let src = "<?php\nclass C { public function foo() {} }\n";
        let facts = PhpExtractor.extract(src, "src/C.php").unwrap();
        let sym = facts
            .symbols
            .iter()
            .find(|s| s.name == "foo")
            .expect("expected symbol 'foo'");
        assert_eq!(
            sym.visibility,
            Visibility::Public,
            "public function must be tagged Public"
        );
    }

    #[test]
    fn visibility_private_method_emitted_and_tagged_private() {
        // `private function` → emitted with Visibility::Private.
        let src = "<?php\nclass C { private function secret() {} }\n";
        let facts = PhpExtractor.extract(src, "src/C.php").unwrap();
        let sym = facts
            .symbols
            .iter()
            .find(|s| s.name == "secret")
            .expect("private method 'secret' must be emitted");
        assert_eq!(
            sym.visibility,
            Visibility::Private,
            "private function must be tagged Private"
        );
    }

    #[test]
    fn visibility_protected_method_emitted_and_tagged_protected() {
        // `protected function` → emitted with Visibility::Protected.
        let src = "<?php\nclass C { protected function hook() {} }\n";
        let facts = PhpExtractor.extract(src, "src/C.php").unwrap();
        let sym = facts
            .symbols
            .iter()
            .find(|s| s.name == "hook")
            .expect("protected method 'hook' must be emitted");
        assert_eq!(
            sym.visibility,
            Visibility::Protected,
            "protected function must be tagged Protected"
        );
    }

    #[test]
    fn visibility_no_modifier_method_defaults_to_public() {
        // Interface method with no modifier → Visibility::Public (implicit).
        let src = "<?php\ninterface I { function read(); }\n";
        let facts = PhpExtractor.extract(src, "src/I.php").unwrap();
        let sym = facts
            .symbols
            .iter()
            .find(|s| s.name == "read")
            .expect("interface method 'read' must be emitted");
        assert_eq!(
            sym.visibility,
            Visibility::Public,
            "method without modifier must default to Public"
        );
    }

    #[test]
    fn visibility_all_modifiers_in_one_class() {
        // Class with public, protected, and private members — all three emitted
        // with correct visibility tags.
        let src = r#"<?php
class Multi {
    public function pub_fn() {}
    protected function prot_fn() {}
    private function priv_fn() {}
    public $pub_prop;
    protected $prot_prop;
    private $priv_prop;
}
"#;
        let facts = PhpExtractor.extract(src, "src/Multi.php").unwrap();
        let by_name = |n: &str| facts.symbols.iter().find(|s| s.name == n).cloned();

        assert_eq!(by_name("pub_fn").unwrap().visibility, Visibility::Public);
        assert_eq!(
            by_name("prot_fn").unwrap().visibility,
            Visibility::Protected
        );
        assert_eq!(by_name("priv_fn").unwrap().visibility, Visibility::Private);
        assert_eq!(by_name("pub_prop").unwrap().visibility, Visibility::Public);
        assert_eq!(
            by_name("prot_prop").unwrap().visibility,
            Visibility::Protected
        );
        assert_eq!(
            by_name("priv_prop").unwrap().visibility,
            Visibility::Private
        );
    }

    #[test]
    fn visibility_top_level_function_is_public() {
        // A free top-level function has no visibility modifier; it must be Public.
        let src = "<?php\nfunction helper() {}\n";
        let facts = PhpExtractor.extract(src, "src/helpers.php").unwrap();
        let sym = facts
            .symbols
            .iter()
            .find(|s| s.name == "helper")
            .expect("expected symbol 'helper'");
        assert_eq!(
            sym.visibility,
            Visibility::Public,
            "top-level function must be tagged Public"
        );
    }
}
