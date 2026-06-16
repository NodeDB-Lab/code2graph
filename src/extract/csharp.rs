// SPDX-License-Identifier: Apache-2.0

//! C# extractor — one tree-sitter pass yielding definitions and references.
//!
//! Definitions: non-`private` type declarations (`class`, `struct`, `interface`,
//! `enum`, `record`) and their non-`private` members (methods, constructors,
//! properties, fields, enum members). Interface members are treated as implicitly
//! public. Qualified identity follows the `namespace_declaration` or
//! `file_scoped_namespace_declaration` if present; otherwise falls back to a
//! path-derived namespace.
//!
//! References: callee identifiers from `invocation_expression` (free calls and
//! member calls), `object_creation_expression` (constructor calls), inheritance
//! via `base_list`, and `using_directive` imports.
//!
//! Emits neutral [`FileFacts`] — no storage entries, no source bodies.

use tree_sitter::{Node, Parser};

use crate::error::{CodegraphError, Result};
use crate::graph::types::{
    Binding, BindingKind, ByteSpan, FileFacts, RefRole, Reference, Scope, ScopeId, ScopeKind,
    Symbol, SymbolKind, TypeRefContext, Visibility,
};
use crate::lang::Language;
use crate::symbol::{Descriptor, SymbolId};

use super::{
    Extractor, MIN_REF_LEN, attach_reference_scopes, collect_call_references, definition_bindings,
    field_text, import_bindings, innermost_scope, node_span, node_text, one_line_signature,
    push_binding, push_import_ref, push_ref, push_scope, push_type_ref, simple_type_name,
};

/// Tree-sitter query capturing call-callee identifiers.
///
/// Pattern 1: free call `Foo()` — identifier/generic_name directly under invocation_expression's `function` field.
/// Pattern 2: member call `obj.Foo()` — member_access_expression under `function` field; captures
///            receiver as `@qualifier` and final name as `@callee`.
/// Pattern 3: constructor call `new Foo(...)` — type identifier under object_creation_expression.
const CALL_QUERY: &str = r#"
[
  (invocation_expression function: (identifier) @callee)
  (invocation_expression function: (generic_name (identifier) @callee))
  (invocation_expression function: (member_access_expression expression: (_) @qualifier name: (identifier) @callee))
  (invocation_expression function: (member_access_expression expression: (_) @qualifier name: (generic_name (identifier) @callee)))
  (object_creation_expression type: (identifier) @callee)
  (object_creation_expression type: (qualified_name name: (identifier) @callee))
  (object_creation_expression type: (generic_name (identifier) @callee))
]
"#;

/// Extracts C# symbols and references.
pub struct CSharpExtractor;

impl Extractor for CSharpExtractor {
    fn lang(&self) -> Language {
        Language::CSharp
    }

    fn extract(&self, source: &str, file: &str) -> Result<FileFacts> {
        let ts_language = crate::grammar::csharp();
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
        let namespaces = csharp_namespaces(&root, bytes, file);

        let defs = collect_symbols(&root, bytes, file, &namespaces);
        let def_bindings = definition_bindings(&defs);
        let mut symbols = defs;
        let mod_sym = super::module_symbol(Language::CSharp, &namespaces, file, source.len());
        let module_id = mod_sym.id.to_scip_string();
        symbols.push(mod_sym);

        let mut references = collect_call_references(
            &root,
            &ts_language,
            CALL_QUERY,
            Language::CSharp,
            bytes,
            file,
        )?;
        collect_inheritance(&root, bytes, file, &mut references);
        collect_imports(&root, bytes, file, &mut references, &module_id);
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
            lang: Language::CSharp.as_str().to_owned(),
            symbols,
            references,
            scopes,
            bindings,
            ffi_exports: Vec::new(),
        })
    }
}

// ── Namespace derivation ─────────────────────────────────────────────────────

/// Derive namespace descriptors from the `namespace_declaration` or
/// `file_scoped_namespace_declaration`, falling back to path-derived segments.
///
/// With a namespace: `namespace A.B.C { … }` → `["A", "B", "C"]`.
/// File-scoped: `namespace A.B.C;` → same.
/// Without: `src/A/B/MyClass.cs` → `["A", "B", "MyClass"]`.
fn csharp_namespaces(root: &Node, bytes: &[u8], file: &str) -> Vec<String> {
    // Search among compilation_unit's direct children.
    for child in root.children(&mut root.walk()) {
        let kind = child.kind();
        if kind != "namespace_declaration" && kind != "file_scoped_namespace_declaration" {
            continue;
        }
        if let Some(name_node) = child.child_by_field_name("name") {
            let text = node_text(&name_node, bytes);
            return text
                .split('.')
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect();
        }
    }

    // Fallback: derive from file path (strip `.cs`, strip leading `src/`).
    let p = file.strip_suffix(".cs").unwrap_or(file);
    let p = p.strip_prefix("src/").unwrap_or(p);
    p.split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

// ── Visibility ───────────────────────────────────────────────────────────────

/// Returns `true` if the declaration should be emitted (not `private`).
///
/// C# declarations have zero or more `modifier` sibling children. We scan them:
/// if `"private"` is found the symbol is suppressed. Everything else (public,
/// protected, internal, or no modifier → default accessibility) is emitted.
/// Interface members carry no modifiers but are implicitly public.
fn is_visible(node: &Node, bytes: &[u8]) -> bool {
    for child in node.children(&mut node.walk()) {
        if child.kind() == "modifier" && node_text(&child, bytes) == "private" {
            return false;
        }
    }
    true
}

// ── Symbol collection ────────────────────────────────────────────────────────

fn collect_symbols(root: &Node, bytes: &[u8], file: &str, namespaces: &[String]) -> Vec<Symbol> {
    let mut out = Vec::new();
    let ns_descriptors: Vec<Descriptor> = namespaces
        .iter()
        .cloned()
        .map(Descriptor::Namespace)
        .collect();

    // Walk looking for namespace or type declarations at the top level.
    collect_types_in(root, bytes, file, &ns_descriptors, false, &mut out);
    out
}

/// Recursively collect type (class/struct/interface/enum/record) declarations
/// and their members from `node`, building descriptor paths from `prefix`.
///
/// `implicit_public` is true when we are inside an interface body (all members
/// are implicitly public regardless of modifiers).
fn collect_types_in(
    node: &Node,
    bytes: &[u8],
    file: &str,
    prefix: &[Descriptor],
    implicit_public: bool,
    out: &mut Vec<Symbol>,
) {
    for child in node.children(&mut node.walk()) {
        match child.kind() {
            // Namespace block — recurse with the same prefix; the namespace
            // descriptors were already derived at the file level.
            "namespace_declaration" | "file_scoped_namespace_declaration" => {
                // The body holds the type declarations.
                if let Some(body) = child.child_by_field_name("body") {
                    collect_types_in(&body, bytes, file, prefix, false, out);
                } else {
                    // file-scoped namespace: members are siblings in compilation_unit
                    // — they will be visited in the outer loop.
                }
            }
            k @ ("class_declaration"
            | "struct_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "record_declaration") => {
                if !implicit_public && !is_visible(&child, bytes) {
                    continue;
                }
                let Some(type_name) = field_text(&child, "name", bytes) else {
                    continue;
                };
                let type_kind = match k {
                    "class_declaration" | "record_declaration" => SymbolKind::Class,
                    "struct_declaration" => SymbolKind::Struct,
                    "interface_declaration" => SymbolKind::Interface,
                    "enum_declaration" => SymbolKind::Enum,
                    _ => SymbolKind::Class,
                };

                let mut type_descriptors = prefix.to_vec();
                type_descriptors.push(Descriptor::Type(type_name.clone()));
                out.push(Symbol {
                    id: SymbolId::global(Language::CSharp.as_str(), type_descriptors.clone()),
                    name: type_name.clone(),
                    kind: type_kind,
                    visibility: Visibility::Public,
                    file: file.to_owned(),
                    line: (child.start_position().row + 1) as u32,
                    span: ByteSpan {
                        start: child.start_byte(),
                        end: child.end_byte(),
                    },
                    signature: one_line_signature(node_text(&child, bytes), &['{', ';']),
                });

                let implicit = k == "interface_declaration";

                // Descend into the type body for members.
                if let Some(body) = child.child_by_field_name("body") {
                    collect_members(&body, bytes, file, &type_descriptors, implicit, out);
                }
            }
            _ => {}
        }
    }
}

/// Collect members from a type body (`declaration_list` or
/// `enum_member_declaration_list`).
fn collect_members(
    body: &Node,
    bytes: &[u8],
    file: &str,
    type_prefix: &[Descriptor],
    implicit_public: bool,
    out: &mut Vec<Symbol>,
) {
    for member in body.children(&mut body.walk()) {
        match member.kind() {
            "method_declaration" | "constructor_declaration" | "property_declaration" => {
                if !implicit_public && !is_visible(&member, bytes) {
                    continue;
                }
                let Some(name) = field_text(&member, "name", bytes) else {
                    continue;
                };
                let mut descriptors = type_prefix.to_vec();
                descriptors.push(Descriptor::Method {
                    name: name.clone(),
                    disambiguator: String::new(),
                });
                out.push(Symbol {
                    id: SymbolId::global(Language::CSharp.as_str(), descriptors),
                    name,
                    kind: SymbolKind::Method,
                    visibility: Visibility::Public,
                    file: file.to_owned(),
                    line: (member.start_position().row + 1) as u32,
                    span: ByteSpan {
                        start: member.start_byte(),
                        end: member.end_byte(),
                    },
                    signature: one_line_signature(node_text(&member, bytes), &['{', ';']),
                });
            }
            "field_declaration" => {
                if !implicit_public && !is_visible(&member, bytes) {
                    continue;
                }
                // field_declaration has no `name` field — descend into
                // variable_declaration → variable_declarator.
                collect_field_declarators(&member, bytes, file, type_prefix, out);
            }
            "enum_member_declaration" => {
                // Enum members are always public.
                let Some(name) = field_text(&member, "name", bytes) else {
                    continue;
                };
                let mut descriptors = type_prefix.to_vec();
                descriptors.push(Descriptor::Term(name.clone()));
                out.push(Symbol {
                    id: SymbolId::global(Language::CSharp.as_str(), descriptors),
                    name,
                    kind: SymbolKind::Const,
                    visibility: Visibility::Public,
                    file: file.to_owned(),
                    line: (member.start_position().row + 1) as u32,
                    span: ByteSpan {
                        start: member.start_byte(),
                        end: member.end_byte(),
                    },
                    signature: one_line_signature(node_text(&member, bytes), &['{', ';', ',']),
                });
            }
            // Nested type declarations inside another type.
            k @ ("class_declaration"
            | "struct_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "record_declaration") => {
                if !implicit_public && !is_visible(&member, bytes) {
                    continue;
                }
                let Some(nested_name) = field_text(&member, "name", bytes) else {
                    continue;
                };
                let nested_kind = match k {
                    "class_declaration" | "record_declaration" => SymbolKind::Class,
                    "struct_declaration" => SymbolKind::Struct,
                    "interface_declaration" => SymbolKind::Interface,
                    "enum_declaration" => SymbolKind::Enum,
                    _ => SymbolKind::Class,
                };
                let mut nested_descriptors = type_prefix.to_vec();
                nested_descriptors.push(Descriptor::Type(nested_name.clone()));
                out.push(Symbol {
                    id: SymbolId::global(Language::CSharp.as_str(), nested_descriptors.clone()),
                    name: nested_name.clone(),
                    kind: nested_kind,
                    visibility: Visibility::Public,
                    file: file.to_owned(),
                    line: (member.start_position().row + 1) as u32,
                    span: ByteSpan {
                        start: member.start_byte(),
                        end: member.end_byte(),
                    },
                    signature: one_line_signature(node_text(&member, bytes), &['{', ';']),
                });
                let implicit = k == "interface_declaration";
                if let Some(nested_body) = member.child_by_field_name("body") {
                    collect_members(
                        &nested_body,
                        bytes,
                        file,
                        &nested_descriptors,
                        implicit,
                        out,
                    );
                }
            }
            _ => {}
        }
    }
}

/// Emit a `Term`/`Static` symbol for each variable declared in a
/// `field_declaration`. The grammar nests as:
///   field_declaration → variable_declaration → variable_declarator* → identifier
fn collect_field_declarators(
    field: &Node,
    bytes: &[u8],
    file: &str,
    type_prefix: &[Descriptor],
    out: &mut Vec<Symbol>,
) {
    for child in field.children(&mut field.walk()) {
        if child.kind() != "variable_declaration" {
            continue;
        }
        for decl in child.children(&mut child.walk()) {
            if decl.kind() != "variable_declarator" {
                continue;
            }
            // First named child that is an identifier is the variable name.
            for id_node in decl.children(&mut decl.walk()) {
                if id_node.kind() == "identifier" {
                    let name = node_text(&id_node, bytes);
                    let mut descriptors = type_prefix.to_vec();
                    descriptors.push(Descriptor::Term(name.to_owned()));
                    out.push(Symbol {
                        id: SymbolId::global(Language::CSharp.as_str(), descriptors),
                        name: name.to_owned(),
                        kind: SymbolKind::Static,
                        visibility: Visibility::Public,
                        file: file.to_owned(),
                        line: (field.start_position().row + 1) as u32,
                        span: ByteSpan {
                            start: field.start_byte(),
                            end: field.end_byte(),
                        },
                        signature: one_line_signature(node_text(field, bytes), &['{', ';']),
                    });
                    break; // only the first identifier is the name
                }
            }
        }
    }
}

// ── Inheritance (base_list) ──────────────────────────────────────────────────

/// Walk the tree and emit `IsImplementation` references for base types listed
/// in a `base_list` node (both `class X : Base, IFoo` and interface extends).
fn collect_inheritance(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    if node.kind() == "base_list" {
        for child in node.children(&mut node.walk()) {
            match child.kind() {
                "identifier" => {
                    push_ref(
                        out,
                        node_text(&child, bytes),
                        &child,
                        file,
                        RefRole::IsImplementation,
                    );
                }
                "qualified_name" | "generic_name" => {
                    let name = simple_type_name(node_text(&child, bytes), ".");
                    push_ref(out, name, &child, file, RefRole::IsImplementation);
                }
                _ => {}
            }
        }
    }
    for child in node.children(&mut node.walk()) {
        collect_inheritance(&child, bytes, file, out);
    }
}

// ── Imports (using_directive) ────────────────────────────────────────────────

/// Walk the tree emitting `Import` references for `using_directive` nodes.
///
/// Handles `using A.B.C;` — the leaf name is `C`, the from_path is `A.B`.
/// Alias forms (`using Alias = X.Y`) and `using static X.Y` are skipped
/// to avoid ambiguity; they do not crash.
fn collect_imports(
    node: &Node,
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Reference>,
    module_id: &str,
) {
    if node.kind() == "using_directive" {
        // Look for the namespace name: a qualified_name or identifier child.
        // Skip alias directives: they have an `=` among their children (name_equals).
        let has_alias = node
            .children(&mut node.walk())
            .any(|c| c.kind() == "name_equals");
        if !has_alias {
            // Find the name node — could be qualified_name or identifier.
            let mut name_node: Option<Node> = None;
            for child in node.children(&mut node.walk()) {
                match child.kind() {
                    "qualified_name" | "identifier" => {
                        name_node = Some(child);
                        break;
                    }
                    _ => {}
                }
            }
            if let Some(qn) = name_node {
                let full_text = node_text(&qn, bytes);
                if qn.kind() == "qualified_name" {
                    // Split on last `.` to get leaf name and from_path.
                    if let Some(dot) = full_text.rfind('.') {
                        let from_path = &full_text[..dot];
                        let leaf = &full_text[dot + 1..];
                        // Find the leaf identifier node for position.
                        if let Some(name_field) = qn.child_by_field_name("name") {
                            push_import_ref(out, leaf, &name_field, file, module_id, from_path);
                        } else {
                            push_import_ref(out, leaf, &qn, file, module_id, from_path);
                        }
                    } else {
                        // Malformed qualified_name — emit as bare.
                        push_import_ref(out, full_text, &qn, file, module_id, "");
                    }
                } else {
                    // Bare identifier: `using Foo;`
                    push_import_ref(out, full_text, &qn, file, module_id, "");
                }
            }
        }
        return;
    }
    for child in node.children(&mut node.walk()) {
        collect_imports(&child, bytes, file, out, module_id);
    }
}

// ── Read / Write references ──────────────────────────────────────────────────

/// Returns `true` when `node` (an `identifier`) is in a position already
/// captured by another collector (call callee, declaration name, parameter
/// name, import binding, assignment LHS, or member-access leaf) so it must
/// NOT also be emitted as a Read reference.
fn is_non_read_position(node: &Node) -> bool {
    let parent = match node.parent() {
        Some(p) => p,
        None => return true, // root — not a read
    };
    // General type-field exclusion: if this identifier IS the `type` field of
    // its parent (covers variable_declaration, parameter, field_declaration →
    // variable_declaration, property_declaration, object_creation_expression,
    // etc.) it is a type-annotation position, not a value read.
    if parent.child_by_field_name("type").as_ref() == Some(node) {
        return true;
    }
    // Method return-type uses the `returns` field (not `type`), also type-position.
    if parent.child_by_field_name("returns").as_ref() == Some(node) {
        return true;
    }
    match parent.kind() {
        // Call callee: `Foo()` — `function:` field of invocation_expression.
        "invocation_expression" => parent.child_by_field_name("function").as_ref() == Some(node),
        // Declaration names: method/constructor/class/struct/interface/enum/record.
        "method_declaration"
        | "constructor_declaration"
        | "property_declaration"
        | "class_declaration"
        | "struct_declaration"
        | "interface_declaration"
        | "enum_declaration"
        | "record_declaration"
        | "enum_member_declaration" => parent.child_by_field_name("name").as_ref() == Some(node),
        // Local variable declarator: the `name:` field is the binding introduction.
        "variable_declarator" => parent.child_by_field_name("name").as_ref() == Some(node),
        // Parameter binding name.
        "parameter" => parent.child_by_field_name("name").as_ref() == Some(node),
        // Using-directive — already Import refs.
        "using_directive" => true,
        // Member-access leaf (`obj.Field` — skip `Field`, keep `obj`).
        "member_access_expression" => parent.child_by_field_name("name").as_ref() == Some(node),
        // Qualified name — type-position names (e.g. in base_list or generic types).
        "qualified_name" => true,
        // Generic name — the type identifier inside `List<T>`.
        "generic_name" => parent.child_by_field_name("name").as_ref() == Some(node),
        // Assignment LHS — handled by collect_write_references.
        "assignment_expression" => parent.child_by_field_name("left").as_ref() == Some(node),
        _ => false,
    }
}

/// Recursively walk `node` and emit [`RefRole::Read`] references for bare
/// `identifier` nodes used in value/expression positions.
///
/// Skips identifiers already captured by other collectors (call callees,
/// declaration names, parameter names, import bindings, assignment LHS,
/// member-access leaf names, type-annotation positions).
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
/// bare-identifier LHS of `assignment_expression` nodes
/// (e.g. `x = 5`, `total += bonus`).
///
/// C# uses `assignment_expression` for both plain (`=`) and compound
/// (`+=`, `-=`, …) assignments — both are covered here.
/// Member / subscript LHS (`obj.Field = …`, `arr[i] = …`) are out of scope
/// in v1 — bare identifiers only.  Applies [`MIN_REF_LEN`].
fn collect_write_references(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    if node.kind() == "assignment_expression" {
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

// ── TypeRef edges ────────────────────────────────────────────────────────────

/// Recursively walk `node` emitting [`RefRole::TypeRef`] references for
/// user-defined type names in typed positions.
///
/// Covers: method return types (`returns` field), parameter types, field/property
/// types. Skips C# predefined types (`predefined_type`).
fn collect_type_references(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    match node.kind() {
        "method_declaration" => {
            if let Some(ret) = node.child_by_field_name("returns") {
                type_leaf(&ret, bytes, file, TypeRefContext::ReturnType, out);
            }
        }
        "parameter" => {
            if let Some(ty) = node.child_by_field_name("type") {
                type_leaf(&ty, bytes, file, TypeRefContext::ParameterType, out);
            }
        }
        "field_declaration" => {
            for child in node.children(&mut node.walk()) {
                if child.kind() == "variable_declaration" {
                    if let Some(ty) = child.child_by_field_name("type") {
                        type_leaf(&ty, bytes, file, TypeRefContext::Field, out);
                    }
                }
            }
        }
        "property_declaration" => {
            if let Some(ty) = node.child_by_field_name("type") {
                type_leaf(&ty, bytes, file, TypeRefContext::Field, out);
            }
        }
        _ => {}
    }
    for child in node.children(&mut node.walk()) {
        collect_type_references(&child, bytes, file, out);
    }
}

fn type_leaf(node: &Node, bytes: &[u8], file: &str, ctx: TypeRefContext, out: &mut Vec<Reference>) {
    match node.kind() {
        "predefined_type" | "void_keyword" => {}
        "identifier" => {
            let name = node_text(node, bytes);
            push_type_ref(out, name, node, file, ctx);
        }
        "qualified_name" | "generic_name" => {
            let name = simple_type_name(node_text(node, bytes), ".");
            push_type_ref(out, name, node, file, ctx);
        }
        "nullable_type" | "array_type" => {
            if let Some(elem) = node.named_children(&mut node.walk()).next() {
                type_leaf(&elem, bytes, file, ctx, out);
            }
        }
        _ => {
            // For other composed types, recurse into named children.
            for child in node.named_children(&mut node.walk()) {
                type_leaf(&child, bytes, file, ctx, out);
            }
        }
    }
}

// ── Scope tree ───────────────────────────────────────────────────────────────

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

fn scope_dfs(node: &Node, parent_id: ScopeId, scopes: &mut Vec<Scope>) {
    match node.kind() {
        "namespace_declaration" | "file_scoped_namespace_declaration" => {
            let ns_id = push_scope(scopes, Some(parent_id), node_span(node), ScopeKind::Module);
            if let Some(body) = node.child_by_field_name("body") {
                for child in body.children(&mut body.walk()) {
                    scope_dfs(&child, ns_id, scopes);
                }
            }
        }
        "class_declaration"
        | "struct_declaration"
        | "interface_declaration"
        | "enum_declaration"
        | "record_declaration" => {
            let type_id = push_scope(scopes, Some(parent_id), node_span(node), ScopeKind::Type);
            if let Some(body) = node.child_by_field_name("body") {
                for child in body.children(&mut body.walk()) {
                    scope_dfs(&child, type_id, scopes);
                }
            }
        }
        "method_declaration" | "constructor_declaration" => {
            let fn_id = push_scope(
                scopes,
                Some(parent_id),
                node_span(node),
                ScopeKind::Function,
            );
            if let Some(body) = node.child_by_field_name("body") {
                for child in body.children(&mut body.walk()) {
                    scope_dfs(&child, fn_id, scopes);
                }
            }
        }
        "block" => {
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

// ── Bindings ─────────────────────────────────────────────────────────────────

fn collect_bindings(root: &Node, bytes: &[u8], scopes: &[Scope]) -> Vec<Binding> {
    let mut out = Vec::new();
    collect_bindings_dfs(root, bytes, scopes, &mut out);
    out
}

fn collect_bindings_dfs(node: &Node, bytes: &[u8], scopes: &[Scope], out: &mut Vec<Binding>) {
    match node.kind() {
        "method_declaration" | "constructor_declaration" => {
            if let Some(params) = node.child_by_field_name("parameters") {
                collect_params(&params, bytes, scopes, out);
            }
        }
        "local_declaration_statement" => {
            // local_declaration_statement → variable_declaration → variable_declarator* → identifier
            for child in node.children(&mut node.walk()) {
                if child.kind() == "variable_declaration" {
                    for decl in child.children(&mut child.walk()) {
                        if decl.kind() == "variable_declarator" {
                            for id_node in decl.children(&mut decl.walk()) {
                                if id_node.kind() == "identifier" {
                                    let name = node_text(&id_node, bytes);
                                    let intro = id_node.start_byte();
                                    if name.len() >= MIN_REF_LEN
                                        && innermost_scope(intro, scopes) != Some(0)
                                    {
                                        push_binding(
                                            out,
                                            name.to_owned(),
                                            intro,
                                            BindingKind::Local,
                                            scopes,
                                        );
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
        "for_each_statement" => {
            if let Some(name_node) = node.child_by_field_name("left") {
                if name_node.kind() == "identifier" {
                    let name = node_text(&name_node, bytes);
                    let intro = name_node.start_byte();
                    if innermost_scope(intro, scopes) != Some(0) {
                        push_binding(out, name.to_owned(), intro, BindingKind::Local, scopes);
                    }
                }
            }
        }
        "catch_clause" => {
            if let Some(decl) = node.child_by_field_name("declaration") {
                if let Some(name_node) = decl.child_by_field_name("name") {
                    let name = node_text(&name_node, bytes);
                    let intro = name_node.start_byte();
                    push_binding(out, name.to_owned(), intro, BindingKind::Param, scopes);
                }
            }
        }
        _ => {}
    }
    for child in node.children(&mut node.walk()) {
        collect_bindings_dfs(&child, bytes, scopes, out);
    }
}

fn collect_params(params: &Node, bytes: &[u8], scopes: &[Scope], out: &mut Vec<Binding>) {
    for child in params.named_children(&mut params.walk()) {
        if child.kind() == "parameter" {
            if let Some(name_node) = child.child_by_field_name("name") {
                let name = node_text(&name_node, bytes);
                let intro = name_node.start_byte();
                push_binding(out, name.to_owned(), intro, BindingKind::Param, scopes);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Definitions ──────────────────────────────────────────────────────────

    #[test]
    fn class_and_method_get_correct_scip_strings() {
        let src = r#"
namespace MyApp.Auth {
    public class SessionManager {
        public bool Validate(string token) { return true; }
        private void Secret() {}
    }
}
"#;
        let facts = CSharpExtractor
            .extract(src, "src/MyApp/Auth/SessionManager.cs")
            .unwrap();

        let by_name = |n: &str| facts.symbols.iter().find(|s| s.name == n).cloned();

        let sm = by_name("SessionManager").unwrap();
        assert_eq!(sm.kind, SymbolKind::Class);
        assert_eq!(
            sm.id.to_scip_string(),
            "codegraph . . . MyApp/Auth/SessionManager#"
        );

        let validate = by_name("Validate").unwrap();
        assert_eq!(validate.kind, SymbolKind::Method);
        assert_eq!(
            validate.id.to_scip_string(),
            "codegraph . . . MyApp/Auth/SessionManager#Validate()."
        );

        // private method must not appear
        assert!(by_name("Secret").is_none());

        assert_eq!(facts.lang, "csharp");
    }

    #[test]
    fn namespace_block_yields_correct_descriptors() {
        let src = r#"
namespace A.B {
    public class C {
        public void M() {}
    }
}
"#;
        let facts = CSharpExtractor.extract(src, "src/A/B/C.cs").unwrap();
        let by_name = |n: &str| facts.symbols.iter().find(|s| s.name == n).cloned();

        let c = by_name("C").unwrap();
        assert_eq!(c.id.to_scip_string(), "codegraph . . . A/B/C#");

        let m = by_name("M").unwrap();
        assert_eq!(m.id.to_scip_string(), "codegraph . . . A/B/C#M().");
    }

    #[test]
    fn file_scoped_namespace_works() {
        let src = r#"
namespace A.B;

public class Foo {
    public void Bar() {}
}
"#;
        let facts = CSharpExtractor.extract(src, "src/A/B/Foo.cs").unwrap();
        let by_name = |n: &str| facts.symbols.iter().find(|s| s.name == n).cloned();

        let foo = by_name("Foo").unwrap();
        assert_eq!(foo.id.to_scip_string(), "codegraph . . . A/B/Foo#");

        let bar = by_name("Bar").unwrap();
        assert_eq!(bar.id.to_scip_string(), "codegraph . . . A/B/Foo#Bar().");
    }

    #[test]
    fn enum_and_enum_member_are_extracted() {
        let src = r#"
namespace N {
    public enum Color { Red, Green, Blue }
}
"#;
        let facts = CSharpExtractor.extract(src, "src/N/Color.cs").unwrap();
        let by_name = |n: &str| facts.symbols.iter().find(|s| s.name == n).cloned();

        let color = by_name("Color").unwrap();
        assert_eq!(color.kind, SymbolKind::Enum);
        assert_eq!(color.id.to_scip_string(), "codegraph . . . N/Color#");

        let red = by_name("Red").unwrap();
        assert_eq!(red.kind, SymbolKind::Const);
        assert_eq!(red.id.to_scip_string(), "codegraph . . . N/Color#Red.");
    }

    #[test]
    fn field_is_extracted() {
        let src = r#"
namespace N {
    public class C {
        public int Count;
    }
}
"#;
        let facts = CSharpExtractor.extract(src, "src/N/C.cs").unwrap();
        let count = facts
            .symbols
            .iter()
            .find(|s| s.name == "Count")
            .expect("expected field Count");
        assert_eq!(count.kind, SymbolKind::Static);
        assert_eq!(count.id.to_scip_string(), "codegraph . . . N/C#Count.");
    }

    // ── References ───────────────────────────────────────────────────────────

    #[test]
    fn qualified_call_captures_qualifier() {
        let src = r#"
public class Client {
    public void Run() {
        var obj = new Service();
        obj.Foo();
    }
}
"#;
        let facts = CSharpExtractor.extract(src, "src/Client.cs").unwrap();

        // Foo should appear as a Call reference.
        let foo = facts
            .references
            .iter()
            .find(|r| r.name == "Foo")
            .expect("expected Call ref for 'Foo'");
        assert_eq!(foo.role, RefRole::Call);
        // The receiver must be captured as the call's qualifier (so Tier-B can
        // disambiguate), not emitted as a separate reference.
        assert_eq!(
            foo.qualifier.as_deref(),
            Some("obj"),
            "expected qualifier 'obj' on the Foo call ref",
        );
    }

    #[test]
    fn using_directive_produces_import_reference() {
        let src = r#"
using System.Collections.Generic;
public class C {}
"#;
        let facts = CSharpExtractor.extract(src, "src/C.cs").unwrap();
        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            import_names.contains(&"Generic"),
            "expected 'Generic' in import refs: {import_names:?}"
        );
        // Verify from_path is set.
        let r = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Import && r.name == "Generic")
            .unwrap();
        assert_eq!(
            r.from_path,
            Some("System.Collections".to_owned()),
            "from_path should be 'System.Collections', got {:?}",
            r.from_path
        );
    }

    #[test]
    fn inheritance_produces_is_implementation_references() {
        let src = r#"
public class Foo : Bar, IBaz {}
"#;
        let facts = CSharpExtractor.extract(src, "src/Foo.cs").unwrap();
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
            inherit_names.contains(&"IBaz"),
            "expected 'IBaz' in {inherit_names:?}"
        );
    }

    #[test]
    fn interface_members_emitted_without_public_modifier() {
        let src = r#"
namespace Svc {
    public interface IReader {
        int Read();
        void Close();
    }
}
"#;
        let facts = CSharpExtractor.extract(src, "src/Svc/IReader.cs").unwrap();
        let by_name = |n: &str| facts.symbols.iter().find(|s| s.name == n).cloned();

        let read = by_name("Read").unwrap();
        assert_eq!(read.kind, SymbolKind::Method);
        let close = by_name("Close").unwrap();
        assert_eq!(close.kind, SymbolKind::Method);
    }

    // ── Read / Write references ──────────────────────────────────────────────

    #[test]
    fn reassignment_emits_write_for_lhs_and_read_for_rhs() {
        // `total = total + bonus;` — Write for the LHS `total`, Read for the
        // RHS `total` and for `bonus`.
        let src = r#"
public class Calc {
    public int Run(int total, int bonus) {
        total = total + bonus;
        return total;
    }
}
"#;
        let facts = CSharpExtractor.extract(src, "src/Calc.cs").unwrap();

        let writes: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Write)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            writes.contains(&"total"),
            "expected Write for 'total', got: {writes:?}",
        );

        let reads: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Read)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            reads.contains(&"bonus"),
            "expected Read for 'bonus', got: {reads:?}",
        );
        // The RHS `total` should also be a Read.
        assert!(
            reads.contains(&"total"),
            "expected Read for RHS 'total', got: {reads:?}",
        );
    }

    #[test]
    fn local_declaration_does_not_emit_write() {
        // `var result = Compute();` — `result` is a binding introduction, NOT a Write.
        let src = r#"
public class Worker {
    public int Run() {
        var result = Compute();
        return result;
    }
    private int Compute() { return 42; }
}
"#;
        let facts = CSharpExtractor.extract(src, "src/Worker.cs").unwrap();

        let writes: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Write)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            !writes.contains(&"result"),
            "declaration binding must NOT produce a Write ref; got writes: {writes:?}",
        );
    }

    #[test]
    fn call_argument_emits_read_but_not_callee() {
        // `Log(config);` — `config` is a Read; `Log` is a Call, NOT a Read.
        let src = r#"
public class App {
    public void Run(object config) {
        Log(config);
    }
    private void Log(object msg) {}
}
"#;
        let facts = CSharpExtractor.extract(src, "src/App.cs").unwrap();

        let reads: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Read)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            reads.contains(&"config"),
            "expected Read for 'config', got: {reads:?}",
        );
        assert!(
            !reads.contains(&"Log"),
            "callee 'Log' must NOT appear as a Read ref; reads: {reads:?}",
        );
    }

    #[test]
    fn member_access_emits_read_for_base_not_leaf() {
        // `value = source.Field;` — Read for `source` (base), NOT for `Field` (leaf).
        let src = r#"
public class Copier {
    public int Run(DataObj source) {
        int value = source.Field;
        return value;
    }
}
public class DataObj { public int Field; }
"#;
        let facts = CSharpExtractor.extract(src, "src/Copier.cs").unwrap();

        let reads: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Read)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            reads.contains(&"source"),
            "expected Read for 'source', got: {reads:?}",
        );
        assert!(
            !reads.contains(&"Field"),
            "member-access leaf 'Field' must NOT be a Read ref; reads: {reads:?}",
        );
    }

    #[test]
    fn type_name_in_typed_local_is_not_a_read() {
        // `Helper result = source;` — `Helper` is a type annotation (TypeRef),
        // NOT a value read. `source` IS a value read.
        let src = r#"
class C {
    void M(Helper source) {
        Helper result = source;
    }
}
"#;
        let facts = CSharpExtractor.extract(src, "src/C.cs").unwrap();

        let reads: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Read)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            !reads.contains(&"Helper"),
            "type name 'Helper' must NOT appear as a Read ref; reads: {reads:?}",
        );
        assert!(
            reads.contains(&"source"),
            "initializer value 'source' must appear as a Read ref; reads: {reads:?}",
        );
    }
}
