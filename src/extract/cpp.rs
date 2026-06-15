// SPDX-License-Identifier: Apache-2.0

//! C++ extractor — one tree-sitter pass yielding definitions and references.
//!
//! Definitions: namespaces, classes/structs/unions and their **visible**
//! members, free functions and variables, enums, type aliases (`typedef` /
//! `using T = X`), and preprocessor macros (`#define`). Qualified identity is
//! derived from the file path (`src/net/sock.cpp` → namespaces `net`, `sock`),
//! then extended by `namespace` blocks and class scopes. The same stem is
//! shared by source and header files so paired translation units share a
//! namespace.
//! References: callee identifiers of `call_expression` nodes (free calls,
//! method calls, and qualified calls).
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
    Extractor, attach_reference_scopes, collect_call_references, definition_bindings, field_text,
    innermost_scope, is_static, node_span, node_text, one_line_signature, push_binding, push_scope,
};

// NOTE: SymbolKind has no Union variant; unions map to Struct. Preprocessor
// macros use Descriptor::Macro (renders with `!`), paired with SymbolKind::Const
// or SymbolKind::Function — same convention as the C extractor.

/// Tree-sitter query capturing call-callee identifiers: free calls, method
/// calls (`obj.f()` / `obj->f()`), and qualified calls (`Ns::f()`).
const CALL_QUERY: &str = r#"
[
  (call_expression function: (identifier) @callee)
  (call_expression function: (field_expression field: (field_identifier) @callee))
  (call_expression function: (qualified_identifier name: (identifier) @callee))
]
"#;

/// Extracts C++ symbols and references.
pub struct CppExtractor;

impl Extractor for CppExtractor {
    fn lang(&self) -> Language {
        Language::Cpp
    }

    fn extract(&self, source: &str, file: &str) -> Result<FileFacts> {
        let ts_language = TsLanguage::from(tree_sitter_cpp::LANGUAGE);
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
        let namespaces = cpp_namespaces(file);

        let mut defs = Vec::new();
        collect_defs(&root, &namespaces, bytes, file, &mut defs);
        let def_bindings = definition_bindings(&defs);
        let mut symbols = defs;
        symbols.push(super::module_symbol(
            Language::Cpp,
            &namespaces,
            file,
            source.len(),
        ));
        let mut references =
            collect_call_references(&root, &ts_language, CALL_QUERY, Language::Cpp, bytes, file)?;
        collect_inheritance(&root, bytes, file, &mut references);

        let scopes = collect_scopes(&root, source.len());
        attach_reference_scopes(&mut references, &scopes);
        let mut bindings = collect_bindings(&root, bytes, &scopes);
        bindings.extend(def_bindings);

        Ok(FileFacts {
            file: file.to_owned(),
            lang: Language::Cpp.as_str().to_owned(),
            symbols,
            references,
            scopes,
            bindings,
            ffi_exports: Vec::new(),
        })
    }
}

/// Derive the C++ namespace path from a file path.
///
/// Strips a C++ or C source/header extension, strips a leading `src/` prefix,
/// then splits on `/`. The file stem is kept as the last namespace segment, so
/// paired source/header files share a namespace via the common stem.
fn cpp_namespaces(file: &str) -> Vec<String> {
    let p = [".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx", ".c", ".h"]
        .iter()
        .find_map(|ext| file.strip_suffix(ext))
        .unwrap_or(file);
    let p = p.strip_prefix("src/").unwrap_or(p);
    p.split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Walk a declarator subtree to the inner name; returns `(name, is_function)`.
///
/// Like C, C++ nests names inside declarator chains. Beyond C, the base name
/// may also be a `field_identifier` (member), `destructor_name` (`~Foo`),
/// `operator_name` (`operator+`), or `qualified_identifier` (`Ns::Cls::fn`,
/// whose last `::` segment is taken as the name). `is_function` is `true` only
/// when a `function_declarator` is encountered on the path.
fn declarator_name(node: &Node, bytes: &[u8]) -> Option<(String, bool)> {
    match node.kind() {
        "identifier" | "type_identifier" | "field_identifier" | "destructor_name"
        | "operator_name" => Some((node_text(node, bytes).to_owned(), false)),
        "qualified_identifier" => {
            let text = node_text(node, bytes);
            let last = text.rsplit("::").next().unwrap_or(text);
            Some((last.to_owned(), false))
        }
        "function_declarator" => {
            let inner = node.child_by_field_name("declarator")?;
            let (name, _) = declarator_name(&inner, bytes)?;
            Some((name, true))
        }
        _ => {
            // pointer_declarator / init_declarator / array_declarator /
            // reference_declarator / attributed_declarator — all expose a
            // "declarator" named field.
            if let Some(d) = node.child_by_field_name("declarator") {
                return declarator_name(&d, bytes);
            }
            // parenthesized_declarator has no named field — scan children.
            for c in node.children(&mut node.walk()) {
                if let Some(r) = declarator_name(&c, bytes) {
                    return Some(r);
                }
            }
            None
        }
    }
}

/// The leaf type name of a class/struct/union name node, which may be a bare
/// `type_identifier`, a `template_type` (templated class), or a
/// `qualified_identifier` (take the last `::` segment).
fn type_leaf_name(node: &Node, bytes: &[u8]) -> Option<String> {
    match node.kind() {
        "type_identifier" => Some(node_text(node, bytes).to_owned()),
        "template_type" => node
            .child_by_field_name("name")
            .and_then(|n| type_leaf_name(&n, bytes)),
        "qualified_identifier" => {
            let text = node_text(node, bytes);
            text.rsplit("::").next().map(str::to_owned)
        }
        _ => None,
    }
}

/// Push a symbol whose leaf descriptor extends `prefix` (a namespace/type chain).
/// The symbol's display name is derived from `leaf.name()`.
fn push_symbol(
    out: &mut Vec<Symbol>,
    node: &Node,
    prefix: &[Descriptor],
    leaf: Descriptor,
    kind: SymbolKind,
    bytes: &[u8],
    file: &str,
) {
    let name = leaf.name().to_owned();
    let mut descriptors = prefix.to_vec();
    descriptors.push(leaf);
    out.push(Symbol {
        id: SymbolId::global(Language::Cpp.as_str(), descriptors),
        name,
        kind,
        file: file.to_owned(),
        line: (node.start_position().row + 1) as u32,
        span: ByteSpan {
            start: node.start_byte(),
            end: node.end_byte(),
        },
        signature: one_line_signature(node_text(node, bytes), &['{', ';']),
    });
}

/// Build the descriptor prefix for a list of namespace segments.
fn namespace_prefix(namespaces: &[String]) -> Vec<Descriptor> {
    namespaces
        .iter()
        .cloned()
        .map(Descriptor::Namespace)
        .collect()
}

/// Process a container node (translation unit or `declaration_list`), handling
/// namespace blocks, top-level defs, and class/struct/union/enum/alias defs.
/// `namespaces` is the current namespace descriptor chain (as plain strings).
fn collect_defs(
    container: &Node,
    namespaces: &[String],
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    for child in container.children(&mut container.walk()) {
        process_node(&child, namespaces, bytes, file, out);
    }
}

/// Process a single declaration-level node.
fn process_node(
    node: &Node,
    namespaces: &[String],
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    match node.kind() {
        "namespace_definition" => {
            // Extend the namespace chain with the (possibly nested or absent) name.
            let mut nested = namespaces.to_vec();
            if let Some(name) = node.child_by_field_name("name") {
                for seg in node_text(&name, bytes).split("::") {
                    if !seg.is_empty() {
                        nested.push(seg.to_owned());
                    }
                }
            }
            if let Some(body) = node.child_by_field_name("body") {
                collect_defs(&body, &nested, bytes, file, out);
            }
        }

        "function_definition" => {
            if is_static(node, bytes) {
                return;
            }
            let Some(decl) = node.child_by_field_name("declarator") else {
                return;
            };
            let Some((name, _)) = declarator_name(&decl, bytes) else {
                return;
            };
            let prefix = namespace_prefix(namespaces);
            push_symbol(
                out,
                node,
                &prefix,
                Descriptor::Method {
                    name,
                    disambiguator: String::new(),
                },
                SymbolKind::Function,
                bytes,
                file,
            );
        }

        "declaration" => {
            if is_static(node, bytes) {
                return;
            }
            // A class/struct/union/enum specifier in the `type` field with a
            // body is an aggregate definition; emit it (and its members).
            if let Some(spec) = node.child_by_field_name("type") {
                emit_aggregate(&spec, namespaces, bytes, file, out);
            }
            let prefix = namespace_prefix(namespaces);
            let mut cursor = node.walk();
            for decl in node.children_by_field_name("declarator", &mut cursor) {
                let Some((name, is_function)) = declarator_name(&decl, bytes) else {
                    continue;
                };
                if is_function {
                    push_symbol(
                        out,
                        node,
                        &prefix,
                        Descriptor::Method {
                            name,
                            disambiguator: String::new(),
                        },
                        SymbolKind::Function,
                        bytes,
                        file,
                    );
                } else {
                    push_symbol(
                        out,
                        node,
                        &prefix,
                        Descriptor::Term(name),
                        SymbolKind::Static,
                        bytes,
                        file,
                    );
                }
            }
        }

        // A bare top-level `class/struct/union/enum Name { ... };`.
        "class_specifier" | "struct_specifier" | "union_specifier" | "enum_specifier" => {
            emit_aggregate(node, namespaces, bytes, file, out);
        }

        "type_definition" => {
            if let Some(spec) = node.child_by_field_name("type") {
                emit_aggregate(&spec, namespaces, bytes, file, out);
            }
            let Some(decl) = node.child_by_field_name("declarator") else {
                return;
            };
            let Some((name, _)) = declarator_name(&decl, bytes) else {
                return;
            };
            let prefix = namespace_prefix(namespaces);
            push_symbol(
                out,
                node,
                &prefix,
                Descriptor::Type(name),
                SymbolKind::TypeAlias,
                bytes,
                file,
            );
        }

        // `using T = X;`
        "alias_declaration" => {
            let Some(name) = field_text(node, "name", bytes) else {
                return;
            };
            let prefix = namespace_prefix(namespaces);
            push_symbol(
                out,
                node,
                &prefix,
                Descriptor::Type(name),
                SymbolKind::TypeAlias,
                bytes,
                file,
            );
        }

        // `template<...> <decl>` — unwrap and process the inner declaration.
        "template_declaration" => {
            for c in node.children(&mut node.walk()) {
                if matches!(
                    c.kind(),
                    "function_definition"
                        | "declaration"
                        | "alias_declaration"
                        | "class_specifier"
                        | "struct_specifier"
                        | "union_specifier"
                ) {
                    process_node(&c, namespaces, bytes, file, out);
                }
            }
        }

        "preproc_def" => {
            if let Some(name) = field_text(node, "name", bytes) {
                let prefix = namespace_prefix(namespaces);
                push_symbol(
                    out,
                    node,
                    &prefix,
                    Descriptor::Macro(name),
                    SymbolKind::Const,
                    bytes,
                    file,
                );
            }
        }

        "preproc_function_def" => {
            if let Some(name) = field_text(node, "name", bytes) {
                let prefix = namespace_prefix(namespaces);
                push_symbol(
                    out,
                    node,
                    &prefix,
                    Descriptor::Macro(name),
                    SymbolKind::Function,
                    bytes,
                    file,
                );
            }
        }

        _ => {}
    }
}

/// If `spec` is a class/struct/union/enum specifier with a body (a definition,
/// not a forward declaration), emit the type symbol and recurse into members.
fn emit_aggregate(
    spec: &Node,
    namespaces: &[String],
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    let (kind, default_public, is_enum) = match spec.kind() {
        "class_specifier" => (SymbolKind::Class, false, false),
        "struct_specifier" => (SymbolKind::Struct, true, false),
        // NOTE: no Union variant — unions map to Struct.
        "union_specifier" => (SymbolKind::Struct, true, false),
        "enum_specifier" => (SymbolKind::Enum, true, true),
        _ => return,
    };

    let body = spec.child_by_field_name("body");
    // No body = forward declaration: emit nothing.
    let Some(body) = body else {
        return;
    };
    let Some(name_node) = spec.child_by_field_name("name") else {
        return;
    };
    let Some(name) = type_leaf_name(&name_node, bytes) else {
        return;
    };

    let prefix = namespace_prefix(namespaces);
    push_symbol(
        out,
        spec,
        &prefix,
        Descriptor::Type(name.clone()),
        kind,
        bytes,
        file,
    );

    // Enumerators are not emitted individually (mirrors the C extractor).
    if is_enum {
        return;
    }

    // The type's own descriptor prefix for nested members.
    let mut type_prefix = prefix;
    type_prefix.push(Descriptor::Type(name));
    collect_members(&body, &type_prefix, default_public, bytes, file, out);
}

/// Collect visible members of a `field_declaration_list`, tracking visibility
/// statefully via `access_specifier` nodes encountered in order.
fn collect_members(
    body: &Node,
    type_prefix: &[Descriptor],
    default_public: bool,
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    let mut current_public = default_public;
    for member in body.children(&mut body.walk()) {
        match member.kind() {
            "access_specifier" => {
                current_public = node_text(&member, bytes).starts_with("public");
            }
            _ if !current_public => {}
            "function_definition" => {
                let Some(decl) = member.child_by_field_name("declarator") else {
                    continue;
                };
                let Some((name, _)) = declarator_name(&decl, bytes) else {
                    continue;
                };
                push_symbol(
                    out,
                    &member,
                    type_prefix,
                    Descriptor::Method {
                        name,
                        disambiguator: String::new(),
                    },
                    SymbolKind::Method,
                    bytes,
                    file,
                );
            }
            "field_declaration" => {
                let Some(decl) = member.child_by_field_name("declarator") else {
                    continue;
                };
                let Some((name, is_function)) = declarator_name(&decl, bytes) else {
                    continue;
                };
                if is_function {
                    push_symbol(
                        out,
                        &member,
                        type_prefix,
                        Descriptor::Method {
                            name,
                            disambiguator: String::new(),
                        },
                        SymbolKind::Method,
                        bytes,
                        file,
                    );
                } else {
                    push_symbol(
                        out,
                        &member,
                        type_prefix,
                        Descriptor::Term(name),
                        SymbolKind::Static,
                        bytes,
                        file,
                    );
                }
            }
            // A nested type (struct inside a class etc.) — recurse, nesting
            // under the outer type.
            "class_specifier" | "struct_specifier" | "union_specifier" | "enum_specifier" => {
                // type_prefix is a namespace+type chain; treat its segments as
                // the "namespaces" for the nested aggregate.
                let nested_ns: Vec<String> =
                    type_prefix.iter().map(|d| d.name().to_owned()).collect();
                emit_aggregate(&member, &nested_ns, bytes, file, out);
            }
            _ => {}
        }
    }
}

// ── Scope tree (Tier-B) ──────────────────────────────────────────────────────

/// Walk a declarator subtree to find the innermost `function_declarator` node.
///
/// C++ allows pointer/reference wrapping around a `function_declarator`:
/// `char *f(int a)` → `pointer_declarator` → `function_declarator`. This helper
/// descends the same chain as [`declarator_name`] and returns the first
/// `function_declarator` encountered, so `collect_bindings_dfs` can reliably
/// reach its `parameters` field regardless of wrapping.
fn find_function_declarator<'tree>(node: &Node<'tree>) -> Option<Node<'tree>> {
    if node.kind() == "function_declarator" {
        return Some(*node);
    }
    // pointer_declarator / reference_declarator / init_declarator / array_declarator
    // all have a "declarator" field.
    if let Some(inner) = node.child_by_field_name("declarator") {
        return find_function_declarator(&inner);
    }
    // parenthesized_declarator — scan children.
    for child in node.children(&mut node.walk()) {
        if let Some(found) = find_function_declarator(&child) {
            return Some(found);
        }
    }
    None
}

/// Build the lexical scope tree for one C++ file.
///
/// `scopes[0]` is always the file-root `Module` scope spanning `[0, source_len)`.
/// C++ opens `Type` scopes for namespace/class/struct/union bodies, `Function`
/// scopes for function definitions and lambdas, and `Block` scopes for bare
/// `compound_statement` nodes not consumed as a function body.
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

/// DFS opening scopes for the C++ AST.
///
/// - `namespace_definition` → `ScopeKind::Type`; children of the
///   `declaration_list` body are peeled under the namespace scope.
/// - `class_specifier` | `struct_specifier` | `union_specifier` →
///   `ScopeKind::Type`; children of the `field_declaration_list` body are
///   peeled under the type scope.
/// - `function_definition` | `lambda_expression` → `ScopeKind::Function`; the
///   `compound_statement` body is peeled to avoid a redundant Block scope.
/// - `compound_statement` not already consumed as a body → `ScopeKind::Block`.
fn scope_dfs(node: &Node, parent_id: ScopeId, scopes: &mut Vec<Scope>) {
    match node.kind() {
        "namespace_definition" => {
            let ns_id = push_scope(scopes, Some(parent_id), node_span(node), ScopeKind::Type);
            // Peel the declaration_list body.
            if let Some(body) = node.child_by_field_name("body") {
                for child in body.children(&mut body.walk()) {
                    scope_dfs(&child, ns_id, scopes);
                }
            } else {
                for child in node.children(&mut node.walk()) {
                    scope_dfs(&child, ns_id, scopes);
                }
            }
        }
        "class_specifier" | "struct_specifier" | "union_specifier" => {
            let type_id = push_scope(scopes, Some(parent_id), node_span(node), ScopeKind::Type);
            // Peel the field_declaration_list body.
            if let Some(body) = node.child_by_field_name("body") {
                for child in body.children(&mut body.walk()) {
                    scope_dfs(&child, type_id, scopes);
                }
            } else {
                for child in node.children(&mut node.walk()) {
                    scope_dfs(&child, type_id, scopes);
                }
            }
        }
        "function_definition" | "lambda_expression" => {
            let fn_id = push_scope(
                scopes,
                Some(parent_id),
                node_span(node),
                ScopeKind::Function,
            );
            // Peel the body compound_statement to avoid a redundant Block scope.
            if let Some(body) = node.child_by_field_name("body") {
                for child in body.children(&mut body.walk()) {
                    scope_dfs(&child, fn_id, scopes);
                }
            }
        }
        "compound_statement" => {
            // A bare block NOT already consumed as a function/lambda body.
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

/// Collect parameter and local-variable [`Binding`]s for one C++ file.
///
/// Covers:
/// - `function_definition` parameters → [`BindingKind::Param`].
/// - `lambda_expression` parameters → [`BindingKind::Param`].
/// - `declaration` nodes inside a `Function` or `Block` scope → [`BindingKind::Local`].
/// - `for_range_loop` declarators inside a `Function` or `Block` scope → [`BindingKind::Local`].
///
/// Namespace bodies open a `Type` scope (not `Function`/`Block`), so namespace-level
/// declarations and class members are excluded from `Local` via the scope-kind guard.
fn collect_bindings(root: &Node, bytes: &[u8], scopes: &[Scope]) -> Vec<Binding> {
    let mut out = Vec::new();
    collect_bindings_dfs(root, bytes, scopes, &mut out);
    out
}

fn collect_bindings_dfs(node: &Node, bytes: &[u8], scopes: &[Scope], out: &mut Vec<Binding>) {
    match node.kind() {
        "function_definition" => {
            // Parameters live in function_declarator → parameters.
            // Use find_function_declarator to handle pointer/reference-return types.
            if let Some(decl) = node.child_by_field_name("declarator") {
                if let Some(fn_decl) = find_function_declarator(&decl) {
                    if let Some(params) = fn_decl.child_by_field_name("parameters") {
                        collect_params(&params, bytes, scopes, out);
                    }
                }
            }
            // Recurse into all children to pick up body bindings.
            for child in node.children(&mut node.walk()) {
                collect_bindings_dfs(&child, bytes, scopes, out);
            }
        }
        "lambda_expression" => {
            // Lambda parameters live in: declarator (abstract_function_declarator) → parameters.
            if let Some(fn_decl) = node.child_by_field_name("declarator") {
                if let Some(params) = fn_decl.child_by_field_name("parameters") {
                    collect_params(&params, bytes, scopes, out);
                }
            }
            // Recurse into all children to pick up body bindings.
            for child in node.children(&mut node.walk()) {
                collect_bindings_dfs(&child, bytes, scopes, out);
            }
        }
        "declaration" => {
            // Emit Local bindings only when the innermost scope is Function or Block.
            // This prevents namespace-level globals and class members from becoming Locals.
            let mut cursor = node.walk();
            for (i, child) in node.children(&mut cursor).enumerate() {
                if node.field_name_for_child(i as u32) == Some("declarator") {
                    if let Some((name, _)) = declarator_name(&child, bytes) {
                        let intro = child.start_byte();
                        if let Some(sid) = innermost_scope(intro, scopes) {
                            if matches!(scopes[sid].kind, ScopeKind::Function | ScopeKind::Block) {
                                push_binding(out, name, intro, BindingKind::Local, scopes);
                            }
                        }
                    }
                }
                // Recurse into EVERY child, including the declarator: a C++ initializer
                // (e.g. `auto f = [](int x){...};`) holds a lambda whose own parameters
                // must be collected. Recursing the `init_declarator` re-emits no Local
                // (it is not a `declaration` node), so there is no double-binding.
                collect_bindings_dfs(&child, bytes, scopes, out);
            }
        }
        "for_range_loop" => {
            // Range-based for: `for (int v : container)` — the declarator field.
            if let Some(decl) = node.child_by_field_name("declarator") {
                if let Some((name, _)) = declarator_name(&decl, bytes) {
                    let intro = decl.start_byte();
                    if let Some(sid) = innermost_scope(intro, scopes) {
                        if matches!(scopes[sid].kind, ScopeKind::Function | ScopeKind::Block) {
                            push_binding(out, name, intro, BindingKind::Local, scopes);
                        }
                    }
                }
            }
            // Recurse into children to catch nested bindings.
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

/// Emit a [`BindingKind::Param`] for each named parameter in a C++
/// `parameter_list` node. Handles `parameter_declaration`,
/// `optional_parameter_declaration`, and `variadic_parameter_declaration`
/// children; skips entries with no `declarator` field (unnamed or `void`).
fn collect_params(params: &Node, bytes: &[u8], scopes: &[Scope], out: &mut Vec<Binding>) {
    for child in params.children(&mut params.walk()) {
        match child.kind() {
            "parameter_declaration"
            | "optional_parameter_declaration"
            | "variadic_parameter_declaration" => {}
            _ => continue,
        }
        let Some(decl) = child.child_by_field_name("declarator") else {
            // Unnamed parameter or `(void)` — skip.
            continue;
        };
        let Some((name, _)) = declarator_name(&decl, bytes) else {
            continue;
        };
        let intro = decl.start_byte();
        // Parameters are always inside a function scope — no kind guard needed.
        push_binding(out, name, intro, BindingKind::Param, scopes);
    }
}

/// Recursively walk `node` collecting `Inherit` references for every
/// `class_specifier` and `struct_specifier` in the tree (including nested
/// classes and those inside namespace blocks).
fn collect_inheritance(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    match node.kind() {
        "class_specifier" | "struct_specifier" => {
            // Find the base_class_clause child (may be absent for types with no bases).
            if let Some(clause) = node
                .children(&mut node.walk())
                .find(|c| c.kind() == "base_class_clause")
            {
                for base in clause.children(&mut clause.walk()) {
                    match base.kind() {
                        "type_identifier" | "qualified_identifier" | "template_type" => {
                            super::push_ref(
                                out,
                                super::simple_type_name(node_text(&base, bytes), "::"),
                                &base,
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

    // Recurse into all children so nested classes and namespace bodies are covered.
    for child in node.children(&mut node.walk()) {
        collect_inheritance(&child, bytes, file, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn by_name<'a>(facts: &'a FileFacts, n: &str) -> Option<&'a Symbol> {
        facts.symbols.iter().find(|s| s.name == n)
    }

    #[test]
    fn free_function_in_namespace() {
        let src = r#"
namespace io {
    int connect(const char *host) { return 0; }
}
"#;
        let facts = CppExtractor.extract(src, "src/net/sock.cpp").unwrap();
        let f = by_name(&facts, "connect").unwrap();
        assert_eq!(f.kind, SymbolKind::Function);
        assert_eq!(
            f.id.to_scip_string(),
            "codegraph . . . net/sock/io/connect()."
        );
        assert_eq!(facts.lang, "cpp");
    }

    #[test]
    fn class_visibility() {
        let src = r#"
namespace io {
    class Sock {
    public:
        void open();
    private:
        void shutdown();
    };
}
"#;
        let facts = CppExtractor.extract(src, "src/net/sock.cpp").unwrap();

        let sock = by_name(&facts, "Sock").unwrap();
        assert_eq!(sock.kind, SymbolKind::Class);
        assert_eq!(
            sock.id.to_scip_string(),
            "codegraph . . . net/sock/io/Sock#"
        );

        let open = by_name(&facts, "open").unwrap();
        assert_eq!(open.kind, SymbolKind::Method);
        assert_eq!(
            open.id.to_scip_string(),
            "codegraph . . . net/sock/io/Sock#open()."
        );

        // private method — must be absent
        assert!(by_name(&facts, "shutdown").is_none());
    }

    #[test]
    fn struct_field_default_public() {
        let src = r#"
struct Point {
    int x;
    int y;
};
"#;
        let facts = CppExtractor.extract(src, "src/geo.cpp").unwrap();

        let point = by_name(&facts, "Point").unwrap();
        assert_eq!(point.kind, SymbolKind::Struct);
        assert_eq!(point.id.to_scip_string(), "codegraph . . . geo/Point#");

        let x = by_name(&facts, "x").unwrap();
        assert_eq!(x.kind, SymbolKind::Static);
        assert_eq!(x.id.to_scip_string(), "codegraph . . . geo/Point#x.");
    }

    #[test]
    fn enum_and_alias() {
        let src = r#"
enum Color { Red, Green };
using Id = int;
typedef int Handle;
"#;
        let facts = CppExtractor.extract(src, "src/types.cpp").unwrap();

        let color = by_name(&facts, "Color").unwrap();
        assert_eq!(color.kind, SymbolKind::Enum);
        assert_eq!(color.id.to_scip_string(), "codegraph . . . types/Color#");

        let id = by_name(&facts, "Id").unwrap();
        assert_eq!(id.kind, SymbolKind::TypeAlias);
        assert_eq!(id.id.to_scip_string(), "codegraph . . . types/Id#");

        let handle = by_name(&facts, "Handle").unwrap();
        assert_eq!(handle.kind, SymbolKind::TypeAlias);
        assert_eq!(handle.id.to_scip_string(), "codegraph . . . types/Handle#");
    }

    #[test]
    fn define_macro() {
        let src = r#"
#define MAX_CONN 64
"#;
        let facts = CppExtractor.extract(src, "src/conf.hpp").unwrap();
        let m = by_name(&facts, "MAX_CONN").unwrap();
        assert_eq!(m.kind, SymbolKind::Const);
        assert_eq!(m.id.to_scip_string(), "codegraph . . . conf/MAX_CONN!");
    }

    #[test]
    fn extracts_call_references() {
        let src = r#"
void run() {
    connect("host");
    obj.handle();
}
"#;
        let facts = CppExtractor.extract(src, "src/main.cpp").unwrap();
        let names: Vec<&str> = facts.references.iter().map(|r| r.name.as_str()).collect();
        assert!(
            names.contains(&"connect"),
            "expected 'connect' in {names:?}"
        );
        assert!(names.contains(&"handle"), "expected 'handle' in {names:?}");
    }

    #[test]
    fn inherit_single_public_base() {
        let src = "class Derived : public Base {};";
        let facts = CppExtractor.extract(src, "src/foo.cpp").unwrap();
        let inherit: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(inherit, vec!["Base"], "expected [Base], got {inherit:?}");
    }

    #[test]
    fn inherit_struct_multiple_bases() {
        let src = "struct S : A, B {};";
        let facts = CppExtractor.extract(src, "src/foo.cpp").unwrap();
        let mut inherit: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();
        inherit.sort_unstable();
        assert_eq!(inherit, vec!["A", "B"], "expected [A, B], got {inherit:?}");
    }

    #[test]
    fn inherit_qualified_base_strips_namespace() {
        let src = "class X : public ns::Base {};";
        let facts = CppExtractor.extract(src, "src/foo.cpp").unwrap();
        let inherit: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(inherit, vec!["Base"], "expected [Base], got {inherit:?}");
    }

    // ── Tier-B scope / binding tests ─────────────────────────────────────────

    #[test]
    fn params_emit_param_bindings() {
        // `void add(int a, int b){}` → Param `a`, `b` in Function scope.
        let src = "void add(int a, int b){}\n";
        let facts = CppExtractor.extract(src, "src/math.cpp").unwrap();

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

    #[test]
    fn reference_param_emits_param_binding() {
        // `void inc(int& r){}` → Param `r` (exercises reference_declarator unwrap).
        let src = "void inc(int& r){}\n";
        let facts = CppExtractor.extract(src, "src/inc.cpp").unwrap();

        let r = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Param && b.name == "r")
            .expect("expected a Param binding for 'r'");
        assert_eq!(
            facts.scopes[r.scope].kind,
            ScopeKind::Function,
            "reference param 'r' should be in a Function scope"
        );
    }

    #[test]
    fn optional_param_emits_param_binding() {
        // `void f(int x, int y = 0){}` → Param `x`, `y` (optional_parameter_declaration).
        let src = "void f(int x, int y = 0){}\n";
        let facts = CppExtractor.extract(src, "src/f.cpp").unwrap();

        let mut param_names: Vec<&str> = facts
            .bindings
            .iter()
            .filter(|b| b.kind == BindingKind::Param)
            .map(|b| b.name.as_str())
            .collect();
        param_names.sort_unstable();
        assert_eq!(
            param_names,
            vec!["x", "y"],
            "expected Param bindings for x and y, got {param_names:?}"
        );
    }

    #[test]
    fn pointer_return_function_params_collected() {
        // `char* dup(const char* s){return 0;}` — pointer_declarator wraps the
        // function_declarator; find_function_declarator must reach the parameters.
        let src = "char* dup(const char* s){return 0;}\n";
        let facts = CppExtractor.extract(src, "src/dup.cpp").unwrap();

        let s = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Param && b.name == "s")
            .expect("pointer-return function's param 's' should be collected");
        assert_eq!(
            facts.scopes[s.scope].kind,
            ScopeKind::Function,
            "param 's' should be in a Function scope"
        );
    }

    #[test]
    fn local_var_emits_local_binding() {
        // `void f(){ int x = 0; }` → Local `x` in a Function or Block scope.
        let src = "void f(){ int x = 0; }\n";
        let facts = CppExtractor.extract(src, "src/f.cpp").unwrap();

        let x = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Local && b.name == "x")
            .expect("expected a Local binding for 'x'");
        assert_ne!(x.scope, 0, "local 'x' must NOT be in scope 0 (file root)");
        assert!(
            matches!(
                facts.scopes[x.scope].kind,
                ScopeKind::Function | ScopeKind::Block
            ),
            "local 'x' scope must be Function or Block, got {:?}",
            facts.scopes[x.scope].kind
        );
    }

    #[test]
    fn range_for_emits_local_binding() {
        // `void f(){ int a[3]={}; for (int v : a){} }` → Local `v`.
        let src = "void f(){ int a[3]={}; for (int v : a){} }\n";
        let facts = CppExtractor.extract(src, "src/f.cpp").unwrap();

        let v = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Local && b.name == "v")
            .expect("expected a Local binding for 'v'");
        assert_ne!(v.scope, 0, "range-for 'v' must NOT be in scope 0");
    }

    #[test]
    fn namespace_global_not_a_local() {
        // `namespace ns { int g; void f(){} }` → NO Local `g`; Definition `g` exists.
        let src = "namespace ns { int g; void f(){} }\n";
        let facts = CppExtractor.extract(src, "src/ns.cpp").unwrap();

        assert!(
            !facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Local && b.name == "g"),
            "namespace global 'g' must NOT be a Local binding"
        );
        assert!(
            facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Definition && b.name == "g"),
            "namespace global 'g' must have a Definition binding"
        );
    }

    #[test]
    fn class_fields_not_locals() {
        // `struct P { int x; int y; };` → NO Local x/y; Definition x/y exist.
        let src = "struct P { int x; int y; };\n";
        let facts = CppExtractor.extract(src, "src/p.cpp").unwrap();

        assert!(
            !facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Local && (b.name == "x" || b.name == "y")),
            "class fields must NOT be Local bindings"
        );
        assert!(
            facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Definition && b.name == "x"),
            "struct field 'x' must have a Definition binding"
        );
        assert!(
            facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Definition && b.name == "y"),
            "struct field 'y' must have a Definition binding"
        );
    }

    #[test]
    fn nesting_produces_type_and_function_scopes() {
        // `struct S { void m(){ int v=0; } };` → Module(0) + Type + Function; Local v in Function.
        let src = "struct S { void m(){ int v=0; } };\n";
        let facts = CppExtractor.extract(src, "src/s.cpp").unwrap();

        let has_type = facts.scopes.iter().any(|s| s.kind == ScopeKind::Type);
        let has_fn = facts.scopes.iter().any(|s| s.kind == ScopeKind::Function);
        assert!(has_type, "expected a Type scope for struct body");
        assert!(has_fn, "expected a Function scope for method body");

        let v = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Local && b.name == "v")
            .expect("expected a Local binding for 'v'");
        assert!(
            matches!(
                facts.scopes[v.scope].kind,
                ScopeKind::Function | ScopeKind::Block
            ),
            "local 'v' must be in a Function or Block scope"
        );
    }

    #[test]
    fn namespace_body_opens_type_scope() {
        // `namespace io { void f(){} }` → >=3 scopes incl a Type for the namespace body.
        let src = "namespace io { void f(){} }\n";
        let facts = CppExtractor.extract(src, "src/io.cpp").unwrap();

        assert!(
            facts.scopes.len() >= 3,
            "expected at least 3 scopes (Module + Type for namespace + Function), got {}",
            facts.scopes.len()
        );
        assert!(
            facts.scopes.iter().any(|s| s.kind == ScopeKind::Type),
            "expected a Type scope for namespace body"
        );
    }

    #[test]
    fn lambda_params_emit_param_bindings() {
        // `void f(){ auto fn = [](int x, int y){}; }` → Param x, y.
        let src = "void f(){ auto fn = [](int x, int y){}; }\n";
        let facts = CppExtractor.extract(src, "src/f.cpp").unwrap();

        let mut param_names: Vec<&str> = facts
            .bindings
            .iter()
            .filter(|b| b.kind == BindingKind::Param)
            .map(|b| b.name.as_str())
            .collect();
        param_names.sort_unstable();
        assert_eq!(
            param_names,
            vec!["x", "y"],
            "expected Param bindings for lambda params x and y, got {param_names:?}"
        );
    }

    #[test]
    fn same_file_call_ref_has_non_zero_scope_and_callee_has_definition() {
        // Two non-static funcs where one calls the other.
        // Assert: Definition binding for callee exists AND the call Reference has scope == Some(non-zero).
        let src = "int helper(){return 0;}\nint caller(){return helper();}\n";
        let facts = CppExtractor.extract(src, "src/pair.cpp").unwrap();

        // Definition binding for `helper` must exist.
        assert!(
            facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Definition && b.name == "helper"),
            "expected a Definition binding for 'helper'"
        );

        // The `helper()` call reference must have a non-zero (non-module) scope.
        let call_ref = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Call && r.name == "helper")
            .expect("expected a Call ref for 'helper'");
        assert!(
            call_ref.scope.is_some() && call_ref.scope != Some(0),
            "helper() call ref must be in a non-zero scope, got {:?}",
            call_ref.scope
        );
    }

    #[test]
    fn out_of_line_method_param_collected() {
        // `class Foo {};\nvoid Foo::bar(int a){}\n` → Param `a` in a Function scope.
        let src = "class Foo {};\nvoid Foo::bar(int a){}\n";
        let facts = CppExtractor.extract(src, "src/foo.cpp").unwrap();

        let a = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Param && b.name == "a")
            .expect("expected a Param binding for 'a' in out-of-line method");
        assert_eq!(
            facts.scopes[a.scope].kind,
            ScopeKind::Function,
            "param 'a' should be in a Function scope"
        );
    }
}
