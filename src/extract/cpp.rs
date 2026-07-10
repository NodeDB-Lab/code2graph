// SPDX-License-Identifier: Apache-2.0

//! C++ extractor — one tree-sitter pass yielding definitions and references.
//!
//! Definitions: namespaces, classes/structs/unions and their members (all
//! access levels — `Public`, `Private`, `Protected`), free functions and
//! variables, enums, type aliases (`typedef` /
//! `using T = X`), and preprocessor macros (`#define`). Qualified identity is
//! derived from the file path (`src/net/sock.cpp` → namespaces `net`, `sock`),
//! then extended by `namespace` blocks and class scopes. The same stem is
//! shared by source and header files so paired translation units share a
//! namespace.
//! References: callee identifiers of `call_expression` nodes (free calls,
//! method calls, and qualified calls).
//!
//! Emits neutral [`FileFacts`] — no storage entries, no source bodies.

use tree_sitter::{Node, Parser};

use crate::error::{CodegraphError, Result};
use crate::graph::types::{
    Binding, BindingKind, ByteSpan, EntryPoint, FileFacts, RefRole, Reference, Scope, ScopeId,
    ScopeKind, Symbol, SymbolKind, TypeRefContext, Visibility,
};
use crate::lang::Language;
use crate::symbol::Descriptor;

use super::{
    ExtractCtx, Extractor, MIN_REF_LEN, attach_reference_scopes, collect_call_references,
    definition_bindings, field_text, innermost_scope, is_static, make_symbol, node_span, node_text,
    one_line_signature, push_binding, push_ref, push_scope, push_type_ref,
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
        let ts_language = crate::grammar::cpp();
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
        let ctx = ExtractCtx {
            bytes,
            file,
            lang: Language::Cpp,
        };
        let namespaces = cpp_namespaces(file);

        let mut defs = Vec::new();
        collect_defs(&root, &namespaces, &ctx, &mut defs);
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
        collect_read_references(&root, bytes, file, &mut references);
        collect_write_references(&root, bytes, file, &mut references);
        collect_type_references(&root, bytes, file, &mut references);

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
    ctx: &ExtractCtx,
    node: &Node,
    prefix: &[Descriptor],
    leaf: Descriptor,
    kind: SymbolKind,
    visibility: Visibility,
) {
    let name = leaf.name().to_owned();
    let mut descriptors = prefix.to_vec();
    descriptors.push(leaf);
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
fn collect_defs(container: &Node, namespaces: &[String], ctx: &ExtractCtx, out: &mut Vec<Symbol>) {
    for child in container.children(&mut container.walk()) {
        process_node(&child, namespaces, ctx, out);
    }
}

/// Process a single declaration-level node.
fn process_node(node: &Node, namespaces: &[String], ctx: &ExtractCtx, out: &mut Vec<Symbol>) {
    match node.kind() {
        "namespace_definition" => {
            // Extend the namespace chain with the (possibly nested or absent) name.
            let mut nested = namespaces.to_vec();
            if let Some(name) = node.child_by_field_name("name") {
                for seg in node_text(&name, ctx.bytes).split("::") {
                    if !seg.is_empty() {
                        nested.push(seg.to_owned());
                    }
                }
            }
            if let Some(body) = node.child_by_field_name("body") {
                collect_defs(&body, &nested, ctx, out);
            }
        }

        "function_definition" => {
            let vis = if is_static(node, ctx.bytes) {
                Visibility::Private
            } else {
                Visibility::Public
            };
            let Some(decl) = node.child_by_field_name("declarator") else {
                return;
            };
            let Some((name, _)) = declarator_name(&decl, ctx.bytes) else {
                return;
            };
            let is_main = name == "main";
            let prefix = namespace_prefix(namespaces);
            push_symbol(
                out,
                ctx,
                node,
                &prefix,
                Descriptor::Method {
                    name,
                    disambiguator: crate::symbol::MethodDisambiguator::empty(),
                },
                SymbolKind::Function,
                vis,
            );
            // Only free/namespace functions reach this arm — class methods are
            // handled in `collect_members`, so `Foo::main` is never flagged.
            if is_main {
                if let Some(s) = out.last_mut() {
                    s.entry_points.push(EntryPoint::Main);
                }
            }
        }

        "declaration" => {
            let vis = if is_static(node, ctx.bytes) {
                Visibility::Private
            } else {
                Visibility::Public
            };
            // A class/struct/union/enum specifier in the `type` field with a
            // body is an aggregate definition; emit it (and its members).
            if let Some(spec) = node.child_by_field_name("type") {
                emit_aggregate(&spec, namespaces, ctx, out);
            }
            let prefix = namespace_prefix(namespaces);
            let mut cursor = node.walk();
            for decl in node.children_by_field_name("declarator", &mut cursor) {
                let Some((name, is_function)) = declarator_name(&decl, ctx.bytes) else {
                    continue;
                };
                if is_function {
                    push_symbol(
                        out,
                        ctx,
                        node,
                        &prefix,
                        Descriptor::Method {
                            name,
                            disambiguator: crate::symbol::MethodDisambiguator::empty(),
                        },
                        SymbolKind::Function,
                        vis,
                    );
                } else {
                    push_symbol(
                        out,
                        ctx,
                        node,
                        &prefix,
                        Descriptor::Term(name),
                        SymbolKind::Static,
                        vis,
                    );
                }
            }
        }

        // A bare top-level `class/struct/union/enum Name { ... };`.
        "class_specifier" | "struct_specifier" | "union_specifier" | "enum_specifier" => {
            emit_aggregate(node, namespaces, ctx, out);
        }

        "type_definition" => {
            if let Some(spec) = node.child_by_field_name("type") {
                emit_aggregate(&spec, namespaces, ctx, out);
            }
            let Some(decl) = node.child_by_field_name("declarator") else {
                return;
            };
            let Some((name, _)) = declarator_name(&decl, ctx.bytes) else {
                return;
            };
            let prefix = namespace_prefix(namespaces);
            push_symbol(
                out,
                ctx,
                node,
                &prefix,
                Descriptor::Type(name),
                SymbolKind::TypeAlias,
                Visibility::Public,
            );
        }

        // `using T = X;`
        "alias_declaration" => {
            let Some(name) = field_text(node, "name", ctx.bytes) else {
                return;
            };
            let prefix = namespace_prefix(namespaces);
            push_symbol(
                out,
                ctx,
                node,
                &prefix,
                Descriptor::Type(name),
                SymbolKind::TypeAlias,
                Visibility::Public,
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
                    process_node(&c, namespaces, ctx, out);
                }
            }
        }

        "preproc_def" => {
            if let Some(name) = field_text(node, "name", ctx.bytes) {
                let prefix = namespace_prefix(namespaces);
                push_symbol(
                    out,
                    ctx,
                    node,
                    &prefix,
                    Descriptor::Macro(name),
                    SymbolKind::Const,
                    Visibility::Public,
                );
            }
        }

        "preproc_function_def" => {
            if let Some(name) = field_text(node, "name", ctx.bytes) {
                let prefix = namespace_prefix(namespaces);
                push_symbol(
                    out,
                    ctx,
                    node,
                    &prefix,
                    Descriptor::Macro(name),
                    SymbolKind::Function,
                    Visibility::Public,
                );
            }
        }

        _ => {}
    }
}

/// If `spec` is a class/struct/union/enum specifier with a body (a definition,
/// not a forward declaration), emit the type symbol and recurse into members.
fn emit_aggregate(spec: &Node, namespaces: &[String], ctx: &ExtractCtx, out: &mut Vec<Symbol>) {
    let (kind, default_vis, is_enum) = match spec.kind() {
        "class_specifier" => (SymbolKind::Class, Visibility::Private, false),
        "struct_specifier" => (SymbolKind::Struct, Visibility::Public, false),
        // NOTE: no Union variant — unions map to Struct.
        "union_specifier" => (SymbolKind::Struct, Visibility::Public, false),
        "enum_specifier" => (SymbolKind::Enum, Visibility::Public, true),
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
    let Some(name) = type_leaf_name(&name_node, ctx.bytes) else {
        return;
    };

    let prefix = namespace_prefix(namespaces);
    push_symbol(
        out,
        ctx,
        spec,
        &prefix,
        Descriptor::Type(name.clone()),
        kind,
        Visibility::Public,
    );

    // Enumerators are not emitted individually (mirrors the C extractor).
    if is_enum {
        return;
    }

    // The type's own descriptor prefix for nested members.
    let mut type_prefix = prefix;
    type_prefix.push(Descriptor::Type(name));
    collect_members(&body, &type_prefix, default_vis, ctx, out);
}

/// Collect all members of a `field_declaration_list`, tracking visibility
/// statefully via `access_specifier` nodes encountered in order.
///
/// All members emit regardless of access level; each is tagged with the
/// `Visibility` in effect at its declaration site:
/// - `class` default → `Private`; `struct`/`union` default → `Public`.
/// - `public:` specifier → `Public`; `private:` → `Private`; `protected:` → `Protected`.
fn collect_members(
    body: &Node,
    type_prefix: &[Descriptor],
    default_vis: Visibility,
    ctx: &ExtractCtx,
    out: &mut Vec<Symbol>,
) {
    let mut current_vis = default_vis;
    for member in body.children(&mut body.walk()) {
        match member.kind() {
            "access_specifier" => {
                let text = node_text(&member, ctx.bytes);
                current_vis = if text.starts_with("public") {
                    Visibility::Public
                } else if text.starts_with("protected") {
                    Visibility::Protected
                } else {
                    Visibility::Private
                };
            }
            "function_definition" => {
                let Some(decl) = member.child_by_field_name("declarator") else {
                    continue;
                };
                let Some((name, _)) = declarator_name(&decl, ctx.bytes) else {
                    continue;
                };
                push_symbol(
                    out,
                    ctx,
                    &member,
                    type_prefix,
                    Descriptor::Method {
                        name,
                        disambiguator: crate::symbol::MethodDisambiguator::empty(),
                    },
                    SymbolKind::Method,
                    current_vis,
                );
            }
            "field_declaration" => {
                let Some(decl) = member.child_by_field_name("declarator") else {
                    continue;
                };
                let Some((name, is_function)) = declarator_name(&decl, ctx.bytes) else {
                    continue;
                };
                if is_function {
                    push_symbol(
                        out,
                        ctx,
                        &member,
                        type_prefix,
                        Descriptor::Method {
                            name,
                            disambiguator: crate::symbol::MethodDisambiguator::empty(),
                        },
                        SymbolKind::Method,
                        current_vis,
                    );
                } else {
                    push_symbol(
                        out,
                        ctx,
                        &member,
                        type_prefix,
                        Descriptor::Term(name),
                        SymbolKind::Static,
                        current_vis,
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
                emit_aggregate(&member, &nested_ns, ctx, out);
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

// ── Edge richness: Read / Write ──────────────────────────────────────────────

/// Returns `true` when `node` (an `identifier`) is in a position already
/// captured by another collector and must NOT also be emitted as a
/// [`RefRole::Read`] reference.
///
/// Skipped positions (C++ grammar):
/// - Call callee: `call_expression` `function:` field bare `identifier`.
/// - Declaration names extracted via the declarator chain: any `identifier`
///   that is the leaf of a `declarator` field under `function_definition`,
///   `declaration`, or `field_declaration`.
/// - Parameter declarator names: bare `identifier` inside
///   `parameter_declaration`, `optional_parameter_declaration`, or
///   `variadic_parameter_declaration` (reached via the `declarator` field).
/// - Field access name: `field_expression` `field:` field (`field_identifier`,
///   a different node kind — but guard defensively in case grammar emits
///   `identifier` there too).
/// - Assignment LHS: `assignment_expression` `left:` — handled by writes.
fn is_non_read_position(node: &Node) -> bool {
    let parent = match node.parent() {
        Some(p) => p,
        None => return true,
    };
    match parent.kind() {
        // Call callee: free call `f()` — identifier is the `function:` field.
        "call_expression" => parent.child_by_field_name("function").as_ref() == Some(node),
        // Qualified call callee: `Ns::f()` — `name:` field of qualified_identifier
        // which is the `function:` of the call.  The `qualified_identifier` case
        // is caught by is_non_read_position on the qualifier check below; here
        // we skip the immediate `name:` identifier.
        "qualified_identifier" => parent.child_by_field_name("name").as_ref() == Some(node),
        // Declarator leaf names — the `declarator:` field chain of
        // function_definition / declaration / field_declaration / init_declarator etc.
        // declarator_name walks this chain; we skip every identifier that sits
        // directly inside any declarator-family node's `declarator` field.
        "function_declarator"
        | "pointer_declarator"
        | "reference_declarator"
        | "array_declarator"
        | "init_declarator"
        | "attributed_declarator" => {
            parent.child_by_field_name("declarator").as_ref() == Some(node)
        }
        // Parameter declarator binding — the identifier reached via the
        // `declarator` field inside parameter_declaration / optional_parameter /
        // variadic_parameter.
        "parameter_declaration"
        | "optional_parameter_declaration"
        | "variadic_parameter_declaration" => {
            // The `declarator` field is the binding; skip it.
            parent.child_by_field_name("declarator").as_ref() == Some(node)
        }
        // Field access name (`obj->field` / `obj.field`): the `field:` field is a
        // `field_identifier`, not an `identifier`, so this arm is defensive only.
        "field_expression" => parent.child_by_field_name("field").as_ref() == Some(node),
        // Assignment LHS — handled by collect_write_references.
        "assignment_expression" => parent.child_by_field_name("left").as_ref() == Some(node),
        _ => false,
    }
}

/// Recursively walk `node` and emit [`RefRole::Read`] references for bare
/// `identifier` nodes used in value/expression positions. Applies [`MIN_REF_LEN`].
///
/// Skips:
/// - Call callees (already [`RefRole::Call`]).
/// - Declarator-chain leaf names (declaration names, parameter names).
/// - `qualified_identifier` `name:` parts (the callee in qualified calls).
/// - `field_expression` `field:` identifiers (field_identifier kind, excluded by
///   node kind; guard in `is_non_read_position` handles any identifier there).
/// - Assignment LHS (handled by [`collect_write_references`]).
///
/// The object/base of a `field_expression` (e.g. `ptr` in `ptr->field`) IS
/// emitted as a Read because it is an `identifier` in the `argument:` position.
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
/// bare-identifier LHS of `assignment_expression` nodes (e.g. `x = 5`,
/// `x += 1`, `x -= 1`).
///
/// Note: `int x = 5;` is a `declaration` with an `init_declarator` (a
/// definition), NOT an `assignment_expression`, so it is not emitted here.
/// Member / subscript / dereference LHS (`obj.field = …`, `arr[i] = …`,
/// `*p = …`) are not covered in v1 — only bare identifiers. Applies [`MIN_REF_LEN`].
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

// ── Edge richness: TypeRef ───────────────────────────────────────────────────

/// Emit a single [`RefRole::TypeRef`] for a type node, given the outer context.
///
/// Handles `type_identifier`, `template_type`, and `qualified_identifier` leaves.
/// For `template_type`: emits the base name (with the given `ctx`), then recurses
/// into `type_arguments` / `template_argument_list` children with `GenericArg`.
/// Skips `primitive_type`, `sized_type_specifier`, and
/// `placeholder_type_specifier` (auto) — these are C++ built-ins.
fn emit_cpp_type_node(
    node: &Node,
    bytes: &[u8],
    file: &str,
    ctx: TypeRefContext,
    out: &mut Vec<Reference>,
) {
    match node.kind() {
        // Skip primitives and auto — not user-defined types.
        "primitive_type" | "sized_type_specifier" | "placeholder_type_specifier" => {}

        "type_identifier" => {
            let name = node_text(node, bytes);
            push_type_ref(out, name, node, file, ctx);
        }

        "qualified_identifier" => {
            // Recurse into the final `name:` segment so a templated tail like
            // `std::vector<Config>` yields base `vector` + GenericArg `Config`,
            // rather than text-splitting to `vector<Config>`. Fall back to the
            // last `::` text segment only when there is no structured name field.
            if let Some(name_node) = node.child_by_field_name("name") {
                emit_cpp_type_node(&name_node, bytes, file, ctx, out);
            } else {
                let text = node_text(node, bytes);
                let leaf = text.rsplit("::").next().unwrap_or(text);
                if !leaf.is_empty() {
                    push_type_ref(out, leaf, node, file, ctx);
                }
            }
        }

        "template_type" => {
            // Base name: the `name` field is a `type_identifier` or
            // `qualified_identifier` identifying the template itself.
            if let Some(name_node) = node.child_by_field_name("name") {
                // Use type_leaf_name to strip any inner qualification.
                if let Some(leaf) = type_leaf_name(&name_node, bytes) {
                    push_type_ref(out, &leaf, &name_node, file, ctx);
                }
            }
            // Type arguments: `template_argument_list` contains the generic args.
            // tree-sitter-cpp names this field "arguments" with kind
            // "template_argument_list". Walk all named children that are type nodes.
            for child in node.children(&mut node.walk()) {
                if child.kind() == "template_argument_list" {
                    for arg in child.children(&mut child.walk()) {
                        // type arguments appear as `type_descriptor` children which
                        // hold a `type:` field, or directly as type nodes.
                        match arg.kind() {
                            "type_descriptor" => {
                                if let Some(t) = arg.child_by_field_name("type") {
                                    emit_cpp_type_node(
                                        &t,
                                        bytes,
                                        file,
                                        TypeRefContext::GenericArg,
                                        out,
                                    );
                                }
                            }
                            "type_identifier" | "qualified_identifier" | "template_type" => {
                                emit_cpp_type_node(
                                    &arg,
                                    bytes,
                                    file,
                                    TypeRefContext::GenericArg,
                                    out,
                                );
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        _ => {}
    }
}

/// Recursively walk `node` and emit [`RefRole::TypeRef`] references for
/// user-defined type names in annotation positions.
///
/// Covered positions (tree-sitter-cpp grammar):
/// - `parameter_declaration` / `optional_parameter_declaration` `type:` field
///   → [`TypeRefContext::ParameterType`]
/// - `function_definition` `type:` field (return type)
///   → [`TypeRefContext::ReturnType`]
/// - `field_declaration` (inside `field_declaration_list`) `type:` field
///   → [`TypeRefContext::Field`]
/// - `template_type` → base name with outer context + recurse args with
///   [`TypeRefContext::GenericArg`]
///
/// Skips `primitive_type`, `sized_type_specifier`, and `placeholder_type_specifier`.
fn collect_type_references(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    match node.kind() {
        // Parameter types: `void f(Config c)` — the `type:` field of the parameter node.
        "parameter_declaration" | "optional_parameter_declaration" => {
            if let Some(type_node) = node.child_by_field_name("type") {
                emit_cpp_type_node(&type_node, bytes, file, TypeRefContext::ParameterType, out);
            }
            // Recurse into children (e.g. default value expressions).
            for child in node.children(&mut node.walk()) {
                collect_type_references(&child, bytes, file, out);
            }
            return;
        }

        // Return types: `Config make() { ... }` — the `type:` field of function_definition.
        "function_definition" => {
            if let Some(type_node) = node.child_by_field_name("type") {
                emit_cpp_type_node(&type_node, bytes, file, TypeRefContext::ReturnType, out);
            }
            // Recurse into the declarator and body so nested functions are covered.
            for child in node.children(&mut node.walk()) {
                collect_type_references(&child, bytes, file, out);
            }
            return;
        }

        // Field types: `struct T { Config conf; };` — `type:` field of field_declaration.
        "field_declaration" => {
            if let Some(type_node) = node.child_by_field_name("type") {
                emit_cpp_type_node(&type_node, bytes, file, TypeRefContext::Field, out);
            }
            for child in node.children(&mut node.walk()) {
                collect_type_references(&child, bytes, file, out);
            }
            return;
        }

        _ => {}
    }

    for child in node.children(&mut node.walk()) {
        collect_type_references(&child, bytes, file, out);
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
    fn free_main_is_entry_point() {
        let facts = CppExtractor
            .extract("int main() { return 0; }", "src/main.cpp")
            .unwrap();
        let main = by_name(&facts, "main").unwrap();
        assert!(
            main.entry_points
                .iter()
                .any(|e| matches!(e, EntryPoint::Main))
        );
    }

    #[test]
    fn method_main_is_not_entry_point() {
        let facts = CppExtractor
            .extract("struct S { int main(); };", "src/s.cpp")
            .unwrap();
        let main = by_name(&facts, "main").unwrap();
        assert!(
            !main
                .entry_points
                .iter()
                .any(|e| matches!(e, EntryPoint::Main))
        );
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

        // public: section → Visibility::Public
        let open = by_name(&facts, "open").unwrap();
        assert_eq!(open.kind, SymbolKind::Method);
        assert_eq!(open.visibility, Visibility::Public);
        assert_eq!(
            open.id.to_scip_string(),
            "codegraph . . . net/sock/io/Sock#open()."
        );

        // private: section — must now emit with Visibility::Private
        let shutdown = by_name(&facts, "shutdown").unwrap();
        assert_eq!(shutdown.kind, SymbolKind::Method);
        assert_eq!(shutdown.visibility, Visibility::Private);
        assert_eq!(
            shutdown.id.to_scip_string(),
            "codegraph . . . net/sock/io/Sock#shutdown()."
        );
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

        // struct members default to Public
        let x = by_name(&facts, "x").unwrap();
        assert_eq!(x.kind, SymbolKind::Static);
        assert_eq!(x.visibility, Visibility::Public);
        assert_eq!(x.id.to_scip_string(), "codegraph . . . geo/Point#x.");

        let y = by_name(&facts, "y").unwrap();
        assert_eq!(y.visibility, Visibility::Public);
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

    // ── Edge richness: Read / Write ──────────────────────────────────────────

    #[test]
    fn read_ref_at_use_not_at_decl() {
        // `int f() { int base = 1; return base; }`
        // → Read ref for `base` at `return base`; the declarator `base` must NOT be Read.
        let src = "int f() { int base = 1; return base; }\n";
        let facts = CppExtractor.extract(src, "src/f.cpp").unwrap();
        let read_refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Read && r.name == "base")
            .collect();
        assert!(
            !read_refs.is_empty(),
            "expected at least one Read ref for 'base', got none"
        );
        // The `return base` starts after the init declarator (byte > 20).
        // In `int f() { int base = 1; return base; }`, `return` is near byte 27.
        let use_ref = read_refs
            .iter()
            .find(|r| r.occ.byte > 20)
            .expect("expected Read ref for 'base' in the return statement (byte > 20)");
        assert!(
            use_ref.occ.byte > 20,
            "Read ref should be at the use site, not the declaration"
        );
    }

    #[test]
    fn write_ref_emitted_for_assignment() {
        // `void f() { int cnt = 0; cnt = 5; }` → Write ref for `cnt` in `cnt = 5`.
        let src = "void f() { int cnt = 0; cnt = 5; }\n";
        let facts = CppExtractor.extract(src, "src/f.cpp").unwrap();
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

    #[test]
    fn call_not_also_read() {
        // `void f() { helper(); }` → Call ref "helper", but NOT also a Read ref.
        let src = "void f() { helper(); }\n";
        let facts = CppExtractor.extract(src, "src/f.cpp").unwrap();
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

    #[test]
    fn field_access_reads_ptr_not_field() {
        // `int f(S* ptr) { return ptr->field; }`
        // → Read "ptr" (the object), no Read "field" (field_identifier, not identifier).
        let src = "struct S { int field; };\nint f(S* ptr) { return ptr->field; }\n";
        let facts = CppExtractor.extract(src, "src/f.cpp").unwrap();
        // `ptr` should be a Read ref (it is an identifier in value position).
        let ptr_reads: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Read && r.name == "ptr")
            .collect();
        assert!(
            !ptr_reads.is_empty(),
            "expected a Read ref for 'ptr', got none"
        );
        // `field` is a `field_identifier` — must NOT appear as a Read ref.
        let field_reads: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Read && r.name == "field")
            .collect();
        assert!(
            field_reads.is_empty(),
            "field_identifier 'field' must NOT be a Read ref; got: {field_reads:?}"
        );
    }

    // ── TypeRef tests ────────────────────────────────────────────────────────

    #[test]
    fn type_ref_param_type() {
        // `void f(Config c) {}` → TypeRef "Config" ctx ParameterType.
        let src = "void f(Config c) {}\n";
        let facts = CppExtractor.extract(src, "src/f.cpp").unwrap();
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
    fn type_ref_return_type() {
        // `Config make() { return Config(); }` → TypeRef "Config" ctx ReturnType.
        let src = "Config make() { return Config(); }\n";
        let facts = CppExtractor.extract(src, "src/f.cpp").unwrap();
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
    fn type_ref_field_type() {
        // `struct T { Config conf; };` → TypeRef "Config" ctx Field.
        let src = "struct T { Config conf; };\n";
        let facts = CppExtractor.extract(src, "src/f.cpp").unwrap();
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
    fn type_ref_template_arg() {
        // `void f(std::vector<Config> xs) {}`
        // → TypeRef "vector" (ParameterType) + TypeRef "Config" (GenericArg).
        let src = "void f(std::vector<Config> xs) {}\n";
        let facts = CppExtractor.extract(src, "src/f.cpp").unwrap();
        let type_refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::TypeRef)
            .collect();
        // "vector" comes from the template_type base (qualified_identifier leaf).
        let vector_ref = type_refs.iter().find(|r| r.name == "vector");
        assert!(
            vector_ref.is_some(),
            "expected TypeRef 'vector', got: {:?}",
            type_refs.iter().map(|r| &r.name).collect::<Vec<_>>()
        );
        assert_eq!(
            vector_ref.unwrap().type_ref_ctx,
            Some(TypeRefContext::ParameterType),
            "expected ParameterType ctx for 'vector'"
        );
        // "Config" comes from the template_argument_list (GenericArg).
        let config_ref = type_refs.iter().find(|r| r.name == "Config");
        assert!(
            config_ref.is_some(),
            "expected TypeRef 'Config', got: {:?}",
            type_refs.iter().map(|r| &r.name).collect::<Vec<_>>()
        );
        assert_eq!(
            config_ref.unwrap().type_ref_ctx,
            Some(TypeRefContext::GenericArg),
            "expected GenericArg ctx for 'Config'"
        );
    }

    #[test]
    fn type_ref_primitive_skipped() {
        // `void f(int n) {}` → NO TypeRef "int".
        let src = "void f(int n) {}\n";
        let facts = CppExtractor.extract(src, "src/f.cpp").unwrap();
        let int_typerefs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::TypeRef && r.name == "int")
            .collect();
        assert!(
            int_typerefs.is_empty(),
            "primitive 'int' must NOT produce a TypeRef, got: {int_typerefs:?}"
        );
    }

    // ── Visibility tests ─────────────────────────────────────────────────────

    #[test]
    fn class_public_member_tagged_public() {
        // `public:` section → Visibility::Public
        let src = "class Foo { public: void go(); };\n";
        let facts = CppExtractor.extract(src, "src/foo.cpp").unwrap();
        let go = by_name(&facts, "go").unwrap();
        assert_eq!(
            go.visibility,
            Visibility::Public,
            "public: member must be Public"
        );
    }

    #[test]
    fn class_private_member_emitted_and_tagged_private() {
        // `private:` section → emitted with Visibility::Private
        let src = "class Foo { private: void secret(); };\n";
        let facts = CppExtractor.extract(src, "src/foo.cpp").unwrap();
        let secret = by_name(&facts, "secret").expect("private member 'secret' must now emit");
        assert_eq!(
            secret.visibility,
            Visibility::Private,
            "private: member must be Private"
        );
    }

    #[test]
    fn class_protected_member_emitted_and_tagged_protected() {
        // `protected:` section → emitted with Visibility::Protected
        let src = "class Foo { protected: void hook(); };\n";
        let facts = CppExtractor.extract(src, "src/foo.cpp").unwrap();
        let hook = by_name(&facts, "hook").expect("protected member 'hook' must emit");
        assert_eq!(
            hook.visibility,
            Visibility::Protected,
            "protected: member must be Protected"
        );
    }

    #[test]
    fn class_default_member_is_private() {
        // class with no access specifier → default Private
        let src = "class Foo { void hidden(); };\n";
        let facts = CppExtractor.extract(src, "src/foo.cpp").unwrap();
        let hidden = by_name(&facts, "hidden").expect("class member with no specifier must emit");
        assert_eq!(
            hidden.visibility,
            Visibility::Private,
            "class default must be Private"
        );
    }

    #[test]
    fn struct_default_member_is_public() {
        // struct with no access specifier → default Public
        let src = "struct Bar { int val; };\n";
        let facts = CppExtractor.extract(src, "src/bar.cpp").unwrap();
        let val = by_name(&facts, "val").expect("struct member with no specifier must emit");
        assert_eq!(
            val.visibility,
            Visibility::Public,
            "struct default must be Public"
        );
    }

    #[test]
    fn static_file_level_fn_is_private() {
        // `static void impl(){}` → internal linkage → Visibility::Private
        let src = "static void impl(){}\n";
        let facts = CppExtractor.extract(src, "src/util.cpp").unwrap();
        let impl_sym = by_name(&facts, "impl").expect("static file-level fn must emit");
        assert_eq!(
            impl_sym.visibility,
            Visibility::Private,
            "static (internal-linkage) fn must be Private"
        );
    }

    #[test]
    fn non_static_file_level_fn_is_public() {
        // `void pub_fn(){}` → external linkage → Visibility::Public
        let src = "void pub_fn(){}\n";
        let facts = CppExtractor.extract(src, "src/util.cpp").unwrap();
        let f = by_name(&facts, "pub_fn").unwrap();
        assert_eq!(
            f.visibility,
            Visibility::Public,
            "non-static fn must be Public"
        );
    }

    #[test]
    fn mixed_access_specifiers_all_members_emit() {
        // Class with public/private/protected sections — all members must emit.
        let src = r#"
class Widget {
public:
    void show();
protected:
    void draw();
private:
    void impl();
};
"#;
        let facts = CppExtractor.extract(src, "src/widget.cpp").unwrap();
        let show = by_name(&facts, "show").expect("show must emit");
        assert_eq!(show.visibility, Visibility::Public);
        let draw = by_name(&facts, "draw").expect("draw must emit");
        assert_eq!(draw.visibility, Visibility::Protected);
        let impl_m = by_name(&facts, "impl").expect("impl must emit");
        assert_eq!(impl_m.visibility, Visibility::Private);
    }
}
