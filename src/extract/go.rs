// SPDX-License-Identifier: Apache-2.0

//! Go extractor — one tree-sitter pass yielding definitions and references.
//!
//! Definitions: top-level declarations (exported and package-private). Covers
//! `func`, methods, `type` (struct/interface/alias),
//! `const`, and `var`. Qualified identity follows the Go convention that a
//! package occupies exactly one directory, so the file's **directory path** is
//! the package identity (e.g. `src/auth/session.go` → namespace `["auth"]`);
//! this is collision-free across same-named packages in different directories.
//! Flat (directory-less) files fall back to the `package` clause name.
//! References: callee identifiers of `call_expression` nodes, plus
//! [`RefRole::Read`] for identifiers used in value/expression positions and
//! [`RefRole::Write`] for bare-identifier left-hand sides of
//! `assignment_statement` nodes.
//!
//! Emits neutral [`FileFacts`] — no storage entries, no source bodies.

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
    push_type_ref, simple_type_name,
};

/// Tree-sitter query capturing call-callee identifiers.
///
/// For a selector call (`pkg.Func()` / `recv.Method()`) the operand is captured
/// as `@qualifier`. A package receiver (`alpha`) yields segs `["alpha"]` that the
/// resolver matches to that package's symbol; a value/complex receiver simply
/// matches no namespace, so Tier-B abstains (never a false edge).
const CALL_QUERY: &str = r#"
(call_expression
  function: [
    (identifier) @callee
    (selector_expression operand: (_) @qualifier field: (field_identifier) @callee)
  ]
)
"#;

/// Extracts Go symbols and references.
pub struct GoExtractor;

impl Extractor for GoExtractor {
    fn lang(&self) -> Language {
        Language::Go
    }

    fn extract(&self, source: &str, file: &str) -> Result<FileFacts> {
        let ts_language = crate::grammar::go();
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
        let namespaces = go_namespaces(&root, bytes, file);

        let ctx = ExtractCtx {
            bytes,
            file,
            lang: Language::Go,
        };
        let defs = collect_symbols(&root, &ctx, &namespaces);
        let def_bindings = definition_bindings(&defs);
        let mut symbols = defs;
        symbols.push(super::module_symbol(
            Language::Go,
            &namespaces,
            file,
            source.len(),
        ));
        let mut references =
            collect_call_references(&root, &ts_language, CALL_QUERY, Language::Go, bytes, file)?;
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
            lang: Language::Go.as_str().to_owned(),
            symbols,
            references,
            scopes,
            bindings,
            ffi_exports: Vec::new(),
        })
    }
}

/// Derive the Go package namespace.
///
/// Go enforces one package per directory, so the file's **directory path** is
/// the collision-free package identity (and aligns with SCIP-go's import-path
/// descriptors). Two same-named packages in different directories (`a/config`
/// and `b/config`) therefore get distinct namespaces, avoiding SCIP-id
/// collisions. Priority:
///
/// 1. **Directory path.** Strip a leading `src/` from `file`, take everything
///    before the last `/`, split on `/`, drop empties. If non-empty, that IS
///    the namespace (e.g. `src/auth/session.go` → `["auth"]`;
///    `auth/session/x.go` → `["auth", "session"]`).
/// 2. **Flat-file fallback.** No directory component → use the `package` clause
///    name (e.g. `util.go` with `package main` → `["main"]`). This keeps the
///    flat eval corpus' same-package files sharing one namespace so the Tier-B
///    resolver can stitch their cross-file calls.
/// 3. **Last resort.** Flat file with no parseable `package` clause → the file
///    stem (`.go` stripped) as a single segment (e.g. `util.go` → `["util"]`).
fn go_namespaces(root: &Node, bytes: &[u8], file: &str) -> Vec<String> {
    let p = file.strip_prefix("src/").unwrap_or(file);
    if let Some((dir, _)) = p.rsplit_once('/') {
        let segs: Vec<String> = dir
            .split('/')
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        if !segs.is_empty() {
            return segs;
        }
    }
    // Flat file: package clause, else file stem.
    if let Some(pkg) = go_package_name(root, bytes) {
        return vec![pkg];
    }
    let stem = p.strip_suffix(".go").unwrap_or(p);
    if stem.is_empty() {
        Vec::new()
    } else {
        vec![stem.to_owned()]
    }
}

/// The package name from the file's `package_clause`, if present and non-empty.
///
/// Grammar: `package_clause` has a `package_identifier` child carrying the name.
/// Returns `None` (no panic) when the clause is absent/unparseable.
fn go_package_name(root: &Node, bytes: &[u8]) -> Option<String> {
    let clause = root
        .children(&mut root.walk())
        .find(|c| c.kind() == "package_clause")?;
    let name = child_text(&clause, "package_identifier", bytes)?;
    if name.is_empty() { None } else { Some(name) }
}

fn collect_symbols(root: &Node, ctx: &ExtractCtx, namespaces: &[String]) -> Vec<Symbol> {
    let mut out = Vec::new();

    let push = |out: &mut Vec<Symbol>,
                node: &Node,
                name: String,
                kind: SymbolKind,
                visibility: Visibility,
                leaf: Descriptor| {
        let mut descriptors: Vec<Descriptor> = namespaces
            .iter()
            .cloned()
            .map(Descriptor::Namespace)
            .collect();
        descriptors.push(leaf);
        out.push(make_symbol(
            ctx,
            node,
            name,
            kind,
            visibility,
            descriptors,
            one_line_signature(node_text(node, ctx.bytes), &['{']),
        ));
    };

    for child in root.children(&mut root.walk()) {
        match child.kind() {
            "function_declaration" => {
                let Some(name) = field_text(&child, "name", ctx.bytes) else {
                    continue;
                };
                let vis = name_visibility(&name);
                push(
                    &mut out,
                    &child,
                    name.clone(),
                    SymbolKind::Function,
                    vis,
                    Descriptor::Method {
                        name,
                        disambiguator: String::new(),
                    },
                );
            }
            "method_declaration" => {
                let Some(name) = field_text(&child, "name", ctx.bytes) else {
                    continue;
                };
                let vis = name_visibility(&name);
                push(
                    &mut out,
                    &child,
                    name.clone(),
                    SymbolKind::Method,
                    vis,
                    Descriptor::Method {
                        name,
                        disambiguator: String::new(),
                    },
                );
            }
            "type_declaration" => {
                for spec in child.children(&mut child.walk()) {
                    let (kind, name) = match spec.kind() {
                        "type_spec" => {
                            let Some(name) = field_text(&spec, "name", ctx.bytes) else {
                                continue;
                            };
                            // Inspect the `type` field to determine the concrete kind.
                            let kind = spec.child_by_field_name("type").map_or(
                                SymbolKind::TypeAlias,
                                |t| match t.kind() {
                                    "struct_type" => SymbolKind::Struct,
                                    "interface_type" => SymbolKind::Interface,
                                    _ => SymbolKind::TypeAlias,
                                },
                            );
                            (kind, name)
                        }
                        "type_alias" => {
                            let Some(name) = field_text(&spec, "name", ctx.bytes) else {
                                continue;
                            };
                            (SymbolKind::TypeAlias, name)
                        }
                        _ => continue,
                    };
                    let vis = name_visibility(&name);
                    push(
                        &mut out,
                        &spec,
                        name.clone(),
                        kind,
                        vis,
                        Descriptor::Type(name),
                    );
                }
            }
            "const_declaration" => {
                for spec in child.children(&mut child.walk()) {
                    if spec.kind() != "const_spec" {
                        continue;
                    }
                    for ident in spec.children(&mut spec.walk()) {
                        if ident.kind() != "identifier" {
                            continue;
                        }
                        let name = node_text(&ident, ctx.bytes).to_owned();
                        let vis = name_visibility(&name);
                        push(
                            &mut out,
                            &spec,
                            name.clone(),
                            SymbolKind::Const,
                            vis,
                            Descriptor::Term(name),
                        );
                    }
                }
            }
            "var_declaration" => {
                for spec in child.children(&mut child.walk()) {
                    if spec.kind() != "var_spec" {
                        continue;
                    }
                    for ident in spec.children(&mut spec.walk()) {
                        if ident.kind() != "identifier" {
                            continue;
                        }
                        let name = node_text(&ident, ctx.bytes).to_owned();
                        let vis = name_visibility(&name);
                        push(
                            &mut out,
                            &spec,
                            name.clone(),
                            SymbolKind::Static,
                            vis,
                            Descriptor::Term(name),
                        );
                    }
                }
            }
            _ => continue,
        }
    }
    out
}

/// Recursively walk the tree and emit one [`RefRole::Import`] reference per
/// `import_spec` node found anywhere in the tree.
///
/// tree-sitter-go grammar:
/// - `import_declaration` → `import_spec` (single) **or** `import_spec_list`
///   (parenthesised group) → contains `import_spec` children.
/// - `import_spec` has field `path` (`interpreted_string_literal` or
///   `raw_string_literal`). The optional field `name` (alias / `_` / `.`) is
///   intentionally ignored; the package's canonical leaf name is what we emit.
fn collect_imports(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    if node.kind() == "import_spec" {
        if let Some(path_node) = node.child_by_field_name("path") {
            let raw = node_text(&path_node, bytes);
            // Strip surrounding quote characters (double-quote or backtick).
            let dequoted = raw.trim_matches('"').trim_matches('`');
            let leaf = simple_type_name(dequoted, "/");
            push_ref(out, leaf, &path_node, file, RefRole::Import);
        }
        // import_spec has no children we need to recurse into.
        return;
    }

    for child in node.children(&mut node.walk()) {
        collect_imports(&child, bytes, file, out);
    }
}

// ── Edge richness: Read / Write ─────────────────────────────────────────────

/// Returns `true` when `node` (an `identifier`) is in a non-read position —
/// already captured by another collector — and must NOT also be emitted as a
/// [`RefRole::Read`] reference.
///
/// Skipped positions (tree-sitter-go specifics):
/// - Call callee: `call_expression` `function:` field.
/// - Function / method / func-literal name: `function_declaration` /
///   `method_declaration` / `func_literal` `name:` field.
/// - Declaration names in `const_spec` and `var_spec` `name:` fields (multi).
/// - Parameter names: `parameter_declaration` `name:` field (multi).
/// - Short variable declaration LHS: identifier children of an
///   `expression_list` whose parent is `short_var_declaration` `left:` field.
/// - Assignment LHS: same structure but parent is `assignment_statement`
///   `left:` — handled by [`collect_write_references`].
/// - Range clause LHS: identifier children of an `expression_list` whose
///   parent is `range_clause` `left:` — either a definition or a write.
/// - Import names: `import_spec` uses `package_identifier` (a different node
///   kind), so plain `identifier` children are naturally excluded.
/// - `selector_expression` `field:` is always a `field_identifier` (different
///   kind), so property names are naturally excluded; the `operand:` identifier
///   (e.g. `c` in `c.Field`) IS a read and is correctly kept.
fn is_non_read_position(node: &Node) -> bool {
    let Some(parent) = node.parent() else {
        return true; // root — not a read
    };
    match parent.kind() {
        // Call callee: `function:` field of a `call_expression`.
        "call_expression" => parent.child_by_field_name("function").as_ref() == Some(node),
        // Function / method name (single `name:` field → identifier).
        "function_declaration" | "method_declaration" | "func_literal" => {
            parent.child_by_field_name("name").as_ref() == Some(node)
        }
        // const_spec / var_spec: ALL identifier direct children are `name:`
        // field entries (the value is nested inside an expression_list grandchild).
        "const_spec" | "var_spec" => {
            // Check if this node appears as a `name:` field child. Since the
            // field is multi-valued, walk it explicitly.
            parent
                .children_by_field_name("name", &mut parent.walk())
                .any(|c| c == *node)
        }
        // parameter_declaration: `name:` field (multi) → identifier.
        "parameter_declaration" | "variadic_parameter_declaration" => parent
            .children_by_field_name("name", &mut parent.walk())
            .any(|c| c == *node),
        // Identifier is inside an expression_list: check whether that list is
        // a `left:` field of a short_var_declaration, assignment_statement, or
        // range_clause — all of which are non-reads for identifiers.
        "expression_list" => {
            if let Some(gp) = parent.parent() {
                let left = gp.child_by_field_name("left");
                match gp.kind() {
                    // `x := 1` — the LHS names are definitions.
                    "short_var_declaration" => left.as_ref() == Some(&parent),
                    // `x = 5` — the LHS names are writes (handled separately).
                    "assignment_statement" => left.as_ref() == Some(&parent),
                    // `for i, v := range xs` / `for i, v = range xs` — LHS
                    // names are either definitions or writes, never reads.
                    "range_clause" => left.as_ref() == Some(&parent),
                    _ => false,
                }
            } else {
                false
            }
        }
        _ => false,
    }
}

/// Recursively walk `node` and emit [`RefRole::Read`] references for bare
/// `identifier` nodes used in value/expression positions.
///
/// Skips identifiers that are:
/// - Call callees (already [`RefRole::Call`])
/// - Declaration names (function/method/const/var/parameter)
/// - Short variable declaration LHS (`:=` defines, not reads)
/// - Assignment LHS (handled by [`collect_write_references`])
/// - Range clause LHS (definitions or writes)
///
/// `field_identifier` (selector field names) and `package_identifier` (import
/// aliases/names) are different node kinds, so they are naturally excluded.
///
/// Applies [`MIN_REF_LEN`] (same threshold as call references).
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
/// bare-identifier left-hand sides of `assignment_statement` nodes
/// (e.g. `x = 5`, `a, b = 1, 2`, `x += 1`).
///
/// The `left:` field is an `expression_list`; only bare `identifier` children
/// are recorded (selector/index LHS such as `obj.field = …` are not covered
/// in v1). Applies [`MIN_REF_LEN`].
///
/// Note: `x := 5` is a `short_var_declaration` (a definition), NOT an
/// `assignment_statement`, so it is correctly not emitted here.
fn collect_write_references(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    if node.kind() == "assignment_statement" {
        if let Some(lhs) = node.child_by_field_name("left") {
            for child in lhs.children(&mut lhs.walk()) {
                if child.kind() == "identifier" {
                    let name = node_text(&child, bytes);
                    if name.len() >= MIN_REF_LEN {
                        push_ref(out, name, &child, file, RefRole::Write);
                    }
                }
            }
        }
    }
    for child in node.children(&mut node.walk()) {
        collect_write_references(&child, bytes, file, out);
    }
}

// ── Edge richness: TypeRef ───────────────────────────────────────────────────

/// Recursively walk a Go type node and emit leaf `type_identifier` nodes.
///
/// Go type grammar rules handled:
/// - `type_identifier` → leaf; emit with `ctx`.
/// - `qualified_type` (`pkg.Type`) → field `name` is a `type_identifier`; emit
///   that leaf (the package qualifier is skipped for v1).
/// - `pointer_type` (`*T`) → field `type` is the pointee; recurse with `ctx`.
/// - `slice_type` (`[]T`) → field `element` is the element; recurse with `ctx`.
/// - `array_type` (`[N]T`) → field `element` is the element; recurse with `ctx`.
/// - `map_type` → fields `key` and `value`; recurse both with `ctx`.
/// - `generic_type` → field `type` is the base `type_identifier` (ctx as given);
///   field `type_arguments` children each recurse with `GenericArg`.
/// - `channel_type` / `interface_type` / `struct_type` and any other container:
///   recurse all named children (catches inline struct/interface annotations).
///
/// Builtin primitives (`int`, `string`, `bool`, …) are `type_identifier` nodes
/// too — emitting them is harmless since they won't resolve to a definition.
fn type_leaf(node: &Node, bytes: &[u8], file: &str, ctx: TypeRefContext, out: &mut Vec<Reference>) {
    match node.kind() {
        "type_identifier" => {
            let name = node_text(node, bytes);
            push_type_ref(out, name, node, file, ctx);
        }
        "qualified_type" => {
            // `pkg.Type` — the `name:` field is the leaf `type_identifier`.
            if let Some(name_node) = node.child_by_field_name("name") {
                type_leaf(&name_node, bytes, file, ctx, out);
            }
        }
        "pointer_type" => {
            // `*T` — the pointee is an unnamed-field child; recurse named children.
            for child in node.named_children(&mut node.walk()) {
                type_leaf(&child, bytes, file, ctx, out);
            }
        }
        "slice_type" => {
            // `[]T` — the element is the `element:` field.
            if let Some(elem) = node.child_by_field_name("element") {
                type_leaf(&elem, bytes, file, ctx, out);
            }
        }
        "array_type" => {
            // `[N]T` — the element is the `element:` field.
            if let Some(elem) = node.child_by_field_name("element") {
                type_leaf(&elem, bytes, file, ctx, out);
            }
        }
        "map_type" => {
            // `map[K]V` — recurse key and value.
            if let Some(key) = node.child_by_field_name("key") {
                type_leaf(&key, bytes, file, ctx, out);
            }
            if let Some(val) = node.child_by_field_name("value") {
                type_leaf(&val, bytes, file, ctx, out);
            }
        }
        "generic_type" => {
            // `Type[T1, T2]` — base type gets outer ctx; arguments get GenericArg.
            if let Some(base) = node.child_by_field_name("type") {
                type_leaf(&base, bytes, file, ctx, out);
            }
            if let Some(args) = node.child_by_field_name("type_arguments") {
                for child in args.named_children(&mut args.walk()) {
                    type_leaf(&child, bytes, file, TypeRefContext::GenericArg, out);
                }
            }
        }
        "channel_type" => {
            // `chan T` or `<-chan T` or `chan<- T`.
            if let Some(val) = node.child_by_field_name("value") {
                type_leaf(&val, bytes, file, ctx, out);
            }
        }
        // Parenthesised / function / interface / struct types:
        // recurse all named children so inline annotations are covered.
        _ => {
            for child in node.named_children(&mut node.walk()) {
                type_leaf(&child, bytes, file, ctx, out);
            }
        }
    }
}

/// Recursively walk `node` and emit [`RefRole::TypeRef`] references for every
/// type identifier that appears in an annotation position.
///
/// Covered positions (tree-sitter-go grammar):
/// - `parameter_declaration` / `variadic_parameter_declaration` `type:` field
///   → [`TypeRefContext::ParameterType`]
/// - `function_declaration` / `method_declaration` `result:` field (single type
///   or `parameter_list` of return types) → [`TypeRefContext::ReturnType`]
/// - `field_declaration` (inside a `struct_type`) `type:` field
///   → [`TypeRefContext::Field`]
///
/// Generic type arguments are handled recursively inside [`type_leaf`] with
/// [`TypeRefContext::GenericArg`].
fn collect_type_references(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    match node.kind() {
        "parameter_declaration" | "variadic_parameter_declaration" => {
            if let Some(type_node) = node.child_by_field_name("type") {
                type_leaf(&type_node, bytes, file, TypeRefContext::ParameterType, out);
            }
            // No further recursion needed — parameters don't nest.
            return;
        }
        "function_declaration" | "method_declaration" => {
            // Return type(s) live in the `result:` field.
            if let Some(result) = node.child_by_field_name("result") {
                if result.kind() == "parameter_list" {
                    // Multiple return types: `func f() (Config, error)`
                    for child in result.named_children(&mut result.walk()) {
                        // Each child is a `parameter_declaration` (with or without
                        // a name) or a bare type node.
                        if child.kind() == "parameter_declaration" {
                            if let Some(t) = child.child_by_field_name("type") {
                                type_leaf(&t, bytes, file, TypeRefContext::ReturnType, out);
                            }
                        } else {
                            // Unnamed return: the child IS the type node.
                            type_leaf(&child, bytes, file, TypeRefContext::ReturnType, out);
                        }
                    }
                } else {
                    // Single return type: `func f() Config`
                    type_leaf(&result, bytes, file, TypeRefContext::ReturnType, out);
                }
            }
            // Fall through to recurse into body / parameters.
        }
        "field_declaration" => {
            if let Some(type_node) = node.child_by_field_name("type") {
                type_leaf(&type_node, bytes, file, TypeRefContext::Field, out);
            }
            return;
        }
        _ => {}
    }

    for child in node.children(&mut node.walk()) {
        collect_type_references(&child, bytes, file, out);
    }
}

// ── Scope tree (Tier-B) ──────────────────────────────────────────────────────

/// Build the lexical scope tree for one Go file.
///
/// `scopes[0]` is always the file-root `Module` scope spanning `[0, source_len)`.
/// Go is function-scoped: `func`/method declarations open a `Function` scope;
/// bare `block` nodes that are NOT a function body open a `Block` scope (e.g.
/// `if`, `for`, `switch` bodies).
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

/// DFS opening `Function` scopes for `function_declaration` / `method_declaration`
/// nodes, and `Block` scopes for bare `block` nodes that are not a function body.
///
/// The function body (`block`) is peeled: its children are visited under the
/// Function scope directly so the body block does not re-open a redundant Block
/// scope. Bare blocks elsewhere (if/for/switch bodies) do open a Block scope.
fn scope_dfs(node: &Node, parent_id: ScopeId, scopes: &mut Vec<Scope>) {
    match node.kind() {
        "function_declaration" | "method_declaration" | "func_literal" => {
            let fn_id = push_scope(
                scopes,
                Some(parent_id),
                node_span(node),
                ScopeKind::Function,
            );
            // Peel the body block: recurse its children under the Function scope
            // directly so the body `block` does not re-open a redundant Block scope.
            if let Some(body) = node.child_by_field_name("body") {
                for child in body.children(&mut body.walk()) {
                    scope_dfs(&child, fn_id, scopes);
                }
            }
        }
        "block" => {
            // A bare block NOT already consumed as a function body (e.g. if/for/
            // switch bodies, or a standalone `{ }` block inside a function).
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

/// Collect parameter and local-variable [`Binding`]s for one Go file.
///
/// Covers:
/// - `function_declaration` / `method_declaration` / `func_literal` parameters
///   and method receivers → [`BindingKind::Param`].
/// - `short_var_declaration` (`:=`) → [`BindingKind::Local`] for each LHS name.
/// - `var_spec` inside `var_declaration` → [`BindingKind::Local`] (only inside
///   a function; top-level ones are already covered by `definition_bindings`).
/// - `const_spec` inside `const_declaration` → same guard as `var_spec`.
/// - `range_clause` left-hand names → [`BindingKind::Local`].
///
/// Top-level `var`/`const` at scope 0 are skipped to avoid duplicating the
/// [`BindingKind::Definition`] bindings emitted by `definition_bindings`.
fn collect_bindings(root: &Node, bytes: &[u8], scopes: &[Scope]) -> Vec<Binding> {
    let mut out = Vec::new();
    collect_bindings_dfs(root, bytes, scopes, &mut out);
    out
}

fn collect_bindings_dfs(node: &Node, bytes: &[u8], scopes: &[Scope], out: &mut Vec<Binding>) {
    match node.kind() {
        "function_declaration" | "method_declaration" | "func_literal" => {
            // Params from the `parameters` field.
            if let Some(params) = node.child_by_field_name("parameters") {
                collect_params(&params, bytes, scopes, out);
            }
            // Receiver (method only) — also a parameter_list.
            if let Some(recv) = node.child_by_field_name("receiver") {
                collect_params(&recv, bytes, scopes, out);
            }
            // Recurse into all children to pick up body bindings.
            for child in node.children(&mut node.walk()) {
                collect_bindings_dfs(&child, bytes, scopes, out);
            }
        }
        "short_var_declaration" => {
            // LHS is the `left` field — an `expression_list`.
            if let Some(left) = node.child_by_field_name("left") {
                for ident in left.children(&mut left.walk()) {
                    if ident.kind() != "identifier" {
                        continue;
                    }
                    let name = node_text(&ident, bytes);
                    if name == "_" {
                        continue;
                    }
                    let intro = ident.start_byte();
                    // Always inside a function — no root-scope guard needed,
                    // but apply it defensively anyway.
                    if innermost_scope(intro, scopes) != Some(0) {
                        push_binding(out, name.to_owned(), intro, BindingKind::Local, scopes);
                    }
                }
            }
            for child in node.children(&mut node.walk()) {
                collect_bindings_dfs(&child, bytes, scopes, out);
            }
        }
        "var_spec" => {
            // Single pass: emit Local bindings for identifier children and recurse.
            // Skip `_` and top-level (scope 0, already a Definition binding).
            for child in node.children(&mut node.walk()) {
                if child.kind() == "identifier" {
                    let name = node_text(&child, bytes);
                    if name != "_" {
                        let intro = child.start_byte();
                        if innermost_scope(intro, scopes) != Some(0) {
                            push_binding(out, name.to_owned(), intro, BindingKind::Local, scopes);
                        }
                    }
                } else {
                    collect_bindings_dfs(&child, bytes, scopes, out);
                }
            }
        }
        "const_spec" => {
            // Same guard as var_spec — single pass.
            for child in node.children(&mut node.walk()) {
                if child.kind() == "identifier" {
                    let name = node_text(&child, bytes);
                    if name != "_" {
                        let intro = child.start_byte();
                        if innermost_scope(intro, scopes) != Some(0) {
                            push_binding(out, name.to_owned(), intro, BindingKind::Local, scopes);
                        }
                    }
                } else {
                    collect_bindings_dfs(&child, bytes, scopes, out);
                }
            }
        }
        "range_clause" => {
            // `for i, v := range xs {}` — left field is an expression_list.
            if let Some(left) = node.child_by_field_name("left") {
                for ident in left.children(&mut left.walk()) {
                    if ident.kind() != "identifier" {
                        continue;
                    }
                    let name = node_text(&ident, bytes);
                    if name == "_" {
                        continue;
                    }
                    let intro = ident.start_byte();
                    if innermost_scope(intro, scopes) != Some(0) {
                        push_binding(out, name.to_owned(), intro, BindingKind::Local, scopes);
                    }
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

/// Emit a [`BindingKind::Param`] for each named parameter in a Go
/// `parameter_list` node (used for both `parameters` and `receiver` fields).
///
/// Handles `parameter_declaration` (one or more names + a type) and
/// `variadic_parameter_declaration` (`...type`). Skips blank `_` names.
fn collect_params(params: &Node, bytes: &[u8], scopes: &[Scope], out: &mut Vec<Binding>) {
    for child in params.named_children(&mut params.walk()) {
        if matches!(
            child.kind(),
            "parameter_declaration" | "variadic_parameter_declaration"
        ) {
            for ident in child.children(&mut child.walk()) {
                if ident.kind() != "identifier" {
                    continue;
                }
                let name = node_text(&ident, bytes);
                if name == "_" {
                    continue;
                }
                let intro = ident.start_byte();
                push_binding(out, name.to_owned(), intro, BindingKind::Param, scopes);
            }
        }
    }
}

/// Map a Go identifier to its [`Visibility`].
///
/// Go's export rule is purely syntactic: a name whose first character is an
/// uppercase Unicode letter is exported (`Public`); everything else (lowercase,
/// underscore-prefixed, empty) is package-private (`Internal`). Go has no
/// concept of `Private` (scope-local) or `Protected` at the package level.
fn name_visibility(name: &str) -> Visibility {
    if name.chars().next().is_some_and(|c| c.is_uppercase()) {
        Visibility::Public
    } else {
        Visibility::Internal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_exported_defs() {
        let src = r#"
package auth

func Validate(tok string) bool { return true }
type Config struct { Timeout int }
type Reader interface { Read() error }
const Max = 3
func helper() {}
"#;
        let facts = GoExtractor.extract(src, "src/auth/session.go").unwrap();
        let by_name = |n: &str| facts.symbols.iter().find(|s| s.name == n).cloned();

        let vt = by_name("Validate").unwrap();
        assert_eq!(vt.id.to_scip_string(), "codegraph . . . auth/Validate().");
        assert_eq!(vt.kind, SymbolKind::Function);
        assert_eq!(vt.visibility, Visibility::Public);

        assert_eq!(by_name("Config").unwrap().kind, SymbolKind::Struct);
        assert_eq!(by_name("Config").unwrap().visibility, Visibility::Public);
        assert_eq!(by_name("Reader").unwrap().kind, SymbolKind::Interface);
        assert_eq!(by_name("Max").unwrap().kind, SymbolKind::Const);

        // unexported — now emitted as Internal (package-private)
        let helper = by_name("helper").expect("helper must now be emitted");
        assert_eq!(helper.kind, SymbolKind::Function);
        assert_eq!(helper.visibility, Visibility::Internal);

        assert_eq!(facts.lang, "go");
    }

    #[test]
    fn flat_files_same_package_share_namespace() {
        // Two FLAT (directory-less) files declaring the same `package main` share
        // the namespace `["main"]` via the flat-file package-clause fallback —
        // this is what lets cross-file resolution stitch the eval corpus.
        let util = GoExtractor
            .extract("package main\nfunc Helper() {}\n", "util.go")
            .unwrap();
        let main = GoExtractor
            .extract("package main\nfunc Run() { Helper() }\n", "main.go")
            .unwrap();
        let helper = util.symbols.iter().find(|s| s.name == "Helper").unwrap();
        let run = main.symbols.iter().find(|s| s.name == "Run").unwrap();
        assert_eq!(helper.id.to_scip_string(), "codegraph . . . main/Helper().");
        assert_eq!(run.id.to_scip_string(), "codegraph . . . main/Run().");
    }

    #[test]
    fn different_directories_are_different_packages() {
        // Go: one package per directory. Same package name in different dirs is
        // a DIFFERENT package, so namespaces (and SCIP ids) must differ.
        let a = GoExtractor
            .extract("package x\nfunc F() {}\n", "pkg_a/x.go")
            .unwrap();
        let b = GoExtractor
            .extract("package x\nfunc F() {}\n", "pkg_b/x.go")
            .unwrap();
        let fa = a.symbols.iter().find(|s| s.name == "F").unwrap();
        let fb = b.symbols.iter().find(|s| s.name == "F").unwrap();
        assert_eq!(fa.id.to_scip_string(), "codegraph . . . pkg_a/F().");
        assert_eq!(fb.id.to_scip_string(), "codegraph . . . pkg_b/F().");
        assert_ne!(fa.id.to_scip_string(), fb.id.to_scip_string());
    }

    #[test]
    fn namespace_falls_back_to_file_stem_without_package_clause() {
        // Flat file (`src/util.go` → `util.go`) with no parseable `package`
        // clause → last-resort file-stem fallback → `["util"]`.
        let facts = GoExtractor
            .extract("func Helper() {}\n", "src/util.go")
            .unwrap();
        let helper = facts.symbols.iter().find(|s| s.name == "Helper").unwrap();
        assert_eq!(helper.id.to_scip_string(), "codegraph . . . util/Helper().");
    }

    #[test]
    fn extracts_method_declaration() {
        let src = r#"
package run

type Server struct{}

func (s *Server) Start() { }
"#;
        let facts = GoExtractor.extract(src, "src/run.go").unwrap();
        let start = facts.symbols.iter().find(|s| s.name == "Start").unwrap();
        assert_eq!(start.kind, SymbolKind::Method);
        assert_eq!(start.id.to_scip_string(), "codegraph . . . run/Start().");
    }

    #[test]
    fn extracts_call_references() {
        let src = r#"
package main

func main() {
    Validate("t")
    obj.Close()
}
"#;
        let facts = GoExtractor.extract(src, "src/main.go").unwrap();
        let names: Vec<&str> = facts.references.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"Validate"));
        assert!(names.contains(&"Close"));
    }

    #[test]
    fn import_single_stdlib() {
        let src = "package main\nimport \"fmt\"\n";
        let facts = GoExtractor.extract(src, "src/main.go").unwrap();
        let imports: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(imports, vec!["fmt"]);
    }

    #[test]
    fn import_deep_path_leaf() {
        let src = "package main\nimport \"github.com/x/y/pkg\"\n";
        let facts = GoExtractor.extract(src, "src/main.go").unwrap();
        let imports: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(imports, vec!["pkg"]);
    }

    #[test]
    fn import_grouped() {
        let src = "package main\nimport (\n  \"os\"\n  \"io/ioutil\"\n)\n";
        let facts = GoExtractor.extract(src, "src/main.go").unwrap();
        let mut imports: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        imports.sort_unstable();
        assert_eq!(imports, vec!["ioutil", "os"]);
    }

    #[test]
    fn import_aliased_emits_leaf_not_alias() {
        let src = "package main\nimport f \"fmt\"\n";
        let facts = GoExtractor.extract(src, "src/main.go").unwrap();
        let imports: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        // The package leaf "fmt" must be emitted; the alias "f" must not appear
        // as an Import reference.
        assert_eq!(imports, vec!["fmt"]);
        let aliases: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import && r.name == "f")
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            aliases.is_empty(),
            "alias 'f' should not appear as an Import ref"
        );
    }

    // ── Tier-B scope / binding tests ─────────────────────────────────────────

    #[test]
    fn func_params_emit_param_bindings() {
        // `func f(a int, b int) {}` → two Param bindings in a Function scope.
        let src = "package p\nfunc f(a int, b int) {}\n";
        let facts = GoExtractor.extract(src, "src/p.go").unwrap();

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
    fn method_receiver_emits_param_binding() {
        // `func (s *Server) Start() {}` → Param binding for `s`.
        let src = "package p\ntype Server struct{}\nfunc (s *Server) Start() {}\n";
        let facts = GoExtractor.extract(src, "src/p.go").unwrap();

        let s_binding = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Param && b.name == "s")
            .expect("expected a Param binding named 's'");
        assert_eq!(
            facts.scopes[s_binding.scope].kind,
            ScopeKind::Function,
            "receiver binding 's' should be in a Function scope"
        );
    }

    #[test]
    fn short_var_decl_emits_local() {
        // `func f() { x := 1 }` → Local binding for `x`.
        let src = "package p\nfunc f() { x := 1 }\n";
        let facts = GoExtractor.extract(src, "src/p.go").unwrap();

        let x = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Local && b.name == "x")
            .expect("expected a Local binding for 'x'");
        assert_eq!(
            facts.scopes[x.scope].kind,
            ScopeKind::Function,
            "x should be in a Function scope"
        );
    }

    #[test]
    fn multi_name_short_var_emits_two_locals() {
        // `func f() { a, b := 1, 2 }` → two Local bindings.
        let src = "package p\nfunc f() { a, b := 1, 2 }\n";
        let facts = GoExtractor.extract(src, "src/p.go").unwrap();

        let locals: Vec<&str> = facts
            .bindings
            .iter()
            .filter(|b| b.kind == BindingKind::Local)
            .map(|b| b.name.as_str())
            .collect();
        assert!(
            locals.contains(&"a"),
            "expected Local for 'a', got {locals:?}"
        );
        assert!(
            locals.contains(&"b"),
            "expected Local for 'b', got {locals:?}"
        );
    }

    #[test]
    fn blank_identifier_skipped() {
        // `func f() { _, b := g() }` → Local `b` only; no binding for `_`.
        let src = "package p\nfunc g() (int, int) { return 0, 0 }\nfunc f() { _, b := g() }\n";
        let facts = GoExtractor.extract(src, "src/p.go").unwrap();

        assert!(
            !facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Local && b.name == "_"),
            "blank '_' must not produce a Local binding"
        );
        assert!(
            facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Local && b.name == "b"),
            "expected Local binding for 'b'"
        );
    }

    #[test]
    fn var_spec_inside_func_emits_local() {
        // `func f() { var x int }` → Local binding for `x`.
        let src = "package p\nfunc f() { var x int }\n";
        let facts = GoExtractor.extract(src, "src/p.go").unwrap();

        let x = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Local && b.name == "x")
            .expect("expected a Local binding for 'x'");
        assert_eq!(
            facts.scopes[x.scope].kind,
            ScopeKind::Function,
            "var inside func should bind in a Function scope"
        );
    }

    #[test]
    fn for_range_vars_emit_locals() {
        // `func f() { for i, v := range xs { _ = i; _ = v } }` → Locals `i`, `v`.
        let src = "package p\nfunc f() { var xs []int\nfor i, v := range xs { _ = i; _ = v } }\n";
        let facts = GoExtractor.extract(src, "src/p.go").unwrap();

        let locals: Vec<&str> = facts
            .bindings
            .iter()
            .filter(|b| b.kind == BindingKind::Local)
            .map(|b| b.name.as_str())
            .collect();
        assert!(
            locals.contains(&"i"),
            "expected Local for 'i', got {locals:?}"
        );
        assert!(
            locals.contains(&"v"),
            "expected Local for 'v', got {locals:?}"
        );
    }

    #[test]
    fn top_level_var_is_not_local_but_is_definition() {
        // `var Config int` at package level → Definition binding only, no Local.
        let src = "package p\nvar Config int\n";
        let facts = GoExtractor.extract(src, "src/p.go").unwrap();

        assert!(
            !facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Local && b.name == "Config"),
            "top-level var must NOT be a Local binding"
        );
        assert!(
            facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Definition && b.name == "Config"),
            "top-level var must have a Definition binding"
        );
    }

    #[test]
    fn nested_block_produces_block_scope_and_ref_attaches_to_it() {
        // A single function with a bare inner block containing a call:
        //   func f() { { helper() } }
        // Expected scopes: Module(0) → Function(1) → Block(2).
        // The `helper` call ref must attribute to the Block scope.
        let src = "package p\nfunc f() { { helper() } }\n";
        let facts = GoExtractor.extract(src, "src/p.go").unwrap();

        assert_eq!(
            facts.scopes[0].kind,
            ScopeKind::Module,
            "scopes[0] must be Module"
        );

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

        // `helper` call ref must be in the Block scope (innermost).
        let h_ref = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Call && r.name == "helper")
            .expect("expected a Call ref for 'helper'");
        assert_eq!(
            h_ref.scope,
            Some(block_scope_id),
            "helper() call should be in the Block scope ({}), got {:?}",
            block_scope_id,
            h_ref.scope
        );
    }

    #[test]
    fn selector_call_captures_package_qualifier() {
        // `alpha.Helper()` → the Call ref for `Helper` carries qualifier `alpha`
        // (the selector operand), so Tier-B can resolve the cross-package call.
        let facts = GoExtractor
            .extract(
                "package main\nfunc Run() {\n\talpha.Helper()\n}\n",
                "main.go",
            )
            .unwrap();
        let call = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Call && r.name == "Helper")
            .expect("expected a Call ref for 'Helper'");
        assert_eq!(call.qualifier.as_deref(), Some("alpha"));

        // A bare same-package call carries no qualifier.
        let bare = GoExtractor
            .extract(
                "package main\nfunc Helper() {}\nfunc Run() {\n\tHelper()\n}\n",
                "main.go",
            )
            .unwrap();
        let bare_call = bare
            .references
            .iter()
            .find(|r| r.role == RefRole::Call && r.name == "Helper")
            .expect("expected a Call ref for 'Helper'");
        assert_eq!(bare_call.qualifier, None);
    }

    #[test]
    fn top_level_func_emits_definition_binding() {
        // `func Helper() {}` → Definition binding named "Helper".
        let src = "package p\nfunc Helper() {}\n";
        let facts = GoExtractor.extract(src, "src/p.go").unwrap();

        let b = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Definition && b.name == "Helper")
            .expect("expected a Definition binding for 'Helper'");
        assert_eq!(b.scope, 0, "top-level def must bind in scope 0");
    }

    // ── Edge richness: Read / Write ──────────────────────────────────────────

    #[test]
    fn read_ref_at_use_not_at_decl() {
        // `func f() int { base := 1; return base }` →
        //   Read ref for `base` at the `return base` use site only;
        //   the `:=` LHS must NOT become a Read.
        let src = "package p\nfunc f() int { base := 1; return base }\n";
        let facts = GoExtractor.extract(src, "src/p.go").unwrap();
        let read_refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Read && r.name == "base")
            .collect();
        // Must have at least one Read ref (the `return base` use).
        assert!(
            !read_refs.is_empty(),
            "expected at least one Read ref for 'base', got none"
        );
        // All Read refs must be AFTER the `:=` declaration.
        // In the source `func f() int { base := 1; return base }`,
        // the `:=` appears at byte ~21; `return base` starts later.
        for r in &read_refs {
            assert!(
                r.occ.byte > 20,
                "Read ref for 'base' must be at the use site (byte > 20), got byte {}",
                r.occ.byte
            );
        }
    }

    #[test]
    fn write_ref_for_assignment_statement() {
        // `func f() { cnt := 0; cnt = 5 }` →
        //   Write ref for `cnt` at `cnt = 5`; the `:=` is a definition, not a write.
        let src = "package p\nfunc f() { cnt := 0; cnt = 5 }\n";
        let facts = GoExtractor.extract(src, "src/p.go").unwrap();
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
        // `func f() { helper() }` → Call ref for "helper", NOT also a Read.
        let src = "package p\nfunc f() { helper() }\n";
        let facts = GoExtractor.extract(src, "src/p.go").unwrap();
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

    // ── TypeRef tests ────────────────────────────────────────────────────────

    #[test]
    fn type_ref_param_type() {
        // `func f(c Config) {}` → TypeRef "Config" ctx ParameterType.
        let src = "package p\nfunc f(c Config) {}\n";
        let facts = GoExtractor.extract(src, "src/p.go").unwrap();
        let found = facts
            .references
            .iter()
            .find(|r| {
                r.role == RefRole::TypeRef
                    && r.name == "Config"
                    && r.type_ref_ctx == Some(TypeRefContext::ParameterType)
            })
            .is_some();
        assert!(
            found,
            "expected TypeRef 'Config' with ParameterType context"
        );
    }

    #[test]
    fn type_ref_pointer_param_type() {
        // `func f(c *Config) {}` → TypeRef "Config" ParameterType (pointer unwrapped).
        let src = "package p\nfunc f(c *Config) {}\n";
        let facts = GoExtractor.extract(src, "src/p.go").unwrap();
        let found = facts
            .references
            .iter()
            .find(|r| {
                r.role == RefRole::TypeRef
                    && r.name == "Config"
                    && r.type_ref_ctx == Some(TypeRefContext::ParameterType)
            })
            .is_some();
        assert!(
            found,
            "expected TypeRef 'Config' with ParameterType from pointer param; refs: {:?}",
            facts
                .references
                .iter()
                .filter(|r| r.role == RefRole::TypeRef)
                .map(|r| (&r.name, r.type_ref_ctx))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn type_ref_return_type() {
        // `func f() Config { return Config{} }` → TypeRef "Config" ctx ReturnType.
        let src = "package p\nfunc f() Config { return Config{} }\n";
        let facts = GoExtractor.extract(src, "src/p.go").unwrap();
        let found = facts
            .references
            .iter()
            .find(|r| {
                r.role == RefRole::TypeRef
                    && r.name == "Config"
                    && r.type_ref_ctx == Some(TypeRefContext::ReturnType)
            })
            .is_some();
        assert!(
            found,
            "expected TypeRef 'Config' with ReturnType context; refs: {:?}",
            facts
                .references
                .iter()
                .filter(|r| r.role == RefRole::TypeRef)
                .map(|r| (&r.name, r.type_ref_ctx))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn type_ref_struct_field_type() {
        // `type T struct { conf Config }` → TypeRef "Config" ctx Field.
        let src = "package p\ntype T struct { conf Config }\n";
        let facts = GoExtractor.extract(src, "src/p.go").unwrap();
        let found = facts
            .references
            .iter()
            .find(|r| {
                r.role == RefRole::TypeRef
                    && r.name == "Config"
                    && r.type_ref_ctx == Some(TypeRefContext::Field)
            })
            .is_some();
        assert!(
            found,
            "expected TypeRef 'Config' with Field context; refs: {:?}",
            facts
                .references
                .iter()
                .filter(|r| r.role == RefRole::TypeRef)
                .map(|r| (&r.name, r.type_ref_ctx))
                .collect::<Vec<_>>()
        );
    }

    // ── Visibility tests ─────────────────────────────────────────────────────

    #[test]
    fn exported_func_has_public_visibility() {
        // A capitalized function name → Visibility::Public.
        let src = "package p\nfunc Exported() {}\n";
        let facts = GoExtractor.extract(src, "src/p.go").unwrap();
        let sym = facts
            .symbols
            .iter()
            .find(|s| s.name == "Exported")
            .expect("Exported must be emitted");
        assert_eq!(
            sym.visibility,
            Visibility::Public,
            "capitalized func must be Public"
        );
    }

    #[test]
    fn unexported_func_emitted_as_internal() {
        // A lowercase function name → NOW emitted with Visibility::Internal.
        let src = "package p\nfunc unexported() {}\n";
        let facts = GoExtractor.extract(src, "src/p.go").unwrap();
        let sym = facts
            .symbols
            .iter()
            .find(|s| s.name == "unexported")
            .expect("unexported func must now be emitted");
        assert_eq!(
            sym.kind,
            SymbolKind::Function,
            "unexported func kind must be Function"
        );
        assert_eq!(
            sym.visibility,
            Visibility::Internal,
            "lowercase func must be Internal (package-private)"
        );
    }

    #[test]
    fn unexported_type_emitted_as_internal() {
        // A lowercase type name → emitted with Visibility::Internal.
        let src = "package p\ntype internalState struct { x int }\n";
        let facts = GoExtractor.extract(src, "src/p.go").unwrap();
        let sym = facts
            .symbols
            .iter()
            .find(|s| s.name == "internalState")
            .expect("internalState type must be emitted");
        assert_eq!(sym.kind, SymbolKind::Struct);
        assert_eq!(
            sym.visibility,
            Visibility::Internal,
            "lowercase type must be Internal"
        );
    }

    #[test]
    fn unexported_const_emitted_as_internal() {
        // A lowercase const name → emitted with Visibility::Internal.
        let src = "package p\nconst maxRetries = 3\n";
        let facts = GoExtractor.extract(src, "src/p.go").unwrap();
        let sym = facts
            .symbols
            .iter()
            .find(|s| s.name == "maxRetries")
            .expect("maxRetries const must be emitted");
        assert_eq!(sym.kind, SymbolKind::Const);
        assert_eq!(
            sym.visibility,
            Visibility::Internal,
            "lowercase const must be Internal"
        );
    }

    #[test]
    fn selector_receiver_is_read_field_is_not() {
        // `func f(conn Conn) { _ = conn.field }` →
        //   Read ref for `conn` (the receiver/operand); no Read ref named "field"
        //   (field_identifier, a different node kind, is naturally excluded).
        let src = "package p\ntype Conn struct{}\nfunc f(conn Conn) { _ = conn.field }\n";
        let facts = GoExtractor.extract(src, "src/p.go").unwrap();
        let field_reads: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Read && r.name == "field")
            .collect();
        assert!(
            field_reads.is_empty(),
            "selector field 'field' must NOT be a Read ref; got: {field_reads:?}"
        );
        // `conn` is a read of the receiver value.
        let conn_reads: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Read && r.name == "conn")
            .collect();
        assert!(
            !conn_reads.is_empty(),
            "expected a Read ref for the receiver 'conn'"
        );
    }
}
