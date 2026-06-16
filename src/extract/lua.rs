// SPDX-License-Identifier: Apache-2.0

//! Lua extractor — one tree-sitter pass yielding definitions and references.
//!
//! Definitions: global functions, local functions, table-dot methods
//! (`function M.foo()`), table-colon methods (`function M:bar()`), local
//! variable declarations (plain locals, function-valued locals, and table
//! constructors treated as modules). Identity is file-path-derived (Lua has no
//! namespace declaration).
//!
//! References: free calls, dot/colon member calls, and `require()` calls
//! (emitted as an `Import` reference rather than a `Call`).
//!
//! Emits neutral [`FileFacts`] — no storage entries, no source bodies.
//!
//! The core extraction logic is shared with the Luau extractor via
//! `extract_lua_family`, which is parameterized by [`Language`] and grammar.

use tree_sitter::{Node, Parser};

use crate::error::{CodegraphError, Result};
use crate::graph::types::{
    Binding, BindingKind, ByteSpan, FileFacts, Reference, Scope, ScopeId, ScopeKind, Symbol,
    SymbolKind,
};
use crate::lang::Language;
use crate::symbol::{Descriptor, SymbolId};

use super::{
    Extractor, MIN_REF_LEN, attach_reference_scopes, collect_call_references, definition_bindings,
    field_text, import_bindings, innermost_scope, node_span, node_text, one_line_signature,
    push_binding, push_import_ref, push_scope,
};

/// Tree-sitter query capturing call-callee identifiers.
///
/// Pattern 1: free call `foo()` — identifier directly as `name`.
/// Pattern 2: dot call `a.bar()` — dot_index_expression; table as `@qualifier`,
///            field as `@callee`.
/// Pattern 3: colon call `a:qux()` — method_index_expression; table as
///            `@qualifier`, method as `@callee`.
const CALL_QUERY: &str = r#"
[
  (function_call name: (identifier) @callee)
  (function_call name: (dot_index_expression table: (identifier) @qualifier field: (identifier) @callee))
  (function_call name: (method_index_expression table: (identifier) @qualifier method: (identifier) @callee))
]
"#;

/// Extracts Lua symbols and references.
pub struct LuaExtractor;

impl Extractor for LuaExtractor {
    fn lang(&self) -> Language {
        Language::Lua
    }

    fn extract(&self, source: &str, file: &str) -> Result<FileFacts> {
        extract_lua_family(source, file, Language::Lua, crate::grammar::lua())
    }
}

/// Shared extraction pass for the Lua language family (Lua and Luau).
///
/// Parameterized by `lang` (determines SCIP scheme tag and `FileFacts.lang`)
/// and `grammar` (the tree-sitter grammar to use). `LuaExtractor` and
/// `LuauExtractor` are thin wrappers that call this function.
pub(crate) fn extract_lua_family(
    source: &str,
    file: &str,
    lang: Language,
    grammar: tree_sitter::Language,
) -> Result<FileFacts> {
    let mut parser = Parser::new();
    parser
        .set_language(&grammar)
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
    let namespaces = lua_namespaces(file);

    let defs = collect_symbols(&root, bytes, file, &namespaces, lang);
    let def_bindings = definition_bindings(&defs);
    let mut symbols = defs;
    let mod_sym = super::module_symbol(lang, &namespaces, file, source.len());
    let module_id = mod_sym.id.to_scip_string();
    symbols.push(mod_sym);

    // Collect all calls; we'll filter `require` out separately.
    let mut references = collect_call_references(&root, &grammar, CALL_QUERY, lang, bytes, file)?;
    // Remove `require` from plain call refs — we re-emit them as Import refs.
    references.retain(|r| r.name != "require");

    collect_require_imports(&root, bytes, file, &mut references, &module_id);

    let scopes = collect_scopes(&root, source.len());
    attach_reference_scopes(&mut references, &scopes);
    let mut bindings = collect_bindings(&root, bytes, &scopes);
    bindings.extend(def_bindings);
    bindings.extend(import_bindings(&references, &scopes));

    Ok(FileFacts {
        file: file.to_owned(),
        lang: lang.as_str().to_owned(),
        symbols,
        references,
        scopes,
        bindings,
        ffi_exports: Vec::new(),
    })
}

// ── Namespace derivation ─────────────────────────────────────────────────────

/// Derive namespace descriptors purely from the file path.
///
/// Lua/Luau have no namespace/package declaration — identity is file-based. We
/// strip `.lua`/`.luau`, strip leading `src/`, `lua/`, or `luau/` (common
/// source roots), then split on `/`.
///
/// `src/util.lua`        → `["util"]`
/// `lua/http/client.lua` → `["http", "client"]`
/// `src/m.luau`          → `["m"]`
fn lua_namespaces(file: &str) -> Vec<String> {
    let p = file
        .strip_suffix(".luau")
        .or_else(|| file.strip_suffix(".lua"))
        .unwrap_or(file);
    let p = p
        .strip_prefix("luau/")
        .or_else(|| p.strip_prefix("lua/"))
        .or_else(|| p.strip_prefix("src/"))
        .unwrap_or(p);
    p.split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

// ── Symbol collection ────────────────────────────────────────────────────────

fn collect_symbols(
    root: &Node,
    bytes: &[u8],
    file: &str,
    namespaces: &[String],
    lang: Language,
) -> Vec<Symbol> {
    let ns_descriptors: Vec<Descriptor> = namespaces
        .iter()
        .cloned()
        .map(Descriptor::Namespace)
        .collect();
    let mut out = Vec::new();
    collect_chunk(root, bytes, file, &ns_descriptors, lang, &mut out);
    out
}

/// Walk the `chunk` node and collect top-level definitions.
///
/// Lua's top-level construct is a `chunk` whose children include:
/// - `function_declaration` nodes (global and table-dot/colon methods)
/// - `local_declaration` with a `function_declaration` value (local function)
/// - `variable_declaration` / assignment with a `function_definition` or
///   `table_constructor` value (local `x = function()` / `local M = {}`)
///
/// Luau additionally has `type_definition` nodes (`type X = …` / `export type
/// X = …`). These never appear in plain Lua source, so the arm is a no-op for
/// Lua and active for Luau.
fn collect_chunk(
    node: &Node,
    bytes: &[u8],
    file: &str,
    prefix: &[Descriptor],
    lang: Language,
    out: &mut Vec<Symbol>,
) {
    // Iterate ALL children (field-labeled `local_declaration` children are
    // returned here too, with their node kind — e.g. a local function still has
    // kind `function_declaration`).
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "function_declaration" => {
                collect_function_declaration(&child, bytes, file, prefix, lang, out);
            }
            "variable_declaration" => {
                collect_variable_declaration(&child, bytes, file, prefix, lang, out);
            }
            "assignment_statement" => {
                collect_assignment(&child, bytes, file, prefix, lang, out);
            }
            // Luau: `type Point = { x: number, y: number }` or `export type Point = …`
            // The `name` field is present regardless of the `export` prefix.
            "type_definition" => {
                collect_type_definition(&child, bytes, file, prefix, lang, out);
            }
            _ => {}
        }
    }
}

/// Emit a symbol for a `function_declaration`.
///
/// Covers:
/// - `function foo() end` → Function `foo` under the file prefix.
/// - `function M.baz() end` → Method `baz` under Type `M`.
/// - `function M:qux() end` → Method `qux` under Type `M`.
fn collect_function_declaration(
    node: &Node,
    bytes: &[u8],
    file: &str,
    prefix: &[Descriptor],
    lang: Language,
    out: &mut Vec<Symbol>,
) {
    let name_node = match node.child_by_field_name("name") {
        Some(n) => n,
        None => return,
    };

    match name_node.kind() {
        "identifier" => {
            // Global function: `function foo() end`
            let name = node_text(&name_node, bytes).to_owned();
            let mut descriptors = prefix.to_vec();
            descriptors.push(Descriptor::Method {
                name: name.clone(),
                disambiguator: String::new(),
            });
            out.push(Symbol {
                id: SymbolId::global(lang.as_str(), descriptors),
                name,
                kind: SymbolKind::Function,
                file: file.to_owned(),
                line: (node.start_position().row + 1) as u32,
                span: ByteSpan {
                    start: node.start_byte(),
                    end: node.end_byte(),
                },
                signature: one_line_signature(node_text(node, bytes), &['{', '(']),
            });
        }
        "dot_index_expression" | "method_index_expression" => {
            // `function M.baz()` or `function M:qux()`
            let table_field = if name_node.kind() == "dot_index_expression" {
                ("table", "field")
            } else {
                ("table", "method")
            };
            let table = match field_text(&name_node, table_field.0, bytes) {
                Some(t) => t,
                None => return,
            };
            let method = match field_text(&name_node, table_field.1, bytes) {
                Some(m) => m,
                None => return,
            };
            let mut descriptors = prefix.to_vec();
            descriptors.push(Descriptor::Type(table));
            descriptors.push(Descriptor::Method {
                name: method.clone(),
                disambiguator: String::new(),
            });
            out.push(Symbol {
                id: SymbolId::global(lang.as_str(), descriptors),
                name: method,
                kind: SymbolKind::Method,
                file: file.to_owned(),
                line: (node.start_position().row + 1) as u32,
                span: ByteSpan {
                    start: node.start_byte(),
                    end: node.end_byte(),
                },
                signature: one_line_signature(node_text(node, bytes), &['{', '(']),
            });
        }
        _ => {}
    }
}

/// Handle `variable_declaration` — covers `local x = 1`, `local f = function()`,
/// `local M = {}`.
fn collect_variable_declaration(
    node: &Node,
    bytes: &[u8],
    file: &str,
    prefix: &[Descriptor],
    lang: Language,
    out: &mut Vec<Symbol>,
) {
    // `variable_declaration` wraps an `assignment_statement` that carries the
    // `variable_list`/`expression_list`; delegate to the shared handler.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "assignment_statement" {
            collect_assignment(&child, bytes, file, prefix, lang, out);
        }
    }
}

/// Handle bare `assignment_statement` (e.g. `local M = {}`; or top-level `x = 1`).
fn collect_assignment(
    node: &Node,
    bytes: &[u8],
    file: &str,
    prefix: &[Descriptor],
    lang: Language,
    out: &mut Vec<Symbol>,
) {
    let names: Vec<Node> = node
        .children(&mut node.walk())
        .find(|c| c.kind() == "variable_list")
        .map(|vl| {
            vl.children(&mut vl.walk())
                .filter(|c| c.kind() == "identifier")
                .collect()
        })
        .unwrap_or_default();

    let values: Vec<Node> = node
        .children(&mut node.walk())
        .find(|c| c.kind() == "expression_list")
        .map(|el| {
            el.children(&mut el.walk())
                .filter(|c| !matches!(c.kind(), "," | " "))
                .collect()
        })
        .unwrap_or_default();

    for (i, name_node) in names.iter().enumerate() {
        let name = node_text(name_node, bytes).to_owned();
        let value_opt = values.get(i);
        let ctx = LuaCtx { bytes, file, lang };
        emit_local_symbol(name, value_opt, node, ctx, prefix, out);
    }
}

/// Per-pass context shared by the deep symbol emitters: the source bytes, the
/// file path, and the language tag. Bundled to keep walker signatures small.
#[derive(Clone, Copy)]
struct LuaCtx<'a> {
    bytes: &'a [u8],
    file: &'a str,
    lang: Language,
}

/// Emit a symbol for a named local or assignment, choosing kind from the value.
fn emit_local_symbol(
    name: String,
    value_opt: Option<&Node>,
    decl_node: &Node,
    ctx: LuaCtx,
    prefix: &[Descriptor],
    out: &mut Vec<Symbol>,
) {
    let (bytes, file, lang) = (ctx.bytes, ctx.file, ctx.lang);
    let (kind, descriptor) = match value_opt.map(|v| v.kind()) {
        Some("function_definition") => (
            SymbolKind::Function,
            Descriptor::Method {
                name: name.clone(),
                disambiguator: String::new(),
            },
        ),
        Some("table_constructor") => (SymbolKind::Module, Descriptor::Type(name.clone())),
        _ => (SymbolKind::Static, Descriptor::Term(name.clone())),
    };

    let mut descriptors = prefix.to_vec();
    descriptors.push(descriptor);
    out.push(Symbol {
        id: SymbolId::global(lang.as_str(), descriptors.clone()),
        name,
        kind,
        file: file.to_owned(),
        line: (decl_node.start_position().row + 1) as u32,
        span: ByteSpan {
            start: decl_node.start_byte(),
            end: decl_node.end_byte(),
        },
        signature: one_line_signature(node_text(decl_node, bytes), &['{', '=']),
    });

    // If it's a table constructor, descend into its fields.
    if let Some(val) = value_opt {
        if val.kind() == "table_constructor" {
            collect_table_fields(val, &descriptors, ctx, out);
        }
    }
}

/// Walk a `table_constructor` emitting methods and static fields.
fn collect_table_fields(
    node: &Node,
    type_prefix: &[Descriptor],
    ctx: LuaCtx,
    out: &mut Vec<Symbol>,
) {
    let (bytes, file, lang) = (ctx.bytes, ctx.file, ctx.lang);
    for child in node.children(&mut node.walk()) {
        if child.kind() != "field" {
            continue;
        }
        // field: name: (identifier) value: <expr>
        let Some(fname) = field_text(&child, "name", bytes) else {
            continue;
        };
        let value_kind = child.child_by_field_name("value").map_or("", |v| v.kind());

        let (kind, descriptor) = if value_kind == "function_definition" {
            (
                SymbolKind::Method,
                Descriptor::Method {
                    name: fname.clone(),
                    disambiguator: String::new(),
                },
            )
        } else {
            (SymbolKind::Static, Descriptor::Term(fname.clone()))
        };

        let mut descriptors = type_prefix.to_vec();
        descriptors.push(descriptor);
        out.push(Symbol {
            id: SymbolId::global(lang.as_str(), descriptors),
            name: fname,
            kind,
            file: file.to_owned(),
            line: (child.start_position().row + 1) as u32,
            span: ByteSpan {
                start: child.start_byte(),
                end: child.end_byte(),
            },
            signature: one_line_signature(node_text(&child, bytes), &['{', '=']),
        });
    }
}

/// Emit a [`SymbolKind::TypeAlias`] for a Luau `type_definition` node.
///
/// Handles both `type X = …` and `export type X = …` — the `name` field is
/// present in both forms so no special-casing is needed for the `export`
/// keyword.  This node never appears in plain Lua source, so calling this
/// function for Lua is a no-op.
fn collect_type_definition(
    node: &Node,
    bytes: &[u8],
    file: &str,
    prefix: &[Descriptor],
    lang: Language,
    out: &mut Vec<Symbol>,
) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let name = node_text(&name_node, bytes).to_owned();
    let mut descriptors = prefix.to_vec();
    descriptors.push(Descriptor::Type(name.clone()));
    out.push(Symbol {
        id: SymbolId::global(lang.as_str(), descriptors),
        name,
        kind: SymbolKind::TypeAlias,
        file: file.to_owned(),
        line: (node.start_position().row + 1) as u32,
        span: ByteSpan {
            start: node.start_byte(),
            end: node.end_byte(),
        },
        signature: one_line_signature(node_text(node, bytes), &['=']),
    });
}

// ── Require imports ──────────────────────────────────────────────────────────

/// Walk the tree and emit [`RefRole::Import`] references for every `require(…)` call.
///
/// `require('pkg.sub')` produces an import reference whose `name` is the leaf
/// segment (`sub`) and whose `from_path` is the full dotted path (`pkg.sub`).
///
/// Luau / Roblox: `require(script.Parent.Mod)` passes a `dot_index_expression`
/// chain instead of a string. We handle it by extracting the full dotted text
/// of that expression; the leaf (last `.`-segment) becomes the `name`. This is
/// additive and a no-op for plain Lua (Lua require is always a string literal).
fn collect_require_imports(
    node: &Node,
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Reference>,
    module_id: &str,
) {
    if node.kind() == "function_call" {
        if let Some(name_node) = node.child_by_field_name("name") {
            if name_node.kind() == "identifier" && node_text(&name_node, bytes) == "require" {
                if let Some(args) = node.child_by_field_name("arguments") {
                    // Case 1: string literal require('pkg.sub')
                    if let Some(from_path) = extract_string_arg(&args, bytes) {
                        let leaf = from_path.rsplit('.').next().unwrap_or(&from_path);
                        if leaf.len() >= MIN_REF_LEN {
                            push_import_ref(out, leaf, &name_node, file, module_id, &from_path);
                        }
                    }
                    // Case 2: dot-expression require(script.Parent.Mod) — Roblox/Luau style.
                    else if let Some(from_path) = extract_dot_expr_arg(&args, bytes) {
                        let leaf = from_path.rsplit('.').next().unwrap_or(&from_path);
                        if leaf.len() >= MIN_REF_LEN {
                            push_import_ref(out, leaf, &name_node, file, module_id, &from_path);
                        }
                    }
                }
            }
        }
    }
    for child in node.children(&mut node.walk()) {
        collect_require_imports(&child, bytes, file, out, module_id);
    }
}

/// Extract the first `dot_index_expression` argument text from an `arguments`
/// node, e.g. `script.Parent.Mod` from `require(script.Parent.Mod)`.
///
/// Returns the raw text of the expression node, which will contain `.`-separated
/// identifiers.
fn extract_dot_expr_arg(args: &Node, bytes: &[u8]) -> Option<String> {
    for child in args.children(&mut args.walk()) {
        if child.kind() == "dot_index_expression" {
            return Some(node_text(&child, bytes).to_owned());
        }
    }
    None
}

/// Extract the first string content from an `arguments` node.
fn extract_string_arg(args: &Node, bytes: &[u8]) -> Option<String> {
    for child in args.children(&mut args.walk()) {
        if child.kind() == "string" {
            // Find string_content child.
            for inner in child.children(&mut child.walk()) {
                if inner.kind() == "string_content" {
                    return Some(node_text(&inner, bytes).to_owned());
                }
            }
            // Fallback: strip surrounding quotes from the string node text.
            let raw = node_text(&child, bytes);
            let stripped = raw
                .strip_prefix('\'')
                .and_then(|s| s.strip_suffix('\''))
                .or_else(|| raw.strip_prefix('"').and_then(|s| s.strip_suffix('"')))
                .unwrap_or(raw);
            if !stripped.is_empty() {
                return Some(stripped.to_owned());
            }
        }
    }
    None
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
        "function_declaration" | "function_definition" => {
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
        "function_declaration" | "function_definition" => {
            // Collect parameters.
            if let Some(params) = node.child_by_field_name("parameters") {
                for child in params.named_children(&mut params.walk()) {
                    if child.kind() == "identifier" {
                        let name = node_text(&child, bytes).to_owned();
                        let intro = child.start_byte();
                        if name.len() >= MIN_REF_LEN && innermost_scope(intro, scopes) != Some(0) {
                            push_binding(out, name, intro, BindingKind::Param, scopes);
                        }
                    }
                }
            }
        }
        "local_declaration" => {
            // local x = …
            let mut cur1 = node.walk();
            for inner in node.children(&mut cur1) {
                if inner.kind() == "variable_declaration" {
                    let mut cur2 = inner.walk();
                    let vl_opt = inner
                        .children(&mut cur2)
                        .find(|c| c.kind() == "variable_list");
                    if let Some(vl) = vl_opt {
                        let mut cur3 = vl.walk();
                        for id in vl.children(&mut cur3) {
                            if id.kind() == "identifier" {
                                let name = node_text(&id, bytes).to_owned();
                                let intro = id.start_byte();
                                if name.len() >= MIN_REF_LEN
                                    && innermost_scope(intro, scopes) != Some(0)
                                {
                                    push_binding(out, name, intro, BindingKind::Local, scopes);
                                }
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
    for child in node.children(&mut node.walk()) {
        collect_bindings_dfs(&child, bytes, scopes, out);
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::types::RefRole;

    fn extract(src: &str, file: &str) -> FileFacts {
        LuaExtractor.extract(src, file).unwrap()
    }

    fn by_name(facts: &FileFacts, name: &str) -> Option<Symbol> {
        facts.symbols.iter().find(|s| s.name == name).cloned()
    }

    // ── Definitions ──────────────────────────────────────────────────────────

    #[test]
    fn global_function_is_extracted() {
        // File `src/util.lua` → namespace = ["util"]
        // foo → descriptors: [Namespace("util"), Method { name: "foo" }]
        // SCIP: "codegraph . . . util/foo()."
        let src = "function foo() end";
        let facts = extract(src, "src/util.lua");

        let foo = by_name(&facts, "foo").unwrap();
        assert_eq!(foo.kind, SymbolKind::Function);
        // Verify SCIP string contains the function descriptor rendering.
        let scip = foo.id.to_scip_string();
        assert!(
            scip.contains("util") && scip.contains("foo"),
            "unexpected SCIP string: {scip}"
        );
        assert_eq!(facts.lang, "lua");
    }

    #[test]
    fn table_dot_method_is_extracted_as_method_under_type() {
        let src = "function M.baz(x) end";
        let facts = extract(src, "src/util.lua");

        let baz = by_name(&facts, "baz").unwrap();
        assert_eq!(baz.kind, SymbolKind::Method);
        // SCIP should encode M as a Type descriptor and baz as Method.
        let scip = baz.id.to_scip_string();
        assert!(
            scip.contains("M#") && scip.contains("baz"),
            "unexpected SCIP string: {scip}"
        );
    }

    #[test]
    fn table_colon_method_is_extracted_as_method_under_type() {
        let src = "function M:qux() end";
        let facts = extract(src, "src/util.lua");

        let qux = by_name(&facts, "qux").unwrap();
        assert_eq!(qux.kind, SymbolKind::Method);
        let scip = qux.id.to_scip_string();
        assert!(
            scip.contains("M#") && scip.contains("qux"),
            "unexpected SCIP string: {scip}"
        );
    }

    #[test]
    fn local_function_is_extracted_as_function() {
        let src = "local function bar() end";
        let facts = extract(src, "src/util.lua");

        let bar = by_name(&facts, "bar").unwrap();
        assert_eq!(bar.kind, SymbolKind::Function);
    }

    #[test]
    fn local_table_is_extracted_as_module() {
        let src = "local M = {}";
        let facts = extract(src, "src/util.lua");

        let m = by_name(&facts, "M").unwrap();
        assert_eq!(m.kind, SymbolKind::Module);
    }

    // ── References ───────────────────────────────────────────────────────────

    #[test]
    fn free_call_is_captured_as_call_ref() {
        let src = "function run() foo() end";
        let facts = extract(src, "src/util.lua");

        let call_ref = facts.references.iter().find(|r| r.name == "foo").unwrap();
        assert_eq!(call_ref.role, RefRole::Call);
    }

    #[test]
    fn member_call_captures_qualifier() {
        let src = "function run() a.bar() end";
        let facts = extract(src, "src/util.lua");

        let bar_ref = facts
            .references
            .iter()
            .find(|r| r.name == "bar")
            .expect("expected Call ref for 'bar'");
        assert_eq!(bar_ref.role, RefRole::Call);
        assert_eq!(
            bar_ref.qualifier.as_deref(),
            Some("a"),
            "expected qualifier 'a' on the bar call ref"
        );
    }

    #[test]
    fn require_produces_import_reference() {
        let src = "local sub = require('pkg.sub')";
        let facts = extract(src, "src/util.lua");

        let import_ref = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Import)
            .expect("expected an Import ref from require");
        // Leaf name is `sub` (last `.`-segment)
        assert_eq!(import_ref.name, "sub");
        assert!(
            import_ref
                .from_path
                .as_deref()
                .is_some_and(|p| p.contains("pkg.sub")),
            "from_path should contain 'pkg.sub', got {:?}",
            import_ref.from_path
        );
    }

    #[test]
    fn require_is_not_emitted_as_plain_call() {
        let src = "local sub = require('pkg.sub')";
        let facts = extract(src, "src/util.lua");

        let require_calls: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Call && r.name == "require")
            .collect();
        assert!(
            require_calls.is_empty(),
            "require should not appear as a Call ref"
        );
    }
}
