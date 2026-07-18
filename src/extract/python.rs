// SPDX-License-Identifier: Apache-2.0

//! Python extractor — one tree-sitter pass yielding definitions and references.
//!
//! Definitions: top-level `def` / `async def` (incl. decorated), `class` (incl.
//! decorated), and module-level ALL_CAPS constants. Qualified identity follows
//! the dotted module path derived from the file path (`src/auth/jwt.py` →
//! namespaces `auth`,`jwt`; `__init__.py` collapses to its package).
//! References: callee identifiers of `call` nodes (`foo(...)`, `obj.method(...)`).
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

#[cfg(feature = "sql")]
use super::emit_embedded_sql_refs;
use super::{
    BindingRules, ExtractCtx, Extractor, MIN_REF_LEN, attach_reference_scopes,
    collect_call_references, definition_bindings, field_text, import_bindings, make_symbol,
    mark_self_receiver_calls, node_span, node_text, one_line_signature, push_binding, push_ref,
    push_scope, push_type_ref,
};

/// Tree-sitter query capturing call-callee identifiers.
const CALL_QUERY: &str = r#"
(call
  function: [
    (identifier) @callee
    (attribute attribute: (identifier) @callee)
  ]
)
"#;

/// Method calls whose receiver is written as the conventional `self` parameter
/// (`self.foo()`).
///
/// Python has no `self` keyword — `self` is a plain `identifier` fixed only by
/// the near-universal convention (PEP 8) that a method's first parameter is
/// named `self`. It is therefore structurally indistinguishable from any other
/// object receiver, so this query captures `@receiver` and
/// [`mark_self_receiver_calls`] applies a text gate comparing it against the
/// literal `"self"`. The resolver still fails closed unless the enclosing symbol
/// is itself a type member, so a stray local named `self` outside a method never
/// yields a false edge.
const SELF_CALL_QUERY: &str = r#"
(call
  function: (attribute object: (identifier) @receiver attribute: (identifier) @callee))
"#;

/// Extracts Python symbols and references.
pub struct PythonExtractor;

impl Extractor for PythonExtractor {
    fn lang(&self) -> Language {
        Language::Python
    }

    fn extract(&self, source: &str, file: &str) -> Result<FileFacts> {
        self.extract_impl(source, file, None)
    }

    fn extract_with_bindings(
        &self,
        source: &str,
        file: &str,
        rules: &BindingRules,
    ) -> Result<FileFacts> {
        self.extract_impl(source, file, Some(rules))
    }
}

impl PythonExtractor {
    fn extract_impl(
        &self,
        source: &str,
        file: &str,
        rules: Option<&BindingRules>,
    ) -> Result<FileFacts> {
        let ts_language = crate::grammar::python();
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
        let namespaces = python_namespaces(file);

        let ctx = ExtractCtx {
            bytes,
            file,
            lang: Language::Python,
        };
        let defs = collect_symbols(&root, &ctx, &namespaces);
        let def_bindings = definition_bindings(&defs);
        let mut symbols = defs;
        // Class methods are gathered separately and appended AFTER `def_bindings`
        // is computed from the method-free `defs`. Python's LEGB rule means class
        // body names are not visible in module scope, so method symbols must never
        // flow through `definition_bindings` (which hard-codes `scope: 0`).
        symbols.extend(collect_class_method_symbols(&root, &ctx, &namespaces));
        let mut mod_sym = super::module_symbol(Language::Python, &namespaces, file, source.len());
        let module_id = mod_sym.id.to_scip_string();
        // Idiomatic Python entry point: a module-level `if __name__ == "__main__"`
        // guard marks the whole module as a `Main` entry point.
        if module_is_main_entry(&root, bytes) {
            mod_sym.entry_points.push(EntryPoint::Main);
        }
        symbols.push(mod_sym);
        let mut references = collect_call_references(
            &root,
            &ts_language,
            CALL_QUERY,
            Language::Python,
            bytes,
            file,
        )?;
        mark_self_receiver_calls(
            &root,
            &ts_language,
            SELF_CALL_QUERY,
            Language::Python,
            bytes,
            &mut references,
            Some("self"),
        )?;
        collect_inheritance(&root, bytes, file, &mut references);
        collect_imports(&root, bytes, file, &mut references, &module_id);
        collect_type_references(&root, bytes, file, &mut references);
        collect_read_references(&root, bytes, file, &mut references);
        collect_write_references(&root, bytes, file, &mut references);
        #[cfg(feature = "sql")]
        if let Some(rules) = rules {
            collect_query_bindings(&root, bytes, file, rules, &mut references);
        }
        #[cfg(not(feature = "sql"))]
        let _ = rules;

        let scopes = collect_scopes(&root, source.len());
        attach_reference_scopes(&mut references, &scopes);
        let mut bindings = collect_bindings(&root, bytes, &scopes);
        bindings.extend(def_bindings);
        bindings.extend(import_bindings(&references, &scopes));

        Ok(FileFacts {
            file: file.to_owned(),
            lang: Language::Python.as_str().to_owned(),
            symbols,
            references,
            scopes,
            bindings,
            ffi_exports: Vec::new(),
        })
    }
}

/// Derive the dotted Python module path (namespace descriptors) from a file path.
fn python_namespaces(file: &str) -> Vec<String> {
    let p = file.strip_prefix("src/").unwrap_or(file);
    let mut parts: Vec<String> = p
        .split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    if let Some(last) = parts.pop() {
        let stem = last
            .strip_suffix(".pyi")
            .or_else(|| last.strip_suffix(".py"))
            .unwrap_or(&last);
        if stem != "__init__" {
            parts.push(stem.to_owned());
        }
    }
    parts
}

/// Terminal identifier names that indicate an HTTP-route decorator call.
///
/// Detection rule (honest boundary): a decorator is an HTTP-route marker when it
/// is a CALL node whose `function:` field's terminal identifier is in this set
/// (case-sensitive). Bare non-call decorators (`@staticmethod`, `@dataclass`) and
/// call decorators whose terminal name is NOT here (`@cache.memoize()`) produce no
/// marker.  This is a syntactic, build-free heuristic — it covers Flask-style
/// `@app.route`, FastAPI `@router.get`, Starlette/Tornado route variants and
/// WebSocket handlers, but cannot detect dynamically constructed route registrations
/// or reflection-based frameworks.
const PY_ROUTE_VERBS: &[&str] = &[
    "get",
    "post",
    "put",
    "delete",
    "patch",
    "head",
    "options",
    "trace",
    "route",
    "websocket",
    "ws",
];

/// Compute entry-point markers for a function symbol.
///
/// `fn_name` is the bare function name (for `Main` detection).
/// `outer_node` is the span node — if it is a `decorated_definition`, its
/// `decorator` children are inspected for HTTP-route call decorators.
///
/// Node-kind path for a route decorator:
/// ```text
/// decorated_definition
///   decorator           ("@" + callee text)
///     call
///       function: attribute  ("app.get") or identifier ("get")
///       arguments: argument_list
/// ```
/// The `function:` field of the `call` is the callee; for an `attribute` node the
/// `attribute:` field gives the terminal identifier, for an `identifier` node the
/// text itself is the terminal.  The `attribute` node's full text (e.g. `app.get`)
/// is used as the `HttpRoute` marker string so the consumer can identify both the
/// framework object and the HTTP method without reparsing.
fn entry_points_for(fn_name: &str, outer_node: &Node, bytes: &[u8]) -> Vec<EntryPoint> {
    let mut markers: Vec<EntryPoint> = Vec::new();

    // (a) Name-based entry point: a function literally named `main`.
    if fn_name == "main" {
        markers.push(EntryPoint::Main);
    }

    // (b) HTTP-route decorator detection — only applies to `decorated_definition`.
    if outer_node.kind() != "decorated_definition" {
        return markers;
    }

    for child in outer_node.children(&mut outer_node.walk()) {
        if child.kind() != "decorator" {
            continue;
        }
        // A decorator node's children: "@" (anonymous) then the callee expression.
        // Route detection only fires when the callee is a CALL (not a bare name).
        let Some(call_node) = child
            .children(&mut child.walk())
            .find(|c| c.kind() == "call")
        else {
            continue;
        };

        // The `function:` field of the call is the callee expression.
        let Some(func_node) = call_node.child_by_field_name("function") else {
            continue;
        };

        // Determine the terminal identifier and the full callee text.
        let (terminal, callee_text) = match func_node.kind() {
            "attribute" => {
                // `app.get` / `router.post` — terminal is the `attribute:` field.
                let terminal = func_node
                    .child_by_field_name("attribute")
                    .map(|n| node_text(&n, bytes))
                    .unwrap_or("");
                let callee = node_text(&func_node, bytes);
                (terminal, callee)
            }
            "identifier" => {
                // bare `get(...)` / `route(...)` — terminal is the whole identifier.
                let text = node_text(&func_node, bytes);
                (text, text)
            }
            _ => continue,
        };

        if PY_ROUTE_VERBS.contains(&terminal) {
            markers.push(EntryPoint::HttpRoute(callee_text.to_owned()));
        }
    }

    markers
}

/// Returns `true` iff a DIRECT child of the `module` root is an `if_statement`
/// whose `condition:` is a `comparison_operator` representing the idiomatic
/// `__name__ == "__main__"` guard (in either operand order).
///
/// Node-kind path:
/// ```text
/// module
///   if_statement
///     condition: comparison_operator
///       identifier ("__name__")  "=="  string ("__main__")
/// ```
/// Detection is strict: the operator must be `==` (an anonymous `==` token child
/// of the `comparison_operator`), one operand must be the bare identifier
/// `__name__`, and the other a string whose content is `__main__`. `!=`/`is`/
/// other comparisons are rejected.
fn module_is_main_entry(root: &tree_sitter::Node, bytes: &[u8]) -> bool {
    root.children(&mut root.walk())
        .filter(|n| n.kind() == "if_statement")
        .filter_map(|n| n.child_by_field_name("condition"))
        .filter(|cond| cond.kind() == "comparison_operator")
        .any(|cond| is_name_eq_main(&cond, bytes))
}

/// Returns `true` when `cond` (a `comparison_operator`) is exactly
/// `__name__ == "__main__"` (either operand order).
fn is_name_eq_main(cond: &Node, bytes: &[u8]) -> bool {
    // The operator must be `==`: exactly one child is the anonymous `==` token,
    // and there must be no other comparison operator token (reject chained/`!=`).
    let eq_tokens = cond
        .children(&mut cond.walk())
        .filter(|c| !c.is_named() && c.kind() == "==")
        .count();
    if eq_tokens != 1 {
        return false;
    }

    let operands: Vec<Node> = cond.named_children(&mut cond.walk()).collect();
    if operands.len() != 2 {
        return false;
    }

    let (a, b) = (operands[0], operands[1]);
    is_dunder_name_pair(&a, &b, bytes) || is_dunder_name_pair(&b, &a, bytes)
}

/// `true` when `name_node` is the identifier `__name__` and `str_node` is a
/// string whose content is `__main__`.
fn is_dunder_name_pair(name_node: &Node, str_node: &Node, bytes: &[u8]) -> bool {
    name_node.kind() == "identifier"
        && node_text(name_node, bytes) == "__name__"
        && str_node.kind() == "string"
        && string_content(str_node, bytes) == "__main__"
}

/// Read the textual content of a `string` node, quote-style agnostic.
///
/// Prefers the `string_content` child (the grammar's named content node); falls
/// back to stripping a single layer of surrounding quotes when absent (e.g. an
/// empty string with no `string_content` child).
fn string_content<'a>(string_node: &Node, bytes: &'a [u8]) -> &'a str {
    if let Some(content) = string_node
        .children(&mut string_node.walk())
        .find(|c| c.kind() == "string_content")
    {
        return node_text(&content, bytes);
    }
    node_text(string_node, bytes)
        .trim_matches('"')
        .trim_matches('\'')
}

fn collect_symbols(root: &Node, ctx: &ExtractCtx, namespaces: &[String]) -> Vec<Symbol> {
    let mut out = Vec::new();
    for child in root.children(&mut root.walk()) {
        // (span node, signature node, name, kind, leaf descriptor)
        let parsed = match child.kind() {
            "function_definition" => def_of(&child, &child, ctx.bytes, true),
            "class_definition" => def_of(&child, &child, ctx.bytes, false),
            "decorated_definition" => {
                let Some(inner) = child
                    .children(&mut child.walk())
                    .find(|c| matches!(c.kind(), "function_definition" | "class_definition"))
                else {
                    continue;
                };
                let is_fn = inner.kind() == "function_definition";
                // span includes decorators (outer node); signature is the def line.
                def_of(&child, &inner, ctx.bytes, is_fn)
            }
            "expression_statement" | "assignment" => const_of(&child, ctx.bytes),
            _ => None,
        };
        let Some((span_node, sig_node, name, kind, leaf)) = parsed else {
            continue;
        };

        let mut descriptors: Vec<Descriptor> = namespaces
            .iter()
            .cloned()
            .map(Descriptor::Namespace)
            .collect();
        descriptors.push(leaf);

        let signature = one_line_signature(node_text(&sig_node, ctx.bytes), &[':']);
        let mut sym = make_symbol(
            ctx,
            &span_node,
            name,
            kind,
            Visibility::Public,
            descriptors,
            signature,
        );
        // Populate entry-point markers for function definitions only.
        // Classes and constants never carry route/main markers.
        if sym.kind == SymbolKind::Function {
            sym.entry_points = entry_points_for(&sym.name, &span_node, ctx.bytes);
        }
        out.push(sym);
    }
    out
}

/// Find the first DIRECT child of `node` whose kind is `kind`.
fn find_child_kind<'a>(node: &Node<'a>, kind: &str) -> Option<Node<'a>> {
    node.children(&mut node.walk()).find(|c| c.kind() == kind)
}

/// Collect [`SymbolKind::Method`] symbols for every top-level class's DIRECT
/// method members (`class_definition` / `decorated_definition` wrapping a
/// `class_definition`, found among `root`'s direct children — same scope as
/// `collect_symbols`). Nested classes are deliberately not descended into.
///
/// Kept as a separate pass so these symbols never flow through
/// `definition_bindings`: see the call site in `extract_impl` for why.
fn collect_class_method_symbols(
    root: &Node,
    ctx: &ExtractCtx,
    namespaces: &[String],
) -> Vec<Symbol> {
    let mut out = Vec::new();
    for child in root.children(&mut root.walk()) {
        let class_node = match child.kind() {
            "class_definition" => child,
            "decorated_definition" => {
                let Some(inner) = find_child_kind(&child, "class_definition") else {
                    continue;
                };
                inner
            }
            _ => continue,
        };
        let Some(class_name) = class_node
            .children(&mut class_node.walk())
            .find(|c| c.kind() == "identifier")
            .map(|c| node_text(&c, ctx.bytes).to_owned())
        else {
            continue;
        };
        collect_class_methods(&class_node, ctx, namespaces, &class_name, &mut out);
    }
    out
}

/// Emit a `Type(class_name).Method(method_name)` symbol for each DIRECT
/// `function_definition` (bare or decorated, incl. `async def`) in a class
/// body block. One level only: nested `def`s inside a method body are local
/// functions, not methods, and are not descended into.
fn collect_class_methods(
    class_node: &Node,
    ctx: &ExtractCtx,
    namespaces: &[String],
    class_name: &str,
    out: &mut Vec<Symbol>,
) {
    let Some(body) = class_node.child_by_field_name("body") else {
        return;
    };
    for member in body.children(&mut body.walk()) {
        let (span_node, sig_node) = match member.kind() {
            "function_definition" => (member, member),
            "decorated_definition" => {
                let Some(inner) = find_child_kind(&member, "function_definition") else {
                    continue;
                };
                (member, inner)
            }
            _ => continue,
        };
        let Some(name) = sig_node
            .children(&mut sig_node.walk())
            .find(|c| c.kind() == "identifier")
            .map(|c| node_text(&c, ctx.bytes).to_owned())
        else {
            continue;
        };
        // Same sentinel skip as `def_of`: drop pure-underscore names, keep real
        // dunders like `__init__`.
        if name.chars().all(|c| c == '_') {
            continue;
        }

        let mut descriptors: Vec<Descriptor> = namespaces
            .iter()
            .cloned()
            .map(Descriptor::Namespace)
            .collect();
        descriptors.push(Descriptor::Type(class_name.to_owned()));
        descriptors.push(Descriptor::Method {
            name: name.clone(),
            disambiguator: crate::symbol::MethodDisambiguator::empty(),
        });

        let signature = one_line_signature(node_text(&sig_node, ctx.bytes), &[':']);
        let sym = make_symbol(
            ctx,
            &span_node,
            name,
            SymbolKind::Method,
            Visibility::Public,
            descriptors,
            signature,
        );
        out.push(sym);
    }
}

/// Build a function/class definition tuple from a def node.
fn def_of<'a>(
    span_node: &Node<'a>,
    sig_node: &Node<'a>,
    bytes: &[u8],
    is_fn: bool,
) -> Option<(Node<'a>, Node<'a>, String, SymbolKind, Descriptor)> {
    let name = sig_node
        .children(&mut sig_node.walk())
        .find(|c| c.kind() == "identifier")
        .map(|c| node_text(&c, bytes).to_owned())?;
    // Drop dunder/sentinel names like `__` but keep real dunder methods? Top-level
    // only here; skip names that are entirely underscores.
    if name.chars().all(|c| c == '_') {
        return None;
    }
    let (kind, leaf) = if is_fn {
        (
            SymbolKind::Function,
            Descriptor::Method {
                name: name.clone(),
                disambiguator: crate::symbol::MethodDisambiguator::empty(),
            },
        )
    } else {
        (SymbolKind::Class, Descriptor::Type(name.clone()))
    };
    Some((*span_node, *sig_node, name, kind, leaf))
}

/// Build a constant definition tuple from an ALL_CAPS module-level assignment.
fn const_of<'a>(
    node: &Node<'a>,
    bytes: &[u8],
) -> Option<(Node<'a>, Node<'a>, String, SymbolKind, Descriptor)> {
    let assign = if node.kind() == "assignment" {
        *node
    } else {
        node.children(&mut node.walk())
            .find(|c| c.kind() == "assignment")?
    };
    let lhs = assign
        .children(&mut assign.walk())
        .find(|c| c.kind() == "identifier")?;
    let name = node_text(&lhs, bytes).to_owned();
    if name.len() < 3
        || !name
            .chars()
            .all(|c| c.is_uppercase() || c == '_' || c.is_numeric())
    {
        return None;
    }
    Some((
        *node,
        *node,
        name.clone(),
        SymbolKind::Const,
        Descriptor::Term(name),
    ))
}

/// Recursively walk `node` collecting `Import` references for every
/// `import_statement` and `import_from_statement` in the tree (covers top-level
/// and function-local imports; both attribute correctly via span-containment in
/// the resolver).
///
/// Rules:
/// - `import_from_statement`'s `module_name` field is the from-path (e.g.
///   `pkg.models` in `from pkg.models import Config`).
/// - `import_statement`'s imported names ARE the from-path (e.g. `import os` →
///   `from_path = "os"`; `import foo.bar` → `from_path = "foo.bar"`).
/// - For a `dotted_name` child: emit the leaf segment (last `.`-separated part).
/// - For an `aliased_import` child: emit the leaf of its `name` field (the real
///   name), ignoring the `alias` field.
/// - `wildcard_import` children (`from x import *`) produce no reference.
fn collect_imports(
    node: &Node,
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Reference>,
    module_id: &str,
) {
    match node.kind() {
        "import_from_statement" => {
            // Extract the from-path once from the `module_name` field.
            let module_name = node.child_by_field_name("module_name");
            let from_path = module_name.map_or("", |n| node_text(&n, bytes));
            // Every segment of the from-path is a module → emit a ModuleRef each,
            // positioned at that segment's own identifier node. Relative imports
            // (`from . import x`) have no `dotted_name` module_name → skip.
            if let Some(mn) = module_name {
                emit_module_path_refs(&mn, false, bytes, file, out);
            }
            for child in node.children_by_field_name("name", &mut node.walk()) {
                match child.kind() {
                    "dotted_name" => {
                        let text = node_text(&child, bytes);
                        let leaf = super::simple_type_name(text, ".");
                        super::push_import_ref(out, leaf, &child, file, module_id, from_path);
                    }
                    "aliased_import" => {
                        // Take the real `name` field (a `dotted_name`), ignore `alias`.
                        if let Some(name_node) = child.child_by_field_name("name") {
                            let text = node_text(&name_node, bytes);
                            let leaf = super::simple_type_name(text, ".");
                            super::push_import_ref(
                                out, leaf, &name_node, file, module_id, from_path,
                            );
                        }
                    }
                    // wildcard_import and anything else produce nothing.
                    _ => {}
                }
            }
            // Import statements cannot contain nested import statements.
            return;
        }
        "import_statement" => {
            // `import foo.bar` / `import foo.bar as baz` — the from-path is the
            // full dotted name of the thing being imported (before any alias).
            for child in node.children_by_field_name("name", &mut node.walk()) {
                match child.kind() {
                    "dotted_name" => {
                        let text = node_text(&child, bytes);
                        let leaf = super::simple_type_name(text, ".");
                        // Every segment EXCEPT the last is a module → ModuleRef each
                        // (the last segment stays the existing leaf Import below).
                        emit_module_path_refs(&child, true, bytes, file, out);
                        // from_path = the full dotted text (e.g. "foo.bar")
                        super::push_import_ref(out, leaf, &child, file, module_id, text);
                    }
                    "aliased_import" => {
                        // Take the real `name` field (a `dotted_name`), ignore `alias`.
                        if let Some(name_node) = child.child_by_field_name("name") {
                            let text = node_text(&name_node, bytes);
                            let leaf = super::simple_type_name(text, ".");
                            // from_path = full dotted path before the alias
                            super::push_import_ref(out, leaf, &name_node, file, module_id, text);
                        }
                    }
                    // wildcard_import and anything else produce nothing.
                    _ => {}
                }
            }
            // Import statements cannot contain nested import statements.
            return;
        }
        _ => {}
    }

    // Recurse into all children to cover nested/local imports.
    for child in node.children(&mut node.walk()) {
        collect_imports(&child, bytes, file, out, module_id);
    }
}

/// Emit a [`RefRole::ModuleRef`] reference for module-path segments of a
/// `dotted_name` node, each positioned at its own child `identifier` node.
///
/// `skip_last` controls which segments count as modules:
/// - `false` — every segment is a module (the `from <module> import …` case,
///   where the entire `module_name` path is modules).
/// - `true` — every segment EXCEPT the trailing leaf is a module (the
///   `import a.b.c` case, where the last segment is the imported leaf and stays
///   an `Import`).
///
/// Empty / non-identifier segments are skipped gracefully (`push_ref` also drops
/// empty names), so relative-import dot parts emit nothing.
fn emit_module_path_refs(
    dotted: &Node,
    skip_last: bool,
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Reference>,
) {
    if skip_last {
        // Collect so we can drop the final identifier (the imported leaf).
        let idents: Vec<Node> = dotted
            .children(&mut dotted.walk())
            .filter(|c| c.kind() == "identifier")
            .collect();
        let module_count = idents.len().saturating_sub(1);
        for id in idents.iter().take(module_count) {
            push_ref(out, node_text(id, bytes), id, file, RefRole::ModuleRef);
        }
    } else {
        // Every identifier is a module segment; no need to allocate.
        for id in dotted
            .children(&mut dotted.walk())
            .filter(|c| c.kind() == "identifier")
        {
            push_ref(out, node_text(&id, bytes), &id, file, RefRole::ModuleRef);
        }
    }
}

/// Recursively walk `node` collecting `Inherit` references for every
/// `class_definition` in the tree (including nested classes).
///
/// For each class that has a `superclasses` field (an `argument_list`), we
/// iterate its named children and handle:
/// - `identifier` — simple base name (e.g. `Base`).
/// - `attribute`  — dotted base; we take the `attribute` field (leaf segment,
///   e.g. `mod.Base` → `Base`).
///
/// Everything else (`subscript` for `Generic[T]`, `call`, `keyword_argument`
/// for `metaclass=`) is skipped gracefully.
fn collect_inheritance(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    if node.kind() == "class_definition" {
        if let Some(superclasses) = node.child_by_field_name("superclasses") {
            for child in superclasses.children(&mut superclasses.walk()) {
                if !child.is_named() {
                    continue;
                }
                match child.kind() {
                    "identifier" => {
                        super::push_ref(
                            out,
                            node_text(&child, bytes),
                            &child,
                            file,
                            RefRole::IsImplementation,
                        );
                    }
                    "attribute" => {
                        if let Some(name) = field_text(&child, "attribute", bytes) {
                            super::push_ref(out, &name, &child, file, RefRole::IsImplementation);
                        }
                    }
                    _ => {} // subscript (Generic[T]), call, keyword_argument, etc.
                }
            }
        }
    }

    // Recurse into all children so nested class definitions are covered.
    for child in node.children(&mut node.walk()) {
        collect_inheritance(&child, bytes, file, out);
    }
}

// ── Edge richness: TypeRef / Read / Write ────────────────────────────────────

/// Emit a [`RefRole::TypeRef`] reference by inspecting a `type:` field value.
///
/// In tree-sitter-python the `type:` field holds one of:
/// - `identifier`  — bare name like `int`, `Config`.
/// - `generic_type` — `List[int]`, `Dict[str, int]`: first named child is the
///   `identifier` (outer type name); child `type_parameter` node holds the
///   subscript args, each a `type` expression.
/// - `union_type`  — `int | str`: two `type` children; recurse each with `ctx`.
/// - `member_type` — `pkg.Sub`: the leaf `identifier` child (the last one) is
///   the referenced name; we skip the qualifier.
/// - Any other expression node (e.g. a string literal `"Foo"` for forward refs)
///   is silently skipped.
fn emit_type_node(
    node: &Node,
    bytes: &[u8],
    file: &str,
    ctx: TypeRefContext,
    out: &mut Vec<Reference>,
) {
    match node.kind() {
        // Transparent `type` wrapper (the named rule in tree-sitter-python that
        // wraps a `type:` field value): unwrap and recurse into the single child.
        "type" => {
            for child in node.named_children(&mut node.walk()) {
                emit_type_node(&child, bytes, file, ctx, out);
            }
        }
        "identifier" => {
            let name = node_text(node, bytes);
            push_type_ref(out, name, node, file, ctx);
        }
        "generic_type" => {
            // First named child is the base identifier.
            if let Some(head) = node.named_children(&mut node.walk()).next() {
                if head.kind() == "identifier" {
                    push_type_ref(out, node_text(&head, bytes), &head, file, ctx);
                }
            }
            // Second named child is `type_parameter` (`[...]`); its named
            // children are `type` expressions → recurse as GenericArg.
            if let Some(tp) = node
                .named_children(&mut node.walk())
                .find(|c| c.kind() == "type_parameter")
            {
                for child in tp.named_children(&mut tp.walk()) {
                    emit_type_node(&child, bytes, file, TypeRefContext::GenericArg, out);
                }
            }
        }
        "union_type" => {
            // Both sides are `type` expressions; recurse with the same context.
            for child in node.named_children(&mut node.walk()) {
                emit_type_node(&child, bytes, file, ctx, out);
            }
        }
        "member_type" => {
            // `pkg.Sub`: the last `identifier` child is the leaf name.
            // (grammar: type "." identifier — the identifier is the second child)
            if let Some(id) = node
                .named_children(&mut node.walk())
                .filter(|c| c.kind() == "identifier")
                .last()
            {
                push_type_ref(out, node_text(&id, bytes), &id, file, ctx);
            }
        }
        // Any other expression (string forward ref, etc.) — skip silently.
        _ => {}
    }
}

/// Recursively walk `node` and emit [`RefRole::TypeRef`] references for every
/// type-annotation position in Python source.
///
/// Covered positions:
/// - `typed_parameter` / `typed_default_parameter` — `type:` field → `ParameterType`
/// - `function_definition` — `return_type:` field → `ReturnType`
/// - `assignment` with a `type:` field (annotated assignment / class body field)
///   → `Field`
fn collect_type_references(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    match node.kind() {
        "typed_parameter" | "typed_default_parameter" => {
            if let Some(typ) = node.child_by_field_name("type") {
                emit_type_node(&typ, bytes, file, TypeRefContext::ParameterType, out);
            }
        }
        "function_definition" => {
            if let Some(ret) = node.child_by_field_name("return_type") {
                emit_type_node(&ret, bytes, file, TypeRefContext::ReturnType, out);
            }
            // Recurse into the function body to catch nested defs.
            for child in node.children(&mut node.walk()) {
                collect_type_references(&child, bytes, file, out);
            }
            return; // avoid double-recurse at the bottom
        }
        "assignment" => {
            if let Some(typ) = node.child_by_field_name("type") {
                emit_type_node(&typ, bytes, file, TypeRefContext::Field, out);
            }
        }
        _ => {}
    }

    for child in node.children(&mut node.walk()) {
        collect_type_references(&child, bytes, file, out);
    }
}

/// Returns `true` when `node` (an `identifier`) is in a non-read position —
/// already captured by another collector — and must NOT also be emitted as a
/// [`RefRole::Read`] reference.
///
/// Skipped positions:
/// - Call callee: `call` node's `function:` field.
/// - Declaration name: `function_definition` / `class_definition` `name:` field.
/// - Parameter name: bare `identifier` directly in `parameters`; or the
///   `identifier` inside `typed_parameter`, `default_parameter`,
///   `typed_default_parameter`, `list_splat_pattern`, `dictionary_splat_pattern`.
/// - Import binding: inside `import_statement` or `import_from_statement` or
///   `dotted_name` or `aliased_import`.
/// - Assignment LHS: `assignment` `left:` field (handled by writes).
/// - Attribute name: `attribute` node's `attribute:` field.
/// - Inside a `type` position: already a TypeRef; skip to avoid duplication.
fn is_non_read_position(node: &Node) -> bool {
    let parent = match node.parent() {
        Some(p) => p,
        None => return true,
    };
    match parent.kind() {
        // Call callee — `function:` field of a `call` node.
        "call" => parent.child_by_field_name("function").as_ref() == Some(node),
        // Declaration names.
        "function_definition" | "class_definition" => {
            parent.child_by_field_name("name").as_ref() == Some(node)
        }
        // Parameter: bare identifier directly inside `parameters`.
        "parameters" => true,
        // Typed / default parameter forms: the bound name identifier.
        "typed_parameter" | "list_splat_pattern" | "dictionary_splat_pattern" => {
            // The name is the first named child (an identifier); not the type.
            // We skip ALL identifier children of typed_parameter that are not
            // in the `type:` field — those are the param names.
            parent.child_by_field_name("type").as_ref() != Some(node) && node.kind() == "identifier"
        }
        "default_parameter" => parent.child_by_field_name("name").as_ref() == Some(node),
        "typed_default_parameter" => parent.child_by_field_name("name").as_ref() == Some(node),
        // Import contexts — already Import refs.
        "import_statement" | "import_from_statement" | "dotted_name" | "aliased_import" => true,
        // Assignment LHS — handled by collect_write_references.
        "assignment" => parent.child_by_field_name("left").as_ref() == Some(node),
        // Attribute name (`obj.attr` — skip the `attr` identifier only).
        "attribute" => parent.child_by_field_name("attribute").as_ref() == Some(node),
        // Inside a `type` node (type annotation position) — already a TypeRef.
        "type" => true,
        // `generic_type`'s first identifier is the type name — already TypeRef.
        "generic_type" => true,
        // `union_type`, `member_type` — inside type position.
        "union_type" | "member_type" => true,
        _ => false,
    }
}

/// Recursively walk `node` and emit [`RefRole::Read`] references for bare
/// `identifier` nodes used in value/expression positions. Applies [`MIN_REF_LEN`].
///
/// Skips positions handled by other collectors (call callees, declaration names,
/// parameter names, import bindings, assignment LHS, attribute property names,
/// type-annotation positions).
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
/// bare-identifier LHS of `assignment` nodes (e.g. `x = 5`, `base = helper()`).
///
/// Attribute/subscript LHS (`obj.attr = …`, `arr[i] = …`) are not covered in
/// v1. Applies [`MIN_REF_LEN`].
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

// ── Query-binding scan (cross-artifact code→SQL edges) ───────────────────────

/// Recursively walk `node` looking for call sites matching one of `rules`'s
/// Python constructs (e.g. `cursor.execute`, `text`), and emit a
/// [`RefRole::TypeRef`] reference (`cross_artifact: true`) for every SQL entity
/// (table/view) named in the embedded SQL argument.
///
/// The Python matching convention is the callee's FINAL name segment (not a
/// dotted path): `cursor.execute(...)` matches on `"execute"`, a bare
/// `text(...)` matches on `"text"`. Never fails extraction: a call that
/// doesn't match the expected shape (no matching rule, non-string argument,
/// malformed SQL, …) is simply skipped.
#[cfg(feature = "sql")]
fn collect_query_bindings(
    node: &Node,
    bytes: &[u8],
    file: &str,
    rules: &BindingRules,
    out: &mut Vec<Reference>,
) {
    if node.kind() == "call" {
        if let Some(func) = node.child_by_field_name("function") {
            let attr_name;
            let callee_name: Option<&str> = match func.kind() {
                "identifier" => Some(node_text(&func, bytes)),
                "attribute" => {
                    attr_name = field_text(&func, "attribute", bytes);
                    attr_name.as_deref()
                }
                _ => None,
            };
            if let Some(callee_name) = callee_name {
                for rule in rules.for_language(Language::Python) {
                    if rule.construct != callee_name {
                        continue;
                    }
                    let Some(arguments) = node.child_by_field_name("arguments") else {
                        continue;
                    };
                    let Some(arg) = arguments
                        .named_children(&mut arguments.walk())
                        .nth(rule.sql_arg)
                    else {
                        continue;
                    };
                    emit_embedded_sql_refs(&arg, "string_content", bytes, file, out);
                }
            }
        }
    }

    for child in node.children(&mut node.walk()) {
        collect_query_bindings(&child, bytes, file, rules, out);
    }
}

// ── Scope tree (Tier-B) ──────────────────────────────────────────────────────

/// Build the lexical scope tree for one Python file.
///
/// `scopes[0]` is always the file-root `Module` scope spanning `[0, source_len)`.
/// Python is **function-scoped, not block-scoped**: only `def`/`async def` open
/// a scope; `if`/`for`/`while`/`with` do not. A `class` body is deliberately
/// **not** a scope either — under Python's LEGB rule a method's name lookup skips
/// the enclosing class, so nested defs take the class's enclosing scope as their
/// parent.
///
/// Known v1 boundaries (documented, not yet handled): comprehension and lambda
/// scopes, and the `global`/`nonlocal` rebinding statements.
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

/// DFS opening a `Function` scope for each `def`, recursing all other nodes with
/// the same parent (so `class` bodies and block statements add no scope).
fn scope_dfs(node: &Node, parent_id: ScopeId, scopes: &mut Vec<Scope>) {
    if node.kind() == "function_definition" {
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
    } else {
        for child in node.children(&mut node.walk()) {
            scope_dfs(&child, parent_id, scopes);
        }
    }
}

// ── Bindings (Tier-B) ────────────────────────────────────────────────────────

/// Collect parameter and local-variable [`Binding`]s for one file.
///
/// Covers function parameters and simple `name = …` assignments (each emitted as
/// `BindingKind::Local`/`Param` with `target = BindingTarget::Local`). Tuple/
/// attribute/subscript assignment targets and the walrus operator are deferred.
fn collect_bindings(root: &Node, bytes: &[u8], scopes: &[Scope]) -> Vec<Binding> {
    let mut out = Vec::new();
    collect_bindings_dfs(root, bytes, scopes, &mut out);
    out
}

fn collect_bindings_dfs(node: &Node, bytes: &[u8], scopes: &[Scope], out: &mut Vec<Binding>) {
    match node.kind() {
        "function_definition" => {
            if let Some(params) = node.child_by_field_name("parameters") {
                collect_params(&params, bytes, scopes, out);
            }
            for child in node.children(&mut node.walk()) {
                collect_bindings_dfs(&child, bytes, scopes, out);
            }
        }
        "assignment" => {
            // Only a bare `name = …` target binds a local in this unit.
            if let Some(left) = node.child_by_field_name("left") {
                if left.kind() == "identifier" {
                    let intro = left.start_byte();
                    let name = node_text(&left, bytes).to_owned();
                    push_binding(out, name, intro, BindingKind::Local, scopes);
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

/// Emit a [`BindingKind::Param`] for each parameter in a `parameters` node,
/// unwrapping the typed / default / splat parameter forms to the bound name.
fn collect_params(params: &Node, bytes: &[u8], scopes: &[Scope], out: &mut Vec<Binding>) {
    for child in params.named_children(&mut params.walk()) {
        let ident = match child.kind() {
            "identifier" => Some(child),
            "default_parameter" | "typed_default_parameter" => child.child_by_field_name("name"),
            "typed_parameter" | "list_splat_pattern" | "dictionary_splat_pattern" => child
                .named_children(&mut child.walk())
                .find(|c| c.kind() == "identifier"),
            _ => None,
        };
        if let Some(id) = ident {
            if id.kind() == "identifier" {
                let intro = id.start_byte();
                let name = node_text(&id, bytes).to_owned();
                push_binding(out, name, intro, BindingKind::Param, scopes);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_receiver_call_marks_self_receiver() {
        let src =
            "class C:\n    def foo(self):\n        pass\n    def run(self):\n        self.foo()\n";
        let facts = PythonExtractor.extract(src, "src/c.py").unwrap();
        let foo_call = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Call && r.name == "foo")
            .expect("expected a Call reference for 'foo'");
        assert!(
            foo_call.self_receiver,
            "self.foo() should mark self_receiver = true"
        );
        assert_eq!(
            foo_call.qualifier, None,
            "self-call qualifier must stay None"
        );
    }

    #[test]
    fn non_self_receiver_call_does_not_mark_self_receiver() {
        let src = "class C:\n    def foo(self):\n        pass\n    def run(self, obj):\n        obj.foo()\n";
        let facts = PythonExtractor.extract(src, "src/c.py").unwrap();
        let foo_calls: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Call && r.name == "foo")
            .collect();
        assert!(
            foo_calls.iter().any(|r| !r.self_receiver),
            "obj.foo() must NOT mark self_receiver, got {foo_calls:?}"
        );
    }

    #[test]
    fn extracts_defs_with_dotted_module() {
        let src = "\
def validate_token(tok):
    return helper()

class Config:
    pass

async def fetch_data():
    pass

MAX_RETRIES = 3
";
        let facts = PythonExtractor.extract(src, "src/auth/jwt.py").unwrap();
        let by_name = |n: &str| facts.symbols.iter().find(|s| s.name == n).cloned();

        let vt = by_name("validate_token").unwrap();
        assert_eq!(
            vt.id.to_scip_string(),
            "codegraph . . . auth/jwt/validate_token()."
        );
        assert_eq!(vt.kind, SymbolKind::Function);

        assert_eq!(by_name("Config").unwrap().kind, SymbolKind::Class);
        assert!(by_name("fetch_data").is_some());
        assert_eq!(by_name("MAX_RETRIES").unwrap().kind, SymbolKind::Const);
    }

    #[test]
    fn init_collapses_to_package() {
        let facts = PythonExtractor
            .extract("def helper(): pass", "src/auth/__init__.py")
            .unwrap();
        assert_eq!(
            facts.symbols[0].id.to_scip_string(),
            "codegraph . . . auth/helper()."
        );
    }

    #[test]
    fn emits_function_scope_and_bindings() {
        let src = "def run(arg):\n    local = 1\n    helper(arg)\n";
        let facts = PythonExtractor.extract(src, "src/main.py").unwrap();
        // Module root scope + one function scope.
        assert_eq!(facts.scopes.len(), 2, "expected module + function scope");
        assert_eq!(facts.scopes[0].kind, ScopeKind::Module);
        assert_eq!(facts.scopes[1].kind, ScopeKind::Function);

        let has = |name: &str, kind: BindingKind| {
            facts
                .bindings
                .iter()
                .any(|b| b.name == name && b.kind == kind)
        };
        assert!(has("arg", BindingKind::Param), "param binding missing");
        assert!(has("local", BindingKind::Local), "local binding missing");
        assert!(has("run", BindingKind::Definition), "def binding missing");
    }

    #[test]
    fn class_body_opens_no_scope_legb() {
        // Python's LEGB skips the class scope for nested defs, so a class body
        // adds no scope: the method's enclosing scope is the module.
        let src = "class Foo:\n    def method(self):\n        pass\n";
        let facts = PythonExtractor.extract(src, "src/m.py").unwrap();
        let fn_scopes: Vec<_> = facts
            .scopes
            .iter()
            .filter(|s| s.kind == ScopeKind::Function)
            .collect();
        assert_eq!(fn_scopes.len(), 1, "only the method opens a scope");
        assert!(
            !facts.scopes.iter().any(|s| s.kind == ScopeKind::Type),
            "class body must not open a Type scope in Python"
        );
        assert_eq!(
            fn_scopes[0].parent,
            Some(0),
            "method's enclosing scope is the module (class skipped)"
        );
    }

    #[test]
    fn class_methods_emit_method_symbols() {
        let src = "class Base:\n    def hello(self):\n        pass\n";
        let facts = PythonExtractor.extract(src, "src/m.py").unwrap();
        let hello = facts
            .symbols
            .iter()
            .find(|s| s.name == "hello")
            .expect("expected a 'hello' symbol");
        assert_eq!(hello.kind, SymbolKind::Method);
        assert!(
            hello.id.to_scip_string().ends_with("Base#hello()."),
            "unexpected scip string: {}",
            hello.id.to_scip_string()
        );
        assert!(
            facts
                .symbols
                .iter()
                .any(|s| s.name == "Base" && s.kind == SymbolKind::Class),
            "expected Base Class symbol to still be present"
        );
    }

    #[test]
    fn dunder_init_is_emitted_as_method() {
        let src = "class Base:\n    def __init__(self):\n        pass\n";
        let facts = PythonExtractor.extract(src, "src/m.py").unwrap();
        let init =
            facts.symbols.iter().find(|s| s.name == "__init__").expect(
                "expected '__init__' to be emitted (only pure-underscore names are skipped)",
            );
        assert_eq!(init.kind, SymbolKind::Method);
    }

    #[test]
    fn decorated_and_async_methods_are_emitted() {
        let src = "\
class Base:
    @staticmethod
    def s():
        pass

    @classmethod
    def c(cls):
        pass

    async def a(self):
        pass
";
        let facts = PythonExtractor.extract(src, "src/m.py").unwrap();
        for name in ["s", "c", "a"] {
            let sym = facts
                .symbols
                .iter()
                .find(|s| s.name == name)
                .unwrap_or_else(|| panic!("expected method '{name}' to be emitted"));
            assert_eq!(sym.kind, SymbolKind::Method, "method '{name}' wrong kind");
        }
    }

    #[test]
    fn nested_def_inside_method_is_not_a_symbol() {
        let src = "\
class Base:
    def outer(self):
        def inner():
            pass
        return inner
";
        let facts = PythonExtractor.extract(src, "src/m.py").unwrap();
        assert!(
            !facts.symbols.iter().any(|s| s.name == "inner"),
            "nested `def inner` must not be emitted as a symbol"
        );
        assert!(facts.symbols.iter().any(|s| s.name == "outer"));
    }

    #[test]
    fn class_methods_do_not_leak_module_scope_bindings() {
        // Guards the risk that method symbols flow through `definition_bindings`
        // (which hard-codes `scope: 0`), which would wrongly make `hello()`
        // resolvable as a bare module-scope call anywhere in the file.
        let src = "class Base:\n    def hello(self):\n        pass\n";
        let facts = PythonExtractor.extract(src, "src/m.py").unwrap();
        assert!(
            !facts
                .bindings
                .iter()
                .any(|b| b.name == "hello" && b.kind == BindingKind::Definition && b.scope == 0),
            "method 'hello' must not have a module-scope Definition binding"
        );
    }

    #[test]
    fn extracts_call_references() {
        let facts = PythonExtractor
            .extract(
                "def main():\n    validate_token('t')\n    helper()\n",
                "src/main.py",
            )
            .unwrap();
        let names: Vec<&str> = facts.references.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"validate_token"));
        assert!(names.contains(&"helper"));
    }

    #[test]
    fn extracts_single_base_class_inherit_reference() {
        let src = "class Sub(Base):\n    pass\n";
        let facts = PythonExtractor.extract(src, "src/mod.py").unwrap();
        let inherit_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(
            inherit_names,
            vec!["Base"],
            "expected ['Base'] in {inherit_names:?}"
        );
    }

    #[test]
    fn extracts_multiple_base_classes_inherit_references() {
        let src = "class Multi(A, B):\n    pass\n";
        let facts = PythonExtractor.extract(src, "src/mod.py").unwrap();
        let inherit_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            inherit_names.contains(&"A"),
            "expected 'A' in {inherit_names:?}"
        );
        assert!(
            inherit_names.contains(&"B"),
            "expected 'B' in {inherit_names:?}"
        );
    }

    #[test]
    fn extracts_dotted_base_class_leaf_segment() {
        let src = "class Dotted(mod.Base):\n    pass\n";
        let facts = PythonExtractor.extract(src, "src/mod.py").unwrap();
        let inherit_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(
            inherit_names,
            vec!["Base"],
            "expected ['Base'] in {inherit_names:?}"
        );
    }

    // --- import extraction tests ---

    #[test]
    fn import_from_statement_emits_leaf_name() {
        let src = "from pkg.models import Config\n";
        let facts = PythonExtractor.extract(src, "src/app.py").unwrap();
        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(
            import_names,
            vec!["Config"],
            "expected ['Config'] in {import_names:?}"
        );
    }

    #[test]
    fn import_statement_emits_module_leaf() {
        // `import os` → leaf "os"; `import foo.bar` → leaf "bar"
        let src = "import os\nimport foo.bar\n";
        let facts = PythonExtractor.extract(src, "src/mod.py").unwrap();
        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            import_names.contains(&"os"),
            "expected 'os' in {import_names:?}"
        );
        assert!(
            import_names.contains(&"bar"),
            "expected 'bar' in {import_names:?}"
        );
    }

    #[test]
    fn import_from_statement_multiple_names() {
        let src = "from x import A, B\n";
        let facts = PythonExtractor.extract(src, "src/mod.py").unwrap();
        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            import_names.contains(&"A"),
            "expected 'A' in {import_names:?}"
        );
        assert!(
            import_names.contains(&"B"),
            "expected 'B' in {import_names:?}"
        );
    }

    #[test]
    fn import_alias_emits_real_name_not_alias() {
        // `from pkg import Thing as T` → ref "Thing", not "T"
        let src = "from pkg import Thing as T\n";
        let facts = PythonExtractor.extract(src, "src/mod.py").unwrap();
        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            import_names.contains(&"Thing"),
            "expected 'Thing' in {import_names:?}"
        );
        assert!(
            !import_names.contains(&"T"),
            "alias 'T' must NOT appear in {import_names:?}"
        );
    }

    #[test]
    fn wildcard_import_emits_nothing() {
        let src = "from x import *\n";
        let facts = PythonExtractor.extract(src, "src/mod.py").unwrap();
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

    #[test]
    fn import_refs_carry_source_module() {
        // The import refs for `from pkg.models import Config` should all have
        // `source_module == Some(<module scip id of src/app.py>)`.
        let src = "from pkg.models import Config\n";
        let file = "src/app.py";
        let facts = PythonExtractor.extract(src, file).unwrap();

        // Compute expected module id the same way the extractor does.
        let namespaces = python_namespaces(file);
        let expected_module_id =
            crate::extract::module_symbol(Language::Python, &namespaces, file, src.len())
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

    #[test]
    fn call_refs_have_no_source_module() {
        let src = "def main():\n    helper()\n";
        let facts = PythonExtractor.extract(src, "src/main.py").unwrap();
        let call_refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Call)
            .collect();
        assert!(!call_refs.is_empty(), "expected at least one Call ref");
        for r in &call_refs {
            assert_eq!(
                r.source_module, None,
                "Call ref '{}' must have source_module = None",
                r.name
            );
        }
    }

    // ── Edge richness: TypeRef / Read / Write ────────────────────────────────

    #[test]
    fn py_param_type_ref_emitted() {
        // `def f(c: Config): pass` → TypeRef "Config" with ParameterType ctx.
        let src = "def f(c: Config): pass\n";
        let facts = PythonExtractor.extract(src, "src/main.py").unwrap();
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
    fn py_return_type_ref_emitted() {
        // `def f() -> Config: pass` → TypeRef "Config" with ReturnType ctx.
        let src = "def f() -> Config: pass\n";
        let facts = PythonExtractor.extract(src, "src/main.py").unwrap();
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
    fn py_annotated_field_type_ref_emitted() {
        // `class C:\n    name: Config` → TypeRef "Config" with Field ctx.
        let src = "class C:\n    name: Config\n";
        let facts = PythonExtractor.extract(src, "src/main.py").unwrap();
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
    fn py_read_ref_emitted_for_use_not_declaration() {
        // `def f():\n    base = 1\n    return base`
        // → Read ref for `base` in `return base`; the LHS `base` is a Write, not a Read.
        let src = "def f():\n    base = 1\n    return base\n";
        let facts = PythonExtractor.extract(src, "src/main.py").unwrap();
        let read_refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Read && r.name == "base")
            .collect();
        assert!(
            !read_refs.is_empty(),
            "expected at least one Read ref for 'base', got none"
        );
        // `return base` starts after the assignment line (byte > 20).
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
    fn py_write_ref_emitted_for_assignment() {
        // `def f():\n    xxx = 5` → Write ref for `xxx`.
        let src = "def f():\n    xxx = 5\n";
        let facts = PythonExtractor.extract(src, "src/main.py").unwrap();
        let write_refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Write && r.name == "xxx")
            .collect();
        assert!(
            !write_refs.is_empty(),
            "expected at least one Write ref for 'xxx', got none — all refs: {:?}",
            facts
                .references
                .iter()
                .map(|r| (&r.name, r.role))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn py_call_not_also_read() {
        // `helper()` → a Call ref for "helper", but NOT also a Read ref.
        let src = "def run():\n    helper()\n";
        let facts = PythonExtractor.extract(src, "src/main.py").unwrap();
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
    fn py_attribute_not_a_read_of_property() {
        // `obj.foo` → no Read ref named "foo" (only `obj` can be a Read).
        let src = "def run():\n    return obj.foo\n";
        let facts = PythonExtractor.extract(src, "src/main.py").unwrap();
        let foo_reads: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Read && r.name == "foo")
            .collect();
        assert!(
            foo_reads.is_empty(),
            "attribute 'foo' must NOT be a Read ref; got: {foo_reads:?}"
        );
    }

    // --- module-path ModuleRef tests ---

    fn module_ref_names(facts: &FileFacts) -> Vec<String> {
        let mut names: Vec<String> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::ModuleRef)
            .map(|r| r.name.clone())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn from_import_emits_module_refs_for_path_segments() {
        let src = "from a.b import c\n";
        let facts = PythonExtractor.extract(src, "src/app.py").unwrap();
        assert_eq!(
            module_ref_names(&facts),
            vec!["a".to_owned(), "b".to_owned()],
        );
        assert!(
            facts
                .references
                .iter()
                .any(|r| r.role == RefRole::Import && r.name == "c"),
            "expected Import ref 'c'"
        );
    }

    #[test]
    fn from_single_module_import() {
        let src = "from a import c\n";
        let facts = PythonExtractor.extract(src, "src/app.py").unwrap();
        assert_eq!(module_ref_names(&facts), vec!["a".to_owned()]);
        assert!(
            facts
                .references
                .iter()
                .any(|r| r.role == RefRole::Import && r.name == "c"),
            "expected Import ref 'c'"
        );
    }

    #[test]
    fn import_dotted_emits_module_refs_except_leaf() {
        let src = "import a.b.c\n";
        let facts = PythonExtractor.extract(src, "src/app.py").unwrap();
        assert_eq!(
            module_ref_names(&facts),
            vec!["a".to_owned(), "b".to_owned()],
        );
        assert!(
            facts
                .references
                .iter()
                .any(|r| r.role == RefRole::Import && r.name == "c"),
            "expected Import ref 'c' (the leaf segment) to still be present"
        );
    }

    #[test]
    fn relative_import_no_crash() {
        let src = "from . import x\n";
        let facts = PythonExtractor.extract(src, "src/app.py").unwrap();
        // The lone dot has no module identifier → no ModuleRef at all.
        let module_refs = module_ref_names(&facts);
        assert!(
            module_refs.is_empty(),
            "relative `from . import x` must emit no ModuleRef, got {:?}",
            module_refs
        );
        // And no empty-named ref leaked through anywhere.
        assert!(
            facts.references.iter().all(|r| !r.name.is_empty()),
            "no reference should have an empty name"
        );
    }

    // --- from_path tests ---

    #[test]
    fn import_from_statement_carries_from_path() {
        // `from pkg.models import Config` → from_path == "pkg.models"
        let src = "from pkg.models import Config\n";
        let facts = PythonExtractor.extract(src, "src/app.py").unwrap();
        let r = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Import && r.name == "Config")
            .expect("expected Import ref for 'Config'");
        assert_eq!(
            r.from_path,
            Some("pkg.models".to_owned()),
            "from_path should be 'pkg.models', got {:?}",
            r.from_path
        );
    }

    #[test]
    fn plain_import_statement_carries_from_path() {
        // `import os` → from_path == "os"; `import foo.bar` → from_path == "foo.bar"
        let src = "import os\nimport foo.bar\n";
        let facts = PythonExtractor.extract(src, "src/mod.py").unwrap();

        let os_ref = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Import && r.name == "os")
            .expect("expected Import ref for 'os'");
        assert_eq!(
            os_ref.from_path,
            Some("os".to_owned()),
            "from_path for 'import os' should be 'os', got {:?}",
            os_ref.from_path
        );

        let bar_ref = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Import && r.name == "bar")
            .expect("expected Import ref for 'bar'");
        assert_eq!(
            bar_ref.from_path,
            Some("foo.bar".to_owned()),
            "from_path for 'import foo.bar' should be 'foo.bar', got {:?}",
            bar_ref.from_path
        );
    }

    // ── Entry-point detection ────────────────────────────────────────────────

    /// Helper: find a symbol by bare name and return a clone.
    fn sym_by_name(facts: &FileFacts, name: &str) -> Symbol {
        facts
            .symbols
            .iter()
            .find(|s| s.name == name)
            .unwrap_or_else(|| {
                panic!("symbol '{name}' not found; symbols: {:?}", {
                    let names: Vec<&str> = facts.symbols.iter().map(|s| s.name.as_str()).collect();
                    names
                })
            })
            .clone()
    }

    /// Helper: render entry_points as a compact string for assertion messages.
    fn ep_str(eps: &[EntryPoint]) -> String {
        eps.iter()
            .map(|ep| match ep {
                EntryPoint::Main => "Main".to_owned(),
                EntryPoint::HttpRoute(m) => format!("HttpRoute({m})"),
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    #[test]
    fn entry_point_app_get_route() {
        // @app.get("/users") → HttpRoute("app.get")
        let src = "@app.get(\"/users\")\ndef list_users():\n    pass\n";
        let facts = PythonExtractor.extract(src, "src/routes.py").unwrap();
        let sym = sym_by_name(&facts, "list_users");
        assert_eq!(
            sym.entry_points.len(),
            1,
            "expected exactly 1 entry point, got [{}]",
            ep_str(&sym.entry_points)
        );
        assert!(
            matches!(&sym.entry_points[0], EntryPoint::HttpRoute(m) if m == "app.get"),
            "expected HttpRoute(\"app.get\"), got [{}]",
            ep_str(&sym.entry_points)
        );
    }

    #[test]
    fn entry_point_app_route_with_methods_arg() {
        // @app.route("/x", methods=["POST"]) → HttpRoute("app.route")
        let src = "@app.route(\"/x\", methods=[\"POST\"])\ndef handler():\n    pass\n";
        let facts = PythonExtractor.extract(src, "src/routes.py").unwrap();
        let sym = sym_by_name(&facts, "handler");
        assert_eq!(
            sym.entry_points.len(),
            1,
            "expected exactly 1 entry point, got [{}]",
            ep_str(&sym.entry_points)
        );
        assert!(
            matches!(&sym.entry_points[0], EntryPoint::HttpRoute(m) if m == "app.route"),
            "expected HttpRoute(\"app.route\"), got [{}]",
            ep_str(&sym.entry_points)
        );
    }

    #[test]
    fn entry_point_non_route_decorator_ignored() {
        // A top-level call-form decorator whose terminal name is NOT a route verb
        // (`lru_cache` ∉ PY_ROUTE_VERBS) must produce no entry point. (Bare
        // non-call decorators like `@staticmethod` only appear on class methods,
        // which `collect_symbols` doesn't descend into.)
        let src =
            "import functools\n@functools.lru_cache(maxsize=128)\ndef compute(x):\n    pass\n";
        let facts = PythonExtractor.extract(src, "src/util.py").unwrap();
        let sym2 = sym_by_name(&facts, "compute");
        assert!(
            sym2.entry_points.is_empty(),
            "non-route call decorator must not produce entry points; got [{}]",
            ep_str(&sym2.entry_points)
        );
    }

    #[test]
    fn entry_point_main_function() {
        // def main(): pass → EntryPoint::Main
        let src = "def main():\n    pass\n";
        let facts = PythonExtractor.extract(src, "src/main.py").unwrap();
        let sym = sym_by_name(&facts, "main");
        assert_eq!(
            sym.entry_points.len(),
            1,
            "expected exactly 1 entry point, got [{}]",
            ep_str(&sym.entry_points)
        );
        assert!(
            matches!(&sym.entry_points[0], EntryPoint::Main),
            "expected Main, got [{}]",
            ep_str(&sym.entry_points)
        );
    }

    #[test]
    fn entry_point_plain_function_empty() {
        // An undecorated, non-main function → empty entry_points.
        let src = "def process(data):\n    return data\n";
        let facts = PythonExtractor.extract(src, "src/util.py").unwrap();
        let sym = sym_by_name(&facts, "process");
        assert!(
            sym.entry_points.is_empty(),
            "plain function must have no entry points; got [{}]",
            ep_str(&sym.entry_points)
        );
    }

    #[test]
    fn entry_point_fastapi_router_post() {
        // @router.post("/items") → HttpRoute("router.post")
        let src = "@router.post(\"/items\")\ndef create_item():\n    pass\n";
        let facts = PythonExtractor.extract(src, "src/items.py").unwrap();
        let sym = sym_by_name(&facts, "create_item");
        assert_eq!(
            sym.entry_points.len(),
            1,
            "expected exactly 1 entry point, got [{}]",
            ep_str(&sym.entry_points)
        );
        assert!(
            matches!(&sym.entry_points[0], EntryPoint::HttpRoute(m) if m == "router.post"),
            "expected HttpRoute(\"router.post\"), got [{}]",
            ep_str(&sym.entry_points)
        );
    }

    #[test]
    fn entry_point_websocket_route() {
        // @bp.websocket("/ws") → HttpRoute("bp.websocket")
        let src = "@bp.websocket(\"/ws\")\ndef ws_handler():\n    pass\n";
        let facts = PythonExtractor.extract(src, "src/ws.py").unwrap();
        let sym = sym_by_name(&facts, "ws_handler");
        assert_eq!(
            sym.entry_points.len(),
            1,
            "expected exactly 1 entry point, got [{}]",
            ep_str(&sym.entry_points)
        );
        assert!(
            matches!(&sym.entry_points[0], EntryPoint::HttpRoute(m) if m == "bp.websocket"),
            "expected HttpRoute(\"bp.websocket\"), got [{}]",
            ep_str(&sym.entry_points)
        );
    }

    #[test]
    fn entry_point_main_guard_marks_module() {
        // A module-level `if __name__ == "__main__":` guard marks the MODULE
        // symbol (kind Module) as a `Main` entry point.
        let src = "if __name__ == \"__main__\":\n    pass\n";
        let facts = PythonExtractor.extract(src, "src/app.py").unwrap();
        let module = facts
            .symbols
            .iter()
            .find(|s| s.kind == SymbolKind::Module)
            .expect("expected a Module symbol");
        assert!(
            module
                .entry_points
                .iter()
                .any(|ep| matches!(ep, EntryPoint::Main)),
            "module guard must mark the module Main; got [{}]",
            ep_str(&module.entry_points)
        );
    }

    #[test]
    fn entry_point_non_main_guard_ignored() {
        // `if __name__ == "__other__":` is NOT the main guard → no entry point.
        let src = "if __name__ == \"__other__\":\n    pass\n";
        let facts = PythonExtractor.extract(src, "src/app.py").unwrap();
        let module = facts
            .symbols
            .iter()
            .find(|s| s.kind == SymbolKind::Module)
            .expect("expected a Module symbol");
        assert!(
            module.entry_points.is_empty(),
            "non-main guard must not mark the module; got [{}]",
            ep_str(&module.entry_points)
        );
    }

    // ── Query-binding cross-artifact refs (code→SQL) ─────────────────────────

    #[cfg(feature = "sql")]
    #[test]
    fn method_call_query_binding_emits_cross_artifact_typeref() {
        let src = "cursor.execute(\"SELECT id FROM users\")\n";
        let facts = PythonExtractor
            .extract_with_bindings(src, "src/app.py", &BindingRules::with_defaults())
            .unwrap();

        let found = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::TypeRef && r.name == "users" && r.cross_artifact);
        let r = found.expect("expected a cross-artifact TypeRef reference named 'users'");

        let select_byte = src.find("SELECT").expect("fixture contains SELECT");
        assert!(
            r.occ.byte >= select_byte,
            "reference byte {} should point at/after 'SELECT' at {}",
            r.occ.byte,
            select_byte
        );
    }

    #[cfg(feature = "sql")]
    #[test]
    fn plain_function_query_binding_emits_cross_artifact_typeref() {
        let src = "text(\"SELECT id FROM orders\")\n";
        let facts = PythonExtractor
            .extract_with_bindings(src, "src/app.py", &BindingRules::with_defaults())
            .unwrap();

        let found = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::TypeRef && r.name == "orders" && r.cross_artifact);
        found.expect("expected a cross-artifact TypeRef reference named 'orders'");
    }

    #[cfg(feature = "sql")]
    #[test]
    fn empty_binding_rules_yield_no_cross_artifact_reference() {
        let src = "cursor.execute(\"SELECT id FROM users\")\n";
        let file = "src/app.py";

        let with_empty_rules = PythonExtractor
            .extract_with_bindings(src, file, &BindingRules::empty())
            .unwrap();
        assert!(
            !with_empty_rules.references.iter().any(|r| r.cross_artifact),
            "an empty binding-rule registry must yield no cross-artifact references"
        );

        let plain = PythonExtractor.extract(src, file).unwrap();
        assert!(
            !plain.references.iter().any(|r| r.cross_artifact),
            "the plain extract() path must yield no cross-artifact references"
        );
    }
}
