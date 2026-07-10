// SPDX-License-Identifier: Apache-2.0

//! Ruby extractor — one tree-sitter pass yielding definitions and references.
//!
//! Definitions: classes, modules, methods (instance and singleton), and constant
//! assignments, discovered by a **recursive walk** so nested class/module bodies
//! are handled correctly.
//!
//! **Visibility note:** Ruby `private` / `protected` are runtime method calls, not
//! syntactic modifiers, so visibility cannot be determined from the AST alone.
//! Every method, class, module, and constant is emitted regardless of the
//! `private` / `protected` call that may follow it. This is a known syntactic-
//! ceiling limitation.
//!
//! **No-arg method calls:** paren-less calls such as `helper` are syntactically
//! indistinguishable from local-variable reads at the tree-sitter level. Only
//! explicit `call` nodes with a `method:` field are captured as references.
//!
//! References: callee identifiers of `call` nodes — both bare (`foo()`, no
//! receiver) and receiver-qualified (`Recv.foo()`, where the receiver is
//! captured as `@qualifier` and forwarded to the resolver for type-qualified
//! resolution).

use tree_sitter::{Node, Parser};

use crate::error::{CodegraphError, Result};
use crate::graph::types::{
    Binding, BindingKind, ByteSpan, FileFacts, RefRole, Reference, Scope, ScopeId, ScopeKind,
    Symbol, SymbolKind, Visibility,
};
use crate::lang::Language;
use crate::symbol::Descriptor;

use super::{
    ExtractCtx, Extractor, MIN_REF_LEN, attach_reference_scopes, collect_call_references,
    definition_bindings, field_text, innermost_scope, make_symbol, node_span, node_text,
    one_line_signature, push_binding, push_ref, push_scope,
};

/// Tree-sitter query capturing explicit call-callee identifiers.
///
/// Two mutually-exclusive patterns (split on the `receiver` field so a qualified
/// call is never double-counted):
/// - bare call `foo()` — `!receiver` asserts no receiver, captures `@callee`.
/// - qualified call `Recv.foo()` — captures the receiver as `@qualifier` and the
///   method as `@callee`, so the call resolves through its receiver (e.g. a module
///   like `Alpha`) instead of fanning out across every same-named method.
const CALL_QUERY: &str = r#"
[
  (call !receiver method: (identifier) @callee)
  (call receiver: (_) @qualifier method: (identifier) @callee)
]
"#;

/// Extracts Ruby symbols and references.
pub struct RubyExtractor;

impl Extractor for RubyExtractor {
    fn lang(&self) -> Language {
        Language::Ruby
    }

    fn extract(&self, source: &str, file: &str) -> Result<FileFacts> {
        let ts_language = crate::grammar::ruby();
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
            lang: Language::Ruby,
        };

        let ns_strings = ruby_namespaces(file);
        let namespaces: Vec<Descriptor> = ns_strings
            .iter()
            .cloned()
            .map(Descriptor::Namespace)
            .collect();

        let mut defs = Vec::new();
        walk(&root, &namespaces, &ctx, &mut defs);
        let def_bindings = definition_bindings(&defs);
        let mut symbols = defs;
        symbols.push(super::module_symbol(
            Language::Ruby,
            &ns_strings,
            file,
            source.len(),
        ));

        let mut references =
            collect_call_references(&root, &ts_language, CALL_QUERY, Language::Ruby, bytes, file)?;
        collect_inheritance(&root, bytes, file, &mut references);
        collect_read_references(&root, bytes, file, &mut references);
        collect_write_references(&root, bytes, file, &mut references);

        let scopes = collect_scopes(&root, source.len());
        attach_reference_scopes(&mut references, &scopes);
        let mut bindings = collect_bindings(&root, bytes, &scopes);
        bindings.extend(def_bindings);

        Ok(FileFacts {
            file: file.to_owned(),
            lang: Language::Ruby.as_str().to_owned(),
            symbols,
            references,
            scopes,
            bindings,
            ffi_exports: Vec::new(),
        })
    }
}

/// Derive the Ruby module path (namespace descriptors) from a file path.
///
/// Strips the `.rb` extension, then strips a leading `lib/`, `app/`, or `src/`
/// prefix (each tried in turn), then splits on `/`. All segments are kept.
fn ruby_namespaces(file: &str) -> Vec<String> {
    let p = file.strip_suffix(".rb").unwrap_or(file);
    let p = p
        .strip_prefix("lib/")
        .or_else(|| p.strip_prefix("app/"))
        .or_else(|| p.strip_prefix("src/"))
        .unwrap_or(p);
    p.split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Recursively walk a node, emitting `Symbol`s into `out`.
///
/// `prefix` is the descriptor path inherited from enclosing class/module nodes.
/// Classes and modules push a `Descriptor::Type` and recurse into their `body`.
/// Methods push a `Descriptor::Method` and do not recurse (inner defs are rare
/// and would produce confusing qualified names). Constant assignments push a
/// `Descriptor::Term`.
fn walk(node: &Node, prefix: &[Descriptor], ctx: &ExtractCtx, out: &mut Vec<Symbol>) {
    for child in node.children(&mut node.walk()) {
        match child.kind() {
            "class" | "module" => {
                let Some(name) = field_text(&child, "name", ctx.bytes) else {
                    continue;
                };
                let kind = if child.kind() == "class" {
                    SymbolKind::Class
                } else {
                    SymbolKind::Module
                };
                let mut descriptors = prefix.to_vec();
                descriptors.push(Descriptor::Type(name.clone()));
                if let Some(body) = child.child_by_field_name("body") {
                    push_symbol(out, ctx, &child, name, kind, descriptors.clone());
                    walk(&body, &descriptors, ctx, out);
                } else {
                    push_symbol(out, ctx, &child, name, kind, descriptors);
                }
            }
            "method" | "singleton_method" => {
                let Some(name) = field_text(&child, "name", ctx.bytes) else {
                    continue;
                };
                let mut descriptors = prefix.to_vec();
                descriptors.push(Descriptor::Method {
                    name: name.clone(),
                    disambiguator: crate::symbol::MethodDisambiguator::empty(),
                });
                push_symbol(out, ctx, &child, name, SymbolKind::Method, descriptors);
                // Do not recurse into method bodies — inner defs would produce
                // misleading qualified names and are not top-level API surface.
            }
            "assignment" => {
                // Constant assignment: the left-hand side is a `constant` node.
                if let Some(left) = child.child_by_field_name("left") {
                    if left.kind() == "constant" {
                        let name = node_text(&left, ctx.bytes).to_owned();
                        let mut descriptors = prefix.to_vec();
                        descriptors.push(Descriptor::Term(name.clone()));
                        push_symbol(out, ctx, &child, name, SymbolKind::Const, descriptors);
                    }
                }
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
    descriptors: Vec<Descriptor>,
) {
    // Empty stop slice → first-line fallback, which is correct for Ruby's
    // `end`-terminated blocks (no `{` to split on).
    let signature = one_line_signature(node_text(node, ctx.bytes), &[]);
    out.push(make_symbol(
        ctx,
        node,
        name,
        kind,
        Visibility::Unknown,
        descriptors,
        signature,
    ));
}

/// Recursively walk `node` collecting `Inherit` references for every `class`
/// node in the tree (including nested classes).
///
/// `module` nodes are skipped — Ruby modules have no superclass.
fn collect_inheritance(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    if node.kind() == "class" {
        if let Some(superclass_node) = node.child_by_field_name("superclass") {
            // The `superclass` node's first named child is the parent type
            // expression (`constant` or `scope_resolution`).
            if let Some(type_node) = superclass_node
                .children(&mut superclass_node.walk())
                .find(|c| c.is_named())
            {
                super::push_ref(
                    out,
                    super::simple_type_name(node_text(&type_node, bytes), "::"),
                    &type_node,
                    file,
                    RefRole::IsImplementation,
                );
            }
        }
    }

    // Recurse into all children so nested classes are covered.
    for child in node.children(&mut node.walk()) {
        collect_inheritance(&child, bytes, file, out);
    }
}

// ── Edge richness: Read / Write ──────────────────────────────────────────────

/// Returns `true` when `node` (an `identifier`) is in a position already handled
/// by another collector and must NOT also be emitted as a [`RefRole::Read`].
///
/// Skipped positions:
/// - `call` node's `method:` field — the callee identifier captured by `CALL_QUERY`
///   as a [`RefRole::Call`] reference.
/// - `method` / `singleton_method` `name:` field — the declaration name.
/// - Any `identifier` directly inside `method_parameters` or `block_parameters`
///   (positional params), or the `name:` field of `optional_parameter`,
///   `keyword_parameter`, `splat_parameter`, `block_parameter`,
///   `hash_splat_parameter` — all are parameter bindings, not reads.
/// - `assignment` `left:` field when the left node is an `identifier` — handled
///   by [`collect_write_references`].
///
/// Note: `instance_variable`, `class_variable`, `global_variable`, and `constant`
/// are different node kinds from `identifier`; they are excluded naturally before
/// this guard is reached.
fn is_non_read_position(node: &Node) -> bool {
    let parent = match node.parent() {
        Some(p) => p,
        None => return true, // root — not a read
    };
    match parent.kind() {
        // Call callee: `obj.method(...)` — the `method:` field of a `call` node.
        // (Paren-less calls like `helper` produce a bare `identifier`, NOT a `call`
        // node; those are emitted as Read, and the resolver distinguishes them.)
        "call" => parent.child_by_field_name("method").as_ref() == Some(node),
        // Declaration names: `def foo` / `def self.foo`.
        "method" | "singleton_method" => parent.child_by_field_name("name").as_ref() == Some(node),
        // Positional parameter: bare `identifier` directly in method/block params.
        "method_parameters" | "block_parameters" => true,
        // Named parameter forms: skip the `name:` field identifier.
        "optional_parameter"
        | "keyword_parameter"
        | "splat_parameter"
        | "block_parameter"
        | "hash_splat_parameter" => parent.child_by_field_name("name").as_ref() == Some(node),
        // Assignment LHS — handled by collect_write_references.
        "assignment" => parent.child_by_field_name("left").as_ref() == Some(node),
        _ => false,
    }
}

/// Recursively walk `node` and emit [`RefRole::Read`] references for bare
/// `identifier` nodes used in value/expression positions.
///
/// In Ruby a bare `identifier` that is NOT a paren-less call (`call` with a
/// `method:` field) is syntactically indistinguishable from a local-variable read.
/// We emit a `Read` for every such identifier and let the Tier-B scope-walk
/// resolver decide: if a binding is visible the edge resolves to that local; if
/// no binding is visible the resolver falls back to `NameOnly` fan-out (treating
/// it as a method call). This is the correct honest approach for a dynamically
/// typed language.
///
/// Applies [`MIN_REF_LEN`]. Does not recurse into `identifier` children (there are
/// none meaningful).
fn collect_read_references(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    if node.kind() == "identifier" {
        let name = node_text(node, bytes);
        if name.len() >= MIN_REF_LEN && !is_non_read_position(node) {
            push_ref(out, name, node, file, RefRole::Read);
        }
        // `identifier` leaves have no meaningful sub-nodes; return early.
        return;
    }
    for child in node.children(&mut node.walk()) {
        collect_read_references(&child, bytes, file, out);
    }
}

/// Recursively walk `node` and emit [`RefRole::Write`] references for the
/// bare-identifier LHS of `assignment` nodes (e.g. `x = 5`, `cnt = 0`).
///
/// Only bare local-name `identifier` LHS targets are covered in v1. Skipped:
/// `instance_variable` / `class_variable` / `global_variable` / `constant` LHS
/// (different node kinds), call-result LHS (`obj.prop = …` — `call` node),
/// and element-reference LHS (`arr[i] = …` — `element_reference`). Applies
/// [`MIN_REF_LEN`].
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

/// Build the lexical scope tree for one Ruby file.
///
/// `scopes[0]` is always the file-root `Module` scope spanning `[0, source_len)`.
/// Ruby opens scopes for:
/// - `class`, `module`, `singleton_class` → `Type` scope
/// - `method`, `singleton_method` → `Function` scope
/// - `block`, `do_block` → `Function` scope (blocks are closure-like; their locals
///   are distinct from the enclosing method)
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

/// DFS opening scopes for Ruby declaration nodes.
///
/// Body peeling strategy (mirrors go.rs/php.rs):
/// - `class` / `module` / `singleton_class`: body field is a `body_statement`;
///   recurse its children under the Type scope so the body node itself does not
///   re-open a redundant scope.
/// - `method` / `singleton_method`: body field may be a `body_statement`
///   (normal def), an expression (endless method: `def f = expr`), or absent
///   (abstract-like). Recurse body_statement children; else recurse the body
///   node itself; if absent, do nothing.
/// - `do_block`: body field is a `body_statement`; recurse its children under
///   the Function scope.
/// - `block`: body field is a `block_body`; recurse its children under the
///   Function scope.
/// - All other nodes: recurse children under the same parent.
fn scope_dfs(node: &Node, parent_id: ScopeId, scopes: &mut Vec<Scope>) {
    match node.kind() {
        "class" | "module" | "singleton_class" => {
            let type_id = push_scope(scopes, Some(parent_id), node_span(node), ScopeKind::Type);
            if let Some(body) = node.child_by_field_name("body") {
                // body is a body_statement — recurse its children
                for child in body.children(&mut body.walk()) {
                    scope_dfs(&child, type_id, scopes);
                }
            }
            // If no body, nothing to recurse into.
        }
        "method" | "singleton_method" => {
            let fn_id = push_scope(
                scopes,
                Some(parent_id),
                node_span(node),
                ScopeKind::Function,
            );
            if let Some(body) = node.child_by_field_name("body") {
                if body.kind() == "body_statement" {
                    // Normal method — peel the body_statement
                    for child in body.children(&mut body.walk()) {
                        scope_dfs(&child, fn_id, scopes);
                    }
                } else {
                    // Endless method (`def f = expr`) — body is the expression
                    scope_dfs(&body, fn_id, scopes);
                }
            }
            // Abstract-ish / empty method: no body field at all → nothing more to do.
        }
        "do_block" => {
            let fn_id = push_scope(
                scopes,
                Some(parent_id),
                node_span(node),
                ScopeKind::Function,
            );
            if let Some(body) = node.child_by_field_name("body") {
                // body is a body_statement
                for child in body.children(&mut body.walk()) {
                    scope_dfs(&child, fn_id, scopes);
                }
            }
        }
        "block" => {
            let fn_id = push_scope(
                scopes,
                Some(parent_id),
                node_span(node),
                ScopeKind::Function,
            );
            if let Some(body) = node.child_by_field_name("body") {
                // body is a block_body
                for child in body.children(&mut body.walk()) {
                    scope_dfs(&child, fn_id, scopes);
                }
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

/// Collect parameter and local-variable [`Binding`]s for one Ruby file.
///
/// Covers:
/// - `method` / `singleton_method` parameters → [`BindingKind::Param`].
/// - `block` / `do_block` parameters → [`BindingKind::Param`].
/// - `assignment` with an `identifier` on the left → [`BindingKind::Local`]
///   (only when the innermost scope is `Function` or `Block`).
///
/// Class-level constant assignments (`BAR = 1` in a class body) are **not**
/// emitted as `Local` because their enclosing scope is `Type`, which fails the
/// Function|Block guard. Instance variables (`@x = ...`), class variables
/// (`@@x`), and global variables (`$x`) are also excluded — the LHS kind is
/// `instance_variable`, `class_variable`, or `global_variable`, not
/// `identifier`, so the guard fires before any scope check.
fn collect_bindings(root: &Node, bytes: &[u8], scopes: &[Scope]) -> Vec<Binding> {
    let mut out = Vec::new();
    collect_bindings_dfs(root, bytes, scopes, &mut out);
    out
}

fn collect_bindings_dfs(node: &Node, bytes: &[u8], scopes: &[Scope], out: &mut Vec<Binding>) {
    match node.kind() {
        "method" | "singleton_method" => {
            if let Some(params) = node.child_by_field_name("parameters") {
                // parameters field is a method_parameters node
                collect_params(&params, bytes, scopes, out);
            }
            for child in node.children(&mut node.walk()) {
                collect_bindings_dfs(&child, bytes, scopes, out);
            }
        }
        "block" | "do_block" => {
            if let Some(params) = node.child_by_field_name("parameters") {
                // parameters field is a block_parameters node
                collect_params(&params, bytes, scopes, out);
            }
            for child in node.children(&mut node.walk()) {
                collect_bindings_dfs(&child, bytes, scopes, out);
            }
        }
        "assignment" => {
            if let Some(left) = node.child_by_field_name("left") {
                if left.kind() == "identifier" {
                    let name = node_text(&left, bytes).to_owned();
                    let intro = left.start_byte();
                    if let Some(sid) = innermost_scope(intro, scopes) {
                        if matches!(scopes[sid].kind, ScopeKind::Function | ScopeKind::Block) {
                            push_binding(out, name, intro, BindingKind::Local, scopes);
                        }
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

/// Emit a [`BindingKind::Param`] for each named parameter in a Ruby
/// `method_parameters` or `block_parameters` node.
///
/// Handles:
/// - `identifier` (positional param) — name is the node text directly.
/// - `optional_parameter` (`a = 1`) — name from `name` field.
/// - `keyword_parameter` (`a:` or `a: default`) — name from `name` field.
/// - `splat_parameter` (`*a`) — name from `name` field (absent for bare `*`).
/// - `block_parameter` (`&b`) — name from `name` field.
/// - `hash_splat_parameter` (`**kw`) — name from `name` field (absent for bare `**`).
/// - Other kinds (e.g. `destructured_parameter`, `forward_parameter`) are skipped.
///
/// No Function|Block guard is needed: params are always introduced inside a
/// method/block, which is a Function scope by construction.
fn collect_params(params: &Node, bytes: &[u8], scopes: &[Scope], out: &mut Vec<Binding>) {
    for child in params.named_children(&mut params.walk()) {
        match child.kind() {
            "identifier" => {
                let name = node_text(&child, bytes).to_owned();
                let intro = child.start_byte();
                push_binding(out, name, intro, BindingKind::Param, scopes);
            }
            "optional_parameter"
            | "keyword_parameter"
            | "splat_parameter"
            | "block_parameter"
            | "hash_splat_parameter" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let name = node_text(&name_node, bytes).to_owned();
                    let intro = name_node.start_byte();
                    push_binding(out, name, intro, BindingKind::Param, scopes);
                }
                // Bare `*` (splat_parameter with no `name` field) and bare `**`
                // (hash_splat_parameter with no `name` field) have no binding.
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_nested_defs() {
        let src = r#"
module Auth
  class Session
    MAX = 3
    def validate(token)
      check(token)
    end
    def self.create
    end
  end
end

TOP = 1
def helper
end
"#;
        let facts = RubyExtractor.extract(src, "lib/auth/session.rb").unwrap();
        let by_name = |n: &str| facts.symbols.iter().find(|s| s.name == n).cloned();

        let auth = by_name("Auth").unwrap();
        assert_eq!(auth.kind, SymbolKind::Module);
        assert_eq!(
            auth.id.to_scip_string(),
            "codegraph . . . auth/session/Auth#"
        );

        let session = by_name("Session").unwrap();
        assert_eq!(session.kind, SymbolKind::Class);
        assert_eq!(
            session.id.to_scip_string(),
            "codegraph . . . auth/session/Auth#Session#"
        );

        let max = by_name("MAX").unwrap();
        assert_eq!(max.kind, SymbolKind::Const);
        assert_eq!(
            max.id.to_scip_string(),
            "codegraph . . . auth/session/Auth#Session#MAX."
        );

        let validate = by_name("validate").unwrap();
        assert_eq!(validate.kind, SymbolKind::Method);
        assert_eq!(
            validate.id.to_scip_string(),
            "codegraph . . . auth/session/Auth#Session#validate()."
        );

        let create = by_name("create").unwrap();
        assert_eq!(create.kind, SymbolKind::Method);
        assert_eq!(
            create.id.to_scip_string(),
            "codegraph . . . auth/session/Auth#Session#create()."
        );

        let top = by_name("TOP").unwrap();
        assert_eq!(top.kind, SymbolKind::Const);
        assert_eq!(top.id.to_scip_string(), "codegraph . . . auth/session/TOP.");

        let helper = by_name("helper").unwrap();
        assert_eq!(helper.kind, SymbolKind::Method);
        assert_eq!(
            helper.id.to_scip_string(),
            "codegraph . . . auth/session/helper()."
        );

        assert_eq!(facts.lang, "ruby");
    }

    #[test]
    fn emits_methods_regardless_of_visibility() {
        let src = r#"
class Svc
  def open
  end
  private
  def secret
  end
end
"#;
        let facts = RubyExtractor.extract(src, "lib/svc.rb").unwrap();
        let by_name = |n: &str| facts.symbols.iter().find(|s| s.name == n).cloned();

        let open_sym = by_name("open").unwrap();
        assert_eq!(open_sym.kind, SymbolKind::Method);

        let secret_sym = by_name("secret").unwrap();
        assert_eq!(secret_sym.kind, SymbolKind::Method);
    }

    #[test]
    fn extracts_call_references() {
        let src = r#"
def run
  validate("t")
  process(data)
end
"#;
        let facts = RubyExtractor.extract(src, "lib/main.rb").unwrap();
        let names: Vec<&str> = facts.references.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"validate"));
        assert!(names.contains(&"process"));
    }

    #[test]
    fn qualified_call_captures_receiver_as_qualifier() {
        // `Alpha.compute` is one call to `compute` qualified by its receiver
        // `Alpha` (a module), so the resolver can disambiguate it from a same-named
        // method in another module. A bare `helper()` carries no qualifier.
        let src = "def run\n  Alpha.compute\n  helper()\nend\n";
        let facts = RubyExtractor.extract(src, "lib/main.rb").unwrap();

        let compute = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Call && r.name == "compute")
            .expect("expected a Call ref for 'compute'");
        assert_eq!(
            compute.qualifier.as_deref(),
            Some("Alpha"),
            "`Alpha.compute` must be qualified by `Alpha`"
        );
        let helper = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Call && r.name == "helper")
            .expect("expected a Call ref for 'helper'");
        assert_eq!(
            helper.qualifier, None,
            "a bare `helper()` call must have no qualifier"
        );
    }

    #[test]
    fn extracts_simple_inheritance() {
        let src = "class Foo < Bar\nend\n";
        let facts = RubyExtractor.extract(src, "lib/foo.rb").unwrap();
        let inherit: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(inherit, vec!["Bar"], "expected [Bar], got {inherit:?}");
    }

    #[test]
    fn extracts_qualified_inheritance_simple_name() {
        let src = "class Foo < A::Bar\nend\n";
        let facts = RubyExtractor.extract(src, "lib/foo.rb").unwrap();
        let inherit: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(inherit, vec!["Bar"], "expected [Bar], got {inherit:?}");
    }

    #[test]
    fn module_emits_no_inheritance_refs() {
        let src = "module M\nend\n";
        let facts = RubyExtractor.extract(src, "lib/m.rb").unwrap();
        let inherit: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            inherit.is_empty(),
            "expected no Inherit refs, got {inherit:?}"
        );
    }

    // ── Tier-B scope / binding tests ─────────────────────────────────────────

    #[test]
    fn method_params_emit_param_bindings() {
        // `def greet(name, age)\nend` → Param `name`, `age` in a Function scope.
        let src = "def greet(name, age)\nend\n";
        let facts = RubyExtractor.extract(src, "lib/greet.rb").unwrap();

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
            "expected Param bindings for name and age, got {param_names:?}"
        );
    }

    #[test]
    fn optional_keyword_splat_block_params() {
        // `def f(a, b: 1, *c, &d)\nend` → Params a, b, c, d.
        let src = "def f(a, b: 1, *c, &d)\nend\n";
        let facts = RubyExtractor.extract(src, "lib/f.rb").unwrap();

        let params: Vec<&str> = facts
            .bindings
            .iter()
            .filter(|b| b.kind == BindingKind::Param)
            .map(|b| b.name.as_str())
            .collect();
        assert!(params.contains(&"a"), "expected Param 'a', got {params:?}");
        assert!(params.contains(&"b"), "expected Param 'b', got {params:?}");
        assert!(params.contains(&"c"), "expected Param 'c', got {params:?}");
        assert!(params.contains(&"d"), "expected Param 'd', got {params:?}");
    }

    #[test]
    fn assignment_local_in_method() {
        // `def f\n  x = 1\nend` → Local `x` in a Function scope.
        let src = "def f\n  x = 1\nend\n";
        let facts = RubyExtractor.extract(src, "lib/f.rb").unwrap();

        let x = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Local && b.name == "x")
            .expect("expected a Local binding for 'x'");
        assert_eq!(
            facts.scopes[x.scope].kind,
            ScopeKind::Function,
            "Local 'x' should be in a Function scope"
        );
    }

    #[test]
    fn block_params_emit_param_bindings() {
        // `[1].each { |item| }` → Param `item` in a Function scope.
        let src = "[1].each { |item| }\n";
        let facts = RubyExtractor.extract(src, "lib/blk.rb").unwrap();

        let _fn_scope = facts
            .scopes
            .iter()
            .find(|s| s.kind == ScopeKind::Function)
            .expect("expected a Function scope for the block");

        let item = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Param && b.name == "item")
            .expect("expected a Param binding for 'item'");
        assert_eq!(
            facts.scopes[item.scope].kind,
            ScopeKind::Function,
            "block param 'item' should be in a Function scope"
        );
    }

    #[test]
    fn class_level_constant_is_definition_not_local() {
        // `class Foo\n  BAR = 1\nend` → NO Local `BAR`; Definition `BAR` exists.
        let src = "class Foo\n  BAR = 1\nend\n";
        let facts = RubyExtractor.extract(src, "lib/foo.rb").unwrap();

        assert!(
            !facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Local && b.name == "BAR"),
            "class-level constant 'BAR' must NOT be a Local binding"
        );
        assert!(
            facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Definition && b.name == "BAR"),
            "expected a Definition binding for 'BAR'"
        );
    }

    #[test]
    fn ivar_assignment_is_not_local() {
        // `def f\n  @x = 1\nend` → NO Local binding for `@x`.
        // The LHS kind is `instance_variable`, not `identifier`.
        let src = "def f\n  @x = 1\nend\n";
        let facts = RubyExtractor.extract(src, "lib/f.rb").unwrap();

        assert!(
            !facts.bindings.iter().any(|b| b.kind == BindingKind::Local),
            "instance variable assignment must NOT produce a Local binding"
        );
    }

    #[test]
    fn nesting_class_method_produces_correct_scopes_and_local() {
        // `class S\n  def h\n    x = 1\n  end\nend`
        // → Module(0); Type scope (class, parent 0); Function scope (method, parent=Type);
        //   Local `x` in the Function scope.
        let src = "class S\n  def h\n    x = 1\n  end\nend\n";
        let facts = RubyExtractor.extract(src, "lib/s.rb").unwrap();

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
    fn same_file_call_ref_has_non_zero_scope() {
        // `def helper\n  0\nend\ndef run\n  helper()\nend`
        // → Definition `helper` exists AND the `helper` Call ref has scope == Some(non-zero).
        let src = "def helper\n  0\nend\ndef run\n  helper()\nend\n";
        let facts = RubyExtractor.extract(src, "lib/main.rb").unwrap();

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
    fn ruby_read_ref_at_use_not_declaration() {
        // `def f\n  base = 1\n  base\nend\n`
        // The `base = 1` LHS is a Write; the bare `base` expression is a Read.
        let src = "def f\n  base = 1\n  base\nend\n";
        let facts = RubyExtractor.extract(src, "lib/f.rb").unwrap();

        let read_refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Read && r.name == "base")
            .collect();
        assert!(
            !read_refs.is_empty(),
            "expected at least one Read ref for 'base'; refs: {:?}",
            facts
                .references
                .iter()
                .map(|r| (&r.name, r.role))
                .collect::<Vec<_>>()
        );
        // The bare `base` expression starts after the assignment line (byte > 15).
        let use_ref = read_refs
            .iter()
            .find(|r| r.occ.byte > 15)
            .expect("expected a Read ref for 'base' at the use site (byte > 15)");
        assert!(
            use_ref.occ.byte > 15,
            "Read ref should be at the use site, not the declaration"
        );
    }

    #[test]
    fn ruby_write_ref_for_assignment() {
        // `def f\n  cnt = 0\n  cnt = 5\nend\n` → at least one Write ref for "cnt".
        let src = "def f\n  cnt = 0\n  cnt = 5\nend\n";
        let facts = RubyExtractor.extract(src, "lib/f.rb").unwrap();

        let write_refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Write && r.name == "cnt")
            .collect();
        assert!(
            !write_refs.is_empty(),
            "expected at least one Write ref for 'cnt'; refs: {:?}",
            facts
                .references
                .iter()
                .map(|r| (&r.name, r.role))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn ruby_explicit_call_method_not_also_read() {
        // `def f\n  obj.helper\nend\n`
        // `helper` is the `method:` field of a `call` node → Call ref only, no Read.
        // `obj` is a bare identifier in value position → Read ref.
        let src = "def f\n  obj.helper\nend\n";
        let facts = RubyExtractor.extract(src, "lib/f.rb").unwrap();

        // `helper` must NOT appear as a Read ref (it's the call method name).
        let helper_reads: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Read && r.name == "helper")
            .collect();
        assert!(
            helper_reads.is_empty(),
            "call method name 'helper' must NOT be a Read ref; got: {helper_reads:?}"
        );

        // `obj` IS a bare identifier in value position → must be a Read.
        let obj_reads: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Read && r.name == "obj")
            .collect();
        assert!(
            !obj_reads.is_empty(),
            "receiver 'obj' should be a Read ref; refs: {:?}",
            facts
                .references
                .iter()
                .map(|r| (&r.name, r.role))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn ruby_ivar_not_a_local_read_or_write() {
        // `def f\n  @val = 1\nend\n`
        // The LHS is an `instance_variable` node, not `identifier` → no Read/Write
        // ref named "val" (and no ref named "@val" either).
        let src = "def f\n  @val = 1\nend\n";
        let facts = RubyExtractor.extract(src, "lib/f.rb").unwrap();

        let val_rw: Vec<_> = facts
            .references
            .iter()
            .filter(|r| {
                matches!(r.role, RefRole::Read | RefRole::Write)
                    && (r.name == "val" || r.name == "@val")
            })
            .collect();
        assert!(
            val_rw.is_empty(),
            "instance variable '@val' must NOT produce a Read/Write identifier ref; got: {val_rw:?}"
        );
    }
}
