// SPDX-License-Identifier: Apache-2.0

//! Solidity extractor — one tree-sitter pass yielding definitions and references.
//!
//! Definitions: declarations whose visibility is not `private`. Qualified
//! identity is derived from the file path (all directory segments kept, `.sol`
//! stripped from the last segment).
//!
//! Covered declaration kinds:
//! - `contract_declaration` → Class; `interface_declaration` → Interface;
//!   `library_declaration` → Class (Solidity libraries map naturally to class)
//! - `function_definition` (top-level → Function; inside contract → Method)
//! - `constructor_definition` (→ Method "constructor"; always emitted)
//! - `modifier_definition` (→ Method)
//! - `fallback_receive_definition` (→ Method "fallback"/"receive")
//! - `state_variable_declaration` (→ Static; `constant`/`immutable` → Const)
//! - `constant_variable_declaration` (file-level → Const)
//! - `event_definition` (→ Other)
//! - `error_declaration` (→ Other)
//! - `struct_declaration` (→ Struct; members → Static)
//! - `enum_declaration` (→ Enum; values → Const)
//! - `user_defined_type_definition` (`type X is Y`) → TypeAlias
//!
//! Skipped: `pragma_directive`, `import_directive`, `using_directive`.
//!
//! References: callee identifiers captured by two call patterns. The grammar's
//! `call_expression` wraps its callee in a visible `expression` node:
//! - free call `foo()` → `(call_expression (expression (identifier) @callee))`
//! - member call `x.foo()` → `(call_expression (expression (member_expression property: (identifier) @callee)))`
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
    Extractor, MIN_REF_LEN, attach_reference_scopes, collect_call_references, definition_bindings,
    field_text, import_bindings, innermost_scope, node_span, node_text, one_line_signature,
    push_binding, push_ref, push_scope,
};

/// Tree-sitter query capturing call-callee identifiers.
///
/// Pattern 1: free call `foo()` — identifier inside the call's `expression` child.
/// Pattern 2: member call `x.foo()` — member_expression's `property` field is the callee.
const CALL_QUERY: &str = r#"
[
  (call_expression (expression (identifier) @callee))
  (call_expression (expression (member_expression property: (identifier) @callee)))
]
"#;

/// Extracts Solidity symbols and references.
pub struct SolidityExtractor;

impl Extractor for SolidityExtractor {
    fn lang(&self) -> Language {
        Language::Solidity
    }

    fn extract(&self, source: &str, file: &str) -> Result<FileFacts> {
        let ts_language = TsLanguage::from(tree_sitter_solidity::LANGUAGE);
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

        let ns_strings = solidity_namespaces(file);
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
            Language::Solidity,
            &ns_strings,
            file,
            source.len(),
        ));

        let mut references = collect_call_references(
            &root,
            &ts_language,
            CALL_QUERY,
            Language::Solidity,
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
            lang: Language::Solidity.as_str().to_owned(),
            symbols,
            references,
            scopes,
            bindings,
            ffi_exports: Vec::new(),
        })
    }
}

// ── Namespace derivation ─────────────────────────────────────────────────────

/// Namespace descriptors derived purely from the file path.
///
/// Strip `.sol` from the last segment, split on `/`, filter empty segments —
/// all directory segments are kept (no `src/` stripping). For example,
/// `contracts/Token.sol` → `["contracts", "Token"]`.
fn solidity_namespaces(file: &str) -> Vec<String> {
    let p = file.strip_suffix(".sol").unwrap_or(file);
    p.split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

// ── Visibility gate ──────────────────────────────────────────────────────────

/// Returns `true` if a declaration should be emitted (not `private`).
///
/// Scans direct children for a node of kind `visibility`. If that node's text
/// is `"private"` the declaration is suppressed; any other value (public,
/// external, internal) or the absence of a visibility node → emit.
/// Recall-first — only `private` is filtered.
fn is_visible(node: &Node, bytes: &[u8]) -> bool {
    for child in node.children(&mut node.walk()) {
        if child.kind() == "visibility" {
            return node_text(&child, bytes) != "private";
        }
    }
    // No visibility child → default visibility → emit.
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
        id: SymbolId::global(Language::Solidity.as_str(), descriptors),
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

/// Emit a container (contract/interface/library) Type symbol and recurse into its body.
fn emit_container_and_body(
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

    // Recurse into `contract_body` (field "body").
    if let Some(body) = node.child_by_field_name("body") {
        collect_decls(body, &type_descriptors, true, bytes, file, out);
    }
}

// ── Declaration collection ───────────────────────────────────────────────────

/// Collect definitions from a container node (source_file or contract_body).
///
/// `prefix` is the descriptor list up to (but not including) the current level.
/// `inside_type` is true when we are inside a contract/interface/library body,
/// which drives `function_definition` → Method vs. Function.
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
            "contract_declaration" | "library_declaration" => {
                handle_container(child, SymbolKind::Class, prefix, bytes, file, out);
            }
            "interface_declaration" => {
                handle_container(child, SymbolKind::Interface, prefix, bytes, file, out);
            }
            "function_definition" => {
                handle_function(child, prefix, inside_type, bytes, file, out);
            }
            "constructor_definition" => {
                handle_constructor(child, prefix, bytes, file, out);
            }
            "modifier_definition" => {
                handle_modifier(child, prefix, bytes, file, out);
            }
            "fallback_receive_definition" => {
                handle_fallback_receive(child, prefix, bytes, file, out);
            }
            "state_variable_declaration" => {
                handle_state_variable(child, prefix, bytes, file, out);
            }
            "constant_variable_declaration" => {
                handle_constant_variable(child, prefix, bytes, file, out);
            }
            "event_definition" | "error_declaration" => {
                handle_event_or_error(child, prefix, bytes, file, out);
            }
            "struct_declaration" => {
                handle_struct(child, prefix, bytes, file, out);
            }
            "enum_declaration" => {
                handle_enum(child, prefix, bytes, file, out);
            }
            "user_defined_type_definition" => {
                handle_typedef(child, prefix, bytes, file, out);
            }
            // pragma_directive, import_directive, using_directive → skip
            _ => {}
        }
    }
}

/// Handle `contract_declaration`, `interface_declaration`, `library_declaration`.
fn handle_container(
    node: Node,
    kind: SymbolKind,
    prefix: &[Descriptor],
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    // Containers have no visibility keyword themselves, but be defensive.
    let type_name = match field_text(&node, "name", bytes) {
        Some(n) => n,
        None => return,
    };
    emit_container_and_body(out, node, type_name, kind, prefix, bytes, file);
}

/// Handle `function_definition`.
///
/// `inside_type` → SymbolKind::Method with Descriptor::Method; otherwise
/// SymbolKind::Function with Descriptor::Method (Solidity free functions are
/// still callable, so Method descriptor is correct).
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

/// Handle `constructor_definition` (no name field → always "constructor").
fn handle_constructor(
    node: Node,
    prefix: &[Descriptor],
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    // Constructors are always emitted; no visibility gate.
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

/// Handle `modifier_definition`.
fn handle_modifier(
    node: Node,
    prefix: &[Descriptor],
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    let name = match field_text(&node, "name", bytes) {
        Some(n) => n,
        None => return,
    };
    let mut descriptors = prefix.to_vec();
    descriptors.push(Descriptor::Method {
        name: name.clone(),
        disambiguator: String::new(),
    });
    push_symbol(
        out,
        &node,
        name,
        SymbolKind::Method,
        descriptors,
        bytes,
        file,
    );
}

/// Handle `fallback_receive_definition`.
///
/// There is no name field; the leading keyword in the raw text determines the
/// name: starts with "fallback" → "fallback", "receive" → "receive".
/// If neither can be determined the node is skipped.
fn handle_fallback_receive(
    node: Node,
    prefix: &[Descriptor],
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    let text = node_text(&node, bytes).trim_start();
    let name = if text.starts_with("fallback") {
        "fallback"
    } else if text.starts_with("receive") {
        "receive"
    } else {
        return;
    };
    let mut descriptors = prefix.to_vec();
    descriptors.push(Descriptor::Method {
        name: name.to_owned(),
        disambiguator: String::new(),
    });
    push_symbol(
        out,
        &node,
        name.to_owned(),
        SymbolKind::Method,
        descriptors,
        bytes,
        file,
    );
}

/// Handle `state_variable_declaration`.
///
/// Visibility is the named field `visibility`. If its text is `"private"`, skip.
/// Kind: Const if node has an `immutable` child or the text contains the word
/// `constant`; otherwise Static.
fn handle_state_variable(
    node: Node,
    prefix: &[Descriptor],
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    // Visibility gate: use the named field `visibility` on this node type.
    if let Some(vis) = node.child_by_field_name("visibility") {
        if node_text(&vis, bytes) == "private" {
            return;
        }
    }

    let name = match field_text(&node, "name", bytes) {
        Some(n) => n,
        None => return,
    };

    // Determine kind: immutable child present, or text contains "constant".
    let has_immutable = node
        .children(&mut node.walk())
        .any(|c| c.kind() == "immutable");
    let text = node_text(&node, bytes);
    let is_constant = has_immutable || text.split_whitespace().any(|w| w == "constant");

    let kind = if is_constant {
        SymbolKind::Const
    } else {
        SymbolKind::Static
    };

    let mut descriptors = prefix.to_vec();
    descriptors.push(Descriptor::Term(name.clone()));
    push_symbol(out, &node, name, kind, descriptors, bytes, file);
}

/// Handle `constant_variable_declaration` (file-level `uint constant X = 1;`).
fn handle_constant_variable(
    node: Node,
    prefix: &[Descriptor],
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    let name = match field_text(&node, "name", bytes) {
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

/// Handle `event_definition` and `error_declaration` (both → Term / Other).
fn handle_event_or_error(
    node: Node,
    prefix: &[Descriptor],
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    let name = match field_text(&node, "name", bytes) {
        Some(n) => n,
        None => return,
    };
    let mut descriptors = prefix.to_vec();
    descriptors.push(Descriptor::Term(name.clone()));
    push_symbol(
        out,
        &node,
        name,
        SymbolKind::Other,
        descriptors,
        bytes,
        file,
    );
}

/// Handle `struct_declaration`.
///
/// Emits a Struct Type symbol, then descends into `struct_body` to emit each
/// `struct_member` as a Term/Static nested under the struct.
fn handle_struct(
    node: Node,
    prefix: &[Descriptor],
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    let type_name = match field_text(&node, "name", bytes) {
        Some(n) => n,
        None => return,
    };

    let mut type_descriptors = prefix.to_vec();
    type_descriptors.push(Descriptor::Type(type_name.clone()));
    push_symbol(
        out,
        &node,
        type_name,
        SymbolKind::Struct,
        type_descriptors.clone(),
        bytes,
        file,
    );

    // Descend into struct_body for members.
    let body = match node.child_by_field_name("body") {
        Some(b) => b,
        None => return,
    };
    let mut cursor = body.walk();
    for member in body.children(&mut cursor) {
        if member.kind() != "struct_member" {
            continue;
        }
        let member_name = match field_text(&member, "name", bytes) {
            Some(n) => n,
            None => continue,
        };
        let mut member_descriptors = type_descriptors.clone();
        member_descriptors.push(Descriptor::Term(member_name.clone()));
        push_symbol(
            out,
            &member,
            member_name,
            SymbolKind::Static,
            member_descriptors,
            bytes,
            file,
        );
    }
}

/// Handle `enum_declaration`.
///
/// Emits an Enum Type symbol, then descends into `enum_body` to emit each
/// `enum_value` as a Term/Const nested under the enum.
fn handle_enum(node: Node, prefix: &[Descriptor], bytes: &[u8], file: &str, out: &mut Vec<Symbol>) {
    let type_name = match field_text(&node, "name", bytes) {
        Some(n) => n,
        None => return,
    };

    let mut type_descriptors = prefix.to_vec();
    type_descriptors.push(Descriptor::Type(type_name.clone()));
    push_symbol(
        out,
        &node,
        type_name,
        SymbolKind::Enum,
        type_descriptors.clone(),
        bytes,
        file,
    );

    // Descend into enum_body for values.
    let body = match node.child_by_field_name("body") {
        Some(b) => b,
        None => return,
    };
    let mut cursor = body.walk();
    for value_node in body.children(&mut cursor) {
        if value_node.kind() != "enum_value" {
            continue;
        }
        // enum_value is a leaf named node; its text is the case name.
        let value_name = node_text(&value_node, bytes).to_owned();
        if value_name.is_empty() {
            continue;
        }
        let mut value_descriptors = type_descriptors.clone();
        value_descriptors.push(Descriptor::Term(value_name.clone()));
        push_symbol(
            out,
            &value_node,
            value_name,
            SymbolKind::Const,
            value_descriptors,
            bytes,
            file,
        );
    }
}

/// Handle `user_defined_type_definition` (`type X is uint;`).
fn handle_typedef(
    node: Node,
    prefix: &[Descriptor],
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    let name = match field_text(&node, "name", bytes) {
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

// ── Scope tree (Tier-B) ─────────────────────────────────────────────────────

/// Build the lexical scope tree for one Solidity file.
///
/// `scopes[0]` is always the file-root `Module` scope spanning `[0, source_len)`.
/// Solidity opens `Type` scopes for contract/library/interface bodies, `Function`
/// scopes for function/modifier/constructor/fallback-receive definitions, and
/// `Block` scopes for bare `block_statement` nodes not consumed as a function body.
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

/// DFS opening scopes for the Solidity AST.
///
/// - `contract_declaration` | `library_declaration` | `interface_declaration` →
///   `ScopeKind::Type`; the `contract_body` field is peeled under the Type scope.
/// - `function_definition` | `modifier_definition` | `constructor_definition` |
///   `fallback_receive_definition` → `ScopeKind::Function`; the `body` field
///   (a `function_body`, may be absent for abstract/interface functions) is peeled.
/// - `block_statement` not already consumed as a function body → `ScopeKind::Block`.
/// - Everything else: recurse under `parent`.
fn scope_dfs(node: &Node, parent_id: ScopeId, scopes: &mut Vec<Scope>) {
    match node.kind() {
        "contract_declaration" | "library_declaration" | "interface_declaration" => {
            let type_id = push_scope(scopes, Some(parent_id), node_span(node), ScopeKind::Type);
            // Peel the contract_body to avoid wrapping its own scope.
            if let Some(body) = node.child_by_field_name("body") {
                for child in body.children(&mut body.walk()) {
                    scope_dfs(&child, type_id, scopes);
                }
            }
        }
        "function_definition"
        | "modifier_definition"
        | "constructor_definition"
        | "fallback_receive_definition" => {
            let fn_id = push_scope(
                scopes,
                Some(parent_id),
                node_span(node),
                ScopeKind::Function,
            );
            // Peel the body (a `function_body`) if present; absent for abstract/interface fns.
            if let Some(body) = node.child_by_field_name("body") {
                for child in body.children(&mut body.walk()) {
                    scope_dfs(&child, fn_id, scopes);
                }
            }
        }
        "block_statement" => {
            // A bare block NOT already consumed as a function body.
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

/// Collect parameter and local-variable [`Binding`]s for one Solidity file.
///
/// Covers:
/// - `function_definition` / `modifier_definition` / `constructor_definition` /
///   `fallback_receive_definition` parameters → [`BindingKind::Param`].
/// - `variable_declaration` inside a `Function` or `Block` scope →
///   [`BindingKind::Local`]. This covers both `variable_declaration_statement`
///   children and tuple destructuring children. The Function|Block scope guard
///   excludes state variables at contract-body (Type) scope.
/// - `variable_declaration_tuple` bare `identifier` children (tuple LHS names
///   like `(a, b) = ...`) → [`BindingKind::Local`] with the same guard.
fn collect_bindings(root: &Node, bytes: &[u8], scopes: &[Scope]) -> Vec<Binding> {
    let mut out = Vec::new();
    collect_bindings_dfs(root, bytes, scopes, &mut out);
    out
}

fn collect_bindings_dfs(node: &Node, bytes: &[u8], scopes: &[Scope], out: &mut Vec<Binding>) {
    match node.kind() {
        "function_definition"
        | "modifier_definition"
        | "constructor_definition"
        | "fallback_receive_definition" => {
            // Parameters: direct children of kind "parameter" with a "name" field.
            for child in node.children(&mut node.walk()) {
                if child.kind() == "parameter" {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        let name = node_text(&name_node, bytes).to_owned();
                        if !name.is_empty() {
                            push_binding(
                                out,
                                name,
                                name_node.start_byte(),
                                BindingKind::Param,
                                scopes,
                            );
                        }
                    }
                }
            }
            // Recurse into all children to pick up body bindings.
            for child in node.children(&mut node.walk()) {
                collect_bindings_dfs(&child, bytes, scopes, out);
            }
        }
        "variable_declaration" => {
            // Emit Local only when the innermost scope is Function or Block.
            // State variables at contract-body (Type) scope are excluded.
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = node_text(&name_node, bytes).to_owned();
                if !name.is_empty() {
                    let intro = name_node.start_byte();
                    if let Some(sid) = innermost_scope(intro, scopes) {
                        if matches!(scopes[sid].kind, ScopeKind::Function | ScopeKind::Block) {
                            push_binding(out, name, intro, BindingKind::Local, scopes);
                        }
                    }
                }
            }
            // Recurse into children (initializer may contain nested constructs).
            for child in node.children(&mut node.walk()) {
                collect_bindings_dfs(&child, bytes, scopes, out);
            }
        }
        "variable_declaration_tuple" => {
            // Tuple destructuring: `(a, b) = expr` — emit Local for each bare identifier.
            for child in node.children(&mut node.walk()) {
                if child.kind() == "identifier" {
                    let name = node_text(&child, bytes).to_owned();
                    if !name.is_empty() {
                        let intro = child.start_byte();
                        if let Some(sid) = innermost_scope(intro, scopes) {
                            if matches!(scopes[sid].kind, ScopeKind::Function | ScopeKind::Block) {
                                push_binding(out, name, intro, BindingKind::Local, scopes);
                            }
                        }
                    }
                } else {
                    collect_bindings_dfs(&child, bytes, scopes, out);
                }
            }
        }
        _ => {
            for child in node.children(&mut node.walk()) {
                collect_bindings_dfs(&child, bytes, scopes, out);
            }
        }
    }
}

// ── Import-edge helpers ──────────────────────────────────────────────────────

/// Recursively walk `node` collecting `Import` references for every
/// `import_directive` in the tree.
///
/// Only named imports are emitted: `import {Foo, Bar} from "./x.sol"` yields
/// two refs (`Foo`, `Bar`). Whole-file imports (`import "./lib.sol"`) and
/// aliased imports (`import {Foo as F}` — the alias `F` is ignored, `Foo` is
/// emitted) are handled correctly. The `source` field (the path string) is
/// intentionally ignored — resolution is by leaf name, not file path.
fn collect_imports(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    if node.kind() == "import_directive" {
        let mut cursor = node.walk();
        for import_name_node in node.children_by_field_name("import_name", &mut cursor) {
            let name = super::node_text(&import_name_node, bytes);
            super::push_ref(out, name, &import_name_node, file, RefRole::Import);
        }
    }

    // Recurse into all children so directives nested inside any structure are covered.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_imports(&child, bytes, file, out);
    }
}

// ── Inheritance-edge helpers ─────────────────────────────────────────────────

/// Recursively walk `node` collecting `Inherit` references for every
/// `contract_declaration` and `interface_declaration` in the tree.
fn collect_inheritance(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    match node.kind() {
        "contract_declaration" | "interface_declaration" => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "inheritance_specifier" {
                    if let Some(ancestor) = child.child_by_field_name("ancestor") {
                        super::push_ref(
                            out,
                            super::simple_type_name(node_text(&ancestor, bytes), "."),
                            &ancestor,
                            file,
                            RefRole::IsImplementation,
                        );
                    }
                }
            }
        }
        _ => {}
    }

    // Recurse into all children so nested contracts/interfaces are covered.
    for child in node.children(&mut node.walk()) {
        collect_inheritance(&child, bytes, file, out);
    }
}

// ── Edge richness: Read / Write ──────────────────────────────────────────────

/// Returns `true` when `node` (an `identifier`) is in a Solidity position that
/// is already captured by another collector and must NOT also be emitted as a
/// Read reference.
///
/// Skipped positions:
/// - Call callee: in the Solidity grammar a free call `foo()` is
///   `(call_expression (expression (identifier)))` — the identifier's parent is
///   the anonymous `expression` wrapper whose parent is `call_expression` with
///   `function:` field pointing at that `expression`. These identifiers are
///   already captured as [`RefRole::Call`] by the CALL_QUERY.
/// - Member property: `x.foo` — the `property:` field of `member_expression`.
///   Only the object base (`x`) is a read; the property name is not an
///   independent identifier read.
/// - Declaration names: `function_definition` / `modifier_definition` /
///   `event_definition` / `struct_declaration` / `state_variable_declaration` /
///   `constant_variable_declaration` / `constructor_definition` /
///   `error_declaration` / `user_defined_type_definition` `name:` field.
/// - Local variable declaration: `variable_declaration` `name:` field.
/// - Parameter name: `parameter` `name:` field.
/// - Type-position identifiers: children of `user_defined_type` (type
///   references like `MyContract`, `IERC20`) and `type_name` `key_identifier` /
///   `value_identifier` fields (mapping key/value types).
/// - Import bindings: children of `import_directive` (already
///   [`RefRole::Import`]).
/// - Inheritance specifiers: children of `inheritance_specifier` (already
///   [`RefRole::IsImplementation`]).
/// - Assignment LHS: `left:` field of `assignment_expression` /
///   `augmented_assignment_expression` — handled by
///   [`collect_write_references`].
fn is_non_read_position(node: &Node) -> bool {
    let parent = match node.parent() {
        Some(p) => p,
        None => return true, // root — not a read
    };
    match parent.kind() {
        // Solidity wraps many expression positions in an `expression` node.
        // Check the grandparent context to decide whether to skip.
        "expression" => {
            if let Some(grandparent) = parent.parent() {
                match grandparent.kind() {
                    // Call callee: `foo()` →
                    // (call_expression function: (expression (identifier)))
                    "call_expression" => {
                        if let Some(fn_field) = grandparent.child_by_field_name("function") {
                            if fn_field == parent {
                                return true; // skip — already a Call ref
                            }
                        }
                    }
                    // Assignment LHS: `x = 5` / `x += 1` →
                    // (assignment_expression left: (expression (identifier)) …)
                    "assignment_expression" | "augmented_assignment_expression" => {
                        if let Some(left_field) = grandparent.child_by_field_name("left") {
                            if left_field == parent {
                                return true; // skip — handled by collect_write_references
                            }
                        }
                    }
                    _ => {}
                }
            }
            false
        }
        // Member property: `x.foo` — property field of member_expression.
        // Only skip the property identifier (the object base IS a read).
        "member_expression" => parent.child_by_field_name("property").as_ref() == Some(node),
        // Declaration names — the identifier is being introduced, not read.
        "function_definition"
        | "modifier_definition"
        | "event_definition"
        | "struct_declaration"
        | "state_variable_declaration"
        | "constant_variable_declaration"
        | "constructor_definition"
        | "error_declaration"
        | "user_defined_type_definition"
        | "enum_declaration" => parent.child_by_field_name("name").as_ref() == Some(node),
        // Local variable declaration name.
        "variable_declaration" => parent.child_by_field_name("name").as_ref() == Some(node),
        // Parameter binding name.
        "parameter" => parent.child_by_field_name("name").as_ref() == Some(node),
        // Type-position: user_defined_type children (e.g. `MyContract`,
        // `IERC20`) are type references, not value reads.
        "user_defined_type" => true,
        // type_name key_identifier / value_identifier fields (mapping types).
        "type_name" => {
            let is_key = parent.child_by_field_name("key_identifier").as_ref() == Some(node);
            let is_val = parent.child_by_field_name("value_identifier").as_ref() == Some(node);
            is_key || is_val
        }
        // Import directives — already RefRole::Import.
        "import_directive" => true,
        // Inheritance specifiers — already RefRole::IsImplementation.
        // (identifiers inside user_defined_type inside inheritance_specifier are
        // caught by the `user_defined_type` arm above)
        "inheritance_specifier" => true,
        // struct_field_assignment key (named initializer `{field: val}`) —
        // the field name is a struct member, not a local read.
        "struct_field_assignment" => parent.child_by_field_name("name").as_ref() == Some(node),
        _ => false,
    }
}

/// Recursively walk `node` and emit [`RefRole::Read`] references for bare
/// `identifier` nodes used in value/expression positions.
///
/// Skips identifiers that are:
/// - Call callees (already [`RefRole::Call`] via the CALL_QUERY)
/// - Member property names in `member_expression` (the object base IS a read)
/// - Declaration names (function / modifier / event / struct / state-variable /
///   local variable / parameter `name:` fields)
/// - Type-position identifiers inside `user_defined_type` or `type_name`
///   mapping fields
/// - Import binding names (already [`RefRole::Import`])
/// - Assignment LHS (handled by [`collect_write_references`])
///
/// Applies [`MIN_REF_LEN`] (same threshold as call references).
fn collect_read_references(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    if node.kind() == "identifier" {
        let name = node_text(node, bytes);
        if name.len() >= MIN_REF_LEN && !is_non_read_position(node) {
            push_ref(out, name, node, file, RefRole::Read);
        }
        // `identifier` nodes have no meaningful children; return early.
        return;
    }
    for child in node.children(&mut node.walk()) {
        collect_read_references(&child, bytes, file, out);
    }
}

/// Recursively walk `node` and emit [`RefRole::Write`] references for the
/// bare-identifier LHS of `assignment_expression` and
/// `augmented_assignment_expression` nodes (e.g. `x = 5`, `x += 1`).
///
/// Member / index LHS (`obj.prop = …`, `arr[i] = …`) are not covered in v1 —
/// only bare `identifier` nodes at the LHS. Applies [`MIN_REF_LEN`].
///
/// Note: `variable_declaration_statement` (`uint x = 5;`) is a definition, not
/// an assignment — it is correctly excluded. Only `assignment_expression` /
/// `augmented_assignment_expression` are handled here.
fn collect_write_references(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    if matches!(
        node.kind(),
        "assignment_expression" | "augmented_assignment_expression"
    ) {
        if let Some(lhs) = node.child_by_field_name("left") {
            // The LHS is an `expression` wrapper in the Solidity grammar; peel it.
            let bare = if lhs.kind() == "expression" {
                // Single named child of the expression wrapper.
                lhs.named_children(&mut lhs.walk()).next()
            } else {
                Some(lhs)
            };
            if let Some(bare_node) = bare {
                if bare_node.kind() == "identifier" {
                    let name = node_text(&bare_node, bytes);
                    if name.len() >= MIN_REF_LEN {
                        push_ref(out, name, &bare_node, file, RefRole::Write);
                    }
                }
            }
        }
    }
    for child in node.children(&mut node.walk()) {
        collect_write_references(&child, bytes, file, out);
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn extract(src: &str, path: &str) -> FileFacts {
        SolidityExtractor.extract(src, path).unwrap()
    }

    fn by_name(facts: &FileFacts, name: &str) -> Option<Symbol> {
        facts.symbols.iter().find(|s| s.name == name).cloned()
    }

    // Test 1: contract with public function and private function → visibility gate.
    #[test]
    fn contract_visibility_gate() {
        let src = r#"
pragma solidity ^0.8.0;
contract Token {
    function mint(address to) public {}
    function _secret() private {}
}
"#;
        let facts = extract(src, "contracts/Token.sol");

        let token = by_name(&facts, "Token").unwrap();
        assert_eq!(token.kind, SymbolKind::Class);
        assert_eq!(
            token.id.to_scip_string(),
            "codegraph . . . contracts/Token/Token#"
        );

        let mint = by_name(&facts, "mint").unwrap();
        assert_eq!(mint.kind, SymbolKind::Method);
        assert_eq!(
            mint.id.to_scip_string(),
            "codegraph . . . contracts/Token/Token#mint()."
        );

        // private function must NOT be emitted
        assert!(by_name(&facts, "_secret").is_none());
    }

    // Test 2: interface → SymbolKind::Interface; library → SymbolKind::Class.
    #[test]
    fn interface_and_library_kinds() {
        let src = r#"
pragma solidity ^0.8.0;
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}
library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256) { return a + b; }
}
"#;
        let facts = extract(src, "contracts/Defs.sol");

        let iface = by_name(&facts, "IERC20").unwrap();
        assert_eq!(iface.kind, SymbolKind::Interface);
        assert_eq!(
            iface.id.to_scip_string(),
            "codegraph . . . contracts/Defs/IERC20#"
        );

        let lib = by_name(&facts, "SafeMath").unwrap();
        assert_eq!(lib.kind, SymbolKind::Class);
        assert_eq!(
            lib.id.to_scip_string(),
            "codegraph . . . contracts/Defs/SafeMath#"
        );
    }

    // Test 3: state variable (public) → Static; `constant` → Const.
    #[test]
    fn state_variable_kinds() {
        let src = r#"
pragma solidity ^0.8.0;
contract Store {
    uint256 public totalSupply;
    uint256 public constant MAX_SUPPLY = 1000;
}
"#;
        let facts = extract(src, "src/Store.sol");

        let total = by_name(&facts, "totalSupply").unwrap();
        assert_eq!(total.kind, SymbolKind::Static);
        assert_eq!(
            total.id.to_scip_string(),
            "codegraph . . . src/Store/Store#totalSupply."
        );

        let max = by_name(&facts, "MAX_SUPPLY").unwrap();
        assert_eq!(max.kind, SymbolKind::Const);
        assert_eq!(
            max.id.to_scip_string(),
            "codegraph . . . src/Store/Store#MAX_SUPPLY."
        );
    }

    // Test 3b: file-level constant_variable_declaration → Const.
    #[test]
    fn file_level_constant() {
        let src = r#"
pragma solidity ^0.8.0;
uint256 constant VERSION = 1;
"#;
        let facts = extract(src, "contracts/Const.sol");

        let ver = by_name(&facts, "VERSION").unwrap();
        assert_eq!(ver.kind, SymbolKind::Const);
        assert_eq!(
            ver.id.to_scip_string(),
            "codegraph . . . contracts/Const/VERSION."
        );
    }

    // Test 4: struct with members → Struct Type + Static members;
    //         enum with values → Enum Type + Const values.
    #[test]
    fn struct_and_enum() {
        let src = r#"
pragma solidity ^0.8.0;
contract Market {
    struct Item {
        uint256 price;
        address seller;
    }
    enum Status { Active, Sold, Cancelled }
}
"#;
        let facts = extract(src, "contracts/Market.sol");

        let item = by_name(&facts, "Item").unwrap();
        assert_eq!(item.kind, SymbolKind::Struct);
        assert_eq!(
            item.id.to_scip_string(),
            "codegraph . . . contracts/Market/Market#Item#"
        );

        let price = by_name(&facts, "price").unwrap();
        assert_eq!(price.kind, SymbolKind::Static);
        assert_eq!(
            price.id.to_scip_string(),
            "codegraph . . . contracts/Market/Market#Item#price."
        );

        let seller = by_name(&facts, "seller").unwrap();
        assert_eq!(seller.kind, SymbolKind::Static);

        let status = by_name(&facts, "Status").unwrap();
        assert_eq!(status.kind, SymbolKind::Enum);
        assert_eq!(
            status.id.to_scip_string(),
            "codegraph . . . contracts/Market/Market#Status#"
        );

        let active = by_name(&facts, "Active").unwrap();
        assert_eq!(active.kind, SymbolKind::Const);
        assert_eq!(
            active.id.to_scip_string(),
            "codegraph . . . contracts/Market/Market#Status#Active."
        );
    }

    // Test 5: event → Other; modifier → Method.
    #[test]
    fn event_and_modifier() {
        let src = r#"
pragma solidity ^0.8.0;
contract Vault {
    event Deposit(address indexed sender, uint256 amount);
    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }
    address owner;
}
"#;
        let facts = extract(src, "contracts/Vault.sol");

        let ev = by_name(&facts, "Deposit").unwrap();
        assert_eq!(ev.kind, SymbolKind::Other);
        assert_eq!(
            ev.id.to_scip_string(),
            "codegraph . . . contracts/Vault/Vault#Deposit."
        );

        let modifier = by_name(&facts, "onlyOwner").unwrap();
        assert_eq!(modifier.kind, SymbolKind::Method);
        assert_eq!(
            modifier.id.to_scip_string(),
            "codegraph . . . contracts/Vault/Vault#onlyOwner()."
        );
    }

    // Test 6: free function at file level (no contract) → Function under namespace.
    #[test]
    fn free_function_top_level() {
        let src = r#"
pragma solidity ^0.8.0;
function computeHash(bytes memory data) pure returns (bytes32) {
    return keccak256(data);
}
"#;
        let facts = extract(src, "lib/Utils.sol");

        let func = by_name(&facts, "computeHash").unwrap();
        assert_eq!(func.kind, SymbolKind::Function);
        assert_eq!(
            func.id.to_scip_string(),
            "codegraph . . . lib/Utils/computeHash()."
        );
    }

    // Test 7: call references captured (free call + member call).
    #[test]
    fn call_references_captured() {
        let src = r#"
pragma solidity ^0.8.0;
contract Caller {
    function run() public {
        foo();
        x.bar();
    }
}
"#;
        let facts = extract(src, "contracts/Caller.sol");
        let names: Vec<&str> = facts.references.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"foo"), "expected 'foo' in {names:?}");
        assert!(names.contains(&"bar"), "expected 'bar' in {names:?}");
    }

    #[test]
    fn lang_tag() {
        let facts = extract("pragma solidity ^0.8.0;", "contracts/Foo.sol");
        assert_eq!(facts.lang, "solidity");
    }

    // Test: contract with multiple bases → two Inherit refs.
    #[test]
    fn contract_multiple_inheritance() {
        let src = "pragma solidity ^0.8.0; contract Foo is Bar, Baz {}";
        let facts = extract(src, "contracts/Foo.sol");

        let inherit: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();
        assert!(inherit.contains(&"Bar"), "expected 'Bar' in {inherit:?}");
        assert!(inherit.contains(&"Baz"), "expected 'Baz' in {inherit:?}");
    }

    // Test: interface extending another → one Inherit ref.
    #[test]
    fn interface_inheritance() {
        let src = "pragma solidity ^0.8.0; interface I is J {}";
        let facts = extract(src, "contracts/I.sol");

        let inherit: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();
        assert!(inherit.contains(&"J"), "expected 'J' in {inherit:?}");
    }

    // Test: dotted library type in is-clause → leaf name only.
    #[test]
    fn dotted_parent_simple_name() {
        let src = "pragma solidity ^0.8.0; contract C is Lib.Base {}";
        let facts = extract(src, "contracts/C.sol");

        let inherit: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            inherit.contains(&"Base"),
            "expected 'Base' (leaf of 'Lib.Base') in {inherit:?}"
        );
        assert!(
            !inherit.contains(&"Lib.Base"),
            "dotted form must not appear in {inherit:?}"
        );
    }

    // Test: single named import → one Import ref.
    #[test]
    fn import_single_named() {
        let src = r#"pragma solidity ^0.8.0; import {ERC20} from "./ERC20.sol";"#;
        let facts = extract(src, "contracts/Token.sol");

        let imports: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(
            imports,
            vec!["ERC20"],
            "expected [\"ERC20\"] but got {imports:?}"
        );
    }

    // Test: multiple named imports → one Import ref per name.
    #[test]
    fn import_multiple_named() {
        let src = r#"pragma solidity ^0.8.0; import {A, B} from "x.sol";"#;
        let facts = extract(src, "contracts/Multi.sol");

        let imports: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert!(imports.contains(&"A"), "expected 'A' in {imports:?}");
        assert!(imports.contains(&"B"), "expected 'B' in {imports:?}");
        assert_eq!(
            imports.len(),
            2,
            "expected exactly 2 import refs, got {imports:?}"
        );
    }

    // Test: aliased import → emit the original name, not the alias.
    #[test]
    fn import_aliased_emits_original_name() {
        let src = r#"pragma solidity ^0.8.0; import {Foo as F} from "x.sol";"#;
        let facts = extract(src, "contracts/Alias.sol");

        let imports: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert!(imports.contains(&"Foo"), "expected 'Foo' in {imports:?}");
        assert!(
            !imports.contains(&"F"),
            "alias 'F' must not appear in {imports:?}"
        );
    }

    // Test: whole-file import (no import_name field) → no Import refs.
    #[test]
    fn import_whole_file_emits_nothing() {
        let src = r#"pragma solidity ^0.8.0; import "./lib.sol";"#;
        let facts = extract(src, "contracts/WF.sol");

        let imports: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            imports.is_empty(),
            "expected no import refs but got {imports:?}"
        );
    }

    // ── Tier-B scope / binding tests ─────────────────────────────────────────

    #[test]
    fn params_emit_param_bindings() {
        // `contract C { function add(uint256 a, uint256 b) public {} }` → Param `a`, `b` in Function scope.
        let src = "contract C { function add(uint256 a, uint256 b) public {} }";
        let facts = extract(src, "contracts/C.sol");

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
    fn unnamed_param_skipped() {
        // `contract C { function f(uint256) public {} }` → zero Param bindings.
        let src = "contract C { function f(uint256) public {} }";
        let facts = extract(src, "contracts/C.sol");

        let params: Vec<&str> = facts
            .bindings
            .iter()
            .filter(|b| b.kind == BindingKind::Param)
            .map(|b| b.name.as_str())
            .collect();
        assert!(
            params.is_empty(),
            "unnamed param must not produce a Param binding, got {params:?}"
        );
    }

    #[test]
    fn modifier_params_emit_param_bindings() {
        // `contract C { modifier onlyRole(bytes32 role) { _; } }` → Param `role`.
        let src = "contract C { modifier onlyRole(bytes32 role) { _; } }";
        let facts = extract(src, "contracts/C.sol");

        let role = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Param && b.name == "role")
            .expect("expected Param binding for 'role'");
        assert_eq!(
            facts.scopes[role.scope].kind,
            ScopeKind::Function,
            "modifier param 'role' should be in a Function scope"
        );
    }

    #[test]
    fn local_var_emits_local_binding() {
        // `contract C { function f() public { uint256 x = 0; } }` → Local `x`.
        let src = "contract C { function f() public { uint256 x = 0; } }";
        let facts = extract(src, "contracts/C.sol");

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
    fn for_init_var_emits_local_binding() {
        // `contract C { function f(uint256[] memory xs) public { for (uint256 i = 0; ...) {} } }`
        // → Local `i`.
        let src = "contract C { function f(uint256[] memory xs) public { for (uint256 i = 0; i < xs.length; i++) {} } }";
        let facts = extract(src, "contracts/C.sol");

        let i_binding = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Local && b.name == "i")
            .expect("expected a Local binding for 'i'");
        assert_ne!(i_binding.scope, 0, "for-init 'i' must NOT be in scope 0");
    }

    #[test]
    fn state_var_not_local_but_is_definition() {
        // `contract C { uint256 public totalSupply; }` → NO Local `totalSupply`; Definition exists.
        let src = "contract C { uint256 public totalSupply; }";
        let facts = extract(src, "contracts/C.sol");

        assert!(
            !facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Local && b.name == "totalSupply"),
            "state variable 'totalSupply' must NOT be a Local binding"
        );
        assert!(
            facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Definition && b.name == "totalSupply"),
            "state variable 'totalSupply' must have a Definition binding"
        );
    }

    #[test]
    fn nesting_produces_type_and_function_scopes() {
        // `contract C { function m() public {} }` → Type scope (contract body) + Function scope.
        let src = "contract C { function m() public {} }";
        let facts = extract(src, "contracts/C.sol");

        let has_type = facts.scopes.iter().any(|s| s.kind == ScopeKind::Type);
        let has_fn = facts.scopes.iter().any(|s| s.kind == ScopeKind::Function);
        assert!(has_type, "expected a Type scope for contract body");
        assert!(has_fn, "expected a Function scope for method body");
    }

    #[test]
    fn same_file_call_ref_has_non_zero_scope() {
        let src = r#"
pragma solidity ^0.8.0;
contract C {
    function helper() internal returns (uint256) { return 42; }
    function compute() public returns (uint256) { return helper(); }
}
"#;
        let facts = extract(src, "contracts/C.sol");

        assert!(
            facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Definition && b.name == "helper"),
            "expected a Definition binding for 'helper'"
        );

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
    fn import_binding_emitted() {
        // `pragma solidity ^0.8.0; import {ERC20} from "./ERC20.sol";` → Import binding `ERC20`.
        let src = r#"pragma solidity ^0.8.0; import {ERC20} from "./ERC20.sol";"#;
        let facts = extract(src, "contracts/Token.sol");

        assert!(
            facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Import && b.name == "ERC20"),
            "expected an Import binding for 'ERC20', got {:?}",
            facts.bindings
        );
    }

    // ── Edge richness: Read / Write ──────────────────────────────────────────

    // Test (C1): Read at use — the use of `base` in `return base` emits Read;
    // the declaration `uint base = 1` must NOT produce a Read.
    #[test]
    fn read_ref_at_use_not_at_declaration() {
        let src = r#"
contract C {
    function f() public returns (uint) {
        uint base = 1;
        return base;
    }
}
"#;
        let facts = extract(src, "contracts/C.sol");

        let read_refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Read && r.name == "base")
            .collect();
        // Must have at least one Read ref (the use in `return base`).
        assert!(
            !read_refs.is_empty(),
            "expected at least one Read ref for 'base', got none; all refs: {:?}",
            facts
                .references
                .iter()
                .map(|r| (&r.name, r.role))
                .collect::<Vec<_>>()
        );
        // The declaration `uint base = 1` comes first; the use in `return base`
        // has a larger byte offset. Verify at least one Read ref is at the use site.
        let decl_byte = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Read && r.name == "base")
            .map(|r| r.occ.byte)
            .unwrap();
        // In the source, `return base` is after `uint base = 1;` — byte > 40.
        assert!(
            decl_byte > 40,
            "Read ref for 'base' should be at the use site (byte > 40), got byte={}",
            decl_byte
        );
    }

    // Test (C2): Write — `cnt = 5;` emits Write "cnt".
    #[test]
    fn write_ref_emitted_for_assignment() {
        let src = r#"
contract C {
    function f() public {
        uint cnt = 0;
        cnt = 5;
    }
}
"#;
        let facts = extract(src, "contracts/C.sol");

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

    // Test (C3): No double-emit — `helper()` produces Call "helper", not also Read.
    #[test]
    fn call_not_also_read() {
        let src = r#"
contract C {
    function f() public {
        helper();
    }
}
"#;
        let facts = extract(src, "contracts/C.sol");

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

    // Test (C4): Member access — `msg.sender` → Read "msg", no Read "sender".
    #[test]
    fn member_access_reads_object_not_property() {
        let src = r#"
contract C {
    function f() public {
        address who = msg.sender;
    }
}
"#;
        let facts = extract(src, "contracts/C.sol");

        // `msg` is the object (base) of a member_expression → should be a Read.
        // (It may or may not appear depending on whether `msg` is a special
        // built-in identifier in tree-sitter-solidity; the key assertion is that
        // `sender` must NOT appear as a Read.)
        let sender_reads: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Read && r.name == "sender")
            .collect();
        assert!(
            sender_reads.is_empty(),
            "property 'sender' in member_expression must NOT be a Read ref; got: {sender_reads:?}"
        );
    }
}
