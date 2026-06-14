// SPDX-License-Identifier: Apache-2.0

//! Rust extractor — one tree-sitter pass yielding definitions and references.
//!
//! Definitions: fully-public top-level items (`pub fn/struct/enum/trait/type/
//! const/static/mod`) plus `impl` blocks. Qualified identity follows the module
//! path derived from the file path (`src/auth/session.rs` → namespaces
//! `auth`,`session`). References: callee identifiers of `call_expression` nodes.
//!
//! Emits neutral [`FileFacts`] — no storage entries, no source bodies.

use tree_sitter::{Language as TsLanguage, Node, Parser};

use crate::error::{CodegraphError, Result};
use crate::graph::types::{
    ByteSpan, FileFacts, RefRole, Reference, Scope, ScopeId, ScopeKind, Symbol, SymbolKind,
};
use crate::lang::Language;
use crate::symbol::{Descriptor, SymbolId};

use super::{Extractor, child_text, collect_call_references, node_text, one_line_signature};

/// Tree-sitter query capturing call-callee identifiers.
const CALL_QUERY: &str = r#"
(call_expression
  function: [
    (identifier) @callee
    (field_expression field: (field_identifier) @callee)
    (scoped_identifier name: (identifier) @callee)
  ]
)
"#;

/// Extracts Rust symbols and references.
pub struct RustExtractor;

impl Extractor for RustExtractor {
    fn lang(&self) -> Language {
        Language::Rust
    }

    fn extract(&self, source: &str, file: &str) -> Result<FileFacts> {
        let ts_language = TsLanguage::from(tree_sitter_rust::LANGUAGE);
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
        let namespaces = rust_namespaces(file);

        let mut symbols = collect_symbols(&root, bytes, file, &namespaces);
        let mod_sym = super::module_symbol(Language::Rust, &namespaces, file, source.len());
        let module_id = mod_sym.id.to_scip_string();
        symbols.push(mod_sym);
        let mut references =
            collect_call_references(&root, &ts_language, CALL_QUERY, Language::Rust, bytes, file)?;
        collect_inheritance(&root, bytes, file, &mut references);
        collect_imports(&root, bytes, file, &mut references, &module_id);

        let scopes = collect_scopes(&root, source.len());
        attach_reference_scopes(&mut references, &scopes);

        Ok(FileFacts {
            file: file.to_owned(),
            lang: Language::Rust.as_str().to_owned(),
            symbols,
            references,
            scopes,
            bindings: Vec::new(),
        })
    }
}

/// Derive the Rust module path (namespace descriptors) from a file path.
fn rust_namespaces(file: &str) -> Vec<String> {
    let p = file.strip_suffix(".rs").unwrap_or(file);
    let p = p.strip_prefix("src/").unwrap_or(p);
    let mut segs: Vec<String> = p
        .split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    if let Some(last) = segs.last() {
        if matches!(last.as_str(), "mod" | "lib" | "main") {
            segs.pop();
        }
    }
    segs
}

fn collect_symbols(root: &Node, bytes: &[u8], file: &str, namespaces: &[String]) -> Vec<Symbol> {
    let mut out = Vec::new();
    for child in root.children(&mut root.walk()) {
        let (kind, leaf) = match child.kind() {
            "function_item" if is_fully_pub(&child, bytes) => {
                let Some(name) = child_text(&child, "identifier", bytes) else {
                    continue;
                };
                (
                    SymbolKind::Function,
                    Descriptor::Method {
                        name: name.clone(),
                        disambiguator: String::new(),
                    },
                )
            }
            "struct_item" if is_fully_pub(&child, bytes) => {
                let Some(name) = child_text(&child, "type_identifier", bytes) else {
                    continue;
                };
                (SymbolKind::Struct, Descriptor::Type(name))
            }
            "enum_item" if is_fully_pub(&child, bytes) => {
                let Some(name) = child_text(&child, "type_identifier", bytes) else {
                    continue;
                };
                (SymbolKind::Enum, Descriptor::Type(name))
            }
            "trait_item" if is_fully_pub(&child, bytes) => {
                let Some(name) = child_text(&child, "type_identifier", bytes) else {
                    continue;
                };
                (SymbolKind::Trait, Descriptor::Type(name))
            }
            "type_item" if is_fully_pub(&child, bytes) => {
                let Some(name) = child_text(&child, "type_identifier", bytes) else {
                    continue;
                };
                (SymbolKind::TypeAlias, Descriptor::Type(name))
            }
            "const_item" if is_fully_pub(&child, bytes) => {
                let Some(name) = child_text(&child, "identifier", bytes) else {
                    continue;
                };
                (SymbolKind::Const, Descriptor::Term(name))
            }
            "static_item" if is_fully_pub(&child, bytes) => {
                let Some(name) = child_text(&child, "identifier", bytes) else {
                    continue;
                };
                (SymbolKind::Static, Descriptor::Term(name))
            }
            "mod_item" if is_fully_pub(&child, bytes) => {
                let Some(name) = child_text(&child, "identifier", bytes) else {
                    continue;
                };
                (SymbolKind::Module, Descriptor::Namespace(name))
            }
            "impl_item" => {
                let name = impl_type_name(&child, bytes);
                (SymbolKind::Impl, Descriptor::Type(name))
            }
            _ => continue,
        };

        let mut descriptors: Vec<Descriptor> = namespaces
            .iter()
            .cloned()
            .map(Descriptor::Namespace)
            .collect();
        descriptors.push(leaf.clone());

        out.push(Symbol {
            id: SymbolId::global(Language::Rust.as_str(), descriptors),
            name: leaf.name().to_owned(),
            kind,
            file: file.to_owned(),
            line: (child.start_position().row + 1) as u32,
            span: ByteSpan {
                start: child.start_byte(),
                end: child.end_byte(),
            },
            signature: one_line_signature(node_text(&child, bytes), &['{']),
        });
    }
    out
}

/// True if the node's first `visibility_modifier` child is bare `pub`.
fn is_fully_pub(node: &Node, bytes: &[u8]) -> bool {
    node.children(&mut node.walk())
        .find(|c| c.kind() == "visibility_modifier")
        .map(|c| node_text(&c, bytes).trim() == "pub")
        .unwrap_or(false)
}

/// Display name for an `impl` block: the last type identifier before the body.
fn impl_type_name(node: &Node, bytes: &[u8]) -> String {
    let mut names = Vec::new();
    for child in node.children(&mut node.walk()) {
        match child.kind() {
            "type_identifier" | "generic_type" | "scoped_type_identifier" => {
                names.push(node_text(&child, bytes).to_owned());
            }
            "declaration_list" => break,
            _ => {}
        }
    }
    names.last().cloned().unwrap_or_else(|| "impl".to_owned())
}

/// Recursively walk `node` collecting `Inherit` references for every
/// `impl_item` (trait implementation) and `trait_item` (supertrait bound) in
/// the tree (including items inside `mod` blocks).
fn collect_inheritance(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    match node.kind() {
        "impl_item" => {
            // Only trait impls have a `trait` field; inherent impls do not.
            if let Some(trait_node) = node.child_by_field_name("trait") {
                super::push_ref(
                    out,
                    super::simple_type_name(node_text(&trait_node, bytes), "::"),
                    &trait_node,
                    file,
                    RefRole::IsImplementation,
                );
            }
        }
        "trait_item" => {
            // `bounds` field is a `trait_bounds` node listing supertraits.
            if let Some(bounds) = node.child_by_field_name("bounds") {
                for child in bounds.children(&mut bounds.walk()) {
                    match child.kind() {
                        "type_identifier" | "generic_type" | "scoped_type_identifier" => {
                            super::push_ref(
                                out,
                                super::simple_type_name(node_text(&child, bytes), "::"),
                                &child,
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

    // Recurse into all children so items inside `mod` blocks are covered.
    for child in node.children(&mut node.walk()) {
        collect_inheritance(&child, bytes, file, out);
    }
}

/// Recursively collect leaf import names from a use-tree node and push an
/// [`RefRole::Import`] reference for each one.
///
/// `prefix` is the accumulated path prefix from enclosing `scoped_use_list`
/// nodes (e.g. `"std::collections"` when processing the list in
/// `use std::collections::{HashMap, BTreeMap}`). It is threaded downward so
/// bare `identifier` leaves inside a `use_list` can report their `from_path`.
///
/// The leaf is always the concrete identifier being imported:
/// - `identifier`         → `from_path = prefix` (the received prefix).
/// - `scoped_identifier`  → `from_path` = its own `path` field (authoritative).
/// - `use_as_clause`      → recurse into the `path` field (alias ignored), passing `prefix` through.
/// - `scoped_use_list`    → compute `new_prefix` from the node's `path` field, then recurse into `list`.
/// - `use_list`           → recurse each named child, passing `prefix` through.
/// - `use_wildcard` / `crate` / `self` / `super` / anything else → skip.
fn collect_use_leaves(
    node: &Node,
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Reference>,
    module_id: &str,
    prefix: &str,
) {
    match node.kind() {
        "identifier" => {
            // Bare leaf inside a use_list — from_path is the enclosing prefix.
            super::push_import_ref(
                out,
                super::node_text(node, bytes),
                node,
                file,
                module_id,
                prefix,
            );
        }
        "scoped_identifier" => {
            // The node's `path` field is the authoritative from-path.
            let from_path = node
                .child_by_field_name("path")
                .map_or("", |n| super::node_text(&n, bytes));
            if let Some(name_node) = node.child_by_field_name("name") {
                super::push_import_ref(
                    out,
                    super::node_text(&name_node, bytes),
                    &name_node,
                    file,
                    module_id,
                    from_path,
                );
            }
        }
        "use_as_clause" => {
            // Alias is ignored; recurse into the path child, passing prefix through.
            if let Some(path_node) = node.child_by_field_name("path") {
                collect_use_leaves(&path_node, bytes, file, out, module_id, prefix);
            }
        }
        "scoped_use_list" => {
            // Compute a fresh prefix from this node's `path` field, then recurse
            // into the list with that prefix so bare identifiers inside the list
            // can report the correct from_path.
            let new_prefix = node
                .child_by_field_name("path")
                .map_or("", |n| super::node_text(&n, bytes));
            if let Some(list_node) = node.child_by_field_name("list") {
                collect_use_leaves(&list_node, bytes, file, out, module_id, new_prefix);
            }
        }
        "use_list" => {
            for child in node.named_children(&mut node.walk()) {
                collect_use_leaves(&child, bytes, file, out, module_id, prefix);
            }
        }
        // use_wildcard, crate, self, super, metavariable → skip
        _ => {}
    }
}

/// Walk the full tree and emit [`RefRole::Import`] references for every
/// `use_declaration`. Recurses into `mod` blocks and function bodies so nested
/// `use` items are also captured.
fn collect_imports(
    node: &Node,
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Reference>,
    module_id: &str,
) {
    if node.kind() == "use_declaration" {
        if let Some(arg) = node.child_by_field_name("argument") {
            collect_use_leaves(&arg, bytes, file, out, module_id, "");
        }
        // No need to recurse further inside a use_declaration.
        return;
    }
    for child in node.children(&mut node.walk()) {
        collect_imports(&child, bytes, file, out, module_id);
    }
}

// ── Scope tree ───────────────────────────────────────────────────────────────

/// Append a new scope to `scopes` and return its [`ScopeId`].
fn push_scope(
    scopes: &mut Vec<Scope>,
    parent: Option<ScopeId>,
    span: ByteSpan,
    kind: ScopeKind,
) -> ScopeId {
    let id = scopes.len();
    scopes.push(Scope { parent, span, kind });
    id
}

/// `ByteSpan` covering the whole extent of `node`.
fn node_span(node: &Node) -> ByteSpan {
    ByteSpan {
        start: node.start_byte(),
        end: node.end_byte(),
    }
}

/// DFS that builds the scope tree for one file.
///
/// The file-root scope (`scopes[0]`) must already be pushed before calling
/// this for the root node's children. `scope_dfs` is called once per node:
/// it inspects `node`'s own kind, opens a new scope for `node` when
/// appropriate, and then recurses into whichever children carry nested scopes.
///
/// `parent_id` is the [`ScopeId`] of the innermost scope already open when
/// this node is visited; new scopes opened for `node` itself use it as their
/// parent.
fn scope_dfs(node: &Node, parent_id: ScopeId, scopes: &mut Vec<Scope>) {
    match node.kind() {
        "function_item" | "closure_expression" => {
            let fn_id = push_scope(
                scopes,
                Some(parent_id),
                node_span(node),
                ScopeKind::Function,
            );
            // Recurse into body's children to avoid double-opening the block.
            if let Some(body) = node.child_by_field_name("body") {
                for child in body.children(&mut body.walk()) {
                    scope_dfs(&child, fn_id, scopes);
                }
            } else {
                for child in node.children(&mut node.walk()) {
                    scope_dfs(&child, fn_id, scopes);
                }
            }
        }
        "mod_item" | "impl_item" | "trait_item" | "struct_item" | "enum_item" => {
            if let Some(body) = node.child_by_field_name("body") {
                let kind = if node.kind() == "mod_item" {
                    ScopeKind::Module
                } else {
                    ScopeKind::Type
                };
                let body_id = push_scope(scopes, Some(parent_id), node_span(&body), kind);
                for child in body.children(&mut body.walk()) {
                    scope_dfs(&child, body_id, scopes);
                }
            } else {
                // No body (e.g. `mod foo;` declaration) — recurse with the same parent.
                for child in node.children(&mut node.walk()) {
                    scope_dfs(&child, parent_id, scopes);
                }
            }
        }
        "block" => {
            let block_id = push_scope(scopes, Some(parent_id), node_span(node), ScopeKind::Block);
            for child in node.children(&mut node.walk()) {
                scope_dfs(&child, block_id, scopes);
            }
        }
        // Macro bodies are not reliable AST — skip entirely.
        "macro_definition" | "macro_invocation" => {}
        // All other nodes: open no scope, recurse children with the same parent.
        _ => {
            for child in node.children(&mut node.walk()) {
                scope_dfs(&child, parent_id, scopes);
            }
        }
    }
}

/// Build and return the full lexical scope tree for `source_len` bytes.
///
/// `scopes[0]` is always the file-root `Module` scope spanning `[0, source_len)`.
fn collect_scopes(root: &Node, source_len: usize) -> Vec<Scope> {
    let mut scopes = Vec::new();
    // Push the file-root scope first (index 0).
    push_scope(
        &mut scopes,
        None,
        ByteSpan {
            start: 0,
            end: source_len,
        },
        ScopeKind::Module,
    );
    // DFS from each top-level child of source_file with parent = 0.
    for child in root.children(&mut root.walk()) {
        scope_dfs(&child, 0, &mut scopes);
    }
    scopes
}

/// Attach each reference to the innermost scope that contains its byte offset.
///
/// Ties on span length (e.g. a function whose body spans the whole file, so its
/// scope equals the root scope) resolve to the higher index: `collect_scopes`
/// always pushes a parent before its children, so the larger index is the more
/// deeply nested scope.
fn attach_reference_scopes(refs: &mut [Reference], scopes: &[Scope]) {
    for r in refs {
        r.scope = scopes
            .iter()
            .enumerate()
            .filter(|(_, s)| s.span.contains(r.occ.byte))
            .min_by_key(|(id, s)| (s.span.len(), std::cmp::Reverse(*id)))
            .map(|(id, _)| id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_defs_with_scip_ids() {
        let src = r#"
pub fn validate_token(tok: &str) -> bool { helper() }
fn private_helper() {}
pub struct Config { pub value: u32 }
"#;
        let facts = RustExtractor.extract(src, "src/auth/session.rs").unwrap();
        let names: Vec<&str> = facts.symbols.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"validate_token"));
        assert!(names.contains(&"Config"));
        assert!(!names.contains(&"private_helper")); // not `pub`

        let vt = facts
            .symbols
            .iter()
            .find(|s| s.name == "validate_token")
            .unwrap();
        assert_eq!(
            vt.id.to_scip_string(),
            "codegraph . . . auth/session/validate_token()."
        );
        assert_eq!(vt.kind, SymbolKind::Function);
    }

    #[test]
    fn extracts_call_references() {
        let src = "pub fn main() { validate_token(\"t\"); helper(); }";
        let facts = RustExtractor.extract(src, "src/main.rs").unwrap();
        let names: Vec<&str> = facts.references.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"validate_token"));
        assert!(names.contains(&"helper"));
    }

    #[test]
    fn trait_impl_emits_inherit_ref_and_inherent_impl_does_not() {
        // Trait impl → one Inherit ref named "Display".
        let src_trait_impl = r#"
use std::fmt;
pub struct Point;
impl fmt::Display for Point {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { Ok(()) }
}
"#;
        let facts = RustExtractor
            .extract(src_trait_impl, "src/point.rs")
            .unwrap();
        let inherit_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            inherit_names.contains(&"Display"),
            "expected 'Display' in {inherit_names:?}"
        );

        // Inherent impl → no Inherit ref.
        let src_inherent = "pub struct Point; impl Point { pub fn new() -> Self { Point } }";
        let facts2 = RustExtractor.extract(src_inherent, "src/point.rs").unwrap();
        let inherit2: Vec<&str> = facts2
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            inherit2.is_empty(),
            "expected no Inherit refs, got {inherit2:?}"
        );
    }

    #[test]
    fn supertrait_bounds_emit_inherit_refs() {
        let src = "pub trait Foo: Bar + Baz {}";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
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
    fn scoped_trait_path_emits_leaf_name() {
        // `impl std::fmt::Display for Point {}` → leaf name "Display"
        let src = r#"
pub struct Point;
impl std::fmt::Display for Point {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { Ok(()) }
}
"#;
        let facts = RustExtractor.extract(src, "src/point.rs").unwrap();
        let inherit_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            inherit_names.contains(&"Display"),
            "expected 'Display' in {inherit_names:?}"
        );
    }

    // ── Import reference tests ────────────────────────────────────────────────

    #[test]
    fn import_scoped_identifier_emits_leaf() {
        // `use a::b::Config;` → one Import ref `Config`
        let src = "use a::b::Config;";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(
            import_names,
            vec!["Config"],
            "expected ['Config'], got {import_names:?}"
        );
    }

    #[test]
    fn import_use_list_emits_all_leaves() {
        // `use std::collections::{HashMap, HashSet};` → Import refs `HashMap` and `HashSet`
        let src = "use std::collections::{HashMap, HashSet};";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let mut import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        import_names.sort_unstable();
        assert_eq!(
            import_names,
            vec!["HashMap", "HashSet"],
            "expected ['HashMap', 'HashSet'], got {import_names:?}"
        );
    }

    #[test]
    fn import_use_as_clause_emits_real_leaf_not_alias() {
        // `use a::b as c;` → Import ref `b` (not `c`)
        let src = "use a::b as c;";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(
            import_names,
            vec!["b"],
            "expected ['b'], got {import_names:?}"
        );
    }

    #[test]
    fn import_wildcard_emits_nothing() {
        // `use a::*;` → NO Import refs
        let src = "use a::*;";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            import_names.is_empty(),
            "expected no Import refs, got {import_names:?}"
        );
    }

    #[test]
    fn import_simple_scoped_path_emits_leaf() {
        // `use std::io::Result;` → Import ref `Result`
        let src = "use std::io::Result;";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(
            import_names,
            vec!["Result"],
            "expected ['Result'], got {import_names:?}"
        );
    }

    #[test]
    fn import_refs_carry_source_module() {
        // `use std::io::Result;` in src/net/client.rs → Import ref carries
        // the module SCIP id of net/client.
        let src = "use std::io::Result;";
        let file = "src/net/client.rs";
        let facts = RustExtractor.extract(src, file).unwrap();

        let namespaces = rust_namespaces(file);
        let expected_module_id =
            crate::extract::module_symbol(Language::Rust, &namespaces, file, src.len())
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

    // --- from_path tests ---

    #[test]
    fn import_scoped_identifier_carries_from_path() {
        // `use std::io::Result;` → from_path == "std::io"
        let src = "use std::io::Result;";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let r = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Import && r.name == "Result")
            .expect("expected Import ref for 'Result'");
        assert_eq!(
            r.from_path,
            Some("std::io".to_owned()),
            "from_path should be 'std::io', got {:?}",
            r.from_path
        );
    }

    #[test]
    fn import_use_list_leaves_carry_prefix_as_from_path() {
        // `use std::collections::{HashMap, BTreeMap};`
        // Both leaf refs must have from_path == "std::collections".
        let src = "use std::collections::{HashMap, BTreeMap};";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let import_refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .collect();
        assert_eq!(
            import_refs.len(),
            2,
            "expected 2 Import refs, got {:?}",
            import_refs.iter().map(|r| &r.name).collect::<Vec<_>>()
        );
        for r in &import_refs {
            assert_eq!(
                r.from_path,
                Some("std::collections".to_owned()),
                "from_path for '{}' should be 'std::collections', got {:?}",
                r.name,
                r.from_path
            );
        }
    }

    // ── Scope tree tests ──────────────────────────────────────────────────────

    #[test]
    fn scope_fn_with_call_has_function_scope_and_ref_attaches_to_it() {
        // A function containing a call: assert root Module scope (index 0) and a
        // Function scope; the call reference's scope should be Some(fn_scope_id),
        // not Some(0) (the root).
        let src = "pub fn greet() { helper(); }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();

        // scopes[0] must be the file-root Module.
        assert!(!facts.scopes.is_empty(), "scopes must not be empty");
        assert_eq!(
            facts.scopes[0].kind,
            ScopeKind::Module,
            "scopes[0] must be Module"
        );
        assert_eq!(facts.scopes[0].parent, None, "root scope has no parent");

        // There must be at least one Function scope.
        let fn_scope_pos = facts
            .scopes
            .iter()
            .position(|s| s.kind == ScopeKind::Function)
            .expect("expected a Function scope");

        // The call reference to `helper` must be attributed to the Function scope,
        // not the root.
        let helper_ref = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Call && r.name == "helper")
            .expect("expected a Call ref for 'helper'");
        assert_eq!(
            helper_ref.scope,
            Some(fn_scope_pos),
            "helper call should be attributed to the Function scope ({}), got {:?}",
            fn_scope_pos,
            helper_ref.scope
        );
    }

    #[test]
    fn nested_block_scope_parent_chains_correctly() {
        // A function whose body contains an inner bare `{ }` block:
        //   fn outer() { { inner_call(); } }
        // Scopes expected: root Module (0), Function (1), Block (2).
        // A ref inside the block must attribute to the Block scope,
        // and the Block scope's parent must be the Function scope.
        let src = "fn outer() { { inner_call(); } }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();

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

        // The call ref inside the block must attribute to the Block scope (innermost).
        let inner_ref = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Call && r.name == "inner_call")
            .expect("expected a Call ref for 'inner_call'");
        assert_eq!(
            inner_ref.scope,
            Some(block_scope_id),
            "inner_call should attribute to the Block scope ({}), got {:?}",
            block_scope_id,
            inner_ref.scope
        );
    }

    #[test]
    fn empty_source_produces_exactly_one_root_scope() {
        // Empty source → collect_scopes returns exactly one scope (the file root),
        // does not panic.
        let ts_language = tree_sitter::Language::from(tree_sitter_rust::LANGUAGE);
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&ts_language).unwrap();
        let tree = parser.parse("", None).unwrap();
        let root = tree.root_node();

        let scopes = collect_scopes(&root, 0);
        assert_eq!(
            scopes.len(),
            1,
            "empty source should produce exactly one scope"
        );
        assert_eq!(scopes[0].kind, ScopeKind::Module);
        assert_eq!(scopes[0].parent, None);
    }

    #[test]
    fn impl_block_with_method_nests_type_then_function_scope() {
        // `impl Foo { fn bar() { call(); } }`
        // Expected nesting: root Module (0) → Type (impl body) → Function (method)
        // A call inside the method attributes to the Function scope (innermost).
        let src = "pub struct Foo; impl Foo { pub fn bar(&self) { call(); } }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();

        let type_scope_id = facts
            .scopes
            .iter()
            .position(|s| s.kind == ScopeKind::Type)
            .expect("expected a Type scope for the impl body");
        let fn_scope_id = facts
            .scopes
            .iter()
            .position(|s| s.kind == ScopeKind::Function)
            .expect("expected a Function scope for the method");

        // Type scope's parent must be the root (0).
        assert_eq!(
            facts.scopes[type_scope_id].parent,
            Some(0),
            "impl body Type scope parent should be root (0)"
        );
        // Function scope's parent must be the Type scope.
        assert_eq!(
            facts.scopes[fn_scope_id].parent,
            Some(type_scope_id),
            "method Function scope parent should be the Type scope"
        );

        // The call ref must attribute to the Function scope (innermost).
        let call_ref = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Call && r.name == "call")
            .expect("expected a Call ref for 'call'");
        assert_eq!(
            call_ref.scope,
            Some(fn_scope_id),
            "call() should attribute to the Function scope ({}), got {:?}",
            fn_scope_id,
            call_ref.scope
        );
    }
}
