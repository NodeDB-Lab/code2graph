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
use crate::graph::types::{ByteSpan, FileFacts, RefRole, Reference, Symbol, SymbolKind};
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
        symbols.push(super::module_symbol(
            Language::Rust,
            &namespaces,
            file,
            source.len(),
        ));
        let mut references =
            collect_call_references(&root, &ts_language, CALL_QUERY, Language::Rust, bytes, file)?;
        collect_inheritance(&root, bytes, file, &mut references);

        Ok(FileFacts {
            file: file.to_owned(),
            lang: Language::Rust.as_str().to_owned(),
            symbols,
            references,
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
                    RefRole::Inherit,
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
                                RefRole::Inherit,
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
            "codegraph    auth/session/validate_token()."
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
            .filter(|r| r.role == RefRole::Inherit)
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
            .filter(|r| r.role == RefRole::Inherit)
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
            .filter(|r| r.role == RefRole::Inherit)
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
            .filter(|r| r.role == RefRole::Inherit)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            inherit_names.contains(&"Display"),
            "expected 'Display' in {inherit_names:?}"
        );
    }
}
