// SPDX-License-Identifier: Apache-2.0

//! PHP extractor — one tree-sitter pass yielding definitions and references.
//!
//! Definitions: top-level functions, classes, interfaces, traits, and enums,
//! plus their public members (methods, properties, constants). Namespace
//! identity comes from the `namespace` declaration when present; otherwise it
//! falls back to path-derived segments (strips `.php`, strips leading `src/`,
//! splits on `/`). Private and protected members are skipped. Interface members
//! are treated as implicitly public. Enum *cases* are not captured in v0 — a
//! deliberate limitation; they require a separate `SymbolKind` and are left for
//! a future pass.
//!
//! PHP supports two namespace forms:
//! - **Statement form**: `namespace App;` followed by sibling declarations.
//! - **Block form**: `namespace App { ... }` with declarations inside a
//!   `compound_statement` body.
//!
//! Both are handled: definitions are collected from the program root and,
//! recursively, from any `namespace_definition` that carries a `body` field.
//!
//! References: callee identifiers of `function_call_expression` (bare calls)
//! and `member_call_expression` (method calls).

use tree_sitter::{Language as TsLanguage, Node, Parser};

use crate::error::{CodegraphError, Result};
use crate::graph::types::{ByteSpan, FileFacts, RefRole, Reference, Symbol, SymbolKind};
use crate::lang::Language;
use crate::symbol::{Descriptor, SymbolId};

use super::{
    Extractor, child_text, collect_call_references, field_text, node_text, one_line_signature,
};

/// Tree-sitter query capturing call-callee identifiers.
const CALL_QUERY: &str = r#"
[
  (function_call_expression
    function: (name) @callee)
  (member_call_expression
    name: (name) @callee)
]
"#;

/// Extracts PHP symbols and references.
pub struct PhpExtractor;

impl Extractor for PhpExtractor {
    fn lang(&self) -> Language {
        Language::Php
    }

    fn extract(&self, source: &str, file: &str) -> Result<FileFacts> {
        let ts_language = TsLanguage::from(tree_sitter_php::LANGUAGE_PHP);
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
        let namespaces = php_namespaces(&root, bytes, file);

        let mut symbols = Vec::new();
        collect_defs(&root, &namespaces, bytes, file, &mut symbols);
        symbols.push(super::module_symbol(
            Language::Php,
            &namespaces,
            file,
            source.len(),
        ));

        let mut references =
            collect_call_references(&root, &ts_language, CALL_QUERY, Language::Php, bytes, file)?;
        collect_inheritance(&root, bytes, file, &mut references);
        collect_imports(&root, bytes, file, &mut references);

        Ok(FileFacts {
            file: file.to_owned(),
            lang: Language::Php.as_str().to_owned(),
            symbols,
            references,
        })
    }
}

/// Derive namespace descriptors from the `namespace` declaration, falling back
/// to path-derived segments when no declaration is present.
///
/// With a namespace: `App\Auth` → `["App", "Auth"]`.
/// Without: `src/app/helpers.php` → `["app", "helpers"]`.
fn php_namespaces(root: &Node, bytes: &[u8], file: &str) -> Vec<String> {
    for child in root.children(&mut root.walk()) {
        if child.kind() != "namespace_definition" {
            continue;
        }
        // The `name` field is a `namespace_name` node whose raw text is the
        // backslash-delimited namespace string, e.g. `App\Auth`.
        if let Some(ns_text) = field_text(&child, "name", bytes) {
            let parts: Vec<String> = ns_text
                .split('\\')
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect();
            if !parts.is_empty() {
                return parts;
            }
        }
    }

    // Fallback: derive from file path (strips `.php`, strips leading `src/`).
    let p = file.strip_suffix(".php").unwrap_or(file);
    let p = p.strip_prefix("src/").unwrap_or(p);
    p.split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Collect top-level definitions from `container` (either the program root or
/// the `compound_statement` body of a block-form namespace).
///
/// Handles both PHP namespace forms:
/// - Statement form: `namespace App;` — the declarations are siblings of the
///   `namespace_definition` node under the program root.
/// - Block form: `namespace App { ... }` — the `namespace_definition` has a
///   `body` field; we recurse into it.
fn collect_defs(
    container: &Node,
    namespaces: &[String],
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    for child in container.children(&mut container.walk()) {
        match child.kind() {
            "function_definition" => {
                let Some(name) = field_text(&child, "name", bytes) else {
                    continue;
                };
                let mut descriptors: Vec<Descriptor> = namespaces
                    .iter()
                    .cloned()
                    .map(Descriptor::Namespace)
                    .collect();
                descriptors.push(Descriptor::Method {
                    name: name.clone(),
                    disambiguator: String::new(),
                });
                push_symbol(
                    out,
                    &child,
                    name,
                    SymbolKind::Function,
                    descriptors,
                    bytes,
                    file,
                );
            }
            kind @ ("class_declaration"
            | "interface_declaration"
            | "trait_declaration"
            | "enum_declaration") => {
                let Some(type_name) = field_text(&child, "name", bytes) else {
                    continue;
                };
                let type_sym_kind = match kind {
                    "class_declaration" => SymbolKind::Class,
                    "interface_declaration" => SymbolKind::Interface,
                    "trait_declaration" => SymbolKind::Trait,
                    "enum_declaration" => SymbolKind::Enum,
                    _ => unreachable!(),
                };
                let mut type_descriptors: Vec<Descriptor> = namespaces
                    .iter()
                    .cloned()
                    .map(Descriptor::Namespace)
                    .collect();
                type_descriptors.push(Descriptor::Type(type_name.clone()));
                push_symbol(
                    out,
                    &child,
                    type_name,
                    type_sym_kind,
                    type_descriptors.clone(),
                    bytes,
                    file,
                );

                // Interface members are implicitly public.
                let implicit_public = kind == "interface_declaration";

                if let Some(body) = child.child_by_field_name("body") {
                    collect_members(&body, &type_descriptors, implicit_public, bytes, file, out);
                }
            }
            "namespace_definition" => {
                // Block-form namespace: recurse into the compound_statement body.
                if let Some(body) = child.child_by_field_name("body") {
                    collect_defs(&body, namespaces, bytes, file, out);
                }
                // Statement-form namespace has no body; its sibling declarations
                // are already visited in the outer loop.
            }
            _ => {}
        }
    }
}

/// Collect public method, property, and constant declarations from a type body.
fn collect_members(
    body: &Node,
    type_descriptors: &[Descriptor],
    implicit_public: bool,
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    for member in body.children(&mut body.walk()) {
        match member.kind() {
            "method_declaration" => {
                if !implicit_public && !is_public(&member, bytes) {
                    continue;
                }
                let Some(name) = field_text(&member, "name", bytes) else {
                    continue;
                };
                let mut descriptors = type_descriptors.to_vec();
                descriptors.push(Descriptor::Method {
                    name: name.clone(),
                    disambiguator: String::new(),
                });
                push_symbol(
                    out,
                    &member,
                    name,
                    SymbolKind::Method,
                    descriptors,
                    bytes,
                    file,
                );
            }
            "property_declaration" => {
                if !implicit_public && !is_public(&member, bytes) {
                    continue;
                }
                // A property_declaration may contain one or more property_element
                // children; each property_element's `name` field is a
                // `variable_name` node whose text includes the leading `$`.
                for elem in member.children(&mut member.walk()) {
                    if elem.kind() != "property_element" {
                        continue;
                    }
                    let Some(raw_name) = field_text(&elem, "name", bytes) else {
                        continue;
                    };
                    // Strip the leading `$` from the variable name.
                    let name = raw_name.strip_prefix('$').unwrap_or(&raw_name).to_owned();
                    let mut descriptors = type_descriptors.to_vec();
                    descriptors.push(Descriptor::Term(name.clone()));
                    push_symbol(
                        out,
                        &member,
                        name,
                        SymbolKind::Static,
                        descriptors,
                        bytes,
                        file,
                    );
                }
            }
            "const_declaration" => {
                if !implicit_public && !is_public(&member, bytes) {
                    continue;
                }
                // A const_declaration contains one or more const_element children;
                // each const_element has a child of kind `name`.
                for elem in member.children(&mut member.walk()) {
                    if elem.kind() != "const_element" {
                        continue;
                    }
                    // const_element has no named field for its name — get by kind.
                    let Some(name) = child_text(&elem, "name", bytes) else {
                        continue;
                    };
                    let mut descriptors = type_descriptors.to_vec();
                    descriptors.push(Descriptor::Term(name.clone()));
                    push_symbol(
                        out,
                        &member,
                        name,
                        SymbolKind::Const,
                        descriptors,
                        bytes,
                        file,
                    );
                }
            }
            _ => {}
        }
    }
}

/// Returns `true` if `node` is public.
///
/// Scans `node`'s direct children for a `visibility_modifier`. If one is found
/// returns whether its text is `"public"`; if none is found returns `true`
/// (PHP members without an explicit modifier default to public).
fn is_public(node: &Node, bytes: &[u8]) -> bool {
    for child in node.children(&mut node.walk()) {
        if child.kind() == "visibility_modifier" {
            return node_text(&child, bytes) == "public";
        }
    }
    // No visibility_modifier present → PHP default is public.
    true
}

/// Recursively walk `node` collecting `Import` references for every
/// `namespace_use_clause` in the tree.
///
/// Handles both the flat form (`use App\Models\User;`) and the grouped form
/// (`use App\Models\{User, Post};`) — the recursive walk reaches
/// `namespace_use_clause` nodes inside `namespace_use_group` automatically.
///
/// For each clause the leaf name is derived from the `qualified_name` or `name`
/// child via [`super::simple_type_name`] with `"\\"` as the separator; any
/// `alias` field is ignored.
fn collect_imports(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    if node.kind() == "namespace_use_clause" {
        // Find the child node that holds the fully-qualified name.
        for child in node.children(&mut node.walk()) {
            if matches!(child.kind(), "qualified_name" | "name") {
                let leaf = super::simple_type_name(node_text(&child, bytes), "\\");
                super::push_ref(out, leaf, &child, file, RefRole::Import);
                break;
            }
        }
    }

    // Recurse into all children so grouped use-clauses are reached.
    for child in node.children(&mut node.walk()) {
        collect_imports(&child, bytes, file, out);
    }
}

/// Recursively walk `node` collecting `Inherit` references for every
/// `class_declaration` and `interface_declaration` in the tree (including nested
/// and namespaced classes).
///
/// For each such node, the following named children are inspected:
/// - `base_clause` — `class extends Parent` (single parent) or
///   `interface extends A, B` (multiple parents).
/// - `class_interface_clause` — `class implements A, B` (multiple interfaces).
///
/// Within those clause nodes, children of kind `name`, `qualified_name`, or
/// `relative_name` are the actual parent/interface type nodes.
fn collect_inheritance(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    if matches!(node.kind(), "class_declaration" | "interface_declaration") {
        for child in node.children(&mut node.walk()) {
            if matches!(child.kind(), "base_clause" | "class_interface_clause") {
                for type_node in child.children(&mut child.walk()) {
                    if matches!(
                        type_node.kind(),
                        "name" | "qualified_name" | "relative_name"
                    ) {
                        super::push_ref(
                            out,
                            super::simple_type_name(node_text(&type_node, bytes), "\\"),
                            &type_node,
                            file,
                            RefRole::Inherit,
                        );
                    }
                }
            }
        }
    }

    // Recurse into all children so nested classes are covered.
    for child in node.children(&mut node.walk()) {
        collect_inheritance(&child, bytes, file, out);
    }
}

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
        id: SymbolId::global(Language::Php.as_str(), descriptors),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_namespaced_defs() {
        let src = r#"<?php
namespace App\Auth;

function format_id($x) { return helper($x); }

class Session {
    const MAX = 3;
    public $token;
    private $secret;
    public function validate($t) { return $this->check($t); }
    private function internal() {}
}

interface Reader {
    function read();
}
"#;
        let facts = PhpExtractor.extract(src, "src/app/Session.php").unwrap();

        let by_name = |n: &str| facts.symbols.iter().find(|s| s.name == n).cloned();

        // Top-level function.
        let format_id = by_name("format_id").unwrap();
        assert_eq!(format_id.kind, SymbolKind::Function);
        assert_eq!(
            format_id.id.to_scip_string(),
            "codegraph . . . App/Auth/format_id()."
        );

        // Class symbol.
        let session = by_name("Session").unwrap();
        assert_eq!(session.kind, SymbolKind::Class);
        assert_eq!(
            session.id.to_scip_string(),
            "codegraph . . . App/Auth/Session#"
        );

        // Class constant.
        let max = by_name("MAX").unwrap();
        assert_eq!(max.kind, SymbolKind::Const);
        assert_eq!(
            max.id.to_scip_string(),
            "codegraph . . . App/Auth/Session#MAX."
        );

        // Public property.
        let token = by_name("token").unwrap();
        assert_eq!(token.kind, SymbolKind::Static);
        assert_eq!(
            token.id.to_scip_string(),
            "codegraph . . . App/Auth/Session#token."
        );

        // Private property must not appear.
        assert!(by_name("secret").is_none());

        // Public method.
        let validate = by_name("validate").unwrap();
        assert_eq!(validate.kind, SymbolKind::Method);
        assert_eq!(
            validate.id.to_scip_string(),
            "codegraph . . . App/Auth/Session#validate()."
        );

        // Private method must not appear.
        assert!(by_name("internal").is_none());

        // Interface symbol.
        let reader = by_name("Reader").unwrap();
        assert_eq!(reader.kind, SymbolKind::Interface);
        assert_eq!(
            reader.id.to_scip_string(),
            "codegraph . . . App/Auth/Reader#"
        );

        // Interface method — implicitly public, no `public` modifier.
        let read = by_name("read").unwrap();
        assert_eq!(read.kind, SymbolKind::Method);
        assert_eq!(
            read.id.to_scip_string(),
            "codegraph . . . App/Auth/Reader#read()."
        );

        assert_eq!(facts.lang, "php");
    }

    #[test]
    fn path_fallback_without_namespace() {
        let src = r#"<?php
function format_date($d) {}
"#;
        let facts = PhpExtractor.extract(src, "src/helpers.php").unwrap();
        let by_name = |n: &str| facts.symbols.iter().find(|s| s.name == n).cloned();

        let format_date = by_name("format_date").unwrap();
        assert_eq!(format_date.kind, SymbolKind::Function);
        assert_eq!(
            format_date.id.to_scip_string(),
            "codegraph . . . helpers/format_date()."
        );
    }

    #[test]
    fn extracts_class_extends_and_implements() {
        let src = "<?php\nclass Foo extends Bar implements Baz {}";
        let facts = PhpExtractor.extract(src, "src/Foo.php").unwrap();

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
    fn extracts_interface_extends_reference() {
        let src = "<?php\ninterface I extends J {}";
        let facts = PhpExtractor.extract(src, "src/I.php").unwrap();

        let inherit_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Inherit)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            inherit_names.contains(&"J"),
            "expected 'J' in {inherit_names:?}"
        );
    }

    #[test]
    fn strips_namespace_from_parent_name() {
        let src = r"<?php
class C extends \App\Base {}";
        let facts = PhpExtractor.extract(src, "src/C.php").unwrap();

        let inherit_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Inherit)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            inherit_names.contains(&"Base"),
            "expected 'Base' (leaf of \\App\\Base) in {inherit_names:?}"
        );
    }

    #[test]
    fn import_simple_use_statement() {
        let src = "<?php\nuse App\\Models\\User;";
        let facts = PhpExtractor.extract(src, "src/Foo.php").unwrap();

        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            import_names.contains(&"User"),
            "expected 'User' in {import_names:?}"
        );
        assert_eq!(import_names.len(), 1);
    }

    #[test]
    fn import_aliased_use_statement_uses_real_name() {
        let src = "<?php\nuse App\\Models\\User as U;";
        let facts = PhpExtractor.extract(src, "src/Foo.php").unwrap();

        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            import_names.contains(&"User"),
            "expected 'User' (real name, not alias) in {import_names:?}"
        );
        // Alias 'U' must not appear as an import reference.
        assert!(
            !import_names.contains(&"U"),
            "alias 'U' must not appear in {import_names:?}"
        );
        assert_eq!(import_names.len(), 1);
    }

    #[test]
    fn import_grouped_use_statement() {
        let src = "<?php\nuse App\\Models\\{User, Post};";
        let facts = PhpExtractor.extract(src, "src/Foo.php").unwrap();

        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            import_names.contains(&"User"),
            "expected 'User' in {import_names:?}"
        );
        assert!(
            import_names.contains(&"Post"),
            "expected 'Post' in {import_names:?}"
        );
        assert_eq!(import_names.len(), 2);
    }

    #[test]
    fn extracts_call_references() {
        let src = r#"<?php
function run() {
    validate("t");
    $obj->process($data);
}
"#;
        let facts = PhpExtractor.extract(src, "src/main.php").unwrap();
        let names: Vec<&str> = facts.references.iter().map(|r| r.name.as_str()).collect();
        assert!(
            names.contains(&"validate"),
            "expected 'validate' in {names:?}"
        );
        assert!(
            names.contains(&"process"),
            "expected 'process' in {names:?}"
        );
    }
}
