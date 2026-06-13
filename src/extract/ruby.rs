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
//! References: callee identifiers of `(call method: (identifier) @callee)` nodes.

use tree_sitter::{Language as TsLanguage, Node, Parser};

use crate::error::{CodegraphError, Result};
use crate::graph::types::{ByteSpan, FileFacts, RefRole, Reference, Symbol, SymbolKind};
use crate::lang::Language;
use crate::symbol::{Descriptor, SymbolId};

use super::{Extractor, collect_call_references, field_text, node_text, one_line_signature};

/// Tree-sitter query capturing explicit call-callee identifiers.
const CALL_QUERY: &str = r#"
(call
  method: (identifier) @callee)
"#;

/// Extracts Ruby symbols and references.
pub struct RubyExtractor;

impl Extractor for RubyExtractor {
    fn lang(&self) -> Language {
        Language::Ruby
    }

    fn extract(&self, source: &str, file: &str) -> Result<FileFacts> {
        let ts_language = TsLanguage::from(tree_sitter_ruby::LANGUAGE);
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

        let ns_strings = ruby_namespaces(file);
        let namespaces: Vec<Descriptor> = ns_strings
            .iter()
            .cloned()
            .map(Descriptor::Namespace)
            .collect();

        let mut symbols = Vec::new();
        walk(&root, &namespaces, bytes, file, &mut symbols);
        symbols.push(super::module_symbol(
            Language::Ruby,
            &ns_strings,
            file,
            source.len(),
        ));

        let mut references =
            collect_call_references(&root, &ts_language, CALL_QUERY, Language::Ruby, bytes, file)?;
        collect_inheritance(&root, bytes, file, &mut references);

        Ok(FileFacts {
            file: file.to_owned(),
            lang: Language::Ruby.as_str().to_owned(),
            symbols,
            references,
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
fn walk(node: &Node, prefix: &[Descriptor], bytes: &[u8], file: &str, out: &mut Vec<Symbol>) {
    for child in node.children(&mut node.walk()) {
        match child.kind() {
            "class" | "module" => {
                let Some(name) = field_text(&child, "name", bytes) else {
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
                    push_symbol(out, &child, name, kind, descriptors.clone(), bytes, file);
                    walk(&body, &descriptors, bytes, file, out);
                } else {
                    push_symbol(out, &child, name, kind, descriptors, bytes, file);
                }
            }
            "method" | "singleton_method" => {
                let Some(name) = field_text(&child, "name", bytes) else {
                    continue;
                };
                let mut descriptors = prefix.to_vec();
                descriptors.push(Descriptor::Method {
                    name: name.clone(),
                    disambiguator: String::new(),
                });
                push_symbol(
                    out,
                    &child,
                    name,
                    SymbolKind::Method,
                    descriptors,
                    bytes,
                    file,
                );
                // Do not recurse into method bodies — inner defs would produce
                // misleading qualified names and are not top-level API surface.
            }
            "assignment" => {
                // Constant assignment: the left-hand side is a `constant` node.
                if let Some(left) = child.child_by_field_name("left") {
                    if left.kind() == "constant" {
                        let name = node_text(&left, bytes).to_owned();
                        let mut descriptors = prefix.to_vec();
                        descriptors.push(Descriptor::Term(name.clone()));
                        push_symbol(
                            out,
                            &child,
                            name,
                            SymbolKind::Const,
                            descriptors,
                            bytes,
                            file,
                        );
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
    node: &Node,
    name: String,
    kind: SymbolKind,
    descriptors: Vec<Descriptor>,
    bytes: &[u8],
    file: &str,
) {
    out.push(Symbol {
        id: SymbolId::global(Language::Ruby.as_str(), descriptors),
        name,
        kind,
        file: file.to_owned(),
        line: (node.start_position().row + 1) as u32,
        span: ByteSpan {
            start: node.start_byte(),
            end: node.end_byte(),
        },
        // Empty stop slice → first-line fallback, which is correct for Ruby's
        // `end`-terminated blocks (no `{` to split on).
        signature: one_line_signature(node_text(node, bytes), &[]),
    });
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
                    RefRole::Inherit,
                );
            }
        }
    }

    // Recurse into all children so nested classes are covered.
    for child in node.children(&mut node.walk()) {
        collect_inheritance(&child, bytes, file, out);
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
        assert_eq!(auth.id.to_scip_string(), "codegraph    auth/session/Auth#");

        let session = by_name("Session").unwrap();
        assert_eq!(session.kind, SymbolKind::Class);
        assert_eq!(
            session.id.to_scip_string(),
            "codegraph    auth/session/Auth#Session#"
        );

        let max = by_name("MAX").unwrap();
        assert_eq!(max.kind, SymbolKind::Const);
        assert_eq!(
            max.id.to_scip_string(),
            "codegraph    auth/session/Auth#Session#MAX."
        );

        let validate = by_name("validate").unwrap();
        assert_eq!(validate.kind, SymbolKind::Method);
        assert_eq!(
            validate.id.to_scip_string(),
            "codegraph    auth/session/Auth#Session#validate()."
        );

        let create = by_name("create").unwrap();
        assert_eq!(create.kind, SymbolKind::Method);
        assert_eq!(
            create.id.to_scip_string(),
            "codegraph    auth/session/Auth#Session#create()."
        );

        let top = by_name("TOP").unwrap();
        assert_eq!(top.kind, SymbolKind::Const);
        assert_eq!(top.id.to_scip_string(), "codegraph    auth/session/TOP.");

        let helper = by_name("helper").unwrap();
        assert_eq!(helper.kind, SymbolKind::Method);
        assert_eq!(
            helper.id.to_scip_string(),
            "codegraph    auth/session/helper()."
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
    fn extracts_simple_inheritance() {
        let src = "class Foo < Bar\nend\n";
        let facts = RubyExtractor.extract(src, "lib/foo.rb").unwrap();
        let inherit: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Inherit)
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
            .filter(|r| r.role == RefRole::Inherit)
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
            .filter(|r| r.role == RefRole::Inherit)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            inherit.is_empty(),
            "expected no Inherit refs, got {inherit:?}"
        );
    }
}
