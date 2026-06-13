// SPDX-License-Identifier: Apache-2.0

//! Go extractor — one tree-sitter pass yielding definitions and references.
//!
//! Definitions: top-level **exported** declarations (first character of the
//! name is uppercase). Covers `func`, methods, `type` (struct/interface/alias),
//! `const`, and `var`. Qualified identity follows the package path derived from
//! the file path (`src/auth/session.go` → namespaces `auth`,`session`).
//! References: callee identifiers of `call_expression` nodes.
//!
//! Emits neutral [`FileFacts`] — no storage entries, no source bodies.

use tree_sitter::{Language as TsLanguage, Node, Parser};

use crate::error::{CodegraphError, Result};
use crate::graph::types::{ByteSpan, FileFacts, RefRole, Reference, Symbol, SymbolKind};
use crate::lang::Language;
use crate::symbol::{Descriptor, SymbolId};

use super::{
    Extractor, collect_call_references, field_text, node_text, one_line_signature, push_ref,
    simple_type_name,
};

/// Tree-sitter query capturing call-callee identifiers.
const CALL_QUERY: &str = r#"
(call_expression
  function: [
    (identifier) @callee
    (selector_expression field: (field_identifier) @callee)
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
        let ts_language = TsLanguage::from(tree_sitter_go::LANGUAGE);
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
        let namespaces = go_namespaces(file);

        let mut symbols = collect_symbols(&root, bytes, file, &namespaces);
        symbols.push(super::module_symbol(
            Language::Go,
            &namespaces,
            file,
            source.len(),
        ));
        let mut references =
            collect_call_references(&root, &ts_language, CALL_QUERY, Language::Go, bytes, file)?;
        collect_imports(&root, bytes, file, &mut references);

        Ok(FileFacts {
            file: file.to_owned(),
            lang: Language::Go.as_str().to_owned(),
            symbols,
            references,
        })
    }
}

/// Derive the Go package path (namespace descriptors) from a file path.
///
/// Strips the `.go` extension, strips a leading `src/` prefix, then splits on
/// `/`. The file stem is kept as the last namespace segment (no `main` drop).
fn go_namespaces(file: &str) -> Vec<String> {
    let p = file.strip_suffix(".go").unwrap_or(file);
    let p = p.strip_prefix("src/").unwrap_or(p);
    p.split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

fn collect_symbols(root: &Node, bytes: &[u8], file: &str, namespaces: &[String]) -> Vec<Symbol> {
    let mut out = Vec::new();

    let push =
        |out: &mut Vec<Symbol>, node: &Node, name: String, kind: SymbolKind, leaf: Descriptor| {
            let mut descriptors: Vec<Descriptor> = namespaces
                .iter()
                .cloned()
                .map(Descriptor::Namespace)
                .collect();
            descriptors.push(leaf);
            out.push(Symbol {
                id: SymbolId::global(Language::Go.as_str(), descriptors),
                name,
                kind,
                file: file.to_owned(),
                line: (node.start_position().row + 1) as u32,
                span: ByteSpan {
                    start: node.start_byte(),
                    end: node.end_byte(),
                },
                signature: one_line_signature(node_text(node, bytes), &['{']),
            });
        };

    for child in root.children(&mut root.walk()) {
        match child.kind() {
            "function_declaration" => {
                let Some(name) = field_text(&child, "name", bytes) else {
                    continue;
                };
                if !is_exported(&name) {
                    continue;
                }
                push(
                    &mut out,
                    &child,
                    name.clone(),
                    SymbolKind::Function,
                    Descriptor::Method {
                        name,
                        disambiguator: String::new(),
                    },
                );
            }
            "method_declaration" => {
                let Some(name) = field_text(&child, "name", bytes) else {
                    continue;
                };
                if !is_exported(&name) {
                    continue;
                }
                push(
                    &mut out,
                    &child,
                    name.clone(),
                    SymbolKind::Method,
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
                            let Some(name) = field_text(&spec, "name", bytes) else {
                                continue;
                            };
                            if !is_exported(&name) {
                                continue;
                            }
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
                            let Some(name) = field_text(&spec, "name", bytes) else {
                                continue;
                            };
                            if !is_exported(&name) {
                                continue;
                            }
                            (SymbolKind::TypeAlias, name)
                        }
                        _ => continue,
                    };
                    push(&mut out, &spec, name.clone(), kind, Descriptor::Type(name));
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
                        let name = node_text(&ident, bytes).to_owned();
                        if !is_exported(&name) {
                            continue;
                        }
                        push(
                            &mut out,
                            &spec,
                            name.clone(),
                            SymbolKind::Const,
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
                        let name = node_text(&ident, bytes).to_owned();
                        if !is_exported(&name) {
                            continue;
                        }
                        push(
                            &mut out,
                            &spec,
                            name.clone(),
                            SymbolKind::Static,
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

/// True if the identifier is exported (first character is uppercase).
fn is_exported(name: &str) -> bool {
    name.chars().next().is_some_and(|c| c.is_uppercase())
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
        assert_eq!(
            vt.id.to_scip_string(),
            "codegraph    auth/session/Validate()."
        );
        assert_eq!(vt.kind, SymbolKind::Function);

        assert_eq!(by_name("Config").unwrap().kind, SymbolKind::Struct);
        assert_eq!(by_name("Reader").unwrap().kind, SymbolKind::Interface);
        assert_eq!(by_name("Max").unwrap().kind, SymbolKind::Const);

        // unexported — must not appear
        assert!(by_name("helper").is_none());

        assert_eq!(facts.lang, "go");
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
        assert_eq!(start.id.to_scip_string(), "codegraph    run/Start().");
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
}
