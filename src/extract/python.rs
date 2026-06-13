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

use tree_sitter::{Language as TsLanguage, Node, Parser, Query, QueryCursor, StreamingIterator};

use crate::error::{CodegraphError, Result};
use crate::graph::types::{ByteSpan, FileFacts, Occurrence, RefRole, Reference, Symbol, SymbolKind};
use crate::lang::Language;
use crate::symbol::{Descriptor, SymbolId};

use super::{node_text, one_line_signature, Extractor};

/// Minimum callee-name length to record as a reference.
const MIN_REF_LEN: usize = 3;

/// Extracts Python symbols and references.
pub struct PythonExtractor;

impl Extractor for PythonExtractor {
    fn lang(&self) -> Language {
        Language::Python
    }

    fn extract(&self, source: &str, file: &str) -> Result<FileFacts> {
        let mut parser = Parser::new();
        parser
            .set_language(&TsLanguage::from(tree_sitter_python::LANGUAGE))
            .map_err(|_| CodegraphError::Parse {
                path: file.to_owned(),
            })?;
        let tree = parser.parse(source, None).ok_or_else(|| CodegraphError::Parse {
            path: file.to_owned(),
        })?;

        let root = tree.root_node();
        let bytes = source.as_bytes();
        let namespaces = python_namespaces(file);

        let symbols = collect_symbols(&root, bytes, file, &namespaces);
        let references = collect_references(&root, bytes, file)?;

        Ok(FileFacts {
            file: file.to_owned(),
            lang: Language::Python.as_str().to_owned(),
            symbols,
            references,
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

fn collect_symbols(root: &Node, bytes: &[u8], file: &str, namespaces: &[String]) -> Vec<Symbol> {
    let mut out = Vec::new();
    for child in root.children(&mut root.walk()) {
        // (span node, signature node, name, kind, leaf descriptor)
        let parsed = match child.kind() {
            "function_definition" => def_of(&child, &child, bytes, true),
            "class_definition" => def_of(&child, &child, bytes, false),
            "decorated_definition" => {
                let Some(inner) = child
                    .children(&mut child.walk())
                    .find(|c| matches!(c.kind(), "function_definition" | "class_definition"))
                else {
                    continue;
                };
                let is_fn = inner.kind() == "function_definition";
                // span includes decorators (outer node); signature is the def line.
                def_of(&child, &inner, bytes, is_fn)
            }
            "expression_statement" | "assignment" => const_of(&child, bytes),
            _ => None,
        };
        let Some((span_node, sig_node, name, kind, leaf)) = parsed else {
            continue;
        };

        let mut descriptors: Vec<Descriptor> =
            namespaces.iter().cloned().map(Descriptor::Namespace).collect();
        descriptors.push(leaf);

        out.push(Symbol {
            id: SymbolId::global(Language::Python.as_str(), descriptors),
            name,
            kind,
            file: file.to_owned(),
            line: (span_node.start_position().row + 1) as u32,
            span: ByteSpan {
                start: span_node.start_byte(),
                end: span_node.end_byte(),
            },
            signature: one_line_signature(node_text(&sig_node, bytes), &[':']),
        });
    }
    out
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
                disambiguator: String::new(),
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
    if name.len() < 3 || !name.chars().all(|c| c.is_uppercase() || c == '_' || c.is_numeric()) {
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

fn collect_references(root: &Node, bytes: &[u8], file: &str) -> Result<Vec<Reference>> {
    let query_src = r#"
(call
  function: [
    (identifier) @callee
    (attribute attribute: (identifier) @callee)
  ]
)
"#;
    let lang = TsLanguage::from(tree_sitter_python::LANGUAGE);
    let query = Query::new(&lang, query_src).map_err(|e| CodegraphError::Query {
        lang: "python".to_owned(),
        msg: e.to_string(),
    })?;
    let callee_idx = query
        .capture_index_for_name("callee")
        .ok_or_else(|| CodegraphError::Query {
            lang: "python".to_owned(),
            msg: "missing @callee capture".to_owned(),
        })?;

    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&query, *root, bytes);
    let mut refs = Vec::new();
    while let Some(m) = matches.next() {
        for cap in m.captures.iter().filter(|c| c.index == callee_idx) {
            let name = node_text(&cap.node, bytes).to_owned();
            if name.len() < MIN_REF_LEN {
                continue;
            }
            refs.push(Reference {
                name,
                occ: Occurrence {
                    file: file.to_owned(),
                    line: (cap.node.start_position().row + 1) as u32,
                    col: cap.node.start_position().column as u32,
                    byte: cap.node.start_byte(),
                },
                role: RefRole::Call,
            });
        }
    }
    Ok(refs)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(vt.id.to_scip_string(), "codegraph    auth/jwt/validate_token().");
        assert_eq!(vt.kind, SymbolKind::Function);

        assert_eq!(by_name("Config").unwrap().kind, SymbolKind::Class);
        assert!(by_name("fetch_data").is_some());
        assert_eq!(by_name("MAX_RETRIES").unwrap().kind, SymbolKind::Const);
    }

    #[test]
    fn init_collapses_to_package() {
        let facts = PythonExtractor.extract("def helper(): pass", "src/auth/__init__.py").unwrap();
        assert_eq!(facts.symbols[0].id.to_scip_string(), "codegraph    auth/helper().");
    }

    #[test]
    fn extracts_call_references() {
        let facts = PythonExtractor
            .extract("def main():\n    validate_token('t')\n    helper()\n", "src/main.py")
            .unwrap();
        let names: Vec<&str> = facts.references.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"validate_token"));
        assert!(names.contains(&"helper"));
    }
}
