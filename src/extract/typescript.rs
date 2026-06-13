// SPDX-License-Identifier: Apache-2.0

//! TypeScript extractor — one tree-sitter pass yielding definitions and references.
//!
//! Definitions: top-level **exported** declarations (`export function/class/
//! interface/type/enum/const`, including `export default function/class`).
//! Qualified identity follows the file's module path (`src/auth/jwt.ts` →
//! namespaces `src`,`auth`,`jwt`), so a symbol is `…/jwt/validateToken().`.
//! References: callee identifiers of `call_expression` nodes.
//!
//! `.tsx` files are parsed with the TSX grammar, `.ts` with TypeScript.
//! Emits neutral [`FileFacts`] — no storage entries, no source bodies.

use tree_sitter::{Language as TsLanguage, Node, Parser, Query, QueryCursor, StreamingIterator};

use crate::error::{CodegraphError, Result};
use crate::graph::types::{ByteSpan, FileFacts, Occurrence, RefRole, Reference, Symbol, SymbolKind};
use crate::lang::Language;
use crate::symbol::{Descriptor, SymbolId};

use super::{node_text, one_line_signature, Extractor};

/// Minimum callee-name length to record as a reference.
const MIN_REF_LEN: usize = 3;

/// Extracts TypeScript symbols and references.
pub struct TypeScriptExtractor;

impl Extractor for TypeScriptExtractor {
    fn lang(&self) -> Language {
        Language::TypeScript
    }

    fn extract(&self, source: &str, file: &str) -> Result<FileFacts> {
        let ts_lang = if file.ends_with(".tsx") {
            tree_sitter_typescript::LANGUAGE_TSX
        } else {
            tree_sitter_typescript::LANGUAGE_TYPESCRIPT
        };

        let mut parser = Parser::new();
        parser
            .set_language(&TsLanguage::from(ts_lang))
            .map_err(|_| CodegraphError::Parse {
                path: file.to_owned(),
            })?;
        let tree = parser.parse(source, None).ok_or_else(|| CodegraphError::Parse {
            path: file.to_owned(),
        })?;

        let root = tree.root_node();
        let bytes = source.as_bytes();
        let namespaces = ts_namespaces(file);

        let symbols = collect_symbols(&root, bytes, file, &namespaces);
        let references = collect_references(&root, &TsLanguage::from(ts_lang), bytes, file)?;

        Ok(FileFacts {
            file: file.to_owned(),
            lang: Language::TypeScript.as_str().to_owned(),
            symbols,
            references,
        })
    }
}

/// Module path (namespace descriptors) from a TS file path: all segments, with
/// the `.ts`/`.tsx` extension stripped from the last.
fn ts_namespaces(file: &str) -> Vec<String> {
    let mut parts: Vec<String> = file
        .split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    if let Some(last) = parts.pop() {
        let stem = last
            .strip_suffix(".tsx")
            .or_else(|| last.strip_suffix(".ts"))
            .unwrap_or(&last);
        parts.push(stem.to_owned());
    }
    parts
}

fn collect_symbols(root: &Node, bytes: &[u8], file: &str, namespaces: &[String]) -> Vec<Symbol> {
    let mut out = Vec::new();
    for stmt in root.children(&mut root.walk()) {
        if stmt.kind() != "export_statement" {
            continue;
        }
        // The exported declaration is a direct child of the export statement.
        for decl in stmt.children(&mut stmt.walk()) {
            emit_declaration(&decl, &stmt, bytes, file, namespaces, &mut out);
        }
    }
    out
}

/// Append symbol(s) for one declaration node (a `lexical_declaration` may yield
/// several). `span_node` is the enclosing `export_statement`.
fn emit_declaration(
    decl: &Node,
    span_node: &Node,
    bytes: &[u8],
    file: &str,
    namespaces: &[String],
    out: &mut Vec<Symbol>,
) {
    let push = |out: &mut Vec<Symbol>, name: String, kind: SymbolKind, leaf: Descriptor| {
        let mut descriptors: Vec<Descriptor> =
            namespaces.iter().cloned().map(Descriptor::Namespace).collect();
        descriptors.push(leaf);
        out.push(Symbol {
            id: SymbolId::global(Language::TypeScript.as_str(), descriptors),
            name,
            kind,
            file: file.to_owned(),
            line: (span_node.start_position().row + 1) as u32,
            span: ByteSpan {
                start: span_node.start_byte(),
                end: span_node.end_byte(),
            },
            signature: one_line_signature(node_text(decl, bytes), &['{']),
        });
    };

    match decl.kind() {
        "function_declaration" => {
            if let Some(n) = ident_child(decl, "identifier", bytes) {
                push(
                    out,
                    n.clone(),
                    SymbolKind::Function,
                    Descriptor::Method {
                        name: n,
                        disambiguator: String::new(),
                    },
                );
            }
        }
        "class_declaration" => emit_named(decl, bytes, SymbolKind::Class, out, &push),
        "interface_declaration" => emit_named(decl, bytes, SymbolKind::Interface, out, &push),
        "type_alias_declaration" => emit_named(decl, bytes, SymbolKind::TypeAlias, out, &push),
        "enum_declaration" => {
            if let Some(n) = ident_child(decl, "identifier", bytes) {
                push(out, n.clone(), SymbolKind::Enum, Descriptor::Type(n));
            }
        }
        "lexical_declaration" => {
            for vd in decl.children(&mut decl.walk()) {
                if vd.kind() != "variable_declarator" {
                    continue;
                }
                if let Some(n) = ident_child(&vd, "identifier", bytes) {
                    push(out, n.clone(), SymbolKind::Const, Descriptor::Term(n));
                }
            }
        }
        _ => {}
    }
}

/// Emit a type-named declaration (class/interface/type-alias) named by a
/// `type_identifier`.
fn emit_named(
    decl: &Node,
    bytes: &[u8],
    kind: SymbolKind,
    out: &mut Vec<Symbol>,
    push: &impl Fn(&mut Vec<Symbol>, String, SymbolKind, Descriptor),
) {
    if let Some(n) = ident_child(decl, "type_identifier", bytes) {
        push(out, n.clone(), kind, Descriptor::Type(n));
    }
}

/// Text of the first direct child of the given kind.
fn ident_child(node: &Node, kind: &str, bytes: &[u8]) -> Option<String> {
    node.children(&mut node.walk())
        .find(|c| c.kind() == kind)
        .map(|c| node_text(&c, bytes).to_owned())
}

fn collect_references(
    root: &Node,
    lang: &TsLanguage,
    bytes: &[u8],
    file: &str,
) -> Result<Vec<Reference>> {
    let query_src = r#"
(call_expression
  function: [
    (identifier) @callee
    (member_expression property: (property_identifier) @callee)
  ]
)
"#;
    let query = Query::new(lang, query_src).map_err(|e| CodegraphError::Query {
        lang: "typescript".to_owned(),
        msg: e.to_string(),
    })?;
    let callee_idx = query
        .capture_index_for_name("callee")
        .ok_or_else(|| CodegraphError::Query {
            lang: "typescript".to_owned(),
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
    fn extracts_exported_decls() {
        let src = "\
export function validateToken(tok: string): boolean { return helper(); }
export class Config {}
export interface Options { timeout: number; }
export const MAX = 3;
function internal() {}
";
        let facts = TypeScriptExtractor.extract(src, "src/auth/jwt.ts").unwrap();
        let by_name = |n: &str| facts.symbols.iter().find(|s| s.name == n).cloned();

        let vt = by_name("validateToken").unwrap();
        assert_eq!(vt.id.to_scip_string(), "codegraph    src/auth/jwt/validateToken().");
        assert_eq!(vt.kind, SymbolKind::Function);

        assert_eq!(by_name("Config").unwrap().kind, SymbolKind::Class);
        assert_eq!(by_name("Options").unwrap().kind, SymbolKind::Interface);
        assert_eq!(by_name("MAX").unwrap().kind, SymbolKind::Const);
        // non-exported declarations are not symbols
        assert!(by_name("internal").is_none());
    }

    #[test]
    fn default_export_function_is_named() {
        let facts = TypeScriptExtractor
            .extract("export default function App() {}", "src/App.tsx")
            .unwrap();
        assert_eq!(facts.symbols.len(), 1);
        assert_eq!(facts.symbols[0].name, "App");
        assert_eq!(facts.symbols[0].id.to_scip_string(), "codegraph    src/App/App().");
    }

    #[test]
    fn extracts_call_references() {
        let facts = TypeScriptExtractor
            .extract("function main() { validateToken('t'); helper(); }", "src/main.ts")
            .unwrap();
        let names: Vec<&str> = facts.references.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"validateToken"));
        assert!(names.contains(&"helper"));
    }
}
