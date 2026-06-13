// SPDX-License-Identifier: Apache-2.0

//! C extractor — one tree-sitter pass yielding definitions and references.
//!
//! Definitions: top-level **non-static** declarations. Covers functions,
//! variables, struct/union/enum type definitions, typedefs, and preprocessor
//! macros (`#define`). Qualified identity is derived from the file path
//! (`src/auth/token.c` → namespaces `auth`, `token`). The same
//! stem is shared by `.c` and `.h` files so paired translation units share a
//! namespace.
//! References: callee identifiers of `call_expression` nodes.
//!
//! Emits neutral [`FileFacts`] — no storage entries, no source bodies.

use tree_sitter::{Language as TsLanguage, Node, Parser};

use crate::error::{CodegraphError, Result};
use crate::graph::types::{ByteSpan, FileFacts, Symbol, SymbolKind};
use crate::lang::Language;
use crate::symbol::{Descriptor, SymbolId};

use super::{
    Extractor, collect_call_references, field_text, is_static, node_text, one_line_signature,
};

// NOTE: SymbolKind has no Union or Macro variants; unions map to Struct,
// and preprocessor macros use Descriptor::Macro for SCIP identity (which
// renders with `!`), paired with SymbolKind::Const or SymbolKind::Function.

/// Tree-sitter query capturing call-callee identifiers.
const CALL_QUERY: &str = r#"
(call_expression
  function: (identifier) @callee
)
"#;

/// Extracts C symbols and references.
pub struct CExtractor;

impl Extractor for CExtractor {
    fn lang(&self) -> Language {
        Language::C
    }

    fn extract(&self, source: &str, file: &str) -> Result<FileFacts> {
        let ts_language = TsLanguage::from(tree_sitter_c::LANGUAGE);
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
        let namespaces = c_namespaces(file);

        let symbols = collect_symbols(&root, bytes, file, &namespaces);
        let references =
            collect_call_references(&root, &ts_language, CALL_QUERY, Language::C, bytes, file)?;

        Ok(FileFacts {
            file: file.to_owned(),
            lang: Language::C.as_str().to_owned(),
            symbols,
            references,
        })
    }
}

/// Derive the C namespace path from a file path.
///
/// Strips the `.c` or `.h` extension, strips a leading `src/` prefix, then
/// splits on `/`. The file stem is kept as the last namespace segment. Paired
/// `.c`/`.h` files intentionally share a namespace via the common stem.
fn c_namespaces(file: &str) -> Vec<String> {
    let p = file
        .strip_suffix(".c")
        .or_else(|| file.strip_suffix(".h"))
        .unwrap_or(file);
    let p = p.strip_prefix("src/").unwrap_or(p);
    p.split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Walk a declarator subtree to the inner name identifier; returns `(name, is_function)`.
///
/// C nests names arbitrarily deep inside declarator chains:
/// `*(*fn)(int)` → `pointer_declarator` → `parenthesized_declarator` →
/// `function_declarator` → `pointer_declarator` → `identifier`.
/// `is_function` is `true` only when a `function_declarator` is encountered on
/// the path, distinguishing function declarations from variable declarations.
fn declarator_name(node: &Node, bytes: &[u8]) -> Option<(String, bool)> {
    match node.kind() {
        "identifier" | "type_identifier" | "field_identifier" => {
            Some((node_text(node, bytes).to_owned(), false))
        }
        "function_declarator" => {
            let inner = node.child_by_field_name("declarator")?;
            let (name, _) = declarator_name(&inner, bytes)?;
            Some((name, true))
        }
        _ => {
            // pointer_declarator / init_declarator / array_declarator /
            // attributed_declarator — all expose a "declarator" named field.
            if let Some(d) = node.child_by_field_name("declarator") {
                return declarator_name(&d, bytes);
            }
            // parenthesized_declarator has no named field — scan children.
            for c in node.children(&mut node.walk()) {
                if let Some(r) = declarator_name(&c, bytes) {
                    return Some(r);
                }
            }
            None
        }
    }
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
                id: SymbolId::global(Language::C.as_str(), descriptors),
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
        };

    for child in root.children(&mut root.walk()) {
        match child.kind() {
            "function_definition" => {
                if is_static(&child, bytes) {
                    continue;
                }
                let Some(decl) = child.child_by_field_name("declarator") else {
                    continue;
                };
                let Some((name, _)) = declarator_name(&decl, bytes) else {
                    continue;
                };
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

            "declaration" => {
                if is_static(&child, bytes) {
                    continue;
                }

                // Step 1: if the `type` field is a struct/union/enum WITH a body,
                // emit a type symbol for the aggregate definition itself.
                if let Some(spec) = child.child_by_field_name("type") {
                    if let Some((agg_kind, agg_name)) = aggregate_type_symbol(&spec, bytes) {
                        push(
                            &mut out,
                            &spec,
                            agg_name.clone(),
                            agg_kind,
                            Descriptor::Type(agg_name),
                        );
                    }
                }

                // Step 2: emit a symbol for each declarator in the declaration.
                let mut cursor = child.walk();
                for decl in child.children_by_field_name("declarator", &mut cursor) {
                    let Some((name, is_function)) = declarator_name(&decl, bytes) else {
                        continue;
                    };
                    if is_function {
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
                    } else {
                        push(
                            &mut out,
                            &child,
                            name.clone(),
                            SymbolKind::Static,
                            Descriptor::Term(name),
                        );
                    }
                }
            }

            "type_definition" => {
                // Step 1: if the `type` field is a named struct/union/enum WITH a body,
                // emit a type symbol for the aggregate.
                if let Some(spec) = child.child_by_field_name("type") {
                    if let Some((agg_kind, agg_name)) = aggregate_type_symbol(&spec, bytes) {
                        push(
                            &mut out,
                            &spec,
                            agg_name.clone(),
                            agg_kind,
                            Descriptor::Type(agg_name),
                        );
                    }
                }

                // Step 2: emit the typedef alias.
                let Some(decl) = child.child_by_field_name("declarator") else {
                    continue;
                };
                let Some((name, _)) = declarator_name(&decl, bytes) else {
                    continue;
                };
                push(
                    &mut out,
                    &child,
                    name.clone(),
                    SymbolKind::TypeAlias,
                    Descriptor::Type(name),
                );
            }

            "preproc_def" => {
                // Object-like macro: `#define NAME value`
                let Some(name) = field_text(&child, "name", bytes) else {
                    continue;
                };
                push(
                    &mut out,
                    &child,
                    name.clone(),
                    SymbolKind::Const,
                    Descriptor::Macro(name),
                );
            }

            "preproc_function_def" => {
                // Function-like macro: `#define NAME(args) body`
                let Some(name) = field_text(&child, "name", bytes) else {
                    continue;
                };
                push(
                    &mut out,
                    &child,
                    name.clone(),
                    SymbolKind::Function,
                    Descriptor::Macro(name),
                );
            }

            // A bare top-level `struct/union/enum Name { ... };` parses as the
            // specifier directly under `translation_unit` (no wrapping
            // `declaration`), so handle it here too.
            "struct_specifier" | "union_specifier" | "enum_specifier" => {
                if let Some((agg_kind, agg_name)) = aggregate_type_symbol(&child, bytes) {
                    push(
                        &mut out,
                        &child,
                        agg_name.clone(),
                        agg_kind,
                        Descriptor::Type(agg_name),
                    );
                }
            }

            _ => continue,
        }
    }
    out
}

/// If `spec` is a `struct_specifier`, `union_specifier`, or `enum_specifier`
/// that has both a `name` field AND a `body` child (meaning it is a definition,
/// not a bare forward reference), return `(SymbolKind, name)`.
fn aggregate_type_symbol(spec: &Node, bytes: &[u8]) -> Option<(SymbolKind, String)> {
    let kind = match spec.kind() {
        "struct_specifier" => SymbolKind::Struct,
        // NOTE: no Union variant — unions map to Struct.
        "union_specifier" => SymbolKind::Struct,
        "enum_specifier" => SymbolKind::Enum,
        _ => return None,
    };
    // Must have a body (i.e. this is a definition, not just a reference).
    let has_body = spec
        .children(&mut spec.walk())
        .any(|c| matches!(c.kind(), "field_declaration_list" | "enumerator_list"));
    if !has_body {
        return None;
    }
    let name = field_text(spec, "name", bytes)?;
    Some((kind, name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_defs_and_skips_static() {
        let src = r#"
#define MAX_LEN 256
int authenticate(const char *tok) { return validate(tok); }
static int helper(void) { return 0; }
struct Session { int id; };
enum Status { OK, FAIL };
typedef struct Session SessionRef;
int global_count;
static int private_count;
"#;
        let facts = CExtractor.extract(src, "src/auth/token.c").unwrap();
        let by_name = |n: &str| facts.symbols.iter().find(|s| s.name == n).cloned();

        // authenticate: exported function
        let auth = by_name("authenticate").unwrap();
        assert_eq!(auth.kind, SymbolKind::Function);
        assert_eq!(
            auth.id.to_scip_string(),
            "codegraph    auth/token/authenticate()."
        );

        // helper: static — must be absent
        assert!(by_name("helper").is_none());

        // Session: struct definition inside a declaration
        let session = by_name("Session").unwrap();
        assert_eq!(session.kind, SymbolKind::Struct);
        assert_eq!(
            session.id.to_scip_string(),
            "codegraph    auth/token/Session#"
        );

        // Status: enum definition inside a declaration
        let status = by_name("Status").unwrap();
        assert_eq!(status.kind, SymbolKind::Enum);
        assert_eq!(
            status.id.to_scip_string(),
            "codegraph    auth/token/Status#"
        );

        // SessionRef: typedef alias
        let alias = by_name("SessionRef").unwrap();
        assert_eq!(alias.kind, SymbolKind::TypeAlias);
        assert_eq!(
            alias.id.to_scip_string(),
            "codegraph    auth/token/SessionRef#"
        );

        // global_count: non-static variable
        let gc = by_name("global_count").unwrap();
        assert_eq!(gc.kind, SymbolKind::Static);
        assert_eq!(
            gc.id.to_scip_string(),
            "codegraph    auth/token/global_count."
        );

        // private_count: static — must be absent
        assert!(by_name("private_count").is_none());

        // MAX_LEN: object-like macro → Const
        let max = by_name("MAX_LEN").unwrap();
        assert_eq!(max.kind, SymbolKind::Const);
        assert_eq!(max.id.to_scip_string(), "codegraph    auth/token/MAX_LEN!");

        assert_eq!(facts.lang, "c");
    }

    #[test]
    fn function_macro_and_prototype() {
        let src = r#"
#define SQUARE(x) ((x)*(x))
int compute(int n);
"#;
        let facts = CExtractor.extract(src, "src/util.h").unwrap();
        let by_name = |n: &str| facts.symbols.iter().find(|s| s.name == n).cloned();

        // SQUARE: function-like macro → Function + Descriptor::Macro
        let sq = by_name("SQUARE").unwrap();
        assert_eq!(sq.kind, SymbolKind::Function);
        assert_eq!(sq.id.to_scip_string(), "codegraph    util/SQUARE!");

        // compute: function prototype in a declaration
        let comp = by_name("compute").unwrap();
        assert_eq!(comp.kind, SymbolKind::Function);
        assert_eq!(comp.id.to_scip_string(), "codegraph    util/compute().");
    }

    #[test]
    fn extracts_call_references() {
        let src = r#"
int main(void) {
    authenticate("t");
    compute(5);
}
"#;
        let facts = CExtractor.extract(src, "src/main.c").unwrap();
        let names: Vec<&str> = facts.references.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"authenticate"));
        assert!(names.contains(&"compute"));
    }
}
