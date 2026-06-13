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

use tree_sitter::{Language as TsLanguage, Node, Parser};

use crate::error::{CodegraphError, Result};
use crate::graph::types::{ByteSpan, FileFacts, RefRole, Reference, Symbol, SymbolKind};
use crate::lang::Language;
use crate::symbol::{Descriptor, SymbolId};

use super::{Extractor, collect_call_references, field_text, node_text, one_line_signature};

/// Tree-sitter query capturing call-callee identifiers.
const CALL_QUERY: &str = r#"
(call
  function: [
    (identifier) @callee
    (attribute attribute: (identifier) @callee)
  ]
)
"#;

/// Extracts Python symbols and references.
pub struct PythonExtractor;

impl Extractor for PythonExtractor {
    fn lang(&self) -> Language {
        Language::Python
    }

    fn extract(&self, source: &str, file: &str) -> Result<FileFacts> {
        let ts_language = TsLanguage::from(tree_sitter_python::LANGUAGE);
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
        let namespaces = python_namespaces(file);

        let mut symbols = collect_symbols(&root, bytes, file, &namespaces);
        symbols.push(super::module_symbol(
            Language::Python,
            &namespaces,
            file,
            source.len(),
        ));
        let mut references = collect_call_references(
            &root,
            &ts_language,
            CALL_QUERY,
            Language::Python,
            bytes,
            file,
        )?;
        collect_inheritance(&root, bytes, file, &mut references);
        collect_imports(&root, bytes, file, &mut references);

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

        let mut descriptors: Vec<Descriptor> = namespaces
            .iter()
            .cloned()
            .map(Descriptor::Namespace)
            .collect();
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
    if name.len() < 3
        || !name
            .chars()
            .all(|c| c.is_uppercase() || c == '_' || c.is_numeric())
    {
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

/// Recursively walk `node` collecting `Import` references for every
/// `import_statement` and `import_from_statement` in the tree (covers top-level
/// and function-local imports; both attribute correctly via span-containment in
/// the resolver).
///
/// Rules:
/// - `import_statement`'s `name` field children are the imported names.
/// - `import_from_statement`'s `name` field children are the *imported symbols*
///   (not the `module_name` of the from-clause).
/// - For a `dotted_name` child: emit the leaf segment (last `.`-separated part).
/// - For an `aliased_import` child: emit the leaf of its `name` field (the real
///   name), ignoring the `alias` field.
/// - `wildcard_import` children (`from x import *`) produce no reference.
fn collect_imports(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    match node.kind() {
        "import_statement" | "import_from_statement" => {
            for child in node.children_by_field_name("name", &mut node.walk()) {
                match child.kind() {
                    "dotted_name" => {
                        let text = node_text(&child, bytes);
                        let leaf = super::simple_type_name(text, ".");
                        super::push_ref(out, leaf, &child, file, RefRole::Import);
                    }
                    "aliased_import" => {
                        // Take the real `name` field (a `dotted_name`), ignore `alias`.
                        if let Some(name_node) = child.child_by_field_name("name") {
                            let text = node_text(&name_node, bytes);
                            let leaf = super::simple_type_name(text, ".");
                            super::push_ref(out, leaf, &name_node, file, RefRole::Import);
                        }
                    }
                    // wildcard_import and anything else produce nothing.
                    _ => {}
                }
            }
        }
        _ => {}
    }

    // Recurse into all children to cover nested/local imports.
    for child in node.children(&mut node.walk()) {
        collect_imports(&child, bytes, file, out);
    }
}

/// Recursively walk `node` collecting `Inherit` references for every
/// `class_definition` in the tree (including nested classes).
///
/// For each class that has a `superclasses` field (an `argument_list`), we
/// iterate its named children and handle:
/// - `identifier` — simple base name (e.g. `Base`).
/// - `attribute`  — dotted base; we take the `attribute` field (leaf segment,
///   e.g. `mod.Base` → `Base`).
///
/// Everything else (`subscript` for `Generic[T]`, `call`, `keyword_argument`
/// for `metaclass=`) is skipped gracefully.
fn collect_inheritance(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    if node.kind() == "class_definition" {
        if let Some(superclasses) = node.child_by_field_name("superclasses") {
            for child in superclasses.children(&mut superclasses.walk()) {
                if !child.is_named() {
                    continue;
                }
                match child.kind() {
                    "identifier" => {
                        super::push_ref(
                            out,
                            node_text(&child, bytes),
                            &child,
                            file,
                            RefRole::Inherit,
                        );
                    }
                    "attribute" => {
                        if let Some(name) = field_text(&child, "attribute", bytes) {
                            super::push_ref(out, &name, &child, file, RefRole::Inherit);
                        }
                    }
                    _ => {} // subscript (Generic[T]), call, keyword_argument, etc.
                }
            }
        }
    }

    // Recurse into all children so nested class definitions are covered.
    for child in node.children(&mut node.walk()) {
        collect_inheritance(&child, bytes, file, out);
    }
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
        assert_eq!(
            vt.id.to_scip_string(),
            "codegraph . . . auth/jwt/validate_token()."
        );
        assert_eq!(vt.kind, SymbolKind::Function);

        assert_eq!(by_name("Config").unwrap().kind, SymbolKind::Class);
        assert!(by_name("fetch_data").is_some());
        assert_eq!(by_name("MAX_RETRIES").unwrap().kind, SymbolKind::Const);
    }

    #[test]
    fn init_collapses_to_package() {
        let facts = PythonExtractor
            .extract("def helper(): pass", "src/auth/__init__.py")
            .unwrap();
        assert_eq!(
            facts.symbols[0].id.to_scip_string(),
            "codegraph . . . auth/helper()."
        );
    }

    #[test]
    fn extracts_call_references() {
        let facts = PythonExtractor
            .extract(
                "def main():\n    validate_token('t')\n    helper()\n",
                "src/main.py",
            )
            .unwrap();
        let names: Vec<&str> = facts.references.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"validate_token"));
        assert!(names.contains(&"helper"));
    }

    #[test]
    fn extracts_single_base_class_inherit_reference() {
        let src = "class Sub(Base):\n    pass\n";
        let facts = PythonExtractor.extract(src, "src/mod.py").unwrap();
        let inherit_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Inherit)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(
            inherit_names,
            vec!["Base"],
            "expected ['Base'] in {inherit_names:?}"
        );
    }

    #[test]
    fn extracts_multiple_base_classes_inherit_references() {
        let src = "class Multi(A, B):\n    pass\n";
        let facts = PythonExtractor.extract(src, "src/mod.py").unwrap();
        let inherit_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Inherit)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            inherit_names.contains(&"A"),
            "expected 'A' in {inherit_names:?}"
        );
        assert!(
            inherit_names.contains(&"B"),
            "expected 'B' in {inherit_names:?}"
        );
    }

    #[test]
    fn extracts_dotted_base_class_leaf_segment() {
        let src = "class Dotted(mod.Base):\n    pass\n";
        let facts = PythonExtractor.extract(src, "src/mod.py").unwrap();
        let inherit_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Inherit)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(
            inherit_names,
            vec!["Base"],
            "expected ['Base'] in {inherit_names:?}"
        );
    }

    // --- import extraction tests ---

    #[test]
    fn import_from_statement_emits_leaf_name() {
        let src = "from pkg.models import Config\n";
        let facts = PythonExtractor.extract(src, "src/app.py").unwrap();
        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(
            import_names,
            vec!["Config"],
            "expected ['Config'] in {import_names:?}"
        );
    }

    #[test]
    fn import_statement_emits_module_leaf() {
        // `import os` → leaf "os"; `import foo.bar` → leaf "bar"
        let src = "import os\nimport foo.bar\n";
        let facts = PythonExtractor.extract(src, "src/mod.py").unwrap();
        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            import_names.contains(&"os"),
            "expected 'os' in {import_names:?}"
        );
        assert!(
            import_names.contains(&"bar"),
            "expected 'bar' in {import_names:?}"
        );
    }

    #[test]
    fn import_from_statement_multiple_names() {
        let src = "from x import A, B\n";
        let facts = PythonExtractor.extract(src, "src/mod.py").unwrap();
        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            import_names.contains(&"A"),
            "expected 'A' in {import_names:?}"
        );
        assert!(
            import_names.contains(&"B"),
            "expected 'B' in {import_names:?}"
        );
    }

    #[test]
    fn import_alias_emits_real_name_not_alias() {
        // `from pkg import Thing as T` → ref "Thing", not "T"
        let src = "from pkg import Thing as T\n";
        let facts = PythonExtractor.extract(src, "src/mod.py").unwrap();
        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            import_names.contains(&"Thing"),
            "expected 'Thing' in {import_names:?}"
        );
        assert!(
            !import_names.contains(&"T"),
            "alias 'T' must NOT appear in {import_names:?}"
        );
    }

    #[test]
    fn wildcard_import_emits_nothing() {
        let src = "from x import *\n";
        let facts = PythonExtractor.extract(src, "src/mod.py").unwrap();
        let import_refs: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            import_refs.is_empty(),
            "expected no Import refs for wildcard, got {import_refs:?}"
        );
    }
}
