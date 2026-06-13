// SPDX-License-Identifier: Apache-2.0

//! Shell extractor — one tree-sitter pass yielding definitions and references.
//!
//! Definitions: top-level `function_definition` nodes, covering all bash function
//! styles (`foo() {}`, `function foo {}`, `function foo() {}`). Qualified identity
//! is derived from the file path (`scripts/deploy.sh` → namespace `deploy`).
//! References: callee identifiers of `command` nodes; the resolver only draws edges
//! to those matching a defined function name.
//!
//! Top-level variable assignments are intentionally NOT captured in v0.
//!
//! Emits neutral [`FileFacts`] — no storage entries, no source bodies.

use tree_sitter::{Language as TsLanguage, Parser};

use crate::error::{CodegraphError, Result};
use crate::graph::types::{ByteSpan, FileFacts, Symbol, SymbolKind};
use crate::lang::Language;
use crate::symbol::{Descriptor, SymbolId};

use super::{Extractor, collect_call_references, field_text, node_text, one_line_signature};

/// Tree-sitter query capturing command-name identifiers as call references.
const CALL_QUERY: &str = r#"
(command
  name: (command_name
    (word) @callee))
"#;

/// Extracts Shell symbols and references.
pub struct ShellExtractor;

impl Extractor for ShellExtractor {
    fn lang(&self) -> Language {
        Language::Shell
    }

    fn extract(&self, source: &str, file: &str) -> Result<FileFacts> {
        let ts_language = TsLanguage::from(tree_sitter_bash::LANGUAGE);
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
        let namespaces = shell_namespaces(file);

        let mut symbols = collect_symbols(&root, bytes, file, &namespaces);
        symbols.push(super::module_symbol(
            Language::Shell,
            &namespaces,
            file,
            source.len(),
        ));
        let references = collect_call_references(
            &root,
            &ts_language,
            CALL_QUERY,
            Language::Shell,
            bytes,
            file,
        )?;

        Ok(FileFacts {
            file: file.to_owned(),
            lang: Language::Shell.as_str().to_owned(),
            symbols,
            references,
        })
    }
}

/// Derive the Shell namespace path from a file path.
///
/// Strips a `.sh`, `.bash`, or `.zsh` extension; strips a leading `src/`, `bin/`,
/// or `scripts/` prefix (each tried in order); then splits on `/`. The file stem
/// is kept as the last namespace segment.
fn shell_namespaces(file: &str) -> Vec<String> {
    let p = file
        .strip_suffix(".sh")
        .or_else(|| file.strip_suffix(".bash"))
        .or_else(|| file.strip_suffix(".zsh"))
        .unwrap_or(file);
    let p = p
        .strip_prefix("src/")
        .or_else(|| p.strip_prefix("bin/"))
        .or_else(|| p.strip_prefix("scripts/"))
        .unwrap_or(p);
    p.split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

fn collect_symbols(
    root: &tree_sitter::Node,
    bytes: &[u8],
    file: &str,
    namespaces: &[String],
) -> Vec<Symbol> {
    let mut out = Vec::new();

    for child in root.children(&mut root.walk()) {
        if child.kind() != "function_definition" {
            continue;
        }
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
        out.push(Symbol {
            id: SymbolId::global(Language::Shell.as_str(), descriptors),
            name,
            kind: SymbolKind::Function,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_functions() {
        let src = "validate() { return 0; }\nfunction deploy { echo done; }\nfunction run() { validate; }\n";
        let facts = ShellExtractor.extract(src, "scripts/deploy.sh").unwrap();
        let by_name = |n: &str| facts.symbols.iter().find(|s| s.name == n).cloned();

        let validate = by_name("validate").unwrap();
        assert_eq!(validate.kind, SymbolKind::Function);
        assert_eq!(
            validate.id.to_scip_string(),
            "codegraph    deploy/validate()."
        );

        assert!(by_name("deploy").is_some());
        assert!(by_name("run").is_some());
        assert_eq!(facts.lang, "shell");
    }

    #[test]
    fn extracts_call_references() {
        let src = "function main { validate; deploy arg1; }\n";
        let facts = ShellExtractor.extract(src, "scripts/main.sh").unwrap();
        let names: Vec<&str> = facts.references.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"validate"));
        assert!(names.contains(&"deploy"));
    }
}
