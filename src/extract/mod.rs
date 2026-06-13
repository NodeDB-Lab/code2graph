// SPDX-License-Identifier: Apache-2.0

//! Extraction: one tree-sitter pass per language → neutral [`FileFacts`].
//!
//! Each [`Extractor`] parses a single source file and emits symbol definitions
//! and references in a single walk. Extractors are pure and deterministic:
//! no I/O, no storage, no resolution.
//! Cross-file linking is the resolver's job ([`crate::resolve`]).

use tree_sitter::{Language as TsLanguage, Node, Query, QueryCursor, StreamingIterator};

use crate::error::{CodegraphError, Result};
use crate::graph::FileFacts;
use crate::graph::types::{Occurrence, RefRole, Reference};
use crate::lang::Language;

pub mod c;
pub mod go;
pub mod java;
pub mod javascript;
pub mod php;
pub mod python;
pub mod ruby;
pub mod rust;
pub mod typescript;

pub use c::CExtractor;
pub use go::GoExtractor;
pub use java::JavaExtractor;
pub use javascript::JavaScriptExtractor;
pub use php::PhpExtractor;
pub use python::PythonExtractor;
pub use ruby::RubyExtractor;
pub use rust::RustExtractor;
pub use typescript::TypeScriptExtractor;

/// A per-language source-to-facts extractor.
pub trait Extractor {
    /// The language this extractor handles.
    fn lang(&self) -> Language;

    /// Parse `source` (the contents of `file`, a project-relative path) and
    /// return its definitions and references.
    fn extract(&self, source: &str, file: &str) -> Result<FileFacts>;
}

/// Extract facts from a single file, dispatching on its language.
///
/// Returns [`CodegraphError::UnsupportedLanguage`] for languages without an
/// extractor yet. Languages are added one at a time behind the [`Extractor`] trait.
pub fn extract_file(lang: Language, source: &str, file: &str) -> Result<FileFacts> {
    match lang {
        Language::C => CExtractor.extract(source, file),
        Language::Go => GoExtractor.extract(source, file),
        Language::Java => JavaExtractor.extract(source, file),
        Language::JavaScript => JavaScriptExtractor.extract(source, file),
        Language::Php => PhpExtractor.extract(source, file),
        Language::Python => PythonExtractor.extract(source, file),
        Language::Ruby => RubyExtractor.extract(source, file),
        Language::Rust => RustExtractor.extract(source, file),
        Language::TypeScript => TypeScriptExtractor.extract(source, file),
        other => Err(CodegraphError::UnsupportedLanguage(
            other.as_str().to_owned(),
        )),
    }
}

/// Extract facts from a file, inferring the language from its path extension.
pub fn extract_path(file: &str, source: &str) -> Result<FileFacts> {
    let lang = Language::from_path(file)
        .ok_or_else(|| CodegraphError::UnsupportedLanguage(file.to_owned()))?;
    extract_file(lang, source, file)
}

/// UTF-8 text of a node's byte range (lossy fallback on invalid UTF-8).
pub(crate) fn node_text<'a>(node: &Node, bytes: &'a [u8]) -> &'a str {
    std::str::from_utf8(&bytes[node.start_byte()..node.end_byte()]).unwrap_or("<invalid utf8>")
}

/// One-line signature: text up to the first top-level `{` or `:`, whitespace-collapsed;
/// falls back to the first line. Shared by extractors that want a declaration preview.
pub(crate) fn one_line_signature(text: &str, stop: &[char]) -> String {
    let mut depth = 0i32;
    let mut end = text.len();
    let mut found = false;
    for (i, c) in text.char_indices() {
        if depth == 0 && stop.contains(&c) {
            end = i;
            found = true;
            break;
        }
        match c {
            '{' | '(' | '[' => depth += 1,
            '}' | ')' | ']' => depth -= 1,
            _ => {}
        }
    }
    let sig = if found {
        &text[..end]
    } else {
        text.lines().next().unwrap_or(text)
    };
    sig.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Minimum callee-name length to record as a reference (drops `ok`, `id`, …).
pub(crate) const MIN_REF_LEN: usize = 3;

/// UTF-8 text of the first direct child of `node` whose kind is `kind`.
pub(crate) fn child_text(node: &Node, kind: &str, bytes: &[u8]) -> Option<String> {
    node.children(&mut node.walk())
        .find(|c| c.kind() == kind)
        .map(|c| node_text(&c, bytes).to_owned())
}

/// UTF-8 text of the child of `node` at the named `field`.
pub(crate) fn field_text(node: &Node, field: &str, bytes: &[u8]) -> Option<String> {
    node.child_by_field_name(field)
        .map(|n| node_text(&n, bytes).to_owned())
}

/// Run a tree-sitter call-reference query and collect its `@callee` captures as
/// [`Reference`]s with [`RefRole::Call`]. The query must expose a capture named
/// `callee`; captures shorter than [`MIN_REF_LEN`] are dropped. Shared by every
/// extractor — only the query string and grammar differ per language.
pub(crate) fn collect_call_references(
    root: &Node,
    ts_lang: &TsLanguage,
    query_src: &str,
    lang: Language,
    bytes: &[u8],
    file: &str,
) -> Result<Vec<Reference>> {
    let query = Query::new(ts_lang, query_src).map_err(|e| CodegraphError::Query {
        lang: lang.as_str().to_owned(),
        msg: e.to_string(),
    })?;
    let callee_idx =
        query
            .capture_index_for_name("callee")
            .ok_or_else(|| CodegraphError::Query {
                lang: lang.as_str().to_owned(),
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
