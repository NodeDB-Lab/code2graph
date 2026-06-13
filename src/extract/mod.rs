// SPDX-License-Identifier: Apache-2.0

//! Extraction: one tree-sitter pass per language → neutral [`FileFacts`].
//!
//! Each [`Extractor`] parses a single source file and emits symbol definitions
//! and references in a single walk. Extractors are pure and deterministic:
//! no I/O, no storage, no resolution.
//! Cross-file linking is the resolver's job ([`crate::resolve`]).

use tree_sitter::Node;

use crate::error::{CodegraphError, Result};
use crate::graph::FileFacts;
use crate::lang::Language;

pub mod python;
pub mod rust;
pub mod typescript;

pub use python::PythonExtractor;
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
        Language::Rust => RustExtractor.extract(source, file),
        Language::Python => PythonExtractor.extract(source, file),
        Language::TypeScript => TypeScriptExtractor.extract(source, file),
        other => Err(CodegraphError::UnsupportedLanguage(other.as_str().to_owned())),
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
