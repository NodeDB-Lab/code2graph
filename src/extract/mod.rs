// SPDX-License-Identifier: Apache-2.0

//! Extraction: one tree-sitter pass per language → neutral [`FileFacts`].
//!
//! Each [`Extractor`] parses a single source file and emits symbol definitions
//! and references in a single walk. Extractors are pure and deterministic:
//! no I/O, no storage, no resolution.
//! Cross-file linking is the resolver's job ([`crate::resolve`]).

use crate::error::{CodegraphError, Result};
use crate::graph::FileFacts;
use crate::lang::Language;

pub mod rust;

pub use rust::RustExtractor;

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
/// extractor yet. Rust is implemented; other languages are added behind this trait.
pub fn extract_file(lang: Language, source: &str, file: &str) -> Result<FileFacts> {
    match lang {
        Language::Rust => RustExtractor.extract(source, file),
        other => Err(CodegraphError::UnsupportedLanguage(other.as_str().to_owned())),
    }
}

/// Extract facts from a file, inferring the language from its path extension.
pub fn extract_path(file: &str, source: &str) -> Result<FileFacts> {
    let lang =
        Language::from_path(file).ok_or_else(|| CodegraphError::UnsupportedLanguage(file.to_owned()))?;
    extract_file(lang, source, file)
}
