// SPDX-License-Identifier: Apache-2.0

//! The [`Extractor`] trait and the language-dispatching entry points
//! ([`extract_file`], [`extract_path`]).

use crate::error::{CodegraphError, Result};
use crate::graph::FileFacts;
use crate::lang::Language;

use super::{
    CExtractor, CppExtractor, GoExtractor, JavaExtractor, JavaScriptExtractor, KotlinExtractor,
    PhpExtractor, PythonExtractor, RubyExtractor, RustExtractor, ShellExtractor, SolidityExtractor,
    SwiftExtractor, TypeScriptExtractor,
};

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
/// Every [`Language`] has an extractor, so the match is exhaustive — adding a new
/// `Language` variant is a compile error until a dispatch arm is added here.
pub fn extract_file(lang: Language, source: &str, file: &str) -> Result<FileFacts> {
    match lang {
        Language::C => CExtractor.extract(source, file),
        Language::Cpp => CppExtractor.extract(source, file),
        Language::Go => GoExtractor.extract(source, file),
        Language::Java => JavaExtractor.extract(source, file),
        Language::JavaScript => JavaScriptExtractor.extract(source, file),
        Language::Php => PhpExtractor.extract(source, file),
        Language::Python => PythonExtractor.extract(source, file),
        Language::Ruby => RubyExtractor.extract(source, file),
        Language::Rust => RustExtractor.extract(source, file),
        Language::Shell => ShellExtractor.extract(source, file),
        Language::Swift => SwiftExtractor.extract(source, file),
        Language::Kotlin => KotlinExtractor.extract(source, file),
        Language::Solidity => SolidityExtractor.extract(source, file),
        Language::TypeScript => TypeScriptExtractor.extract(source, file),
    }
}

/// Extract facts from a file, inferring the language from its path extension.
pub fn extract_path(file: &str, source: &str) -> Result<FileFacts> {
    let lang = Language::from_path(file)
        .ok_or_else(|| CodegraphError::UnsupportedLanguage(file.to_owned()))?;
    extract_file(lang, source, file)
}
