// SPDX-License-Identifier: Apache-2.0

//! The [`Extractor`] trait and the language-dispatching entry points
//! ([`extract_file`], [`extract_path`]).

use crate::error::{CodegraphError, Result};
use crate::graph::FileFacts;
use crate::lang::Language;

#[cfg(feature = "c")]
use super::CExtractor;
#[cfg(feature = "csharp")]
use super::CSharpExtractor;
#[cfg(feature = "cpp")]
use super::CppExtractor;
#[cfg(feature = "go")]
use super::GoExtractor;
#[cfg(feature = "hcl")]
use super::HclExtractor;
#[cfg(feature = "java")]
use super::JavaExtractor;
#[cfg(feature = "typescript")]
use super::JavaScriptExtractor;
#[cfg(feature = "kotlin")]
use super::KotlinExtractor;
#[cfg(feature = "php")]
use super::PhpExtractor;
#[cfg(feature = "python")]
use super::PythonExtractor;
#[cfg(feature = "ruby")]
use super::RubyExtractor;
#[cfg(feature = "rust")]
use super::RustExtractor;
#[cfg(feature = "scala")]
use super::ScalaExtractor;
#[cfg(feature = "shell")]
use super::ShellExtractor;
#[cfg(feature = "solidity")]
use super::SolidityExtractor;
#[cfg(feature = "sql")]
use super::SqlExtractor;
#[cfg(feature = "swift")]
use super::SwiftExtractor;
#[cfg(feature = "typescript")]
use super::TypeScriptExtractor;

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
/// Each language arm is compiled only when the corresponding Cargo feature is
/// enabled (e.g. `rust`, `python`, `typescript`, …). Disabled languages return
/// [`CodegraphError::UnsupportedLanguage`] at runtime.
pub fn extract_file(lang: Language, source: &str, file: &str) -> Result<FileFacts> {
    #[allow(unreachable_patterns)]
    match lang {
        #[cfg(feature = "c")]
        Language::C => CExtractor.extract(source, file),
        #[cfg(feature = "csharp")]
        Language::CSharp => CSharpExtractor.extract(source, file),
        #[cfg(feature = "cpp")]
        Language::Cpp => CppExtractor.extract(source, file),
        #[cfg(feature = "go")]
        Language::Go => GoExtractor.extract(source, file),
        #[cfg(feature = "java")]
        Language::Java => JavaExtractor.extract(source, file),
        #[cfg(feature = "typescript")]
        Language::JavaScript => JavaScriptExtractor.extract(source, file),
        #[cfg(feature = "php")]
        Language::Php => PhpExtractor.extract(source, file),
        #[cfg(feature = "python")]
        Language::Python => PythonExtractor.extract(source, file),
        #[cfg(feature = "ruby")]
        Language::Ruby => RubyExtractor.extract(source, file),
        #[cfg(feature = "rust")]
        Language::Rust => RustExtractor.extract(source, file),
        #[cfg(feature = "shell")]
        Language::Shell => ShellExtractor.extract(source, file),
        #[cfg(feature = "swift")]
        Language::Swift => SwiftExtractor.extract(source, file),
        #[cfg(feature = "kotlin")]
        Language::Kotlin => KotlinExtractor.extract(source, file),
        #[cfg(feature = "solidity")]
        Language::Solidity => SolidityExtractor.extract(source, file),
        #[cfg(feature = "sql")]
        Language::Sql => SqlExtractor.extract(source, file),
        #[cfg(feature = "hcl")]
        Language::Hcl => HclExtractor.extract(source, file),
        #[cfg(feature = "typescript")]
        Language::TypeScript => TypeScriptExtractor.extract(source, file),
        #[cfg(feature = "scala")]
        Language::Scala => ScalaExtractor.extract(source, file),
        _ => Err(CodegraphError::UnsupportedLanguage(format!(
            "{} (grammar feature disabled)",
            lang.as_str()
        ))),
    }
}

/// Extract facts from a file, inferring the language from its path extension.
pub fn extract_path(file: &str, source: &str) -> Result<FileFacts> {
    let lang = Language::from_path(file)
        .ok_or_else(|| CodegraphError::UnsupportedLanguage(file.to_owned()))?;
    extract_file(lang, source, file)
}
