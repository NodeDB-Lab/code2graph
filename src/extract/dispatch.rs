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
#[cfg(feature = "dart")]
use super::DartExtractor;
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
#[cfg(feature = "lua")]
use super::LuaExtractor;
#[cfg(feature = "luau")]
use super::LuauExtractor;
#[cfg(feature = "pascal")]
use super::PascalExtractor;
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
#[cfg(feature = "svelte")]
use super::SvelteExtractor;
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

    /// Like [`Extractor::extract`], but given a [`crate::extract::BindingRules`]
    /// registry describing which language constructs carry embedded secondary
    /// artifacts (e.g. SQL strings). Extractors that don't recognize any such
    /// construct can ignore `rules` and behave exactly like [`Extractor::extract`]
    /// — which is what the default implementation does.
    fn extract_with_bindings(
        &self,
        source: &str,
        file: &str,
        rules: &crate::extract::BindingRules,
    ) -> Result<FileFacts> {
        let _ = rules;
        self.extract(source, file)
    }
}

/// Extract facts from a single file, dispatching on its language, with no
/// query-binding rules applied (equivalent to
/// `extract_file_with_bindings(lang, source, file, &BindingRules::empty())`).
///
/// Each language arm is compiled only when the corresponding Cargo feature is
/// enabled (e.g. `rust`, `python`, `typescript`, …). Disabled languages return
/// [`CodegraphError::UnsupportedLanguage`] at runtime.
pub fn extract_file(lang: Language, source: &str, file: &str) -> Result<FileFacts> {
    extract_file_with_bindings(lang, source, file, &super::BindingRules::empty())
}

/// Extract facts from a single file, dispatching on its language, applying
/// `rules` to recognize embedded secondary-artifact constructs (e.g. SQL
/// strings passed to a query-binding function).
///
/// Each language arm is compiled only when the corresponding Cargo feature is
/// enabled (e.g. `rust`, `python`, `typescript`, …). Disabled languages return
/// [`CodegraphError::UnsupportedLanguage`] at runtime.
#[cfg_attr(not(feature = "_extractors"), allow(unused_variables))]
pub fn extract_file_with_bindings(
    lang: Language,
    source: &str,
    file: &str,
    rules: &super::BindingRules,
) -> Result<FileFacts> {
    #[allow(unreachable_patterns)]
    #[cfg_attr(not(feature = "_extractors"), allow(unused_mut))]
    let mut facts = match lang {
        #[cfg(feature = "c")]
        Language::C => CExtractor.extract_with_bindings(source, file, rules),
        #[cfg(feature = "csharp")]
        Language::CSharp => CSharpExtractor.extract_with_bindings(source, file, rules),
        #[cfg(feature = "cpp")]
        Language::Cpp => CppExtractor.extract_with_bindings(source, file, rules),
        #[cfg(feature = "go")]
        Language::Go => GoExtractor.extract_with_bindings(source, file, rules),
        #[cfg(feature = "java")]
        Language::Java => JavaExtractor.extract_with_bindings(source, file, rules),
        #[cfg(feature = "typescript")]
        Language::JavaScript => JavaScriptExtractor.extract_with_bindings(source, file, rules),
        #[cfg(feature = "php")]
        Language::Php => PhpExtractor.extract_with_bindings(source, file, rules),
        #[cfg(feature = "python")]
        Language::Python => PythonExtractor.extract_with_bindings(source, file, rules),
        #[cfg(feature = "ruby")]
        Language::Ruby => RubyExtractor.extract_with_bindings(source, file, rules),
        #[cfg(feature = "rust")]
        Language::Rust => RustExtractor.extract_with_bindings(source, file, rules),
        #[cfg(feature = "shell")]
        Language::Shell => ShellExtractor.extract_with_bindings(source, file, rules),
        #[cfg(feature = "swift")]
        Language::Swift => SwiftExtractor.extract_with_bindings(source, file, rules),
        #[cfg(feature = "kotlin")]
        Language::Kotlin => KotlinExtractor.extract_with_bindings(source, file, rules),
        #[cfg(feature = "solidity")]
        Language::Solidity => SolidityExtractor.extract_with_bindings(source, file, rules),
        #[cfg(feature = "sql")]
        Language::Sql => SqlExtractor.extract_with_bindings(source, file, rules),
        #[cfg(feature = "hcl")]
        Language::Hcl => HclExtractor.extract_with_bindings(source, file, rules),
        #[cfg(feature = "typescript")]
        Language::TypeScript => TypeScriptExtractor.extract_with_bindings(source, file, rules),
        #[cfg(feature = "scala")]
        Language::Scala => ScalaExtractor.extract_with_bindings(source, file, rules),
        #[cfg(feature = "dart")]
        Language::Dart => DartExtractor.extract_with_bindings(source, file, rules),
        #[cfg(feature = "lua")]
        Language::Lua => LuaExtractor.extract_with_bindings(source, file, rules),
        #[cfg(feature = "luau")]
        Language::Luau => LuauExtractor.extract_with_bindings(source, file, rules),
        #[cfg(feature = "pascal")]
        Language::Pascal => PascalExtractor.extract_with_bindings(source, file, rules),
        #[cfg(feature = "svelte")]
        Language::Svelte => SvelteExtractor.extract_with_bindings(source, file, rules),
        _ => Err(CodegraphError::UnsupportedLanguage(format!(
            "{} (grammar feature disabled)",
            lang.as_str()
        ))),
    }?;
    #[cfg(feature = "_extractors")]
    dedupe_symbol_identities(&mut facts);
    Ok(facts)
}

/// Enforce the `FileFacts` invariant that every symbol has a unique
/// `SymbolId`. A build-free syntactic pass can emit the same definition twice
/// when it is guarded by mutually-exclusive `#[cfg(...)]` (or `#ifdef`) — the
/// two occurrences are one logical symbol, so keep the first and drop the
/// rest. Mirrors the first-seen-wins dedup the layered resolver applies when
/// merging (see `resolve::layered`).
#[cfg(feature = "_extractors")]
fn dedupe_symbol_identities(facts: &mut FileFacts) {
    let mut seen = std::collections::HashSet::with_capacity(facts.symbols.len());
    facts
        .symbols
        .retain(|symbol| seen.insert(symbol.id.clone()));
}

/// Extract facts from a file, inferring the language from its path extension,
/// with no query-binding rules applied.
pub fn extract_path(file: &str, source: &str) -> Result<FileFacts> {
    extract_path_with_bindings(file, source, &super::BindingRules::empty())
}

/// Extract facts from a file, inferring the language from its path extension,
/// applying `rules` to recognize embedded secondary-artifact constructs.
pub fn extract_path_with_bindings(
    file: &str,
    source: &str,
    rules: &super::BindingRules,
) -> Result<FileFacts> {
    let lang = Language::from_path(file)
        .ok_or_else(|| CodegraphError::UnsupportedLanguage(file.to_owned()))?;
    extract_file_with_bindings(lang, source, file, rules)
}

#[cfg(all(test, feature = "rust"))]
mod tests {
    use super::*;

    /// A syntactic pass can't evaluate `#[cfg(...)]`, so mutually-exclusive
    /// cfg-gated definitions of the same item (common in Rust for
    /// platform-specific code) are both emitted by the tree-sitter walk. They
    /// must collapse to a single logical symbol rather than surviving as two
    /// symbols with the same `SymbolId` — which would later fail
    /// `validate_structure`'s duplicate-identity check and abort the whole
    /// file.
    #[test]
    fn cfg_gated_duplicate_definitions_collapse_to_one_symbol() {
        let src = r#"
#[cfg(unix)]
fn identity() -> u32 { 1 }

#[cfg(not(unix))]
fn identity() -> u32 { 2 }
"#;
        let facts = extract_path("src/lib.rs", src).unwrap();
        let matches: Vec<_> = facts
            .symbols
            .iter()
            .filter(|s| s.name == "identity")
            .collect();
        assert_eq!(
            matches.len(),
            1,
            "cfg-gated duplicate definitions must dedupe to a single symbol, got {matches:?}"
        );
    }
}
