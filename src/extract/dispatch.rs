// SPDX-License-Identifier: Apache-2.0

//! The [`Extractor`] trait and the language-dispatching entry points
//! ([`extract_file`], [`extract_path`]).

use crate::error::{CodegraphError, Result};
use crate::graph::{FileFacts, FileFactsValidationContext, validate_file_facts_with_context};
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
///
/// Implementors provide the raw tree-sitter pass ([`Extractor::extract_facts`]);
/// callers use [`Extractor::extract`], which normalizes that output and enforces
/// the [`FileFacts`] context contract on it. Keeping the contract at this seam —
/// rather than only at the public dispatch entry points — means a language pass
/// that emits facts a consumer's deserialization boundary would reject fails
/// here, in that extractor's own tests, instead of silently degrading into an
/// omitted file downstream.
pub trait Extractor {
    /// The language this extractor handles.
    fn lang(&self) -> Language;

    /// Parse `source` (the contents of `file`, a project-relative path) and
    /// return its definitions and references.
    ///
    /// This is the implementation hook. Call [`Extractor::extract`] instead: it
    /// applies the normalization and validation every consumer relies on.
    fn extract_facts(&self, source: &str, file: &str) -> Result<FileFacts>;

    /// Like [`Extractor::extract_facts`], but given a
    /// [`crate::extract::BindingRules`] registry describing which language
    /// constructs carry embedded secondary artifacts (e.g. SQL strings).
    /// Extractors that don't recognize any such construct can ignore `rules` and
    /// behave exactly like [`Extractor::extract_facts`] — which is what the
    /// default implementation does.
    fn extract_facts_with_bindings(
        &self,
        source: &str,
        file: &str,
        rules: &crate::extract::BindingRules,
    ) -> Result<FileFacts> {
        let _ = rules;
        self.extract_facts(source, file)
    }

    /// Extract normalized, contract-checked facts for `file`.
    fn extract(&self, source: &str, file: &str) -> Result<FileFacts> {
        let facts = self.extract_facts(source, file)?;
        normalize_and_validate(facts, self.lang(), source, file)
    }

    /// Extract normalized, contract-checked facts for `file`, applying `rules`.
    fn extract_with_bindings(
        &self,
        source: &str,
        file: &str,
        rules: &crate::extract::BindingRules,
    ) -> Result<FileFacts> {
        let facts = self.extract_facts_with_bindings(source, file, rules)?;
        normalize_and_validate(facts, self.lang(), source, file)
    }
}

/// Normalize a raw language pass's output and hold it to its context contract.
///
/// A free function rather than a trait method so no implementor can weaken it.
fn normalize_and_validate(
    mut facts: FileFacts,
    lang: Language,
    source: &str,
    file: &str,
) -> Result<FileFacts> {
    dedupe_symbol_identities(&mut facts);
    validate_file_facts_with_context(
        &facts,
        FileFactsValidationContext {
            expected_file: file,
            expected_language: lang,
            source_len: source.len(),
        },
    )?;
    Ok(facts)
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
    let facts = match lang {
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
    // Every arm above returns through `Extractor::extract_with_bindings`, which
    // has already deduped and validated against this exact context.
    Ok(facts)
}

/// Enforce the `FileFacts` invariant that every symbol has a unique
/// `SymbolId`. A build-free syntactic pass can emit the same definition twice
/// when it is guarded by mutually-exclusive `#[cfg(...)]` (or `#ifdef`) — the
/// two occurrences are one logical symbol, so keep the first and drop the
/// rest. Mirrors the first-seen-wins dedup the layered resolver applies when
/// merging (see `resolve::layered`).
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

    /// The gate that keeps issue-class "the library accepted it, the consumer
    /// rejected it" bugs from shipping: a language pass whose raw output breaks
    /// the context contract must fail at the extractor seam, where its own unit
    /// tests will see it — not silently downstream at a deserialization boundary
    /// that turns the whole file into an omission.
    #[test]
    fn a_contract_violating_pass_fails_at_the_extractor_seam() {
        struct ViolatingExtractor;

        impl Extractor for ViolatingExtractor {
            fn lang(&self) -> Language {
                Language::Rust
            }

            fn extract_facts(&self, _source: &str, file: &str) -> Result<FileFacts> {
                Ok(FileFacts {
                    file: file.to_owned(),
                    lang: "rust".to_owned(),
                    symbols: Vec::new(),
                    // `source_module` is an import-only field. Carrying it on a
                    // call is exactly the shape of metadata drift that a new
                    // role-specific field introduces.
                    references: vec![crate::graph::Reference {
                        name: "helper".to_owned(),
                        occ: crate::graph::Occurrence {
                            file: file.to_owned(),
                            line: 1,
                            col: 1,
                            byte: 0,
                        },
                        role: crate::graph::RefRole::Call,
                        source_module: Some("module".to_owned()),
                        from_path: None,
                        imported_name: None,
                        is_reexport: false,
                        qualifier: None,
                        scope: None,
                        type_ref_ctx: None,
                        cross_artifact: false,
                        self_receiver: false,
                    }],
                    scopes: Vec::new(),
                    bindings: Vec::new(),
                    ffi_exports: Vec::new(),
                })
            }
        }

        let source = "fn caller() { helper() }\n";
        assert!(
            ViolatingExtractor
                .extract_facts(source, "src/lib.rs")
                .is_ok(),
            "the raw pass itself is unguarded — the seam is what enforces the contract"
        );
        let error = ViolatingExtractor
            .extract(source, "src/lib.rs")
            .expect_err("a contract-violating pass must not escape its extractor");
        assert!(
            error.to_string().contains("source_module"),
            "the failure must name the rule that fired, got {error}"
        );
    }

    #[test]
    fn dispatch_returns_context_valid_member_read_facts() {
        let source = "struct Entry { extra: i64 }\nfn read(entry: &Entry) -> i64 { entry.extra }\n";
        let facts = extract_path("src/entry.rs", source).expect("dispatch extraction");
        assert!(facts.references.iter().any(|reference| {
            reference.role == crate::graph::RefRole::Read
                && reference.name == "extra"
                && reference.qualifier.as_deref() == Some("entry")
        }));
        validate_file_facts_with_context(
            &facts,
            FileFactsValidationContext {
                expected_file: "src/entry.rs",
                expected_language: Language::Rust,
                source_len: source.len(),
            },
        )
        .expect("public dispatch output must satisfy its context contract");
    }

    #[cfg(feature = "typescript")]
    #[test]
    fn dispatch_returns_context_valid_typescript_and_javascript_property_reads() {
        for (file, language, source) in [
            (
                "src/entry.ts",
                Language::TypeScript,
                "interface Entry { extra: number }\nfunction read(entry: Entry) { return entry.extra; }\n",
            ),
            (
                "src/entry.js",
                Language::JavaScript,
                "function read(entry) { return entry.extra; }\n",
            ),
        ] {
            let facts = extract_path(file, source).expect("dispatch extraction");
            assert!(facts.references.iter().any(|reference| {
                reference.role == crate::graph::RefRole::Read
                    && reference.name == "extra"
                    && reference.qualifier.as_deref() == Some("entry")
            }));
            validate_file_facts_with_context(
                &facts,
                FileFactsValidationContext {
                    expected_file: file,
                    expected_language: language,
                    source_len: source.len(),
                },
            )
            .expect("public dispatch output must satisfy its context contract");
        }
    }
}
