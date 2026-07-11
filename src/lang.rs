// SPDX-License-Identifier: Apache-2.0

//! The set of languages code2graph can parse, plus extension dispatch.
//!
//! This is the single place that enumerates language coverage; extraction and
//! resolution dispatch off it.

/// Whether a language's extractor is included in this build.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LanguageAvailability {
    /// The Cargo feature for this language is enabled.
    Enabled,
    /// The Cargo feature for this language is disabled.
    FeatureDisabled,
}

/// A source language code2graph knows how to parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Language {
    Rust,
    TypeScript, // .ts, .tsx
    JavaScript, // .js, .jsx, .mjs, .cjs
    Python,     // .py, .pyi
    Go,         // .go
    Shell,      // .sh, .bash, .zsh
    C,          // .c, .h
    Cpp,        // .cc, .cpp, .cxx, .hh, .hpp, .hxx
    Java,       // .java
    Ruby,       // .rb
    Php,        // .php
    Swift,      // .swift
    Kotlin,     // .kt, .kts
    Solidity,   // .sol
    Sql,        // .sql
    Hcl,        // .tf, .hcl, .tfvars
    CSharp,     // .cs
    Scala,      // .scala, .sc
    Dart,       // .dart
    Lua,        // .lua
    Luau,       // .luau
    Pascal,     // .pas, .dpr, .dpk, .lpr
    Svelte,     // .svelte
}

impl Language {
    /// Reports whether this language's extractor is included in the current build.
    pub const fn availability(self) -> LanguageAvailability {
        match self {
            Language::Rust => availability(cfg!(feature = "rust")),
            Language::TypeScript | Language::JavaScript => {
                availability(cfg!(feature = "typescript"))
            }
            Language::Python => availability(cfg!(feature = "python")),
            Language::Go => availability(cfg!(feature = "go")),
            Language::Shell => availability(cfg!(feature = "shell")),
            Language::C => availability(cfg!(feature = "c")),
            Language::Cpp => availability(cfg!(feature = "cpp")),
            Language::Java => availability(cfg!(feature = "java")),
            Language::Ruby => availability(cfg!(feature = "ruby")),
            Language::Php => availability(cfg!(feature = "php")),
            Language::Swift => availability(cfg!(feature = "swift")),
            Language::Kotlin => availability(cfg!(feature = "kotlin")),
            Language::Solidity => availability(cfg!(feature = "solidity")),
            Language::Sql => availability(cfg!(feature = "sql")),
            Language::Hcl => availability(cfg!(feature = "hcl")),
            Language::CSharp => availability(cfg!(feature = "csharp")),
            Language::Scala => availability(cfg!(feature = "scala")),
            Language::Dart => availability(cfg!(feature = "dart")),
            Language::Lua => availability(cfg!(feature = "lua")),
            Language::Luau => availability(cfg!(feature = "luau")),
            Language::Pascal => availability(cfg!(feature = "pascal")),
            Language::Svelte => availability(cfg!(feature = "svelte")),
        }
    }

    /// Every `Language` variant. Kept exhaustive by the `all_is_exhaustive` test.
    pub const ALL: &[Language] = &[
        Language::Rust,
        Language::TypeScript,
        Language::JavaScript,
        Language::Python,
        Language::Go,
        Language::Shell,
        Language::C,
        Language::Cpp,
        Language::Java,
        Language::Ruby,
        Language::Php,
        Language::Swift,
        Language::Kotlin,
        Language::Solidity,
        Language::Sql,
        Language::Hcl,
        Language::CSharp,
        Language::Scala,
        Language::Dart,
        Language::Lua,
        Language::Luau,
        Language::Pascal,
        Language::Svelte,
    ];

    /// This variant's file extensions (without the leading dot); the first entry
    /// is the primary/canonical extension. Single source of truth for
    /// `from_extension` — keep in sync with the extensions accepted there.
    pub fn extensions(self) -> &'static [&'static str] {
        match self {
            Language::Rust => &["rs"],
            Language::TypeScript => &["ts", "tsx"],
            Language::JavaScript => &["js", "jsx", "mjs", "cjs"],
            Language::Python => &["py", "pyi"],
            Language::Go => &["go"],
            Language::Shell => &["sh", "bash", "zsh"],
            Language::C => &["c", "h"],
            Language::Cpp => &["cc", "cpp", "cxx", "hh", "hpp", "hxx"],
            Language::Java => &["java"],
            Language::Ruby => &["rb"],
            Language::Php => &["php"],
            Language::Swift => &["swift"],
            Language::Kotlin => &["kt", "kts"],
            Language::Solidity => &["sol"],
            Language::Sql => &["sql"],
            Language::Hcl => &["tf", "hcl", "tfvars"],
            Language::CSharp => &["cs"],
            Language::Scala => &["scala", "sc"],
            Language::Dart => &["dart"],
            Language::Lua => &["lua"],
            Language::Luau => &["luau"],
            Language::Pascal => &["pas", "dpr", "dpk", "lpr"],
            Language::Svelte => &["svelte"],
        }
    }

    /// Canonical lowercase language tag (stable; used in `SymbolKey.lang`).
    pub fn as_str(self) -> &'static str {
        match self {
            Language::Rust => "rust",
            Language::TypeScript => "typescript",
            Language::JavaScript => "javascript",
            Language::Python => "python",
            Language::Go => "go",
            Language::Shell => "shell",
            Language::C => "c",
            Language::Cpp => "cpp",
            Language::Java => "java",
            Language::Ruby => "ruby",
            Language::Php => "php",
            Language::Swift => "swift",
            Language::Kotlin => "kotlin",
            Language::Solidity => "solidity",
            Language::Sql => "sql",
            Language::Hcl => "hcl",
            Language::CSharp => "csharp",
            Language::Scala => "scala",
            Language::Dart => "dart",
            Language::Lua => "lua",
            Language::Luau => "luau",
            Language::Pascal => "pascal",
            Language::Svelte => "svelte",
        }
    }

    /// Map a lowercase file extension to a `Language`, or `None` if unknown.
    /// Derives from `extensions()` so the mapping has a single source of truth.
    pub fn from_extension(ext: &str) -> Option<Self> {
        Language::ALL
            .iter()
            .copied()
            .find(|l| l.extensions().contains(&ext))
    }

    /// Map a file path to a `Language` via its extension.
    pub fn from_path(path: &str) -> Option<Self> {
        let ext = path.rsplit('.').next()?;
        Self::from_extension(&ext.to_lowercase())
    }
}

const fn availability(enabled: bool) -> LanguageAvailability {
    if enabled {
        LanguageAvailability::Enabled
    } else {
        LanguageAvailability::FeatureDisabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn availability_matches_each_language_feature_in_every_build() {
        macro_rules! assert_availability {
            ($language:expr, $feature:literal) => {
                assert_eq!(
                    $language.availability(),
                    if cfg!(feature = $feature) {
                        LanguageAvailability::Enabled
                    } else {
                        LanguageAvailability::FeatureDisabled
                    },
                    "{language:?} must track the `{feature}` Cargo feature",
                    language = $language,
                    feature = $feature,
                );
            };
        }

        assert_availability!(Language::Rust, "rust");
        assert_availability!(Language::TypeScript, "typescript");
        assert_availability!(Language::JavaScript, "typescript");
        assert_availability!(Language::Python, "python");
        assert_availability!(Language::Go, "go");
        assert_availability!(Language::Shell, "shell");
        assert_availability!(Language::C, "c");
        assert_availability!(Language::Cpp, "cpp");
        assert_availability!(Language::Java, "java");
        assert_availability!(Language::Ruby, "ruby");
        assert_availability!(Language::Php, "php");
        assert_availability!(Language::Swift, "swift");
        assert_availability!(Language::Kotlin, "kotlin");
        assert_availability!(Language::Solidity, "solidity");
        assert_availability!(Language::Sql, "sql");
        assert_availability!(Language::Hcl, "hcl");
        assert_availability!(Language::CSharp, "csharp");
        assert_availability!(Language::Scala, "scala");
        assert_availability!(Language::Dart, "dart");
        assert_availability!(Language::Lua, "lua");
        assert_availability!(Language::Luau, "luau");
        assert_availability!(Language::Pascal, "pascal");
        assert_availability!(Language::Svelte, "svelte");
    }

    #[test]
    fn extension_dispatch() {
        assert_eq!(Language::from_extension("rs"), Some(Language::Rust));
        assert_eq!(Language::from_path("src/auth/mod.rs"), Some(Language::Rust));
        assert_eq!(Language::from_path("a/b/Main.KT"), Some(Language::Kotlin));
        assert_eq!(Language::from_extension("bin"), None);
    }

    #[test]
    fn tag_is_stable_lowercase() {
        assert_eq!(Language::TypeScript.as_str(), "typescript");
    }

    /// Compile-time guard: a new `Language` variant forces a new arm here (no
    /// wildcard), where the contributor is reminded to also add it to `Language::ALL`.
    fn assert_variant_in_all(l: Language) -> bool {
        let listed = match l {
            // EVERY variant must be listed here AND in `Language::ALL`.
            Language::Rust
            | Language::TypeScript
            | Language::JavaScript
            | Language::Python
            | Language::Go
            | Language::Shell
            | Language::C
            | Language::Cpp
            | Language::Java
            | Language::Ruby
            | Language::Php
            | Language::Swift
            | Language::Kotlin
            | Language::Solidity
            | Language::Sql
            | Language::Hcl
            | Language::CSharp
            | Language::Scala
            | Language::Dart
            | Language::Lua
            | Language::Luau
            | Language::Pascal
            | Language::Svelte => true,
        };
        listed && Language::ALL.contains(&l)
    }

    #[test]
    fn all_is_exhaustive() {
        for &l in Language::ALL {
            assert!(
                assert_variant_in_all(l),
                "variant missing from Language::ALL"
            );
        }
    }

    #[test]
    fn supported_languages_doc_lists_each_primary_extension() {
        let path = format!("{}/docs/supported-languages.md", env!("CARGO_MANIFEST_DIR"));
        let doc =
            std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
        for &lang in Language::ALL {
            let primary = lang.extensions()[0];
            let token = format!("`.{primary}`"); // doc cells are backticked: `.rs`
            assert!(
                doc.contains(&token),
                "language {lang:?} (primary ext .{primary}) is not listed in \
                 docs/supported-languages.md — add its row and update the doc",
            );
        }
    }
}
