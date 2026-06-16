// SPDX-License-Identifier: Apache-2.0

//! The set of languages code2graph can parse, plus extension dispatch.
//!
//! This is the single place that enumerates language coverage; extraction and
//! resolution dispatch off it.

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
}

impl Language {
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
        }
    }

    /// Map a lowercase file extension to a `Language`, or `None` if unknown.
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext {
            "rs" => Some(Self::Rust),
            "ts" | "tsx" => Some(Self::TypeScript),
            "js" | "jsx" | "mjs" | "cjs" => Some(Self::JavaScript),
            "py" | "pyi" => Some(Self::Python),
            "go" => Some(Self::Go),
            "sh" | "bash" | "zsh" => Some(Self::Shell),
            "c" | "h" => Some(Self::C),
            "cc" | "cpp" | "cxx" | "hh" | "hpp" | "hxx" => Some(Self::Cpp),
            "java" => Some(Self::Java),
            "rb" => Some(Self::Ruby),
            "php" => Some(Self::Php),
            "swift" => Some(Self::Swift),
            "kt" | "kts" => Some(Self::Kotlin),
            "sol" => Some(Self::Solidity),
            "sql" => Some(Self::Sql),
            "tf" | "hcl" | "tfvars" => Some(Self::Hcl),
            "cs" => Some(Self::CSharp),
            "scala" | "sc" => Some(Self::Scala),
            "dart" => Some(Self::Dart),
            "lua" => Some(Self::Lua),
            "luau" => Some(Self::Luau),
            "pas" | "dpr" | "dpk" | "lpr" => Some(Self::Pascal),
            _ => None,
        }
    }

    /// Map a file path to a `Language` via its extension.
    pub fn from_path(path: &str) -> Option<Self> {
        let ext = path.rsplit('.').next()?;
        Self::from_extension(&ext.to_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
