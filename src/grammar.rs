// SPDX-License-Identifier: Apache-2.0

//! Grammar chokepoint — the **sole** importer of every `tree_sitter_*` grammar crate.
//!
//! Each public function returns a [`tree_sitter::Language`] for the requested grammar
//! and is gated on the corresponding Cargo feature (`rust`, `python`, `typescript`, …).
//! All grammar crate imports live here; no extractor module may import a grammar crate
//! directly.

#[cfg(feature = "_extractors")]
use tree_sitter::Language;

#[cfg(feature = "rust")]
/// Returns the tree-sitter grammar for Rust.
pub fn rust() -> Language {
    tree_sitter_rust::LANGUAGE.into()
}

#[cfg(feature = "python")]
/// Returns the tree-sitter grammar for Python.
pub fn python() -> Language {
    tree_sitter_python::LANGUAGE.into()
}

#[cfg(feature = "typescript")]
/// Returns the tree-sitter grammar for TypeScript.
pub fn typescript() -> Language {
    tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()
}

#[cfg(feature = "typescript")]
/// Returns the tree-sitter grammar for TSX (TypeScript + JSX).
pub fn tsx() -> Language {
    tree_sitter_typescript::LANGUAGE_TSX.into()
}

#[cfg(feature = "go")]
/// Returns the tree-sitter grammar for Go.
pub fn go() -> Language {
    tree_sitter_go::LANGUAGE.into()
}

#[cfg(feature = "java")]
/// Returns the tree-sitter grammar for Java.
pub fn java() -> Language {
    tree_sitter_java::LANGUAGE.into()
}

#[cfg(feature = "c")]
/// Returns the tree-sitter grammar for C.
pub fn c() -> Language {
    tree_sitter_c::LANGUAGE.into()
}

#[cfg(feature = "cpp")]
/// Returns the tree-sitter grammar for C++.
pub fn cpp() -> Language {
    tree_sitter_cpp::LANGUAGE.into()
}

#[cfg(feature = "ruby")]
/// Returns the tree-sitter grammar for Ruby.
pub fn ruby() -> Language {
    tree_sitter_ruby::LANGUAGE.into()
}

#[cfg(feature = "php")]
/// Returns the tree-sitter grammar for PHP.
pub fn php() -> Language {
    tree_sitter_php::LANGUAGE_PHP.into()
}

#[cfg(feature = "shell")]
/// Returns the tree-sitter grammar for Bash/Shell (via `tree-sitter-bash`).
pub fn shell() -> Language {
    tree_sitter_bash::LANGUAGE.into()
}

#[cfg(feature = "swift")]
/// Returns the tree-sitter grammar for Swift.
pub fn swift() -> Language {
    tree_sitter_swift::LANGUAGE.into()
}

#[cfg(feature = "kotlin")]
/// Returns the tree-sitter grammar for Kotlin (via `tree-sitter-kotlin-ng`).
pub fn kotlin() -> Language {
    tree_sitter_kotlin_ng::LANGUAGE.into()
}

#[cfg(feature = "solidity")]
/// Returns the tree-sitter grammar for Solidity.
pub fn solidity() -> Language {
    tree_sitter_solidity::LANGUAGE.into()
}

#[cfg(feature = "sql")]
/// Returns the tree-sitter grammar for SQL (via `tree-sitter-sequel`).
pub fn sql() -> Language {
    tree_sitter_sequel::LANGUAGE.into()
}

#[cfg(feature = "hcl")]
/// Returns the tree-sitter grammar for HCL (HashiCorp Configuration Language).
pub fn hcl() -> Language {
    tree_sitter_hcl::LANGUAGE.into()
}

#[cfg(feature = "csharp")]
/// Returns the tree-sitter grammar for C#.
pub fn csharp() -> Language {
    tree_sitter_c_sharp::LANGUAGE.into()
}

#[cfg(feature = "scala")]
/// Returns the tree-sitter grammar for Scala.
pub fn scala() -> Language {
    tree_sitter_scala::LANGUAGE.into()
}

#[cfg(feature = "dart")]
/// Returns the tree-sitter grammar for Dart.
pub fn dart() -> Language {
    tree_sitter_dart::LANGUAGE.into()
}

#[cfg(feature = "lua")]
/// Returns the tree-sitter grammar for Lua.
pub fn lua() -> Language {
    tree_sitter_lua::LANGUAGE.into()
}

#[cfg(feature = "luau")]
/// Returns the tree-sitter grammar for Luau.
pub fn luau() -> Language {
    tree_sitter_luau::LANGUAGE.into()
}

#[cfg(feature = "pascal")]
/// Returns the tree-sitter grammar for Pascal / Delphi.
pub fn pascal() -> Language {
    tree_sitter_pascal::LANGUAGE.into()
}

#[cfg(feature = "svelte")]
/// Returns the tree-sitter grammar for Svelte single-file components.
pub fn svelte() -> Language {
    tree_sitter_svelte_ng::LANGUAGE.into()
}

#[cfg(test)]
mod tests {
    #[cfg(any(
        feature = "rust",
        feature = "python",
        feature = "typescript",
        feature = "go",
        feature = "java",
        feature = "c",
        feature = "cpp",
        feature = "ruby",
        feature = "php",
        feature = "shell",
        feature = "swift",
        feature = "kotlin",
        feature = "solidity",
        feature = "sql",
        feature = "hcl",
        feature = "csharp",
        feature = "scala",
        feature = "dart",
        feature = "lua",
        feature = "luau",
        feature = "pascal",
        feature = "svelte"
    ))]
    use tree_sitter::{LANGUAGE_VERSION, MIN_COMPATIBLE_LANGUAGE_VERSION};

    #[cfg(any(
        feature = "rust",
        feature = "python",
        feature = "typescript",
        feature = "go",
        feature = "java",
        feature = "c",
        feature = "cpp",
        feature = "ruby",
        feature = "php",
        feature = "shell",
        feature = "swift",
        feature = "kotlin",
        feature = "solidity",
        feature = "sql",
        feature = "hcl",
        feature = "csharp",
        feature = "scala",
        feature = "dart",
        feature = "lua",
        feature = "luau",
        feature = "pascal",
        feature = "svelte"
    ))]
    fn check(name: &str, lang: tree_sitter::Language) {
        let v = lang.abi_version();
        assert!(
            (MIN_COMPATIBLE_LANGUAGE_VERSION..=LANGUAGE_VERSION).contains(&v),
            "grammar `{name}` ABI {v} outside [{MIN_COMPATIBLE_LANGUAGE_VERSION}, {LANGUAGE_VERSION}]"
        );
    }

    #[cfg(feature = "_extractors")]
    #[test]
    fn abi_versions_are_compatible() {
        #[cfg(feature = "rust")]
        check("rust", super::rust());
        #[cfg(feature = "python")]
        check("python", super::python());
        #[cfg(feature = "typescript")]
        check("typescript", super::typescript());
        #[cfg(feature = "typescript")]
        check("tsx", super::tsx());
        #[cfg(feature = "go")]
        check("go", super::go());
        #[cfg(feature = "java")]
        check("java", super::java());
        #[cfg(feature = "c")]
        check("c", super::c());
        #[cfg(feature = "cpp")]
        check("cpp", super::cpp());
        #[cfg(feature = "ruby")]
        check("ruby", super::ruby());
        #[cfg(feature = "php")]
        check("php", super::php());
        #[cfg(feature = "shell")]
        check("shell", super::shell());
        #[cfg(feature = "swift")]
        check("swift", super::swift());
        #[cfg(feature = "kotlin")]
        check("kotlin", super::kotlin());
        #[cfg(feature = "solidity")]
        check("solidity", super::solidity());
        #[cfg(feature = "sql")]
        check("sql", super::sql());
        #[cfg(feature = "hcl")]
        check("hcl", super::hcl());
        #[cfg(feature = "csharp")]
        check("csharp", super::csharp());
        #[cfg(feature = "scala")]
        check("scala", super::scala());
        #[cfg(feature = "dart")]
        check("dart", super::dart());
        #[cfg(feature = "lua")]
        check("lua", super::lua());
        #[cfg(feature = "luau")]
        check("luau", super::luau());
        #[cfg(feature = "pascal")]
        check("pascal", super::pascal());
        #[cfg(feature = "svelte")]
        check("svelte", super::svelte());
    }
}
