// SPDX-License-Identifier: Apache-2.0

//! Luau extractor — reuses the Lua-family core (`extract_lua_family`).
//!
//! Luau is a typed superset of Lua whose tree-sitter AST is identical to Lua's
//! for every construct the Lua extractor already handles. The only Luau additions
//! are:
//!
//! - `type_definition` nodes (`type X = …` / `export type X = …`) → emitted as
//!   [`SymbolKind::TypeAlias`].
//! - Typed parameters and return types — these don't affect symbol extraction.
//! - `require(script.Parent.Mod)` dot-expression paths (Roblox style) — handled
//!   by the shared require import collector.
//!
//! [`SymbolKind::TypeAlias`]: crate::graph::types::SymbolKind::TypeAlias

use crate::error::Result;
use crate::graph::FileFacts;
use crate::lang::Language;

use super::{Extractor, lua::extract_lua_family};

/// Extracts Luau symbols and references by delegating to the shared Lua-family
/// extraction pass with the Luau grammar and [`Language::Luau`] tag.
pub struct LuauExtractor;

impl Extractor for LuauExtractor {
    fn lang(&self) -> Language {
        Language::Luau
    }

    fn extract(&self, source: &str, file: &str) -> Result<FileFacts> {
        extract_lua_family(source, file, Language::Luau, crate::grammar::luau())
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::types::{RefRole, SymbolKind};

    fn extract(src: &str, file: &str) -> FileFacts {
        LuauExtractor.extract(src, file).unwrap()
    }

    fn by_name(facts: &FileFacts, name: &str) -> Option<crate::graph::types::Symbol> {
        facts.symbols.iter().find(|s| s.name == name).cloned()
    }

    // (1) type_definition → SymbolKind::TypeAlias with luau scheme
    #[test]
    fn type_alias_is_extracted() {
        let src = "type Point = { x: number, y: number }";
        let facts = extract(src, "src/geo.luau");

        let sym = by_name(&facts, "Point").expect("expected Point symbol");
        assert_eq!(sym.kind, SymbolKind::TypeAlias);
        // The SCIP scheme is the literal "codegraph"; language identity is on
        // FileFacts.lang. The alias renders as a Type descriptor (`Point#`).
        assert_eq!(sym.id.to_scip_string(), "codegraph . . . geo/Point#");
        assert_eq!(facts.lang, "luau");
    }

    // (1b) export type_definition
    #[test]
    fn exported_type_alias_is_extracted() {
        let src = "export type ID = number";
        let facts = extract(src, "src/types.luau");

        let sym = by_name(&facts, "ID").expect("expected ID symbol");
        assert_eq!(sym.kind, SymbolKind::TypeAlias);
    }

    // (2) typed function — typed params/return types don't break extraction
    #[test]
    fn typed_function_is_extracted_as_function() {
        let src = "function foo(a: number): number\n  return a\nend";
        let facts = extract(src, "src/math.luau");

        let sym = by_name(&facts, "foo").expect("expected foo symbol");
        assert_eq!(sym.kind, SymbolKind::Function);
        assert_eq!(sym.id.to_scip_string(), "codegraph . . . math/foo().");
        assert_eq!(facts.lang, "luau");
    }

    // (3) table dot method → Method under Type M
    #[test]
    fn table_dot_method_is_extracted_as_method_under_type() {
        let src = "function M.baz() end";
        let facts = extract(src, "src/mod.luau");

        let sym = by_name(&facts, "baz").expect("expected baz symbol");
        assert_eq!(sym.kind, SymbolKind::Method);
        let scip = sym.id.to_scip_string();
        assert!(
            scip.contains("M#") && scip.contains("baz"),
            "unexpected SCIP string: {scip}"
        );
    }

    // (4) require('pkg') → Import reference
    #[test]
    fn require_produces_import_reference() {
        let src = "local sub = require('pkg.sub')";
        let facts = extract(src, "src/util.luau");

        let imp = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Import)
            .expect("expected Import ref from require");
        assert_eq!(imp.name, "sub");
        assert!(
            imp.from_path
                .as_deref()
                .is_some_and(|p| p.contains("pkg.sub")),
            "from_path should contain 'pkg.sub', got {:?}",
            imp.from_path
        );
    }

    // (5) .luau file path yields the right namespace
    #[test]
    fn luau_file_path_yields_correct_namespace() {
        let src = "function helper() end";
        let facts = extract(src, "src/utils/helper.luau");

        let sym = by_name(&facts, "helper").expect("expected helper symbol");
        let scip = sym.id.to_scip_string();
        // Namespace segments "utils/helper" should appear in the SCIP string.
        assert!(
            scip.contains("utils") && scip.contains("helper"),
            "unexpected SCIP string: {scip}"
        );
    }
}
