// SPDX-License-Identifier: Apache-2.0

//! JavaScript extractor — reuses the TypeScript grammar, which is a strict
//! superset of JavaScript, so the same syntactic pass applies.
//!
//! Definitions: top-level **exported** declarations (`export function/class/
//! const`, including `export default function/class`). Type-only constructs
//! (`interface`/`type`/`enum`) simply never appear in JavaScript sources.
//! Qualified identity follows the file's module path (`src/auth/jwt.js` →
//! namespaces `src`,`auth`,`jwt`), so a symbol is `…/jwt/validateToken().`.
//! References: callee identifiers of `call_expression` nodes.
//!
//! `.jsx` files are parsed with the TSX grammar; `.js`/`.mjs`/`.cjs` with the
//! TypeScript grammar. Emits neutral [`FileFacts`] — no storage, no bodies.

use crate::error::Result;
use crate::graph::FileFacts;
use crate::lang::Language;

use super::Extractor;
use super::typescript::extract_ecmascript;

/// Extracts JavaScript symbols and references.
pub struct JavaScriptExtractor;

impl Extractor for JavaScriptExtractor {
    fn lang(&self) -> Language {
        Language::JavaScript
    }

    fn extract(&self, source: &str, file: &str) -> Result<FileFacts> {
        extract_ecmascript(source, file, Language::JavaScript, None)
    }

    fn extract_with_bindings(
        &self,
        source: &str,
        file: &str,
        rules: &super::BindingRules,
    ) -> Result<FileFacts> {
        extract_ecmascript(source, file, Language::JavaScript, Some(rules))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::types::{SymbolKind, Visibility};

    #[test]
    fn extracts_exported_decls() {
        let src = "\
export function validateToken(tok) { return helper(); }
export class Config {}
export const MAX = 3;
function internal() {}
";
        let facts = JavaScriptExtractor.extract(src, "src/auth/jwt.js").unwrap();
        let by_name = |n: &str| facts.symbols.iter().find(|s| s.name == n).cloned();

        let vt = by_name("validateToken").unwrap();
        // The SCIP scheme is "codegraph"; the language lives in `facts.lang` and
        // the symbol's `lang` field, not in the rendered string.
        assert_eq!(
            vt.id.to_scip_string(),
            "codegraph . . . src/auth/jwt/validateToken()."
        );
        assert_eq!(vt.kind, SymbolKind::Function);
        assert_eq!(vt.visibility, Visibility::Public);
        assert_eq!(facts.lang, "javascript");

        let cfg = by_name("Config").unwrap();
        assert_eq!(cfg.kind, SymbolKind::Class);
        assert_eq!(cfg.visibility, Visibility::Public);

        let max = by_name("MAX").unwrap();
        assert_eq!(max.kind, SymbolKind::Const);
        assert_eq!(max.visibility, Visibility::Public);

        // Non-exported declarations are now emitted with Visibility::Private.
        let internal = by_name("internal").expect("internal must now be emitted as Private");
        assert_eq!(internal.kind, SymbolKind::Function);
        assert_eq!(internal.visibility, Visibility::Private);
    }

    #[test]
    fn default_export_function_in_jsx() {
        let facts = JavaScriptExtractor
            .extract(
                "export default function App() { return <div/>; }",
                "src/App.jsx",
            )
            .unwrap();
        // 1 declared symbol + 1 module symbol
        assert_eq!(facts.symbols.len(), 2);
        let app = facts.symbols.iter().find(|s| s.name == "App").unwrap();
        assert_eq!(app.id.to_scip_string(), "codegraph . . . src/App/App().");
    }

    #[test]
    fn extracts_call_references_in_esm() {
        let facts = JavaScriptExtractor
            .extract(
                "function main() { validateToken('t'); helper(); }",
                "src/main.mjs",
            )
            .unwrap();
        let names: Vec<&str> = facts.references.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"validateToken"));
        assert!(names.contains(&"helper"));
    }
}
