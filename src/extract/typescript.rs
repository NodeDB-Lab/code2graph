// SPDX-License-Identifier: Apache-2.0

//! TypeScript extractor — one tree-sitter pass yielding definitions and references.
//!
//! Definitions: top-level **exported** declarations (`export function/class/
//! interface/type/enum/const`, including `export default function/class`).
//! Qualified identity follows the file's module path (`src/auth/jwt.ts` →
//! namespaces `src`,`auth`,`jwt`), so a symbol is `…/jwt/validateToken().`.
//! References: callee identifiers of `call_expression` nodes.
//!
//! `.tsx`/`.jsx` files are parsed with the TSX grammar, otherwise TypeScript.
//! Emits neutral [`FileFacts`] — no storage entries, no source bodies.
//!
//! The extraction core ([`extract_ecmascript`]) is shared with the JavaScript
//! extractor, which reuses the TypeScript grammar (a superset of JavaScript);
//! the two differ only in their language tag.

use tree_sitter::{Language as TsLanguage, Node, Parser};

use crate::error::{CodegraphError, Result};
use crate::graph::types::{
    Binding, BindingKind, ByteSpan, FileFacts, RefRole, Reference, Scope, ScopeId, ScopeKind,
    Symbol, SymbolKind,
};
use crate::lang::Language;
use crate::symbol::{Descriptor, SymbolId};

use super::{
    Extractor, attach_reference_scopes, child_text, collect_call_references, definition_bindings,
    import_bindings, node_span, node_text, one_line_signature, push_binding, push_scope,
};

/// Tree-sitter query capturing call-callee identifiers.
const CALL_QUERY: &str = r#"
(call_expression
  function: [
    (identifier) @callee
    (member_expression property: (property_identifier) @callee)
  ]
)
"#;

/// Extracts TypeScript symbols and references.
pub struct TypeScriptExtractor;

impl Extractor for TypeScriptExtractor {
    fn lang(&self) -> Language {
        Language::TypeScript
    }

    fn extract(&self, source: &str, file: &str) -> Result<FileFacts> {
        extract_ecmascript(source, file, Language::TypeScript)
    }
}

/// Shared TypeScript/JavaScript extraction core. The TypeScript grammar is a
/// superset of JavaScript, so both extractors parse with it; `lang` selects the
/// language tag and SCIP scheme. `.tsx`/`.jsx` files use the TSX grammar.
pub(super) fn extract_ecmascript(source: &str, file: &str, lang: Language) -> Result<FileFacts> {
    let ts_lang = if file.ends_with(".tsx") || file.ends_with(".jsx") {
        tree_sitter_typescript::LANGUAGE_TSX
    } else {
        tree_sitter_typescript::LANGUAGE_TYPESCRIPT
    };

    let ts_language = TsLanguage::from(ts_lang);
    let mut parser = Parser::new();
    parser
        .set_language(&ts_language)
        .map_err(|_| CodegraphError::Parse {
            path: file.to_owned(),
        })?;
    let tree = parser
        .parse(source, None)
        .ok_or_else(|| CodegraphError::Parse {
            path: file.to_owned(),
        })?;

    let root = tree.root_node();
    let bytes = source.as_bytes();
    let namespaces = module_namespaces(file);

    let defs = collect_symbols(&root, bytes, file, &namespaces, lang);
    let def_bindings = definition_bindings(&defs);
    let mut symbols = defs;
    let mod_sym = super::module_symbol(lang, &namespaces, file, source.len());
    let module_id = mod_sym.id.to_scip_string();
    symbols.push(mod_sym);
    let mut references =
        collect_call_references(&root, &ts_language, CALL_QUERY, lang, bytes, file)?;
    collect_inheritance(&root, bytes, file, &mut references);
    collect_imports(&root, bytes, file, &mut references, &module_id);

    let scopes = collect_scopes(&root, source.len());
    attach_reference_scopes(&mut references, &scopes);
    let mut bindings = collect_bindings(&root, bytes, &scopes);
    bindings.extend(def_bindings);
    bindings.extend(import_bindings(&references, &scopes));

    Ok(FileFacts {
        file: file.to_owned(),
        lang: lang.as_str().to_owned(),
        symbols,
        references,
        scopes,
        bindings,
        ffi_exports: Vec::new(),
    })
}

/// Module path (namespace descriptors) from a source file path: all path
/// segments, with the final file extension stripped from the last segment.
fn module_namespaces(file: &str) -> Vec<String> {
    let mut parts: Vec<String> = file
        .split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    if let Some(last) = parts.pop() {
        let stem = last
            .rsplit_once('.')
            .map_or(last.as_str(), |(stem, _)| stem);
        parts.push(stem.to_owned());
    }
    parts
}

fn collect_symbols(
    root: &Node,
    bytes: &[u8],
    file: &str,
    namespaces: &[String],
    lang: Language,
) -> Vec<Symbol> {
    let mut out = Vec::new();
    for stmt in root.children(&mut root.walk()) {
        if stmt.kind() != "export_statement" {
            continue;
        }
        // The exported declaration is a direct child of the export statement.
        for decl in stmt.children(&mut stmt.walk()) {
            emit_declaration(&decl, &stmt, bytes, file, namespaces, lang, &mut out);
        }
    }
    out
}

/// Append symbol(s) for one declaration node (a `lexical_declaration` may yield
/// several). `span_node` is the enclosing `export_statement`.
fn emit_declaration(
    decl: &Node,
    span_node: &Node,
    bytes: &[u8],
    file: &str,
    namespaces: &[String],
    lang: Language,
    out: &mut Vec<Symbol>,
) {
    let push = |out: &mut Vec<Symbol>, name: String, kind: SymbolKind, leaf: Descriptor| {
        let mut descriptors: Vec<Descriptor> = namespaces
            .iter()
            .cloned()
            .map(Descriptor::Namespace)
            .collect();
        descriptors.push(leaf);
        out.push(Symbol {
            id: SymbolId::global(lang.as_str(), descriptors),
            name,
            kind,
            file: file.to_owned(),
            line: (span_node.start_position().row + 1) as u32,
            span: ByteSpan {
                start: span_node.start_byte(),
                end: span_node.end_byte(),
            },
            signature: one_line_signature(node_text(decl, bytes), &['{']),
        });
    };

    match decl.kind() {
        "function_declaration" => {
            if let Some(n) = child_text(decl, "identifier", bytes) {
                push(
                    out,
                    n.clone(),
                    SymbolKind::Function,
                    Descriptor::Method {
                        name: n,
                        disambiguator: String::new(),
                    },
                );
            }
        }
        "class_declaration" => emit_named(decl, bytes, SymbolKind::Class, out, &push),
        "interface_declaration" => emit_named(decl, bytes, SymbolKind::Interface, out, &push),
        "type_alias_declaration" => emit_named(decl, bytes, SymbolKind::TypeAlias, out, &push),
        "enum_declaration" => {
            if let Some(n) = child_text(decl, "identifier", bytes) {
                push(out, n.clone(), SymbolKind::Enum, Descriptor::Type(n));
            }
        }
        "lexical_declaration" => {
            for vd in decl.children(&mut decl.walk()) {
                if vd.kind() != "variable_declarator" {
                    continue;
                }
                if let Some(n) = child_text(&vd, "identifier", bytes) {
                    push(out, n.clone(), SymbolKind::Const, Descriptor::Term(n));
                }
            }
        }
        _ => {}
    }
}

/// Emit a type-named declaration (class/interface/type-alias) named by a
/// `type_identifier`.
fn emit_named(
    decl: &Node,
    bytes: &[u8],
    kind: SymbolKind,
    out: &mut Vec<Symbol>,
    push: &impl Fn(&mut Vec<Symbol>, String, SymbolKind, Descriptor),
) {
    if let Some(n) = child_text(decl, "type_identifier", bytes) {
        push(out, n.clone(), kind, Descriptor::Type(n));
    }
}

/// Recursively walk `node` collecting `Inherit` references for every
/// `class_declaration` and `interface_declaration` in the tree (including nested
/// classes).
///
/// Tree-sitter node shape (TypeScript / TSX grammar):
/// - `class_declaration` → optional `class_heritage` child
///   - `extends_clause` → field `value` (the superclass expression)
///   - `implements_clause` → named children: `type_identifier | generic_type |
///     nested_type_identifier`
/// - `interface_declaration` → optional `extends_type_clause` child
///   - named children: `type_identifier | generic_type | nested_type_identifier`
fn collect_inheritance(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    match node.kind() {
        "class_declaration" => {
            // Locate the `class_heritage` child (if any).
            if let Some(heritage) = node
                .children(&mut node.walk())
                .find(|c| c.kind() == "class_heritage")
            {
                for clause in heritage.children(&mut heritage.walk()) {
                    match clause.kind() {
                        "extends_clause" => {
                            // The superclass is the `value` field.
                            if let Some(value) = clause.child_by_field_name("value") {
                                super::push_ref(
                                    out,
                                    super::simple_type_name(node_text(&value, bytes), "."),
                                    &value,
                                    file,
                                    RefRole::IsImplementation,
                                );
                            }
                        }
                        "implements_clause" => {
                            // Each named child is an implemented interface type.
                            for type_node in clause.children(&mut clause.walk()) {
                                if type_node.is_named()
                                    && matches!(
                                        type_node.kind(),
                                        "type_identifier"
                                            | "generic_type"
                                            | "nested_type_identifier"
                                    )
                                {
                                    super::push_ref(
                                        out,
                                        super::simple_type_name(node_text(&type_node, bytes), "."),
                                        &type_node,
                                        file,
                                        RefRole::IsImplementation,
                                    );
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        "interface_declaration" => {
            // Locate the `extends_type_clause` child (if any).
            if let Some(extends_clause) = node
                .children(&mut node.walk())
                .find(|c| c.kind() == "extends_type_clause")
            {
                for type_node in extends_clause.children(&mut extends_clause.walk()) {
                    if type_node.is_named()
                        && matches!(
                            type_node.kind(),
                            "type_identifier" | "generic_type" | "nested_type_identifier"
                        )
                    {
                        super::push_ref(
                            out,
                            super::simple_type_name(node_text(&type_node, bytes), "."),
                            &type_node,
                            file,
                            RefRole::IsImplementation,
                        );
                    }
                }
            }
        }
        _ => {}
    }

    // Recurse into all children so nested classes are covered.
    for child in node.children(&mut node.walk()) {
        collect_inheritance(&child, bytes, file, out);
    }
}

/// Recursively walk `node` collecting `Import` references for every
/// `import_statement` in the tree.
///
/// Tree-sitter node shape (TypeScript / TSX grammar):
/// ```text
/// import_statement
///   source: string            ← module path string — IGNORED
///   import_clause
///     identifier              ← default import: `import Foo from "x"`
///     named_imports
///       import_specifier
///         name: identifier    ← named import binding: `import { A } from "x"`
///         alias: identifier   ← IGNORED (`import { A as B }`)
///     namespace_import        ← `import * as ns from "x"` — SKIPPED entirely
/// ```
///
/// Only the binding name at the call-site is emitted; module sources and
/// aliases are deliberately not recorded.
fn collect_imports(
    node: &Node,
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Reference>,
    module_id: &str,
) {
    if node.kind() == "import_statement" {
        // Extract the from-path once from the `source` field (a string literal).
        // The raw text includes surrounding quotes; strip both styles.
        let from_path = node
            .child_by_field_name("source")
            .map(|n| {
                let raw = super::node_text(&n, bytes);
                raw.trim_matches('"').trim_matches('\'').to_owned()
            })
            .unwrap_or_default();

        // Locate the `import_clause` child (may be absent for bare `import "x"`).
        if let Some(clause) = node
            .children(&mut node.walk())
            .find(|c| c.kind() == "import_clause")
        {
            for child in clause.children(&mut clause.walk()) {
                match child.kind() {
                    // Default import: `import Foo from "x"`
                    "identifier" => {
                        super::push_import_ref(
                            out,
                            super::node_text(&child, bytes),
                            &child,
                            file,
                            module_id,
                            &from_path,
                        );
                    }
                    // Named imports: `import { A, B as C } from "x"`
                    "named_imports" => {
                        for specifier in child.children(&mut child.walk()) {
                            if specifier.kind() != "import_specifier" {
                                continue;
                            }
                            // `name` field is the real (original) name, not the alias.
                            if let Some(name_node) = specifier.child_by_field_name("name") {
                                if name_node.kind() == "identifier" {
                                    super::push_import_ref(
                                        out,
                                        super::node_text(&name_node, bytes),
                                        &name_node,
                                        file,
                                        module_id,
                                        &from_path,
                                    );
                                }
                                // string-named imports (exotic) → skip silently
                            }
                        }
                    }
                    // Namespace import: `import * as ns from "x"` → skip
                    "namespace_import" => {}
                    _ => {}
                }
            }
        }
        // Do not recurse further into `import_statement`; it cannot contain
        // nested import statements.
        return;
    }

    // Recurse into all other nodes so top-level and module-scoped imports are covered.
    for child in node.children(&mut node.walk()) {
        collect_imports(&child, bytes, file, out, module_id);
    }
}

// ── Scope tree (Tier-B) ──────────────────────────────────────────────────────

/// ECMAScript function-like node kinds — each opens a `Function` scope.
const FN_KINDS: &[&str] = &[
    "function_declaration",
    "function_expression",
    "arrow_function",
    "method_definition",
    "generator_function_declaration",
    "generator_function",
];

/// Build the lexical scope tree for one TS/JS file.
///
/// `scopes[0]` is the file-root `Module` scope. ECMAScript is block-scoped:
/// every function-like node opens a `Function` scope and every standalone
/// `statement_block` (an `if`/`for`/`while` body or a bare block) opens a
/// `Block` scope. A `class` body opens no scope — like Python's LEGB, a method's
/// unqualified name lookup does not see class members.
///
/// Known v1 boundary: `var` is function-scoped but is recorded as a block-scoped
/// local (treated like `let`); hoisting of `var` is not modelled.
fn collect_scopes(root: &Node, source_len: usize) -> Vec<Scope> {
    let mut scopes = Vec::new();
    push_scope(
        &mut scopes,
        None,
        ByteSpan {
            start: 0,
            end: source_len,
        },
        ScopeKind::Module,
    );
    for child in root.children(&mut root.walk()) {
        scope_dfs(&child, 0, &mut scopes);
    }
    scopes
}

fn scope_dfs(node: &Node, parent_id: ScopeId, scopes: &mut Vec<Scope>) {
    if FN_KINDS.contains(&node.kind()) {
        let fn_id = push_scope(
            scopes,
            Some(parent_id),
            node_span(node),
            ScopeKind::Function,
        );
        // Recurse the body. For a brace body, descend into its children directly
        // so the body `statement_block` does not open a redundant nested scope.
        if let Some(body) = node.child_by_field_name("body") {
            if body.kind() == "statement_block" {
                for child in body.children(&mut body.walk()) {
                    scope_dfs(&child, fn_id, scopes);
                }
            } else {
                scope_dfs(&body, fn_id, scopes); // arrow with an expression body
            }
        }
    } else if node.kind() == "statement_block" {
        let block_id = push_scope(scopes, Some(parent_id), node_span(node), ScopeKind::Block);
        for child in node.children(&mut node.walk()) {
            scope_dfs(&child, block_id, scopes);
        }
    } else {
        for child in node.children(&mut node.walk()) {
            scope_dfs(&child, parent_id, scopes);
        }
    }
}

// ── Bindings (Tier-B) ────────────────────────────────────────────────────────

/// Collect parameter and variable [`Binding`]s for one TS/JS file.
///
/// Covers function parameters and `let`/`const`/`var` declarators (each a bare
/// `identifier` name; destructuring patterns are deferred). Top-level definitions
/// and imports are added by the caller from the shared helpers.
fn collect_bindings(root: &Node, bytes: &[u8], scopes: &[Scope]) -> Vec<Binding> {
    let mut out = Vec::new();
    collect_bindings_dfs(root, bytes, scopes, &mut out);
    out
}

fn collect_bindings_dfs(node: &Node, bytes: &[u8], scopes: &[Scope], out: &mut Vec<Binding>) {
    if FN_KINDS.contains(&node.kind()) {
        if let Some(params) = node.child_by_field_name("parameters") {
            collect_params(&params, bytes, scopes, out);
        } else if let Some(p) = node.child_by_field_name("parameter") {
            // single-identifier arrow parameter, e.g. `x => …`
            if p.kind() == "identifier" {
                push_binding(
                    out,
                    node_text(&p, bytes).to_owned(),
                    p.start_byte(),
                    BindingKind::Param,
                    scopes,
                );
            }
        }
        for child in node.children(&mut node.walk()) {
            collect_bindings_dfs(&child, bytes, scopes, out);
        }
    } else if node.kind() == "variable_declarator" {
        // `let`/`const` (lexical_declaration) and `var` (variable_declaration)
        // both nest a `variable_declarator` with a `name` field.
        if let Some(name) = node.child_by_field_name("name") {
            if name.kind() == "identifier" {
                push_binding(
                    out,
                    node_text(&name, bytes).to_owned(),
                    name.start_byte(),
                    BindingKind::Local,
                    scopes,
                );
            }
        }
        for child in node.children(&mut node.walk()) {
            collect_bindings_dfs(&child, bytes, scopes, out);
        }
    } else {
        for child in node.children(&mut node.walk()) {
            collect_bindings_dfs(&child, bytes, scopes, out);
        }
    }
}

/// Emit a [`BindingKind::Param`] for each parameter in a `formal_parameters`
/// node, unwrapping the typed `required_parameter`/`optional_parameter` forms.
fn collect_params(params: &Node, bytes: &[u8], scopes: &[Scope], out: &mut Vec<Binding>) {
    for child in params.named_children(&mut params.walk()) {
        let ident = match child.kind() {
            "identifier" => Some(child),
            "required_parameter" | "optional_parameter" => child.child_by_field_name("pattern"),
            _ => None,
        };
        if let Some(id) = ident {
            if id.kind() == "identifier" {
                push_binding(
                    out,
                    node_text(&id, bytes).to_owned(),
                    id.start_byte(),
                    BindingKind::Param,
                    scopes,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_exported_decls() {
        let src = "\
export function validateToken(tok: string): boolean { return helper(); }
export class Config {}
export interface Options { timeout: number; }
export const MAX = 3;
function internal() {}
";
        let facts = TypeScriptExtractor.extract(src, "src/auth/jwt.ts").unwrap();
        let by_name = |n: &str| facts.symbols.iter().find(|s| s.name == n).cloned();

        let vt = by_name("validateToken").unwrap();
        assert_eq!(
            vt.id.to_scip_string(),
            "codegraph . . . src/auth/jwt/validateToken()."
        );
        assert_eq!(vt.kind, SymbolKind::Function);

        assert_eq!(by_name("Config").unwrap().kind, SymbolKind::Class);
        assert_eq!(by_name("Options").unwrap().kind, SymbolKind::Interface);
        assert_eq!(by_name("MAX").unwrap().kind, SymbolKind::Const);
        // non-exported declarations are not symbols
        assert!(by_name("internal").is_none());
    }

    #[test]
    fn default_export_function_is_named() {
        let facts = TypeScriptExtractor
            .extract("export default function App() {}", "src/App.tsx")
            .unwrap();
        // 1 declared symbol + 1 module symbol
        assert_eq!(facts.symbols.len(), 2);
        let app = facts.symbols.iter().find(|s| s.name == "App").unwrap();
        assert_eq!(app.id.to_scip_string(), "codegraph . . . src/App/App().");
    }

    #[test]
    fn emits_function_block_scopes_and_bindings() {
        let src = "export function run(arg: number) {\n  const local = 1;\n  if (arg) { helper(local); }\n}\n";
        let facts = TypeScriptExtractor.extract(src, "src/main.ts").unwrap();
        assert!(
            facts.scopes.iter().any(|s| s.kind == ScopeKind::Function),
            "expected a Function scope"
        );
        assert!(
            facts.scopes.iter().any(|s| s.kind == ScopeKind::Block),
            "expected a Block scope (the if body)"
        );
        let has = |name: &str, kind: BindingKind| {
            facts
                .bindings
                .iter()
                .any(|b| b.name == name && b.kind == kind)
        };
        assert!(has("arg", BindingKind::Param), "param binding missing");
        assert!(
            has("local", BindingKind::Local),
            "const local binding missing"
        );
        assert!(has("run", BindingKind::Definition), "def binding missing");
    }

    #[test]
    fn extracts_call_references() {
        let facts = TypeScriptExtractor
            .extract(
                "function main() { validateToken('t'); helper(); }",
                "src/main.ts",
            )
            .unwrap();
        let names: Vec<&str> = facts.references.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"validateToken"));
        assert!(names.contains(&"helper"));
    }

    // ── Inheritance tests ────────────────────────────────────────────────────

    #[test]
    fn ts_class_extends_and_implements() {
        let src = "class Sub extends Base implements Iface {}";
        let facts = TypeScriptExtractor.extract(src, "src/sub.ts").unwrap();
        let inherit_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            inherit_names.contains(&"Base"),
            "expected 'Base' in {inherit_names:?}"
        );
        assert!(
            inherit_names.contains(&"Iface"),
            "expected 'Iface' in {inherit_names:?}"
        );
    }

    #[test]
    fn ts_interface_extends_multiple() {
        let src = "interface I extends A, B {}";
        let facts = TypeScriptExtractor.extract(src, "src/i.ts").unwrap();
        let inherit_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            inherit_names.contains(&"A"),
            "expected 'A' in {inherit_names:?}"
        );
        assert!(
            inherit_names.contains(&"B"),
            "expected 'B' in {inherit_names:?}"
        );
    }

    #[test]
    fn ts_class_extends_qualified_name() {
        let src = "class C extends ns.Base {}";
        let facts = TypeScriptExtractor.extract(src, "src/c.ts").unwrap();
        let inherit_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            inherit_names.contains(&"Base"),
            "expected leaf 'Base' from 'ns.Base' in {inherit_names:?}"
        );
    }

    #[test]
    fn js_class_extends_base() {
        // JavaScript routes through the same extract_ecmascript core; verify
        // that inheritance edges are emitted for .js files too.
        use crate::extract::Extractor as _;
        use crate::extract::JavaScriptExtractor;
        let src = "class Sub extends Base {}";
        let facts = JavaScriptExtractor.extract(src, "src/sub.js").unwrap();
        let inherit_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            inherit_names.contains(&"Base"),
            "expected 'Base' in JS inherit refs: {inherit_names:?}"
        );
    }

    // ── Import reference tests ───────────────────────────────────────────────

    #[test]
    fn ts_named_import_emits_import_ref() {
        // `import { Service } from "./svc";` → one Import ref `Service`
        let src = r#"import { Service } from "./svc";"#;
        let facts = TypeScriptExtractor.extract(src, "src/client.ts").unwrap();
        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(
            import_names,
            vec!["Service"],
            "expected exactly [Service], got {import_names:?}"
        );
    }

    #[test]
    fn ts_default_import_emits_import_ref() {
        // `import Foo from "./foo";` → Import ref `Foo`
        let src = r#"import Foo from "./foo";"#;
        let facts = TypeScriptExtractor.extract(src, "src/use.ts").unwrap();
        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            import_names.contains(&"Foo"),
            "expected 'Foo' in import refs: {import_names:?}"
        );
    }

    #[test]
    fn ts_named_import_with_alias_emits_real_name() {
        // `import { A, B as C } from "x";` → Import refs `A` and `B` (not alias `C`)
        let src = r#"import { A, B as C } from "x";"#;
        let facts = TypeScriptExtractor.extract(src, "src/aliases.ts").unwrap();
        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            import_names.contains(&"A"),
            "expected 'A' in import refs: {import_names:?}"
        );
        assert!(
            import_names.contains(&"B"),
            "expected 'B' (real name) in import refs: {import_names:?}"
        );
        assert!(
            !import_names.contains(&"C"),
            "alias 'C' must NOT appear in import refs: {import_names:?}"
        );
    }

    #[test]
    fn ts_namespace_import_emits_no_import_refs() {
        // `import * as ns from "x";` → NO Import refs
        let src = r#"import * as ns from "x";"#;
        let facts = TypeScriptExtractor.extract(src, "src/ns.ts").unwrap();
        let import_refs: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            import_refs.is_empty(),
            "namespace import must produce no Import refs, got {import_refs:?}"
        );
    }

    #[test]
    fn js_named_import_emits_import_ref() {
        // JavaScript (.js) through the shared extract_ecmascript core.
        // `import { thing } from "./m";` → Import ref `thing`
        use crate::extract::Extractor as _;
        use crate::extract::JavaScriptExtractor;
        let src = r#"import { thing } from "./m";"#;
        let facts = JavaScriptExtractor.extract(src, "src/consumer.js").unwrap();
        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            import_names.contains(&"thing"),
            "expected 'thing' in JS import refs: {import_names:?}"
        );
    }

    #[test]
    fn ts_import_refs_carry_source_module() {
        // `import { Service } from "./svc";` in src/auth/client.ts → all
        // Import refs carry the SCIP module id of src/auth/client.
        let src = r#"import { Service } from "./svc";"#;
        let file = "src/auth/client.ts";
        let facts = TypeScriptExtractor.extract(src, file).unwrap();

        let namespaces = module_namespaces(file);
        let expected_module_id =
            crate::extract::module_symbol(Language::TypeScript, &namespaces, file, src.len())
                .id
                .to_scip_string();

        let import_refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .collect();
        assert!(!import_refs.is_empty(), "expected at least one Import ref");
        for r in &import_refs {
            assert_eq!(
                r.source_module,
                Some(expected_module_id.clone()),
                "Import ref '{}' should carry source_module = {:?}",
                r.name,
                expected_module_id
            );
        }
    }

    // --- from_path tests ---

    #[test]
    fn ts_named_import_carries_from_path() {
        // `import { Service } from "./svc";` → from_path == "./svc" (quotes stripped)
        let src = r#"import { Service } from "./svc";"#;
        let facts = TypeScriptExtractor.extract(src, "src/client.ts").unwrap();
        let r = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Import && r.name == "Service")
            .expect("expected Import ref for 'Service'");
        assert_eq!(
            r.from_path,
            Some("./svc".to_owned()),
            "from_path should be './svc', got {:?}",
            r.from_path
        );
    }
}
