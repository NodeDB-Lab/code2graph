// SPDX-License-Identifier: Apache-2.0

//! C extractor — one tree-sitter pass yielding definitions and references.
//!
//! Definitions: top-level **non-static** declarations. Covers functions,
//! variables, struct/union/enum type definitions, typedefs, and preprocessor
//! macros (`#define`). Qualified identity is derived from the file path
//! (`src/auth/token.c` → namespaces `auth`, `token`). The same
//! stem is shared by `.c` and `.h` files so paired translation units share a
//! namespace.
//! References: callee identifiers of `call_expression` nodes.
//!
//! Emits neutral [`FileFacts`] — no storage entries, no source bodies.

use tree_sitter::{Language as TsLanguage, Node, Parser};

use crate::error::{CodegraphError, Result};
use crate::graph::types::{
    Binding, BindingKind, ByteSpan, FfiAbi, FfiExport, FileFacts, Scope, ScopeId, ScopeKind,
    Symbol, SymbolKind,
};
use crate::lang::Language;
use crate::symbol::{Descriptor, SymbolId};

use super::{
    Extractor, attach_reference_scopes, collect_call_references, definition_bindings, field_text,
    innermost_scope, is_static, node_span, node_text, one_line_signature, push_binding, push_scope,
};

// NOTE: SymbolKind has no Union or Macro variants; unions map to Struct,
// and preprocessor macros use Descriptor::Macro for SCIP identity (which
// renders with `!`), paired with SymbolKind::Const or SymbolKind::Function.

/// Tree-sitter query capturing call-callee identifiers.
const CALL_QUERY: &str = r#"
(call_expression
  function: (identifier) @callee
)
"#;

/// Extracts C symbols and references.
pub struct CExtractor;

impl Extractor for CExtractor {
    fn lang(&self) -> Language {
        Language::C
    }

    fn extract(&self, source: &str, file: &str) -> Result<FileFacts> {
        let ts_language = TsLanguage::from(tree_sitter_c::LANGUAGE);
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
        let namespaces = c_namespaces(file);

        let defs = collect_symbols(&root, bytes, file, &namespaces);
        let def_bindings = definition_bindings(&defs);
        let ffi_exports = jni_exports(&defs);
        let mut symbols = defs;
        symbols.push(super::module_symbol(
            Language::C,
            &namespaces,
            file,
            source.len(),
        ));
        let mut references =
            collect_call_references(&root, &ts_language, CALL_QUERY, Language::C, bytes, file)?;

        let scopes = collect_scopes(&root, source.len());
        attach_reference_scopes(&mut references, &scopes);
        let mut bindings = collect_bindings(&root, bytes, &scopes);
        bindings.extend(def_bindings);

        Ok(FileFacts {
            file: file.to_owned(),
            lang: Language::C.as_str().to_owned(),
            symbols,
            references,
            scopes,
            bindings,
            ffi_exports,
        })
    }
}

/// Derive the C namespace path from a file path.
///
/// Strips the `.c` or `.h` extension, strips a leading `src/` prefix, then
/// splits on `/`. The file stem is kept as the last namespace segment. Paired
/// `.c`/`.h` files intentionally share a namespace via the common stem.
fn c_namespaces(file: &str) -> Vec<String> {
    let p = file
        .strip_suffix(".c")
        .or_else(|| file.strip_suffix(".h"))
        .unwrap_or(file);
    let p = p.strip_prefix("src/").unwrap_or(p);
    p.split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Emit a JNI [`FfiExport`] for each function whose name follows the `Java_*`
/// mangling — the common case where a Java `native` method's implementation is
/// written in C. The resolver bridges it to the declaring Java method.
fn jni_exports(symbols: &[Symbol]) -> Vec<FfiExport> {
    symbols
        .iter()
        .filter(|s| s.kind == SymbolKind::Function && s.name.starts_with("Java_"))
        .map(|s| FfiExport {
            symbol: s.id.clone(),
            abi: FfiAbi::Jni,
            export_name: s.name.clone(),
        })
        .collect()
}

/// Walk a declarator subtree to the inner name identifier; returns `(name, is_function)`.
///
/// C nests names arbitrarily deep inside declarator chains:
/// `*(*fn)(int)` → `pointer_declarator` → `parenthesized_declarator` →
/// `function_declarator` → `pointer_declarator` → `identifier`.
/// `is_function` is `true` only when a `function_declarator` is encountered on
/// the path, distinguishing function declarations from variable declarations.
fn declarator_name(node: &Node, bytes: &[u8]) -> Option<(String, bool)> {
    match node.kind() {
        "identifier" | "type_identifier" | "field_identifier" => {
            Some((node_text(node, bytes).to_owned(), false))
        }
        "function_declarator" => {
            let inner = node.child_by_field_name("declarator")?;
            let (name, _) = declarator_name(&inner, bytes)?;
            Some((name, true))
        }
        _ => {
            // pointer_declarator / init_declarator / array_declarator /
            // attributed_declarator — all expose a "declarator" named field.
            if let Some(d) = node.child_by_field_name("declarator") {
                return declarator_name(&d, bytes);
            }
            // parenthesized_declarator has no named field — scan children.
            for c in node.children(&mut node.walk()) {
                if let Some(r) = declarator_name(&c, bytes) {
                    return Some(r);
                }
            }
            None
        }
    }
}

/// Walk a declarator subtree to find the innermost `function_declarator` node.
///
/// C allows pointer (and other) wrapping around a `function_declarator`:
/// `int *f(int a)` → `pointer_declarator` → `function_declarator`. This helper
/// descends the same chain as [`declarator_name`] and returns the first
/// `function_declarator` encountered, so `collect_bindings_dfs` can reliably
/// reach its `parameters` field regardless of wrapping.
fn find_function_declarator<'tree>(node: &Node<'tree>) -> Option<Node<'tree>> {
    if node.kind() == "function_declarator" {
        return Some(*node);
    }
    // pointer_declarator / init_declarator / array_declarator all have a "declarator" field.
    if let Some(inner) = node.child_by_field_name("declarator") {
        return find_function_declarator(&inner);
    }
    // parenthesized_declarator — scan children.
    for child in node.children(&mut node.walk()) {
        if let Some(found) = find_function_declarator(&child) {
            return Some(found);
        }
    }
    None
}

fn collect_symbols(root: &Node, bytes: &[u8], file: &str, namespaces: &[String]) -> Vec<Symbol> {
    let mut out = Vec::new();

    let push =
        |out: &mut Vec<Symbol>, node: &Node, name: String, kind: SymbolKind, leaf: Descriptor| {
            let mut descriptors: Vec<Descriptor> = namespaces
                .iter()
                .cloned()
                .map(Descriptor::Namespace)
                .collect();
            descriptors.push(leaf);
            out.push(Symbol {
                id: SymbolId::global(Language::C.as_str(), descriptors),
                name,
                kind,
                file: file.to_owned(),
                line: (node.start_position().row + 1) as u32,
                span: ByteSpan {
                    start: node.start_byte(),
                    end: node.end_byte(),
                },
                signature: one_line_signature(node_text(node, bytes), &['{', ';']),
            });
        };

    for child in root.children(&mut root.walk()) {
        match child.kind() {
            "function_definition" => {
                if is_static(&child, bytes) {
                    continue;
                }
                let Some(decl) = child.child_by_field_name("declarator") else {
                    continue;
                };
                let Some((name, _)) = declarator_name(&decl, bytes) else {
                    continue;
                };
                push(
                    &mut out,
                    &child,
                    name.clone(),
                    SymbolKind::Function,
                    Descriptor::Method {
                        name,
                        disambiguator: String::new(),
                    },
                );
            }

            "declaration" => {
                if is_static(&child, bytes) {
                    continue;
                }

                // Step 1: if the `type` field is a struct/union/enum WITH a body,
                // emit a type symbol for the aggregate definition itself.
                if let Some(spec) = child.child_by_field_name("type") {
                    if let Some((agg_kind, agg_name)) = aggregate_type_symbol(&spec, bytes) {
                        push(
                            &mut out,
                            &spec,
                            agg_name.clone(),
                            agg_kind,
                            Descriptor::Type(agg_name),
                        );
                    }
                }

                // Step 2: emit a symbol for each declarator in the declaration.
                let mut cursor = child.walk();
                for decl in child.children_by_field_name("declarator", &mut cursor) {
                    let Some((name, is_function)) = declarator_name(&decl, bytes) else {
                        continue;
                    };
                    if is_function {
                        push(
                            &mut out,
                            &child,
                            name.clone(),
                            SymbolKind::Function,
                            Descriptor::Method {
                                name,
                                disambiguator: String::new(),
                            },
                        );
                    } else {
                        push(
                            &mut out,
                            &child,
                            name.clone(),
                            SymbolKind::Static,
                            Descriptor::Term(name),
                        );
                    }
                }
            }

            "type_definition" => {
                // Step 1: if the `type` field is a named struct/union/enum WITH a body,
                // emit a type symbol for the aggregate.
                if let Some(spec) = child.child_by_field_name("type") {
                    if let Some((agg_kind, agg_name)) = aggregate_type_symbol(&spec, bytes) {
                        push(
                            &mut out,
                            &spec,
                            agg_name.clone(),
                            agg_kind,
                            Descriptor::Type(agg_name),
                        );
                    }
                }

                // Step 2: emit the typedef alias.
                let Some(decl) = child.child_by_field_name("declarator") else {
                    continue;
                };
                let Some((name, _)) = declarator_name(&decl, bytes) else {
                    continue;
                };
                push(
                    &mut out,
                    &child,
                    name.clone(),
                    SymbolKind::TypeAlias,
                    Descriptor::Type(name),
                );
            }

            "preproc_def" => {
                // Object-like macro: `#define NAME value`
                let Some(name) = field_text(&child, "name", bytes) else {
                    continue;
                };
                push(
                    &mut out,
                    &child,
                    name.clone(),
                    SymbolKind::Const,
                    Descriptor::Macro(name),
                );
            }

            "preproc_function_def" => {
                // Function-like macro: `#define NAME(args) body`
                let Some(name) = field_text(&child, "name", bytes) else {
                    continue;
                };
                push(
                    &mut out,
                    &child,
                    name.clone(),
                    SymbolKind::Function,
                    Descriptor::Macro(name),
                );
            }

            // A bare top-level `struct/union/enum Name { ... };` parses as the
            // specifier directly under `translation_unit` (no wrapping
            // `declaration`), so handle it here too.
            "struct_specifier" | "union_specifier" | "enum_specifier" => {
                if let Some((agg_kind, agg_name)) = aggregate_type_symbol(&child, bytes) {
                    push(
                        &mut out,
                        &child,
                        agg_name.clone(),
                        agg_kind,
                        Descriptor::Type(agg_name),
                    );
                }
            }

            _ => continue,
        }
    }
    out
}

/// If `spec` is a `struct_specifier`, `union_specifier`, or `enum_specifier`
/// that has both a `name` field AND a `body` child (meaning it is a definition,
/// not a bare forward reference), return `(SymbolKind, name)`.
fn aggregate_type_symbol(spec: &Node, bytes: &[u8]) -> Option<(SymbolKind, String)> {
    let kind = match spec.kind() {
        "struct_specifier" => SymbolKind::Struct,
        // NOTE: no Union variant — unions map to Struct.
        "union_specifier" => SymbolKind::Struct,
        "enum_specifier" => SymbolKind::Enum,
        _ => return None,
    };
    // Must have a body (i.e. this is a definition, not just a reference).
    spec.child_by_field_name("body")?;
    let name = field_text(spec, "name", bytes)?;
    Some((kind, name))
}

// ── Scope tree (Tier-B) ──────────────────────────────────────────────────────

/// Build the lexical scope tree for one C file.
///
/// `scopes[0]` is always the file-root `Module` scope spanning `[0, source_len)`.
/// C is function-scoped: `function_definition` nodes open a `Function` scope;
/// `compound_statement` nodes NOT consumed as a function body open a `Block`
/// scope (e.g. `if`/`for`/`while` bodies, bare `{ }` blocks).
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

/// DFS opening `Function` scopes for `function_definition` nodes, and `Block`
/// scopes for bare `compound_statement` nodes not consumed as a function body.
///
/// The function body (`compound_statement`) is peeled: its children are visited
/// under the Function scope directly, so the body block does not re-open a
/// redundant Block scope. Bare blocks elsewhere (if/for/while/switch bodies)
/// do open a Block scope.
fn scope_dfs(node: &Node, parent_id: ScopeId, scopes: &mut Vec<Scope>) {
    match node.kind() {
        "function_definition" => {
            let fn_id = push_scope(
                scopes,
                Some(parent_id),
                node_span(node),
                ScopeKind::Function,
            );
            // Peel the body: recurse children of the compound_statement directly
            // under the Function scope to avoid a redundant Block scope.
            if let Some(body) = node.child_by_field_name("body") {
                for child in body.children(&mut body.walk()) {
                    scope_dfs(&child, fn_id, scopes);
                }
            }
        }
        "compound_statement" => {
            // A bare block NOT already consumed as a function body.
            let block_id = push_scope(scopes, Some(parent_id), node_span(node), ScopeKind::Block);
            for child in node.children(&mut node.walk()) {
                scope_dfs(&child, block_id, scopes);
            }
        }
        _ => {
            for child in node.children(&mut node.walk()) {
                scope_dfs(&child, parent_id, scopes);
            }
        }
    }
}

// ── Bindings (Tier-B) ────────────────────────────────────────────────────────

/// Collect parameter and local-variable [`Binding`]s for one C file.
///
/// Covers:
/// - `function_definition` parameters → [`BindingKind::Param`].
/// - `declaration` nodes inside a function body → [`BindingKind::Local`] (scope-0
///   declarations are skipped — they are globals, already covered by
///   `definition_bindings`).
/// - `for_statement` initializer declarations are reached by the normal recursion
///   into `declaration` children.
fn collect_bindings(root: &Node, bytes: &[u8], scopes: &[Scope]) -> Vec<Binding> {
    let mut out = Vec::new();
    collect_bindings_dfs(root, bytes, scopes, &mut out);
    out
}

fn collect_bindings_dfs(node: &Node, bytes: &[u8], scopes: &[Scope], out: &mut Vec<Binding>) {
    match node.kind() {
        "function_definition" => {
            // Parameters live in the function_declarator → parameter_list.
            // Use find_function_declarator to handle pointer-return types like
            // `int *f(int a)`, where the declarator field is a pointer_declarator
            // wrapping the function_declarator.
            if let Some(decl) = node.child_by_field_name("declarator") {
                if let Some(fn_decl) = find_function_declarator(&decl) {
                    if let Some(params) = fn_decl.child_by_field_name("parameters") {
                        collect_params(&params, bytes, scopes, out);
                    }
                }
            }
            // Recurse into all children to pick up body bindings.
            for child in node.children(&mut node.walk()) {
                collect_bindings_dfs(&child, bytes, scopes, out);
            }
        }
        "declaration" => {
            // Single pass: emit Local bindings for declarator-field children and
            // recurse into everything else (catches for-init sub-trees).
            // Scope-0 guard keeps file-scope globals from becoming Locals.
            let mut cursor = node.walk();
            for (i, child) in node.children(&mut cursor).enumerate() {
                if node.field_name_for_child(i as u32) == Some("declarator") {
                    if let Some((name, _)) = declarator_name(&child, bytes) {
                        let intro = child.start_byte();
                        if innermost_scope(intro, scopes) != Some(0) {
                            push_binding(out, name, intro, BindingKind::Local, scopes);
                        }
                    }
                    // Declarator subtrees have no nested `declaration` nodes — skip recursion.
                } else {
                    collect_bindings_dfs(&child, bytes, scopes, out);
                }
            }
        }
        _ => {
            for child in node.children(&mut node.walk()) {
                collect_bindings_dfs(&child, bytes, scopes, out);
            }
        }
    }
}

/// Emit a [`BindingKind::Param`] for each named parameter in a C
/// `parameter_list` node. Handles `parameter_declaration` children; skips
/// `(void)` entries (no `declarator` field or `declarator_name` returns `None`).
fn collect_params(params: &Node, bytes: &[u8], scopes: &[Scope], out: &mut Vec<Binding>) {
    for child in params.children(&mut params.walk()) {
        if child.kind() != "parameter_declaration" {
            continue;
        }
        let Some(decl) = child.child_by_field_name("declarator") else {
            // `(void)` — no declarator; skip.
            continue;
        };
        let Some((name, _)) = declarator_name(&decl, bytes) else {
            continue;
        };
        let intro = decl.start_byte();
        // Parameters are always inside a function — no scope-0 guard needed.
        push_binding(out, name, intro, BindingKind::Param, scopes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::types::RefRole;

    #[test]
    fn extracts_defs_and_skips_static() {
        let src = r#"
#define MAX_LEN 256
int authenticate(const char *tok) { return validate(tok); }
static int helper(void) { return 0; }
struct Session { int id; };
enum Status { OK, FAIL };
typedef struct Session SessionRef;
int global_count;
static int private_count;
"#;
        let facts = CExtractor.extract(src, "src/auth/token.c").unwrap();
        let by_name = |n: &str| facts.symbols.iter().find(|s| s.name == n).cloned();

        // authenticate: exported function
        let auth = by_name("authenticate").unwrap();
        assert_eq!(auth.kind, SymbolKind::Function);
        assert_eq!(
            auth.id.to_scip_string(),
            "codegraph . . . auth/token/authenticate()."
        );

        // helper: static — must be absent
        assert!(by_name("helper").is_none());

        // Session: struct definition inside a declaration
        let session = by_name("Session").unwrap();
        assert_eq!(session.kind, SymbolKind::Struct);
        assert_eq!(
            session.id.to_scip_string(),
            "codegraph . . . auth/token/Session#"
        );

        // Status: enum definition inside a declaration
        let status = by_name("Status").unwrap();
        assert_eq!(status.kind, SymbolKind::Enum);
        assert_eq!(
            status.id.to_scip_string(),
            "codegraph . . . auth/token/Status#"
        );

        // SessionRef: typedef alias
        let alias = by_name("SessionRef").unwrap();
        assert_eq!(alias.kind, SymbolKind::TypeAlias);
        assert_eq!(
            alias.id.to_scip_string(),
            "codegraph . . . auth/token/SessionRef#"
        );

        // global_count: non-static variable
        let gc = by_name("global_count").unwrap();
        assert_eq!(gc.kind, SymbolKind::Static);
        assert_eq!(
            gc.id.to_scip_string(),
            "codegraph . . . auth/token/global_count."
        );

        // private_count: static — must be absent
        assert!(by_name("private_count").is_none());

        // MAX_LEN: object-like macro → Const
        let max = by_name("MAX_LEN").unwrap();
        assert_eq!(max.kind, SymbolKind::Const);
        assert_eq!(
            max.id.to_scip_string(),
            "codegraph . . . auth/token/MAX_LEN!"
        );

        assert_eq!(facts.lang, "c");
    }

    #[test]
    fn function_macro_and_prototype() {
        let src = r#"
#define SQUARE(x) ((x)*(x))
int compute(int n);
"#;
        let facts = CExtractor.extract(src, "src/util.h").unwrap();
        let by_name = |n: &str| facts.symbols.iter().find(|s| s.name == n).cloned();

        // SQUARE: function-like macro → Function + Descriptor::Macro
        let sq = by_name("SQUARE").unwrap();
        assert_eq!(sq.kind, SymbolKind::Function);
        assert_eq!(sq.id.to_scip_string(), "codegraph . . . util/SQUARE!");

        // compute: function prototype in a declaration
        let comp = by_name("compute").unwrap();
        assert_eq!(comp.kind, SymbolKind::Function);
        assert_eq!(comp.id.to_scip_string(), "codegraph . . . util/compute().");
    }

    #[test]
    fn extracts_call_references() {
        let src = r#"
int main(void) {
    authenticate("t");
    compute(5);
}
"#;
        let facts = CExtractor.extract(src, "src/main.c").unwrap();
        let names: Vec<&str> = facts.references.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"authenticate"));
        assert!(names.contains(&"compute"));
    }

    // ── Tier-B scope / binding tests ─────────────────────────────────────────

    #[test]
    fn func_params_emit_param_bindings() {
        // `int add(int a, int b) { return a + b; }` → Param `a`, `b` in Function scope.
        let src = "int add(int a, int b) { return a + b; }\n";
        let facts = CExtractor.extract(src, "src/math.c").unwrap();

        let fn_scope_id = facts
            .scopes
            .iter()
            .position(|s| s.kind == ScopeKind::Function)
            .expect("expected a Function scope");

        let mut param_names: Vec<(&str, ScopeId)> = facts
            .bindings
            .iter()
            .filter(|b| b.kind == BindingKind::Param)
            .map(|b| (b.name.as_str(), b.scope))
            .collect();
        param_names.sort_by_key(|(n, _)| *n);

        assert_eq!(
            param_names,
            vec![("a", fn_scope_id), ("b", fn_scope_id)],
            "expected Param bindings for a and b, got {param_names:?}"
        );
    }

    #[test]
    fn pointer_param_emits_param_binding() {
        // `int process(int *p) { return *p; }` → Param `p` (exercises pointer_declarator unwrap).
        let src = "int process(int *p) { return *p; }\n";
        let facts = CExtractor.extract(src, "src/proc.c").unwrap();

        let p = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Param && b.name == "p")
            .expect("expected a Param binding for 'p'");
        assert_eq!(
            facts.scopes[p.scope].kind,
            ScopeKind::Function,
            "pointer param 'p' should be in a Function scope"
        );
    }

    #[test]
    fn pointer_return_function_params_collected() {
        // `char *dup(const char *s)` wraps the function_declarator in a
        // pointer_declarator; params must still be reached via find_function_declarator.
        let src = "char *dup(const char *s) { return 0; }\n";
        let facts = CExtractor.extract(src, "src/dup.c").unwrap();

        let s = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Param && b.name == "s")
            .expect("pointer-return function's param 's' should be collected");
        assert_eq!(
            facts.scopes[s.scope].kind,
            ScopeKind::Function,
            "param 's' should be in a Function scope"
        );
    }

    #[test]
    fn local_var_decl_emits_local_binding() {
        // `int f(void) { int x = 0; return x; }` → Local `x`, scope != 0.
        let src = "int f(void) { int x = 0; return x; }\n";
        let facts = CExtractor.extract(src, "src/f.c").unwrap();

        let x = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Local && b.name == "x")
            .expect("expected a Local binding for 'x'");
        assert_ne!(x.scope, 0, "local 'x' must NOT be in scope 0 (file root)");
    }

    #[test]
    fn multi_declarator_emits_two_locals() {
        // `int f(void) { int a, b; return a + b; }` → Locals `a`, `b`.
        let src = "int f(void) { int a, b; return a + b; }\n";
        let facts = CExtractor.extract(src, "src/f.c").unwrap();

        let locals: Vec<&str> = facts
            .bindings
            .iter()
            .filter(|b| b.kind == BindingKind::Local)
            .map(|b| b.name.as_str())
            .collect();
        assert!(
            locals.contains(&"a"),
            "expected Local for 'a', got {locals:?}"
        );
        assert!(
            locals.contains(&"b"),
            "expected Local for 'b', got {locals:?}"
        );
    }

    #[test]
    fn for_init_var_emits_local() {
        // `void f(void) { for (int i = 0; i < 10; i++) {} }` → Local `i`.
        let src = "void f(void) { for (int i = 0; i < 10; i++) {} }\n";
        let facts = CExtractor.extract(src, "src/f.c").unwrap();

        let i = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Local && b.name == "i")
            .expect("expected a Local binding for 'i'");
        assert_ne!(
            i.scope, 0,
            "for-init 'i' must NOT be in scope 0 (file root)"
        );
    }

    #[test]
    fn file_scope_global_is_not_local_but_is_definition() {
        // `int global_count;\nvoid f(void) {}\n` → NO Local for `global_count`,
        // but a Definition binding exists.
        let src = "int global_count;\nvoid f(void) {}\n";
        let facts = CExtractor.extract(src, "src/g.c").unwrap();

        assert!(
            !facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Local && b.name == "global_count"),
            "global_count must NOT be a Local binding"
        );
        assert!(
            facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Definition && b.name == "global_count"),
            "global_count must have a Definition binding"
        );
    }

    #[test]
    fn nesting_produces_correct_scope_tree() {
        // `void f(void) { { ; } }` → exactly 3 scopes: Module(0), Function, Block(parent=Function).
        // The body compound_statement must NOT double-open.
        let src = "void f(void) { { ; } }\n";
        let facts = CExtractor.extract(src, "src/f.c").unwrap();

        assert_eq!(facts.scopes.len(), 3, "expected exactly 3 scopes");
        assert_eq!(facts.scopes[0].kind, ScopeKind::Module);

        let fn_scope_id = facts
            .scopes
            .iter()
            .position(|s| s.kind == ScopeKind::Function)
            .expect("expected a Function scope");
        let block_scope_id = facts
            .scopes
            .iter()
            .position(|s| s.kind == ScopeKind::Block)
            .expect("expected a Block scope");

        assert_eq!(
            facts.scopes[block_scope_id].parent,
            Some(fn_scope_id),
            "Block scope parent should be the Function scope"
        );
    }

    #[test]
    fn top_level_non_static_func_emits_definition_binding() {
        // `int helper(void) { return 0; }` → Definition binding `helper` at scope 0.
        let src = "int helper(void) { return 0; }\n";
        let facts = CExtractor.extract(src, "src/h.c").unwrap();

        let b = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Definition && b.name == "helper")
            .expect("expected a Definition binding for 'helper'");
        assert_eq!(b.scope, 0, "top-level def must bind in scope 0");
    }

    #[test]
    fn static_func_excluded_from_definition_bindings() {
        // `static int helper(void) { return 0; }` → NO Definition binding `helper`
        // (static symbols are skipped by collect_symbols).
        let src = "static int helper(void) { return 0; }\n";
        let facts = CExtractor.extract(src, "src/h.c").unwrap();

        assert!(
            !facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Definition && b.name == "helper"),
            "static 'helper' must NOT produce a Definition binding"
        );
    }

    #[test]
    fn void_param_skipped() {
        // `int f(void) { return 0; }` → zero Param bindings (void is not a named param).
        let src = "int f(void) { return 0; }\n";
        let facts = CExtractor.extract(src, "src/f.c").unwrap();

        let params: Vec<&str> = facts
            .bindings
            .iter()
            .filter(|b| b.kind == BindingKind::Param)
            .map(|b| b.name.as_str())
            .collect();
        assert!(
            params.is_empty(),
            "expected zero Param bindings for (void), got {params:?}"
        );
    }

    #[test]
    fn same_file_call_ref_has_non_zero_scope_and_callee_has_definition() {
        // Two non-static funcs where one calls the other.
        // Assert: Definition binding for callee exists AND the call Reference has scope == Some(non-zero).
        let src = "int helper(void) { return 0; }\nint caller(void) { return helper(); }\n";
        let facts = CExtractor.extract(src, "src/pair.c").unwrap();

        // Definition binding for `helper` must exist.
        assert!(
            facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Definition && b.name == "helper"),
            "expected a Definition binding for 'helper'"
        );

        // The `helper()` call reference must have a non-zero (non-module) scope.
        let call_ref = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Call && r.name == "helper")
            .expect("expected a Call ref for 'helper'");
        assert!(
            call_ref.scope.is_some() && call_ref.scope != Some(0),
            "helper() call ref must be in a non-zero scope, got {:?}",
            call_ref.scope
        );
    }
}
