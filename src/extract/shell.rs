// SPDX-License-Identifier: Apache-2.0

//! Shell extractor — one tree-sitter pass yielding definitions and references.
//!
//! Definitions: top-level `function_definition` nodes, covering all bash function
//! styles (`foo() {}`, `function foo {}`, `function foo() {}`). Qualified identity
//! is derived from the file path (`scripts/deploy.sh` → namespace `deploy`).
//! References: callee identifiers of `command` nodes; the resolver only draws edges
//! to those matching a defined function name.
//!
//! Top-level variable assignments are intentionally NOT captured in v0.
//!
//! Emits neutral [`FileFacts`] — no storage entries, no source bodies.

use tree_sitter::{Node, Parser};

use crate::error::{CodegraphError, Result};
use crate::graph::types::{
    Binding, BindingKind, ByteSpan, FileFacts, RefRole, Reference, Scope, ScopeId, ScopeKind,
    Symbol, SymbolKind, Visibility,
};
use crate::lang::Language;
use crate::symbol::Descriptor;

use super::{
    ExtractCtx, Extractor, MIN_REF_LEN, attach_reference_scopes, collect_call_references,
    definition_bindings, field_text, innermost_scope, make_symbol, node_span, node_text,
    one_line_signature, push_binding, push_ref, push_scope,
};

/// Tree-sitter query capturing command-name identifiers as call references.
const CALL_QUERY: &str = r#"
(command
  name: (command_name
    (word) @callee))
"#;

/// Extracts Shell symbols and references.
pub struct ShellExtractor;

impl Extractor for ShellExtractor {
    fn lang(&self) -> Language {
        Language::Shell
    }

    fn extract(&self, source: &str, file: &str) -> Result<FileFacts> {
        let ts_language = crate::grammar::shell();
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
        let namespaces = shell_namespaces(file);
        let ctx = ExtractCtx {
            bytes,
            file,
            lang: Language::Shell,
        };

        let defs = collect_symbols(&root, &ctx, &namespaces);
        let def_bindings = definition_bindings(&defs);
        let mut symbols = defs;
        symbols.push(super::module_symbol(
            Language::Shell,
            &namespaces,
            file,
            source.len(),
        ));
        let mut references = collect_call_references(
            &root,
            &ts_language,
            CALL_QUERY,
            Language::Shell,
            ctx.bytes,
            ctx.file,
        )?;

        collect_read_references(&root, ctx.bytes, ctx.file, &mut references);
        collect_write_references(&root, ctx.bytes, ctx.file, &mut references);

        let scopes = collect_scopes(&root, source.len());
        attach_reference_scopes(&mut references, &scopes);
        let mut bindings = collect_bindings(&root, ctx.bytes, &scopes);
        bindings.extend(def_bindings);

        Ok(FileFacts {
            file: file.to_owned(),
            lang: Language::Shell.as_str().to_owned(),
            symbols,
            references,
            scopes,
            bindings,
            ffi_exports: Vec::new(),
        })
    }
}

/// Derive the Shell namespace path from a file path.
///
/// Strips a `.sh`, `.bash`, or `.zsh` extension; strips a leading `src/`, `bin/`,
/// or `scripts/` prefix (each tried in order); then splits on `/`. The file stem
/// is kept as the last namespace segment.
fn shell_namespaces(file: &str) -> Vec<String> {
    let p = file
        .strip_suffix(".sh")
        .or_else(|| file.strip_suffix(".bash"))
        .or_else(|| file.strip_suffix(".zsh"))
        .unwrap_or(file);
    let p = p
        .strip_prefix("src/")
        .or_else(|| p.strip_prefix("bin/"))
        .or_else(|| p.strip_prefix("scripts/"))
        .unwrap_or(p);
    p.split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

fn collect_symbols(
    root: &tree_sitter::Node,
    ctx: &ExtractCtx<'_>,
    namespaces: &[String],
) -> Vec<Symbol> {
    let mut out = Vec::new();

    for child in root.children(&mut root.walk()) {
        if child.kind() != "function_definition" {
            continue;
        }
        let Some(name) = field_text(&child, "name", ctx.bytes) else {
            continue;
        };
        let mut descriptors: Vec<Descriptor> = namespaces
            .iter()
            .cloned()
            .map(Descriptor::Namespace)
            .collect();
        descriptors.push(Descriptor::Method {
            name: name.clone(),
            disambiguator: String::new(),
        });
        let signature = one_line_signature(node_text(&child, ctx.bytes), &['{']);
        out.push(make_symbol(
            ctx,
            &child,
            name,
            SymbolKind::Function,
            Visibility::Unknown,
            descriptors,
            signature,
        ));
    }
    out
}

// ── Edge richness: Read / Write ─────────────────────────────────────────────

/// Recursively walk `node` and emit [`RefRole::Read`] references for every
/// `variable_name` node whose parent is a `simple_expansion` (`$var`) or
/// `expansion` (`${var}`). These are the only positions where a `variable_name`
/// represents a variable *read* in the bash grammar.
///
/// Assignment LHS variable names (the `name:` child of `variable_assignment`)
/// are naturally excluded because their parent kind is `variable_assignment`,
/// not `simple_expansion` or `expansion`.
///
/// Special/positional parameters (`$1`, `$?`, `$@`, …) are plain tokens — not
/// `variable_name` nodes — so they are excluded automatically.
///
/// Applies [`MIN_REF_LEN`].
fn collect_read_references(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    if node.kind() == "variable_name" {
        if let Some(parent) = node.parent() {
            if matches!(parent.kind(), "simple_expansion" | "expansion") {
                let name = node_text(node, bytes);
                if name.len() >= MIN_REF_LEN {
                    push_ref(out, name, node, file, RefRole::Read);
                }
            }
        }
        // variable_name has no meaningful children for reads; return early.
        return;
    }
    for child in node.children(&mut node.walk()) {
        collect_read_references(&child, bytes, file, out);
    }
}

/// Recursively walk `node` and emit [`RefRole::Write`] references for the
/// `name:` field of every `variable_assignment` node whose name is a
/// `variable_name` (not a subscript/array LHS, deferred to v2).
///
/// This covers both plain assignments (`count=5`) and those inside
/// `declaration_command` (`local x=1`, `declare y=2`). The resolver's
/// self-edge guard handles the case where a `local x=5` simultaneously
/// defines and writes `x`.
///
/// Applies [`MIN_REF_LEN`].
fn collect_write_references(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    if node.kind() == "variable_assignment" {
        if let Some(name_node) = node.child_by_field_name("name") {
            if name_node.kind() == "variable_name" {
                let name = node_text(&name_node, bytes);
                if name.len() >= MIN_REF_LEN {
                    push_ref(out, name, &name_node, file, RefRole::Write);
                }
            }
        }
    }
    for child in node.children(&mut node.walk()) {
        collect_write_references(&child, bytes, file, out);
    }
}

// ── Scope tree (Tier-B) ──────────────────────────────────────────────────────

/// Build the lexical scope tree for one Shell file.
///
/// `scopes[0]` is always the file-root `Module` scope spanning `[0, source_len)`.
/// Shell is function-scoped: `function_definition` nodes open a `Function` scope.
/// No `Block` scope is emitted for v1 (shell's compound_statement does not introduce
/// a new name-resolution region beyond the enclosing function).
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

/// DFS opening `Function` scopes for `function_definition` nodes.
///
/// The function body is peeled: its children are visited under the Function scope
/// directly so the body compound_statement does not re-open a redundant scope.
fn scope_dfs(node: &Node, parent_id: ScopeId, scopes: &mut Vec<Scope>) {
    if node.kind() == "function_definition" {
        let fn_id = push_scope(
            scopes,
            Some(parent_id),
            node_span(node),
            ScopeKind::Function,
        );
        // Peel the body field (compound_statement, subshell, if_statement, …):
        // recurse its children under the Function scope so the body node itself
        // does not open a redundant scope.
        if let Some(body) = node.child_by_field_name("body") {
            for child in body.children(&mut body.walk()) {
                scope_dfs(&child, fn_id, scopes);
            }
        }
    } else {
        for child in node.children(&mut node.walk()) {
            scope_dfs(&child, parent_id, scopes);
        }
    }
}

// ── Bindings (Tier-B) ────────────────────────────────────────────────────────

/// Collect local-variable [`Binding`]s for one Shell file.
///
/// Shell local bindings are scoped declarations only:
/// - `declaration_command` (`local`, `declare`, `typeset`, `export`, `readonly`):
///   each `variable_assignment` child whose `name` field is a `variable_name`
///   (not subscript/array) → [`BindingKind::Local`].
/// - `for_statement` loop variable (`variable` field) → [`BindingKind::Local`].
///
/// Plain `variable_assignment` at statement level is intentionally NOT emitted
/// as Local — in shell those are global (or dynamic-scope) assignments.
/// No `Param` bindings are emitted: shell positional parameters (`$1`, `$@`, …)
/// have no syntactic binding node in tree-sitter-bash.
///
/// Both cases apply the guard `matches!(scope.kind, ScopeKind::Function | ScopeKind::Block)`
/// so top-level declarations (`export FOO=bar` at module scope) are excluded.
fn collect_bindings(root: &Node, bytes: &[u8], scopes: &[Scope]) -> Vec<Binding> {
    let mut out = Vec::new();
    collect_bindings_dfs(root, bytes, scopes, &mut out);
    out
}

fn collect_bindings_dfs(node: &Node, bytes: &[u8], scopes: &[Scope], out: &mut Vec<Binding>) {
    match node.kind() {
        "declaration_command" => {
            // Children include variable_assignment nodes (no named field — walk all).
            for child in node.children(&mut node.walk()) {
                if child.kind() == "variable_assignment" {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        // Skip subscript/array forms (e.g. `local arr[0]=val`).
                        if name_node.kind() == "variable_name" {
                            let name = node_text(&name_node, bytes);
                            let intro = name_node.start_byte();
                            let sid = innermost_scope(intro, scopes).unwrap_or(0);
                            if matches!(scopes[sid].kind, ScopeKind::Function | ScopeKind::Block) {
                                push_binding(
                                    out,
                                    name.to_owned(),
                                    intro,
                                    BindingKind::Local,
                                    scopes,
                                );
                            }
                        }
                    }
                }
                // Don't recurse into children of declaration_command children here;
                // they cannot contain nested declaration_commands or for_statements.
            }
            // Still recurse the declaration_command itself in case of edge cases.
            for child in node.children(&mut node.walk()) {
                collect_bindings_dfs(&child, bytes, scopes, out);
            }
        }
        "for_statement" => {
            // `for VAR in ...; do ... done` — the loop variable is the `variable` field.
            if let Some(var_node) = node.child_by_field_name("variable") {
                // The variable field is always variable_name per the grammar.
                let name = node_text(&var_node, bytes);
                let intro = var_node.start_byte();
                let sid = innermost_scope(intro, scopes).unwrap_or(0);
                if matches!(scopes[sid].kind, ScopeKind::Function | ScopeKind::Block) {
                    push_binding(out, name.to_owned(), intro, BindingKind::Local, scopes);
                }
            }
            for child in node.children(&mut node.walk()) {
                collect_bindings_dfs(&child, bytes, scopes, out);
            }
        }
        _ => {
            for child in node.children(&mut node.walk()) {
                collect_bindings_dfs(&child, bytes, scopes, out);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::types::RefRole;

    #[test]
    fn extracts_functions() {
        let src = "validate() { return 0; }\nfunction deploy { echo done; }\nfunction run() { validate; }\n";
        let facts = ShellExtractor.extract(src, "scripts/deploy.sh").unwrap();
        let by_name = |n: &str| facts.symbols.iter().find(|s| s.name == n).cloned();

        let validate = by_name("validate").unwrap();
        assert_eq!(validate.kind, SymbolKind::Function);
        assert_eq!(
            validate.id.to_scip_string(),
            "codegraph . . . deploy/validate()."
        );

        assert!(by_name("deploy").is_some());
        assert!(by_name("run").is_some());
        assert_eq!(facts.lang, "shell");
    }

    #[test]
    fn extracts_call_references() {
        let src = "function main { validate; deploy arg1; }\n";
        let facts = ShellExtractor.extract(src, "scripts/main.sh").unwrap();
        let names: Vec<&str> = facts.references.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"validate"));
        assert!(names.contains(&"deploy"));
    }

    // ── Tier-B scope / binding tests ─────────────────────────────────────────

    #[test]
    fn function_body_opens_function_scope() {
        // `greet() { echo hi; }` → scopes[0]=Module, a Function scope with parent 0.
        let src = "greet() { echo hi; }\n";
        let facts = ShellExtractor.extract(src, "scripts/greet.sh").unwrap();

        assert_eq!(
            facts.scopes[0].kind,
            ScopeKind::Module,
            "scopes[0] must be Module"
        );
        let fn_scope = facts
            .scopes
            .iter()
            .find(|s| s.kind == ScopeKind::Function)
            .expect("expected a Function scope");
        assert_eq!(
            fn_scope.parent,
            Some(0),
            "Function scope parent must be the Module scope (0)"
        );
    }

    #[test]
    fn local_var_emits_local_binding() {
        // `local CONF=...` inside a function → Local binding `CONF` in Function scope.
        let src = "setup() {\n  local CONF=/etc/app.conf\n}\n";
        let facts = ShellExtractor.extract(src, "scripts/setup.sh").unwrap();

        let conf = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Local && b.name == "CONF")
            .expect("expected a Local binding named 'CONF'");
        assert_eq!(
            facts.scopes[conf.scope].kind,
            ScopeKind::Function,
            "CONF should be bound in a Function scope"
        );
    }

    #[test]
    fn plain_assignment_is_not_local() {
        // `X=1` inside a function body is NOT a Local binding (global in shell).
        let src = "run() {\n  X=1\n}\n";
        let facts = ShellExtractor.extract(src, "scripts/run.sh").unwrap();

        assert!(
            !facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Local && b.name == "X"),
            "plain variable_assignment must NOT produce a Local binding"
        );
    }

    #[test]
    fn same_file_call_ref_has_function_scope() {
        // `helper` is defined and called in the same file; the call ref should be
        // attributed to the Function scope enclosing the call site.
        let src = "helper() { return 0; }\ndeploy() { helper; }\n";
        let facts = ShellExtractor.extract(src, "scripts/deploy.sh").unwrap();

        // Definition binding for `helper` must exist.
        assert!(
            facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Definition && b.name == "helper"),
            "expected a Definition binding for 'helper'"
        );

        // The `helper` call ref must be inside a non-zero Function scope.
        let helper_ref = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Call && r.name == "helper")
            .expect("expected a Call ref for 'helper'");
        let scope_id = helper_ref
            .scope
            .expect("helper call ref must have a scope attached");
        assert_ne!(
            scope_id, 0,
            "call must be in a Function scope, not Module (0)"
        );
        assert_eq!(
            facts.scopes[scope_id].kind,
            ScopeKind::Function,
            "helper call scope must be Function"
        );
    }

    #[test]
    fn for_loop_var_emits_local() {
        // `for item in a b c` inside a function → Local binding `item`.
        let src = "process() {\n  for item in a b c; do\n    echo $item\n  done\n}\n";
        let facts = ShellExtractor.extract(src, "scripts/process.sh").unwrap();

        let item = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Local && b.name == "item")
            .expect("expected a Local binding named 'item'");
        assert_eq!(
            facts.scopes[item.scope].kind,
            ScopeKind::Function,
            "for-loop variable 'item' should be in a Function scope"
        );
    }

    #[test]
    fn no_param_bindings() {
        // Shell positional params (`$1`, `$@`) have no syntactic binding node.
        let src = "greet() { echo $1; }\n";
        let facts = ShellExtractor.extract(src, "scripts/greet.sh").unwrap();

        assert!(
            !facts.bindings.iter().any(|b| b.kind == BindingKind::Param),
            "shell extractor must not emit any Param bindings"
        );
    }

    #[test]
    fn top_level_func_definition_binding_at_scope_0() {
        // A top-level function definition → Definition binding in scope 0.
        let src = "deploy() { echo done; }\n";
        let facts = ShellExtractor.extract(src, "scripts/deploy.sh").unwrap();

        let b = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Definition && b.name == "deploy")
            .expect("expected a Definition binding for 'deploy'");
        assert_eq!(b.scope, 0, "top-level def must bind in scope 0 (Module)");
    }

    // ── Edge richness: Read / Write ──────────────────────────────────────────

    #[test]
    fn read_via_simple_expansion() {
        // `$conf` → simple_expansion → Read ref "conf".
        let src = "setup() {\n  local conf=1\n  echo $conf\n}\n";
        let facts = ShellExtractor.extract(src, "scripts/test.sh").unwrap();
        let read_refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Read && r.name == "conf")
            .collect();
        assert!(
            !read_refs.is_empty(),
            "expected Read ref for 'conf' via $conf expansion, got none; all refs: {:?}",
            facts
                .references
                .iter()
                .map(|r| (&r.name, r.role))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn read_via_brace_expansion() {
        // `${name}` → expansion → Read ref "name".
        let src = "f() {\n  local name=x\n  echo ${name}\n}\n";
        let facts = ShellExtractor.extract(src, "scripts/test.sh").unwrap();
        let read_refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Read && r.name == "name")
            .collect();
        assert!(
            !read_refs.is_empty(),
            "expected Read ref for 'name' via ${{name}} expansion, got none; all refs: {:?}",
            facts
                .references
                .iter()
                .map(|r| (&r.name, r.role))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn write_via_variable_assignment() {
        // `count=5` → variable_assignment → Write ref "count".
        let src = "f() {\n  count=5\n}\n";
        let facts = ShellExtractor.extract(src, "scripts/test.sh").unwrap();
        let write_refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Write && r.name == "count")
            .collect();
        assert!(
            !write_refs.is_empty(),
            "expected Write ref for 'count' from count=5 assignment, got none; all refs: {:?}",
            facts
                .references
                .iter()
                .map(|r| (&r.name, r.role))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn assignment_lhs_is_write_not_read() {
        // `base=1` → exactly one Read "base" (from `$base`), zero Reads from the LHS.
        let src = "f() {\n  base=1\n  echo $base\n}\n";
        let facts = ShellExtractor.extract(src, "scripts/test.sh").unwrap();

        let base_reads: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Read && r.name == "base")
            .collect();
        assert_eq!(
            base_reads.len(),
            1,
            "expected exactly one Read ref for 'base' (from $base), got {}; refs: {:?}",
            base_reads.len(),
            facts
                .references
                .iter()
                .filter(|r| r.name == "base")
                .map(|r| (&r.name, r.role))
                .collect::<Vec<_>>()
        );

        let base_writes: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Write && r.name == "base")
            .collect();
        assert!(
            !base_writes.is_empty(),
            "expected a Write ref for 'base' from base=1, got none"
        );
    }
}
