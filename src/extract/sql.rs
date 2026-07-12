// SPDX-License-Identifier: Apache-2.0

//! SQL extractor — extracts DDL symbols (tables, views, columns) and CTE
//! definitions via tree-sitter-sequel.
//!
//! Emits neutral [`FileFacts`] — no storage entries, no source bodies. References
//! (table use-sites in FROM/JOIN/INSERT/UPDATE/DELETE/REFERENCES clauses) are
//! emitted as [`RefRole::TypeRef`] so the language-agnostic resolver can link them
//! to their table/view definitions automatically.
//!
//! Tier-B scope/binding extraction: CTE names introduced by `WITH … AS (…)` are
//! emitted as [`BindingKind::Definition`] bindings in the enclosing statement scope
//! (not scope 0 — the file root). A `FROM revenue` reference inside the same
//! statement therefore resolves with [`Confidence::Scoped`](crate::graph::Confidence::Scoped).

use std::collections::HashMap;

use tree_sitter::{Node, Parser};

use crate::error::{CodegraphError, Result};
use crate::graph::types::{
    Binding, BindingKind, BindingTarget, ByteSpan, FileFacts, Occurrence, RefRole, Reference,
    Scope, ScopeId, ScopeKind, Symbol, SymbolKind, Visibility,
};
use crate::lang::Language;
use crate::symbol::Descriptor;

use super::{
    ExtractCtx, Extractor, attach_reference_scopes, definition_bindings, innermost_scope,
    make_symbol, node_span, push_scope,
};

/// Extracts SQL symbols and references (tables, views, columns).
pub struct SqlExtractor;

impl Extractor for SqlExtractor {
    fn lang(&self) -> Language {
        Language::Sql
    }

    fn extract(&self, source: &str, file: &str) -> Result<FileFacts> {
        let ts_language = crate::grammar::sql();
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
        let ctx = ExtractCtx {
            bytes,
            file,
            lang: Language::Sql,
        };

        // DDL symbols (CREATE TABLE / VIEW / columns) — bound at file-root scope (0).
        let defs = collect_symbols(&root, &ctx);
        let def_bindings = definition_bindings(&defs);
        let mut symbols = defs;

        // CTE symbols: each `WITH name AS (…)` introduces a name local to its
        // enclosing statement scope — NOT the file root.
        let cte_symbols = collect_cte_symbols(&root, &ctx);
        symbols.extend(cte_symbols.iter().cloned());

        // Module symbol: stable SCIP identity for the whole file.
        symbols.push(super::module_symbol(Language::Sql, &[], file, source.len()));

        // References (all object_reference nodes that aren't DDL definition names).
        let mut references = collect_references(&root, ctx.bytes, ctx.file);

        // Scope tree: scope[0] = Module over whole file; each `statement` or
        // `subquery` node gets its own `Other` scope.
        let scopes = collect_scopes(&root, source.len());
        attach_reference_scopes(&mut references, &scopes);

        // CTE bindings (Definition in statement scope) + DDL bindings (scope 0).
        let mut bindings = collect_cte_bindings(&root, ctx.bytes, &scopes, &cte_symbols);
        bindings.extend(def_bindings);

        Ok(FileFacts {
            file: file.to_owned(),
            lang: Language::Sql.as_str().to_owned(),
            symbols,
            references,
            scopes,
            bindings,
            ffi_exports: Vec::new(),
        })
    }
}

// ── Symbol extraction ─────────────────────────────────────────────────────────

/// Walk the tree recursively and collect DDL symbols (tables, views, columns).
///
/// SQL has no path-namespace derived from the file path — the optional schema
/// prefix comes from the SQL itself and is captured directly.
fn collect_symbols(root: &Node, ctx: &ExtractCtx) -> Vec<Symbol> {
    let mut out = Vec::new();
    collect_symbols_recursive(root, ctx, &mut out);
    out
}

fn collect_symbols_recursive(node: &Node, ctx: &ExtractCtx, out: &mut Vec<Symbol>) {
    match node.kind() {
        "create_table" => {
            extract_table(node, ctx, out);
        }
        "create_view" | "create_materialized_view" => {
            extract_view(node, ctx, out);
        }
        _ => {
            for child in node.children(&mut node.walk()) {
                collect_symbols_recursive(&child, ctx, out);
            }
        }
    }
}

/// Extract the unquoted name and optional unquoted schema from the first
/// `object_reference` child of `node`. Returns `None` if the node has no
/// `object_reference` child or that child has no `name` field.
fn object_name_and_schema<'a>(
    node: &'a Node<'a>,
    bytes: &[u8],
) -> Option<(String, Option<String>)> {
    let obj_ref = first_object_reference(node)?;
    let name_node = obj_ref.child_by_field_name("name")?;
    let name = super::unquote(super::node_text(&name_node, bytes)).to_owned();
    let schema = obj_ref
        .child_by_field_name("schema")
        .map(|n| super::unquote(super::node_text(&n, bytes)).to_owned());
    Some((name, schema))
}

/// Extract the table name (and optional schema) from the first `object_reference`
/// child of a `create_table` node.
fn extract_table(node: &Node, ctx: &ExtractCtx, out: &mut Vec<Symbol>) {
    let Some((table_name, schema)) = object_name_and_schema(node, ctx.bytes) else {
        return;
    };

    // Build the table symbol.
    let table_descriptors = build_descriptors(schema.as_deref(), &table_name, None);
    out.push(make_symbol(
        ctx,
        node,
        table_name.clone(),
        SymbolKind::Table,
        Visibility::Public,
        table_descriptors,
        super::one_line_signature(super::node_text(node, ctx.bytes), &['(']),
    ));

    // Extract columns from the `column_definitions` child (absent for CTAS).
    let Some(col_defs) = node
        .children(&mut node.walk())
        .find(|c| c.kind() == "column_definitions")
    else {
        return;
    };

    for col_child in col_defs.children(&mut col_defs.walk()) {
        if col_child.kind() != "column_definition" {
            continue;
        }
        let Some(col_name_node) = col_child.child_by_field_name("name") else {
            continue;
        };
        let raw_col = super::node_text(&col_name_node, ctx.bytes);
        let col_name = super::unquote(raw_col).to_owned();

        let col_descriptors = build_descriptors(schema.as_deref(), &table_name, Some(&col_name));
        out.push(make_symbol(
            ctx,
            &col_child,
            col_name,
            SymbolKind::Column,
            Visibility::Public,
            col_descriptors,
            super::one_line_signature(super::node_text(&col_child, ctx.bytes), &['(']),
        ));
    }
}

/// Extract the view name (and optional schema) from the first `object_reference`
/// child of a `create_view` or `create_materialized_view` node.
fn extract_view(node: &Node, ctx: &ExtractCtx, out: &mut Vec<Symbol>) {
    let Some((view_name, schema)) = object_name_and_schema(node, ctx.bytes) else {
        return;
    };

    let view_descriptors = build_descriptors(schema.as_deref(), &view_name, None);
    out.push(make_symbol(
        ctx,
        node,
        view_name,
        SymbolKind::View,
        Visibility::Public,
        view_descriptors,
        super::one_line_signature(super::node_text(node, ctx.bytes), &['(']),
    ));
}

/// Find the first child of `node` with kind `object_reference`.
fn first_object_reference<'a>(node: &'a Node<'a>) -> Option<Node<'a>> {
    node.children(&mut node.walk())
        .find(|c| c.kind() == "object_reference")
}

/// Build the descriptor vec for a table/view (column = None) or column.
///
/// Schema namespace is prepended only when present. Columns use `Descriptor::Term`
/// as the leaf; tables/views use `Descriptor::Type`.
fn build_descriptors(schema: Option<&str>, table: &str, column: Option<&str>) -> Vec<Descriptor> {
    let mut descriptors = Vec::new();
    if let Some(s) = schema {
        descriptors.push(Descriptor::Namespace(s.to_owned()));
    }
    descriptors.push(Descriptor::Type(table.to_owned()));
    if let Some(col) = column {
        descriptors.push(Descriptor::Term(col.to_owned()));
    }
    descriptors
}

// ── Reference extraction ──────────────────────────────────────────────────────

/// Walk the tree and collect [`RefRole::TypeRef`] references for every
/// `object_reference` node that is NOT the definition name of a
/// `create_table` / `create_view` / `create_materialized_view` statement.
///
/// The rule is: a direct child `object_reference` of one of those three
/// parent kinds names the object being *created* (already a Symbol); every
/// other `object_reference` in the tree is a use-site — FROM/JOIN/INSERT INTO /
/// UPDATE / DELETE FROM / foreign-key REFERENCES / subquery names, etc.
///
/// v1 boundary: some constructs we don't yet extract as symbols (e.g.
/// `CREATE TRIGGER`, `CREATE INDEX`) also produce `object_reference` nodes for
/// their own names, which we'll emit as refs here. They simply resolve to
/// nothing (no matching symbol) — a harmless no-op until those symbol kinds are
/// added.
fn collect_references(root: &Node, bytes: &[u8], file: &str) -> Vec<Reference> {
    let entity_refs = collect_entity_refs(root, bytes);
    entity_refs
        .into_iter()
        .map(|e| Reference {
            name: e.name,
            occ: Occurrence {
                file: file.to_owned(),
                line: (e.rel_row + 1) as u32,
                col: e.rel_col as u32,
                byte: e.rel_byte,
            },
            role: RefRole::TypeRef,
            source_module: None,
            from_path: None,
            is_reexport: false,
            imported_name: None,
            qualifier: e.qualifier,
            scope: None,
            type_ref_ctx: None,
        })
        .collect()
}

/// A SQL entity use-site (table/view/object reference), with coordinates
/// relative to the SQL string that was parsed — NOT tied to any file.
///
/// This is the reusable unit an embedded-SQL extractor (SQL inside another
/// language's source) can rebase onto its own byte offsets.
pub(crate) struct SqlEntityRef {
    /// The unquoted table/object name.
    pub name: String,
    /// The unquoted schema qualifier, if any (e.g. `app` in `app.users`).
    pub qualifier: Option<String>,
    /// `object_reference` node's start byte, relative to the parsed SQL string.
    pub rel_byte: usize,
    /// `object_reference` node's start row, relative to the parsed SQL string.
    pub rel_row: usize,
    /// `object_reference` node's start column, relative to the parsed SQL string.
    pub rel_col: usize,
}

/// Walk the tree and collect [`SqlEntityRef`]s for every `object_reference`
/// node that is NOT the definition name of a `create_table` / `create_view` /
/// `create_materialized_view` statement. See [`collect_references`] for the
/// full rule and its v1 boundary notes.
fn collect_entity_refs(root: &Node, bytes: &[u8]) -> Vec<SqlEntityRef> {
    let mut out = Vec::new();
    collect_entity_refs_recursive(root, bytes, &mut out);
    out
}

fn collect_entity_refs_recursive(node: &Node, bytes: &[u8], out: &mut Vec<SqlEntityRef>) {
    if node.kind() == "object_reference" {
        // Determine whether this is the definition name: a direct child of
        // create_table / create_view / create_materialized_view.
        let is_definition_name = node
            .parent()
            .map(|p| {
                matches!(
                    p.kind(),
                    "create_table" | "create_view" | "create_materialized_view"
                )
            })
            .unwrap_or(false);

        if !is_definition_name {
            // Emit an entity ref for this use-site.
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = super::unquote(super::node_text(&name_node, bytes)).to_owned();
                if !name.is_empty() {
                    let qualifier = node
                        .child_by_field_name("schema")
                        .map(|n| super::unquote(super::node_text(&n, bytes)).to_owned());
                    out.push(SqlEntityRef {
                        name,
                        qualifier,
                        rel_byte: node.start_byte(),
                        rel_row: node.start_position().row,
                        rel_col: node.start_position().column,
                    });
                }
            }
        }
        // Recurse into children of this object_reference as well (nested
        // object_references can appear in subqueries).
    }
    for child in node.children(&mut node.walk()) {
        collect_entity_refs_recursive(&child, bytes, out);
    }
}

// ── Tier-B: scope tree ────────────────────────────────────────────────────────

/// Build the lexical scope tree for one SQL file.
///
/// `scopes[0]` is always the file-root `Module` scope spanning `[0, source_len)`.
/// Each `statement` or `subquery` node opens a `ScopeKind::Other` scope; other
/// constructs do not introduce new name-resolution regions.
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
    // Walk the root's children (the top-level statements in the program node).
    for child in root.children(&mut root.walk()) {
        scope_dfs(&child, 0, &mut scopes);
    }
    scopes
}

/// DFS that opens `Other` scopes for `statement` and `subquery` nodes.
fn scope_dfs(node: &Node, parent: ScopeId, scopes: &mut Vec<Scope>) {
    match node.kind() {
        "statement" | "subquery" => {
            let new_id = push_scope(scopes, Some(parent), node_span(node), ScopeKind::Other);
            for child in node.children(&mut node.walk()) {
                scope_dfs(&child, new_id, scopes);
            }
        }
        _ => {
            for child in node.children(&mut node.walk()) {
                scope_dfs(&child, parent, scopes);
            }
        }
    }
}

// ── Tier-B: CTE symbol extraction ────────────────────────────────────────────

/// Return the first `identifier` child of a `cte` node (the CTE name node).
///
/// Both CTE symbol and CTE binding collection need to locate this same node;
/// this helper avoids duplicating the traversal.
#[inline]
fn cte_identifier_node<'a>(cte_node: &Node<'a>) -> Option<Node<'a>> {
    cte_node
        .children(&mut cte_node.walk())
        .find(|c| c.kind() == "identifier")
}

/// Collect a [`Symbol`] for every CTE name introduced by `WITH … AS (…)`.
///
/// The CTE name is the first `identifier` child of a `cte` node. The symbol
/// uses the same [`Descriptor::Type`] leaf as DDL table/view definitions (no
/// schema prefix — CTEs are always local to their statement scope).
fn collect_cte_symbols(root: &Node, ctx: &ExtractCtx) -> Vec<Symbol> {
    let mut out = Vec::new();
    collect_cte_symbols_dfs(root, ctx, &mut out);
    out
}

fn collect_cte_symbols_dfs(node: &Node, ctx: &ExtractCtx, out: &mut Vec<Symbol>) {
    if node.kind() == "cte" {
        // The first child of kind `identifier` is the CTE name.
        if let Some(name_node) = cte_identifier_node(node) {
            let name = super::unquote(super::node_text(&name_node, ctx.bytes)).to_owned();
            if !name.is_empty() {
                // Mirror DDL SymbolId style: Descriptor::Type as the single leaf.
                let descriptors = vec![Descriptor::Type(name.clone())];
                out.push(make_symbol(
                    ctx,
                    node,
                    name,
                    SymbolKind::Other,
                    Visibility::Public,
                    descriptors,
                    String::new(),
                ));
            }
        }
        // Do NOT recurse into `cte` children to avoid re-entering nested CTEs
        // from within this one's body statement — those will be visited by the
        // outer DFS as siblings of the parent `statement`.
        return;
    }
    for child in node.children(&mut node.walk()) {
        collect_cte_symbols_dfs(&child, ctx, out);
    }
}

// ── Tier-B: CTE binding collection ───────────────────────────────────────────

/// Collect [`BindingKind::Definition`] bindings for each CTE name.
///
/// Each binding lives in the innermost scope containing the CTE's name node —
/// that is the `statement` or `subquery` scope opened by the enclosing WITH
/// clause, never scope 0 (the file root). This is what enables the scope-graph
/// resolver to prefer the CTE definition over any global table of the same name.
fn collect_cte_bindings(
    root: &Node,
    bytes: &[u8],
    scopes: &[Scope],
    cte_symbols: &[Symbol],
) -> Vec<Binding> {
    // Index CTE symbols by name for O(1) lookup.
    let by_name: HashMap<&str, &Symbol> =
        cte_symbols.iter().map(|s| (s.name.as_str(), s)).collect();
    let mut out = Vec::new();
    collect_cte_bindings_dfs(root, bytes, scopes, &by_name, &mut out);
    out
}

fn collect_cte_bindings_dfs<'a>(
    node: &Node,
    bytes: &[u8],
    scopes: &[Scope],
    by_name: &HashMap<&'a str, &'a Symbol>,
    out: &mut Vec<Binding>,
) {
    if node.kind() == "cte" {
        if let Some(name_node) = cte_identifier_node(node) {
            let name = super::unquote(super::node_text(&name_node, bytes));
            if let Some(sym) = by_name.get(name) {
                let scope = innermost_scope(name_node.start_byte(), scopes).unwrap_or(0);
                out.push(Binding {
                    scope,
                    name: name.to_owned(),
                    intro: name_node.start_byte(),
                    kind: BindingKind::Definition,
                    target: BindingTarget::Def(sym.id.clone()),
                });
            }
        }
        // Do not recurse further — same rationale as collect_cte_symbols_dfs.
        return;
    }
    for child in node.children(&mut node.walk()) {
        collect_cte_bindings_dfs(&child, bytes, scopes, by_name, out);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::extract_path;

    fn scip(sym: &Symbol) -> String {
        sym.id.to_scip_string()
    }

    fn find_by_name<'a>(symbols: &'a [Symbol], name: &str) -> Option<&'a Symbol> {
        symbols.iter().find(|s| s.name == name)
    }

    // ── Module symbol still present ───────────────────────────────────────────

    #[test]
    fn sql_stub_parses_and_emits_module_symbol() {
        let src = "CREATE TABLE users (id INT, name TEXT);";
        let facts = SqlExtractor.extract(src, "db/schema.sql").unwrap();

        assert_eq!(facts.lang, "sql");
        assert!(
            !facts.symbols.is_empty(),
            "expected at least the module symbol, got {:?}",
            facts.symbols
        );
        let mod_sym = facts.symbols.iter().find(|s| s.name == "schema").unwrap();
        assert!(
            mod_sym.id.to_scip_string().contains("schema"),
            "module symbol SCIP string should contain the file stem; got: {}",
            mod_sym.id.to_scip_string()
        );
        // A pure CREATE TABLE with no use-sites emits no references.
        assert!(
            facts
                .references
                .iter()
                .all(|r| r.role != RefRole::TypeRef || r.name != "users"),
            "pure DDL should not emit a TypeRef reference for the table being created"
        );
    }

    #[test]
    fn dispatch_routes_sql_extension() {
        let src = "CREATE TABLE orders (id INT);";
        let facts = extract_path("db/orders.sql", src).unwrap();
        assert_eq!(facts.lang, "sql");
    }

    // ── Basic table + columns ─────────────────────────────────────────────────

    #[test]
    fn create_table_emits_table_and_column_symbols() {
        let src = "CREATE TABLE users (id INT, email TEXT);";
        let facts = SqlExtractor.extract(src, "db/schema.sql").unwrap();

        let table = find_by_name(&facts.symbols, "users").expect("expected 'users' table symbol");
        assert_eq!(table.kind, SymbolKind::Table);
        assert!(
            scip(table).ends_with("users#"),
            "table SCIP should end with 'users#', got: {}",
            scip(table)
        );

        let id_col = find_by_name(&facts.symbols, "id").expect("expected 'id' column symbol");
        assert_eq!(id_col.kind, SymbolKind::Column);
        assert!(
            scip(id_col).ends_with("users#id."),
            "id column SCIP should end with 'users#id.', got: {}",
            scip(id_col)
        );

        let email_col =
            find_by_name(&facts.symbols, "email").expect("expected 'email' column symbol");
        assert_eq!(email_col.kind, SymbolKind::Column);
        assert!(
            scip(email_col).ends_with("users#email."),
            "email column SCIP should end with 'users#email.', got: {}",
            scip(email_col)
        );
    }

    // ── Schema-qualified table ────────────────────────────────────────────────

    #[test]
    fn schema_qualified_table_and_column() {
        let src = "CREATE TABLE app.users (id INT);";
        let facts = SqlExtractor.extract(src, "db/schema.sql").unwrap();

        let table = find_by_name(&facts.symbols, "users").expect("expected 'users' symbol");
        assert_eq!(table.kind, SymbolKind::Table);
        assert!(
            scip(table).ends_with("app/users#"),
            "table SCIP should end with 'app/users#', got: {}",
            scip(table)
        );

        let id_col = find_by_name(&facts.symbols, "id").expect("expected 'id' column symbol");
        assert_eq!(id_col.kind, SymbolKind::Column);
        assert!(
            scip(id_col).ends_with("app/users#id."),
            "id column SCIP should end with 'app/users#id.', got: {}",
            scip(id_col)
        );
    }

    // ── View ─────────────────────────────────────────────────────────────────

    #[test]
    fn create_view_emits_view_symbol_no_columns() {
        let src = "CREATE VIEW active_users AS SELECT * FROM users;";
        let facts = SqlExtractor.extract(src, "db/schema.sql").unwrap();

        let view =
            find_by_name(&facts.symbols, "active_users").expect("expected 'active_users' symbol");
        assert_eq!(view.kind, SymbolKind::View);
        assert!(
            scip(view).ends_with("active_users#"),
            "view SCIP should end with 'active_users#', got: {}",
            scip(view)
        );

        // No column symbols from a view (no column_definitions).
        let col_count = facts
            .symbols
            .iter()
            .filter(|s| s.kind == SymbolKind::Column)
            .count();
        assert_eq!(col_count, 0, "views should produce no column symbols");
    }

    // ── Quoted identifiers ────────────────────────────────────────────────────

    #[test]
    fn double_quoted_table_name_strips_quotes() {
        let src = r#"CREATE TABLE "my table" (id INT);"#;
        let facts = SqlExtractor.extract(src, "db/schema.sql").unwrap();

        let table = find_by_name(&facts.symbols, "my table")
            .expect("expected 'my table' symbol (unquoted)");
        assert_eq!(table.kind, SymbolKind::Table);
        assert!(
            scip(table).contains("my table"),
            "SCIP should contain the bare name 'my table', got: {}",
            scip(table)
        );
    }

    // ── CTAS guard (no column_definitions) ───────────────────────────────────

    #[test]
    fn ctas_does_not_panic_and_emits_table_symbol_only() {
        // CREATE TABLE ... AS SELECT has no column_definitions child.
        let src = "CREATE TABLE summary AS SELECT id, name FROM users;";
        let facts = SqlExtractor.extract(src, "db/schema.sql").unwrap();

        // Should not panic; table symbol should still appear.
        let table =
            find_by_name(&facts.symbols, "summary").expect("expected 'summary' table symbol");
        assert_eq!(table.kind, SymbolKind::Table);

        // No column symbols because there is no column_definitions node.
        let col_count = facts
            .symbols
            .iter()
            .filter(|s| s.kind == SymbolKind::Column)
            .count();
        assert_eq!(col_count, 0, "CTAS table should produce no column symbols");
    }

    // ── Robustness / empty / malformed ────────────────────────────────────────

    #[test]
    fn empty_sql_does_not_panic_and_returns_module_symbol() {
        let facts = SqlExtractor.extract("", "db/empty.sql").unwrap();
        // At minimum the module symbol must be present.
        assert!(
            facts.symbols.iter().any(|s| s.kind == SymbolKind::Module),
            "empty SQL should still produce the module symbol"
        );
        // No DDL symbols at all.
        assert!(
            !facts.symbols.iter().any(|s| matches!(
                s.kind,
                SymbolKind::Table | SymbolKind::View | SymbolKind::Column
            )),
            "empty SQL should produce no DDL symbols"
        );
    }

    #[test]
    fn malformed_sql_does_not_panic() {
        let facts = SqlExtractor
            .extract("THIS IS NOT VALID SQL !!!", "db/bad.sql")
            .unwrap();
        // Must not panic; module symbol must be present.
        assert!(
            facts.symbols.iter().any(|s| s.kind == SymbolKind::Module),
            "malformed SQL should still return Ok with the module symbol"
        );
    }

    // ── Reference extraction tests ────────────────────────────────────────────

    /// `SELECT * FROM users` → one TypeRef reference named `users`, no qualifier.
    #[test]
    fn select_from_emits_typeref_reference() {
        let src = "SELECT * FROM users;";
        let facts = SqlExtractor.extract(src, "db/query.sql").unwrap();
        let refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::TypeRef && r.name == "users")
            .collect();
        assert_eq!(
            refs.len(),
            1,
            "expected exactly one TypeRef ref named 'users', got: {:?}",
            facts.references
        );
        assert_eq!(
            refs[0].qualifier, None,
            "unqualified ref should have no qualifier"
        );
    }

    /// `SELECT * FROM app.users` → TypeRef ref named `users`, qualifier `Some("app")`.
    #[test]
    fn select_from_schema_qualified_emits_qualifier() {
        let src = "SELECT * FROM app.users;";
        let facts = SqlExtractor.extract(src, "db/query.sql").unwrap();
        let refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::TypeRef && r.name == "users")
            .collect();
        assert_eq!(
            refs.len(),
            1,
            "expected one TypeRef ref named 'users', got: {:?}",
            facts.references
        );
        assert_eq!(
            refs[0].qualifier,
            Some("app".to_owned()),
            "schema-qualified ref should carry qualifier 'app'"
        );
    }

    /// JOIN emits a TypeRef reference for the joined table.
    #[test]
    fn join_emits_typeref_reference() {
        let src = "SELECT * FROM orders JOIN users ON orders.user_id = users.id;";
        let facts = SqlExtractor.extract(src, "db/query.sql").unwrap();
        let users_refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::TypeRef && r.name == "users")
            .collect();
        assert!(
            !users_refs.is_empty(),
            "expected at least one TypeRef ref for 'users' (JOIN target), got: {:?}",
            facts.references
        );
    }

    /// Foreign-key REFERENCES clause emits a TypeRef reference for the referenced table.
    #[test]
    fn foreign_key_references_emits_typeref() {
        let src = "CREATE TABLE orders (id INT, user_id INT REFERENCES users(id));";
        let facts = SqlExtractor.extract(src, "db/schema.sql").unwrap();
        let fk_refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::TypeRef && r.name == "users")
            .collect();
        assert_eq!(
            fk_refs.len(),
            1,
            "expected one TypeRef ref for FK REFERENCES 'users', got: {:?}",
            facts.references
        );
    }

    /// Pure DDL: `CREATE TABLE users (id INT)` alone emits NO TypeRef reference
    /// for `users` — the definition name is skipped.
    #[test]
    fn pure_ddl_no_typeref_for_definition_name() {
        let src = "CREATE TABLE users (id INT);";
        let facts = SqlExtractor.extract(src, "db/schema.sql").unwrap();
        let typeref_users: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::TypeRef && r.name == "users")
            .collect();
        assert!(
            typeref_users.is_empty(),
            "pure DDL CREATE TABLE should NOT emit a TypeRef ref for 'users' (it's the definition name), \
             got: {:?}",
            typeref_users
        );
    }

    // ── Tier-B scope / CTE tests ──────────────────────────────────────────────

    /// A WITH statement opens at least one non-module (Other) scope.
    #[test]
    fn cte_statement_opens_other_scope() {
        let src = "WITH r AS (SELECT 1) SELECT * FROM r;";
        let facts = SqlExtractor.extract(src, "db/query.sql").unwrap();
        // scope[0] = Module; at least one more scope with kind Other.
        assert!(
            facts.scopes.len() >= 2,
            "expected at least two scopes (Module + statement), got: {:?}",
            facts.scopes
        );
        let has_other = facts.scopes.iter().any(|s| s.kind == ScopeKind::Other);
        assert!(has_other, "expected at least one ScopeKind::Other scope");
        // Every Other scope has Some(parent) leading back toward 0.
        for scope in &facts.scopes {
            if scope.kind == ScopeKind::Other {
                assert!(
                    scope.parent.is_some(),
                    "Other scope should have a parent, got: {:?}",
                    scope
                );
            }
        }
    }

    /// CTE name → Definition binding in a non-zero Other scope.
    #[test]
    fn cte_name_gets_definition_binding_in_statement_scope() {
        let src = "WITH revenue AS (SELECT amount FROM sales) SELECT * FROM revenue;";
        let facts = SqlExtractor.extract(src, "db/query.sql").unwrap();

        let binding = facts
            .bindings
            .iter()
            .find(|b| b.name == "revenue" && b.kind == BindingKind::Definition);
        let binding = binding.expect("expected a Definition binding for 'revenue'");

        // Binding must be in a non-zero scope (not the file root).
        assert_ne!(
            binding.scope, 0,
            "CTE binding should be in a statement scope, not the file root (scope 0)"
        );
        // The scope it lives in must be ScopeKind::Other.
        assert_eq!(
            facts.scopes[binding.scope].kind,
            ScopeKind::Other,
            "CTE binding scope should be ScopeKind::Other, got: {:?}",
            facts.scopes[binding.scope]
        );
    }

    /// The `FROM revenue` reference inside a CTE statement has its scope set.
    #[test]
    fn cte_from_ref_has_scope_set() {
        let src = "WITH revenue AS (SELECT amount FROM sales) SELECT * FROM revenue;";
        let facts = SqlExtractor.extract(src, "db/query.sql").unwrap();

        let revenue_ref = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::TypeRef && r.name == "revenue");
        let revenue_ref =
            revenue_ref.expect("expected a TypeRef reference named 'revenue' (FROM revenue)");
        assert!(
            revenue_ref.scope.is_some(),
            "FROM revenue reference should have scope set, got None"
        );
    }

    /// CTE definition emits a Symbol with kind Other and the correct name/line.
    #[test]
    fn cte_emits_symbol() {
        let src = "WITH revenue AS (SELECT amount FROM sales) SELECT * FROM revenue;";
        let facts = SqlExtractor.extract(src, "db/query.sql").unwrap();

        let sym = find_by_name(&facts.symbols, "revenue")
            .expect("expected a Symbol named 'revenue' for the CTE definition");
        assert_eq!(
            sym.kind,
            SymbolKind::Other,
            "CTE symbol kind should be Other"
        );
        assert_eq!(sym.line, 1, "CTE symbol should be on line 1");
    }

    /// A plain `SELECT * FROM users` (no CTE) still produces scopes and the
    /// `users` reference has its scope set.
    #[test]
    fn plain_select_scopes_and_ref_scope() {
        let src = "SELECT * FROM users;";
        let facts = SqlExtractor.extract(src, "db/query.sql").unwrap();

        assert!(
            !facts.scopes.is_empty(),
            "plain SELECT should still produce scopes"
        );
        let users_ref = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::TypeRef && r.name == "users")
            .expect("expected TypeRef ref for 'users'");
        assert!(
            users_ref.scope.is_some(),
            "plain SELECT FROM ref should have scope set"
        );
    }

    /// DDL `CREATE TABLE orders (id INT)` still gets a Definition binding at scope 0.
    #[test]
    fn ddl_gets_definition_binding_at_scope_0() {
        let src = "CREATE TABLE orders (id INT);";
        let facts = SqlExtractor.extract(src, "db/schema.sql").unwrap();

        let binding = facts
            .bindings
            .iter()
            .find(|b| b.name == "orders" && b.kind == BindingKind::Definition);
        let binding = binding.expect("expected a Definition binding for 'orders'");
        assert_eq!(
            binding.scope, 0,
            "DDL Definition binding should be at file-root scope (0)"
        );
    }
}
