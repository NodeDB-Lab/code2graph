// SPDX-License-Identifier: Apache-2.0

//! SQL extractor — extracts DDL symbols (tables, views, columns) via tree-sitter-sequel.
//!
//! Emits neutral [`FileFacts`] — no storage entries, no source bodies. References
//! (table use-sites in FROM/JOIN/INSERT/UPDATE/DELETE/REFERENCES clauses) are now
//! emitted as [`RefRole::TypeRef`] so the language-agnostic resolver can link them
//! to their table/view definitions automatically.

use tree_sitter::{Language as TsLanguage, Node, Parser};

use crate::error::{CodegraphError, Result};
use crate::graph::types::{ByteSpan, FileFacts, RefRole, Reference, Symbol, SymbolKind};
use crate::lang::Language;
use crate::symbol::{Descriptor, SymbolId};

use super::Extractor;

/// Extracts SQL symbols and references (tables, views, columns).
pub struct SqlExtractor;

impl Extractor for SqlExtractor {
    fn lang(&self) -> Language {
        Language::Sql
    }

    fn extract(&self, source: &str, file: &str) -> Result<FileFacts> {
        let ts_language = TsLanguage::from(tree_sitter_sequel::LANGUAGE);
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

        let mut symbols = collect_symbols(&root, bytes, file);
        let mod_sym = super::module_symbol(Language::Sql, &[], file, source.len());
        symbols.push(mod_sym);

        let references = collect_references(&root, bytes, file);

        Ok(FileFacts {
            file: file.to_owned(),
            lang: Language::Sql.as_str().to_owned(),
            symbols,
            references,
            scopes: Vec::new(),
            bindings: Vec::new(),
            ffi_exports: Vec::new(),
        })
    }
}

// ── Symbol extraction ─────────────────────────────────────────────────────────

/// Walk the tree recursively and collect DDL symbols (tables, views, columns).
///
/// SQL has no path-namespace derived from the file path — the optional schema
/// prefix comes from the SQL itself and is captured directly.
fn collect_symbols(root: &Node, bytes: &[u8], file: &str) -> Vec<Symbol> {
    let mut out = Vec::new();
    collect_symbols_recursive(root, bytes, file, &mut out);
    out
}

fn collect_symbols_recursive(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Symbol>) {
    match node.kind() {
        "create_table" => {
            extract_table(node, bytes, file, out);
        }
        "create_view" | "create_materialized_view" => {
            extract_view(node, bytes, file, out);
        }
        _ => {
            for child in node.children(&mut node.walk()) {
                collect_symbols_recursive(&child, bytes, file, out);
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
fn extract_table(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Symbol>) {
    let Some((table_name, schema)) = object_name_and_schema(node, bytes) else {
        return;
    };

    // Build the table symbol.
    let table_descriptors = build_descriptors(schema.as_deref(), &table_name, None);
    out.push(Symbol {
        id: SymbolId::global(Language::Sql.as_str(), table_descriptors),
        name: table_name.clone(),
        kind: SymbolKind::Table,
        file: file.to_owned(),
        line: (node.start_position().row + 1) as u32,
        span: ByteSpan {
            start: node.start_byte(),
            end: node.end_byte(),
        },
        signature: super::one_line_signature(super::node_text(node, bytes), &['(']),
    });

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
        let raw_col = super::node_text(&col_name_node, bytes);
        let col_name = super::unquote(raw_col).to_owned();

        let col_descriptors = build_descriptors(schema.as_deref(), &table_name, Some(&col_name));
        out.push(Symbol {
            id: SymbolId::global(Language::Sql.as_str(), col_descriptors),
            name: col_name,
            kind: SymbolKind::Column,
            file: file.to_owned(),
            line: (col_child.start_position().row + 1) as u32,
            span: ByteSpan {
                start: col_child.start_byte(),
                end: col_child.end_byte(),
            },
            signature: super::one_line_signature(super::node_text(&col_child, bytes), &['(']),
        });
    }
}

/// Extract the view name (and optional schema) from the first `object_reference`
/// child of a `create_view` or `create_materialized_view` node.
fn extract_view(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Symbol>) {
    let Some((view_name, schema)) = object_name_and_schema(node, bytes) else {
        return;
    };

    let view_descriptors = build_descriptors(schema.as_deref(), &view_name, None);
    out.push(Symbol {
        id: SymbolId::global(Language::Sql.as_str(), view_descriptors),
        name: view_name,
        kind: SymbolKind::View,
        file: file.to_owned(),
        line: (node.start_position().row + 1) as u32,
        span: ByteSpan {
            start: node.start_byte(),
            end: node.end_byte(),
        },
        signature: super::one_line_signature(super::node_text(node, bytes), &['(']),
    });
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
    let mut out = Vec::new();
    collect_references_recursive(root, bytes, file, &mut out);
    out
}

fn collect_references_recursive(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
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
            // Emit a TypeRef reference for this use-site.
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = super::unquote(super::node_text(&name_node, bytes)).to_owned();
                if !name.is_empty() {
                    let qualifier = node
                        .child_by_field_name("schema")
                        .map(|n| super::unquote(super::node_text(&n, bytes)).to_owned());
                    out.push(Reference {
                        name,
                        occ: super::node_occurrence(node, file),
                        role: RefRole::TypeRef,
                        source_module: None,
                        from_path: None,
                        qualifier,
                        scope: None,
                    });
                }
            }
        }
        // Recurse into children of this object_reference as well (nested
        // object_references can appear in subqueries).
    }
    for child in node.children(&mut node.walk()) {
        collect_references_recursive(&child, bytes, file, out);
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
}
