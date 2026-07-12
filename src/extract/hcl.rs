// SPDX-License-Identifier: Apache-2.0

//! HCL/Terraform extractor — extracts block symbols (resource, data, module)
//! and reference traversals via tree-sitter-hcl.
//!
//! Emits neutral [`FileFacts`] — no storage entries, no source bodies.
//! References: every attribute-value traversal of the form `T.N[.attr…]`
//! (e.g. `aws_subnet.main.id`, `module.vpc.id`) is emitted as a
//! [`RefRole::TypeRef`] with `name = seg1` and `qualifier = Some(seg0)`, so
//! the language-agnostic resolver can link them to resource / module symbols.
//!
//! ## Tree structure (tree-sitter-hcl 1.1.0)
//!
//! A traversal `aws_subnet.main.id` is represented as an `expression` node
//! whose **named children** are, in order:
//! 1. `variable_expr` — one `identifier` child whose text is `aws_subnet` (seg0).
//! 2. `get_attr`      — one `identifier` child whose text is `main` (seg1).
//! 3. `get_attr`      — one `identifier` child whose text is `id`.
//!
//! `variable_expr` and each `get_attr` are **siblings** under `expression`; they
//! are not nested. `${…}` interpolations wrap the same chain inside
//! `template_interpolation` → `expression`, so the same traversal applies.

use tree_sitter::{Node, Parser};

use crate::error::{CodegraphError, Result};
use crate::graph::types::{
    ByteSpan, FileFacts, RefRole, Reference, Scope, ScopeKind, Symbol, SymbolKind, Visibility,
};
use crate::lang::Language;
use crate::symbol::Descriptor;

use super::{
    ExtractCtx, Extractor, attach_reference_scopes, definition_bindings, make_symbol, push_scope,
};

/// Extracts HCL/Terraform symbols and references.
pub struct HclExtractor;

impl Extractor for HclExtractor {
    fn lang(&self) -> Language {
        Language::Hcl
    }

    fn extract(&self, source: &str, file: &str) -> Result<FileFacts> {
        let ts_language = crate::grammar::hcl();
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
            lang: Language::Hcl,
        };

        // Collect definitions first so we can derive bindings before adding the
        // file-module symbol (the module symbol is not a user-written definition).
        let defs = collect_symbols(&root, &ctx);
        let def_bindings = definition_bindings(&defs);
        let mut symbols = defs;
        symbols.push(super::module_symbol(Language::Hcl, &[], file, source.len()));

        let mut references = collect_references(&root, ctx.bytes, ctx.file);

        // HCL is flat — one Module scope spanning the whole file, no nesting.
        let scopes = collect_scopes(source.len());
        attach_reference_scopes(&mut references, &scopes);

        // Only definition bindings for HCL (no imports, no locals).
        let bindings = def_bindings;

        Ok(FileFacts {
            file: file.to_owned(),
            lang: Language::Hcl.as_str().to_owned(),
            symbols,
            references,
            scopes,
            bindings,
            ffi_exports: Vec::new(),
        })
    }
}

// ── Scope collection ──────────────────────────────────────────────────────────

/// Build the scope tree for an HCL file.
///
/// HCL has no nested lexical scopes (unlike Rust/Python function bodies or
/// JS block scopes).  A single [`ScopeKind::Module`] scope spanning the whole
/// file is sufficient: every top-level definition binds at scope 0 and every
/// reference (including qualified traversals like `module.vpc.id`) is attached
/// to the same file-root scope.  Qualified references are resolved by the
/// scope-graph resolver's **path-qualified-call** arm, which bypasses the
/// lexical scope walk entirely.
fn collect_scopes(source_len: usize) -> Vec<Scope> {
    let mut scopes: Vec<Scope> = Vec::new();
    push_scope(
        &mut scopes,
        None,
        ByteSpan {
            start: 0,
            end: source_len,
        },
        ScopeKind::Module,
    );
    scopes
}

// ── Symbol extraction ─────────────────────────────────────────────────────────

/// Extract `(block_type, labels)` from a `block` node.
///
/// Walk named children: the first `identifier` child is the block type; every
/// subsequent `string_lit` or `identifier` child (in order) before a
/// `block_start` child is a label. Returns `None` if the block has no type
/// identifier.
fn block_type_and_labels(block: &Node, bytes: &[u8]) -> Option<(String, Vec<String>)> {
    // Collect all named children up front into a Vec to avoid borrow conflicts
    // with tree-sitter's walk cursor.
    let named: Vec<Node> = {
        let mut cursor = block.walk();
        block.named_children(&mut cursor).collect()
    };

    // First named child must be an `identifier` — the block type.
    let first = named.first()?;
    if first.kind() != "identifier" {
        return None;
    }
    let block_type = super::node_text(first, bytes).to_owned();

    // Collect label children: `string_lit` or `identifier` until `block_start`.
    let mut labels = Vec::new();
    for child in named.iter().skip(1) {
        match child.kind() {
            "string_lit" => {
                labels.push(super::unquote(super::node_text(child, bytes)).to_owned());
            }
            "identifier" => {
                // An unquoted label identifier (rare in practice, but valid HCL).
                labels.push(super::node_text(child, bytes).to_owned());
            }
            "block_start" | "body" | "block_end" | "object_start" | "object_end" => break,
            _ => {
                // Skip unknown node kinds; stop if it looks like we're past the labels.
            }
        }
    }

    Some((block_type, labels))
}

/// Walk the root `body` and collect top-level block symbols.
///
/// Only processes direct `block` children of the root `body` — does NOT recurse
/// into block bodies (nested blocks like `lifecycle` are config, not declarations).
///
/// `.tfvars` files may parse to an `object` root rather than a `body` — guard:
/// if the root's first named child is not `body`, emit no block symbols.
fn collect_symbols(root: &Node, ctx: &ExtractCtx) -> Vec<Symbol> {
    // Find the `body` child of `config_file`.
    let body = {
        let mut cursor = root.walk();
        root.named_children(&mut cursor)
            .find(|c| c.kind() == "body")
    };
    let Some(body) = body else {
        // Root has no `body` (e.g. a `.tfvars` JSON file parses as `object`).
        return Vec::new();
    };

    let top_level_blocks: Vec<Node> = {
        let mut cursor = body.walk();
        body.named_children(&mut cursor).collect()
    };

    let mut out = Vec::new();
    for block in &top_level_blocks {
        if block.kind() != "block" {
            continue;
        }
        if let Some(sym) = extract_block_symbol(block, ctx) {
            out.push(sym);
        }
    }
    out
}

/// Attempt to extract a [`Symbol`] from a top-level HCL `block` node.
///
/// Dispatch on the block type:
/// - `resource "T" "N"` → `SymbolKind::Resource`, SCIP `T/N#`
/// - `data "T" "N"`     → `SymbolKind::Resource`, SCIP `data/T/N#`
/// - `module "N"`        → `SymbolKind::Module`,   SCIP `module/N#`
/// - All others (variable/output/provider/locals/terraform/…) → skipped.
///   v1 boundary: these block types are recognised by Terraform but deferred
///   until a later unit defines their symbol taxonomy.
fn extract_block_symbol(block: &Node, ctx: &ExtractCtx) -> Option<Symbol> {
    let (block_type, labels) = block_type_and_labels(block, ctx.bytes)?;

    let sig = super::one_line_signature(super::node_text(block, ctx.bytes), &['{']);

    match block_type.as_str() {
        "resource" => {
            // Expects exactly 2 labels: type ("aws_instance") and name ("web").
            if labels.len() < 2 {
                return None; // Malformed — skip gracefully.
            }
            let res_type = &labels[0];
            let res_name = &labels[1];
            let descriptors = vec![
                Descriptor::Namespace(res_type.clone()),
                Descriptor::Type(res_name.clone()),
            ];
            Some(make_symbol(
                ctx,
                block,
                res_name.clone(),
                SymbolKind::Resource,
                Visibility::Public,
                descriptors,
                sig,
            ))
        }
        "data" => {
            // Expects exactly 2 labels: data-source type and name.
            // SCIP: `data/T/N#` — the `data` namespace prevents collision with
            // a resource of the same type/name, mirroring Terraform's `data.T.N`
            // reference form.
            if labels.len() < 2 {
                return None; // Malformed — skip gracefully.
            }
            let src_type = &labels[0];
            let src_name = &labels[1];
            let descriptors = vec![
                Descriptor::Namespace("data".to_owned()),
                Descriptor::Namespace(src_type.clone()),
                Descriptor::Type(src_name.clone()),
            ];
            Some(make_symbol(
                ctx,
                block,
                src_name.clone(),
                SymbolKind::Resource,
                Visibility::Public,
                descriptors,
                sig,
            ))
        }
        "module" => {
            // Expects exactly 1 label: the module instance name.
            // SCIP: `module/N#`
            if labels.is_empty() {
                return None; // Malformed — skip gracefully.
            }
            let mod_name = &labels[0];
            let descriptors = vec![
                Descriptor::Namespace("module".to_owned()),
                Descriptor::Type(mod_name.clone()),
            ];
            Some(make_symbol(
                ctx,
                block,
                mod_name.clone(),
                SymbolKind::Module,
                Visibility::Public,
                descriptors,
                sig,
            ))
        }
        // v1 boundary: variable, output, provider, locals, terraform, and any
        // other block types are deferred — they are recognised by Terraform but
        // their symbol taxonomy (kind, descriptor shape) is left for a later unit.
        _ => None,
    }
}

// ── Reference extraction ──────────────────────────────────────────────────────

/// Walk the whole parse tree and collect [`RefRole::TypeRef`] references for
/// every **attribute-value traversal** with at least two segments.
///
/// A traversal is recognised when we visit an `expression` node that has a
/// `variable_expr` named child **and** at least one `get_attr` named sibling
/// within the same `expression`.  We emit exactly one [`Reference`] per
/// traversal:
/// - `name`      = the first `get_attr` identifier (seg1, e.g. `main`).
/// - `qualifier` = the `variable_expr` identifier (seg0, e.g. `aws_subnet`).
///
/// This means `aws_subnet.main.id` resolves to name `main`, qualifier
/// `aws_subnet`, matching the SCIP symbol `aws_subnet/main#`.  `module.vpc.x`
/// → name `vpc`, qualifier `module`, matching `module/vpc#`.  A bare
/// `variable_expr` with no `get_attr` sibling (single segment) is skipped.
///
/// v1 boundaries:
/// - `data.T.N` references (leading `data`, 3 segments) won't resolve to the
///   extracted data symbol with the 2-segment rule because the emitted name
///   would be `T`, not `N`.  This is a harmless no-op (no wrong edge).
/// - `var.region` → name `region`, qualifier `var`; no `var` symbol is
///   extracted in v1, so this simply produces no edge.
fn collect_references(root: &Node, bytes: &[u8], file: &str) -> Vec<Reference> {
    let mut out = Vec::new();
    collect_references_recursive(root, bytes, file, &mut out);
    out
}

fn collect_references_recursive(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    // Detect an `expression` node that starts a traversal chain.
    //
    // The tree-sitter-hcl grammar encodes `aws_subnet.main.id` as:
    //   expression
    //     variable_expr → identifier("aws_subnet")
    //     get_attr      → identifier("main")
    //     get_attr      → identifier("id")
    //
    // We collect the named children of every `expression` node; when the first
    // named child is a `variable_expr` and at least one subsequent named child
    // is a `get_attr`, we have a traversal.  We emit one reference and do NOT
    // recurse further into this `expression`'s named children to avoid
    // double-emitting for the same chain.
    if node.kind() == "expression" {
        let named: Vec<Node> = {
            let mut cursor = node.walk();
            node.named_children(&mut cursor).collect()
        };

        // Does this expression open with a variable_expr?
        if let Some(first) = named.first() {
            if first.kind() == "variable_expr" {
                // Locate the first get_attr sibling.
                let first_get_attr = named.iter().find(|n| n.kind() == "get_attr");
                if let Some(get_attr) = first_get_attr {
                    // seg0: identifier inside variable_expr
                    if let Some(seg0_node) = first
                        .named_children(&mut first.walk())
                        .find(|n| n.kind() == "identifier")
                    {
                        // seg1: identifier inside the first get_attr
                        if let Some(seg1_node) = get_attr
                            .named_children(&mut get_attr.walk())
                            .find(|n| n.kind() == "identifier")
                        {
                            let seg0 = super::node_text(&seg0_node, bytes);
                            let seg1 = super::node_text(&seg1_node, bytes);

                            // Both segments must be non-empty; we do NOT apply
                            // MIN_REF_LEN here — Terraform names like "vpc" or
                            // "web" are exactly 3 chars; "id" (2 chars) only
                            // appears as seg2+, never as seg1 in a real
                            // resource traversal.  Skip only truly empty text
                            // (parse error fallback).
                            if !seg0.is_empty() && !seg1.is_empty() {
                                out.push(Reference {
                                    name: seg1.to_owned(),
                                    qualifier: Some(seg0.to_owned()),
                                    role: RefRole::TypeRef,
                                    occ: super::node_occurrence(first, file),
                                    source_module: None,
                                    from_path: None,
                                    is_reexport: false,
                                    imported_name: None,
                                    scope: None,
                                    type_ref_ctx: None,
                                    cross_artifact: false,
                                });
                            }
                        }
                    }

                    // This expression is a traversal root — do not recurse
                    // into its named children (they are the variable_expr and
                    // get_attr nodes we just processed).  But we must still
                    // recurse into non-traversal child sub-trees (e.g. nested
                    // expressions inside function call arguments).  Since the
                    // children of a traversal expression are all either
                    // `variable_expr`, `get_attr`, or `index` nodes (not
                    // further `expression` nodes), it is safe to return here.
                    return;
                }
            }
        }
    }

    // Recurse into all children (named and anonymous) so we reach nested
    // expressions inside blocks, function arguments, interpolations, etc.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_references_recursive(&child, bytes, file, out);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::extract_path;
    use crate::graph::types::SymbolKind;

    fn scip(sym: &Symbol) -> String {
        sym.id.to_scip_string()
    }

    fn find_by_name<'a>(symbols: &'a [Symbol], name: &str) -> Option<&'a Symbol> {
        symbols.iter().find(|s| s.name == name)
    }

    // ── Dispatch / module symbol ──────────────────────────────────────────────

    #[test]
    fn hcl_emits_module_symbol() {
        let src = r#"resource "aws_instance" "web" {}"#;
        let facts = HclExtractor.extract(src, "infra/main.tf").unwrap();

        assert_eq!(facts.lang, "hcl");
        let mod_sym = facts
            .symbols
            .iter()
            .find(|s| s.kind == SymbolKind::Module && s.name == "main")
            .expect("expected a Module symbol named 'main'");
        assert!(
            mod_sym.id.to_scip_string().contains("main"),
            "module symbol SCIP string should contain 'main'; got: {}",
            mod_sym.id.to_scip_string()
        );
    }

    #[test]
    fn dispatch_routes_tf_extension() {
        let src = r#"resource "aws_instance" "web" {}"#;
        let facts = extract_path("infra/main.tf", src).unwrap();
        assert_eq!(facts.lang, "hcl");
    }

    #[test]
    fn dispatch_routes_hcl_extension() {
        let src = r#"variable "region" { default = "us-east-1" }"#;
        let facts = extract_path("infra/vars.hcl", src).unwrap();
        assert_eq!(facts.lang, "hcl");
    }

    #[test]
    fn dispatch_routes_tfvars_extension() {
        let src = r#"region = "us-east-1""#;
        let facts = extract_path("infra/prod.tfvars", src).unwrap();
        assert_eq!(facts.lang, "hcl");
    }

    // ── resource block ────────────────────────────────────────────────────────

    #[test]
    fn resource_block_emits_resource_symbol() {
        let src = r#"resource "aws_instance" "web" {}"#;
        let facts = HclExtractor.extract(src, "infra/main.tf").unwrap();

        let sym = find_by_name(&facts.symbols, "web").expect("expected 'web' Resource symbol");
        assert_eq!(sym.kind, SymbolKind::Resource);
        assert!(
            scip(sym).ends_with("aws_instance/web#"),
            "resource SCIP should end with 'aws_instance/web#'; got: {}",
            scip(sym)
        );
    }

    // ── data block ────────────────────────────────────────────────────────────

    #[test]
    fn data_block_emits_resource_symbol_with_data_namespace() {
        let src = r#"data "aws_ami" "ubuntu" {}"#;
        let facts = HclExtractor.extract(src, "infra/main.tf").unwrap();

        let sym =
            find_by_name(&facts.symbols, "ubuntu").expect("expected 'ubuntu' Resource symbol");
        assert_eq!(sym.kind, SymbolKind::Resource);
        assert!(
            scip(sym).ends_with("data/aws_ami/ubuntu#"),
            "data SCIP should end with 'data/aws_ami/ubuntu#'; got: {}",
            scip(sym)
        );
    }

    // ── module block ──────────────────────────────────────────────────────────

    #[test]
    fn module_block_emits_module_symbol() {
        let src = r#"module "vpc" { source = "./vpc" }"#;
        let facts = HclExtractor.extract(src, "infra/main.tf").unwrap();

        // There will be two Module-kind symbols: the file module symbol ("main")
        // and the module block symbol ("vpc"). Find the one named "vpc".
        let sym = facts
            .symbols
            .iter()
            .find(|s| s.kind == SymbolKind::Module && s.name == "vpc")
            .expect("expected a Module symbol named 'vpc'");
        assert!(
            scip(sym).ends_with("module/vpc#"),
            "module SCIP should end with 'module/vpc#'; got: {}",
            scip(sym)
        );
    }

    // ── v1 boundary: variable skipped ────────────────────────────────────────

    #[test]
    fn variable_block_alone_emits_no_block_symbol() {
        // `variable` is deferred (v1 boundary). Only the file module symbol appears.
        let src = r#"variable "region" {}"#;
        let facts = HclExtractor.extract(src, "infra/vars.tf").unwrap();

        // No Resource or non-file-module Module symbol.
        let block_syms: Vec<_> = facts
            .symbols
            .iter()
            .filter(|s| s.name == "region")
            .collect();
        assert!(
            block_syms.is_empty(),
            "variable block should produce no symbol in v1; got: {:?}",
            block_syms
        );
        // The file module symbol must still be present.
        assert!(
            facts.symbols.iter().any(|s| s.kind == SymbolKind::Module),
            "the file module symbol should still be present"
        );
    }

    // ── multi-block file ──────────────────────────────────────────────────────

    #[test]
    fn multi_block_file_emits_all_three_symbols() {
        let src = r#"
resource "aws_instance" "web" {}
data "aws_ami" "ubuntu" {}
module "vpc" { source = "./vpc" }
"#;
        let facts = HclExtractor.extract(src, "infra/main.tf").unwrap();

        let web = find_by_name(&facts.symbols, "web").expect("expected 'web'");
        assert_eq!(web.kind, SymbolKind::Resource);
        assert!(
            scip(web).ends_with("aws_instance/web#"),
            "got: {}",
            scip(web)
        );

        let ubuntu = find_by_name(&facts.symbols, "ubuntu").expect("expected 'ubuntu'");
        assert_eq!(ubuntu.kind, SymbolKind::Resource);
        assert!(
            scip(ubuntu).ends_with("data/aws_ami/ubuntu#"),
            "got: {}",
            scip(ubuntu)
        );

        let vpc = facts
            .symbols
            .iter()
            .find(|s| s.kind == SymbolKind::Module && s.name == "vpc")
            .expect("expected 'vpc'");
        assert!(scip(vpc).ends_with("module/vpc#"), "got: {}", scip(vpc));
    }

    // ── empty / malformed ─────────────────────────────────────────────────────

    #[test]
    fn empty_hcl_does_not_panic_and_returns_module_symbol() {
        let facts = HclExtractor.extract("", "infra/empty.tf").unwrap();
        assert!(
            facts.symbols.iter().any(|s| s.kind == SymbolKind::Module),
            "empty HCL should still produce the module symbol"
        );
        assert!(
            facts.references.is_empty(),
            "empty HCL should emit no references"
        );
    }

    #[test]
    fn malformed_hcl_does_not_panic() {
        let facts = HclExtractor
            .extract("THIS IS NOT VALID HCL !!!", "infra/bad.tf")
            .unwrap();
        assert!(
            facts.symbols.iter().any(|s| s.kind == SymbolKind::Module),
            "malformed HCL should still return Ok with the module symbol"
        );
    }

    // ── Reference extraction (H3) ─────────────────────────────────────────────

    /// `subnet_id = aws_subnet.main.id` → one TypeRef ref with name `main`,
    /// qualifier `aws_subnet`.
    #[test]
    fn resource_attr_traversal_emits_typeref_ref() {
        let src = r#"resource "aws_instance" "web" { subnet_id = aws_subnet.main.id }"#;
        let facts = HclExtractor.extract(src, "infra/main.tf").unwrap();

        let refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::TypeRef && r.name == "main")
            .collect();
        assert_eq!(
            refs.len(),
            1,
            "expected exactly one TypeRef ref named 'main', got: {:?}",
            facts.references
        );
        assert_eq!(
            refs[0].qualifier,
            Some("aws_subnet".to_owned()),
            "qualifier should be 'aws_subnet', got: {:?}",
            refs[0].qualifier
        );
    }

    /// `x = module.vpc.id` inside a resource body → TypeRef ref name `vpc`,
    /// qualifier `module`.
    #[test]
    fn module_traversal_in_resource_body_emits_typeref_ref() {
        let src = r#"resource "aws_instance" "web" { x = module.vpc.id }"#;
        let facts = HclExtractor.extract(src, "infra/main.tf").unwrap();

        let refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::TypeRef && r.name == "vpc")
            .collect();
        assert_eq!(
            refs.len(),
            1,
            "expected exactly one TypeRef ref named 'vpc', got: {:?}",
            facts.references
        );
        assert_eq!(
            refs[0].qualifier,
            Some("module".to_owned()),
            "qualifier should be 'module', got: {:?}",
            refs[0].qualifier
        );
    }

    /// `subnet_id = "${aws_subnet.main.id}"` — traversal inside a string
    /// interpolation — should still be captured via the `template_interpolation`
    /// → `expression` path.
    ///
    /// If the grammar represents interpolated expressions differently and capture
    /// fails here, this test is updated to document the v1 boundary rather than
    /// faking it.
    #[test]
    fn traversal_inside_interpolation_emits_typeref_ref() {
        let src = r#"resource "aws_instance" "web" { subnet_id = "${aws_subnet.main.id}" }"#;
        let facts = HclExtractor.extract(src, "infra/main.tf").unwrap();

        let refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::TypeRef && r.name == "main")
            .collect();
        assert_eq!(
            refs.len(),
            1,
            "expected one TypeRef ref 'main' from interpolated traversal; \
             if this fails, the grammar wraps interpolations differently — \
             document as v1 boundary. Got: {:?}",
            facts.references
        );
        assert_eq!(refs[0].qualifier, Some("aws_subnet".to_owned()));
    }

    /// A bare single-segment `variable_expr` (no `get_attr`) → no reference
    /// emitted (can't identify an entity from one segment alone).
    #[test]
    fn single_segment_variable_expr_emits_no_ref() {
        // `local.x` would be two segments; a plain variable reference like
        // `count.index` would be two segments.  Use an attribute that is just
        // a plain variable name with no dot:
        let src = r#"resource "aws_instance" "web" { count = each }"#;
        let facts = HclExtractor.extract(src, "infra/main.tf").unwrap();

        // Ensure no spurious TypeRef refs are emitted for the bare identifier.
        let bare_refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::TypeRef && r.name == "each")
            .collect();
        assert!(
            bare_refs.is_empty(),
            "bare single-segment variable should produce no TypeRef ref; got: {:?}",
            bare_refs
        );
    }

    // ── Tier-B scope / binding wiring ─────────────────────────────────────────

    /// One Module scope spanning the whole file.
    #[test]
    fn tier_b_one_module_scope_spans_file() {
        use crate::graph::types::ScopeKind;

        let src = r#"module "vpc" { source = "./vpc" }"#;
        let facts = HclExtractor.extract(src, "infra/main.tf").unwrap();

        assert_eq!(facts.scopes.len(), 1, "expected exactly one scope");
        let s = &facts.scopes[0];
        assert_eq!(s.kind, ScopeKind::Module, "scope kind should be Module");
        assert_eq!(s.parent, None, "root scope has no parent");
        assert_eq!(s.span.start, 0, "scope should start at 0");
        assert_eq!(s.span.end, src.len(), "scope should end at source length");
    }

    /// module block → Definition binding at scope 0.
    #[test]
    fn tier_b_module_block_yields_definition_binding() {
        use crate::graph::types::{BindingKind, BindingTarget};

        let src = r#"module "vpc" { source = "./vpc" }"#;
        let facts = HclExtractor.extract(src, "infra/main.tf").unwrap();

        let binding = facts
            .bindings
            .iter()
            .find(|b| b.name == "vpc")
            .expect("expected a binding named 'vpc'");
        assert_eq!(
            binding.kind,
            BindingKind::Definition,
            "binding kind should be Definition"
        );
        assert_eq!(binding.scope, 0, "module binding must live in scope 0");
        assert!(
            matches!(binding.target, BindingTarget::Def(_)),
            "target should be BindingTarget::Def(_); got {:?}",
            binding.target
        );
    }

    /// resource block → Definition binding at scope 0.
    #[test]
    fn tier_b_resource_block_yields_definition_binding() {
        use crate::graph::types::{BindingKind, BindingTarget};

        let src = r#"resource "aws_instance" "web" {}"#;
        let facts = HclExtractor.extract(src, "infra/main.tf").unwrap();

        let binding = facts
            .bindings
            .iter()
            .find(|b| b.name == "web")
            .expect("expected a binding named 'web'");
        assert_eq!(
            binding.kind,
            BindingKind::Definition,
            "binding kind should be Definition"
        );
        assert_eq!(binding.scope, 0, "resource binding must live in scope 0");
        assert!(
            matches!(binding.target, BindingTarget::Def(_)),
            "target should be BindingTarget::Def(_); got {:?}",
            binding.target
        );
    }

    /// A reference like `module.vpc.id` gets its `scope` set to Some(_) after
    /// scope attachment.
    #[test]
    fn tier_b_reference_scope_is_attached() {
        let src = r#"resource "aws_instance" "web" { x = module.vpc.id }"#;
        let facts = HclExtractor.extract(src, "infra/main.tf").unwrap();

        // Find the TypeRef reference for "vpc" (qualifier "module").
        let vpc_ref = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::TypeRef && r.name == "vpc")
            .expect("expected a TypeRef ref named 'vpc'");
        assert!(
            vpc_ref.scope.is_some(),
            "reference scope should be attached (Some(_)); got None"
        );
    }

    /// End-to-end resolution via ScopeGraphResolver: `module.vpc.id` reference
    /// resolves exactly to the `module "vpc"` definition with Exact confidence.
    #[test]
    fn tier_b_e2e_qualified_module_ref_resolves_exact() {
        use crate::graph::types::{Confidence, RefRole};
        use crate::resolve::{Resolver, ScopeGraphResolver};

        let src = "module \"vpc\" {\n  source = \"./vpc\"\n}\n\nresource \"aws_instance\" \"web\" {\n  vpc_id = module.vpc.id\n}\n";
        let facts = HclExtractor.extract(src, "infra/main.tf").unwrap();
        let graph = ScopeGraphResolver.resolve(&[facts]).unwrap();

        // Collect TypeRef edges whose `to` SCIP string contains "module/vpc".
        let typeref_edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.role == RefRole::TypeRef && e.to.to_scip_string().contains("module/vpc"))
            .collect();

        assert_eq!(
            typeref_edges.len(),
            1,
            "expected exactly one TypeRef edge targeting module/vpc, got: {:?}",
            typeref_edges
                .iter()
                .map(|e| format!(
                    "{} → {} ({:?})",
                    e.from.to_scip_string(),
                    e.to.to_scip_string(),
                    e.confidence
                ))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            typeref_edges[0].confidence,
            Confidence::Exact,
            "qualified module reference should resolve with Exact confidence"
        );
    }
}
