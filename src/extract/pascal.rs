// SPDX-License-Identifier: Apache-2.0

//! Pascal / Delphi extractor — one tree-sitter pass yielding definitions and references.
//!
//! Definitions: classes, records, interfaces, enums (with their enum values), and their
//! members (methods, fields), plus standalone top-level procedures/functions in a `program`
//! or `unit` implementation section. Method *implementations* (`procedure TFoo.Run; begin end;`)
//! are skipped — only the declaration inside the class interface body is the definition site.
//!
//! Namespace: the `moduleName` identifier (`unit MyUnit;` → `["MyUnit"]`). Pascal is
//! case-insensitive, but source casing is preserved (consistent with all other extractors).
//!
//! References: call expressions (free and qualified via `exprDot`), `uses` clauses (imports),
//! class parent inheritance (`IsImplementation`), and type references (parameter / field /
//! return-type positions).
//!
//! Emits neutral [`FileFacts`] — no storage entries, no source bodies.

use tree_sitter::{Node, Parser};

use crate::error::{CodegraphError, Result};
use crate::graph::types::{
    Binding, BindingKind, ByteSpan, FileFacts, RefRole, Reference, Scope, ScopeId, ScopeKind,
    Symbol, SymbolKind, TypeRefContext,
};
use crate::lang::Language;
use crate::symbol::{Descriptor, SymbolId};

use super::{
    Extractor, MIN_REF_LEN, attach_reference_scopes, collect_call_references, definition_bindings,
    field_text, import_bindings, innermost_scope, node_span, node_text, one_line_signature,
    push_binding, push_import_ref, push_ref, push_scope, push_type_ref, simple_type_name,
};

/// Tree-sitter query capturing call-callee identifiers.
///
/// Pattern 1: free call `Bar()` — identifier directly as `entity` field.
/// Pattern 2: member call `obj.Method()` — exprDot under `entity` field; lhs captured as
///            `@qualifier`, rhs as `@callee`.
const CALL_QUERY: &str = r#"
[
  (exprCall entity: (identifier) @callee)
  (exprCall entity: (exprDot lhs: (identifier) @qualifier rhs: (identifier) @callee))
]
"#;

/// Extracts Pascal / Delphi symbols and references.
pub struct PascalExtractor;

impl Extractor for PascalExtractor {
    fn lang(&self) -> Language {
        Language::Pascal
    }

    fn extract(&self, source: &str, file: &str) -> Result<FileFacts> {
        let ts_language = crate::grammar::pascal();
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
        let namespaces = pascal_namespaces(&root, bytes, file);

        let defs = collect_symbols(&root, bytes, file, &namespaces);
        let def_bindings = definition_bindings(&defs);
        let mut symbols = defs;
        let mod_sym = super::module_symbol(Language::Pascal, &namespaces, file, source.len());
        let module_id = mod_sym.id.to_scip_string();
        symbols.push(mod_sym);

        let mut references = collect_call_references(
            &root,
            &ts_language,
            CALL_QUERY,
            Language::Pascal,
            bytes,
            file,
        )?;
        collect_inheritance(&root, bytes, file, &mut references);
        collect_imports(&root, bytes, file, &mut references, &module_id);
        collect_type_references(&root, bytes, file, &mut references);

        let scopes = collect_scopes(&root, source.len());
        attach_reference_scopes(&mut references, &scopes);
        let mut bindings = collect_bindings(&root, bytes, &scopes);
        bindings.extend(def_bindings);
        bindings.extend(import_bindings(&references, &scopes));

        Ok(FileFacts {
            file: file.to_owned(),
            lang: Language::Pascal.as_str().to_owned(),
            symbols,
            references,
            scopes,
            bindings,
            ffi_exports: Vec::new(),
        })
    }
}

// ── Namespace derivation ─────────────────────────────────────────────────────

/// Derive namespace descriptors from the `moduleName` identifier at the top of the unit
/// or program. Falls back to a path-derived namespace if no moduleName is found.
///
/// `unit MyUnit;` → `["MyUnit"]`
/// `program Greeter;` → `["Greeter"]`
///
/// NOTE: Pascal is case-insensitive in practice, but we preserve source casing here
/// (consistent with every other extractor). Consumers that need case-folding should
/// normalise at the consumer layer.
fn pascal_namespaces(root: &Node, bytes: &[u8], file: &str) -> Vec<String> {
    // root → unit | program
    for top in root.children(&mut root.walk()) {
        if top.kind() == "unit" || top.kind() == "program" {
            for child in top.children(&mut top.walk()) {
                if child.kind() == "moduleName" {
                    for id in child.children(&mut child.walk()) {
                        if id.kind() == "identifier" {
                            return vec![node_text(&id, bytes).to_owned()];
                        }
                    }
                }
            }
        }
    }

    // Fallback: derive from file path (strip Pascal extensions, strip leading `src/`).
    let p = file
        .strip_suffix(".pas")
        .or_else(|| file.strip_suffix(".dpr"))
        .or_else(|| file.strip_suffix(".dpk"))
        .or_else(|| file.strip_suffix(".lpr"))
        .unwrap_or(file);
    let p = p.strip_prefix("src/").unwrap_or(p);
    p.split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

// ── Symbol collection ────────────────────────────────────────────────────────

fn collect_symbols(root: &Node, bytes: &[u8], file: &str, namespaces: &[String]) -> Vec<Symbol> {
    let ns_descriptors: Vec<Descriptor> = namespaces
        .iter()
        .cloned()
        .map(Descriptor::Namespace)
        .collect();
    let mut out = Vec::new();

    for top in root.children(&mut root.walk()) {
        match top.kind() {
            "unit" => collect_unit(&top, bytes, file, &ns_descriptors, &mut out),
            "program" => collect_program(&top, bytes, file, &ns_descriptors, &mut out),
            _ => {}
        }
    }
    out
}

/// Collect definitions from a `unit` node.
/// Types live in the `interface` section; standalone procs in `implementation`.
fn collect_unit(
    unit: &Node,
    bytes: &[u8],
    file: &str,
    prefix: &[Descriptor],
    out: &mut Vec<Symbol>,
) {
    for child in unit.children(&mut unit.walk()) {
        match child.kind() {
            "interface" => collect_decl_types(&child, bytes, file, prefix, out),
            "implementation" => collect_impl_procs(&child, bytes, file, prefix, out),
            _ => {}
        }
    }
}

/// Collect definitions from a `program` node: standalone top-level `defProc`s.
fn collect_program(
    prog: &Node,
    bytes: &[u8],
    file: &str,
    prefix: &[Descriptor],
    out: &mut Vec<Symbol>,
) {
    collect_impl_procs(prog, bytes, file, prefix, out);
}

/// Walk `node` and emit symbols for every `declType` found (class, record, interface, enum).
fn collect_decl_types(
    node: &Node,
    bytes: &[u8],
    file: &str,
    prefix: &[Descriptor],
    out: &mut Vec<Symbol>,
) {
    for child in node.children(&mut node.walk()) {
        if child.kind() == "declTypes" {
            for decl in child.children(&mut child.walk()) {
                if decl.kind() == "declType" {
                    collect_decl_type(&decl, bytes, file, prefix, out);
                }
            }
        }
    }
}

/// Emit a symbol for a single `declType` and its members.
fn collect_decl_type(
    node: &Node,
    bytes: &[u8],
    file: &str,
    prefix: &[Descriptor],
    out: &mut Vec<Symbol>,
) {
    // The type name is in the `name` field (an identifier).
    let Some(name) = field_text(node, "name", bytes) else {
        return;
    };

    // The type body is in the `type` field.
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };

    // Unwrap a wrapper `type` node if present.
    let inner = unwrap_type_node(&type_node);

    let (kind, members) = classify_decl_type(&inner);

    let mut type_descriptors = prefix.to_vec();
    type_descriptors.push(Descriptor::Type(name.clone()));

    out.push(Symbol {
        id: SymbolId::global(Language::Pascal.as_str(), type_descriptors.clone()),
        name: name.clone(),
        kind,
        file: file.to_owned(),
        line: (node.start_position().row + 1) as u32,
        span: ByteSpan {
            start: node.start_byte(),
            end: node.end_byte(),
        },
        signature: one_line_signature(node_text(node, bytes), &['{', ';']),
    });

    if kind == SymbolKind::Enum {
        collect_enum_values(&inner, bytes, file, &type_descriptors, out);
    } else {
        collect_members(&inner, bytes, file, &type_descriptors, members, out);
    }
}

/// Returns a reference to the inner meaningful node — if `node` is a `type` wrapper,
/// descend one level.
fn unwrap_type_node<'a>(node: &Node<'a>) -> Node<'a> {
    if node.kind() == "type" {
        // The real type node is the first named child.
        if let Some(inner) = node.named_children(&mut node.walk()).next() {
            return inner;
        }
    }
    *node
}

/// Classify a `declClass` or `declIntf` node (or `declEnum` inside a `type` wrapper).
/// Returns `(SymbolKind, true_if_members_should_be_collected)`.
fn classify_decl_type(node: &Node) -> (SymbolKind, bool) {
    match node.kind() {
        "declClass" => {
            // Distinguish class vs record by looking for kRecord keyword child.
            let is_record = node
                .children(&mut node.walk())
                .any(|c| c.kind() == "kRecord");
            if is_record {
                (SymbolKind::Struct, true)
            } else {
                (SymbolKind::Class, true)
            }
        }
        "declIntf" => (SymbolKind::Interface, true),
        "declEnum" => (SymbolKind::Enum, false),
        // Unknown — try to provide something sensible.
        _ => (SymbolKind::Class, false),
    }
}

/// Emit `SymbolKind::Const` for each `declEnumValue` inside an enum body.
fn collect_enum_values(
    enum_node: &Node,
    bytes: &[u8],
    file: &str,
    type_prefix: &[Descriptor],
    out: &mut Vec<Symbol>,
) {
    for child in enum_node.children(&mut enum_node.walk()) {
        if child.kind() == "declEnumValue" {
            if let Some(val_name) = field_text(&child, "name", bytes) {
                let mut descriptors = type_prefix.to_vec();
                descriptors.push(Descriptor::Term(val_name.clone()));
                out.push(Symbol {
                    id: SymbolId::global(Language::Pascal.as_str(), descriptors),
                    name: val_name,
                    kind: SymbolKind::Const,
                    file: file.to_owned(),
                    line: (child.start_position().row + 1) as u32,
                    span: ByteSpan {
                        start: child.start_byte(),
                        end: child.end_byte(),
                    },
                    signature: one_line_signature(node_text(&child, bytes), &['{', ';', ',']),
                });
            }
        }
    }
}

/// Walk a class/record/interface body (`declClass` or `declIntf`) and emit member symbols.
fn collect_members(
    body: &Node,
    bytes: &[u8],
    file: &str,
    type_prefix: &[Descriptor],
    emit: bool,
    out: &mut Vec<Symbol>,
) {
    if !emit {
        return;
    }
    collect_members_in(body, bytes, file, type_prefix, out);
}

fn collect_members_in(
    node: &Node,
    bytes: &[u8],
    file: &str,
    type_prefix: &[Descriptor],
    out: &mut Vec<Symbol>,
) {
    for child in node.children(&mut node.walk()) {
        match child.kind() {
            "declSection" => {
                // Visibility section (kPublic, kPrivate, …); recurse into it.
                collect_members_in(&child, bytes, file, type_prefix, out);
            }
            "declProc" => {
                emit_method(&child, bytes, file, type_prefix, out);
            }
            "declField" => {
                emit_field(&child, bytes, file, type_prefix, out);
            }
            _ => {}
        }
    }
}

/// Emit a `SymbolKind::Method` for a `declProc` that is a member declaration.
fn emit_method(
    node: &Node,
    bytes: &[u8],
    file: &str,
    type_prefix: &[Descriptor],
    out: &mut Vec<Symbol>,
) {
    let Some(name) = field_text(node, "name", bytes) else {
        return;
    };
    // Skip if the name node is a qualified name (genericDot) — that's a body, not a decl.
    // When used as a member declaration, name should be a plain identifier.
    // The field_text helper already returns the text; we check for a dot separator.
    if name.contains('.') {
        return;
    }

    let mut descriptors = type_prefix.to_vec();
    descriptors.push(Descriptor::Method {
        name: name.clone(),
        disambiguator: String::new(),
    });
    out.push(Symbol {
        id: SymbolId::global(Language::Pascal.as_str(), descriptors),
        name,
        kind: SymbolKind::Method,
        file: file.to_owned(),
        line: (node.start_position().row + 1) as u32,
        span: ByteSpan {
            start: node.start_byte(),
            end: node.end_byte(),
        },
        signature: one_line_signature(node_text(node, bytes), &['{', ';']),
    });
}

/// Emit a `SymbolKind::Static` for a `declField`.
fn emit_field(
    node: &Node,
    bytes: &[u8],
    file: &str,
    type_prefix: &[Descriptor],
    out: &mut Vec<Symbol>,
) {
    let Some(name) = field_text(node, "name", bytes) else {
        return;
    };
    let mut descriptors = type_prefix.to_vec();
    descriptors.push(Descriptor::Term(name.clone()));
    out.push(Symbol {
        id: SymbolId::global(Language::Pascal.as_str(), descriptors),
        name,
        kind: SymbolKind::Static,
        file: file.to_owned(),
        line: (node.start_position().row + 1) as u32,
        span: ByteSpan {
            start: node.start_byte(),
            end: node.end_byte(),
        },
        signature: one_line_signature(node_text(node, bytes), &['{', ';']),
    });
}

/// Walk `node` and emit `SymbolKind::Function` for standalone `defProc`s whose header's
/// `declProc` name is a plain `identifier` (not a qualified `genericDot`).
/// Skips method implementations like `procedure TFoo.Run; begin end;`.
fn collect_impl_procs(
    node: &Node,
    bytes: &[u8],
    file: &str,
    prefix: &[Descriptor],
    out: &mut Vec<Symbol>,
) {
    for child in node.children(&mut node.walk()) {
        if child.kind() == "defProc" {
            if let Some(header) = child.child_by_field_name("header") {
                if header.kind() == "declProc" {
                    // The name field of the declProc tells us if it's a method impl.
                    // Method impls have `genericDot` (e.g. `TFoo.Run`); standalone procs
                    // have a plain `identifier`.
                    let name_is_plain_ident = header
                        .child_by_field_name("name")
                        .map(|n| n.kind() == "identifier")
                        .unwrap_or(false);

                    if name_is_plain_ident {
                        if let Some(name) = field_text(&header, "name", bytes) {
                            let mut descriptors = prefix.to_vec();
                            descriptors.push(Descriptor::Method {
                                name: name.clone(),
                                disambiguator: String::new(),
                            });
                            out.push(Symbol {
                                id: SymbolId::global(Language::Pascal.as_str(), descriptors),
                                name,
                                kind: SymbolKind::Function,
                                file: file.to_owned(),
                                line: (child.start_position().row + 1) as u32,
                                span: ByteSpan {
                                    start: child.start_byte(),
                                    end: child.end_byte(),
                                },
                                signature: one_line_signature(node_text(&header, bytes), &[';']),
                            });
                        }
                    }
                }
            }
        }
    }
}

// ── Inheritance ──────────────────────────────────────────────────────────────

/// Walk the tree and emit `IsImplementation` refs for the parent class of a `declClass`.
///
/// In the Pascal AST, a `declClass` has an optional `parent` field (a `typeref` node
/// containing the parent identifier).
fn collect_inheritance(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    if matches!(node.kind(), "declClass" | "declIntf") {
        // The parent class and any implemented interfaces are direct `typeref`
        // children of the class node (the grammar's `parent` field points at the
        // `(` token, not the type). Record fields carry their own typerefs nested
        // under `declField`, so direct typeref children are heritage only.
        for child in node.children(&mut node.walk()) {
            if child.kind() != "typeref" {
                continue;
            }
            for id in child.children(&mut child.walk()) {
                if id.kind() == "identifier" {
                    push_ref(
                        out,
                        node_text(&id, bytes),
                        &id,
                        file,
                        RefRole::IsImplementation,
                    );
                }
            }
        }
    }
    for child in node.children(&mut node.walk()) {
        collect_inheritance(&child, bytes, file, out);
    }
}

// ── Imports (uses clause) ────────────────────────────────────────────────────

/// Walk the tree emitting `Import` refs for every unit name in `declUses` nodes.
///
/// `uses SysUtils, Classes;` → Import refs for `SysUtils` and `Classes`.
/// Each used unit is a flat identifier; `from_path` is the unit name itself (no nesting).
fn collect_imports(
    node: &Node,
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Reference>,
    module_id: &str,
) {
    if node.kind() == "declUses" {
        for child in node.children(&mut node.walk()) {
            if child.kind() == "moduleName" {
                for id in child.children(&mut child.walk()) {
                    if id.kind() == "identifier" {
                        let name = node_text(&id, bytes);
                        // from_path is the unit name itself (flat import, no parent path).
                        push_import_ref(out, name, &id, file, module_id, name);
                    }
                }
            }
        }
        return;
    }
    for child in node.children(&mut node.walk()) {
        collect_imports(&child, bytes, file, out, module_id);
    }
}

// ── TypeRef edges ────────────────────────────────────────────────────────────

/// Walk the tree emitting [`RefRole::TypeRef`] references for type names in typed positions.
///
/// Covers: `declArg` type, `declField` type, `declProc` return `type`.
fn collect_type_references(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    match node.kind() {
        "declArg" => {
            if let Some(ty) = node.child_by_field_name("type") {
                type_leaf(&ty, bytes, file, TypeRefContext::ParameterType, out);
            }
        }
        "declField" => {
            if let Some(ty) = node.child_by_field_name("type") {
                type_leaf(&ty, bytes, file, TypeRefContext::Field, out);
            }
        }
        "declProc" => {
            // Function return type is in the `type` field (only present for functions,
            // not procedures).
            if let Some(ty) = node.child_by_field_name("type") {
                type_leaf(&ty, bytes, file, TypeRefContext::ReturnType, out);
            }
        }
        _ => {}
    }
    for child in node.children(&mut node.walk()) {
        collect_type_references(&child, bytes, file, out);
    }
}

fn type_leaf(node: &Node, bytes: &[u8], file: &str, ctx: TypeRefContext, out: &mut Vec<Reference>) {
    match node.kind() {
        "typeref" => {
            for id in node.children(&mut node.walk()) {
                if id.kind() == "identifier" {
                    let name = node_text(&id, bytes);
                    push_type_ref(out, name, &id, file, ctx);
                }
            }
        }
        "type" => {
            for child in node.named_children(&mut node.walk()) {
                type_leaf(&child, bytes, file, ctx, out);
            }
        }
        "identifier" => {
            let name = node_text(node, bytes);
            push_type_ref(out, name, node, file, ctx);
        }
        _ => {
            let name = simple_type_name(node_text(node, bytes), ".");
            if !name.is_empty() {
                push_type_ref(out, name, node, file, ctx);
            }
        }
    }
}

// ── Scope tree ───────────────────────────────────────────────────────────────

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
    match node.kind() {
        "unit" | "program" => {
            let mod_id = push_scope(scopes, Some(parent_id), node_span(node), ScopeKind::Module);
            for child in node.children(&mut node.walk()) {
                scope_dfs(&child, mod_id, scopes);
            }
        }
        "declClass" | "declIntf" => {
            let type_id = push_scope(scopes, Some(parent_id), node_span(node), ScopeKind::Type);
            for child in node.children(&mut node.walk()) {
                scope_dfs(&child, type_id, scopes);
            }
        }
        "defProc" => {
            let fn_id = push_scope(
                scopes,
                Some(parent_id),
                node_span(node),
                ScopeKind::Function,
            );
            if let Some(body) = node.child_by_field_name("body") {
                for child in body.children(&mut body.walk()) {
                    scope_dfs(&child, fn_id, scopes);
                }
            }
        }
        "block" => {
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

// ── Bindings ─────────────────────────────────────────────────────────────────

fn collect_bindings(root: &Node, bytes: &[u8], scopes: &[Scope]) -> Vec<Binding> {
    let mut out = Vec::new();
    collect_bindings_dfs(root, bytes, scopes, &mut out);
    out
}

fn collect_bindings_dfs(node: &Node, bytes: &[u8], scopes: &[Scope], out: &mut Vec<Binding>) {
    // Collect procedure/function parameters from declArg nodes.
    if node.kind() == "declArg" {
        if let Some(name) = field_text(node, "name", bytes) {
            let intro = node.start_byte();
            if name.len() >= MIN_REF_LEN && innermost_scope(intro, scopes) != Some(0) {
                push_binding(out, name, intro, BindingKind::Param, scopes);
            }
        }
    }
    for child in node.children(&mut node.walk()) {
        collect_bindings_dfs(&child, bytes, scopes, out);
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn extract(src: &str, file: &str) -> FileFacts {
        PascalExtractor.extract(src, file).unwrap()
    }

    fn by_name(facts: &FileFacts, name: &str) -> Option<Symbol> {
        facts.symbols.iter().find(|s| s.name == name).cloned()
    }

    // ── Definitions ──────────────────────────────────────────────────────────

    #[test]
    fn class_and_method_get_correct_scip_strings() {
        let src = r#"
unit MyUnit;
interface
type
  TFoo = class(TObject)
  public
    procedure Run;
  end;
implementation
end.
"#;
        let facts = extract(src, "src/MyUnit.pas");

        let foo = by_name(&facts, "TFoo").unwrap();
        assert_eq!(foo.kind, SymbolKind::Class);
        assert_eq!(foo.id.to_scip_string(), "codegraph . . . MyUnit/TFoo#");

        let run = by_name(&facts, "Run").unwrap();
        assert_eq!(run.kind, SymbolKind::Method);
        assert_eq!(
            run.id.to_scip_string(),
            "codegraph . . . MyUnit/TFoo#Run()."
        );

        assert_eq!(facts.lang, "pascal");
    }

    #[test]
    fn record_with_field_is_extracted() {
        let src = r#"
unit MyUnit;
interface
type
  TPoint = record
    X: Integer;
  end;
implementation
end.
"#;
        let facts = extract(src, "src/MyUnit.pas");

        let tp = by_name(&facts, "TPoint").unwrap();
        assert_eq!(tp.kind, SymbolKind::Struct);
        assert_eq!(tp.id.to_scip_string(), "codegraph . . . MyUnit/TPoint#");

        let x = by_name(&facts, "X").unwrap();
        assert_eq!(x.kind, SymbolKind::Static);
        assert_eq!(x.id.to_scip_string(), "codegraph . . . MyUnit/TPoint#X.");
    }

    #[test]
    fn enum_and_values_are_extracted() {
        let src = r#"
unit MyUnit;
interface
type
  TColor = (Red, Green);
implementation
end.
"#;
        let facts = extract(src, "src/MyUnit.pas");

        let color = by_name(&facts, "TColor").unwrap();
        assert_eq!(color.kind, SymbolKind::Enum);
        assert_eq!(color.id.to_scip_string(), "codegraph . . . MyUnit/TColor#");

        let red = by_name(&facts, "Red").unwrap();
        assert_eq!(red.kind, SymbolKind::Const);
        assert_eq!(
            red.id.to_scip_string(),
            "codegraph . . . MyUnit/TColor#Red."
        );

        let green = by_name(&facts, "Green").unwrap();
        assert_eq!(green.kind, SymbolKind::Const);
        assert_eq!(
            green.id.to_scip_string(),
            "codegraph . . . MyUnit/TColor#Green."
        );
    }

    #[test]
    fn free_call_captured_as_call_ref() {
        let src = r#"
program Greeter;
procedure Greet;
begin
  Bar();
end;
begin
end.
"#;
        let facts = extract(src, "src/Greeter.dpr");

        let bar_ref = facts
            .references
            .iter()
            .find(|r| r.name == "Bar" && r.role == RefRole::Call);
        assert!(bar_ref.is_some(), "expected Call ref for 'Bar'");
    }

    #[test]
    fn qualified_call_captures_qualifier() {
        let src = r#"
program Greeter;
procedure Greet;
begin
  obj.Method();
end;
begin
end.
"#;
        let facts = extract(src, "src/Greeter.dpr");

        let method_ref = facts
            .references
            .iter()
            .find(|r| r.name == "Method" && r.role == RefRole::Call)
            .expect("expected Call ref for 'Method'");
        assert_eq!(
            method_ref.qualifier.as_deref(),
            Some("obj"),
            "expected qualifier 'obj' on Method call ref",
        );
    }

    #[test]
    fn uses_clause_produces_import_refs() {
        let src = r#"
unit MyUnit;
interface
uses SysUtils, Classes;
implementation
end.
"#;
        let facts = extract(src, "src/MyUnit.pas");

        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();

        assert!(
            import_names.contains(&"SysUtils"),
            "expected 'SysUtils' in import refs: {import_names:?}"
        );
        assert!(
            import_names.contains(&"Classes"),
            "expected 'Classes' in import refs: {import_names:?}"
        );
    }

    #[test]
    fn class_parent_produces_is_implementation_ref() {
        let src = r#"
unit MyUnit;
interface
type
  TFoo = class(TObject)
  end;
implementation
end.
"#;
        let facts = extract(src, "src/MyUnit.pas");

        let inherit: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();

        assert!(
            inherit.contains(&"TObject"),
            "expected 'TObject' in IsImplementation refs: {inherit:?}"
        );
    }

    #[test]
    fn standalone_proc_is_function_and_method_impl_is_skipped() {
        let src = r#"
unit MyUnit;
interface
type
  TFoo = class
  public
    procedure Run;
  end;
implementation
procedure Greet;
begin
end;
procedure TFoo.Run;
begin
end;
end.
"#;
        let facts = extract(src, "src/MyUnit.pas");

        // Standalone Greet should appear as Function.
        let greet = by_name(&facts, "Greet").unwrap();
        assert_eq!(greet.kind, SymbolKind::Function);

        // TFoo.Run method impl must NOT produce a second Run symbol.
        let run_count = facts.symbols.iter().filter(|s| s.name == "Run").count();
        assert_eq!(
            run_count, 1,
            "Run should appear exactly once (the declaration, not the impl)"
        );
    }
}
