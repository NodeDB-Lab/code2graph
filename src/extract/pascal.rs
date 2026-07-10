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
    Symbol, SymbolKind, TypeRefContext, Visibility,
};
use crate::lang::Language;
use crate::symbol::Descriptor;

use super::{
    ExtractCtx, Extractor, MIN_REF_LEN, attach_reference_scopes, collect_call_references,
    definition_bindings, field_text, import_bindings, innermost_scope, make_symbol, node_span,
    node_text, one_line_signature, push_binding, push_import_ref, push_ref, push_scope,
    push_type_ref, simple_type_name,
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
        let ctx = ExtractCtx {
            bytes,
            file,
            lang: Language::Pascal,
        };

        let defs = collect_symbols(&root, &ctx, &namespaces);
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
        collect_read_references(&root, bytes, file, &mut references);
        collect_write_references(&root, bytes, file, &mut references);

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

fn collect_symbols(root: &Node, ctx: &ExtractCtx, namespaces: &[String]) -> Vec<Symbol> {
    let ns_descriptors: Vec<Descriptor> = namespaces
        .iter()
        .cloned()
        .map(Descriptor::Namespace)
        .collect();
    let mut out = Vec::new();

    for top in root.children(&mut root.walk()) {
        match top.kind() {
            "unit" => collect_unit(&top, ctx, &ns_descriptors, &mut out),
            "program" => collect_program(&top, ctx, &ns_descriptors, &mut out),
            _ => {}
        }
    }
    out
}

/// Collect definitions from a `unit` node.
/// Types live in the `interface` section; standalone procs in `implementation`.
fn collect_unit(unit: &Node, ctx: &ExtractCtx, prefix: &[Descriptor], out: &mut Vec<Symbol>) {
    for child in unit.children(&mut unit.walk()) {
        match child.kind() {
            "interface" => collect_decl_types(&child, ctx, prefix, out),
            "implementation" => collect_impl_procs(&child, ctx, prefix, out),
            _ => {}
        }
    }
}

/// Collect definitions from a `program` node: standalone top-level `defProc`s.
fn collect_program(prog: &Node, ctx: &ExtractCtx, prefix: &[Descriptor], out: &mut Vec<Symbol>) {
    collect_impl_procs(prog, ctx, prefix, out);
}

/// Walk `node` and emit symbols for every `declType` found (class, record, interface, enum).
fn collect_decl_types(node: &Node, ctx: &ExtractCtx, prefix: &[Descriptor], out: &mut Vec<Symbol>) {
    for child in node.children(&mut node.walk()) {
        if child.kind() == "declTypes" {
            for decl in child.children(&mut child.walk()) {
                if decl.kind() == "declType" {
                    collect_decl_type(&decl, ctx, prefix, out);
                }
            }
        }
    }
}

/// Emit a symbol for a single `declType` and its members.
fn collect_decl_type(node: &Node, ctx: &ExtractCtx, prefix: &[Descriptor], out: &mut Vec<Symbol>) {
    // The type name is in the `name` field (an identifier).
    let Some(name) = field_text(node, "name", ctx.bytes) else {
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

    out.push(make_symbol(
        ctx,
        node,
        name.clone(),
        kind,
        // Unit-level type declarations are in the interface section — always public.
        Visibility::Public,
        type_descriptors.clone(),
        one_line_signature(node_text(node, ctx.bytes), &['{', ';']),
    ));

    if kind == SymbolKind::Enum {
        collect_enum_values(&inner, ctx, &type_descriptors, out);
    } else {
        collect_members(&inner, ctx, &type_descriptors, members, out);
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
    ctx: &ExtractCtx,
    type_prefix: &[Descriptor],
    out: &mut Vec<Symbol>,
) {
    for child in enum_node.children(&mut enum_node.walk()) {
        if child.kind() == "declEnumValue" {
            if let Some(val_name) = field_text(&child, "name", ctx.bytes) {
                let mut descriptors = type_prefix.to_vec();
                descriptors.push(Descriptor::Term(val_name.clone()));
                out.push(make_symbol(
                    ctx,
                    &child,
                    val_name,
                    SymbolKind::Const,
                    // Enum values are part of a unit-level type — always public.
                    Visibility::Public,
                    descriptors,
                    one_line_signature(node_text(&child, ctx.bytes), &['{', ';', ',']),
                ));
            }
        }
    }
}

/// Derive the `Visibility` for a `declSection` node by inspecting its keyword children.
///
/// Grammar: `declSection = optional(kStrict) + (kPublished | kPublic | kProtected | kPrivate)`
///
/// Mapping:
/// - `published` / `public`           → `Visibility::Public`
/// - `protected` / `strict protected` → `Visibility::Protected`
/// - `private`   / `strict private`   → `Visibility::Private`
fn section_visibility(node: &Node) -> Visibility {
    let mut has_strict = false;
    let mut vis_kw: Option<&str> = None;

    for child in node.children(&mut node.walk()) {
        match child.kind() {
            "kStrict" => has_strict = true,
            "kPublished" | "kPublic" => vis_kw = Some("public"),
            "kProtected" => vis_kw = Some("protected"),
            "kPrivate" => vis_kw = Some("private"),
            _ => {}
        }
    }

    match vis_kw {
        Some("public") => Visibility::Public,
        Some("protected") => Visibility::Protected,
        Some("private") => Visibility::Private,
        // `strict` without a recognised keyword is unusual; treat as Private (strictest default).
        None if has_strict => Visibility::Private,
        _ => Visibility::Public, // `published` / bare section → public
    }
}

/// Walk a class/record/interface body (`declClass` or `declIntf`) and emit member symbols.
fn collect_members(
    body: &Node,
    ctx: &ExtractCtx,
    type_prefix: &[Descriptor],
    emit: bool,
    out: &mut Vec<Symbol>,
) {
    if !emit {
        return;
    }
    // Pascal class default (before any section keyword) is `published`, which maps to Public.
    collect_members_in(body, ctx, type_prefix, Visibility::Public, out);
}

fn collect_members_in(
    node: &Node,
    ctx: &ExtractCtx,
    type_prefix: &[Descriptor],
    current_vis: Visibility,
    out: &mut Vec<Symbol>,
) {
    for child in node.children(&mut node.walk()) {
        match child.kind() {
            "declSection" => {
                // Visibility section (kPublic, kPrivate, …); determine its visibility and recurse.
                let vis = section_visibility(&child);
                collect_members_in(&child, ctx, type_prefix, vis, out);
            }
            "declProc" => {
                emit_method(&child, ctx, type_prefix, current_vis, out);
            }
            "declField" => {
                emit_field(&child, ctx, type_prefix, current_vis, out);
            }
            _ => {}
        }
    }
}

/// Emit a `SymbolKind::Method` for a `declProc` that is a member declaration.
fn emit_method(
    node: &Node,
    ctx: &ExtractCtx,
    type_prefix: &[Descriptor],
    vis: Visibility,
    out: &mut Vec<Symbol>,
) {
    let Some(name) = field_text(node, "name", ctx.bytes) else {
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
        disambiguator: crate::symbol::MethodDisambiguator::empty(),
    });
    out.push(make_symbol(
        ctx,
        node,
        name,
        SymbolKind::Method,
        vis,
        descriptors,
        one_line_signature(node_text(node, ctx.bytes), &['{', ';']),
    ));
}

/// Emit a `SymbolKind::Static` for a `declField`.
fn emit_field(
    node: &Node,
    ctx: &ExtractCtx,
    type_prefix: &[Descriptor],
    vis: Visibility,
    out: &mut Vec<Symbol>,
) {
    let Some(name) = field_text(node, "name", ctx.bytes) else {
        return;
    };
    let mut descriptors = type_prefix.to_vec();
    descriptors.push(Descriptor::Term(name.clone()));
    out.push(make_symbol(
        ctx,
        node,
        name,
        SymbolKind::Static,
        vis,
        descriptors,
        one_line_signature(node_text(node, ctx.bytes), &['{', ';']),
    ));
}

/// Walk `node` and emit `SymbolKind::Function` for standalone `defProc`s whose header's
/// `declProc` name is a plain `identifier` (not a qualified `genericDot`).
/// Skips method implementations like `procedure TFoo.Run; begin end;`.
fn collect_impl_procs(node: &Node, ctx: &ExtractCtx, prefix: &[Descriptor], out: &mut Vec<Symbol>) {
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
                        if let Some(name) = field_text(&header, "name", ctx.bytes) {
                            let mut descriptors = prefix.to_vec();
                            descriptors.push(Descriptor::Method {
                                name: name.clone(),
                                disambiguator: crate::symbol::MethodDisambiguator::empty(),
                            });
                            out.push(make_symbol(
                                ctx,
                                &child,
                                name,
                                SymbolKind::Function,
                                // Standalone top-level procedures/functions are public.
                                Visibility::Public,
                                descriptors,
                                one_line_signature(node_text(&header, ctx.bytes), &[';']),
                            ));
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

// ── Read / write references ──────────────────────────────────────────────────

/// Returns `true` when `node` (an `identifier`) sits in a position already
/// captured by another collector — a call entity/callee, a declaration name
/// (procedure, type, var, const, parameter, enum value, label, module),
/// an import binding, an assignment LHS (handled by [`collect_write_references`]),
/// or a member-access leaf (`rhs` of `exprDot`) — and so must NOT also be
/// emitted as a Read reference.
///
/// The base (`lhs`) of `exprDot` (e.g. `Source` in `Source.Field`) is a genuine
/// read and is intentionally NOT excluded — only the leaf (`rhs`) is skipped.
fn is_non_read_position(node: &Node) -> bool {
    let parent = match node.parent() {
        Some(p) => p,
        None => return true, // root — not a read
    };
    match parent.kind() {
        // Call entity/callee — already a Call ref (free or qualified).
        "exprCall" => parent.child_by_field_name("entity").as_ref() == Some(node),
        // Member-access leaf: `Source.Field` — skip the rhs (leaf) only; the
        // lhs (base) is a genuine read and falls through.
        "exprDot" => parent.child_by_field_name("rhs").as_ref() == Some(node),
        // Assignment LHS — handled by collect_write_references.
        "assignment" => parent.child_by_field_name("lhs").as_ref() == Some(node),
        // Inline var-assignment declaration `var x: T := …` — `x` is the
        // binding name inside the varAssignDef wrapper (not a read).
        "varAssignDef" => true,
        // Declaration names — proc/function name is single (leave as-is).
        "declProc" => parent.child_by_field_name("name").as_ref() == Some(node),
        "declType" => parent.child_by_field_name("name").as_ref() == Some(node),
        // Multi-name decl nodes: `var A, B: T;` / `const A, B = …;` /
        // `field A, B: T;` / `procedure Foo(A, B: T)` all allow multiple
        // identifiers in the `name` field. Use `is_field_child` so every
        // name child (not just the first) is recognised as a declaration site.
        "declVar" => is_field_child(&parent, "name", node),
        "declConst" => is_field_child(&parent, "name", node),
        "declField" => is_field_child(&parent, "name", node),
        "declArg" => is_field_child(&parent, "name", node),
        "declEnumValue" => parent.child_by_field_name("name").as_ref() == Some(node),
        "declLabel" => parent.child_by_field_name("name").as_ref() == Some(node),
        // Module/unit/program name in `moduleName` node — already the module symbol.
        "moduleName" => true,
        // `uses` import bindings — already Import refs.
        "declUses" => true,
        // Type-name positions — already captured as TypeRef by collect_type_references.
        // `type_leaf` walks `typeref` children for identifiers, and recurses into `type`
        // named children where an identifier may appear directly. Mirror both paths here
        // so no type name is double-emitted as a Read.
        "typeref" => true,
        "type" => true,
        _ => false,
    }
}

/// True when `node` is one of the children occupying `parent`'s `field` field.
/// Unlike `child_by_field_name`, this matches EVERY child of a `multiple: true`
/// field (e.g. `var A, B: T;` where both `A` and `B` are `name` children of
/// `declVar`).
fn is_field_child(parent: &Node, field: &str, node: &Node) -> bool {
    parent
        .children_by_field_name(field, &mut parent.walk())
        .any(|c| c == *node)
}

/// Recursively walk `node` and emit [`RefRole::Read`] references for bare
/// `identifier` nodes used in value/expression positions. Applies [`MIN_REF_LEN`].
///
/// Skips identifiers that are already captured by other collectors (call callees,
/// declaration names, import binding names, assignment LHS, member-access leaf)
/// via [`is_non_read_position`].
fn collect_read_references(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    if node.kind() == "identifier" {
        let name = node_text(node, bytes);
        if name.len() >= MIN_REF_LEN && !is_non_read_position(node) {
            push_ref(out, name, node, file, RefRole::Read);
        }
        // `identifier` nodes have no meaningful children; return early.
        return;
    }
    for child in node.children(&mut node.walk()) {
        collect_read_references(&child, bytes, file, out);
    }
}

/// Recursively walk `node` and emit [`RefRole::Write`] references for the
/// bare-identifier LHS of Pascal `assignment` statements (`:=`).
///
/// Pascal `:=` produces an `assignment` node with a named `lhs` field (from the
/// grammar's `op.infix` helper). Only bare `identifier` LHS targets are covered —
/// member/subscript LHS (`rec.Field := …`, `arr[i] := …`) are out of scope for
/// v1. `var`/`const` declarations never use `:=` in the Pascal grammar (they use
/// `=` via `defaultValue`), so no parent-exclusion is needed. Applies [`MIN_REF_LEN`].
fn collect_write_references(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    if node.kind() == "assignment" {
        if let Some(lhs) = node.child_by_field_name("lhs") {
            if lhs.kind() == "identifier" {
                let name = node_text(&lhs, bytes);
                if name.len() >= MIN_REF_LEN {
                    push_ref(out, name, &lhs, file, RefRole::Write);
                }
            }
        }
    }
    for child in node.children(&mut node.walk()) {
        collect_write_references(&child, bytes, file, out);
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
    // A declArg's "name" field is multiple: true (e.g. `Alpha, Bravo: Integer`),
    // so we iterate every name-field child to bind all parameters, using each
    // identifier's own start_byte as the intro offset.
    if node.kind() == "declArg" {
        let mut cursor = node.walk();
        for name_node in node.children_by_field_name("name", &mut cursor) {
            let name = node_text(&name_node, bytes).to_owned();
            let intro = name_node.start_byte();
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

    // ── Visibility ───────────────────────────────────────────────────────────

    /// Standalone procedure in the implementation section → `Visibility::Public`.
    #[test]
    fn standalone_proc_visibility_is_public() {
        let src = r#"
unit MyUnit;
interface
implementation
procedure Greet;
begin
end;
end.
"#;
        let facts = extract(src, "src/MyUnit.pas");
        let greet = by_name(&facts, "Greet").unwrap();
        assert_eq!(greet.visibility, Visibility::Public);
    }

    /// Unit-level type declaration → `Visibility::Public`.
    #[test]
    fn top_level_type_visibility_is_public() {
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
        assert_eq!(tp.visibility, Visibility::Public);
    }

    /// Enum value at unit level → `Visibility::Public`.
    #[test]
    fn enum_value_visibility_is_public() {
        let src = r#"
unit MyUnit;
interface
type
  TColor = (Red, Green);
implementation
end.
"#;
        let facts = extract(src, "src/MyUnit.pas");
        let red = by_name(&facts, "Red").unwrap();
        assert_eq!(red.visibility, Visibility::Public);
    }

    /// Class member under `public` section → `Visibility::Public`.
    #[test]
    fn class_member_under_public_section_is_public() {
        let src = r#"
unit MyUnit;
interface
type
  TFoo = class
  public
    procedure Run;
  end;
implementation
end.
"#;
        let facts = extract(src, "src/MyUnit.pas");
        let run = by_name(&facts, "Run").unwrap();
        assert_eq!(run.visibility, Visibility::Public);
    }

    /// Class member under `published` section → `Visibility::Public`.
    #[test]
    fn class_member_under_published_section_is_public() {
        let src = r#"
unit MyUnit;
interface
type
  TFoo = class
  published
    procedure Run;
  end;
implementation
end.
"#;
        let facts = extract(src, "src/MyUnit.pas");
        let run = by_name(&facts, "Run").unwrap();
        assert_eq!(run.visibility, Visibility::Public);
    }

    /// Class member under `protected` section → `Visibility::Protected`.
    #[test]
    fn class_member_under_protected_section_is_protected() {
        let src = r#"
unit MyUnit;
interface
type
  TFoo = class
  protected
    procedure InternalRun;
  end;
implementation
end.
"#;
        let facts = extract(src, "src/MyUnit.pas");
        let m = by_name(&facts, "InternalRun").unwrap();
        assert_eq!(m.visibility, Visibility::Protected);
    }

    /// Class member under `private` section → `Visibility::Private`.
    #[test]
    fn class_member_under_private_section_is_private() {
        let src = r#"
unit MyUnit;
interface
type
  TFoo = class
  private
    FValue: Integer;
  end;
implementation
end.
"#;
        let facts = extract(src, "src/MyUnit.pas");
        let f = by_name(&facts, "FValue").unwrap();
        assert_eq!(f.visibility, Visibility::Private);
    }

    /// Class member under `strict private` section → `Visibility::Private`.
    #[test]
    fn class_member_under_strict_private_section_is_private() {
        let src = r#"
unit MyUnit;
interface
type
  TFoo = class
  strict private
    FSecret: Integer;
  end;
implementation
end.
"#;
        let facts = extract(src, "src/MyUnit.pas");
        let f = by_name(&facts, "FSecret").unwrap();
        assert_eq!(f.visibility, Visibility::Private);
    }

    /// Class member under `strict protected` section → `Visibility::Protected`.
    #[test]
    fn class_member_under_strict_protected_section_is_protected() {
        let src = r#"
unit MyUnit;
interface
type
  TFoo = class
  strict protected
    procedure HalfHidden;
  end;
implementation
end.
"#;
        let facts = extract(src, "src/MyUnit.pas");
        let m = by_name(&facts, "HalfHidden").unwrap();
        assert_eq!(m.visibility, Visibility::Protected);
    }

    /// Class member before any section keyword → Pascal default (published) → `Visibility::Public`.
    #[test]
    fn class_member_before_any_section_keyword_is_public() {
        let src = r#"
unit MyUnit;
interface
type
  TFoo = class
    DefaultField: Integer;
  end;
implementation
end.
"#;
        let facts = extract(src, "src/MyUnit.pas");
        let f = by_name(&facts, "DefaultField").unwrap();
        assert_eq!(f.visibility, Visibility::Public);
    }

    /// Multi-section class: members track their own section independently.
    #[test]
    fn class_members_track_sections_independently() {
        let src = r#"
unit MyUnit;
interface
type
  TFoo = class
  public
    procedure PubMethod;
  private
    FField: Integer;
  protected
    procedure ProMethod;
  end;
implementation
end.
"#;
        let facts = extract(src, "src/MyUnit.pas");

        let pub_m = by_name(&facts, "PubMethod").unwrap();
        assert_eq!(pub_m.visibility, Visibility::Public);

        let priv_f = by_name(&facts, "FField").unwrap();
        assert_eq!(priv_f.visibility, Visibility::Private);

        let pro_m = by_name(&facts, "ProMethod").unwrap();
        assert_eq!(pro_m.visibility, Visibility::Protected);
    }

    // ── Read / write references ──────────────────────────────────────────────

    /// `Total := Total + Bonus;` — LHS emits Write for `Total`, RHS emits
    /// Read for `Total` and Read for `Bonus`.
    #[test]
    fn assignment_emits_write_and_reads() {
        let src = r#"
program Greeter;
procedure Run;
var Total: Integer;
var Bonus: Integer;
begin
  Total := Total + Bonus;
end;
begin
end.
"#;
        let facts = extract(src, "src/Greeter.dpr");

        let writes: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Write)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            writes.iter().any(|n| n.eq_ignore_ascii_case("Total")),
            "expected Write ref for 'Total': {writes:?}"
        );

        let reads: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Read)
            .map(|r| r.name.as_str())
            .collect();
        // RHS `Total` (read) and `Bonus` (read) must both appear.
        assert!(
            reads.iter().any(|n| n.eq_ignore_ascii_case("Total")),
            "expected Read ref for 'Total' on RHS: {reads:?}"
        );
        assert!(
            reads.iter().any(|n| n.eq_ignore_ascii_case("Bonus")),
            "expected Read ref for 'Bonus': {reads:?}"
        );
    }

    /// `var Result: Integer;` is a declaration, NOT an assignment — no Write ref
    /// should be emitted for `Result`.
    #[test]
    fn var_declaration_does_not_emit_write() {
        let src = r#"
program Greeter;
procedure Run;
var Result: Integer;
begin
end;
begin
end.
"#;
        let facts = extract(src, "src/Greeter.dpr");

        let writes: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Write)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            !writes.iter().any(|n| n.eq_ignore_ascii_case("Result")),
            "expected NO Write ref for var declaration 'Result': {writes:?}"
        );
    }

    /// A call argument identifier emits a Read; the callee itself does NOT.
    #[test]
    fn call_argument_is_read_callee_is_not() {
        let src = r#"
program Greeter;
procedure Run;
var Arg: Integer;
begin
  Process(Arg);
end;
begin
end.
"#;
        let facts = extract(src, "src/Greeter.dpr");

        let reads: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Read)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            reads.iter().any(|n| n.eq_ignore_ascii_case("Arg")),
            "expected Read ref for call argument 'Arg': {reads:?}"
        );

        // The callee `Process` is already a Call ref; it must NOT also appear as Read.
        assert!(
            !reads.iter().any(|n| n.eq_ignore_ascii_case("Process")),
            "callee 'Process' must NOT appear as a Read ref: {reads:?}"
        );
    }

    /// `Value := Source.Field;` — base `Source` emits a Read; leaf `Field` does NOT.
    #[test]
    fn field_access_base_is_read_leaf_is_not() {
        let src = r#"
program Greeter;
procedure Run;
var Value: Integer;
begin
  Value := Source.Field;
end;
begin
end.
"#;
        let facts = extract(src, "src/Greeter.dpr");

        let reads: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Read)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            reads.iter().any(|n| n.eq_ignore_ascii_case("Source")),
            "expected Read ref for field-access base 'Source': {reads:?}"
        );
        assert!(
            !reads.iter().any(|n| n.eq_ignore_ascii_case("Field")),
            "field-access leaf 'Field' must NOT appear as a Read ref: {reads:?}"
        );
    }

    /// `var Total: TMyType;` — the type name `TMyType` must NOT be emitted as a Read
    /// (it is already captured as a TypeRef). Value identifiers used in an assignment
    /// (`Source` on the RHS) still must appear as Read.
    #[test]
    fn type_name_in_var_decl_is_not_a_read() {
        let src = r#"
program Greeter;
procedure Run;
var Total: TMyType;
begin
  Total := Source;
end;
begin
end.
"#;
        let facts = extract(src, "src/Greeter.dpr");

        let reads: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Read)
            .map(|r| r.name.as_str())
            .collect();

        // The type name must NOT appear as a Read — it is a TypeRef, not a value read.
        assert!(
            !reads.iter().any(|n| n.eq_ignore_ascii_case("TMyType")),
            "type name 'TMyType' must NOT appear as a Read ref: {reads:?}"
        );

        // A genuine value read on the RHS of an assignment must still be captured.
        assert!(
            reads.iter().any(|n| n.eq_ignore_ascii_case("Source")),
            "expected Read ref for value identifier 'Source': {reads:?}"
        );
    }

    /// `var Total, Bonus: Integer;` — comma-grouped declaration names must NOT
    /// be emitted as Read references. Both `Total` and `Bonus` occupy the `name`
    /// field of the same `declVar` node; the fix uses `is_field_child` so every
    /// `name`-field child is recognised as a declaration site, not just the first.
    #[test]
    fn comma_grouped_var_decl_names_are_not_reads() {
        let src = r#"
program Greeter;
procedure Run;
var Total, Bonus: Integer;
begin
end;
begin
end.
"#;
        let facts = extract(src, "src/Greeter.dpr");

        let reads: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Read)
            .map(|r| r.name.as_str())
            .collect();

        assert!(
            !reads.iter().any(|n| n.eq_ignore_ascii_case("Total")),
            "declaration name 'Total' must NOT appear as a Read ref: {reads:?}"
        );
        assert!(
            !reads.iter().any(|n| n.eq_ignore_ascii_case("Bonus")),
            "declaration name 'Bonus' must NOT appear as a Read ref: {reads:?}"
        );
    }

    /// `procedure Foo(Alpha, Bravo: Integer)` — both comma-grouped parameter names
    /// must each receive a `BindingKind::Param` binding, not just the first.
    #[test]
    fn comma_grouped_params_both_get_param_bindings() {
        let src = r#"
program Greeter;
procedure Foo(Alpha, Bravo: Integer);
begin
end;
begin
end.
"#;
        let facts = extract(src, "src/Greeter.dpr");

        let param_names: Vec<&str> = facts
            .bindings
            .iter()
            .filter(|b| b.kind == BindingKind::Param)
            .map(|b| b.name.as_str())
            .collect();

        assert!(
            param_names.iter().any(|n| n.eq_ignore_ascii_case("Alpha")),
            "expected Param binding for 'Alpha': {param_names:?}"
        );
        assert!(
            param_names.iter().any(|n| n.eq_ignore_ascii_case("Bravo")),
            "expected Param binding for 'Bravo': {param_names:?}"
        );
    }
}
