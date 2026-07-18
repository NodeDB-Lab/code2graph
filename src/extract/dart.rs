// SPDX-License-Identifier: Apache-2.0

//! Dart extractor — one tree-sitter pass yielding definitions and references.
//!
//! Definitions: classes, mixins, enums, extensions, type aliases, top-level
//! functions, top-level variables, and their members (methods, constructors,
//! fields). Identity is file-path-derived (Dart has no explicit namespace
//! declaration in source; convention is library/file-based).
//!
//! References: call expressions (free and member/chained), import directives
//! with `show` combinators or `as` aliases, type references in parameter and
//! return-type positions, and superclass/interface/mixin `IsImplementation` refs.
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
    ExtractCtx, Extractor, MIN_REF_LEN, attach_reference_scopes, child_text,
    collect_call_references, definition_bindings, field_text, import_bindings, innermost_scope,
    make_symbol, mark_self_receiver_calls, node_span, node_text, one_line_signature,
    push_import_ref, push_ref, push_scope, push_type_ref, push_typed_binding, simple_type_name,
};

/// Tree-sitter query capturing call-callee identifiers.
///
/// Pattern 1: free call `foo()` — identifier directly as `function` field.
/// Pattern 2: member call `a.bar()` — member_expression under `function` field;
///            receiver captured as `@qualifier`, method name as `@callee`.
const CALL_QUERY: &str = r#"
[
  (call_expression function: (identifier) @callee)
  (call_expression function: (member_expression object: (_) @qualifier property: (identifier) @callee))
  (call_expression function: (member_expression object: "this" property: (identifier) @callee))
]
"#;

/// Method calls whose receiver is written as the `this` keyword
/// (`this.foo()`).
///
/// Deliberately a *separate* query from [`CALL_QUERY`] rather than an extra
/// alternation branch there, mirroring the Rust extractor's `SELF_CALL_QUERY`:
/// `member_expression object: "this" property: (identifier) …` and the
/// existing `member_expression object: (_) @qualifier property: (identifier)
/// …` branch both structurally match the same `this.foo()` node, and
/// tree-sitter's alternation explores every branch that fits — combining
/// them in one `[ ]` would double-emit the reference. Run as a second pass
/// and correlate back to [`CALL_QUERY`]'s output by the `identifier`'s byte
/// offset (identical node in both queries). `this` is an anonymous token in
/// the Dart grammar (not a named node), so it is matched as the literal
/// `"this"`.
const SELF_CALL_QUERY: &str = r#"
(call_expression function: (member_expression object: "this" property: (identifier) @callee))
"#;

/// Extracts Dart symbols and references.
pub struct DartExtractor;

impl Extractor for DartExtractor {
    fn lang(&self) -> Language {
        Language::Dart
    }

    fn extract(&self, source: &str, file: &str) -> Result<FileFacts> {
        let ts_language = crate::grammar::dart();
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
        let namespaces = dart_namespaces(file);
        let ctx = ExtractCtx {
            bytes,
            file,
            lang: Language::Dart,
        };

        let defs = collect_symbols(&root, &ctx, &namespaces);
        let def_bindings = definition_bindings(&defs);
        let mut symbols = defs;
        let mod_sym = super::module_symbol(Language::Dart, &namespaces, file, source.len());
        let module_id = mod_sym.id.to_scip_string();
        symbols.push(mod_sym);

        let mut references =
            collect_call_references(&root, &ts_language, CALL_QUERY, Language::Dart, bytes, file)?;
        mark_self_receiver_calls(
            &root,
            &ts_language,
            SELF_CALL_QUERY,
            Language::Dart,
            bytes,
            &mut references,
            None,
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
            lang: Language::Dart.as_str().to_owned(),
            symbols,
            references,
            scopes,
            bindings,
            ffi_exports: Vec::new(),
        })
    }
}

// ── Namespace derivation ─────────────────────────────────────────────────────

/// Derive namespace descriptors purely from the file path.
///
/// Dart has no namespace/package declaration in source — identity is
/// file/library-based. We strip `.dart`, strip leading `src/` and `lib/`
/// (Dart's conventional source roots), then split on `/`.
///
/// `lib/models/user.dart` → `["models", "user"]`
/// `src/utils/helper.dart` → `["utils", "helper"]`
fn dart_namespaces(file: &str) -> Vec<String> {
    let p = file.strip_suffix(".dart").unwrap_or(file);
    let p = p
        .strip_prefix("lib/")
        .or_else(|| p.strip_prefix("src/"))
        .unwrap_or(p);
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
    collect_top_level(root, ctx, &ns_descriptors, &mut out);
    out
}

/// Walk the `source_file` node and collect top-level definitions.
fn collect_top_level(node: &Node, ctx: &ExtractCtx, prefix: &[Descriptor], out: &mut Vec<Symbol>) {
    for child in node.children(&mut node.walk()) {
        match child.kind() {
            "class_declaration" => {
                collect_class(&child, ctx, prefix, SymbolKind::Class, out);
            }
            "mixin_declaration" => {
                collect_mixin(&child, ctx, prefix, out);
            }
            "enum_declaration" => {
                collect_enum(&child, ctx, prefix, out);
            }
            "extension_declaration" => {
                collect_extension(&child, ctx, prefix, out);
            }
            "type_alias" => {
                collect_type_alias(&child, ctx, prefix, out);
            }
            "function_declaration" => {
                collect_top_function(&child, ctx, prefix, out);
            }
            "top_level_variable_declaration" => {
                collect_top_level_vars(&child, ctx, prefix, out);
            }
            _ => {}
        }
    }
}

/// Emit a class or extension symbol and recurse into its `class_body` for members.
fn collect_class(
    node: &Node,
    ctx: &ExtractCtx,
    prefix: &[Descriptor],
    kind: SymbolKind,
    out: &mut Vec<Symbol>,
) {
    let Some(name) = field_text(node, "name", ctx.bytes) else {
        return;
    };
    let mut descriptors = prefix.to_vec();
    descriptors.push(Descriptor::Type(name.clone()));
    out.push(make_symbol(
        ctx,
        node,
        name,
        kind,
        Visibility::Unknown,
        descriptors.clone(),
        one_line_signature(node_text(node, ctx.bytes), &['{', ';']),
    ));

    // Recurse into class_body for members.
    if let Some(body) = node.child_by_field_name("body") {
        collect_class_members(&body, ctx, &descriptors, out);
    }
}

/// Emit a mixin declaration and its body members.
///
/// Mixins are trait-like constructs: `mixin Foo on Bar { ... }`.
fn collect_mixin(node: &Node, ctx: &ExtractCtx, prefix: &[Descriptor], out: &mut Vec<Symbol>) {
    let Some(name) = field_text(node, "name", ctx.bytes) else {
        return;
    };
    let mut descriptors = prefix.to_vec();
    descriptors.push(Descriptor::Type(name.clone()));
    out.push(make_symbol(
        ctx,
        node,
        name,
        SymbolKind::Trait,
        Visibility::Unknown,
        descriptors.clone(),
        one_line_signature(node_text(node, ctx.bytes), &['{', ';']),
    ));

    // Recurse into class_body (mixins share the same body shape as classes).
    if let Some(body) = node.child_by_field_name("body") {
        collect_class_members(&body, ctx, &descriptors, out);
    }
}

/// Emit an enum and its constants.
fn collect_enum(node: &Node, ctx: &ExtractCtx, prefix: &[Descriptor], out: &mut Vec<Symbol>) {
    let Some(name) = field_text(node, "name", ctx.bytes) else {
        return;
    };
    let mut descriptors = prefix.to_vec();
    descriptors.push(Descriptor::Type(name.clone()));
    out.push(make_symbol(
        ctx,
        node,
        name,
        SymbolKind::Enum,
        Visibility::Unknown,
        descriptors.clone(),
        one_line_signature(node_text(node, ctx.bytes), &['{', ';']),
    ));

    // Collect enum constants from enum_body.
    if let Some(body) = node.child_by_field_name("body") {
        for member in body.children(&mut body.walk()) {
            if member.kind() == "enum_constant" {
                if let Some(const_name) = field_text(&member, "name", ctx.bytes) {
                    let mut const_desc = descriptors.clone();
                    const_desc.push(Descriptor::Term(const_name.clone()));
                    out.push(make_symbol(
                        ctx,
                        &member,
                        const_name,
                        SymbolKind::Const,
                        Visibility::Unknown,
                        const_desc,
                        one_line_signature(node_text(&member, ctx.bytes), &['{', ';', ',']),
                    ));
                }
            }
        }
    }
}

/// Emit an extension declaration and its body members.
///
/// Extensions extend an existing type: `extension FooExt on Foo { ... }`.
fn collect_extension(node: &Node, ctx: &ExtractCtx, prefix: &[Descriptor], out: &mut Vec<Symbol>) {
    let Some(name) = field_text(node, "name", ctx.bytes) else {
        return;
    };
    let mut descriptors = prefix.to_vec();
    descriptors.push(Descriptor::Type(name.clone()));
    out.push(make_symbol(
        ctx,
        node,
        name,
        SymbolKind::Class,
        Visibility::Unknown,
        descriptors.clone(),
        one_line_signature(node_text(node, ctx.bytes), &['{', ';']),
    ));

    // Recurse into extension_body for members (same shape as class_body).
    if let Some(body) = node.child_by_field_name("body") {
        collect_class_members(&body, ctx, &descriptors, out);
    }
}

/// Emit a type alias: `typedef MyType = SomeOtherType;`
fn collect_type_alias(node: &Node, ctx: &ExtractCtx, prefix: &[Descriptor], out: &mut Vec<Symbol>) {
    // The name is the FIRST type_identifier child (no field name in the grammar).
    let name_node = node
        .children(&mut node.walk())
        .find(|c| c.kind() == "type_identifier");
    let Some(name_node) = name_node else { return };
    let name = node_text(&name_node, ctx.bytes).to_owned();

    let mut descriptors = prefix.to_vec();
    descriptors.push(Descriptor::Type(name.clone()));
    out.push(make_symbol(
        ctx,
        node,
        name,
        SymbolKind::TypeAlias,
        Visibility::Unknown,
        descriptors,
        one_line_signature(node_text(node, ctx.bytes), &['{', ';']),
    ));
}

/// Emit a top-level function: `void foo() { ... }`
///
/// The name lives on the inner `function_signature` child via its `name` field.
fn collect_top_function(
    node: &Node,
    ctx: &ExtractCtx,
    prefix: &[Descriptor],
    out: &mut Vec<Symbol>,
) {
    // function_declaration has a `signature` field → function_signature with `name`.
    let name_opt = node
        .child_by_field_name("signature")
        .and_then(|sig| sig.child_by_field_name("name"))
        .map(|n| node_text(&n, ctx.bytes).to_owned());
    let Some(name) = name_opt else { return };

    let mut descriptors = prefix.to_vec();
    descriptors.push(Descriptor::Method {
        name: name.clone(),
        disambiguator: crate::symbol::MethodDisambiguator::empty(),
    });
    out.push(make_symbol(
        ctx,
        node,
        name,
        SymbolKind::Function,
        Visibility::Unknown,
        descriptors,
        one_line_signature(node_text(node, ctx.bytes), &['{', ';', '=']),
    ));
}

/// Emit top-level variable declarations.
///
/// Grammar: `top_level_variable_declaration → type? initialized_identifier_list`
/// where `initialized_identifier_list → initialized_identifier* `,` ...`
/// Each `initialized_identifier` has a `name` field (identifier).
fn collect_top_level_vars(
    node: &Node,
    ctx: &ExtractCtx,
    prefix: &[Descriptor],
    out: &mut Vec<Symbol>,
) {
    for child in node.children(&mut node.walk()) {
        if child.kind() == "initialized_identifier_list" {
            emit_initialized_identifiers(&child, node, ctx, prefix, out);
        }
    }
}

/// Emit one `Symbol` per `initialized_identifier` found inside an
/// `initialized_identifier_list`.
fn emit_initialized_identifiers(
    list_node: &Node,
    decl_node: &Node,
    ctx: &ExtractCtx,
    prefix: &[Descriptor],
    out: &mut Vec<Symbol>,
) {
    for item in list_node.children(&mut list_node.walk()) {
        if item.kind() == "initialized_identifier" {
            if let Some(name) = field_text(&item, "name", ctx.bytes) {
                let mut descriptors = prefix.to_vec();
                descriptors.push(Descriptor::Term(name.clone()));
                out.push(make_symbol(
                    ctx,
                    decl_node,
                    name,
                    SymbolKind::Static,
                    Visibility::Unknown,
                    descriptors,
                    one_line_signature(node_text(decl_node, ctx.bytes), &['{', ';']),
                ));
            }
        }
    }
}

/// Walk a `class_body` or `extension_body` and emit member symbols.
fn collect_class_members(
    body: &Node,
    ctx: &ExtractCtx,
    type_prefix: &[Descriptor],
    out: &mut Vec<Symbol>,
) {
    for wrapper in body.children(&mut body.walk()) {
        if wrapper.kind() != "class_member" {
            continue;
        }
        // Each class_member wraps exactly one inner node.
        for member in wrapper.children(&mut wrapper.walk()) {
            match member.kind() {
                "method_declaration" => {
                    // method_declaration → signature: method_signature → function_signature → name
                    let name_opt = member
                        .child_by_field_name("signature")
                        .and_then(|ms| {
                            // method_signature may itself contain a function_signature
                            ms.children(&mut ms.walk())
                                .find(|c| c.kind() == "function_signature")
                        })
                        .and_then(|fs| fs.child_by_field_name("name"))
                        .map(|n| node_text(&n, ctx.bytes).to_owned())
                        // Fallback: getter_signature has its name directly
                        .or_else(|| {
                            member
                                .child_by_field_name("signature")
                                .and_then(|ms| ms.child_by_field_name("name"))
                                .map(|n| node_text(&n, ctx.bytes).to_owned())
                        });
                    if let Some(name) = name_opt {
                        emit_method(name, &member, ctx, type_prefix, out);
                    }
                }
                "declaration" => {
                    // Could be a constructor or a field.
                    // constructor_signature: has a `name` field (identifier, possibly "ClassName.named").
                    // field: has initialized_identifier_list.
                    let has_constructor = member
                        .children(&mut member.walk())
                        .any(|c| c.kind() == "constructor_signature");

                    if has_constructor {
                        // Find constructor_signature → name
                        for child in member.children(&mut member.walk()) {
                            if child.kind() == "constructor_signature" {
                                if let Some(name) = field_text(&child, "name", ctx.bytes) {
                                    emit_method(name, &child, ctx, type_prefix, out);
                                }
                            }
                        }
                    } else {
                        // Field declaration: find initialized_identifier_list
                        for child in member.children(&mut member.walk()) {
                            if child.kind() == "initialized_identifier_list" {
                                emit_initialized_identifiers(
                                    &child,
                                    &member,
                                    ctx,
                                    type_prefix,
                                    out,
                                );
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

/// Emit a method/constructor symbol with `Descriptor::Method`.
fn emit_method(
    name: String,
    node: &Node,
    ctx: &ExtractCtx,
    prefix: &[Descriptor],
    out: &mut Vec<Symbol>,
) {
    let mut descriptors = prefix.to_vec();
    descriptors.push(Descriptor::Method {
        name: name.clone(),
        disambiguator: crate::symbol::MethodDisambiguator::empty(),
    });
    out.push(make_symbol(
        ctx,
        node,
        name,
        SymbolKind::Method,
        Visibility::Unknown,
        descriptors,
        one_line_signature(node_text(node, ctx.bytes), &['{', ';', '=']),
    ));
}

// ── Inheritance ──────────────────────────────────────────────────────────────

/// Walk the tree and emit `IsImplementation` references for superclass and
/// interface type references.
///
/// Covers:
/// - `class_declaration` → `superclass` field → `type` → `type_identifier`
/// - `class_declaration` / `mixin_declaration` → `interfaces` field → `type` nodes
/// - `mixin_declaration` → `on` type constraint (child `type` node)
fn collect_inheritance(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    match node.kind() {
        "class_declaration" => {
            // superclass field
            if let Some(superclass) = node.child_by_field_name("superclass") {
                emit_type_identifier_refs(&superclass, bytes, file, RefRole::IsImplementation, out);
            }
            // interfaces field
            if let Some(interfaces) = node.child_by_field_name("interfaces") {
                emit_type_identifier_refs(&interfaces, bytes, file, RefRole::IsImplementation, out);
            }
        }
        "mixin_declaration" => {
            // `on` constraint: the `type` child (not a named field — it's a positional child
            // after `on` keyword); walk children for type nodes.
            let mut saw_on = false;
            for child in node.children(&mut node.walk()) {
                match child.kind() {
                    "on" => saw_on = true,
                    "type" if saw_on => {
                        emit_type_identifier_refs(
                            &child,
                            bytes,
                            file,
                            RefRole::IsImplementation,
                            out,
                        );
                    }
                    "class_body" => break,
                    _ => {}
                }
            }
            // interfaces field
            if let Some(interfaces) = node.child_by_field_name("interfaces") {
                emit_type_identifier_refs(&interfaces, bytes, file, RefRole::IsImplementation, out);
            }
        }
        _ => {}
    }
    for child in node.children(&mut node.walk()) {
        collect_inheritance(&child, bytes, file, out);
    }
}

/// Walk `node` and emit `IsImplementation` refs for every `type_identifier` found.
fn emit_type_identifier_refs(
    node: &Node,
    bytes: &[u8],
    file: &str,
    role: RefRole,
    out: &mut Vec<Reference>,
) {
    if node.kind() == "type_identifier" {
        push_ref(out, node_text(node, bytes), node, file, role);
        return;
    }
    for child in node.children(&mut node.walk()) {
        emit_type_identifier_refs(&child, bytes, file, role, out);
    }
}

// ── Imports ──────────────────────────────────────────────────────────────────

/// Walk the tree emitting `Import` references for `library_import` nodes.
///
/// Dart import syntax:
/// ```dart
/// import 'package:a/b.dart';                 // bare — skip (no specific name)
/// import 'package:a/b.dart' as alias;        // alias form → emit alias name
/// import 'package:a/b.dart' show Foo, Bar;   // show combinator → emit Foo, Bar
/// import 'package:a/b.dart' hide Foo;        // hide combinator → skip
/// ```
///
/// The `from_path` is the URI string (quotes stripped).
fn collect_imports(
    node: &Node,
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Reference>,
    module_id: &str,
) {
    if node.kind() == "import_or_export" {
        collect_import_or_export(node, bytes, file, out, module_id);
        return;
    }
    for child in node.children(&mut node.walk()) {
        collect_imports(&child, bytes, file, out, module_id);
    }
}

fn collect_import_or_export(
    node: &Node,
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Reference>,
    module_id: &str,
) {
    // Find the library_import child.
    for child in node.children(&mut node.walk()) {
        if child.kind() == "library_import" {
            collect_library_import(&child, bytes, file, out, module_id);
        }
    }
}

fn collect_library_import(
    node: &Node,
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Reference>,
    module_id: &str,
) {
    // Find import_specification.
    for child in node.children(&mut node.walk()) {
        if child.kind() == "import_specification" {
            collect_import_specification(&child, bytes, file, out, module_id);
        }
    }
}

fn collect_import_specification(
    node: &Node,
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Reference>,
    module_id: &str,
) {
    // Get URI from the `uri` field → configurable_uri → uri → string_literal.
    let uri_text = extract_uri_text(node, bytes);
    let Some(from_path) = uri_text else { return };

    // Collect combinators and alias.
    let mut show_names: Vec<(String, Node)> = Vec::new();
    let mut alias_node: Option<Node> = None;
    let mut has_show = false;

    for child in node.children(&mut node.walk()) {
        match child.kind() {
            "combinator" => {
                // combinator: `show Foo, Bar` or `hide Foo`
                // First keyword child: `show` or `hide`
                let keyword = child
                    .children(&mut child.walk())
                    .find(|c| matches!(c.kind(), "show" | "hide"))
                    .map(|c| c.kind());
                if keyword == Some("show") {
                    has_show = true;
                    for id in child.children(&mut child.walk()) {
                        if id.kind() == "identifier" {
                            let name = node_text(&id, bytes).to_owned();
                            show_names.push((name, id));
                        }
                    }
                }
                // hide → skip (we don't reference those names)
            }
            "identifier" => {
                // The `as alias` identifier — appears as a direct child
                // after the `as` keyword.
                alias_node = Some(child);
            }
            _ => {}
        }
    }

    if has_show {
        for (name, id_node) in &show_names {
            push_import_ref(out, name, id_node, file, module_id, &from_path);
        }
    } else if let Some(alias) = alias_node {
        let name = node_text(&alias, bytes);
        push_import_ref(out, name, &alias, file, module_id, &from_path);
    }
    // Bare import with no alias/show → nothing specific to reference.
}

/// Extract the URI string content (quotes stripped) from an `import_specification`.
fn extract_uri_text(node: &Node, bytes: &[u8]) -> Option<String> {
    // Walk: import_specification → uri field → configurable_uri → uri → string_literal
    let uri_field = node.child_by_field_name("uri")?;
    // uri_field might be configurable_uri or uri directly — walk down to string_literal.
    let raw = find_string_literal(&uri_field, bytes)?;
    // Strip surrounding quotes (single or double).
    let stripped = raw
        .strip_prefix('\'')
        .and_then(|s| s.strip_suffix('\''))
        .or_else(|| raw.strip_prefix('"').and_then(|s| s.strip_suffix('"')))
        .unwrap_or(raw);
    Some(stripped.to_owned())
}

fn find_string_literal<'a>(node: &Node, bytes: &'a [u8]) -> Option<&'a str> {
    if node.kind() == "string_literal" {
        return Some(node_text(node, bytes));
    }
    for child in node.children(&mut node.walk()) {
        if let Some(s) = find_string_literal(&child, bytes) {
            return Some(s);
        }
    }
    None
}

// ── TypeRef edges ────────────────────────────────────────────────────────────

/// Recursively walk `node` emitting [`RefRole::TypeRef`] references for
/// user-defined type names in typed positions.
fn collect_type_references(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    match node.kind() {
        "function_declaration" => {
            // return type lives on the function_signature under `signature`
            if let Some(sig) = node.child_by_field_name("signature") {
                if let Some(ret) = sig.child_by_field_name("return_type") {
                    type_leaf(&ret, bytes, file, TypeRefContext::ReturnType, out);
                }
            }
        }
        "method_declaration" => {
            if let Some(sig) = node.child_by_field_name("signature") {
                // method_signature wraps function_signature
                let fs = sig
                    .children(&mut sig.walk())
                    .find(|c| c.kind() == "function_signature");
                if let Some(fs) = fs {
                    if let Some(ret) = fs.child_by_field_name("return_type") {
                        type_leaf(&ret, bytes, file, TypeRefContext::ReturnType, out);
                    }
                }
            }
        }
        "formal_parameter" => {
            // type child (not a named field — walk children for `type` node).
            for child in node.children(&mut node.walk()) {
                if child.kind() == "type" {
                    type_leaf(&child, bytes, file, TypeRefContext::ParameterType, out);
                    break;
                }
            }
        }
        "top_level_variable_declaration" | "declaration" => {
            // type child for field/variable declarations
            for child in node.children(&mut node.walk()) {
                if child.kind() == "type" {
                    type_leaf(&child, bytes, file, TypeRefContext::Field, out);
                    break;
                }
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
        // Built-in/void types — skip.
        "void_type" => {}
        "type_identifier" => {
            let name = node_text(node, bytes);
            // Skip common primitives.
            if !matches!(
                name,
                "int" | "double" | "num" | "bool" | "String" | "Object" | "dynamic" | "Never"
            ) {
                push_type_ref(out, name, node, file, ctx);
            }
        }
        "type" => {
            // Recurse into the inner type.
            for child in node.named_children(&mut node.walk()) {
                type_leaf(&child, bytes, file, ctx, out);
            }
        }
        _ => {
            // Qualified or generic types — take the simple leaf name.
            let name = simple_type_name(node_text(node, bytes), ".");
            if !name.is_empty() {
                push_type_ref(out, name, node, file, ctx);
            }
        }
    }
}

// ── Read / Write references ──────────────────────────────────────────────────

/// Returns `true` when `node` (an `identifier`) is the sole bare-identifier
/// target of an `assignment_expression`'s `left` field via an
/// `assignable_expression` wrapper.
///
/// Concretely, the AST shape for `total = …` is:
/// ```text
/// (assignment_expression
///   left: (assignable_expression (identifier))   ← bare target
///   right: …)
/// ```
/// A member/index target such as `obj.prop = …` produces an
/// `assignable_expression` with MORE than one identifier child (or extra
/// selector children), so it does NOT match and is excluded from both Write
/// emission and Read exclusion — leaving `obj` as a genuine Read.
///
/// The test applied: `node.parent()` is `assignable_expression`, that parent
/// has exactly ONE direct `identifier` child (and it is `node`), and the
/// grandparent is `assignment_expression` with the `assignable_expression` as
/// its `left` field.
fn is_bare_assignable_target(node: &Node) -> bool {
    let Some(assignable) = node.parent() else {
        return false;
    };
    if assignable.kind() != "assignable_expression" {
        return false;
    }
    // The grandparent must be assignment_expression with assignable as `left`.
    let Some(assignment) = assignable.parent() else {
        return false;
    };
    if assignment.kind() != "assignment_expression" {
        return false;
    }
    if assignment.child_by_field_name("left").as_ref() != Some(&assignable) {
        return false;
    }
    // Count direct `identifier` children of the assignable_expression.
    // A bare target has exactly one; a member/index target has more.
    let id_count = assignable
        .children(&mut assignable.walk())
        .filter(|c| c.kind() == "identifier")
        .count();
    id_count == 1
}

/// Returns `true` when `node` (an `identifier`) is in a position already
/// captured by another collector and must NOT also be emitted as a Read ref.
///
/// Excluded positions:
/// - Call callee: `function` field of `call_expression`.
/// - Function/getter/setter declaration names: `name` field of
///   `function_signature`, `getter_signature`, `setter_signature`,
///   `constructor_signature`.
/// - Class / mixin / enum / extension declaration names: `name` field of the
///   respective declaration node.
/// - Typed identifier binding names (e.g. `int x`): `name` field of
///   `typed_identifier`.
/// - Variable binding names: `name` field of `initialized_identifier`
///   (local and field variable declarations with `var`/`final`/untyped).
/// - Import binding names: `import_specification` (alias identifier) or
///   `combinator` (show combinator — already Import refs).
/// - Assignment LHS bare target: sole `identifier` inside the
///   `assignable_expression` that is the `left` field of
///   `assignment_expression` — handled by `collect_write_references`.
///   Member/index targets (e.g. `obj` in `obj.prop = x`) are NOT excluded
///   and remain Reads.
/// - Member-access property (the leaf after `.`): `property` field of
///   `member_expression`, `null_aware_member_expression`, and cascade
///   variants — skip the property identifier; the object base is a genuine read.
/// - Type-annotation positions: Dart uses `type_identifier` (not `identifier`)
///   for type names, so those are implicitly excluded by only walking `identifier`.
fn is_non_read_position(node: &Node) -> bool {
    let parent = match node.parent() {
        Some(p) => p,
        None => return true, // root — not a read
    };
    match parent.kind() {
        // Call callee: `function:` field of call_expression.
        "call_expression" => parent.child_by_field_name("function").as_ref() == Some(node),
        // Function/getter/setter signature name — the identifier is the `name`
        // field directly on the *_signature node (not on function_declaration,
        // which wraps via a `signature` field instead).
        "function_signature" | "getter_signature" | "setter_signature" => {
            parent.child_by_field_name("name").as_ref() == Some(node)
        }
        // Constructor name field on constructor_signature.
        "constructor_signature" => parent.child_by_field_name("name").as_ref() == Some(node),
        // Class / mixin / enum / extension declaration names.
        "class_declaration"
        | "mixin_declaration"
        | "enum_declaration"
        | "extension_declaration"
        | "extension_type_declaration" => parent.child_by_field_name("name").as_ref() == Some(node),
        // Typed identifier (e.g. `int x` in a declaration or parameter) — the
        // `name` field is the bound identifier.
        "typed_identifier" => parent.child_by_field_name("name").as_ref() == Some(node),
        // Variable binding names in initialized_identifier (local + field vars).
        "initialized_identifier" => parent.child_by_field_name("name").as_ref() == Some(node),
        // Import alias identifier — direct child of import_specification.
        // Show-combinator identifier — direct child of combinator.
        "import_specification" | "combinator" => true,
        // Bare assignment LHS target (sole identifier inside assignable_expression
        // that is the left field of assignment_expression) — handled by
        // collect_write_references. Member/index assignable targets are NOT
        // excluded here: `obj` in `obj.prop = x` is a genuine Read.
        "assignable_expression" => is_bare_assignable_target(node),
        // Member-access property leaf (`obj.prop` — skip `prop`, keep `obj`).
        "member_expression"
        | "null_aware_member_expression"
        | "cascade_member_expression"
        | "cascade_null_aware_member_expression" => {
            parent.child_by_field_name("property").as_ref() == Some(node)
        }
        _ => false,
    }
}

/// Recursively walk `node` and emit [`RefRole::Read`] references for bare
/// `identifier` nodes used in value/expression positions.
///
/// Skips identifiers already captured by other collectors:
/// call callees, declaration names, variable binding names, parameter names,
/// import binding names, assignment LHS, member-access property leaves.
/// Applies [`MIN_REF_LEN`].
fn collect_read_references(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    if node.kind() == "identifier" {
        let name = node_text(node, bytes);
        if name.len() >= MIN_REF_LEN && !is_non_read_position(node) {
            push_ref(out, name, node, file, RefRole::Read);
        }
        // identifiers have no meaningful sub-identifier children; return early.
        return;
    }
    for child in node.children(&mut node.walk()) {
        collect_read_references(&child, bytes, file, out);
    }
}

/// Recursively walk `node` and emit [`RefRole::Write`] references for the
/// bare-identifier LHS of `assignment_expression` nodes
/// (e.g. `x = 5`, `x += 1`, `x ??= value`).
///
/// All compound/simple assignments share the `assignment_expression` node kind
/// in tree-sitter-dart (the operator variant is tracked in the `operator` field,
/// not a separate node kind).
///
/// The actual AST structure wraps the target in an `assignable_expression`:
/// ```text
/// (assignment_expression
///   left: (assignable_expression (identifier))
///   right: …)
/// ```
/// A Write is emitted only for a bare target — i.e. when the
/// `assignable_expression` holds exactly one `identifier` child (no
/// member/index selectors). Member/index
/// LHS (`obj.prop = …`, `arr[i] = …`) are not covered in v1. As a defensive
/// fallback the direct `left == identifier` case (grammar may vary) is also
/// handled. Applies [`MIN_REF_LEN`].
fn collect_write_references(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    if node.kind() == "assignment_expression" {
        if let Some(lhs) = node.child_by_field_name("left") {
            match lhs.kind() {
                // Actual Dart AST: left field is assignable_expression wrapping
                // a bare identifier.
                "assignable_expression" => {
                    // Collect all direct identifier children in one walk.
                    // Exactly one → bare target (Write); more than one → member/index
                    // target (not a v1 Write). Context already guarantees lhs is the
                    // `left` field of `assignment_expression`, so the grandparent
                    // checks inside `is_bare_assignable_target` are redundant here.
                    let id_children: Vec<_> = lhs
                        .children(&mut lhs.walk())
                        .filter(|c| c.kind() == "identifier")
                        .collect();
                    if let [id_node] = id_children.as_slice() {
                        let name = node_text(id_node, bytes);
                        if name.len() >= MIN_REF_LEN {
                            push_ref(out, name, id_node, file, RefRole::Write);
                        }
                    }
                }
                // Defensive fallback: direct identifier as left field.
                "identifier" => {
                    let name = node_text(&lhs, bytes);
                    if name.len() >= MIN_REF_LEN {
                        push_ref(out, name, &lhs, file, RefRole::Write);
                    }
                }
                _ => {}
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
        "class_declaration"
        | "mixin_declaration"
        | "enum_declaration"
        | "extension_declaration" => {
            let type_id = push_scope(scopes, Some(parent_id), node_span(node), ScopeKind::Type);
            if let Some(body) = node.child_by_field_name("body") {
                for child in body.children(&mut body.walk()) {
                    scope_dfs(&child, type_id, scopes);
                }
            }
        }
        "function_declaration" | "method_declaration" => {
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
    match node.kind() {
        "function_declaration" | "method_declaration" => {
            // Collect formal parameters.
            // The parameters live on the function_signature child under `parameters` field.
            let sig = node.child_by_field_name("signature");
            let fs = sig.as_ref().and_then(|s| {
                s.children(&mut s.walk())
                    .find(|c| c.kind() == "function_signature")
            });
            let params_node = fs
                .as_ref()
                .and_then(|f| f.child_by_field_name("parameters"))
                .or_else(|| {
                    sig.as_ref()
                        .and_then(|s| s.child_by_field_name("parameters"))
                });
            if let Some(params) = params_node {
                collect_params(&params, bytes, scopes, out);
            }
        }
        "local_variable_declaration" => {
            // local_variable_declaration → initialized_variable_definition, which
            // carries the primary declared identifier as its `name` field (plus an
            // optional `type` child shared by every comma-separated identifier),
            // and any further identifiers as sibling `initialized_identifier`
            // children (each with its own `name`/`value` fields, no `type`).
            for child in node.children(&mut node.walk()) {
                if child.kind() == "initialized_variable_definition" {
                    // Declared type is a plain `type` child (not a named field),
                    // shared by every comma-separated identifier in this
                    // definition. Dart has no `new` keyword requirement (since
                    // Dart 2), so a bare call `Foo()` is syntactically identical
                    // to a function call `foo()` — there is no reliable
                    // constructor-call marker to infer a type from, unlike
                    // Rust's struct literal or C#'s `new`. So an untyped local
                    // (`var x = Foo()`) always yields `None` here — never guessed.
                    let type_name = child_text(&child, "type", bytes)
                        .map(|t| simple_type_name(&t, ".").to_owned());
                    if let Some(name) = field_text(&child, "name", bytes) {
                        let intro = child
                            .child_by_field_name("name")
                            .map(|n| n.start_byte())
                            .unwrap_or_else(|| child.start_byte());
                        if name.len() >= MIN_REF_LEN && innermost_scope(intro, scopes) != Some(0) {
                            push_typed_binding(
                                out,
                                name,
                                intro,
                                BindingKind::Local,
                                scopes,
                                type_name.clone(),
                            );
                        }
                    }
                    for item in child
                        .named_children(&mut child.walk())
                        .filter(|c| c.kind() == "initialized_identifier")
                    {
                        if let Some(name) = field_text(&item, "name", bytes) {
                            let intro = item
                                .child_by_field_name("name")
                                .map(|n| n.start_byte())
                                .unwrap_or_else(|| item.start_byte());
                            if name.len() >= MIN_REF_LEN
                                && innermost_scope(intro, scopes) != Some(0)
                            {
                                push_typed_binding(
                                    out,
                                    name,
                                    intro,
                                    BindingKind::Local,
                                    scopes,
                                    type_name.clone(),
                                );
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
    for child in node.children(&mut node.walk()) {
        collect_bindings_dfs(&child, bytes, scopes, out);
    }
}

fn collect_params(params: &Node, bytes: &[u8], scopes: &[Scope], out: &mut Vec<Binding>) {
    for child in params.named_children(&mut params.walk()) {
        // formal_parameter has a `name` field (identifier).
        if child.kind() == "formal_parameter" {
            if let Some(name) = field_text(&child, "name", bytes) {
                let intro = child.start_byte();
                // Declared type is a plain `type` child (not a named field).
                let type_name =
                    child_text(&child, "type", bytes).map(|t| simple_type_name(&t, ".").to_owned());
                push_typed_binding(out, name, intro, BindingKind::Param, scopes, type_name);
            }
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn extract(src: &str, file: &str) -> FileFacts {
        DartExtractor.extract(src, file).unwrap()
    }

    fn by_name(facts: &FileFacts, name: &str) -> Option<Symbol> {
        facts.symbols.iter().find(|s| s.name == name).cloned()
    }

    // ── Definitions ──────────────────────────────────────────────────────────

    #[test]
    fn class_and_method_get_correct_scip_strings() {
        // File `lib/models/user.dart` → namespace = ["models", "user"]
        let src = r#"
class User {
  String getName() { return ''; }
}
"#;
        let facts = extract(src, "lib/models/user.dart");

        let user = by_name(&facts, "User").unwrap();
        assert_eq!(user.kind, SymbolKind::Class);
        assert_eq!(
            user.id.to_scip_string(),
            "codegraph . . . models/user/User#"
        );

        let get_name = by_name(&facts, "getName").unwrap();
        assert_eq!(get_name.kind, SymbolKind::Method);
        assert_eq!(
            get_name.id.to_scip_string(),
            "codegraph . . . models/user/User#getName()."
        );

        assert_eq!(facts.lang, "dart");
    }

    #[test]
    fn top_level_function_is_extracted() {
        let src = r#"
void greet(String name) {
  print(name);
}
"#;
        let facts = extract(src, "lib/utils/greeter.dart");
        let greet = by_name(&facts, "greet").unwrap();
        assert_eq!(greet.kind, SymbolKind::Function);
        assert_eq!(
            greet.id.to_scip_string(),
            "codegraph . . . utils/greeter/greet()."
        );
    }

    #[test]
    fn mixin_is_extracted_as_trait() {
        let src = r#"
mixin Flyable on Animal {
  void fly() {}
}
"#;
        let facts = extract(src, "lib/mixins/flyable.dart");
        let mixin = by_name(&facts, "Flyable").unwrap();
        assert_eq!(mixin.kind, SymbolKind::Trait);
        assert_eq!(
            mixin.id.to_scip_string(),
            "codegraph . . . mixins/flyable/Flyable#"
        );
    }

    #[test]
    fn enum_and_constants_are_extracted() {
        let src = r#"
enum Color { red, green, blue }
"#;
        let facts = extract(src, "lib/models/color.dart");

        let color = by_name(&facts, "Color").unwrap();
        assert_eq!(color.kind, SymbolKind::Enum);
        assert_eq!(
            color.id.to_scip_string(),
            "codegraph . . . models/color/Color#"
        );

        let red = by_name(&facts, "red").unwrap();
        assert_eq!(red.kind, SymbolKind::Const);
        assert_eq!(
            red.id.to_scip_string(),
            "codegraph . . . models/color/Color#red."
        );
    }

    #[test]
    fn type_alias_is_extracted() {
        let src = r#"
typedef Callback = void Function(String);
"#;
        let facts = extract(src, "lib/types/aliases.dart");
        let alias = by_name(&facts, "Callback").unwrap();
        assert_eq!(alias.kind, SymbolKind::TypeAlias);
    }

    #[test]
    fn top_level_variable_is_extracted_as_static() {
        let src = r#"
String appName = 'MyApp';
"#;
        let facts = extract(src, "lib/config/constants.dart");
        let var_sym = by_name(&facts, "appName").unwrap();
        assert_eq!(var_sym.kind, SymbolKind::Static);
    }

    // ── References ───────────────────────────────────────────────────────────

    #[test]
    fn qualified_call_captures_qualifier() {
        let src = r#"
class Client {
  void run() {
    var svc = Service();
    svc.process();
  }
}
"#;
        let facts = extract(src, "lib/client.dart");

        let process = facts
            .references
            .iter()
            .find(|r| r.name == "process")
            .expect("expected Call ref for 'process'");
        assert_eq!(process.role, RefRole::Call);
        assert_eq!(
            process.qualifier.as_deref(),
            Some("svc"),
            "expected qualifier 'svc' on the process call ref",
        );
    }

    #[test]
    fn this_receiver_call_marks_self_receiver() {
        let src = r#"
class C {
  void foo() {}
  void run() { this.foo(); }
}
"#;
        let facts = extract(src, "lib/c.dart");
        let foo_call = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Call && r.name == "foo")
            .expect("expected a Call reference for 'foo'");
        assert!(
            foo_call.self_receiver,
            "this.foo() should mark self_receiver = true"
        );
        assert_eq!(
            foo_call.qualifier, None,
            "self-call qualifier must stay None"
        );
    }

    #[test]
    fn non_self_receiver_call_does_not_mark_self_receiver() {
        let src = r#"
class C {
  void foo() {}
  void run(C obj) { obj.foo(); }
}
"#;
        let facts = extract(src, "lib/c.dart");
        let foo_calls: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Call && r.name == "foo")
            .collect();
        assert!(
            foo_calls.iter().any(|r| !r.self_receiver),
            "obj.foo() must NOT mark self_receiver, got {foo_calls:?}"
        );
    }

    #[test]
    fn import_show_produces_import_references() {
        let src = r#"
import 'package:a/b.dart' show Foo, Bar;
class C {}
"#;
        let facts = extract(src, "lib/c.dart");

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
        assert!(
            import_names.contains(&"Bar"),
            "expected 'Bar' in import refs: {import_names:?}"
        );

        let foo_ref = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Import && r.name == "Foo")
            .unwrap();
        assert!(
            foo_ref
                .from_path
                .as_deref()
                .is_some_and(|p| p.contains("package:a/b.dart")),
            "from_path should contain the URI, got {:?}",
            foo_ref.from_path
        );
    }

    #[test]
    fn superclass_and_interface_produce_is_implementation_refs() {
        let src = r#"
class Dog extends Animal implements Pet {
  void bark() {}
}
"#;
        let facts = extract(src, "lib/dog.dart");

        let inherit_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();

        assert!(
            inherit_names.contains(&"Animal"),
            "expected 'Animal' in IsImplementation refs: {inherit_names:?}"
        );
        assert!(
            inherit_names.contains(&"Pet"),
            "expected 'Pet' in IsImplementation refs: {inherit_names:?}"
        );
    }

    // ── Read / Write references ──────────────────────────────────────────────

    #[test]
    fn reassignment_emits_write_for_lhs_and_reads_for_rhs() {
        // `total = total + bonus;` — Write for `total` (LHS), Read for `total`
        // and `bonus` on the RHS.
        let src = r#"
void run() {
  var total = 0;
  var bonus = 5;
  total = total + bonus;
}
"#;
        let facts = extract(src, "lib/run.dart");

        let writes: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Write)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            writes.contains(&"total"),
            "expected Write ref for 'total': {writes:?}"
        );

        let reads: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Read)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            reads.contains(&"bonus"),
            "expected Read ref for 'bonus': {reads:?}"
        );
        assert!(
            reads.contains(&"total"),
            "expected Read ref for RHS 'total': {reads:?}"
        );
    }

    #[test]
    fn declaration_does_not_emit_write_for_bound_name() {
        // `var result = compute();` — the binding name `result` is NOT a Write.
        let src = r#"
void run() {
  var result = compute();
}
"#;
        let facts = extract(src, "lib/run.dart");

        let write_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Write)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            !write_names.contains(&"result"),
            "declaration name 'result' must NOT produce a Write ref: {write_names:?}"
        );
    }

    #[test]
    fn call_argument_is_read_but_callee_is_not() {
        // `logger(config);` — Read for `config`, no Read for the callee `logger`.
        let src = r#"
void run() {
  logger(config);
}
"#;
        let facts = extract(src, "lib/run.dart");

        let reads: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Read)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            reads.contains(&"config"),
            "expected Read ref for 'config': {reads:?}"
        );
        assert!(
            !reads.contains(&"logger"),
            "callee 'logger' must NOT be emitted as a Read ref: {reads:?}"
        );
    }

    #[test]
    fn member_access_object_is_read_but_property_is_not() {
        // `value = source.field;` — Read for `source`, NOT for `field`.
        let src = r#"
void run() {
  var value = 0;
  value = source.field;
}
"#;
        let facts = extract(src, "lib/run.dart");

        let reads: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Read)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            reads.contains(&"source"),
            "expected Read ref for 'source': {reads:?}"
        );
        assert!(
            !reads.contains(&"field"),
            "member property 'field' must NOT be emitted as a Read ref: {reads:?}"
        );
    }

    // ── Binding type_name (local-typed-call resolution) ────────────────────────

    #[test]
    fn typed_local_declaration_carries_type_name() {
        let src = r#"
void run() {
  Repo repo = Repo();
}
"#;
        let facts = extract(src, "lib/run.dart");
        let repo = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Local && b.name == "repo")
            .expect("expected a Local binding for 'repo'");
        assert_eq!(repo.type_name.as_deref(), Some("Repo"));
    }

    #[test]
    fn constructor_call_local_has_no_type_name() {
        // `var repo = Repo();` — Dart has no `new` requirement (since Dart 2),
        // so a bare call `Repo()` is syntactically identical to a function
        // call `repo()`; there is no reliable constructor marker to infer
        // from, so this must stay `None` rather than guess.
        let src = r#"
void run() {
  var repo = Repo();
}
"#;
        let facts = extract(src, "lib/run.dart");
        let repo = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Local && b.name == "repo")
            .expect("expected a Local binding for 'repo'");
        assert_eq!(repo.type_name, None);
    }

    #[test]
    fn untyped_local_has_no_type_name() {
        let src = r#"
void run() {
  var result = compute();
}
"#;
        let facts = extract(src, "lib/run.dart");
        let result = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Local && b.name == "result")
            .expect("expected a Local binding for 'result'");
        assert_eq!(result.type_name, None);
    }

    #[test]
    fn typed_param_carries_type_name() {
        let src = "void run(Repo repo) {}";
        let facts = extract(src, "lib/run.dart");
        let repo = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Param && b.name == "repo")
            .expect("expected a Param binding for 'repo'");
        assert_eq!(repo.type_name.as_deref(), Some("Repo"));
    }
}
