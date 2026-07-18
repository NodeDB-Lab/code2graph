// SPDX-License-Identifier: Apache-2.0

//! Swift extractor — one tree-sitter pass yielding definitions and references.
//!
//! Definitions: all declarations are emitted, each tagged with its real
//! [`Visibility`]. Qualified identity follows the file's path
//! (`Sources/Auth/Session.swift` → namespaces `Sources`, `Auth`, `Session`).
//!
//! Covered declaration kinds:
//! - `class_declaration` with `declaration_kind` ∈ {class, struct, enum, actor, extension}
//! - `protocol_declaration`
//! - `function_declaration` / `init_declaration` (top-level and member)
//! - `property_declaration` (let → Const, var → Static)
//! - `typealias_declaration`
//! - `enum_entry` inside `enum_class_body`
//!
//! Extensions do not emit a new Type symbol; their members are nested under the
//! extended type's identifier using the file-path namespaces.
//!
//! References: callee identifiers of `call_expression` nodes (both free calls
//! `foo()` and member calls `x.foo()`).
//!
//! Emits neutral [`FileFacts`] — no storage entries, no source bodies.

use tree_sitter::{Node, Parser};

use crate::error::{CodegraphError, Result};
use crate::graph::types::{
    Binding, BindingKind, ByteSpan, EntryPoint, FileFacts, RefRole, Reference, Scope, ScopeId,
    ScopeKind, Symbol, SymbolKind, TypeRefContext, Visibility,
};
use crate::lang::Language;
use crate::symbol::Descriptor;

use super::{
    ExtractCtx, Extractor, MIN_REF_LEN, attach_reference_scopes, collect_call_references,
    definition_bindings, field_text, import_bindings, innermost_scope, make_symbol,
    mark_self_receiver_calls, node_span, node_text, one_line_signature, push_binding, push_ref,
    push_scope, push_type_ref,
};

/// Tree-sitter query capturing call-callee identifiers.
///
/// Pattern 1: free call `foo()` → simple_identifier direct child of call_expression.
/// Pattern 2: member call `x.foo()` → navigation_expression inside call_expression,
///            with a navigation_suffix whose `suffix` field is a simple_identifier.
const CALL_QUERY: &str = r#"
[
  (call_expression (simple_identifier) @callee)
  (call_expression (navigation_expression suffix: (navigation_suffix suffix: (simple_identifier) @callee)))
]
"#;

/// Method calls whose receiver is written as the `self` keyword
/// (`self.foo()`).
///
/// Deliberately a *separate* query from [`CALL_QUERY`] rather than an extra
/// alternation branch there, mirroring the Rust extractor's `SELF_CALL_QUERY`:
/// `navigation_expression target: (self_expression) …` and the existing
/// member-call pattern both structurally match the same `self.foo()` node,
/// and tree-sitter's alternation explores every branch that fits — combining
/// them in one `[ ]` would double-emit the reference. Run as a second pass
/// and correlate back to [`CALL_QUERY`]'s output by the `simple_identifier`'s
/// byte offset (identical node in both queries).
const SELF_CALL_QUERY: &str = r#"
(call_expression
  (navigation_expression
    target: (self_expression)
    suffix: (navigation_suffix suffix: (simple_identifier) @callee)))
"#;

/// Extracts Swift symbols and references.
pub struct SwiftExtractor;

impl Extractor for SwiftExtractor {
    fn lang(&self) -> Language {
        Language::Swift
    }

    fn extract(&self, source: &str, file: &str) -> Result<FileFacts> {
        let ts_language = crate::grammar::swift();
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
            lang: Language::Swift,
        };
        let ns_strings = swift_namespaces(file);
        let ns_descriptors: Vec<Descriptor> = ns_strings
            .iter()
            .cloned()
            .map(Descriptor::Namespace)
            .collect();

        let mut defs = Vec::new();
        collect_decls(root, &ns_descriptors, &ctx, &mut defs);
        let def_bindings = definition_bindings(&defs);
        let mut symbols = defs;
        symbols.push(super::module_symbol(
            Language::Swift,
            &ns_strings,
            file,
            source.len(),
        ));

        let mut references = collect_call_references(
            &root,
            &ts_language,
            CALL_QUERY,
            Language::Swift,
            bytes,
            file,
        )?;
        mark_self_receiver_calls(
            &root,
            &ts_language,
            SELF_CALL_QUERY,
            Language::Swift,
            bytes,
            &mut references,
            None,
        )?;
        collect_inheritance(&root, bytes, file, &mut references);
        collect_imports(&root, bytes, file, &mut references);
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
            lang: Language::Swift.as_str().to_owned(),
            symbols,
            references,
            scopes,
            bindings,
            ffi_exports: Vec::new(),
        })
    }
}

// ── Namespace derivation ─────────────────────────────────────────────────────

/// File-path namespace descriptors for a Swift source file.
///
/// `Sources/Auth/Session.swift` → `["Sources", "Auth", "Session"]`
/// All path segments are kept (including `Sources`); the final segment has its
/// `.swift` extension stripped.
fn swift_namespaces(file: &str) -> Vec<String> {
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

// ── Visibility reader ────────────────────────────────────────────────────────

/// Read the declared [`Visibility`] from a declaration node.
///
/// Scans the `modifiers` child for a `visibility_modifier` and maps it:
/// - `"open"` | `"public"` → [`Visibility::Public`]
/// - `"package"` → [`Visibility::Internal`]
/// - `"internal"` | no modifier → [`Visibility::Internal`] (Swift's default)
/// - `"private"` | `"fileprivate"` → [`Visibility::Private`]
fn read_visibility(node: &Node, bytes: &[u8]) -> Visibility {
    for child in node.children(&mut node.walk()) {
        if child.kind() != "modifiers" {
            continue;
        }
        for modifier in child.children(&mut child.walk()) {
            if modifier.kind() == "visibility_modifier" {
                return match node_text(&modifier, bytes) {
                    "open" | "public" => Visibility::Public,
                    "package" | "internal" => Visibility::Internal,
                    "private" | "fileprivate" => Visibility::Private,
                    _ => Visibility::Internal,
                };
            }
        }
        // modifiers present but no visibility_modifier → implicit internal
        return Visibility::Internal;
    }
    // No modifiers child → implicit internal (Swift default)
    Visibility::Internal
}

// ── Type-name leaf extraction ────────────────────────────────────────────────

/// Extract the bare identifier from a type-name node.
///
/// The `name` field of `class_declaration` may be a `type_identifier` (plain
/// types) or a `user_type` / other compound node (e.g. `extension Array<Int>`).
/// Recurses into the first child until a `type_identifier` or `simple_identifier`
/// leaf is found.  Returns `None` if no leaf is reachable.
fn leaf_type_name(node: Node, bytes: &[u8]) -> Option<String> {
    match node.kind() {
        "type_identifier" | "simple_identifier" => Some(node_text(&node, bytes).to_owned()),
        _ => {
            // Descend into the first named child.
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.is_named() {
                    if let Some(name) = leaf_type_name(child, bytes) {
                        return Some(name);
                    }
                }
            }
            None
        }
    }
}

// ── Inheritance reference extraction ────────────────────────────────────────

/// Recursively walk `node` and push one `Inherit` reference for every
/// `inheritance_specifier` found inside `class_declaration` or
/// `protocol_declaration` nodes.
fn collect_inheritance(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    match node.kind() {
        "class_declaration" | "protocol_declaration" => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "inheritance_specifier" {
                    if let Some(inherits_from) = child.child_by_field_name("inherits_from") {
                        super::push_ref(
                            out,
                            super::simple_type_name(node_text(&inherits_from, bytes), "."),
                            &inherits_from,
                            file,
                            RefRole::IsImplementation,
                        );
                    }
                }
            }
        }
        _ => {}
    }

    // Recurse into all children so nested types are covered.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_inheritance(&child, bytes, file, out);
    }
}

// ── Import reference extraction ─────────────────────────────────────────────

/// Recursively walk `node` and push one `Import` reference for every
/// `import_declaration` found.  The imported name is the leaf of the
/// (possibly dotted) module path — `Foundation` → `Foundation`,
/// `os.log` → `log`.
fn collect_imports(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    if node.kind() == "import_declaration" {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "identifier" {
                let leaf = super::simple_type_name(node_text(&child, bytes), ".");
                super::push_ref(out, leaf, &child, file, RefRole::Import);
                break;
            }
        }
    }

    // Recurse into all children so any top-level imports are reached.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_imports(&child, bytes, file, out);
    }
}

// ── Symbol builder ───────────────────────────────────────────────────────────

/// Build a [`Symbol`] and push it onto `out`.
///
/// Delegates to [`make_symbol`] from `support.rs`; the signature stop-chars
/// for Swift are `['{', '\n']`.
fn push_symbol(
    out: &mut Vec<Symbol>,
    ctx: &ExtractCtx,
    node: &Node,
    name: String,
    kind: SymbolKind,
    visibility: Visibility,
    descriptors: Vec<Descriptor>,
) {
    let signature = one_line_signature(node_text(node, ctx.bytes), &['{', '\n']);
    out.push(make_symbol(
        ctx,
        node,
        name,
        kind,
        visibility,
        descriptors,
        signature,
    ));
}

// ── Declaration collection ───────────────────────────────────────────────────

/// Collect definitions from a container node (source_file or a type body).
///
/// `prefix` is the descriptor list up to (but not including) the current level.
/// For top-level: prefix = file-path Namespace descriptors.
/// For type members: prefix = file-path Namespaces + Type(name).
fn collect_decls(container: Node, prefix: &[Descriptor], ctx: &ExtractCtx, out: &mut Vec<Symbol>) {
    // A function declared inside a type body should be SymbolKind::Method.
    let inside_type = matches!(prefix.last(), Some(Descriptor::Type(_)));

    let mut cursor = container.walk();
    for child in container.children(&mut cursor) {
        match child.kind() {
            "class_declaration" => handle_class_declaration(child, prefix, ctx, out),
            "protocol_declaration" => handle_protocol_declaration(child, prefix, ctx, out),
            "function_declaration" => handle_function(child, prefix, ctx, out, inside_type),
            "init_declaration" => handle_init(child, prefix, ctx, out),
            "property_declaration" => handle_property(child, prefix, ctx, out),
            "typealias_declaration" => handle_typealias(child, prefix, ctx, out),
            "enum_entry" => handle_enum_entry(child, prefix, ctx, out),
            _ => {}
        }
    }
}

/// Handle `class_declaration` — covers class/struct/enum/actor/extension.
fn handle_class_declaration(
    node: Node,
    prefix: &[Descriptor],
    ctx: &ExtractCtx,
    out: &mut Vec<Symbol>,
) {
    let visibility = read_visibility(&node, ctx.bytes);
    let kind_text = field_text(&node, "declaration_kind", ctx.bytes).unwrap_or_default();
    let name_node = match node.child_by_field_name("name") {
        Some(n) => n,
        None => return,
    };
    let type_name = match leaf_type_name(name_node, ctx.bytes) {
        Some(n) => n,
        None => return,
    };

    let body = match node.child_by_field_name("body") {
        Some(b) => b,
        None => return,
    };

    if kind_text == "extension" {
        // Extension: no new Type symbol. Members go under Type(extended_name)
        // using the file-path prefix (same as if the type were defined here).
        let mut member_prefix = prefix.to_vec();
        member_prefix.push(Descriptor::Type(type_name));
        collect_decls(body, &member_prefix, ctx, out);
        return;
    }

    let sym_kind = match kind_text.as_str() {
        "class" => SymbolKind::Class,
        "struct" => SymbolKind::Struct,
        "enum" => SymbolKind::Enum,
        "actor" => SymbolKind::Class,
        _ => SymbolKind::Other,
    };

    // Emit the Type symbol.
    let mut type_descriptors = prefix.to_vec();
    type_descriptors.push(Descriptor::Type(type_name.clone()));
    push_symbol(
        out,
        ctx,
        &node,
        type_name,
        sym_kind,
        visibility,
        type_descriptors.clone(),
    );

    // Recurse into body for members.
    collect_decls(body, &type_descriptors, ctx, out);
}

/// Handle `protocol_declaration`.
fn handle_protocol_declaration(
    node: Node,
    prefix: &[Descriptor],
    ctx: &ExtractCtx,
    out: &mut Vec<Symbol>,
) {
    let visibility = read_visibility(&node, ctx.bytes);
    let type_name = match field_text(&node, "name", ctx.bytes) {
        Some(n) => n,
        None => return,
    };

    let mut type_descriptors = prefix.to_vec();
    type_descriptors.push(Descriptor::Type(type_name.clone()));
    push_symbol(
        out,
        ctx,
        &node,
        type_name,
        SymbolKind::Interface,
        visibility,
        type_descriptors.clone(),
    );

    // protocol_declaration has a `body` field whose kind is `protocol_body`.
    // protocol_body itself has a `body` field (inner compound_statement-like node).
    if let Some(proto_body) = node.child_by_field_name("body") {
        collect_protocol_members(proto_body, &type_descriptors, ctx, out);
    }
}

/// Walk `protocol_body` for `protocol_function_declaration` and
/// `protocol_property_declaration`.
///
/// `protocol_body` exposes its members as direct children (not via a named
/// `body` field — the grammar's `body` field only covers
/// `protocol_function_declaration` items).  We iterate all children instead.
fn collect_protocol_members(
    body: Node,
    prefix: &[Descriptor],
    ctx: &ExtractCtx,
    out: &mut Vec<Symbol>,
) {
    let mut cursor = body.walk();
    for member in body.children(&mut cursor) {
        match member.kind() {
            "protocol_function_declaration" => {
                let visibility = read_visibility(&member, ctx.bytes);
                let name = match field_text(&member, "name", ctx.bytes) {
                    Some(n) => n,
                    None => continue,
                };
                let mut descriptors = prefix.to_vec();
                descriptors.push(Descriptor::Method {
                    name: name.clone(),
                    disambiguator: crate::symbol::MethodDisambiguator::empty(),
                });
                push_symbol(
                    out,
                    ctx,
                    &member,
                    name,
                    SymbolKind::Method,
                    visibility,
                    descriptors,
                );
            }
            "protocol_property_declaration" => {
                let visibility = read_visibility(&member, ctx.bytes);
                // field `name` on protocol_property_declaration is a `pattern` node
                let name = match member.child_by_field_name("name") {
                    Some(pat) => match pat.child_by_field_name("bound_identifier") {
                        Some(bi) => node_text(&bi, ctx.bytes).to_owned(),
                        None => continue,
                    },
                    None => continue,
                };
                let mut descriptors = prefix.to_vec();
                descriptors.push(Descriptor::Term(name.clone()));
                push_symbol(
                    out,
                    ctx,
                    &member,
                    name,
                    SymbolKind::Const,
                    visibility,
                    descriptors,
                );
            }
            _ => {}
        }
    }
}

/// Handle `function_declaration`.
///
/// `inside_type` controls whether to use SymbolKind::Function (top-level) or
/// SymbolKind::Method (member).
fn handle_function(
    node: Node,
    prefix: &[Descriptor],
    ctx: &ExtractCtx,
    out: &mut Vec<Symbol>,
    inside_type: bool,
) {
    let visibility = read_visibility(&node, ctx.bytes);
    // field `name` is usually a simple_identifier; for operators it may not be.
    let name = match field_text(&node, "name", ctx.bytes) {
        Some(n) => n,
        None => return,
    };
    let kind = if inside_type {
        SymbolKind::Method
    } else {
        SymbolKind::Function
    };
    // Name-only across top-level and inside-type (covers `static func main`
    // of an `@main` type); `@main` itself is deferred.
    let is_main = name == "main";
    let mut descriptors = prefix.to_vec();
    descriptors.push(Descriptor::Method {
        name: name.clone(),
        disambiguator: crate::symbol::MethodDisambiguator::empty(),
    });
    push_symbol(out, ctx, &node, name, kind, visibility, descriptors);
    if is_main {
        if let Some(s) = out.last_mut() {
            s.entry_points.push(EntryPoint::Main);
        }
    }
}

/// Handle `init_declaration` — name is always "init".
fn handle_init(node: Node, prefix: &[Descriptor], ctx: &ExtractCtx, out: &mut Vec<Symbol>) {
    let visibility = read_visibility(&node, ctx.bytes);
    let mut descriptors = prefix.to_vec();
    descriptors.push(Descriptor::Method {
        name: "init".to_owned(),
        disambiguator: crate::symbol::MethodDisambiguator::empty(),
    });
    push_symbol(
        out,
        ctx,
        &node,
        "init".to_owned(),
        SymbolKind::Method,
        visibility,
        descriptors,
    );
}

/// Handle `property_declaration`.
///
/// Finds the `value_binding_pattern` child to determine let/var mutability.
/// The variable name is from the `name` field (a `pattern` node) → `bound_identifier`.
fn handle_property(node: Node, prefix: &[Descriptor], ctx: &ExtractCtx, out: &mut Vec<Symbol>) {
    let visibility = read_visibility(&node, ctx.bytes);

    // Determine let vs var from the value_binding_pattern child.
    let is_let = {
        let mut found_let = true; // default to let if we can't determine
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "value_binding_pattern" {
                found_let = field_text(&child, "mutability", ctx.bytes).is_none_or(|m| m == "let");
                break;
            }
        }
        found_let
    };

    // The `name` field is a `pattern` node; the variable name is in
    // pattern's `bound_identifier` field (a simple_identifier).
    let name_node = match node.child_by_field_name("name") {
        Some(n) => n,
        None => return,
    };
    let var_name = match name_node.child_by_field_name("bound_identifier") {
        Some(bi) => node_text(&bi, ctx.bytes).to_owned(),
        // Tuple destructuring or other complex patterns — skip gracefully.
        None => return,
    };

    let kind = if is_let {
        SymbolKind::Const
    } else {
        SymbolKind::Static
    };
    let mut descriptors = prefix.to_vec();
    descriptors.push(Descriptor::Term(var_name.clone()));
    push_symbol(out, ctx, &node, var_name, kind, visibility, descriptors);
}

/// Handle `typealias_declaration`.
fn handle_typealias(node: Node, prefix: &[Descriptor], ctx: &ExtractCtx, out: &mut Vec<Symbol>) {
    let visibility = read_visibility(&node, ctx.bytes);
    let name = match field_text(&node, "name", ctx.bytes) {
        Some(n) => n,
        None => return,
    };
    let mut descriptors = prefix.to_vec();
    descriptors.push(Descriptor::Type(name.clone()));
    push_symbol(
        out,
        ctx,
        &node,
        name,
        SymbolKind::TypeAlias,
        visibility,
        descriptors,
    );
}

/// Handle `enum_entry` (cases inside an enum body).
fn handle_enum_entry(node: Node, prefix: &[Descriptor], ctx: &ExtractCtx, out: &mut Vec<Symbol>) {
    let visibility = read_visibility(&node, ctx.bytes);
    let name = match field_text(&node, "name", ctx.bytes) {
        Some(n) => n,
        None => return,
    };
    let mut descriptors = prefix.to_vec();
    descriptors.push(Descriptor::Term(name.clone()));
    push_symbol(
        out,
        ctx,
        &node,
        name,
        SymbolKind::Const,
        visibility,
        descriptors,
    );
}

// ── Type-annotation references (TypeRef) ────────────────────────────────────

/// Walk a single Swift type node and emit [`RefRole::TypeRef`] references for
/// every named type identifier leaf found inside it.
///
/// Tree-sitter-swift type node shapes handled:
/// - `user_type` → first `type_identifier` child is the leaf name; if a
///   `type_arguments` sibling is present each `name:` field child recurses with
///   `GenericArg`.
/// - `optional_type` → `wrapped:` field recurses with the outer `ctx`.
/// - `array_type` → `element:` field recurses with the outer `ctx`.
/// - `dictionary_type` → `key:` and `value:` fields recurse with the outer `ctx`.
/// - All other container type nodes (tuple, function, protocol composition,
///   existential, opaque, …) → recurse all named children with the outer `ctx`
///   as a best-effort catch.
fn type_leaf_swift(
    node: &Node,
    bytes: &[u8],
    file: &str,
    ctx: TypeRefContext,
    out: &mut Vec<Reference>,
) {
    match node.kind() {
        "user_type" => {
            // user_type children: one `type_identifier` (the name) and optionally
            // a `type_arguments` node.  Walk named children to find them.
            let mut type_args_node: Option<Node> = None;
            for child in node.named_children(&mut node.walk()) {
                match child.kind() {
                    "type_identifier" => {
                        let name = node_text(&child, bytes);
                        push_type_ref(out, name, &child, file, ctx);
                    }
                    "type_arguments" => {
                        type_args_node = Some(child);
                    }
                    _ => {}
                }
            }
            // Recurse into generic type arguments with GenericArg context.
            if let Some(args) = type_args_node {
                // type_arguments `name:` field carries each argument type.
                // tree-sitter exposes them as named children; the field is
                // repeated so we walk all named children instead.
                for child in args.named_children(&mut args.walk()) {
                    type_leaf_swift(&child, bytes, file, TypeRefContext::GenericArg, out);
                }
            }
        }
        "optional_type" => {
            // `T?` — the inner type is the `wrapped:` field.
            if let Some(inner) = node.child_by_field_name("wrapped") {
                type_leaf_swift(&inner, bytes, file, ctx, out);
            }
        }
        "array_type" => {
            // `[T]` — the element type is the `element:` field.
            if let Some(elem) = node.child_by_field_name("element") {
                type_leaf_swift(&elem, bytes, file, ctx, out);
            }
        }
        "dictionary_type" => {
            // `[K: V]` — key and value fields.
            if let Some(key) = node.child_by_field_name("key") {
                type_leaf_swift(&key, bytes, file, ctx, out);
            }
            if let Some(val) = node.child_by_field_name("value") {
                type_leaf_swift(&val, bytes, file, ctx, out);
            }
        }
        // tuple_type, function_type, protocol_composition_type, existential_type,
        // opaque_type, metatype, type_pack_expansion, etc. — recurse named children.
        _ => {
            for child in node.named_children(&mut node.walk()) {
                type_leaf_swift(&child, bytes, file, ctx, out);
            }
        }
    }
}

/// Recursively walk `node` and emit [`RefRole::TypeRef`] references for every
/// type identifier in an annotation position.
///
/// Covered positions (tree-sitter-swift grammar):
/// - `parameter` `type:` field → [`TypeRefContext::ParameterType`]
/// - `function_declaration` `return_type:` field → [`TypeRefContext::ReturnType`]
/// - `init_declaration` parameter types (via `parameter` children) → `ParameterType`
/// - `property_declaration` → `type_annotation` child → `type:` field
///   → [`TypeRefContext::Field`]
///
/// Generic type arguments are handled recursively inside [`type_leaf_swift`]
/// with [`TypeRefContext::GenericArg`].
fn collect_type_references(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    match node.kind() {
        // Function/init parameter types: `parameter` has a `type:` field.
        "parameter" => {
            if let Some(type_node) = node.child_by_field_name("type") {
                type_leaf_swift(&type_node, bytes, file, TypeRefContext::ParameterType, out);
            }
            // No further recursion needed for a parameter node.
            return;
        }
        // Function return type: `function_declaration` has a `return_type:` field.
        "function_declaration" => {
            if let Some(ret) = node.child_by_field_name("return_type") {
                type_leaf_swift(&ret, bytes, file, TypeRefContext::ReturnType, out);
            }
            // Fall through to recurse into children (body, parameter list).
        }
        // Property type annotation: `property_declaration` has a `type_annotation`
        // child (not a named field) carrying the declared type in its `type:` field.
        "property_declaration" | "protocol_property_declaration" => {
            for child in node.children(&mut node.walk()) {
                if child.kind() == "type_annotation" {
                    if let Some(type_node) = child.child_by_field_name("type") {
                        type_leaf_swift(&type_node, bytes, file, TypeRefContext::Field, out);
                    }
                }
            }
            // Fall through to recurse into children.
        }
        _ => {}
    }

    for child in node.children(&mut node.walk()) {
        collect_type_references(&child, bytes, file, out);
    }
}

// ── Edge richness: Read / Write ─────────────────────────────────────────────

/// Returns `true` when `node` (a `simple_identifier`) is in a position already
/// captured by another collector and must NOT also be emitted as a
/// [`RefRole::Read`] reference.
///
/// Skipped positions:
/// - Call callee: `simple_identifier` that is a direct child of `call_expression`
///   (pattern 1 of CALL_QUERY). Because `call_expression` exposes no named
///   `function:` field (its children are unnamed), any `simple_identifier` that
///   is an immediate child of `call_expression` is the callee — call arguments
///   are wrapped in a `call_suffix` node, not placed directly.
/// - Navigation member: parent is `navigation_suffix` — the `.foo` in `x.foo`
///   (pattern 2 of CALL_QUERY captures these as member callees; the base `x` IS
///   emitted as a Read because its parent is `navigation_expression`, not
///   `navigation_suffix`).
/// - Declaration name: `function_declaration`, `protocol_function_declaration`,
///   or `enum_entry` whose `name:` field is this node.
/// - Property binding: parent is `pattern` and this node is the `bound_identifier`
///   field — the name introduced by `let x` / `var x`.
/// - Parameter names: parent is `parameter` and this node is either the `name:`
///   field (internal name) or the `external_name:` field (the call-site label
///   in `func f(label name: T)`) — both are binding positions, not reads.
/// - Argument label: parent is `value_argument_label` — the label in `f(label: v)`.
/// - Assignment LHS: parent is `directly_assignable_expression` — handled by
///   [`collect_write_references`].
fn is_non_read_position(node: &Node) -> bool {
    let parent = match node.parent() {
        Some(p) => p,
        None => return true, // root — not a read
    };
    match parent.kind() {
        // Call callee (pattern 1 of CALL_QUERY): simple_identifier direct child
        // of call_expression. Call arguments live in call_suffix, not here.
        "call_expression" => true,
        // Navigation member (pattern 2 of CALL_QUERY): the .foo part.
        // The base (parent = navigation_expression) is NOT skipped — it IS a read.
        "navigation_suffix" => true,
        // Function / protocol-function declaration name.
        "function_declaration" | "protocol_function_declaration" => {
            parent.child_by_field_name("name").as_ref() == Some(node)
        }
        // Enum case name: `case north` — name field is a simple_identifier.
        "enum_entry" => parent.child_by_field_name("name").as_ref() == Some(node),
        // Property binding: `let x = …` — pattern's bound_identifier field.
        "pattern" => parent.child_by_field_name("bound_identifier").as_ref() == Some(node),
        // Parameter names: `func f(label name: T)` — both the external label
        // (`external_name` field) and the internal name (`name` field) are
        // parameter binding positions, not reads.
        "parameter" => {
            parent.child_by_field_name("name").as_ref() == Some(node)
                || parent.child_by_field_name("external_name").as_ref() == Some(node)
        }
        // Argument label in a function call: `f(label: value)`.
        "value_argument_label" => true,
        // Assignment LHS wrapper — handled by collect_write_references.
        "directly_assignable_expression" => true,
        _ => false,
    }
}

/// Recursively walk `node` and emit [`RefRole::Read`] references for bare
/// `simple_identifier` nodes used in value/expression positions.
///
/// Skips positions handled by other collectors:
/// - Call callees (CALL_QUERY pattern 1/2 — [`RefRole::Call`])
/// - Navigation member (`.foo` in `x.foo`) — the base `x` is emitted
/// - Declaration names (`function_declaration`, `protocol_function_declaration`,
///   `enum_entry` name fields)
/// - Property binding names (`pattern` → `bound_identifier`)
/// - Parameter names (`parameter.name` and `parameter.external_name`)
/// - Argument labels (`value_argument_label`)
/// - Assignment LHS (`directly_assignable_expression`)
///
/// `type_identifier` (used for type names) is a distinct node kind and is
/// naturally excluded — this function matches only `simple_identifier` nodes.
/// Applies [`MIN_REF_LEN`].
fn collect_read_references(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    if node.kind() == "simple_identifier" {
        let name = node_text(node, bytes);
        if name.len() >= MIN_REF_LEN && !is_non_read_position(node) {
            push_ref(out, name, node, file, RefRole::Read);
        }
        // simple_identifier nodes have no meaningful named children; return early.
        return;
    }
    for child in node.children(&mut node.walk()) {
        collect_read_references(&child, bytes, file, out);
    }
}

/// Recursively walk `node` and emit [`RefRole::Write`] references for the
/// bare-identifier LHS of Swift `assignment` nodes (e.g. `cnt = 5`, `cnt += 1`).
///
/// Swift assignment node shape (tree-sitter-swift grammar):
/// ```text
/// assignment
///   target: directly_assignable_expression
///     simple_identifier   ← bare LHS; emit Write if len >= MIN_REF_LEN
///   operator: =  (or +=, -=, …)
///   result: <rhs expression>
/// ```
///
/// `property_declaration` (`let`/`var x = 5`) is a *definition*, not an
/// assignment — it is correctly excluded because it produces a `property_declaration`
/// node, not an `assignment` node. Member/subscript LHS (`obj.prop = …`,
/// `arr[i] = …`) are not covered in v1 — only bare `simple_identifier` targets.
/// Applies [`MIN_REF_LEN`].
fn collect_write_references(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    if node.kind() == "assignment" {
        // The `target` field is a `directly_assignable_expression` whose sole
        // unnamed child is the LHS expression. For a bare identifier LHS the
        // inner node is a `simple_identifier`.
        if let Some(target) = node.child_by_field_name("target") {
            // target.kind() == "directly_assignable_expression"
            // Its first (and only) named child is the actual expression.
            if let Some(lhs) = target.named_child(0) {
                if lhs.kind() == "simple_identifier" {
                    let name = node_text(&lhs, bytes);
                    if name.len() >= MIN_REF_LEN {
                        push_ref(out, name, &lhs, file, RefRole::Write);
                    }
                }
            }
        }
    }
    for child in node.children(&mut node.walk()) {
        collect_write_references(&child, bytes, file, out);
    }
}

// ── Scope tree (Tier-B) ──────────────────────────────────────────────────────

/// Build the lexical scope tree for one Swift file.
///
/// `scopes[0]` is always the file-root `Module` scope spanning `[0, source_len)`.
/// Swift opens scopes for `class_declaration`/`protocol_declaration` (`Type`),
/// `function_declaration`/`init_declaration`/`lambda_literal` (`Function`), and
/// `statements` not already consumed as a function body (`Block`).
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

/// DFS opening scopes for Swift declaration nodes.
///
/// Uses the "peel-the-body" pattern so body containers do not re-open a
/// redundant scope on top of the declaration scope.
fn scope_dfs(node: &Node, parent_id: ScopeId, scopes: &mut Vec<Scope>) {
    match node.kind() {
        "class_declaration" | "protocol_declaration" => {
            let type_id = push_scope(scopes, Some(parent_id), node_span(node), ScopeKind::Type);
            // Peel the body: the body field of class_declaration is class_body or
            // enum_class_body; for protocol_declaration it is protocol_body. Recurse
            // directly into the body's children to avoid a redundant scope node.
            for child in node.children(&mut node.walk()) {
                if matches!(
                    child.kind(),
                    "class_body" | "enum_class_body" | "protocol_body"
                ) {
                    for body_child in child.children(&mut child.walk()) {
                        scope_dfs(&body_child, type_id, scopes);
                    }
                }
            }
        }
        "function_declaration" | "init_declaration" => {
            let fn_id = push_scope(
                scopes,
                Some(parent_id),
                node_span(node),
                ScopeKind::Function,
            );
            // function_body is a `body` field; its only child is `statements`.
            // Peel two levels: function_body → statements → children.
            if let Some(body) = node.child_by_field_name("body") {
                // body kind is "function_body"; look for the "statements" child.
                for body_child in body.children(&mut body.walk()) {
                    if body_child.kind() == "statements" {
                        for stmt_child in body_child.children(&mut body_child.walk()) {
                            scope_dfs(&stmt_child, fn_id, scopes);
                        }
                        break;
                    }
                }
            }
        }
        "lambda_literal" => {
            let fn_id = push_scope(
                scopes,
                Some(parent_id),
                node_span(node),
                ScopeKind::Function,
            );
            // All direct children (statements, type field, attributes) are recursed
            // under the Function scope.
            for child in node.children(&mut node.walk()) {
                scope_dfs(&child, fn_id, scopes);
            }
        }
        "statements" => {
            // A bare `statements` block not already consumed as a function/lambda
            // body (e.g. top-level, guard, if/else, do-catch bodies). Open a Block
            // scope and recurse its children.
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

/// Collect parameter and local-variable [`Binding`]s for one Swift file.
///
/// Covers:
/// - `function_declaration` / `init_declaration` parameters (from `parameter`
///   children whose `name` field is a `simple_identifier`) → [`BindingKind::Param`].
/// - `lambda_literal` parameters via `type` field → `lambda_function_type` →
///   `lambda_function_type_parameters` → `lambda_parameter` children whose `name`
///   field is a `simple_identifier` → [`BindingKind::Param`].
/// - `property_declaration` `name` field → `pattern` → `bound_identifier` field
///   inside a `Function` or `Block` scope → [`BindingKind::Local`].
/// - `for_statement` `item` field → `pattern` → `bound_identifier` inside a
///   `Function` or `Block` scope → [`BindingKind::Local`].
///
/// Class/struct-level properties (in `Type` scopes) are covered by
/// [`definition_bindings`] as [`BindingKind::Definition`] and excluded here.
fn collect_bindings(root: &Node, bytes: &[u8], scopes: &[Scope]) -> Vec<Binding> {
    let mut out = Vec::new();
    collect_bindings_dfs(root, bytes, scopes, &mut out);
    out
}

fn collect_bindings_dfs(node: &Node, bytes: &[u8], scopes: &[Scope], out: &mut Vec<Binding>) {
    match node.kind() {
        "function_declaration" | "init_declaration" => {
            // Collect params: walk children looking for `parameter` nodes.
            // In the Swift grammar, `parameter` nodes are nested inside the
            // `_function_value_parameters` construct, but tree-sitter flattens
            // unnamed wrapper nodes so we recurse all children and pick up
            // `parameter` nodes anywhere under the function header.
            collect_swift_params(node, bytes, scopes, out);
            // Recurse into children to pick up body bindings.
            for child in node.children(&mut node.walk()) {
                collect_bindings_dfs(&child, bytes, scopes, out);
            }
        }
        "lambda_literal" => {
            // Lambda params live in: type field → lambda_function_type →
            // lambda_function_type_parameters child → lambda_parameter children.
            if let Some(lft) = node.child_by_field_name("type") {
                // lft kind == "lambda_function_type"
                for lft_child in lft.children(&mut lft.walk()) {
                    if lft_child.kind() == "lambda_function_type_parameters" {
                        for param in lft_child.children(&mut lft_child.walk()) {
                            if param.kind() == "lambda_parameter" {
                                // `name` field on lambda_parameter: use first
                                // simple_identifier child of the name field.
                                if let Some(name_node) = param.child_by_field_name("name") {
                                    if name_node.kind() == "simple_identifier" {
                                        let name = node_text(&name_node, bytes);
                                        let intro = name_node.start_byte();
                                        push_binding(
                                            out,
                                            name.to_owned(),
                                            intro,
                                            BindingKind::Param,
                                            scopes,
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
            for child in node.children(&mut node.walk()) {
                collect_bindings_dfs(&child, bytes, scopes, out);
            }
        }
        "property_declaration" => {
            // Emit Local only when inside a Function or Block scope.
            // Class-level properties sit in a Type scope and are excluded by this
            // guard — they are captured by definition_bindings as Definition.
            //
            // Path: name field → pattern → bound_identifier field → simple_identifier.
            if let Some(name_node) = node.child_by_field_name("name") {
                // name_node kind == "pattern"
                if let Some(bi) = name_node.child_by_field_name("bound_identifier") {
                    let intro = bi.start_byte();
                    let sid = innermost_scope(intro, scopes).unwrap_or(0);
                    if matches!(scopes[sid].kind, ScopeKind::Function | ScopeKind::Block) {
                        let name = node_text(&bi, bytes);
                        push_binding(out, name.to_owned(), intro, BindingKind::Local, scopes);
                    }
                }
            }
            for child in node.children(&mut node.walk()) {
                collect_bindings_dfs(&child, bytes, scopes, out);
            }
        }
        "for_statement" => {
            // Loop variable: item field → pattern → bound_identifier field → simple_identifier.
            if let Some(item) = node.child_by_field_name("item") {
                // item kind == "pattern" (aliased from _binding_pattern_no_expr)
                if let Some(bi) = item.child_by_field_name("bound_identifier") {
                    let intro = bi.start_byte();
                    let sid = innermost_scope(intro, scopes).unwrap_or(0);
                    if matches!(scopes[sid].kind, ScopeKind::Function | ScopeKind::Block) {
                        let name = node_text(&bi, bytes);
                        push_binding(out, name.to_owned(), intro, BindingKind::Local, scopes);
                    }
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

/// Collect [`BindingKind::Param`] bindings from `parameter` nodes that are
/// descendants of `func_node` (a `function_declaration` or `init_declaration`).
///
/// The Swift grammar wraps parameters in an unnamed `_function_value_parameters`
/// inline rule; tree-sitter surfaces the `parameter` named nodes as descendants.
/// We walk only the non-body children to avoid picking up nested function params.
fn collect_swift_params(func_node: &Node, bytes: &[u8], scopes: &[Scope], out: &mut Vec<Binding>) {
    collect_params_dfs(func_node, bytes, scopes, out, true);
}

fn collect_params_dfs(
    node: &Node,
    bytes: &[u8],
    scopes: &[Scope],
    out: &mut Vec<Binding>,
    is_root: bool,
) {
    if !is_root
        && matches!(
            node.kind(),
            "function_declaration" | "init_declaration" | "lambda_literal"
        )
    {
        // Don't descend into nested functions/lambdas — their params belong to
        // their own scope and will be picked up when we visit them in the DFS.
        return;
    }
    if node.kind() == "parameter" {
        // `name` field is the INTERNAL name (simple_identifier).
        if let Some(name_node) = node.child_by_field_name("name") {
            if name_node.kind() == "simple_identifier" {
                let name = node_text(&name_node, bytes);
                let intro = name_node.start_byte();
                push_binding(out, name.to_owned(), intro, BindingKind::Param, scopes);
            }
        }
        // No need to recurse into a parameter node's children.
        return;
    }
    for child in node.children(&mut node.walk()) {
        collect_params_dfs(&child, bytes, scopes, out, false);
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::types::TypeRefContext;

    fn extract(src: &str, path: &str) -> FileFacts {
        SwiftExtractor.extract(src, path).unwrap()
    }

    fn by_name(facts: &FileFacts, name: &str) -> Option<Symbol> {
        facts.symbols.iter().find(|s| s.name == name).cloned()
    }

    #[test]
    fn main_function_is_entry_point() {
        let facts = extract("func main() {}", "src/main.swift");
        let main = by_name(&facts, "main").unwrap();
        assert!(
            main.entry_points
                .iter()
                .any(|e| matches!(e, EntryPoint::Main))
        );
    }

    // Test 1: public class with public func and private func — all emitted with correct visibility.
    #[test]
    fn public_class_visibility_gate() {
        let src = r#"
public class Session {
    public func validate() -> Bool { return true }
    private func secret() {}
    let token = ""
}
"#;
        let facts = extract(src, "Sources/Auth/Session.swift");

        // Class itself emitted with Public visibility.
        let session = by_name(&facts, "Session").unwrap();
        assert_eq!(session.kind, SymbolKind::Class);
        assert_eq!(session.visibility, Visibility::Public);
        assert_eq!(
            session.id.to_scip_string(),
            "codegraph . . . Sources/Auth/Session/Session#"
        );

        // Public method emitted with Public visibility, nested under Type.
        let validate = by_name(&facts, "validate").unwrap();
        assert_eq!(validate.kind, SymbolKind::Method);
        assert_eq!(validate.visibility, Visibility::Public);
        assert_eq!(
            validate.id.to_scip_string(),
            "codegraph . . . Sources/Auth/Session/Session#validate()."
        );

        // Private method IS now emitted, tagged Private.
        let secret = by_name(&facts, "secret").unwrap();
        assert_eq!(secret.kind, SymbolKind::Method);
        assert_eq!(secret.visibility, Visibility::Private);
        assert_eq!(
            secret.id.to_scip_string(),
            "codegraph . . . Sources/Auth/Session/Session#secret()."
        );

        // let property (implicit internal → Internal visibility).
        let token = by_name(&facts, "token").unwrap();
        assert_eq!(token.kind, SymbolKind::Const);
        assert_eq!(token.visibility, Visibility::Internal);
        assert_eq!(
            token.id.to_scip_string(),
            "codegraph . . . Sources/Auth/Session/Session#token."
        );
    }

    // Test 2: struct with let property
    #[test]
    fn struct_with_let_property() {
        let src = r#"
struct Point {
    let x: Double
    var y: Double
}
"#;
        let facts = extract(src, "Sources/Models/Point.swift");

        let point = by_name(&facts, "Point").unwrap();
        assert_eq!(point.kind, SymbolKind::Struct);
        assert_eq!(
            point.id.to_scip_string(),
            "codegraph . . . Sources/Models/Point/Point#"
        );

        let x = by_name(&facts, "x").unwrap();
        assert_eq!(x.kind, SymbolKind::Const);
        assert_eq!(
            x.id.to_scip_string(),
            "codegraph . . . Sources/Models/Point/Point#x."
        );

        let y = by_name(&facts, "y").unwrap();
        assert_eq!(y.kind, SymbolKind::Static);
        assert_eq!(
            y.id.to_scip_string(),
            "codegraph . . . Sources/Models/Point/Point#y."
        );
    }

    // Test 3: enum with cases
    #[test]
    fn enum_with_cases() {
        let src = r#"
enum Direction {
    case north
    case south
    case east
    case west
}
"#;
        let facts = extract(src, "Sources/Direction.swift");

        let dir = by_name(&facts, "Direction").unwrap();
        assert_eq!(dir.kind, SymbolKind::Enum);
        assert_eq!(
            dir.id.to_scip_string(),
            "codegraph . . . Sources/Direction/Direction#"
        );

        for case in &["north", "south", "east", "west"] {
            let sym = by_name(&facts, case).unwrap();
            assert_eq!(sym.kind, SymbolKind::Const);
            assert_eq!(
                sym.id.to_scip_string(),
                format!("codegraph . . . Sources/Direction/Direction#{case}.")
            );
        }
    }

    // Test 4: protocol with function requirement
    #[test]
    fn protocol_with_function_requirement() {
        let src = r#"
public protocol Readable {
    func read() -> String
}
"#;
        let facts = extract(src, "Sources/Protocols/Readable.swift");

        let proto = by_name(&facts, "Readable").unwrap();
        assert_eq!(proto.kind, SymbolKind::Interface);
        assert_eq!(
            proto.id.to_scip_string(),
            "codegraph . . . Sources/Protocols/Readable/Readable#"
        );

        let read = by_name(&facts, "read").unwrap();
        assert_eq!(read.kind, SymbolKind::Method);
        assert_eq!(
            read.id.to_scip_string(),
            "codegraph . . . Sources/Protocols/Readable/Readable#read()."
        );
    }

    // Test 5: extension — no new Type symbol, members under Type(Foo)
    #[test]
    fn extension_members_without_type_symbol() {
        let src = r#"
extension Foo {
    public func bar() {}
}
"#;
        let facts = extract(src, "Sources/Foo+Ext.swift");

        // No "Foo" Type emitted (extension doesn't create a new type symbol).
        // bar should be nested under Sources/Foo+Ext/Foo# ('+' is a simple-ident char, no backticks).
        let bar = by_name(&facts, "bar").unwrap();
        assert_eq!(bar.kind, SymbolKind::Method);
        assert_eq!(
            bar.id.to_scip_string(),
            "codegraph . . . Sources/Foo+Ext/Foo#bar()."
        );
    }

    // Test 6: top-level func → SymbolKind::Function, nested under file namespaces
    #[test]
    fn top_level_function() {
        let src = r#"
public func greet(name: String) -> String {
    return "Hello " + name
}
"#;
        let facts = extract(src, "Sources/Utils/Greeting.swift");

        let greet = by_name(&facts, "greet").unwrap();
        assert_eq!(greet.kind, SymbolKind::Function);
        assert_eq!(
            greet.id.to_scip_string(),
            "codegraph . . . Sources/Utils/Greeting/greet()."
        );
    }

    // Test 7: call references captured
    #[test]
    fn call_references_captured() {
        let src = r#"
func main() {
    validate("t")
    let obj = Foo()
    obj.process()
}
"#;
        let facts = extract(src, "Sources/main.swift");
        let names: Vec<&str> = facts.references.iter().map(|r| r.name.as_str()).collect();
        assert!(
            names.contains(&"validate"),
            "expected 'validate' in {names:?}"
        );
        assert!(
            names.contains(&"process"),
            "expected 'process' in {names:?}"
        );
    }

    #[test]
    fn lang_tag() {
        let facts = extract("func foo() {}", "Sources/Foo.swift");
        assert_eq!(facts.lang, "swift");
    }

    #[test]
    fn self_receiver_call_marks_self_receiver() {
        let src = r#"
class S {
    func foo() {}
    func run() { self.foo() }
}
"#;
        let facts = extract(src, "Sources/S.swift");
        let foo_call = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Call && r.name == "foo")
            .expect("expected a Call reference for 'foo'");
        assert!(
            foo_call.self_receiver,
            "self.foo() should mark self_receiver = true"
        );
        assert_eq!(
            foo_call.qualifier, None,
            "self-call qualifier must stay None"
        );
    }

    #[test]
    fn non_self_receiver_call_does_not_mark_self_receiver() {
        let src = r#"
class S {
    func foo() {}
    func run(obj: S) { obj.foo() }
}
"#;
        let facts = extract(src, "Sources/S.swift");
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

    // Test 9: class with superclass and protocol conformance
    #[test]
    fn class_inheritance_and_conformance() {
        let src = "class Sub: Base, Proto {}";
        let facts = extract(src, "Sources/Sub.swift");

        let inherit: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();
        assert!(inherit.contains(&"Base"), "expected 'Base' in {inherit:?}");
        assert!(
            inherit.contains(&"Proto"),
            "expected 'Proto' in {inherit:?}"
        );
    }

    // Test 10: protocol inheritance
    #[test]
    fn protocol_inheritance() {
        let src = "protocol P: Q {}";
        let facts = extract(src, "Sources/P.swift");

        let inherit: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();
        assert!(inherit.contains(&"Q"), "expected 'Q' in {inherit:?}");
    }

    // Test 11: struct conformance
    #[test]
    fn struct_conformance() {
        let src = "struct S: Equatable {}";
        let facts = extract(src, "Sources/S.swift");

        let inherit: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            inherit.contains(&"Equatable"),
            "expected 'Equatable' in {inherit:?}"
        );
    }

    // Test 12: simple module import → one Import ref named after the module
    #[test]
    fn import_foundation() {
        let src = "import Foundation";
        let facts = extract(src, "Sources/Foo.swift");

        let imports: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            imports.contains(&"Foundation"),
            "expected 'Foundation' in {imports:?}"
        );
    }

    // Test 13: submodule import → leaf name only
    #[test]
    fn import_submodule_leaf() {
        let src = "import os.log";
        let facts = extract(src, "Sources/Bar.swift");

        let imports: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            imports.contains(&"log"),
            "expected 'log' (leaf of os.log) in {imports:?}"
        );
    }

    // ── Tier-B scope / binding tests ─────────────────────────────────────────

    // Test B1: function params → Param bindings (internal names) in Function scope.
    #[test]
    fn func_params_emit_param_bindings() {
        let src = "func f(label a: Int, b: String) {}";
        let facts = extract(src, "Sources/F.swift");

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
            "expected Param bindings for a and b (internal names), got {param_names:?}"
        );
    }

    // Test B2: local let inside function → Local binding in Function scope.
    #[test]
    fn local_let_emits_local_binding() {
        let src = "func f() { let x = 1 }";
        let facts = extract(src, "Sources/F.swift");

        let x = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Local && b.name == "x")
            .expect("expected a Local binding for 'x'");
        assert!(
            matches!(
                facts.scopes[x.scope].kind,
                ScopeKind::Function | ScopeKind::Block
            ),
            "x should be in a Function or Block scope, got {:?}",
            facts.scopes[x.scope].kind
        );
    }

    // Test B3: local var inside function → Local binding.
    #[test]
    fn local_var_emits_local_binding() {
        let src = "func f() { var y = 2 }";
        let facts = extract(src, "Sources/F.swift");

        let y = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Local && b.name == "y")
            .expect("expected a Local binding for 'y'");
        assert!(
            matches!(
                facts.scopes[y.scope].kind,
                ScopeKind::Function | ScopeKind::Block
            ),
            "y should be in a Function or Block scope, got {:?}",
            facts.scopes[y.scope].kind
        );
    }

    // Test B4: for-in loop variable → Local binding.
    #[test]
    fn for_in_var_emits_local_binding() {
        let src = "func f() { for x in [1, 2] {} }";
        let facts = extract(src, "Sources/F.swift");

        let x = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Local && b.name == "x")
            .expect("expected a Local binding for for-in 'x'");
        assert!(
            matches!(
                facts.scopes[x.scope].kind,
                ScopeKind::Function | ScopeKind::Block
            ),
            "for-in x should be in a Function or Block scope, got {:?}",
            facts.scopes[x.scope].kind
        );
    }

    // Test B5: class property is NOT a Local but IS a Definition.
    #[test]
    fn class_property_not_local_but_is_definition() {
        let src = "class C { let count = 0 }";
        let facts = extract(src, "Sources/C.swift");

        assert!(
            !facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Local && b.name == "count"),
            "class property 'count' must NOT be a Local binding"
        );
        assert!(
            facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Definition && b.name == "count"),
            "class property 'count' must have a Definition binding"
        );
    }

    // Test B6: nested class+func → Module → Type → Function scope chain.
    #[test]
    fn nested_class_fun_scope_chain() {
        let src = "class C { func f() {} }";
        let facts = extract(src, "Sources/C.swift");

        assert_eq!(
            facts.scopes[0].kind,
            ScopeKind::Module,
            "scopes[0] must be Module"
        );

        let type_scope_id = facts
            .scopes
            .iter()
            .position(|s| s.kind == ScopeKind::Type)
            .expect("expected a Type scope");
        let fn_scope_id = facts
            .scopes
            .iter()
            .position(|s| s.kind == ScopeKind::Function)
            .expect("expected a Function scope");

        assert_eq!(
            facts.scopes[type_scope_id].parent,
            Some(0),
            "Type scope parent should be Module (0)"
        );
        assert_eq!(
            facts.scopes[fn_scope_id].parent,
            Some(type_scope_id),
            "Function scope parent should be the Type scope"
        );
    }

    // Test B7: lambda params → Param binding in a Function scope (the lambda's).
    #[test]
    fn lambda_params_emit_param_bindings() {
        // `{ a in a + 1 }` — `a` is the lambda parameter.
        let src = "func f() { let g: (Int) -> Int = { a in a + 1 } }";
        let facts = extract(src, "Sources/F.swift");

        let a = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Param && b.name == "a")
            .expect("expected a Param binding for lambda param 'a'");
        assert_eq!(
            facts.scopes[a.scope].kind,
            ScopeKind::Function,
            "lambda param 'a' should be in a Function scope"
        );
    }

    // Test B8: init params → Param binding in a Function scope.
    #[test]
    fn init_params_emit_param_bindings() {
        let src = "class C { init(x: Int) {} }";
        let facts = extract(src, "Sources/C.swift");

        let x = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Param && b.name == "x")
            .expect("expected a Param binding for init param 'x'");
        assert_eq!(
            facts.scopes[x.scope].kind,
            ScopeKind::Function,
            "init param 'x' should be in a Function scope"
        );
    }

    // Test B9: same-file call ref has scope attached (non-zero = innermost scope).
    #[test]
    fn same_file_call_ref_has_scope() {
        let src = "func greet() {}\nfunc main() { greet() }";
        let facts = extract(src, "Sources/Greet.swift");

        assert!(
            by_name(&facts, "greet").is_some(),
            "expected 'greet' Definition"
        );

        let greet_ref = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Call && r.name == "greet")
            .expect("expected a Call ref for 'greet'");
        assert!(
            greet_ref.scope.is_some() && greet_ref.scope != Some(0),
            "greet() call ref should be in a non-root scope, got {:?}",
            greet_ref.scope
        );
    }

    // Test B10: import binding → Import binding named after the module.
    #[test]
    fn import_emits_import_binding() {
        let src = "import Foundation\nfunc f() {}";
        let facts = extract(src, "Sources/F.swift");

        assert!(
            facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Import && b.name == "Foundation"),
            "expected an Import binding named 'Foundation', got {:?}",
            facts
                .bindings
                .iter()
                .filter(|b| b.kind == BindingKind::Import)
                .map(|b| b.name.as_str())
                .collect::<Vec<_>>()
        );
    }

    // Test B11: struct property is NOT a Local but IS a Definition.
    #[test]
    fn struct_property_not_local_but_is_definition() {
        let src = "struct S { var count: Int = 0 }";
        let facts = extract(src, "Sources/S.swift");

        assert!(
            !facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Local && b.name == "count"),
            "struct property 'count' must NOT be a Local binding"
        );
        assert!(
            facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Definition && b.name == "count"),
            "struct property 'count' must have a Definition binding"
        );
    }

    // ── Edge richness: Read / Write ──────────────────────────────────────────

    // Test RW1: Read at use site, NOT at the let binding.
    #[test]
    fn read_ref_emitted_at_use_not_declaration() {
        // `func f() -> Int { let base = 1; return base }`
        // → Read ref for `base` in `return base`, not at the `let base`.
        let src = "func f() -> Int { let base = 1; return base }";
        let facts = extract(src, "Sources/F.swift");

        let read_refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Read && r.name == "base")
            .collect();
        assert!(
            !read_refs.is_empty(),
            "expected at least one Read ref for 'base', got none; refs = {:?}",
            facts
                .references
                .iter()
                .map(|r| (&r.name, r.role))
                .collect::<Vec<_>>()
        );
        // The `let base` keyword is near the start; the `return base` use appears later.
        // Verify the Read ref byte offset is after the `=` sign (byte > 20).
        let use_ref = read_refs
            .iter()
            .find(|r| r.occ.byte > 20)
            .expect("expected Read ref for 'base' in the return expression (byte > 20)");
        assert!(
            use_ref.occ.byte > 20,
            "Read ref should be at the use site, not the declaration"
        );
    }

    // Test RW2: Write ref emitted for assignment (not for the let/var declaration).
    #[test]
    fn write_ref_emitted_for_assignment() {
        // `func f() { var cnt = 0; cnt = 5 }`
        // → Write ref for the `cnt = 5` assignment; the `var cnt` declaration is NOT a Write.
        let src = "func f() { var cnt = 0; cnt = 5 }";
        let facts = extract(src, "Sources/F.swift");

        let write_refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Write && r.name == "cnt")
            .collect();
        assert!(
            !write_refs.is_empty(),
            "expected at least one Write ref for 'cnt', got none; refs = {:?}",
            facts
                .references
                .iter()
                .map(|r| (&r.name, r.role))
                .collect::<Vec<_>>()
        );
    }

    // Test RW3: Call callee is NOT also emitted as a Read.
    #[test]
    fn call_not_also_read() {
        // `func f() { helper() }` → Call ref for "helper", but NOT a Read ref.
        let src = "func f() { helper() }";
        let facts = extract(src, "Sources/F.swift");

        let call_refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Call && r.name == "helper")
            .collect();
        assert!(!call_refs.is_empty(), "expected a Call ref for 'helper'");

        let read_refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Read && r.name == "helper")
            .collect();
        assert!(
            read_refs.is_empty(),
            "helper() must NOT produce a Read ref; got: {read_refs:?}"
        );
    }

    // ── TypeRef tests ────────────────────────────────────────────────────────

    // Test TR1: parameter type emits TypeRef with ParameterType context.
    #[test]
    fn type_ref_parameter_type() {
        let src = "func f(c: Config) {}";
        let facts = extract(src, "Sources/F.swift");

        let type_refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| {
                r.role == RefRole::TypeRef
                    && r.name == "Config"
                    && r.type_ref_ctx == Some(TypeRefContext::ParameterType)
            })
            .collect();
        assert!(
            !type_refs.is_empty(),
            "expected TypeRef 'Config' with ParameterType context; refs = {:?}",
            facts
                .references
                .iter()
                .filter(|r| r.role == RefRole::TypeRef)
                .map(|r| (&r.name, r.type_ref_ctx))
                .collect::<Vec<_>>()
        );
    }

    // Test TR2: property type emits TypeRef with Field context.
    #[test]
    fn type_ref_property_field() {
        let src = "class C { let conf: Config }";
        let facts = extract(src, "Sources/C.swift");

        let type_refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| {
                r.role == RefRole::TypeRef
                    && r.name == "Config"
                    && r.type_ref_ctx == Some(TypeRefContext::Field)
            })
            .collect();
        assert!(
            !type_refs.is_empty(),
            "expected TypeRef 'Config' with Field context; refs = {:?}",
            facts
                .references
                .iter()
                .filter(|r| r.role == RefRole::TypeRef)
                .map(|r| (&r.name, r.type_ref_ctx))
                .collect::<Vec<_>>()
        );
    }

    // Test TR3: generic type argument emits TypeRef with GenericArg context.
    // `func f(xs: Array<Config>) {}` → "Config" with GenericArg.
    #[test]
    fn type_ref_generic_arg() {
        let src = "func f(xs: Array<Config>) {}";
        let facts = extract(src, "Sources/F.swift");

        let type_refs_all: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::TypeRef)
            .map(|r| (&r.name, r.type_ref_ctx))
            .collect();

        let has_config_generic_arg = facts.references.iter().any(|r| {
            r.role == RefRole::TypeRef
                && r.name == "Config"
                && r.type_ref_ctx == Some(TypeRefContext::GenericArg)
        });
        assert!(
            has_config_generic_arg,
            "expected TypeRef 'Config' with GenericArg context; type_refs = {type_refs_all:?}"
        );
    }

    // Test TR4: function return type emits TypeRef with ReturnType context.
    #[test]
    fn type_ref_return_type() {
        let src = "func f() -> Config { fatalError() }";
        let facts = extract(src, "Sources/F.swift");

        let type_refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| {
                r.role == RefRole::TypeRef
                    && r.name == "Config"
                    && r.type_ref_ctx == Some(TypeRefContext::ReturnType)
            })
            .collect();
        assert!(
            !type_refs.is_empty(),
            "expected TypeRef 'Config' with ReturnType context; refs = {:?}",
            facts
                .references
                .iter()
                .filter(|r| r.role == RefRole::TypeRef)
                .map(|r| (&r.name, r.type_ref_ctx))
                .collect::<Vec<_>>()
        );
    }

    // Test RW4: Navigation member is NOT a Read; the base IS a Read.
    #[test]
    fn navigation_member_not_a_read() {
        // `func f(obj: C) { use(obj.field) }` → Read "obj" (the base), no Read "field".
        // "use" is a call; "obj" is read (base of navigation); "field" is a nav member — skip.
        let src = "func f(obj: Cls) { use(obj.field) }";
        let facts = extract(src, "Sources/F.swift");

        // Navigation member "field" must NOT be a Read.
        let field_reads: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Read && r.name == "field")
            .collect();
        assert!(
            field_reads.is_empty(),
            "navigation member 'field' must NOT be a Read ref; got: {field_reads:?}"
        );

        // The base "obj" (≥3 chars) must be a Read.
        let obj_reads: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Read && r.name == "obj")
            .collect();
        assert!(
            !obj_reads.is_empty(),
            "base 'obj' of navigation expression must be a Read ref; refs = {:?}",
            facts
                .references
                .iter()
                .map(|r| (&r.name, r.role))
                .collect::<Vec<_>>()
        );
    }

    // ── Visibility tests ─────────────────────────────────────────────────────

    // Test V1: `public` modifier → Visibility::Public.
    #[test]
    fn visibility_public_modifier() {
        let src = "public class Foo {}";
        let facts = extract(src, "Sources/Foo.swift");
        let foo = by_name(&facts, "Foo").unwrap();
        assert_eq!(
            foo.visibility,
            Visibility::Public,
            "expected Public for 'public class'"
        );
    }

    // Test V2: `open` modifier → Visibility::Public.
    #[test]
    fn visibility_open_modifier() {
        let src = "open class Base {}";
        let facts = extract(src, "Sources/Base.swift");
        let base = by_name(&facts, "Base").unwrap();
        assert_eq!(
            base.visibility,
            Visibility::Public,
            "expected Public for 'open class'"
        );
    }

    // Test V3: `private` modifier → Visibility::Private, symbol IS emitted.
    #[test]
    fn visibility_private_emitted_with_private_tag() {
        let src = "class Outer { private func hidden() {} }";
        let facts = extract(src, "Sources/Outer.swift");
        let hidden = by_name(&facts, "hidden").expect("private func must be emitted");
        assert_eq!(
            hidden.visibility,
            Visibility::Private,
            "expected Private for 'private func'"
        );
    }

    // Test V4: `fileprivate` modifier → Visibility::Private, symbol IS emitted.
    #[test]
    fn visibility_fileprivate_emitted_with_private_tag() {
        let src = "fileprivate struct Internal {}";
        let facts = extract(src, "Sources/Internal.swift");
        let sym = by_name(&facts, "Internal").expect("fileprivate struct must be emitted");
        assert_eq!(
            sym.visibility,
            Visibility::Private,
            "expected Private for 'fileprivate struct'"
        );
    }

    // Test V5: no modifier → Visibility::Internal (Swift implicit default).
    #[test]
    fn visibility_no_modifier_is_internal() {
        let src = "func helper() {}";
        let facts = extract(src, "Sources/Helper.swift");
        let helper = by_name(&facts, "helper").unwrap();
        assert_eq!(
            helper.visibility,
            Visibility::Internal,
            "expected Internal for unmodified func"
        );
    }

    // Test V6: `internal` modifier → Visibility::Internal.
    #[test]
    fn visibility_internal_modifier() {
        let src = "internal class Cache {}";
        let facts = extract(src, "Sources/Cache.swift");
        let cache = by_name(&facts, "Cache").unwrap();
        assert_eq!(
            cache.visibility,
            Visibility::Internal,
            "expected Internal for 'internal class'"
        );
    }

    // Test V7: `package` modifier → Visibility::Internal.
    #[test]
    fn visibility_package_modifier() {
        let src = "package func packageApi() {}";
        let facts = extract(src, "Sources/Api.swift");
        let api = by_name(&facts, "packageApi").unwrap();
        assert_eq!(
            api.visibility,
            Visibility::Internal,
            "expected Internal for 'package func'"
        );
    }

    // Test V8: mixed-visibility class — all members emitted with correct tags.
    #[test]
    fn visibility_mixed_class_all_emitted() {
        let src = r#"
public class Service {
    public func publicOp() {}
    internal func internalOp() {}
    private func privateOp() {}
    fileprivate func fileprivateOp() {}
}
"#;
        let facts = extract(src, "Sources/Service.swift");

        let public_op = by_name(&facts, "publicOp").expect("publicOp must be emitted");
        assert_eq!(public_op.visibility, Visibility::Public);

        let internal_op = by_name(&facts, "internalOp").expect("internalOp must be emitted");
        assert_eq!(internal_op.visibility, Visibility::Internal);

        let private_op = by_name(&facts, "privateOp").expect("privateOp must be emitted");
        assert_eq!(private_op.visibility, Visibility::Private);

        let fileprivate_op =
            by_name(&facts, "fileprivateOp").expect("fileprivateOp must be emitted");
        assert_eq!(fileprivate_op.visibility, Visibility::Private);
    }
}
