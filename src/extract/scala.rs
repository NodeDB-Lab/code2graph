// SPDX-License-Identifier: Apache-2.0

//! Scala extractor — one tree-sitter pass yielding definitions and references.
//!
//! Definitions: type declarations (`class`, `trait`, `object`, `enum`) and
//! their members (`def`, `val`, `var`, `type`). Qualified identity follows
//! `package_clause` declarations, falling back to a path-derived namespace.
//!
//! References: callee identifiers from `call_expression` (free calls and
//! field-expression qualified calls), inheritance via `extends_clause`,
//! `import_declaration` imports, and return/parameter type references.
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
    mark_self_receiver_calls, node_span, node_text, one_line_signature, push_binding,
    push_import_ref, push_ref, push_scope, push_type_ref, simple_type_name,
};

/// Tree-sitter query capturing call-callee identifiers.
///
/// Pattern 1: free call `foo()` — identifier directly as `function` field.
/// Pattern 2: generic-function call `foo[T]()` — generic_function wrapping identifier.
/// Pattern 3: qualified call `obj.foo()` — field_expression as `function` field;
///            the receiver is captured as `@qualifier` and the member name as `@callee`.
/// Pattern 4: qualified generic call `obj.foo[T]()`.
const CALL_QUERY: &str = r#"
[
  (call_expression function: (identifier) @callee)
  (call_expression function: (generic_function function: (identifier) @callee))
  (call_expression function: (field_expression value: (_) @qualifier field: (identifier) @callee))
  (call_expression function: (generic_function function: (field_expression value: (_) @qualifier field: (identifier) @callee)))
]
"#;

/// Method calls whose receiver is written as the `this` keyword (`this.foo()`).
///
/// Scala's `this` parses as a plain `identifier` node (text `"this"`),
/// structurally indistinguishable from any other value receiver, so this
/// query captures `@receiver` and [`mark_self_receiver_calls`] applies a text
/// gate comparing it against the literal `"this"`.
const SELF_CALL_QUERY: &str = r#"
(call_expression function: (field_expression value: (identifier) @receiver field: (identifier) @callee))
"#;

/// Extracts Scala symbols and references.
pub struct ScalaExtractor;

impl Extractor for ScalaExtractor {
    fn lang(&self) -> Language {
        Language::Scala
    }

    fn extract(&self, source: &str, file: &str) -> Result<FileFacts> {
        let ts_language = crate::grammar::scala();
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
            lang: Language::Scala,
        };
        let namespaces = scala_namespaces(&root, bytes, file);

        let defs = collect_symbols(&root, &ctx, &namespaces);
        let def_bindings = definition_bindings(&defs);
        let mut symbols = defs;
        let mod_sym = super::module_symbol(Language::Scala, &namespaces, file, source.len());
        let module_id = mod_sym.id.to_scip_string();
        symbols.push(mod_sym);

        let mut references = collect_call_references(
            &root,
            &ts_language,
            CALL_QUERY,
            Language::Scala,
            bytes,
            file,
        )?;
        mark_self_receiver_calls(
            &root,
            &ts_language,
            SELF_CALL_QUERY,
            Language::Scala,
            bytes,
            &mut references,
            Some("this"),
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
            lang: Language::Scala.as_str().to_owned(),
            symbols,
            references,
            scopes,
            bindings,
            ffi_exports: Vec::new(),
        })
    }
}

// ── Namespace derivation ─────────────────────────────────────────────────────

/// Derive namespace descriptors from `package_clause` nodes, falling back to a
/// path-derived namespace.
///
/// A Scala file may have one or more `package_clause` nodes. Each clause's
/// `name` field can be a dotted identifier like `a.b.c`; we split on `.` and
/// accumulate segments across all clauses.
/// Fallback: strip `.scala`/`.sc`, strip leading `src/`, split on `/`.
fn scala_namespaces(root: &Node, bytes: &[u8], file: &str) -> Vec<String> {
    let mut segments: Vec<String> = Vec::new();

    for child in root.children(&mut root.walk()) {
        if child.kind() != "package_clause" {
            continue;
        }
        if let Some(name_node) = child.child_by_field_name("name") {
            let text = node_text(&name_node, bytes);
            for seg in text.split('.').filter(|s| !s.is_empty()) {
                segments.push(seg.to_owned());
            }
        }
    }

    if !segments.is_empty() {
        return segments;
    }

    // Fallback: derive from file path.
    let p = file
        .strip_suffix(".scala")
        .or_else(|| file.strip_suffix(".sc"))
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
    collect_defs_in(root, ctx, &ns_descriptors, &mut out);
    out
}

/// Collect Scala definition nodes recursively, extending `prefix` as we descend
/// into type bodies.
fn collect_defs_in(node: &Node, ctx: &ExtractCtx, prefix: &[Descriptor], out: &mut Vec<Symbol>) {
    for child in node.children(&mut node.walk()) {
        match child.kind() {
            // Skip into the package body or compilation unit.
            "package_clause" => {
                if let Some(body) = child.child_by_field_name("body") {
                    collect_defs_in(&body, ctx, prefix, out);
                } else {
                    // Package without braces — siblings at the top level continue.
                }
            }

            "class_definition" => {
                emit_type_def(&child, ctx, prefix, SymbolKind::Class, out);
            }
            "trait_definition" => {
                emit_type_def(&child, ctx, prefix, SymbolKind::Trait, out);
            }
            "object_definition" | "package_object" => {
                emit_type_def(&child, ctx, prefix, SymbolKind::Module, out);
            }
            "enum_definition" => {
                emit_enum_def(&child, ctx, prefix, out);
            }
            "function_definition" => {
                emit_function(&child, ctx, prefix, out);
            }
            "val_definition" => {
                emit_val_or_var(&child, ctx, prefix, SymbolKind::Const, out);
            }
            "var_definition" => {
                emit_val_or_var(&child, ctx, prefix, SymbolKind::Static, out);
            }
            "type_definition" => {
                emit_type_alias(&child, ctx, prefix, out);
            }

            _ => {
                // Recurse into any other container (e.g. template_body at top level).
                collect_defs_in(&child, ctx, prefix, out);
            }
        }
    }
}

/// Emit a single type symbol (class/trait/object) and recurse into its body.
fn emit_type_def(
    node: &Node,
    ctx: &ExtractCtx,
    prefix: &[Descriptor],
    kind: SymbolKind,
    out: &mut Vec<Symbol>,
) {
    let Some(name) = name_text(node, ctx.bytes) else {
        return;
    };
    let mut descriptors = prefix.to_vec();
    descriptors.push(Descriptor::Type(name.clone()));
    out.push(make_symbol(
        ctx,
        node,
        name,
        kind,
        read_visibility(node, ctx.bytes),
        descriptors.clone(),
        one_line_signature(node_text(node, ctx.bytes), &['{', ';']),
    ));

    // Recurse into the template body for member definitions.
    if let Some(body) = node.child_by_field_name("body") {
        collect_members_in(&body, ctx, &descriptors, out);
    }
}

/// Emit an enum type and its cases.
fn emit_enum_def(node: &Node, ctx: &ExtractCtx, prefix: &[Descriptor], out: &mut Vec<Symbol>) {
    let Some(name) = name_text(node, ctx.bytes) else {
        return;
    };
    let mut descriptors = prefix.to_vec();
    descriptors.push(Descriptor::Type(name.clone()));
    out.push(make_symbol(
        ctx,
        node,
        name,
        SymbolKind::Enum,
        read_visibility(node, ctx.bytes),
        descriptors.clone(),
        one_line_signature(node_text(node, ctx.bytes), &['{', ';']),
    ));

    // Emit enum cases. They live under `enum_case_definitions` nodes nested in
    // the `enum_body`, and a single `case A, B` puts several `name` fields on one
    // case node — so descend one level and collect every `name` field.
    if let Some(body) = node.child_by_field_name("body") {
        for group in body.children(&mut body.walk()) {
            if group.kind() != "enum_case_definitions" {
                continue;
            }
            for case in group.children(&mut group.walk()) {
                if !matches!(case.kind(), "simple_enum_case" | "full_enum_case") {
                    continue;
                }
                let mut cursor = case.walk();
                for name_node in case
                    .children_by_field_name("name", &mut cursor)
                    .filter(|n| matches!(n.kind(), "identifier" | "operator_identifier"))
                {
                    let case_name = node_text(&name_node, ctx.bytes).to_owned();
                    let mut case_desc = descriptors.clone();
                    case_desc.push(Descriptor::Term(case_name.clone()));
                    out.push(make_symbol(
                        ctx,
                        &case,
                        case_name,
                        SymbolKind::Const,
                        read_visibility(&case, ctx.bytes),
                        case_desc,
                        one_line_signature(node_text(&case, ctx.bytes), &['{', ';', ',']),
                    ));
                }
            }
        }
        // Also descend into body for nested type/method members.
        collect_members_in(&body, ctx, &descriptors, out);
    }
}

/// Collect members inside a `template_body` or `enum_body`.
fn collect_members_in(
    body: &Node,
    ctx: &ExtractCtx,
    type_prefix: &[Descriptor],
    out: &mut Vec<Symbol>,
) {
    for member in body.children(&mut body.walk()) {
        match member.kind() {
            "function_definition" => {
                emit_function(&member, ctx, type_prefix, out);
            }
            "val_definition" => {
                emit_val_or_var(&member, ctx, type_prefix, SymbolKind::Const, out);
            }
            "var_definition" => {
                emit_val_or_var(&member, ctx, type_prefix, SymbolKind::Static, out);
            }
            "type_definition" => {
                emit_type_alias(&member, ctx, type_prefix, out);
            }
            "class_definition" => {
                emit_type_def(&member, ctx, type_prefix, SymbolKind::Class, out);
            }
            "trait_definition" => {
                emit_type_def(&member, ctx, type_prefix, SymbolKind::Trait, out);
            }
            "object_definition" => {
                emit_type_def(&member, ctx, type_prefix, SymbolKind::Module, out);
            }
            "enum_definition" => {
                emit_enum_def(&member, ctx, type_prefix, out);
            }
            // skip simple_enum_case / full_enum_case — handled by emit_enum_def
            _ => {}
        }
    }
}

/// Emit a `function_definition` → `SymbolKind::Method`.
fn emit_function(node: &Node, ctx: &ExtractCtx, prefix: &[Descriptor], out: &mut Vec<Symbol>) {
    let Some(name) = name_text(node, ctx.bytes) else {
        return;
    };
    // Name-only `main` detection (covers `def main` in an `object`).
    let is_main = name == "main";
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
        read_visibility(node, ctx.bytes),
        descriptors,
        one_line_signature(node_text(node, ctx.bytes), &['{', ';', '=']),
    ));
    if is_main {
        if let Some(s) = out.last_mut() {
            s.entry_points.push(EntryPoint::Main);
        }
    }
}

/// Emit a `val_definition` or `var_definition` → `SymbolKind::Const`/`Static`.
///
/// The `pattern` field is typically an `identifier` for the simple case.
/// Destructuring patterns are skipped.
fn emit_val_or_var(
    node: &Node,
    ctx: &ExtractCtx,
    prefix: &[Descriptor],
    kind: SymbolKind,
    out: &mut Vec<Symbol>,
) {
    // The name is in the `pattern` field — try it as an identifier directly,
    // or fall back to checking if the pattern node is an identifier.
    let name: Option<String> = if let Some(pat) = node.child_by_field_name("pattern") {
        if pat.kind() == "identifier" {
            Some(node_text(&pat, ctx.bytes).to_owned())
        } else {
            // Could be a tuple pattern, etc. — skip.
            None
        }
    } else {
        // Try `name` field as fallback.
        field_text(node, "name", ctx.bytes)
    };

    let Some(name) = name else { return };
    let mut descriptors = prefix.to_vec();
    descriptors.push(Descriptor::Term(name.clone()));
    out.push(make_symbol(
        ctx,
        node,
        name,
        kind,
        read_visibility(node, ctx.bytes),
        descriptors,
        one_line_signature(node_text(node, ctx.bytes), &['{', ';', '=']),
    ));
}

/// Emit a `type_definition` → `SymbolKind::TypeAlias`.
fn emit_type_alias(node: &Node, ctx: &ExtractCtx, prefix: &[Descriptor], out: &mut Vec<Symbol>) {
    // `type_definition` has a `name` field = `type_identifier`.
    let Some(name) = field_text(node, "name", ctx.bytes) else {
        return;
    };
    let mut descriptors = prefix.to_vec();
    descriptors.push(Descriptor::Type(name.clone()));
    out.push(make_symbol(
        ctx,
        node,
        name,
        SymbolKind::TypeAlias,
        read_visibility(node, ctx.bytes),
        descriptors,
        one_line_signature(node_text(node, ctx.bytes), &['{', ';', '=']),
    ));
}

/// Get the name text for a definition node.
///
/// Scala definitions use a `name` field that is usually an `identifier` or
/// `operator_identifier`. We simply take whatever text is there.
fn name_text(node: &Node, bytes: &[u8]) -> Option<String> {
    let n = node.child_by_field_name("name")?;
    Some(node_text(&n, bytes).to_owned())
}

/// Read the declared visibility from a Scala definition node.
///
/// Scala's access modifiers live in a `modifiers` named child, which in turn
/// contains an `access_modifier` node. The `access_modifier` is structured as:
///
/// ```text
/// access_modifier
///   "private" | "protected"   ← anonymous keyword token
///   access_qualifier?          ← present when [qualifier] is written
///     identifier               ← the package/this name
/// ```
///
/// Mapping:
/// - `private` (bare)         → `Visibility::Private`
/// - `protected` (bare)       → `Visibility::Protected`
/// - `private[...]`           → `Visibility::Internal`  (scoped/package access)
/// - `protected[...]`         → `Visibility::Internal`
/// - no access modifier       → `Visibility::Public`    (Scala's default)
fn read_visibility(node: &Node, bytes: &[u8]) -> Visibility {
    // Walk unnamed children to find the `modifiers` named child.
    let modifiers = node
        .children(&mut node.walk())
        .find(|c| c.kind() == "modifiers");

    let modifiers = match modifiers {
        Some(m) => m,
        None => return Visibility::Public,
    };

    // Within `modifiers`, look for an `access_modifier` child.
    let access_mod = modifiers
        .children(&mut modifiers.walk())
        .find(|c| c.kind() == "access_modifier");

    let access_mod = match access_mod {
        Some(a) => a,
        None => return Visibility::Public,
    };

    // The first child of `access_modifier` is the anonymous keyword token
    // (`private` or `protected`). We read its text from the source bytes.
    let keyword_node = match access_mod.child(0) {
        Some(n) => n,
        None => return Visibility::Public,
    };
    let keyword = node_text(&keyword_node, bytes);

    // Check whether a `[qualifier]` is present — indicated by an
    // `access_qualifier` named child.
    let has_qualifier = access_mod
        .children(&mut access_mod.walk())
        .any(|c| c.kind() == "access_qualifier");

    if has_qualifier {
        // `private[pkg]`, `protected[pkg]`, `private[this]` → package/scoped.
        Visibility::Internal
    } else {
        match keyword {
            "private" => Visibility::Private,
            "protected" => Visibility::Protected,
            _ => Visibility::Public,
        }
    }
}

// ── Inheritance (extends_clause) ─────────────────────────────────────────────

/// Walk the tree and emit `IsImplementation` references for types listed in an
/// `extends_clause` node (both `class X extends Base with Mixin`).
fn collect_inheritance(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    if node.kind() == "extends_clause" {
        for child in node.named_children(&mut node.walk()) {
            match child.kind() {
                "type_identifier" | "identifier" => {
                    push_ref(
                        out,
                        node_text(&child, bytes),
                        &child,
                        file,
                        RefRole::IsImplementation,
                    );
                }
                // Qualified or generic type like `scala.collection.Seq[T]`.
                "generic_type" | "stable_type_identifier" => {
                    let name = simple_type_name(node_text(&child, bytes), ".");
                    push_ref(out, name, &child, file, RefRole::IsImplementation);
                }
                _ => {}
            }
        }
    }
    for child in node.children(&mut node.walk()) {
        collect_inheritance(&child, bytes, file, out);
    }
}

// ── Imports (import_declaration) ─────────────────────────────────────────────

/// Walk the tree emitting `Import` references for `import_declaration` nodes.
///
/// Handles:
/// - `import a.b.C` — leaf `C`, from_path `a.b`.
/// - `import a.b.{C, D}` — two import refs, each with from_path `a.b`.
/// - Wildcard `import a.b._` / `import a.b.*` — skipped.
/// - Renames `import a.{B => C}` — skipped to avoid ambiguity.
fn collect_imports(
    node: &Node,
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Reference>,
    module_id: &str,
) {
    if node.kind() == "import_declaration" {
        // The `path` field is the dotted path; may end with selectors in braces.
        // We look at named children of the import_declaration to find the structure.
        collect_import_node(node, bytes, file, out, module_id);
        return;
    }
    for child in node.children(&mut node.walk()) {
        collect_imports(&child, bytes, file, out, module_id);
    }
}

fn collect_import_node(
    node: &Node,
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Reference>,
    module_id: &str,
) {
    // Walk children to find a potential import_selectors (braced list).
    // Otherwise, the last identifier is the leaf.
    let mut prefix_parts: Vec<&str> = Vec::new();
    let mut selector_node: Option<Node> = None;
    let mut last_id: Option<Node> = None;

    for child in node.named_children(&mut node.walk()) {
        match child.kind() {
            "identifier" | "operator_identifier" => {
                if let Some(prev) = last_id.take() {
                    prefix_parts.push(node_text(&prev, bytes));
                }
                last_id = Some(child);
            }
            "import_selectors" => {
                selector_node = Some(child);
            }
            _ => {}
        }
    }

    if let Some(sel) = selector_node {
        // Braced selectors: build from_path from prefix_parts + last_id.
        if let Some(last) = last_id {
            prefix_parts.push(node_text(&last, bytes));
        }
        let from_path = prefix_parts.join(".");
        for sel_child in sel.named_children(&mut sel.walk()) {
            match sel_child.kind() {
                "identifier" => {
                    let name = node_text(&sel_child, bytes);
                    if name == "_" || name == "*" {
                        continue;
                    }
                    push_import_ref(out, name, &sel_child, file, module_id, &from_path);
                }
                "import_selector" => {
                    // rename or specific selector
                    if let Some(first) = sel_child.named_children(&mut sel_child.walk()).next() {
                        if first.kind() == "identifier" {
                            let name = node_text(&first, bytes);
                            if name == "_" || name == "*" {
                                continue;
                            }
                            // Check if it's a rename (has `=>` child).
                            let has_rename = sel_child
                                .children(&mut sel_child.walk())
                                .any(|c| c.kind() == "=>");
                            if has_rename {
                                continue; // skip renames
                            }
                            push_import_ref(out, name, &first, file, module_id, &from_path);
                        }
                    }
                }
                _ => {}
            }
        }
    } else if let Some(leaf) = last_id {
        // Simple dotted import: `import a.b.C`
        let leaf_text = node_text(&leaf, bytes);
        if leaf_text == "_" || leaf_text == "*" {
            return; // wildcard import
        }
        let from_path = prefix_parts.join(".");
        push_import_ref(out, leaf_text, &leaf, file, module_id, &from_path);
    }
}

// ── Read / Write references ──────────────────────────────────────────────────

/// Returns `true` when `node` (an `identifier`) is in a position already captured
/// by another collector and must NOT also be emitted as a Read reference.
///
/// Excluded positions:
/// - Call callee: the `function:` field of `call_expression` or the inner
///   `function:` field of `generic_function` inside a `call_expression`.
/// - Declaration names: `name:` field of `function_definition`,
///   `class_definition`, `trait_definition`, `object_definition`,
///   `package_object`, `enum_definition`, `type_definition`.
/// - Val/var binding: `pattern:` field of `val_definition` / `var_definition`
///   (the bound name, not a re-assignment).
/// - Parameter names: `name:` field of `parameter` / `class_parameter`.
/// - Import binding names: direct parent is `import_declaration`,
///   `import_selectors`, or `import_selector` (already captured as
///   `RefRole::Import`).
/// - Member-access leaf: the `field:` field of `field_expression` (e.g. the
///   `.foo` in `obj.foo`) — the receiver (`value:`) IS a read; only the leaf
///   member name is skipped.
/// - Assignment LHS: the `left:` field of `assignment_expression` — handled by
///   `collect_write_references`.
fn is_non_read_position(node: &Node) -> bool {
    let parent = match node.parent() {
        Some(p) => p,
        None => return true, // root — not a read
    };
    match parent.kind() {
        // Call callee — `function:` field of `call_expression`.
        "call_expression" => parent.child_by_field_name("function").as_ref() == Some(node),
        // Inner callee of a generic call `foo[T]()` — generic_function's `function:`.
        "generic_function" => parent.child_by_field_name("function").as_ref() == Some(node),
        // Declaration names.
        "function_definition"
        | "class_definition"
        | "trait_definition"
        | "object_definition"
        | "package_object"
        | "enum_definition"
        | "type_definition" => parent.child_by_field_name("name").as_ref() == Some(node),
        // Val/var binding name (binding introduction, not re-assignment).
        "val_definition" | "var_definition" => {
            parent.child_by_field_name("pattern").as_ref() == Some(node)
        }
        // Parameter bound name.
        "parameter" | "class_parameter" => {
            parent.child_by_field_name("name").as_ref() == Some(node)
        }
        // Import binding — already an Import ref.
        "import_declaration" | "import_selectors" | "import_selector" => true,
        // Member-access leaf (`obj.foo` — skip `foo`, keep `obj`).
        "field_expression" => parent.child_by_field_name("field").as_ref() == Some(node),
        // Assignment LHS — handled by collect_write_references.
        "assignment_expression" => parent.child_by_field_name("left").as_ref() == Some(node),
        _ => false,
    }
}

/// Recursively walk `node` and emit [`RefRole::Read`] references for bare
/// `identifier` nodes used in value/expression positions.
///
/// Skips identifiers that are:
/// - Call callees (already [`RefRole::Call`])
/// - Declaration names (function / class / trait / object / val binding / param)
/// - Import binding names (already [`RefRole::Import`])
/// - Member-access leaves (the `field:` of `field_expression`)
/// - Assignment LHS (handled by [`collect_write_references`])
///
/// Applies [`MIN_REF_LEN`] (same threshold as calls).
fn collect_read_references(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    if node.kind() == "identifier" {
        let name = node_text(node, bytes);
        if name.len() >= MIN_REF_LEN && !is_non_read_position(node) {
            push_ref(out, name, node, file, RefRole::Read);
        }
        // identifiers have no meaningful children; return early.
        return;
    }
    for child in node.children(&mut node.walk()) {
        collect_read_references(&child, bytes, file, out);
    }
}

/// Recursively walk `node` and emit [`RefRole::Write`] references for the
/// bare-identifier LHS of `assignment_expression` nodes (e.g. `x = expr`).
///
/// Note: `val x = …` / `var x = …` definitions are `val_definition` /
/// `var_definition` nodes — distinct from `assignment_expression` — and are
/// deliberately excluded. Only a re-assignment `x = expr` is a Write.
///
/// Member/index LHS (`obj.field = …`) is not covered in v1. Applies [`MIN_REF_LEN`].
fn collect_write_references(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    if node.kind() == "assignment_expression" {
        if let Some(lhs) = node.child_by_field_name("left") {
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

// ── TypeRef edges ────────────────────────────────────────────────────────────

/// Recursively walk `node` emitting [`RefRole::TypeRef`] references for
/// user-defined type names in typed positions.
///
/// Covers: function return types (`return_type` field), parameter types,
/// val/var type annotations (`type` field).
fn collect_type_references(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    match node.kind() {
        "function_definition" => {
            if let Some(ret) = node.child_by_field_name("return_type") {
                type_leaf(&ret, bytes, file, TypeRefContext::ReturnType, out);
            }
        }
        "val_definition" | "var_definition" => {
            if let Some(ty) = node.child_by_field_name("type") {
                type_leaf(&ty, bytes, file, TypeRefContext::Field, out);
            }
        }
        "parameter" | "class_parameter" => {
            if let Some(ty) = node.child_by_field_name("type") {
                type_leaf(&ty, bytes, file, TypeRefContext::ParameterType, out);
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
        // Primitive / builtin scalar types — skip.
        "unit_type" | "tuple_type" | "function_type" => {}
        "type_identifier" | "identifier" => {
            let name = node_text(node, bytes);
            push_type_ref(out, name, node, file, ctx);
        }
        "stable_type_identifier" | "generic_type" => {
            let name = simple_type_name(node_text(node, bytes), ".");
            push_type_ref(out, name, node, file, ctx);
        }
        _ => {
            for child in node.named_children(&mut node.walk()) {
                type_leaf(&child, bytes, file, ctx, out);
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
        "class_definition" | "trait_definition" | "object_definition" | "package_object"
        | "enum_definition" => {
            let type_id = push_scope(scopes, Some(parent_id), node_span(node), ScopeKind::Type);
            if let Some(body) = node.child_by_field_name("body") {
                for child in body.children(&mut body.walk()) {
                    scope_dfs(&child, type_id, scopes);
                }
            }
        }
        "function_definition" => {
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
        "function_definition" => {
            // Collect parameters.
            for child in node.children(&mut node.walk()) {
                if child.kind() == "parameters" || child.kind() == "parameter_clause" {
                    collect_params(&child, bytes, scopes, out);
                }
            }
        }
        "val_definition" | "var_definition" => {
            // Local val/var inside a block scope.
            if let Some(pat) = node.child_by_field_name("pattern") {
                if pat.kind() == "identifier" {
                    let name = node_text(&pat, bytes);
                    let intro = pat.start_byte();
                    if name.len() >= MIN_REF_LEN && innermost_scope(intro, scopes) != Some(0) {
                        push_binding(out, name.to_owned(), intro, BindingKind::Local, scopes);
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
        if child.kind() == "parameter" || child.kind() == "class_parameter" {
            // The name field may be `name` or the first identifier child.
            let name_opt = child
                .child_by_field_name("name")
                .map(|n| node_text(&n, bytes).to_owned());
            if let Some(name) = name_opt {
                let intro = child.start_byte();
                push_binding(out, name, intro, BindingKind::Param, scopes);
            }
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn extract(src: &str, file: &str) -> FileFacts {
        ScalaExtractor.extract(src, file).unwrap()
    }

    fn by_name(facts: &FileFacts, name: &str) -> Option<Symbol> {
        facts.symbols.iter().find(|s| s.name == name).cloned()
    }

    #[test]
    fn main_method_is_entry_point() {
        let facts = extract(
            "object M { def main(args: Array[String]): Unit = {} }",
            "src/M.scala",
        );
        let main = by_name(&facts, "main").unwrap();
        assert!(
            main.entry_points
                .iter()
                .any(|e| matches!(e, EntryPoint::Main))
        );
    }

    // ── Definitions ──────────────────────────────────────────────────────────

    #[test]
    fn class_and_method_get_correct_scip_strings() {
        let src = r#"
package com.example

class SessionManager {
  def validate(token: String): Boolean = true
}
"#;
        let facts = extract(src, "src/com/example/SessionManager.scala");

        let sm = by_name(&facts, "SessionManager").unwrap();
        assert_eq!(sm.kind, SymbolKind::Class);
        assert_eq!(
            sm.id.to_scip_string(),
            "codegraph . . . com/example/SessionManager#"
        );

        let validate = by_name(&facts, "validate").unwrap();
        assert_eq!(validate.kind, SymbolKind::Method);
        assert_eq!(
            validate.id.to_scip_string(),
            "codegraph . . . com/example/SessionManager#validate()."
        );

        assert_eq!(facts.lang, "scala");
    }

    #[test]
    fn package_declaration_yields_namespace_descriptors() {
        let src = r#"
package a.b

class C {}
"#;
        let facts = extract(src, "src/a/b/C.scala");
        let c = by_name(&facts, "C").unwrap();
        assert_eq!(c.id.to_scip_string(), "codegraph . . . a/b/C#");
    }

    #[test]
    fn trait_is_extracted_as_trait_kind() {
        let src = r#"
package io.example

trait Readable {
  def read(): String
}
"#;
        let facts = extract(src, "src/io/example/Readable.scala");
        let t = by_name(&facts, "Readable").unwrap();
        assert_eq!(t.kind, SymbolKind::Trait);
        assert_eq!(
            t.id.to_scip_string(),
            "codegraph . . . io/example/Readable#"
        );
    }

    #[test]
    fn object_is_extracted_as_module_with_nested_member() {
        let src = r#"
package app

object Config {
  val host: String = "localhost"
}
"#;
        let facts = extract(src, "src/app/Config.scala");
        let obj = by_name(&facts, "Config").unwrap();
        assert_eq!(obj.kind, SymbolKind::Module);
        assert_eq!(obj.id.to_scip_string(), "codegraph . . . app/Config#");

        let host = by_name(&facts, "host").unwrap();
        assert_eq!(host.kind, SymbolKind::Const);
        assert_eq!(host.id.to_scip_string(), "codegraph . . . app/Config#host.");
    }

    #[test]
    fn scala3_enum_yields_enum_and_cases() {
        let src = r#"
package colors

enum Color {
  case Red
  case Green
  case Blue
}
"#;
        let facts = extract(src, "src/colors/Color.scala");

        let color = by_name(&facts, "Color").unwrap();
        assert_eq!(color.kind, SymbolKind::Enum);
        assert_eq!(color.id.to_scip_string(), "codegraph . . . colors/Color#");

        let red = by_name(&facts, "Red").unwrap();
        assert_eq!(red.kind, SymbolKind::Const);
        assert_eq!(red.id.to_scip_string(), "codegraph . . . colors/Color#Red.");
    }

    #[test]
    fn type_alias_is_extracted() {
        let src = r#"
package myapp

type Id = Int
"#;
        let facts = extract(src, "src/myapp/Types.scala");
        let id = by_name(&facts, "Id").unwrap();
        assert_eq!(id.kind, SymbolKind::TypeAlias);
        assert_eq!(id.id.to_scip_string(), "codegraph . . . myapp/Id#");
    }

    // ── Self-receiver tests ──────────────────────────────────────────────────

    #[test]
    fn this_receiver_call_marks_self_receiver() {
        let src = r#"
class C {
  def foo(): Unit = {}
  def run(): Unit = { this.foo() }
}
"#;
        let facts = extract(src, "src/C.scala");
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
  def foo(): Unit = {}
  def run(obj: C): Unit = { obj.foo() }
}
"#;
        let facts = extract(src, "src/C.scala");
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

    // ── References ───────────────────────────────────────────────────────────

    #[test]
    fn parameter_type_yields_type_reference() {
        let src = r#"
package myapp

class Handler {
  def run(req: Request): Unit = {}
}
"#;
        let facts = extract(src, "src/myapp/Handler.scala");
        assert!(
            facts
                .references
                .iter()
                .any(|r| r.role == RefRole::TypeRef && r.name == "Request"),
            "expected a TypeRef to parameter type 'Request': {:?}",
            facts
                .references
                .iter()
                .map(|r| (&r.role, &r.name))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn qualified_call_captures_qualifier() {
        let src = r#"
class Client {
  def run(): Unit = {
    val svc = new Service()
    svc.process()
  }
}
"#;
        let facts = extract(src, "src/Client.scala");

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
    fn import_produces_import_reference_with_from_path() {
        let src = r#"
import scala.collection.mutable.ArrayBuffer

class Foo {}
"#;
        let facts = extract(src, "src/Foo.scala");
        let import_refs: Vec<&Reference> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .collect();

        let arr = import_refs
            .iter()
            .find(|r| r.name == "ArrayBuffer")
            .expect("expected import ref for 'ArrayBuffer'");
        assert_eq!(
            arr.from_path,
            Some("scala.collection.mutable".to_owned()),
            "from_path should be 'scala.collection.mutable', got {:?}",
            arr.from_path
        );
    }

    // ── Read / Write references ──────────────────────────────────────────────

    #[test]
    fn reassignment_emits_write_and_reads_for_rhs() {
        let src = r#"
object O {
  def m(): Unit = {
    var total = 0
    val bonus = 10
    total = total + bonus
  }
}
"#;
        let facts = extract(src, "src/O.scala");
        let refs = &facts.references;

        // `total =` on the LHS of assignment_expression → Write.
        assert!(
            refs.iter()
                .any(|r| r.role == RefRole::Write && r.name == "total"),
            "expected Write ref for 'total': {:?}",
            refs.iter().map(|r| (&r.role, &r.name)).collect::<Vec<_>>()
        );
        // `bonus` on the RHS → Read.
        assert!(
            refs.iter()
                .any(|r| r.role == RefRole::Read && r.name == "bonus"),
            "expected Read ref for 'bonus': {:?}",
            refs.iter().map(|r| (&r.role, &r.name)).collect::<Vec<_>>()
        );
        // `total` on the RHS of `total + bonus` → Read.
        let read_totals: Vec<_> = refs
            .iter()
            .filter(|r| r.role == RefRole::Read && r.name == "total")
            .collect();
        assert!(
            !read_totals.is_empty(),
            "expected at least one Read ref for 'total' (RHS usage)"
        );
    }

    #[test]
    fn val_definition_does_not_emit_write_for_binding_name() {
        let src = r#"
object O {
  def m(): Unit = {
    val result = compute()
  }
  def compute(): Int = 42
}
"#;
        let facts = extract(src, "src/O.scala");
        assert!(
            !facts
                .references
                .iter()
                .any(|r| r.role == RefRole::Write && r.name == "result"),
            "val binding 'result' must NOT emit a Write ref: {:?}",
            facts
                .references
                .iter()
                .map(|r| (&r.role, &r.name))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn free_call_arg_is_read_but_callee_is_not() {
        let src = r#"
object O {
  def m(): Unit = {
    val config = Config()
    logger(config)
  }
  def logger(x: Any): Unit = {}
}
"#;
        let facts = extract(src, "src/O.scala");
        // `config` passed as argument → Read.
        assert!(
            facts
                .references
                .iter()
                .any(|r| r.role == RefRole::Read && r.name == "config"),
            "expected Read ref for argument 'config': {:?}",
            facts
                .references
                .iter()
                .map(|r| (&r.role, &r.name))
                .collect::<Vec<_>>()
        );
        // `logger` is the callee → Call, NOT Read.
        assert!(
            !facts
                .references
                .iter()
                .any(|r| r.role == RefRole::Read && r.name == "logger"),
            "callee 'logger' must NOT emit a Read ref: {:?}",
            facts
                .references
                .iter()
                .map(|r| (&r.role, &r.name))
                .collect::<Vec<_>>()
        );
    }

    // ── Visibility ───────────────────────────────────────────────────────────

    #[test]
    fn plain_def_has_public_visibility() {
        let src = r#"
package app

class Svc {
  def open(): Unit = {}
}
"#;
        let facts = extract(src, "src/app/Svc.scala");
        let sym = by_name(&facts, "open").unwrap();
        assert_eq!(
            sym.visibility,
            Visibility::Public,
            "plain `def` must be Public (Scala default)"
        );
    }

    #[test]
    fn private_def_has_private_visibility() {
        let src = r#"
package app

class Svc {
  private def secret(): Unit = {}
}
"#;
        let facts = extract(src, "src/app/Svc.scala");
        let sym = by_name(&facts, "secret").unwrap();
        assert_eq!(
            sym.visibility,
            Visibility::Private,
            "`private def` must be Private"
        );
    }

    #[test]
    fn protected_def_has_protected_visibility() {
        let src = r#"
package app

class Svc {
  protected def hook(): Unit = {}
}
"#;
        let facts = extract(src, "src/app/Svc.scala");
        let sym = by_name(&facts, "hook").unwrap();
        assert_eq!(
            sym.visibility,
            Visibility::Protected,
            "`protected def` must be Protected"
        );
    }

    #[test]
    fn private_qualified_def_has_internal_visibility() {
        let src = r#"
package app

class Svc {
  private[app] def pkg(): Unit = {}
}
"#;
        let facts = extract(src, "src/app/Svc.scala");
        let sym = by_name(&facts, "pkg").unwrap();
        assert_eq!(
            sym.visibility,
            Visibility::Internal,
            "`private[pkg] def` must be Internal"
        );
    }

    #[test]
    fn field_expression_receiver_is_read_but_leaf_is_not() {
        let src = r#"
object O {
  def m(): Unit = {
    var value = 0
    val source = Src()
    value = source.field
  }
  class Src { val field: Int = 1 }
}
"#;
        let facts = extract(src, "src/O.scala");
        // `source` is the receiver (value: field of field_expression) → Read.
        assert!(
            facts
                .references
                .iter()
                .any(|r| r.role == RefRole::Read && r.name == "source"),
            "expected Read ref for receiver 'source': {:?}",
            facts
                .references
                .iter()
                .map(|r| (&r.role, &r.name))
                .collect::<Vec<_>>()
        );
        // `field` is the member-access leaf → must NOT be a Read.
        assert!(
            !facts
                .references
                .iter()
                .any(|r| r.role == RefRole::Read && r.name == "field"),
            "member-access leaf 'field' must NOT emit a Read ref: {:?}",
            facts
                .references
                .iter()
                .map(|r| (&r.role, &r.name))
                .collect::<Vec<_>>()
        );
    }
}
