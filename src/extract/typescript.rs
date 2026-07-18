// SPDX-License-Identifier: Apache-2.0

//! TypeScript extractor — one tree-sitter pass yielding definitions and references.
//!
//! Definitions: ALL top-level declarations, tagged with their real [`Visibility`]:
//! exported declarations (`export function/class/interface/type/enum/const`,
//! including `export default function/class`) → [`Visibility::Public`]; bare
//! (non-exported) top-level declarations → [`Visibility::Private`].
//! Qualified identity follows the file's module path (`src/auth/jwt.ts` →
//! namespaces `src`,`auth`,`jwt`), so a symbol is `…/jwt/validateToken().`.
//! References: callee identifiers of `call_expression` nodes.
//!
//! `.tsx`/`.jsx` files are parsed with the TSX grammar, otherwise TypeScript.
//! Emits neutral [`FileFacts`] — no storage entries, no source bodies.
//!
//! The extraction core (`extract_ecmascript`) is shared with the JavaScript
//! extractor, which reuses the TypeScript grammar (a superset of JavaScript);
//! the two differ only in their language tag.

use tree_sitter::{Node, Parser};

use crate::error::{CodegraphError, Result};
use crate::graph::types::{
    Binding, BindingKind, ByteSpan, FileFacts, RefRole, Reference, Scope, ScopeId, ScopeKind,
    Symbol, SymbolKind, TypeRefContext, Visibility,
};
use crate::lang::Language;
use crate::symbol::Descriptor;

#[cfg(feature = "sql")]
use super::emit_embedded_sql_refs;
use super::{
    BindingRules, ExtractCtx, Extractor, MIN_REF_LEN, attach_reference_scopes, child_text,
    collect_call_references, definition_bindings, import_bindings, make_symbol,
    mark_self_receiver_calls, node_span, node_text, one_line_signature, push_binding, push_ref,
    push_scope, push_type_ref,
};

/// Tree-sitter query capturing call-callee identifiers.
const CALL_QUERY: &str = r#"
(call_expression
  function: [
    (identifier) @callee
    (member_expression property: (property_identifier) @callee)
  ]
)
"#;

/// Method calls whose receiver is written as the `this` keyword (`this.foo()`).
///
/// Deliberately a *separate* query from [`CALL_QUERY`] rather than an extra
/// alternation branch there, mirroring the Rust extractor's `SELF_CALL_QUERY`:
/// `member_expression object: (this) …` structurally matches the same
/// `member_expression property: (property_identifier) @callee` branch
/// [`CALL_QUERY`] already has, so folding it in would double-emit. Run as a
/// second pass and correlate back to [`CALL_QUERY`]'s output by the
/// `property_identifier`'s byte offset (identical node in both queries).
const SELF_CALL_QUERY: &str = r#"
(call_expression
  function: (member_expression
    object: (this)
    property: (property_identifier) @callee))
"#;

/// Extracts TypeScript symbols and references.
pub struct TypeScriptExtractor;

impl Extractor for TypeScriptExtractor {
    fn lang(&self) -> Language {
        Language::TypeScript
    }

    fn extract(&self, source: &str, file: &str) -> Result<FileFacts> {
        extract_ecmascript(source, file, Language::TypeScript, None)
    }

    fn extract_with_bindings(
        &self,
        source: &str,
        file: &str,
        rules: &BindingRules,
    ) -> Result<FileFacts> {
        extract_ecmascript(source, file, Language::TypeScript, Some(rules))
    }
}

/// Shared TypeScript/JavaScript extraction core. The TypeScript grammar is a
/// superset of JavaScript, so both extractors parse with it; `lang` selects the
/// language tag and SCIP scheme. `.tsx`/`.jsx` files use the TSX grammar.
pub(super) fn extract_ecmascript(
    source: &str,
    file: &str,
    lang: Language,
    rules: Option<&BindingRules>,
) -> Result<FileFacts> {
    let ts_language = if file.ends_with(".tsx") || file.ends_with(".jsx") {
        crate::grammar::tsx()
    } else {
        crate::grammar::typescript()
    };
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
    let namespaces = module_namespaces(file);

    let ctx = ExtractCtx { bytes, file, lang };
    let defs = collect_symbols(&root, &ctx, &namespaces);
    let def_bindings = definition_bindings(&defs);
    let mut symbols = defs;
    let mod_sym = super::module_symbol(lang, &namespaces, file, source.len());
    let module_id = mod_sym.id.to_scip_string();
    symbols.push(mod_sym);
    let mut references =
        collect_call_references(&root, &ts_language, CALL_QUERY, lang, bytes, file)?;
    mark_self_receiver_calls(
        &root,
        &ts_language,
        SELF_CALL_QUERY,
        lang,
        bytes,
        &mut references,
        None,
    )?;
    collect_inheritance(&root, bytes, file, &mut references);
    collect_imports(&root, bytes, file, &mut references, &module_id);
    collect_type_references(&root, bytes, file, &mut references);
    collect_read_references(&root, bytes, file, &mut references);
    collect_write_references(&root, bytes, file, &mut references);

    #[cfg(feature = "sql")]
    if let Some(rules) = rules {
        collect_query_bindings(&root, bytes, file, lang, rules, &mut references);
    }
    #[cfg(not(feature = "sql"))]
    let _ = rules;

    let scopes = collect_scopes(&root, source.len());
    attach_reference_scopes(&mut references, &scopes);
    let mut bindings = collect_bindings(&root, bytes, &scopes);
    bindings.extend(def_bindings);
    bindings.extend(import_bindings(&references, &scopes));

    Ok(FileFacts {
        file: file.to_owned(),
        lang: lang.as_str().to_owned(),
        symbols,
        references,
        scopes,
        bindings,
        ffi_exports: Vec::new(),
    })
}

/// Module path (namespace descriptors) from a source file path: all path
/// segments, with the final file extension stripped from the last segment.
pub(super) fn module_namespaces(file: &str) -> Vec<String> {
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

/// Strips a single trailing conventional TS/JS module extension from an
/// import specifier, e.g. `./commands.ts` → `./commands`. Mirrors the
/// extension-stripping [`module_namespaces`] applies to a file's own path,
/// so an import `from_path` lands on the same extension-free segments as
/// the imported file's namespace chain (required for scope-tier suffix
/// matching to succeed). Leaves bare package specifiers (`react`,
/// `@scope/pkg`) and extensionless paths (`./foo`) untouched, since their
/// trailing segment never matches a known extension.
fn strip_module_extension(path: &str) -> &str {
    const KNOWN_EXTENSIONS: &[&str] = &["ts", "tsx", "mts", "cts", "js", "jsx", "mjs", "cjs"];
    match path.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() && KNOWN_EXTENSIONS.contains(&ext) => stem,
        _ => path,
    }
}

/// Bare top-level declaration node kinds that are emitted with
/// [`Visibility::Private`] (non-exported, module-scoped).
const BARE_DECL_KINDS: &[&str] = &[
    "function_declaration",
    "generator_function_declaration",
    "class_declaration",
    "abstract_class_declaration",
    "interface_declaration",
    "type_alias_declaration",
    "enum_declaration",
    "lexical_declaration",
    "variable_declaration",
];

fn collect_symbols(root: &Node, ctx: &ExtractCtx, namespaces: &[String]) -> Vec<Symbol> {
    let mut out = Vec::new();
    for stmt in root.children(&mut root.walk()) {
        match stmt.kind() {
            "export_statement" => {
                // Exported declarations are direct children of the export statement.
                // The span covers the full `export ...` statement node.
                for decl in stmt.children(&mut stmt.walk()) {
                    emit_declaration(
                        DeclSite { decl, span: stmt },
                        ctx,
                        namespaces,
                        Visibility::Public,
                        &mut out,
                    );
                }
            }
            kind if BARE_DECL_KINDS.contains(&kind) => {
                // Non-exported top-level declaration: the declaration node is
                // its own span node (there is no enclosing export_statement).
                emit_declaration(
                    DeclSite {
                        decl: stmt,
                        span: stmt,
                    },
                    ctx,
                    namespaces,
                    Visibility::Private,
                    &mut out,
                );
            }
            _ => {}
        }
    }
    out
}

/// A declaration node together with the node whose span/line locates it. For an
/// exported declaration `span` is the enclosing `export_statement`; for a bare
/// declaration `span` is the declaration itself. Named fields (rather than a
/// same-typed `(Node, Node)` tuple) so the two can't be transposed by accident.
struct DeclSite<'t> {
    decl: Node<'t>,
    span: Node<'t>,
}

/// Append symbol(s) for one declaration node (a `lexical_declaration` or
/// `variable_declaration` may yield several). `visibility` reflects whether the
/// declaration was exported (`Public`) or bare (`Private`).
fn emit_declaration(
    site: DeclSite,
    ctx: &ExtractCtx,
    namespaces: &[String],
    visibility: Visibility,
    out: &mut Vec<Symbol>,
) {
    let decl = &site.decl;
    let span_node = &site.span;
    let push = |out: &mut Vec<Symbol>, name: String, kind: SymbolKind, leaf: Descriptor| {
        let mut descriptors: Vec<Descriptor> = namespaces
            .iter()
            .cloned()
            .map(Descriptor::Namespace)
            .collect();
        descriptors.push(leaf);
        let signature = one_line_signature(node_text(decl, ctx.bytes), &['{']);
        out.push(make_symbol(
            ctx,
            span_node,
            name,
            kind,
            visibility,
            descriptors,
            signature,
        ));
    };

    match decl.kind() {
        "function_declaration" | "generator_function_declaration" => {
            if let Some(n) = child_text(decl, "identifier", ctx.bytes) {
                push(
                    out,
                    n.clone(),
                    SymbolKind::Function,
                    Descriptor::Method {
                        name: n,
                        disambiguator: crate::symbol::MethodDisambiguator::empty(),
                    },
                );
            }
        }
        "class_declaration" | "abstract_class_declaration" => {
            emit_named(decl, ctx.bytes, SymbolKind::Class, out, &push);
            // Members are only meaningful for a named class; an anonymous
            // `export default class { ... }` has no `Type` descriptor to
            // qualify them under, so it is skipped (mirrors `emit_named`'s guard).
            if let Some(class_name) = child_text(decl, "type_identifier", ctx.bytes) {
                collect_class_members(decl, ctx, namespaces, &class_name, out);
            }
        }
        "interface_declaration" => emit_named(decl, ctx.bytes, SymbolKind::Interface, out, &push),
        "type_alias_declaration" => emit_named(decl, ctx.bytes, SymbolKind::TypeAlias, out, &push),
        "enum_declaration" => {
            if let Some(n) = child_text(decl, "identifier", ctx.bytes) {
                push(out, n.clone(), SymbolKind::Enum, Descriptor::Type(n));
            }
        }
        "lexical_declaration" => {
            for vd in decl.children(&mut decl.walk()) {
                if vd.kind() != "variable_declarator" {
                    continue;
                }
                if let Some(n) = child_text(&vd, "identifier", ctx.bytes) {
                    push(out, n.clone(), SymbolKind::Const, Descriptor::Term(n));
                }
            }
        }
        "variable_declaration" => {
            // `var` declarations: same structure as `lexical_declaration`.
            for vd in decl.children(&mut decl.walk()) {
                if vd.kind() != "variable_declarator" {
                    continue;
                }
                if let Some(n) = child_text(&vd, "identifier", ctx.bytes) {
                    push(out, n.clone(), SymbolKind::Const, Descriptor::Term(n));
                }
            }
        }
        _ => {}
    }
}

/// Emit a type-named declaration (class/interface/type-alias) named by a
/// `type_identifier`.
fn emit_named(
    decl: &Node,
    bytes: &[u8],
    kind: SymbolKind,
    out: &mut Vec<Symbol>,
    push: &impl Fn(&mut Vec<Symbol>, String, SymbolKind, Descriptor),
) {
    if let Some(n) = child_text(decl, "type_identifier", bytes) {
        push(out, n.clone(), kind, Descriptor::Type(n));
    }
}

/// Build the descriptor path for a class member: namespaces + `Type(type_name)`
/// + `leaf`. Mirrors the Rust/Java extractors' member-descriptor helper.
fn member_descriptors(namespaces: &[String], type_name: &str, leaf: Descriptor) -> Vec<Descriptor> {
    let mut descriptors: Vec<Descriptor> = namespaces
        .iter()
        .cloned()
        .map(Descriptor::Namespace)
        .collect();
    descriptors.push(Descriptor::Type(type_name.to_owned()));
    descriptors.push(leaf);
    descriptors
}

/// Emit a [`SymbolKind::Method`] symbol for each `method_definition` in a
/// class's body (static/async/get/set/`constructor` are all `method_definition`
/// nodes and are handled uniformly).
///
/// Skips members whose name is not a plain identifier — `computed_property_name`
/// (`[Symbol.iterator]()`), `string` (`"lit"()`), or `number` (`123()`) — since
/// none of those produce a well-formed SCIP method descriptor.
///
/// Arrow-function class fields (`foo = () => {}`, a `public_field_definition`)
/// and interface `method_signature` members are intentionally out of scope here;
/// only real `method_definition` members are covered.
///
/// Visibility: an explicit `accessibility_modifier` child (`public`/`private`/
/// `protected`) is honored; absent that, TS/JS members are public by default.
fn collect_class_members(
    class_decl: &Node,
    ctx: &ExtractCtx,
    namespaces: &[String],
    class_name: &str,
    out: &mut Vec<Symbol>,
) {
    let Some(body) = class_decl.child_by_field_name("body") else {
        return;
    };
    for member in body.children(&mut body.walk()) {
        if member.kind() != "method_definition" {
            continue;
        }
        let Some(name_node) = member.child_by_field_name("name") else {
            continue;
        };
        if !matches!(
            name_node.kind(),
            "property_identifier" | "private_property_identifier"
        ) {
            continue;
        }
        let name = node_text(&name_node, ctx.bytes).to_owned();
        let visibility = member_visibility(&member, ctx.bytes);
        let descriptors = member_descriptors(
            namespaces,
            class_name,
            Descriptor::Method {
                name: name.clone(),
                disambiguator: crate::symbol::MethodDisambiguator::empty(),
            },
        );
        let signature = one_line_signature(node_text(&member, ctx.bytes), &['{']);
        out.push(make_symbol(
            ctx,
            &member,
            name,
            SymbolKind::Method,
            visibility,
            descriptors,
            signature,
        ));
    }
}

/// Read a class member's visibility from its `accessibility_modifier` child, if
/// any. TS/JS class members are public by default (unlike Java's package-private
/// default), so an absent modifier maps to [`Visibility::Public`], not
/// [`Visibility::Internal`].
fn member_visibility(member: &Node, bytes: &[u8]) -> Visibility {
    member
        .children(&mut member.walk())
        .find(|c| c.kind() == "accessibility_modifier")
        .map_or(Visibility::Public, |m| match node_text(&m, bytes) {
            "private" => Visibility::Private,
            "protected" => Visibility::Protected,
            _ => Visibility::Public,
        })
}

/// Recursively walk `node` collecting `Inherit` references for every
/// `class_declaration` and `interface_declaration` in the tree (including nested
/// classes).
///
/// Tree-sitter node shape (TypeScript / TSX grammar):
/// - `class_declaration` → optional `class_heritage` child
///   - `extends_clause` → field `value` (the superclass expression)
///   - `implements_clause` → named children: `type_identifier | generic_type |
///     nested_type_identifier`
/// - `interface_declaration` → optional `extends_type_clause` child
///   - named children: `type_identifier | generic_type | nested_type_identifier`
fn collect_inheritance(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    match node.kind() {
        "class_declaration" => {
            // Locate the `class_heritage` child (if any).
            if let Some(heritage) = node
                .children(&mut node.walk())
                .find(|c| c.kind() == "class_heritage")
            {
                for clause in heritage.children(&mut heritage.walk()) {
                    match clause.kind() {
                        "extends_clause" => {
                            // The superclass is the `value` field.
                            if let Some(value) = clause.child_by_field_name("value") {
                                super::push_ref(
                                    out,
                                    super::simple_type_name(node_text(&value, bytes), "."),
                                    &value,
                                    file,
                                    RefRole::IsImplementation,
                                );
                            }
                        }
                        "implements_clause" => {
                            // Each named child is an implemented interface type.
                            for type_node in clause.children(&mut clause.walk()) {
                                if type_node.is_named()
                                    && matches!(
                                        type_node.kind(),
                                        "type_identifier"
                                            | "generic_type"
                                            | "nested_type_identifier"
                                    )
                                {
                                    super::push_ref(
                                        out,
                                        super::simple_type_name(node_text(&type_node, bytes), "."),
                                        &type_node,
                                        file,
                                        RefRole::IsImplementation,
                                    );
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        "interface_declaration" => {
            // Locate the `extends_type_clause` child (if any).
            if let Some(extends_clause) = node
                .children(&mut node.walk())
                .find(|c| c.kind() == "extends_type_clause")
            {
                for type_node in extends_clause.children(&mut extends_clause.walk()) {
                    if type_node.is_named()
                        && matches!(
                            type_node.kind(),
                            "type_identifier" | "generic_type" | "nested_type_identifier"
                        )
                    {
                        super::push_ref(
                            out,
                            super::simple_type_name(node_text(&type_node, bytes), "."),
                            &type_node,
                            file,
                            RefRole::IsImplementation,
                        );
                    }
                }
            }
        }
        _ => {}
    }

    // Recurse into all children so nested classes are covered.
    for child in node.children(&mut node.walk()) {
        collect_inheritance(&child, bytes, file, out);
    }
}

/// Recursively walk `node` collecting `Import` references for every
/// `import_statement` in the tree.
///
/// Tree-sitter node shape (TypeScript / TSX grammar):
/// ```text
/// import_statement
///   source: string            ← module path string — IGNORED
///   import_clause
///     identifier              ← default import: `import Foo from "x"`
///     named_imports
///       import_specifier
///         name: identifier    ← named import binding: `import { A } from "x"`
///         alias: identifier   ← IGNORED (`import { A as B }`)
///     namespace_import        ← `import * as ns from "x"` — SKIPPED entirely
/// ```
///
/// Only the binding name at the call-site is emitted; module sources and
/// aliases are deliberately not recorded.
fn collect_imports(
    node: &Node,
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Reference>,
    module_id: &str,
) {
    if node.kind() == "import_statement" {
        // Extract the from-path once from the `source` field (a string literal).
        // The raw text includes surrounding quotes; strip both styles.
        let from_path = node
            .child_by_field_name("source")
            .map(|n| {
                let raw = super::node_text(&n, bytes);
                let unquoted = raw.trim_matches('"').trim_matches('\'');
                strip_module_extension(unquoted).to_owned()
            })
            .unwrap_or_default();

        // Locate the `import_clause` child (may be absent for bare `import "x"`).
        if let Some(clause) = node
            .children(&mut node.walk())
            .find(|c| c.kind() == "import_clause")
        {
            for child in clause.children(&mut clause.walk()) {
                match child.kind() {
                    // Default import: `import Foo from "x"`
                    "identifier" => {
                        super::push_import_ref(
                            out,
                            super::node_text(&child, bytes),
                            &child,
                            file,
                            module_id,
                            &from_path,
                        );
                    }
                    // Named imports: `import { A, B as C } from "x"`
                    "named_imports" => {
                        for specifier in child.children(&mut child.walk()) {
                            if specifier.kind() != "import_specifier" {
                                continue;
                            }
                            // `name` field is the real (original) name, not the alias.
                            if let Some(name_node) = specifier.child_by_field_name("name") {
                                if name_node.kind() == "identifier" {
                                    super::push_import_ref(
                                        out,
                                        super::node_text(&name_node, bytes),
                                        &name_node,
                                        file,
                                        module_id,
                                        &from_path,
                                    );
                                }
                                // string-named imports (exotic) → skip silently
                            }
                        }
                    }
                    // Namespace import: `import * as ns from "x"` → skip
                    "namespace_import" => {}
                    _ => {}
                }
            }
        }
        // Do not recurse further into `import_statement`; it cannot contain
        // nested import statements.
        return;
    }

    // Recurse into all other nodes so top-level and module-scoped imports are covered.
    for child in node.children(&mut node.walk()) {
        collect_imports(&child, bytes, file, out, module_id);
    }
}

// ── Edge richness: TypeRef / Read / Write ────────────────────────────────────

/// Recursively walk `node` and emit [`RefRole::TypeRef`] references for every
/// type-identifier that appears in a typed annotation position.
///
/// Covered positions (TypeScript / TSX grammar):
/// - `required_parameter` / `optional_parameter` `type:` field → `ParameterType`
/// - `function_declaration` / `function_signature` / `method_definition` /
///   `arrow_function` `return_type:` field → `ReturnType`
/// - `public_field_definition` / `property_signature` `type:` field → `Field`
/// - Inside a `type_arguments` node (generic arguments) → `GenericArg`
/// - Any other `type_identifier` in a `type_annotation` → `Other`
///
/// For `generic_type` nodes the head `type_identifier` (the `name` field or
/// first named child) takes the outer context, then `type_arguments` children
/// are visited with `GenericArg`.
fn collect_type_references(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    // Helper: emit a type ref from a (possibly generic or nested) type node at
    // the given context. If the node is a `generic_type`, recurse into its
    // type_arguments with GenericArg context. If it is a `nested_type_identifier`
    // take the `right` field as the leaf name.
    fn emit_type_node(
        node: &Node,
        bytes: &[u8],
        file: &str,
        ctx: TypeRefContext,
        out: &mut Vec<Reference>,
    ) {
        match node.kind() {
            "type_identifier" => {
                let name = node_text(node, bytes);
                push_type_ref(out, name, node, file, ctx);
            }
            "generic_type" => {
                // The `name` field (or first named child) is the outer type name.
                if let Some(head) = node.child_by_field_name("name") {
                    emit_type_node(&head, bytes, file, ctx, out);
                }
                // Type arguments are generic params.
                if let Some(args) = node.child_by_field_name("type_arguments") {
                    for child in args.named_children(&mut args.walk()) {
                        emit_type_node(&child, bytes, file, TypeRefContext::GenericArg, out);
                    }
                }
            }
            "nested_type_identifier" => {
                // e.g. `ns.Type` — take the `right` (leaf) field.
                if let Some(right) = node.child_by_field_name("right") {
                    emit_type_node(&right, bytes, file, ctx, out);
                }
            }
            // Unwrap a bare `type_annotation` wrapper (the `: T` node itself).
            "type_annotation" => {
                for child in node.named_children(&mut node.walk()) {
                    emit_type_node(&child, bytes, file, ctx, out);
                }
            }
            // Union / intersection / parenthesized types — recurse so we catch
            // all leaves (e.g. `A | B`, `(C & D)`).
            "union_type" | "intersection_type" | "parenthesized_type" => {
                for child in node.named_children(&mut node.walk()) {
                    emit_type_node(&child, bytes, file, ctx, out);
                }
            }
            // Array / readonly wrappers: recurse into the element type.
            "array_type" | "readonly_type" => {
                for child in node.named_children(&mut node.walk()) {
                    emit_type_node(&child, bytes, file, TypeRefContext::Other, out);
                }
            }
            _ => {}
        }
    }

    match node.kind() {
        // Parameters: `(c: Config)` — type is a `type_annotation` child at field `type`.
        "required_parameter" | "optional_parameter" => {
            if let Some(ann) = node.child_by_field_name("type") {
                // The annotation node may be `type_annotation` wrapping the type,
                // or the type node directly depending on grammar version.
                for child in ann.named_children(&mut ann.walk()) {
                    emit_type_node(&child, bytes, file, TypeRefContext::ParameterType, out);
                }
            }
        }
        // Return types: `function f(): Config`.
        "function_declaration" | "function_signature" | "method_definition" | "arrow_function" => {
            if let Some(ret) = node.child_by_field_name("return_type") {
                for child in ret.named_children(&mut ret.walk()) {
                    emit_type_node(&child, bytes, file, TypeRefContext::ReturnType, out);
                }
            }
            // Recurse into function body to catch nested functions.
            for child in node.children(&mut node.walk()) {
                collect_type_references(&child, bytes, file, out);
            }
            return; // avoid double-recurse at the bottom
        }
        // Field / property types: `field: Type;`
        "public_field_definition" | "property_signature" => {
            if let Some(typ) = node.child_by_field_name("type") {
                for child in typ.named_children(&mut typ.walk()) {
                    emit_type_node(&child, bytes, file, TypeRefContext::Field, out);
                }
            }
        }
        _ => {}
    }

    for child in node.children(&mut node.walk()) {
        collect_type_references(&child, bytes, file, out);
    }
}

/// Node kinds whose `name:` / `function:` child is a declaration binding, not a
/// read. Used by `collect_read_references` to skip declaration-name positions.
const DECL_KINDS_WITH_NAME: &[&str] = &[
    "function_declaration",
    "function_expression",
    "function_signature",
    "class_declaration",
    "method_definition",
    "generator_function_declaration",
    "generator_function",
];

/// Returns `true` when `node` (an `identifier`) is in a position that is already
/// captured by another collector (call callee, declaration name, import binding,
/// parameter pattern, variable declarator name) and must NOT also be emitted as
/// a Read reference.
fn is_non_read_position(node: &Node) -> bool {
    let parent = match node.parent() {
        Some(p) => p,
        None => return true, // root — not a read
    };
    match parent.kind() {
        // Call callee: `helper()` — function field of call_expression.
        "call_expression" => parent.child_by_field_name("function").as_ref() == Some(node),
        // Declaration names (function/class/method/generator).
        kind if DECL_KINDS_WITH_NAME.contains(&kind) => {
            parent.child_by_field_name("name").as_ref() == Some(node)
        }
        // Variable declarator LHS: `const x = …`
        "variable_declarator" => parent.child_by_field_name("name").as_ref() == Some(node),
        // Parameter pattern (the binding name, not the default expression).
        "required_parameter" | "optional_parameter" => {
            parent.child_by_field_name("pattern").as_ref() == Some(node)
        }
        // Import specifier / clause / namespace — already Import refs.
        "import_clause" => true,
        "import_specifier" => true,
        // Shorthand property in an object literal: `{ foo }` — `foo` is both
        // key and value; treat as a read (the value side). The grammar represents
        // this as `shorthand_property_identifier`, not `identifier`, so this arm
        // is defensive only.
        "pair" => {
            // `pair` has key: and value: fields; skip only the key.
            parent.child_by_field_name("key").as_ref() == Some(node)
        }
        // Assignment LHS — handled by collect_write_references.
        "assignment_expression" | "augmented_assignment_expression" => {
            parent.child_by_field_name("left").as_ref() == Some(node)
        }
        _ => false,
    }
}

/// Recursively walk `node` and emit [`RefRole::Read`] references for bare
/// `identifier` nodes used in value/expression positions.
///
/// Skips identifiers that are:
/// - Call callees (already [`RefRole::Call`])
/// - Declaration names (function / class / variable declarator / param pattern)
/// - Import binding names (already [`RefRole::Import`])
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
/// bare-identifier LHS of `assignment_expression` and
/// `augmented_assignment_expression` nodes (e.g. `x = 5`, `x += 1`).
///
/// Member / subscript LHS (`obj.prop = …`, `arr[i] = …`) are not covered in
/// v1 — only bare identifiers.  Applies [`MIN_REF_LEN`].
fn collect_write_references(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    if matches!(
        node.kind(),
        "assignment_expression" | "augmented_assignment_expression"
    ) {
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

// ── Query-binding scan (cross-artifact code→SQL edges) ───────────────────────

/// Recursively walk `node` looking for call sites matching one of `rules`'s
/// constructs for `lang` (e.g. `knex.raw`), and emit a [`RefRole::TypeRef`]
/// reference (`cross_artifact: true`) for every SQL entity (table/view) named
/// in the embedded SQL argument.
///
/// Never fails extraction: a construct that doesn't match the expected shape
/// (unexpected argument kind, no string literal, malformed SQL, …) is simply
/// skipped.
#[cfg(feature = "sql")]
fn collect_query_bindings(
    node: &Node,
    bytes: &[u8],
    file: &str,
    lang: Language,
    rules: &BindingRules,
    out: &mut Vec<Reference>,
) {
    if node.kind() == "call_expression" {
        if let Some(func) = node.child_by_field_name("function") {
            if func.kind() == "member_expression" {
                let callee = node_text(&func, bytes);
                for rule in rules.for_language(lang) {
                    if rule.construct != callee {
                        continue;
                    }
                    let Some(arguments) = node.child_by_field_name("arguments") else {
                        continue;
                    };
                    let Some(arg) = arguments
                        .named_children(&mut arguments.walk())
                        .nth(rule.sql_arg)
                    else {
                        continue;
                    };
                    emit_embedded_sql_refs(&arg, "string_fragment", bytes, file, out);
                }
            }
        }
    }
    for child in node.children(&mut node.walk()) {
        collect_query_bindings(&child, bytes, file, lang, rules, out);
    }
}

// ── Scope tree (Tier-B) ──────────────────────────────────────────────────────

/// ECMAScript function-like node kinds — each opens a `Function` scope.
const FN_KINDS: &[&str] = &[
    "function_declaration",
    "function_expression",
    "arrow_function",
    "method_definition",
    "generator_function_declaration",
    "generator_function",
];

/// Build the lexical scope tree for one TS/JS file.
///
/// `scopes[0]` is the file-root `Module` scope. ECMAScript is block-scoped:
/// every function-like node opens a `Function` scope and every standalone
/// `statement_block` (an `if`/`for`/`while` body or a bare block) opens a
/// `Block` scope. A `class` body opens no scope — like Python's LEGB, a method's
/// unqualified name lookup does not see class members.
///
/// Known v1 boundary: `var` is function-scoped but is recorded as a block-scoped
/// local (treated like `let`); hoisting of `var` is not modelled.
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
    if FN_KINDS.contains(&node.kind()) {
        let fn_id = push_scope(
            scopes,
            Some(parent_id),
            node_span(node),
            ScopeKind::Function,
        );
        // Recurse the body. For a brace body, descend into its children directly
        // so the body `statement_block` does not open a redundant nested scope.
        if let Some(body) = node.child_by_field_name("body") {
            if body.kind() == "statement_block" {
                for child in body.children(&mut body.walk()) {
                    scope_dfs(&child, fn_id, scopes);
                }
            } else {
                scope_dfs(&body, fn_id, scopes); // arrow with an expression body
            }
        }
    } else if node.kind() == "statement_block" {
        let block_id = push_scope(scopes, Some(parent_id), node_span(node), ScopeKind::Block);
        for child in node.children(&mut node.walk()) {
            scope_dfs(&child, block_id, scopes);
        }
    } else {
        for child in node.children(&mut node.walk()) {
            scope_dfs(&child, parent_id, scopes);
        }
    }
}

// ── Bindings (Tier-B) ────────────────────────────────────────────────────────

/// Collect parameter and variable [`Binding`]s for one TS/JS file.
///
/// Covers function parameters and `let`/`const`/`var` declarators (each a bare
/// `identifier` name; destructuring patterns are deferred). Top-level definitions
/// and imports are added by the caller from the shared helpers.
fn collect_bindings(root: &Node, bytes: &[u8], scopes: &[Scope]) -> Vec<Binding> {
    let mut out = Vec::new();
    collect_bindings_dfs(root, bytes, scopes, &mut out);
    out
}

fn collect_bindings_dfs(node: &Node, bytes: &[u8], scopes: &[Scope], out: &mut Vec<Binding>) {
    if FN_KINDS.contains(&node.kind()) {
        if let Some(params) = node.child_by_field_name("parameters") {
            collect_params(&params, bytes, scopes, out);
        } else if let Some(p) = node.child_by_field_name("parameter") {
            // single-identifier arrow parameter, e.g. `x => …`
            if p.kind() == "identifier" {
                push_binding(
                    out,
                    node_text(&p, bytes).to_owned(),
                    p.start_byte(),
                    BindingKind::Param,
                    scopes,
                );
            }
        }
        for child in node.children(&mut node.walk()) {
            collect_bindings_dfs(&child, bytes, scopes, out);
        }
    } else if node.kind() == "variable_declarator" {
        // `let`/`const` (lexical_declaration) and `var` (variable_declaration)
        // both nest a `variable_declarator` with a `name` field.
        if let Some(name) = node.child_by_field_name("name") {
            if name.kind() == "identifier" {
                push_binding(
                    out,
                    node_text(&name, bytes).to_owned(),
                    name.start_byte(),
                    BindingKind::Local,
                    scopes,
                );
            }
        }
        for child in node.children(&mut node.walk()) {
            collect_bindings_dfs(&child, bytes, scopes, out);
        }
    } else {
        for child in node.children(&mut node.walk()) {
            collect_bindings_dfs(&child, bytes, scopes, out);
        }
    }
}

/// Emit a [`BindingKind::Param`] for each parameter in a `formal_parameters`
/// node, unwrapping the typed `required_parameter`/`optional_parameter` forms.
fn collect_params(params: &Node, bytes: &[u8], scopes: &[Scope], out: &mut Vec<Binding>) {
    for child in params.named_children(&mut params.walk()) {
        let ident = match child.kind() {
            "identifier" => Some(child),
            "required_parameter" | "optional_parameter" => child.child_by_field_name("pattern"),
            _ => None,
        };
        if let Some(id) = ident {
            if id.kind() == "identifier" {
                push_binding(
                    out,
                    node_text(&id, bytes).to_owned(),
                    id.start_byte(),
                    BindingKind::Param,
                    scopes,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_exported_decls() {
        let src = "\
export function validateToken(tok: string): boolean { return helper(); }
export class Config {}
export interface Options { timeout: number; }
export const MAX = 3;
function internal() {}
";
        let facts = TypeScriptExtractor.extract(src, "src/auth/jwt.ts").unwrap();
        let by_name = |n: &str| facts.symbols.iter().find(|s| s.name == n).cloned();

        let vt = by_name("validateToken").unwrap();
        assert_eq!(
            vt.id.to_scip_string(),
            "codegraph . . . src/auth/jwt/validateToken()."
        );
        assert_eq!(vt.kind, SymbolKind::Function);
        assert_eq!(vt.visibility, Visibility::Public);

        let cfg = by_name("Config").unwrap();
        assert_eq!(cfg.kind, SymbolKind::Class);
        assert_eq!(cfg.visibility, Visibility::Public);

        let opts = by_name("Options").unwrap();
        assert_eq!(opts.kind, SymbolKind::Interface);
        assert_eq!(opts.visibility, Visibility::Public);

        let max = by_name("MAX").unwrap();
        assert_eq!(max.kind, SymbolKind::Const);
        assert_eq!(max.visibility, Visibility::Public);

        // Non-exported declarations are now emitted with Visibility::Private.
        let internal = by_name("internal").expect("internal must now be emitted as Private");
        assert_eq!(internal.kind, SymbolKind::Function);
        assert_eq!(internal.visibility, Visibility::Private);
    }

    #[test]
    fn bare_decl_visibility_private() {
        // Bare (non-exported) top-level declarations → Visibility::Private.
        let src = "\
function g() {}
const X = 1;
";
        let facts = TypeScriptExtractor.extract(src, "src/mod.ts").unwrap();
        let by_name = |n: &str| facts.symbols.iter().find(|s| s.name == n).cloned();

        let g = by_name("g").expect("bare function g must be emitted");
        assert_eq!(g.kind, SymbolKind::Function);
        assert_eq!(g.visibility, Visibility::Private);

        let x = by_name("X").expect("bare const X must be emitted");
        assert_eq!(x.kind, SymbolKind::Const);
        assert_eq!(x.visibility, Visibility::Private);
    }

    #[test]
    fn exported_decl_visibility_public() {
        // Exported declarations → Visibility::Public.
        let src = "\
export function f() {}
export const Y = 2;
";
        let facts = TypeScriptExtractor.extract(src, "src/mod.ts").unwrap();
        let by_name = |n: &str| facts.symbols.iter().find(|s| s.name == n).cloned();

        let f = by_name("f").expect("exported function f must be emitted");
        assert_eq!(f.kind, SymbolKind::Function);
        assert_eq!(f.visibility, Visibility::Public);

        let y = by_name("Y").expect("exported const Y must be emitted");
        assert_eq!(y.kind, SymbolKind::Const);
        assert_eq!(y.visibility, Visibility::Public);
    }

    #[test]
    fn default_export_function_is_named() {
        let facts = TypeScriptExtractor
            .extract("export default function App() {}", "src/App.tsx")
            .unwrap();
        // 1 declared symbol + 1 module symbol
        assert_eq!(facts.symbols.len(), 2);
        let app = facts.symbols.iter().find(|s| s.name == "App").unwrap();
        assert_eq!(app.id.to_scip_string(), "codegraph . . . src/App/App().");
    }

    #[test]
    fn emits_function_block_scopes_and_bindings() {
        let src = "export function run(arg: number) {\n  const local = 1;\n  if (arg) { helper(local); }\n}\n";
        let facts = TypeScriptExtractor.extract(src, "src/main.ts").unwrap();
        assert!(
            facts.scopes.iter().any(|s| s.kind == ScopeKind::Function),
            "expected a Function scope"
        );
        assert!(
            facts.scopes.iter().any(|s| s.kind == ScopeKind::Block),
            "expected a Block scope (the if body)"
        );
        let has = |name: &str, kind: BindingKind| {
            facts
                .bindings
                .iter()
                .any(|b| b.name == name && b.kind == kind)
        };
        assert!(has("arg", BindingKind::Param), "param binding missing");
        assert!(
            has("local", BindingKind::Local),
            "const local binding missing"
        );
        assert!(has("run", BindingKind::Definition), "def binding missing");
    }

    #[test]
    fn extracts_call_references() {
        let facts = TypeScriptExtractor
            .extract(
                "function main() { validateToken('t'); helper(); }",
                "src/main.ts",
            )
            .unwrap();
        let names: Vec<&str> = facts.references.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"validateToken"));
        assert!(names.contains(&"helper"));
    }

    // ── Inheritance tests ────────────────────────────────────────────────────

    #[test]
    fn ts_class_extends_and_implements() {
        let src = "class Sub extends Base implements Iface {}";
        let facts = TypeScriptExtractor.extract(src, "src/sub.ts").unwrap();
        let inherit_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            inherit_names.contains(&"Base"),
            "expected 'Base' in {inherit_names:?}"
        );
        assert!(
            inherit_names.contains(&"Iface"),
            "expected 'Iface' in {inherit_names:?}"
        );
    }

    #[test]
    fn ts_interface_extends_multiple() {
        let src = "interface I extends A, B {}";
        let facts = TypeScriptExtractor.extract(src, "src/i.ts").unwrap();
        let inherit_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            inherit_names.contains(&"A"),
            "expected 'A' in {inherit_names:?}"
        );
        assert!(
            inherit_names.contains(&"B"),
            "expected 'B' in {inherit_names:?}"
        );
    }

    #[test]
    fn ts_class_extends_qualified_name() {
        let src = "class C extends ns.Base {}";
        let facts = TypeScriptExtractor.extract(src, "src/c.ts").unwrap();
        let inherit_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            inherit_names.contains(&"Base"),
            "expected leaf 'Base' from 'ns.Base' in {inherit_names:?}"
        );
    }

    #[test]
    fn js_class_extends_base() {
        // JavaScript routes through the same extract_ecmascript core; verify
        // that inheritance edges are emitted for .js files too.
        use crate::extract::Extractor as _;
        use crate::extract::JavaScriptExtractor;
        let src = "class Sub extends Base {}";
        let facts = JavaScriptExtractor.extract(src, "src/sub.js").unwrap();
        let inherit_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            inherit_names.contains(&"Base"),
            "expected 'Base' in JS inherit refs: {inherit_names:?}"
        );
    }

    // ── Import reference tests ───────────────────────────────────────────────

    #[test]
    fn ts_named_import_emits_import_ref() {
        // `import { Service } from "./svc";` → one Import ref `Service`
        let src = r#"import { Service } from "./svc";"#;
        let facts = TypeScriptExtractor.extract(src, "src/client.ts").unwrap();
        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(
            import_names,
            vec!["Service"],
            "expected exactly [Service], got {import_names:?}"
        );
    }

    #[test]
    fn ts_default_import_emits_import_ref() {
        // `import Foo from "./foo";` → Import ref `Foo`
        let src = r#"import Foo from "./foo";"#;
        let facts = TypeScriptExtractor.extract(src, "src/use.ts").unwrap();
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
    }

    #[test]
    fn ts_named_import_with_alias_emits_real_name() {
        // `import { A, B as C } from "x";` → Import refs `A` and `B` (not alias `C`)
        let src = r#"import { A, B as C } from "x";"#;
        let facts = TypeScriptExtractor.extract(src, "src/aliases.ts").unwrap();
        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            import_names.contains(&"A"),
            "expected 'A' in import refs: {import_names:?}"
        );
        assert!(
            import_names.contains(&"B"),
            "expected 'B' (real name) in import refs: {import_names:?}"
        );
        assert!(
            !import_names.contains(&"C"),
            "alias 'C' must NOT appear in import refs: {import_names:?}"
        );
    }

    #[test]
    fn ts_namespace_import_emits_no_import_refs() {
        // `import * as ns from "x";` → NO Import refs
        let src = r#"import * as ns from "x";"#;
        let facts = TypeScriptExtractor.extract(src, "src/ns.ts").unwrap();
        let import_refs: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            import_refs.is_empty(),
            "namespace import must produce no Import refs, got {import_refs:?}"
        );
    }

    #[test]
    fn js_named_import_emits_import_ref() {
        // JavaScript (.js) through the shared extract_ecmascript core.
        // `import { thing } from "./m";` → Import ref `thing`
        use crate::extract::Extractor as _;
        use crate::extract::JavaScriptExtractor;
        let src = r#"import { thing } from "./m";"#;
        let facts = JavaScriptExtractor.extract(src, "src/consumer.js").unwrap();
        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            import_names.contains(&"thing"),
            "expected 'thing' in JS import refs: {import_names:?}"
        );
    }

    #[test]
    fn ts_import_refs_carry_source_module() {
        // `import { Service } from "./svc";` in src/auth/client.ts → all
        // Import refs carry the SCIP module id of src/auth/client.
        let src = r#"import { Service } from "./svc";"#;
        let file = "src/auth/client.ts";
        let facts = TypeScriptExtractor.extract(src, file).unwrap();

        let namespaces = module_namespaces(file);
        let expected_module_id =
            crate::extract::module_symbol(Language::TypeScript, &namespaces, file, src.len())
                .id
                .to_scip_string();

        let import_refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .collect();
        assert!(!import_refs.is_empty(), "expected at least one Import ref");
        for r in &import_refs {
            assert_eq!(
                r.source_module,
                Some(expected_module_id.clone()),
                "Import ref '{}' should carry source_module = {:?}",
                r.name,
                expected_module_id
            );
        }
    }

    // --- from_path tests ---

    #[test]
    fn ts_named_import_carries_from_path() {
        // `import { Service } from "./svc";` → from_path == "./svc" (quotes stripped)
        let src = r#"import { Service } from "./svc";"#;
        let facts = TypeScriptExtractor.extract(src, "src/client.ts").unwrap();
        let r = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Import && r.name == "Service")
            .expect("expected Import ref for 'Service'");
        assert_eq!(
            r.from_path,
            Some("./svc".to_owned()),
            "from_path should be './svc', got {:?}",
            r.from_path
        );
    }

    #[test]
    fn ts_import_from_path_strips_ts_extension() {
        // `import { X } from "./mod.ts";` → from_path == "./mod" (extension
        // stripped so it matches module_namespaces' extension-free segments).
        let src = r#"import { X } from "./mod.ts";"#;
        let facts = TypeScriptExtractor.extract(src, "src/client.ts").unwrap();
        let r = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Import && r.name == "X")
            .expect("expected Import ref for 'X'");
        assert_eq!(
            r.from_path,
            Some("./mod".to_owned()),
            "from_path should be './mod' (extension stripped), got {:?}",
            r.from_path
        );
    }

    #[test]
    fn js_import_from_path_strips_js_extension() {
        // Same extraction path is shared with JS; `.js` should strip too.
        use crate::extract::Extractor as _;
        use crate::extract::JavaScriptExtractor;
        let src = r#"import { X } from "./mod.js";"#;
        let facts = JavaScriptExtractor.extract(src, "src/client.js").unwrap();
        let r = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Import && r.name == "X")
            .expect("expected Import ref for 'X'");
        assert_eq!(
            r.from_path,
            Some("./mod".to_owned()),
            "from_path should be './mod' (extension stripped), got {:?}",
            r.from_path
        );
    }

    #[test]
    fn ts_import_from_path_without_extension_is_unchanged() {
        // `import { X } from "./mod";` (no extension) stays as-is.
        let src = r#"import { X } from "./mod";"#;
        let facts = TypeScriptExtractor.extract(src, "src/client.ts").unwrap();
        let r = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Import && r.name == "X")
            .expect("expected Import ref for 'X'");
        assert_eq!(r.from_path, Some("./mod".to_owned()));
    }

    #[test]
    fn ts_import_from_path_bare_package_specifier_is_unchanged() {
        // Bare package specifiers with dotted names (e.g. `lodash.debounce`)
        // must not be mistaken for a file extension.
        let src = r#"import { X } from "lodash.debounce";"#;
        let facts = TypeScriptExtractor.extract(src, "src/client.ts").unwrap();
        let r = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Import && r.name == "X")
            .expect("expected Import ref for 'X'");
        assert_eq!(r.from_path, Some("lodash.debounce".to_owned()));
    }

    // ── Edge richness: TypeRef / Read / Write ────────────────────────────────

    #[test]
    fn ts_param_type_ref_emitted() {
        // `function f(c: Config) {}` → TypeRef "Config" with ParameterType ctx.
        let src = "function f(c: Config) {}";
        let facts = TypeScriptExtractor.extract(src, "src/main.ts").unwrap();
        let r = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::TypeRef && r.name == "Config")
            .expect("expected TypeRef ref for 'Config'");
        assert_eq!(
            r.type_ref_ctx,
            Some(TypeRefContext::ParameterType),
            "expected ParameterType ctx, got {:?}",
            r.type_ref_ctx
        );
    }

    #[test]
    fn ts_return_type_ref_emitted() {
        // `function f(): Config { return null; }` → TypeRef "Config" with ReturnType ctx.
        let src = "function f(): Config { return null; }";
        let facts = TypeScriptExtractor.extract(src, "src/main.ts").unwrap();
        let r = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::TypeRef && r.name == "Config")
            .expect("expected TypeRef ref for 'Config'");
        assert_eq!(
            r.type_ref_ctx,
            Some(TypeRefContext::ReturnType),
            "expected ReturnType ctx, got {:?}",
            r.type_ref_ctx
        );
    }

    #[test]
    fn ts_read_ref_emitted_for_use_not_declaration() {
        // `function f() { const base = 1; return base; }`
        // → Read ref for the `base` in `return base`; the declarator name must NOT be a Read.
        let src = "function f() { const base = 1; return base; }";
        let facts = TypeScriptExtractor.extract(src, "src/main.ts").unwrap();
        let read_refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Read && r.name == "base")
            .collect();
        // There must be at least one Read ref (the use in `return base`).
        assert!(
            !read_refs.is_empty(),
            "expected at least one Read ref for 'base', got none"
        );
        // The declaration `const base = 1` starts before the `return` statement.
        // Verify that at least one Read ref byte offset is AFTER the `=` (i.e. not the decl).
        // In `function f() { const base = 1; return base; }` the return keyword starts at ~35.
        let use_ref = read_refs
            .iter()
            .find(|r| r.occ.byte > 20)
            .expect("expected Read ref for 'base' in the return statement (byte > 20)");
        assert!(
            use_ref.occ.byte > 20,
            "Read ref should be at the use site, not the declaration"
        );
    }

    #[test]
    fn ts_write_ref_emitted_for_assignment() {
        // `function f() { let xxx = 0; xxx = 5; }` → Write ref for `xxx = 5`.
        let src = "function f() { let xxx = 0; xxx = 5; }";
        let facts = TypeScriptExtractor.extract(src, "src/main.ts").unwrap();
        let write_refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Write && r.name == "xxx")
            .collect();
        assert!(
            !write_refs.is_empty(),
            "expected at least one Write ref for 'xxx', got none — all refs: {:?}",
            facts
                .references
                .iter()
                .map(|r| (&r.name, r.role))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn ts_call_not_also_read() {
        // `helper()` → a Call ref for "helper", but NOT also a Read ref.
        let src = "function run() { helper(); }";
        let facts = TypeScriptExtractor.extract(src, "src/main.ts").unwrap();
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

    #[test]
    fn ts_property_access_not_a_read_of_property() {
        // `obj.foo` → no Read ref named "foo" (property_identifier, not identifier).
        // A Read ref for `obj` is acceptable.
        let src = "function run() { return obj.foo; }";
        let facts = TypeScriptExtractor.extract(src, "src/main.ts").unwrap();
        let foo_reads: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Read && r.name == "foo")
            .collect();
        assert!(
            foo_reads.is_empty(),
            "property 'foo' in member_expression must NOT be a Read ref; got: {foo_reads:?}"
        );
    }

    // ── Query-binding scan (cross-artifact code→SQL edges) ───────────────────

    #[cfg(feature = "sql")]
    #[test]
    fn knex_raw_call_emits_cross_artifact_typeref_ts() {
        let src = r#"function run() { knex.raw("SELECT id FROM users"); }"#;
        let facts = TypeScriptExtractor
            .extract_with_bindings(src, "src/app.ts", &BindingRules::with_defaults())
            .unwrap();
        let r = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::TypeRef && r.name == "users" && r.cross_artifact)
            .expect("expected a cross-artifact TypeRef reference for 'users'");
        assert!(
            r.occ.byte >= src.find("SELECT").unwrap(),
            "reference byte offset should be inside the SQL string"
        );
    }

    #[cfg(feature = "sql")]
    #[test]
    fn knex_raw_call_emits_cross_artifact_typeref_js() {
        use crate::extract::JavaScriptExtractor;

        let src = r#"function run() { knex.raw("SELECT id FROM users"); }"#;
        let facts = JavaScriptExtractor
            .extract_with_bindings(src, "src/app.js", &BindingRules::with_defaults())
            .unwrap();
        let r = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::TypeRef && r.name == "users" && r.cross_artifact)
            .expect("expected a cross-artifact TypeRef reference for 'users'");
        assert!(
            r.occ.byte >= src.find("SELECT").unwrap(),
            "reference byte offset should be inside the SQL string"
        );
    }

    #[cfg(feature = "sql")]
    #[test]
    fn empty_binding_rules_yield_no_cross_artifact_reference_ts() {
        let src = r#"function run() { knex.raw("SELECT id FROM users"); }"#;
        let file = "src/app.ts";

        let facts_empty = TypeScriptExtractor
            .extract_with_bindings(src, file, &BindingRules::empty())
            .unwrap();
        assert!(
            !facts_empty.references.iter().any(|r| r.cross_artifact),
            "empty BindingRules must yield no cross_artifact references"
        );

        let facts_plain = TypeScriptExtractor.extract(src, file).unwrap();
        assert!(
            !facts_plain.references.iter().any(|r| r.cross_artifact),
            "plain extract() must yield no cross_artifact references"
        );
    }

    #[test]
    fn self_receiver_method_call_is_marked_self_receiver() {
        // `this.foo()` — member_expression object: (this) arm → leaf "foo",
        // qualifier None, self_receiver true.
        let src = "class Person { caller() { this.foo(); } }";
        let facts = TypeScriptExtractor.extract(src, "src/main.ts").unwrap();
        let r = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Call && r.name == "foo")
            .expect("expected a Call ref for 'foo'");
        assert!(
            r.self_receiver,
            "this.foo() should have self_receiver == true"
        );
        assert_eq!(
            r.qualifier, None,
            "this.foo() should still have qualifier == None, got {:?}",
            r.qualifier
        );
    }

    #[test]
    fn non_self_method_call_is_not_marked_self_receiver() {
        // `x.foo()` on a local variable — must NOT be marked self_receiver.
        let src = "class Person { caller(x) { x.foo(); } }";
        let facts = TypeScriptExtractor.extract(src, "src/main.ts").unwrap();
        let r = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Call && r.name == "foo")
            .expect("expected a Call ref for 'foo'");
        assert!(
            !r.self_receiver,
            "x.foo() must not have self_receiver == true"
        );
    }

    // ── Class member (method) symbol tests ───────────────────────────────────

    #[test]
    fn class_methods_emit_method_symbols() {
        let src = "class Config { save() {} load() {} }";
        let facts = TypeScriptExtractor.extract(src, "src/config.ts").unwrap();

        let cfg = facts
            .symbols
            .iter()
            .find(|s| s.name == "Config")
            .expect("Config Type symbol must still be emitted");
        assert_eq!(cfg.kind, SymbolKind::Class);

        let save = facts
            .symbols
            .iter()
            .find(|s| s.name == "save")
            .expect("expected a 'save' Method symbol");
        assert_eq!(save.kind, SymbolKind::Method);
        assert_eq!(
            save.id.to_scip_string(),
            "codegraph . . . src/config/Config#save()."
        );
        assert_eq!(save.visibility, Visibility::Public);

        let load = facts
            .symbols
            .iter()
            .find(|s| s.name == "load")
            .expect("expected a 'load' Method symbol");
        assert_eq!(load.kind, SymbolKind::Method);
        assert_eq!(
            load.id.to_scip_string(),
            "codegraph . . . src/config/Config#load()."
        );
    }

    #[test]
    fn js_class_method_emits_method_symbol() {
        // JavaScript routes through the shared extract_ecmascript core.
        use crate::extract::JavaScriptExtractor;

        let src = "class C { m() {} }";
        let facts = JavaScriptExtractor.extract(src, "src/c.js").unwrap();
        let m = facts
            .symbols
            .iter()
            .find(|s| s.name == "m")
            .expect("expected an 'm' Method symbol via the JS extractor");
        assert_eq!(m.kind, SymbolKind::Method);
        assert_eq!(m.id.to_scip_string(), "codegraph . . . src/c/C#m().");
    }

    #[test]
    fn class_static_and_accessor_methods_emit_method_symbols() {
        let src = "class S { static make() {} get val() {} }";
        let facts = TypeScriptExtractor.extract(src, "src/s.ts").unwrap();

        let make = facts
            .symbols
            .iter()
            .find(|s| s.name == "make")
            .expect("expected a static 'make' Method symbol");
        assert_eq!(make.kind, SymbolKind::Method);

        let val = facts
            .symbols
            .iter()
            .find(|s| s.name == "val")
            .expect("expected a 'val' accessor Method symbol");
        assert_eq!(val.kind, SymbolKind::Method);
    }

    #[test]
    fn non_identifier_method_names_are_not_emitted() {
        // Computed and literal member names must not leak in as malformed
        // Method symbols.
        let src = r#"class X { ["a"+"b"]() {} "lit"() {} }"#;
        let facts = TypeScriptExtractor.extract(src, "src/x.ts").unwrap();

        let method_count = facts
            .symbols
            .iter()
            .filter(|s| s.kind == SymbolKind::Method)
            .count();
        assert_eq!(
            method_count, 0,
            "computed/string-named members must not be emitted as Method symbols"
        );
    }

    #[test]
    fn anonymous_default_class_emits_no_type_or_member_symbols() {
        // `export default class { ... }` has no name — neither the class Type
        // symbol nor its members can be emitted.
        let src = "export default class { m() {} }";
        let facts = TypeScriptExtractor.extract(src, "src/anon.ts").unwrap();

        assert!(
            !facts.symbols.iter().any(|s| s.kind == SymbolKind::Class),
            "anonymous default class must not emit a Type symbol"
        );
        assert!(
            !facts.symbols.iter().any(|s| s.kind == SymbolKind::Method),
            "anonymous default class members must not be emitted"
        );
    }

    #[test]
    fn js_self_receiver_method_call_is_marked_self_receiver() {
        // Same as the TS test above, but through the JavaScript extractor —
        // proves the shared `extract_ecmascript` core covers JS too.
        use crate::extract::JavaScriptExtractor;

        let src = "class Person { caller() { this.foo(); } }";
        let facts = JavaScriptExtractor.extract(src, "src/main.js").unwrap();
        let r = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Call && r.name == "foo")
            .expect("expected a Call ref for 'foo'");
        assert!(
            r.self_receiver,
            "this.foo() should have self_receiver == true"
        );
    }
}
