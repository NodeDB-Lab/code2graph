// SPDX-License-Identifier: Apache-2.0

//! Java extractor — one tree-sitter pass yielding definitions and references.
//!
//! Definitions: **public** top-level type declarations (`class`, `interface`,
//! `enum`, `record`, `@interface`) and their public members (methods,
//! constructors, fields). Interface and annotation-type members are treated as
//! implicitly public. Qualified identity follows the `package` declaration;
//! files without a package declaration fall back to a path-derived namespace.
//! References: callee identifiers of `method_invocation` and
//! `object_creation_expression` nodes.
//!
//! Emits neutral [`FileFacts`] — no storage entries, no source bodies.

use tree_sitter::{Language as TsLanguage, Node, Parser};

use crate::error::{CodegraphError, Result};
use crate::graph::types::{
    Binding, BindingKind, ByteSpan, FileFacts, RefRole, Reference, Scope, ScopeId, ScopeKind,
    Symbol, SymbolKind,
};
use crate::lang::Language;
use crate::symbol::{Descriptor, SymbolId};

use super::{
    Extractor, attach_reference_scopes, collect_call_references, definition_bindings, field_text,
    import_bindings, innermost_scope, node_span, node_text, one_line_signature, push_binding,
    push_ref, push_scope,
};

/// Tree-sitter query capturing call-callee identifiers.
const CALL_QUERY: &str = r#"
[
  (method_invocation name: (identifier) @callee)
  (object_creation_expression type: (type_identifier) @callee)
]
"#;

/// Extracts Java symbols and references.
pub struct JavaExtractor;

impl Extractor for JavaExtractor {
    fn lang(&self) -> Language {
        Language::Java
    }

    fn extract(&self, source: &str, file: &str) -> Result<FileFacts> {
        let ts_language = TsLanguage::from(tree_sitter_java::LANGUAGE);
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
        let namespaces = java_namespaces(&root, bytes, file);

        let defs = collect_symbols(&root, bytes, file, &namespaces);
        let def_bindings = definition_bindings(&defs);
        let mut symbols = defs;
        let mod_sym = super::module_symbol(Language::Java, &namespaces, file, source.len());
        let module_id = mod_sym.id.to_scip_string();
        symbols.push(mod_sym);
        let mut references =
            collect_call_references(&root, &ts_language, CALL_QUERY, Language::Java, bytes, file)?;
        collect_inheritance(&root, bytes, file, &mut references);
        collect_imports(&root, bytes, file, &mut references, &module_id);
        collect_jni_natives(&root, bytes, file, &namespaces, &mut references);

        let scopes = collect_scopes(&root, source.len());
        attach_reference_scopes(&mut references, &scopes);
        let mut bindings = collect_bindings(&root, bytes, &scopes);
        bindings.extend(def_bindings);
        bindings.extend(import_bindings(&references, &scopes));

        Ok(FileFacts {
            file: file.to_owned(),
            lang: Language::Java.as_str().to_owned(),
            symbols,
            references,
            scopes,
            bindings,
            ffi_exports: Vec::new(),
        })
    }
}

/// Derive namespace descriptors from the `package` declaration, falling back to
/// path-derived segments when no `package` statement is present.
///
/// With a package: `com.example.auth` → `["com", "example", "auth"]`.
/// Without: `src/com/example/auth/SessionManager.java` → `["com", "example",
/// "auth", "SessionManager"]` (same algorithm as the Go extractor).
fn java_namespaces(root: &Node, bytes: &[u8], file: &str) -> Vec<String> {
    // Look for a package_declaration among the root's direct children.
    for child in root.children(&mut root.walk()) {
        if child.kind() != "package_declaration" {
            continue;
        }
        // The package name is a direct child: either `scoped_identifier` (e.g.
        // `com.example.auth`) or a bare `identifier` (e.g. `auth`).
        for pkg_child in child.children(&mut child.walk()) {
            match pkg_child.kind() {
                "scoped_identifier" | "identifier" => {
                    let text = node_text(&pkg_child, bytes);
                    return text
                        .split('.')
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned)
                        .collect();
                }
                _ => {}
            }
        }
    }

    // Fallback: derive from file path (strips `.java`, strips leading `src/`).
    let p = file.strip_suffix(".java").unwrap_or(file);
    let p = p.strip_prefix("src/").unwrap_or(p);
    p.split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

fn collect_symbols(root: &Node, bytes: &[u8], file: &str, namespaces: &[String]) -> Vec<Symbol> {
    let mut out = Vec::new();

    // Walk root's direct children for top-level type declarations.
    for child in root.children(&mut root.walk()) {
        let type_kind = match child.kind() {
            k @ ("class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "record_declaration"
            | "annotation_type_declaration") => k,
            _ => continue,
        };

        // Gate: only public types.
        if !is_public(&child, bytes) {
            continue;
        }

        let Some(type_name) = field_text(&child, "name", bytes) else {
            continue;
        };

        let type_sym_kind = match type_kind {
            "class_declaration" | "record_declaration" => SymbolKind::Class,
            "interface_declaration" | "annotation_type_declaration" => SymbolKind::Interface,
            "enum_declaration" => SymbolKind::Enum,
            _ => SymbolKind::Class,
        };

        // Emit the type symbol.
        let mut type_descriptors: Vec<Descriptor> = namespaces
            .iter()
            .cloned()
            .map(Descriptor::Namespace)
            .collect();
        type_descriptors.push(Descriptor::Type(type_name.clone()));
        out.push(Symbol {
            id: SymbolId::global(Language::Java.as_str(), type_descriptors),
            name: type_name.clone(),
            kind: type_sym_kind,
            file: file.to_owned(),
            line: (child.start_position().row + 1) as u32,
            span: ByteSpan {
                start: child.start_byte(),
                end: child.end_byte(),
            },
            signature: one_line_signature(node_text(&child, bytes), &['{', ';']),
        });

        // Members are implicitly public for interfaces and annotation types.
        let implicit_public = matches!(
            type_kind,
            "interface_declaration" | "annotation_type_declaration"
        );

        // Descend into the type body to collect members.
        let Some(body) = child.child_by_field_name("body") else {
            continue;
        };

        collect_members(
            &body,
            bytes,
            file,
            namespaces,
            &type_name,
            implicit_public,
            &mut out,
        );
    }

    out
}

/// Collect method, constructor, and field declarations from a type body node.
///
/// For `enum_declaration` the body is `enum_body`, which may contain an
/// `enum_body_declarations` child that wraps the methods and fields — we
/// descend into that extra level automatically.
fn collect_members(
    body: &Node,
    bytes: &[u8],
    file: &str,
    namespaces: &[String],
    type_name: &str,
    implicit_public: bool,
    out: &mut Vec<Symbol>,
) {
    for member in body.children(&mut body.walk()) {
        match member.kind() {
            // enum methods/fields live one level deeper inside enum_body_declarations.
            "enum_body_declarations" => {
                collect_members(
                    &member,
                    bytes,
                    file,
                    namespaces,
                    type_name,
                    implicit_public,
                    out,
                );
            }
            "method_declaration" | "constructor_declaration" => {
                if !implicit_public && !is_public(&member, bytes) {
                    continue;
                }
                let Some(name) = field_text(&member, "name", bytes) else {
                    continue;
                };
                let mut descriptors: Vec<Descriptor> = namespaces
                    .iter()
                    .cloned()
                    .map(Descriptor::Namespace)
                    .collect();
                descriptors.push(Descriptor::Type(type_name.to_owned()));
                descriptors.push(Descriptor::Method {
                    name: name.clone(),
                    disambiguator: String::new(),
                });
                out.push(Symbol {
                    id: SymbolId::global(Language::Java.as_str(), descriptors),
                    name,
                    kind: SymbolKind::Method,
                    file: file.to_owned(),
                    line: (member.start_position().row + 1) as u32,
                    span: ByteSpan {
                        start: member.start_byte(),
                        end: member.end_byte(),
                    },
                    signature: one_line_signature(node_text(&member, bytes), &['{', ';']),
                });
            }
            "field_declaration" => {
                if !implicit_public && !is_public(&member, bytes) {
                    continue;
                }
                // A single field_declaration may declare multiple variables.
                let mut cursor = member.walk();
                for declarator in member.children_by_field_name("declarator", &mut cursor) {
                    let Some(var_name) = field_text(&declarator, "name", bytes) else {
                        continue;
                    };
                    let mut descriptors: Vec<Descriptor> = namespaces
                        .iter()
                        .cloned()
                        .map(Descriptor::Namespace)
                        .collect();
                    descriptors.push(Descriptor::Type(type_name.to_owned()));
                    descriptors.push(Descriptor::Term(var_name.clone()));
                    out.push(Symbol {
                        id: SymbolId::global(Language::Java.as_str(), descriptors),
                        name: var_name,
                        kind: SymbolKind::Static,
                        file: file.to_owned(),
                        line: (member.start_position().row + 1) as u32,
                        span: ByteSpan {
                            start: member.start_byte(),
                            end: member.end_byte(),
                        },
                        signature: one_line_signature(node_text(&member, bytes), &['{', ';']),
                    });
                }
            }
            _ => {}
        }
    }
}

/// Recursively walk `node` collecting `Inherit` references for every
/// `class_declaration` and `interface_declaration` in the tree (including nested
/// classes).
fn collect_inheritance(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    match node.kind() {
        "class_declaration" => {
            // superclass: child field `superclass` is a `superclass` node;
            // its children are the `extends` keyword + the actual type node.
            // We skip named nodes that are keywords and take the first type node.
            if let Some(superclass_node) = node.child_by_field_name("superclass") {
                // The `superclass` node contains an anonymous `extends` keyword
                // followed by the named type node. Take the first named child.
                if let Some(type_node) = superclass_node
                    .children(&mut superclass_node.walk())
                    .find(|c| c.is_named())
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

            // interfaces: child field `interfaces` → `super_interfaces` →
            // `type_list` → each _type child
            if let Some(ifaces_node) = node.child_by_field_name("interfaces") {
                push_type_list_refs(&ifaces_node, bytes, file, out);
            }
        }
        "interface_declaration" => {
            // extends_interfaces is a CHILD (not a field) named "extends_interfaces"
            if let Some(extends_node) = node
                .children(&mut node.walk())
                .find(|c| c.kind() == "extends_interfaces")
            {
                push_type_list_refs(&extends_node, bytes, file, out);
            }
        }
        _ => {}
    }

    // Recurse into all children so nested classes are covered.
    for child in node.children(&mut node.walk()) {
        collect_inheritance(&child, bytes, file, out);
    }
}

/// Descend a `super_interfaces` / `extends_interfaces` node to find
/// `type_list` and push one `Inherit` reference per named `_type` child.
fn push_type_list_refs(container: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    let Some(type_list) = container
        .children(&mut container.walk())
        .find(|c| c.kind() == "type_list")
    else {
        return;
    };
    for type_node in type_list.children(&mut type_list.walk()) {
        if type_node.is_named() {
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

/// Recursively walk `node` collecting `Import` references for every
/// `import_declaration` in the tree.
///
/// - Wildcard imports (`import com.x.*`) are skipped entirely.
/// - Named imports (`import com.example.Service`) emit a single ref whose
///   name is the leaf identifier (e.g. `Service`), positioned at that leaf.
/// - Static named imports (`import static com.x.Util.helper`) are treated
///   identically — only the leaf name matters.
/// - Bare identifier imports (`import Foo`) use the identifier text directly.
fn collect_imports(
    node: &Node,
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Reference>,
    module_id: &str,
) {
    if node.kind() == "import_declaration" {
        // Single pass over the import's children. We must scan all of them: a
        // wildcard `asterisk` can appear *after* the `scoped_identifier` sibling
        // (e.g. `import com.x.*;`), so an early exit on the identifier would miss
        // it. Record the first scoped/bare name and whether a wildcard is present.
        let mut scoped: Option<Node> = None;
        let mut bare: Option<Node> = None;
        let mut has_wildcard = false;
        for child in node.children(&mut node.walk()) {
            match child.kind() {
                "asterisk" => has_wildcard = true,
                "scoped_identifier" if scoped.is_none() => scoped = Some(child),
                "identifier" if bare.is_none() => bare = Some(child),
                _ => {}
            }
        }

        if !has_wildcard {
            // Prefer a `scoped_identifier`; fall back to a bare `identifier`.
            if let Some(child) = scoped {
                // The `name` field is the final leaf (e.g. `Foo` in `com.x.Foo`).
                // tree-sitter-java names the prefix field `scope` (the package).
                if let Some(name_node) = child.child_by_field_name("name") {
                    let name = super::node_text(&name_node, bytes);
                    let from_path = child
                        .child_by_field_name("scope")
                        .map_or("", |n| super::node_text(&n, bytes));
                    super::push_import_ref(out, name, &name_node, file, module_id, from_path);
                }
            } else if let Some(child) = bare {
                // Bare identifier import: `import Foo;` — no package prefix.
                let name = super::node_text(&child, bytes);
                super::push_import_ref(out, name, &child, file, module_id, "");
            }
        }
    }

    // Recurse — import_declarations are top-level, but recursing everywhere is harmless.
    for child in node.children(&mut node.walk()) {
        collect_imports(&child, bytes, file, out, module_id);
    }
}

/// True iff `node` has a `modifiers` child containing the modifier `keyword`.
fn has_modifier(node: &Node, bytes: &[u8], keyword: &str) -> bool {
    node.children(&mut node.walk())
        .find(|c| c.kind() == "modifiers")
        .is_some_and(|mods| {
            mods.children(&mut mods.walk())
                .any(|m| node_text(&m, bytes) == keyword)
        })
}

/// True iff `node` has a `modifiers` child that contains the text `"public"`.
///
/// If there is no `modifiers` child (package-private), returns `false`.
fn is_public(node: &Node, bytes: &[u8]) -> bool {
    has_modifier(node, bytes, "public")
}

/// Emit an FFI-bridge reference for every `native` method, so the resolver links
/// it to its C/Rust implementation across the JNI boundary.
///
/// A Java `native` method `m` in class `C` of package `a.b` is implemented by a
/// native function named `Java_a_b_C_m` (the JNI mangling). We emit a `Call`
/// reference carrying that mangled name at the method's site; the FFI resolver
/// bridges it to a matching `Jni`-ABI export (e.g. a Rust `#[no_mangle] fn
/// Java_a_b_C_m`). v1 handles top-level classes and the basic mangling — overload
/// signature suffixes and `_`/Unicode escaping (`_1`, `_0xxxx`) are not applied.
fn collect_jni_natives(
    root: &Node,
    bytes: &[u8],
    file: &str,
    namespaces: &[String],
    out: &mut Vec<Reference>,
) {
    for ty in root.children(&mut root.walk()) {
        if !matches!(
            ty.kind(),
            "class_declaration"
                | "interface_declaration"
                | "enum_declaration"
                | "record_declaration"
        ) {
            continue;
        }
        let Some(class) = field_text(&ty, "name", bytes) else {
            continue;
        };
        let Some(body) = ty.child_by_field_name("body") else {
            continue;
        };
        for member in body.children(&mut body.walk()) {
            if member.kind() != "method_declaration" || !has_modifier(&member, bytes, "native") {
                continue;
            }
            let Some(name_node) = member.child_by_field_name("name") else {
                continue;
            };
            let method = node_text(&name_node, bytes);
            let mangled = jni_mangle(namespaces, &class, method);
            push_ref(out, &mangled, &name_node, file, RefRole::Call);
        }
    }
}

/// JNI short-form mangled name for a native method: `Java_<pkg>_<Class>_<method>`
/// (package segments joined with `_`; omitted entirely for the default package).
fn jni_mangle(namespaces: &[String], class: &str, method: &str) -> String {
    if namespaces.is_empty() {
        format!("Java_{class}_{method}")
    } else {
        format!("Java_{}_{}_{}", namespaces.join("_"), class, method)
    }
}

// ── Scope tree (Tier-B) ──────────────────────────────────────────────────────

/// Build the lexical scope tree for one Java file.
///
/// `scopes[0]` is always the file-root `Module` scope spanning `[0, source_len)`.
/// Java opens scopes for type declarations (`class`, `interface`, `enum`, `record`,
/// `@interface`) and method/constructor/lambda bodies.
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

/// DFS opening scopes for Java declaration nodes.
///
/// Uses the "peel-the-body" pattern: the scope opens on the whole declaration
/// node, then we recurse into the body's **children** directly (not the body
/// itself), so the body block does not double-open an extra scope.
fn scope_dfs(node: &Node, parent_id: ScopeId, scopes: &mut Vec<Scope>) {
    match node.kind() {
        "class_declaration"
        | "interface_declaration"
        | "enum_declaration"
        | "record_declaration"
        | "annotation_type_declaration" => {
            let type_id = push_scope(scopes, Some(parent_id), node_span(node), ScopeKind::Type);
            // Peel the body so the body-block itself does not re-open a scope.
            if let Some(body) = node.child_by_field_name("body") {
                for child in body.children(&mut body.walk()) {
                    scope_dfs(&child, type_id, scopes);
                }
            }
        }
        "method_declaration" | "constructor_declaration" | "compact_constructor_declaration" => {
            let fn_id = push_scope(
                scopes,
                Some(parent_id),
                node_span(node),
                ScopeKind::Function,
            );
            // Abstract / native methods have no body — handle `None`.
            // Constructor bodies use kind `constructor_body` but the field name
            // is still "body" in tree-sitter-java.
            if let Some(body) = node.child_by_field_name("body") {
                for child in body.children(&mut body.walk()) {
                    scope_dfs(&child, fn_id, scopes);
                }
            }
        }
        "lambda_expression" => {
            let fn_id = push_scope(
                scopes,
                Some(parent_id),
                node_span(node),
                ScopeKind::Function,
            );
            // If the lambda body is a block, peel it; otherwise recurse all children.
            if let Some(body) = node.child_by_field_name("body") {
                if body.kind() == "block" {
                    for child in body.children(&mut body.walk()) {
                        scope_dfs(&child, fn_id, scopes);
                    }
                } else {
                    scope_dfs(&body, fn_id, scopes);
                }
            }
        }
        "block" => {
            // A bare block NOT already consumed as a method/constructor body.
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

/// Collect parameter and local-variable [`Binding`]s for one Java file.
///
/// Covers:
/// - `method_declaration` / `constructor_declaration` /
///   `compact_constructor_declaration` parameters → [`BindingKind::Param`].
/// - `lambda_expression` parameters (formal, inferred, or bare identifier)
///   → [`BindingKind::Param`].
/// - `local_variable_declaration` declarators → [`BindingKind::Local`]
///   (scope-0 guard prevents field_declarations from leaking in).
/// - `enhanced_for_statement` loop variable → [`BindingKind::Local`].
/// - `catch_formal_parameter` → [`BindingKind::Param`].
///
/// Class fields (`field_declaration`) are excluded by the scope-0 guard; they are
/// covered by [`definition_bindings`] as [`BindingKind::Definition`].
fn collect_bindings(root: &Node, bytes: &[u8], scopes: &[Scope]) -> Vec<Binding> {
    let mut out = Vec::new();
    collect_bindings_dfs(root, bytes, scopes, &mut out);
    out
}

fn collect_bindings_dfs(node: &Node, bytes: &[u8], scopes: &[Scope], out: &mut Vec<Binding>) {
    match node.kind() {
        "method_declaration" | "constructor_declaration" | "compact_constructor_declaration" => {
            if let Some(params) = node.child_by_field_name("parameters") {
                collect_params(&params, bytes, scopes, out);
            }
            for child in node.children(&mut node.walk()) {
                collect_bindings_dfs(&child, bytes, scopes, out);
            }
        }
        "lambda_expression" => {
            if let Some(params_node) = node.child_by_field_name("parameters") {
                match params_node.kind() {
                    "formal_parameters" => {
                        collect_params(&params_node, bytes, scopes, out);
                    }
                    "inferred_parameters" => {
                        // `(a, b) -> …` — each named child is an `identifier`.
                        for child in params_node.named_children(&mut params_node.walk()) {
                            if child.kind() == "identifier" {
                                let name = node_text(&child, bytes);
                                let intro = child.start_byte();
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
                    "identifier" => {
                        // `x -> …` — single bare identifier parameter.
                        let name = node_text(&params_node, bytes);
                        let intro = params_node.start_byte();
                        push_binding(out, name.to_owned(), intro, BindingKind::Param, scopes);
                    }
                    _ => {}
                }
            }
            for child in node.children(&mut node.walk()) {
                collect_bindings_dfs(&child, bytes, scopes, out);
            }
        }
        "local_variable_declaration" => {
            let mut cursor = node.walk();
            for declarator in node.children_by_field_name("declarator", &mut cursor) {
                if let Some(name_node) = declarator.child_by_field_name("name") {
                    let name = node_text(&name_node, bytes);
                    let intro = name_node.start_byte();
                    // Scope-0 guard: field_declarations live at the Type scope;
                    // local_variable_declarations inside a method body will never
                    // be at scope 0 unless the parser emits something unusual.
                    if innermost_scope(intro, scopes) != Some(0) {
                        push_binding(out, name.to_owned(), intro, BindingKind::Local, scopes);
                    }
                }
            }
            for child in node.children(&mut node.walk()) {
                collect_bindings_dfs(&child, bytes, scopes, out);
            }
        }
        "enhanced_for_statement" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = node_text(&name_node, bytes);
                let intro = name_node.start_byte();
                if innermost_scope(intro, scopes) != Some(0) {
                    push_binding(out, name.to_owned(), intro, BindingKind::Local, scopes);
                }
            }
            for child in node.children(&mut node.walk()) {
                collect_bindings_dfs(&child, bytes, scopes, out);
            }
        }
        "catch_formal_parameter" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = node_text(&name_node, bytes);
                let intro = name_node.start_byte();
                push_binding(out, name.to_owned(), intro, BindingKind::Param, scopes);
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

/// Emit a [`BindingKind::Param`] for each named parameter in a Java
/// `formal_parameters` node.
///
/// Handles `formal_parameter` (typed param) and `spread_parameter` (varargs
/// `int... xs`). The `name` field is exposed directly on each node via
/// `child_by_field_name("name")`.
fn collect_params(params: &Node, bytes: &[u8], scopes: &[Scope], out: &mut Vec<Binding>) {
    for child in params.named_children(&mut params.walk()) {
        match child.kind() {
            "formal_parameter" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let name = node_text(&name_node, bytes);
                    let intro = name_node.start_byte();
                    push_binding(out, name.to_owned(), intro, BindingKind::Param, scopes);
                }
            }
            "spread_parameter" => {
                // `int... xs` — the declarator is a `variable_declarator` child;
                // the name is its `name` field.
                for grandchild in child.named_children(&mut child.walk()) {
                    if grandchild.kind() == "variable_declarator" {
                        if let Some(name_node) = grandchild.child_by_field_name("name") {
                            let name = node_text(&name_node, bytes);
                            let intro = name_node.start_byte();
                            push_binding(out, name.to_owned(), intro, BindingKind::Param, scopes);
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_public_class_and_method() {
        let src = r#"package com.example.auth;
public class SessionManager {
    public boolean validate(String token) { return true; }
    private void secret() {}
    int packagePrivate;
}
class Helper {}
"#;
        let facts = JavaExtractor
            .extract(src, "src/com/example/auth/SessionManager.java")
            .unwrap();

        let by_name = |n: &str| facts.symbols.iter().find(|s| s.name == n).cloned();

        let sm = by_name("SessionManager").unwrap();
        assert_eq!(sm.kind, SymbolKind::Class);
        assert_eq!(
            sm.id.to_scip_string(),
            "codegraph . . . com/example/auth/SessionManager#"
        );

        let validate = by_name("validate").unwrap();
        assert_eq!(validate.kind, SymbolKind::Method);
        assert_eq!(
            validate.id.to_scip_string(),
            "codegraph . . . com/example/auth/SessionManager#validate()."
        );

        // private method — must not appear
        assert!(by_name("secret").is_none());
        // package-private field — must not appear
        assert!(by_name("packagePrivate").is_none());
        // non-public type — must not appear
        assert!(by_name("Helper").is_none());

        assert_eq!(facts.lang, "java");
    }

    #[test]
    fn interface_members_are_public() {
        let src = r#"package io.svc;
public interface Reader {
    int read();
    void close();
}
"#;
        let facts = JavaExtractor
            .extract(src, "src/io/svc/Reader.java")
            .unwrap();

        let by_name = |n: &str| facts.symbols.iter().find(|s| s.name == n).cloned();

        let reader = by_name("Reader").unwrap();
        assert_eq!(reader.kind, SymbolKind::Interface);
        assert_eq!(reader.id.to_scip_string(), "codegraph . . . io/svc/Reader#");

        // Both methods must be emitted even though they carry no `public` modifier.
        let read = by_name("read").unwrap();
        assert_eq!(read.kind, SymbolKind::Method);
        assert_eq!(
            read.id.to_scip_string(),
            "codegraph . . . io/svc/Reader#read()."
        );

        let close = by_name("close").unwrap();
        assert_eq!(close.kind, SymbolKind::Method);
        assert_eq!(
            close.id.to_scip_string(),
            "codegraph . . . io/svc/Reader#close()."
        );
    }

    #[test]
    fn extracts_call_references() {
        let src = r#"package com.example;
public class Client {
    public void run() {
        validate("t");
        new Server();
    }
}
"#;
        let facts = JavaExtractor
            .extract(src, "src/com/example/Client.java")
            .unwrap();

        let names: Vec<&str> = facts.references.iter().map(|r| r.name.as_str()).collect();
        assert!(
            names.contains(&"validate"),
            "expected 'validate' in {names:?}"
        );
        assert!(names.contains(&"Server"), "expected 'Server' in {names:?}");
    }

    #[test]
    fn extracts_class_inheritance_references() {
        let src = "package p; public class Foo extends Bar implements Baz {}";
        let facts = JavaExtractor.extract(src, "src/p/Foo.java").unwrap();

        let inherit_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            inherit_names.contains(&"Bar"),
            "expected 'Bar' in {inherit_names:?}"
        );
        assert!(
            inherit_names.contains(&"Baz"),
            "expected 'Baz' in {inherit_names:?}"
        );
    }

    #[test]
    fn extracts_interface_extends_reference() {
        let src = "package p; public interface I extends J {}";
        let facts = JavaExtractor.extract(src, "src/p/I.java").unwrap();

        let inherit_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            inherit_names.contains(&"J"),
            "expected 'J' in {inherit_names:?}"
        );
    }

    #[test]
    fn extracts_named_import_reference() {
        let src = "import com.example.Service;\nclass A {}";
        let facts = JavaExtractor.extract(src, "src/A.java").unwrap();

        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            import_names.contains(&"Service"),
            "expected 'Service' in {import_names:?}"
        );
        assert_eq!(
            import_names.len(),
            1,
            "unexpected extra imports: {import_names:?}"
        );
    }

    #[test]
    fn extracts_static_import_reference() {
        let src = "import static com.x.Util.helper;\nclass A {}";
        let facts = JavaExtractor.extract(src, "src/A.java").unwrap();

        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            import_names.contains(&"helper"),
            "expected 'helper' in {import_names:?}"
        );
        assert_eq!(
            import_names.len(),
            1,
            "unexpected extra imports: {import_names:?}"
        );
    }

    #[test]
    fn wildcard_import_emits_no_reference() {
        let src = "import com.x.*;\nclass A {}";
        let facts = JavaExtractor.extract(src, "src/A.java").unwrap();

        let import_refs: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            import_refs.is_empty(),
            "expected no import refs but got: {import_refs:?}"
        );
    }

    #[test]
    fn import_refs_carry_source_module() {
        // `import com.example.Service;` in a file without a package declaration
        // → Import ref carries the SCIP module id derived from the file path.
        let src = "import com.example.Service;\nclass A {}";
        let file = "src/com/example/A.java";
        let facts = JavaExtractor.extract(src, file).unwrap();

        // Replicate the namespace derivation used by the extractor (no package
        // declaration → path-derived fallback in java_namespaces).
        let p = file.strip_suffix(".java").unwrap_or(file);
        let p = p.strip_prefix("src/").unwrap_or(p);
        let namespaces: Vec<String> = p
            .split('/')
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        let expected_module_id =
            crate::extract::module_symbol(Language::Java, &namespaces, file, src.len())
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
    fn named_import_carries_from_path() {
        // `import com.example.Service;` → from_path == "com.example"
        let src = "import com.example.Service;\nclass A {}";
        let facts = JavaExtractor.extract(src, "src/A.java").unwrap();
        let r = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Import && r.name == "Service")
            .expect("expected Import ref for 'Service'");
        assert_eq!(
            r.from_path,
            Some("com.example".to_owned()),
            "from_path should be 'com.example', got {:?}",
            r.from_path
        );
    }

    // ── Tier-B scope / binding tests ─────────────────────────────────────────

    #[test]
    fn method_params_emit_param_bindings() {
        // `public void f(int a, String b){}` → two Param bindings in a Function scope.
        let src = "package p;\npublic class C { public void f(int a, String b){} }";
        let facts = JavaExtractor.extract(src, "src/p/C.java").unwrap();

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
            "expected Param bindings for a and b, got {param_names:?}"
        );
    }

    #[test]
    fn constructor_param_emits_param_binding() {
        // `public C(int x){}` → Param `x` in a Function scope.
        let src = "package p;\npublic class C { public C(int x){} }";
        let facts = JavaExtractor.extract(src, "src/p/C.java").unwrap();

        let x = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Param && b.name == "x")
            .expect("expected Param binding for 'x'");
        assert_eq!(
            facts.scopes[x.scope].kind,
            ScopeKind::Function,
            "constructor param 'x' should be in a Function scope"
        );
    }

    #[test]
    fn local_var_inside_method_emits_local() {
        // `int x = 1;` inside a method → Local `x`.
        let src = "package p;\npublic class C { public void f() { int x = 1; } }";
        let facts = JavaExtractor.extract(src, "src/p/C.java").unwrap();

        let x = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Local && b.name == "x")
            .expect("expected Local binding for 'x'");
        assert_ne!(x.scope, 0, "local 'x' must not be in scope 0");
    }

    #[test]
    fn multi_declarator_emits_two_locals() {
        // `int a, b;` inside a method → Locals `a` and `b`.
        let src = "package p;\npublic class C { public void f() { int a = 1, b = 2; } }";
        let facts = JavaExtractor.extract(src, "src/p/C.java").unwrap();

        let locals: Vec<&str> = facts
            .bindings
            .iter()
            .filter(|b| b.kind == BindingKind::Local)
            .map(|b| b.name.as_str())
            .collect();
        assert!(
            locals.contains(&"a"),
            "expected Local for 'a', got {locals:?}"
        );
        assert!(
            locals.contains(&"b"),
            "expected Local for 'b', got {locals:?}"
        );
    }

    #[test]
    fn enhanced_for_loop_var_emits_local() {
        // `for (int x : xs) {}` → Local `x`.
        let src = "package p;\npublic class C { public void f(int[] xs) { for (int x : xs) {} } }";
        let facts = JavaExtractor.extract(src, "src/p/C.java").unwrap();

        let x = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Local && b.name == "x")
            .expect("expected Local binding for 'x'");
        assert_ne!(x.scope, 0, "enhanced-for 'x' must not be in scope 0");
    }

    #[test]
    fn class_field_is_definition_not_local() {
        // `public int count;` at class level → Definition binding, NOT Local.
        let src = "package p;\npublic class C { public int count; }";
        let facts = JavaExtractor.extract(src, "src/p/C.java").unwrap();

        assert!(
            !facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Local && b.name == "count"),
            "class field 'count' must NOT be a Local binding"
        );
        // The Definition binding for `count` comes from definition_bindings.
        let def = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Definition && b.name == "count")
            .expect("expected a Definition binding for 'count'");
        assert_eq!(
            def.scope, 0,
            "Definition binding for 'count' must be at scope 0"
        );
    }

    #[test]
    fn nesting_produces_correct_scope_hierarchy() {
        // `public class C { public void f() {} }` → Module → Type → Function.
        let src = "package p;\npublic class C { public void f() {} }";
        let facts = JavaExtractor.extract(src, "src/p/C.java").unwrap();

        assert_eq!(
            facts.scopes[0].kind,
            ScopeKind::Module,
            "scopes[0] must be Module"
        );

        let type_scopes: Vec<ScopeId> = facts
            .scopes
            .iter()
            .enumerate()
            .filter(|(_, s)| s.kind == ScopeKind::Type)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(type_scopes.len(), 1, "expected exactly one Type scope");

        let type_scope_id = type_scopes[0];
        assert_eq!(
            facts.scopes[type_scope_id].parent,
            Some(0),
            "Type scope parent must be Module (0)"
        );

        let fn_scopes: Vec<ScopeId> = facts
            .scopes
            .iter()
            .enumerate()
            .filter(|(_, s)| s.kind == ScopeKind::Function)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(fn_scopes.len(), 1, "expected exactly one Function scope");

        let fn_scope_id = fn_scopes[0];
        assert_eq!(
            facts.scopes[fn_scope_id].parent,
            Some(type_scope_id),
            "Function scope parent must be the Type scope"
        );
    }

    #[test]
    fn catch_param_emits_param_binding() {
        // `catch (Exception e) {}` → Param `e`.
        let src = r#"package p;
public class C {
    public void f() {
        try {} catch (Exception e) {}
    }
}"#;
        let facts = JavaExtractor.extract(src, "src/p/C.java").unwrap();

        let e = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Param && b.name == "e")
            .expect("expected Param binding for 'e'");
        assert_ne!(e.scope, 0, "catch param 'e' must not be in scope 0");
    }

    #[test]
    fn lambda_inferred_params_emit_param_bindings() {
        // `(a, b) -> a + b` → Params `a` and `b`.
        let src = r#"package p;
public class C {
    public void f() {
        java.util.function.BiFunction<Integer,Integer,Integer> fn = (a, b) -> a + b;
    }
}"#;
        let facts = JavaExtractor.extract(src, "src/p/C.java").unwrap();

        let params: Vec<&str> = facts
            .bindings
            .iter()
            .filter(|b| b.kind == BindingKind::Param)
            .map(|b| b.name.as_str())
            .collect();
        assert!(params.contains(&"a"), "expected Param 'a', got {params:?}");
        assert!(params.contains(&"b"), "expected Param 'b', got {params:?}");
        for p in facts
            .bindings
            .iter()
            .filter(|b| b.kind == BindingKind::Param)
        {
            assert_ne!(
                p.scope, 0,
                "lambda param '{}' must not be in scope 0",
                p.name
            );
        }
    }

    #[test]
    fn varargs_param_emits_param_binding() {
        // `public void f(int... xs){}` → Param `xs`.
        let src = "package p;\npublic class C { public void f(int... xs){} }";
        let facts = JavaExtractor.extract(src, "src/p/C.java").unwrap();

        let xs = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Param && b.name == "xs")
            .expect("expected Param binding for 'xs'");
        assert_ne!(xs.scope, 0, "varargs param 'xs' must not be in scope 0");
    }

    #[test]
    fn import_binding_emits_import_kind() {
        // `import com.example.Service;` → an Import binding named `Service`.
        let src = "import com.example.Service;\nclass A {}";
        let facts = JavaExtractor.extract(src, "src/A.java").unwrap();

        let svc = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Import && b.name == "Service")
            .expect("expected Import binding for 'Service'");
        // Import bindings land in the module scope.
        assert_eq!(
            svc.scope, 0,
            "Import binding 'Service' should be in scope 0"
        );
    }

    #[test]
    fn same_file_call_ref_has_non_zero_scope() {
        // Calc.java-style test: `add` is defined in the class and called from `doubleAdd`.
        // The call ref for `add` should be attached to a non-zero scope.
        let src = r#"package com.example;
public class Calc {
    public int add(int a, int b) {
        return a + b;
    }
    public int doubleAdd(int x) {
        return add(x, x);
    }
}"#;
        let facts = JavaExtractor
            .extract(src, "src/com/example/Calc.java")
            .unwrap();

        // There must be a Definition binding for `add`.
        assert!(
            facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Definition && b.name == "add"),
            "expected a Definition binding for 'add'"
        );

        // The `add` Call ref must have a non-None, non-zero scope.
        let add_ref = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Call && r.name == "add")
            .expect("expected a Call ref for 'add'");
        let scope_id = add_ref
            .scope
            .expect("add() Call ref must have a scope attached");
        assert_ne!(
            scope_id, 0,
            "add() Call ref scope must not be the module root"
        );
    }
}
