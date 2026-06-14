// SPDX-License-Identifier: Apache-2.0

//! Kotlin extractor — one tree-sitter pass yielding definitions and references.
//!
//! Definitions: declarations whose visibility is not `private`. Qualified
//! identity follows the `package_header` declaration, falling back to a
//! path-derived namespace when none is present.
//!
//! Covered declaration kinds:
//! - `class_declaration` (class/data class/sealed class/annotation class → Class;
//!   with `enum_class_body` → Enum; with `interface` keyword → Interface)
//! - `object_declaration` (singleton object → Class)
//! - `companion_object` (companion object → Class, nested under outer type)
//! - `function_declaration` (top-level → Function; inside type body → Method)
//! - `property_declaration` (`val` → Const, `var` → Static)
//! - `type_alias` (TypeAlias; name from the `type` field)
//! - `enum_entry` (inside `enum_class_body` → Const)
//! - `secondary_constructor` (inside class body → Method with name "constructor")
//!
//! Skipped in v0: `primary_constructor` (implicitly part of the class signature),
//! `anonymous_initializer` (no logical name).
//!
//! References: callee identifiers captured by two call patterns:
//! - free call `foo()` → `(call_expression (identifier) @callee)`
//! - member call `x.foo()` → `(call_expression (navigation_expression (identifier) @callee))`
//!
//! Emits neutral [`FileFacts`] — no storage entries, no source bodies.

use tree_sitter::{Language as TsLanguage, Node, Parser};

use crate::error::{CodegraphError, Result};
use crate::graph::types::{ByteSpan, FileFacts, RefRole, Reference, Symbol, SymbolKind};
use crate::lang::Language;
use crate::symbol::{Descriptor, SymbolId};

use super::{Extractor, collect_call_references, field_text, node_text, one_line_signature};

/// Tree-sitter query capturing call-callee identifiers.
///
/// Pattern 1: free call `foo()` — identifier is a direct child of call_expression.
/// Pattern 2: member call `x.foo()` — navigation_expression inside call_expression
///            has an identifier child that is the callee.
const CALL_QUERY: &str = r#"
[
  (call_expression (identifier) @callee)
  (call_expression (navigation_expression (identifier) @callee))
]
"#;

/// Extracts Kotlin symbols and references.
pub struct KotlinExtractor;

impl Extractor for KotlinExtractor {
    fn lang(&self) -> Language {
        Language::Kotlin
    }

    fn extract(&self, source: &str, file: &str) -> Result<FileFacts> {
        let ts_language = TsLanguage::from(tree_sitter_kotlin_ng::LANGUAGE);
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
        let ns_strings = kotlin_namespaces(&root, bytes, file);
        let ns_descriptors: Vec<Descriptor> = ns_strings
            .iter()
            .cloned()
            .map(Descriptor::Namespace)
            .collect();

        let mut symbols = Vec::new();
        collect_decls(root, &ns_descriptors, false, bytes, file, &mut symbols);
        symbols.push(super::module_symbol(
            Language::Kotlin,
            &ns_strings,
            file,
            source.len(),
        ));

        let mut references = collect_call_references(
            &root,
            &ts_language,
            CALL_QUERY,
            Language::Kotlin,
            bytes,
            file,
        )?;
        collect_inheritance(&root, bytes, file, &mut references);
        collect_imports(&root, bytes, file, &mut references);

        Ok(FileFacts {
            file: file.to_owned(),
            lang: Language::Kotlin.as_str().to_owned(),
            symbols,
            references,
            scopes: Vec::new(),
            bindings: Vec::new(),
            ffi_exports: Vec::new(),
        })
    }
}

// ── Namespace derivation ─────────────────────────────────────────────────────

/// Namespace descriptors for a Kotlin source file.
///
/// If a `package_header` is present, its `qualified_identifier` text is split on
/// `.` → e.g. `package com.example` → `["com", "example"]`.
///
/// Fallback (no package declaration): strip `.kt`/`.kts`, strip a leading
/// `src/`, split on `/` — e.g. `src/com/example/Auth.kt` →
/// `["com", "example", "Auth"]`.
fn kotlin_namespaces(root: &Node, bytes: &[u8], file: &str) -> Vec<String> {
    for child in root.children(&mut root.walk()) {
        if child.kind() != "package_header" {
            continue;
        }
        for pkg_child in child.children(&mut child.walk()) {
            if pkg_child.kind() == "qualified_identifier" || pkg_child.kind() == "identifier" {
                let text = node_text(&pkg_child, bytes);
                return text
                    .split('.')
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect();
            }
        }
    }

    // Fallback: derive from path.
    let p = file
        .strip_suffix(".kts")
        .or_else(|| file.strip_suffix(".kt"))
        .unwrap_or(file);
    let p = p.strip_prefix("src/").unwrap_or(p);
    p.split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

// ── Visibility gate ──────────────────────────────────────────────────────────

/// Returns `true` if a declaration should be emitted (not `private`).
///
/// Scans the `modifiers` child for a `visibility_modifier`. If the modifier text
/// is `"private"` the symbol is suppressed; everything else (public, internal,
/// protected, or no modifier at all → implicit public/internal) is emitted.
/// Recall-first, matches the project stance.
fn is_visible(node: &Node, bytes: &[u8]) -> bool {
    for child in node.children(&mut node.walk()) {
        if child.kind() != "modifiers" {
            continue;
        }
        for modifier in child.children(&mut child.walk()) {
            if modifier.kind() == "visibility_modifier" {
                return node_text(&modifier, bytes) != "private";
            }
        }
        // modifiers node present but no visibility_modifier → implicit → emit
        return true;
    }
    // No modifiers node → implicit → emit
    true
}

// ── Symbol builder ───────────────────────────────────────────────────────────

/// Build a [`Symbol`] and push it onto `out`.
fn push_symbol(
    out: &mut Vec<Symbol>,
    node: &Node,
    name: String,
    kind: SymbolKind,
    descriptors: Vec<Descriptor>,
    bytes: &[u8],
    file: &str,
) {
    out.push(Symbol {
        id: SymbolId::global(Language::Kotlin.as_str(), descriptors),
        name,
        kind,
        file: file.to_owned(),
        line: (node.start_position().row + 1) as u32,
        span: ByteSpan {
            start: node.start_byte(),
            end: node.end_byte(),
        },
        signature: one_line_signature(node_text(node, bytes), &['{', '\n']),
    });
}

/// Emit a Type symbol for `type_name` and recurse into its body for members.
///
/// Shared tail of `handle_class`, `handle_object`, and `handle_companion`:
/// all three build the same `type_descriptors` vec, push the symbol, then
/// recurse into the body. Both `class_body` and `enum_class_body` are treated
/// as bodies — an `enum_class_body` only ever appears under a class, so checking
/// for it unconditionally is harmless for objects/companions.
fn emit_type_and_body(
    out: &mut Vec<Symbol>,
    node: Node,
    type_name: String,
    kind: SymbolKind,
    prefix: &[Descriptor],
    bytes: &[u8],
    file: &str,
) {
    let mut type_descriptors = prefix.to_vec();
    type_descriptors.push(Descriptor::Type(type_name.clone()));
    push_symbol(
        out,
        &node,
        type_name,
        kind,
        type_descriptors.clone(),
        bytes,
        file,
    );

    let mut body_cursor = node.walk();
    for body_child in node.children(&mut body_cursor) {
        if matches!(body_child.kind(), "class_body" | "enum_class_body") {
            collect_decls(body_child, &type_descriptors, true, bytes, file, out);
        }
    }
}

// ── Declaration collection ───────────────────────────────────────────────────

/// Collect definitions from a container node (source_file or a type body).
///
/// `prefix` is the descriptor list up to (but not including) the current level.
/// Top-level: prefix = package Namespace descriptors.
/// Type members: prefix = package Namespaces + Type(name).
/// `inside_type` drives Function vs Method for function_declaration.
fn collect_decls(
    container: Node,
    prefix: &[Descriptor],
    inside_type: bool,
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    let mut cursor = container.walk();
    for child in container.children(&mut cursor) {
        match child.kind() {
            "class_declaration" => handle_class(child, prefix, bytes, file, out),
            "object_declaration" => handle_object(child, prefix, bytes, file, out),
            "companion_object" => handle_companion(child, prefix, bytes, file, out),
            "function_declaration" => handle_function(child, prefix, inside_type, bytes, file, out),
            "property_declaration" => handle_property(child, prefix, bytes, file, out),
            "type_alias" => handle_typealias(child, prefix, bytes, file, out),
            "enum_entry" => handle_enum_entry(child, prefix, bytes, file, out),
            "secondary_constructor" => {
                handle_secondary_constructor(child, prefix, bytes, file, out)
            }
            _ => {}
        }
    }
}

/// Handle `class_declaration` — covers class/data class/sealed class/annotation
/// class (→ Class), interface (→ Interface), and enum class (→ Enum).
fn handle_class(
    node: Node,
    prefix: &[Descriptor],
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    if !is_visible(&node, bytes) {
        return;
    }
    let name_node = match node.child_by_field_name("name") {
        Some(n) => n,
        None => return,
    };
    let type_name = node_text(&name_node, bytes).to_owned();

    // Determine kind: enum_class_body → Enum; "interface" keyword before name → Interface; else Class.
    let sym_kind = if node
        .children(&mut node.walk())
        .any(|c| c.kind() == "enum_class_body")
    {
        SymbolKind::Enum
    } else {
        // Scan text from node start up to the name node start for "interface".
        let prefix_text = std::str::from_utf8(&bytes[node.start_byte()..name_node.start_byte()])
            .unwrap_or_default();
        if prefix_text.split_whitespace().any(|w| w == "interface") {
            SymbolKind::Interface
        } else {
            SymbolKind::Class
        }
    };

    emit_type_and_body(out, node, type_name, sym_kind, prefix, bytes, file);
}

/// Handle `object_declaration` (singleton object → SymbolKind::Class).
fn handle_object(
    node: Node,
    prefix: &[Descriptor],
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    if !is_visible(&node, bytes) {
        return;
    }
    let type_name = match field_text(&node, "name", bytes) {
        Some(n) => n,
        None => return,
    };

    emit_type_and_body(out, node, type_name, SymbolKind::Class, prefix, bytes, file);
}

/// Handle `companion_object` (nested companion → SymbolKind::Class).
///
/// The `name` field may be absent (anonymous `companion object`); in that case
/// the conventional name "Companion" is used.
fn handle_companion(
    node: Node,
    prefix: &[Descriptor],
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    if !is_visible(&node, bytes) {
        return;
    }
    let type_name = field_text(&node, "name", bytes).unwrap_or_else(|| "Companion".to_owned());

    emit_type_and_body(out, node, type_name, SymbolKind::Class, prefix, bytes, file);
}

/// Handle `function_declaration`.
///
/// `inside_type` → SymbolKind::Method; otherwise SymbolKind::Function.
fn handle_function(
    node: Node,
    prefix: &[Descriptor],
    inside_type: bool,
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    if !is_visible(&node, bytes) {
        return;
    }
    let name = match field_text(&node, "name", bytes) {
        Some(n) => n,
        None => return,
    };
    let kind = if inside_type {
        SymbolKind::Method
    } else {
        SymbolKind::Function
    };
    let mut descriptors = prefix.to_vec();
    descriptors.push(Descriptor::Method {
        name: name.clone(),
        disambiguator: String::new(),
    });
    push_symbol(out, &node, name, kind, descriptors, bytes, file);
}

/// Handle `property_declaration`.
///
/// The name lives inside a `variable_declaration` child (→ its `identifier`
/// child). `val` → Const; `var` → Static. Multi-variable destructuring
/// (`multi_variable_declaration`) is skipped gracefully.
fn handle_property(
    node: Node,
    prefix: &[Descriptor],
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    if !is_visible(&node, bytes) {
        return;
    }

    // Find name from variable_declaration → identifier.
    let var_name: Option<String> = {
        let mut found = None;
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "variable_declaration" {
                // identifier is a direct child of variable_declaration
                let mut vc = child.walk();
                for vc_child in child.children(&mut vc) {
                    if vc_child.kind() == "identifier" {
                        found = Some(node_text(&vc_child, bytes).to_owned());
                        break;
                    }
                }
                break;
            }
            // multi_variable_declaration → skip
            if child.kind() == "multi_variable_declaration" {
                return;
            }
        }
        found
    };
    let var_name = match var_name {
        Some(n) => n,
        None => return,
    };

    // val vs var: scan anonymous token children for kind "var".
    let is_var = node.children(&mut node.walk()).any(|c| c.kind() == "var");
    let kind = if is_var {
        SymbolKind::Static
    } else {
        SymbolKind::Const
    };

    let mut descriptors = prefix.to_vec();
    descriptors.push(Descriptor::Term(var_name.clone()));
    push_symbol(out, &node, var_name, kind, descriptors, bytes, file);
}

/// Handle `type_alias`.
///
/// The alias name is in the `type` field (grammar quirk).
fn handle_typealias(
    node: Node,
    prefix: &[Descriptor],
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    if !is_visible(&node, bytes) {
        return;
    }
    let name = match field_text(&node, "type", bytes) {
        Some(n) => n,
        None => return,
    };
    let mut descriptors = prefix.to_vec();
    descriptors.push(Descriptor::Type(name.clone()));
    push_symbol(
        out,
        &node,
        name,
        SymbolKind::TypeAlias,
        descriptors,
        bytes,
        file,
    );
}

/// Handle `enum_entry` (cases inside `enum_class_body`).
///
/// The entry name is in an `identifier` child.
fn handle_enum_entry(
    node: Node,
    prefix: &[Descriptor],
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    if !is_visible(&node, bytes) {
        return;
    }
    // enum_entry has an identifier child (the case name).
    let name: Option<String> = {
        let mut cursor = node.walk();
        node.children(&mut cursor)
            .find(|c| c.kind() == "identifier")
            .map(|c| node_text(&c, bytes).to_owned())
    };
    let name = match name {
        Some(n) => n,
        None => return,
    };
    let mut descriptors = prefix.to_vec();
    descriptors.push(Descriptor::Term(name.clone()));
    push_symbol(
        out,
        &node,
        name,
        SymbolKind::Const,
        descriptors,
        bytes,
        file,
    );
}

/// Handle `secondary_constructor` inside a class body.
///
/// Emitted as `Method { name: "constructor", disambiguator: "" }`.
fn handle_secondary_constructor(
    node: Node,
    prefix: &[Descriptor],
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    if !is_visible(&node, bytes) {
        return;
    }
    let mut descriptors = prefix.to_vec();
    descriptors.push(Descriptor::Method {
        name: "constructor".to_owned(),
        disambiguator: String::new(),
    });
    push_symbol(
        out,
        &node,
        "constructor".to_owned(),
        SymbolKind::Method,
        descriptors,
        bytes,
        file,
    );
}

// ── Inheritance extraction ───────────────────────────────────────────────────

/// Pre-order search returning the first descendant (or self) whose kind is
/// `user_type`. Covers all three `delegation_specifier` sub-forms uniformly:
/// - `constructor_invocation` → `type` child is a `user_type`
/// - `explicit_delegation`    → `type` child is a `user_type`
/// - bare `type`              → directly contains a `user_type`
fn first_user_type<'a>(node: &Node<'a>) -> Option<Node<'a>> {
    if node.kind() == "user_type" {
        return Some(*node);
    }
    for child in node.children(&mut node.walk()) {
        if let Some(found) = first_user_type(&child) {
            return Some(found);
        }
    }
    None
}

/// Recursively walk the tree collecting `Inherit` references for every
/// `class_declaration` and `object_declaration` that has a `delegation_specifiers`
/// child.
fn collect_inheritance(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    if matches!(node.kind(), "class_declaration" | "object_declaration") {
        for child in node.children(&mut node.walk()) {
            if child.kind() == "delegation_specifiers" {
                for spec in child.children(&mut child.walk()) {
                    if spec.kind() == "delegation_specifier" {
                        if let Some(user_type_node) = first_user_type(&spec) {
                            super::push_ref(
                                out,
                                super::simple_type_name(node_text(&user_type_node, bytes), "."),
                                &user_type_node,
                                file,
                                RefRole::IsImplementation,
                            );
                        }
                    }
                }
            }
        }
    }

    // Recurse into all children so nested classes are covered.
    for child in node.children(&mut node.walk()) {
        collect_inheritance(&child, bytes, file, out);
    }
}

// ── Import extraction ────────────────────────────────────────────────────────

/// Recursively walk the tree collecting `Import` references for every
/// `import` node that is not a wildcard (`import com.x.*`).
///
/// For each qualifying `import` node the first child of kind
/// `qualified_identifier` or `identifier` provides the full import path;
/// [`super::simple_type_name`] extracts the leaf name (e.g. `com.x.Foo` → `Foo`).
/// Wildcards are detected by a `*` in the raw node text and silently dropped.
fn collect_imports(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    if node.kind() == "import" {
        let raw = node_text(node, bytes);
        if !raw.contains('*') {
            // Find the first child that carries the import path.
            for child in node.children(&mut node.walk()) {
                if matches!(child.kind(), "qualified_identifier" | "identifier") {
                    let leaf = super::simple_type_name(node_text(&child, bytes), ".");
                    super::push_ref(out, leaf, &child, file, RefRole::Import);
                    break;
                }
            }
        }
        // Don't recurse into an import node's children further.
        return;
    }

    for child in node.children(&mut node.walk()) {
        collect_imports(&child, bytes, file, out);
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn extract(src: &str, path: &str) -> FileFacts {
        KotlinExtractor.extract(src, path).unwrap()
    }

    fn by_name(facts: &FileFacts, name: &str) -> Option<Symbol> {
        facts.symbols.iter().find(|s| s.name == name).cloned()
    }

    // Test 1: class with public fun + private fun; visibility gate
    #[test]
    fn class_visibility_gate() {
        let src = r#"package com.ex
class Session {
    fun open() {}
    private fun secret() {}
}
"#;
        let facts = extract(src, "src/com/ex/Session.kt");

        let session = by_name(&facts, "Session").unwrap();
        assert_eq!(session.kind, SymbolKind::Class);
        assert_eq!(
            session.id.to_scip_string(),
            "codegraph . . . com/ex/Session#"
        );

        let open = by_name(&facts, "open").unwrap();
        assert_eq!(open.kind, SymbolKind::Method);
        assert_eq!(
            open.id.to_scip_string(),
            "codegraph . . . com/ex/Session#open()."
        );

        // private method must NOT be emitted
        assert!(by_name(&facts, "secret").is_none());
    }

    // Test 2: interface → SymbolKind::Interface
    #[test]
    fn interface_kind() {
        let src = r#"package com.ex
interface Readable {
    fun read(): String
}
"#;
        let facts = extract(src, "src/com/ex/Readable.kt");

        let readable = by_name(&facts, "Readable").unwrap();
        assert_eq!(readable.kind, SymbolKind::Interface);
        assert_eq!(
            readable.id.to_scip_string(),
            "codegraph . . . com/ex/Readable#"
        );
    }

    // Test 3: enum class with entries → Enum + Const
    #[test]
    fn enum_class_with_entries() {
        let src = r#"package com.ex
enum class Direction {
    NORTH,
    SOUTH,
    EAST,
    WEST
}
"#;
        let facts = extract(src, "src/com/ex/Direction.kt");

        let dir = by_name(&facts, "Direction").unwrap();
        assert_eq!(dir.kind, SymbolKind::Enum);
        assert_eq!(dir.id.to_scip_string(), "codegraph . . . com/ex/Direction#");

        for entry in &["NORTH", "SOUTH", "EAST", "WEST"] {
            let sym = by_name(&facts, entry).unwrap();
            assert_eq!(sym.kind, SymbolKind::Const);
            assert_eq!(
                sym.id.to_scip_string(),
                format!("codegraph . . . com/ex/Direction#{entry}.")
            );
        }
    }

    // Test 4: object declaration → SymbolKind::Class (singleton)
    #[test]
    fn object_singleton() {
        let src = r#"package com.ex
object Registry {
    fun register() {}
}
"#;
        let facts = extract(src, "src/com/ex/Registry.kt");

        let reg = by_name(&facts, "Registry").unwrap();
        assert_eq!(reg.kind, SymbolKind::Class);
        assert_eq!(reg.id.to_scip_string(), "codegraph . . . com/ex/Registry#");

        let register = by_name(&facts, "register").unwrap();
        assert_eq!(register.kind, SymbolKind::Method);
        assert_eq!(
            register.id.to_scip_string(),
            "codegraph . . . com/ex/Registry#register()."
        );
    }

    // Test 5: val → Const, var → Static
    #[test]
    fn val_and_var_properties() {
        let src = r#"package com.ex
class Config {
    val maxRetries: Int = 3
    var timeout: Long = 5000
}
"#;
        let facts = extract(src, "src/com/ex/Config.kt");

        let max = by_name(&facts, "maxRetries").unwrap();
        assert_eq!(max.kind, SymbolKind::Const);
        assert_eq!(
            max.id.to_scip_string(),
            "codegraph . . . com/ex/Config#maxRetries."
        );

        let timeout = by_name(&facts, "timeout").unwrap();
        assert_eq!(timeout.kind, SymbolKind::Static);
        assert_eq!(
            timeout.id.to_scip_string(),
            "codegraph . . . com/ex/Config#timeout."
        );
    }

    // Test 6: top-level fun → SymbolKind::Function under namespace
    #[test]
    fn top_level_function() {
        let src = r#"package com.ex
fun greet(name: String): String {
    return "Hello $name"
}
"#;
        let facts = extract(src, "src/com/ex/Greeting.kt");

        let greet = by_name(&facts, "greet").unwrap();
        assert_eq!(greet.kind, SymbolKind::Function);
        assert_eq!(greet.id.to_scip_string(), "codegraph . . . com/ex/greet().");
    }

    // Test 7: typealias → SymbolKind::TypeAlias (name from `type` field)
    #[test]
    fn type_alias() {
        let src = r#"package com.ex
typealias StringList = List<String>
"#;
        let facts = extract(src, "src/com/ex/Aliases.kt");

        let alias = by_name(&facts, "StringList").unwrap();
        assert_eq!(alias.kind, SymbolKind::TypeAlias);
        assert_eq!(
            alias.id.to_scip_string(),
            "codegraph . . . com/ex/StringList#"
        );
    }

    // Test 8: call references captured (free call + member call)
    #[test]
    fn call_references_captured() {
        let src = r#"package com.ex
fun main() {
    foo()
    val x = SomeClass()
    x.bar()
}
"#;
        let facts = extract(src, "src/com/ex/Main.kt");
        let names: Vec<&str> = facts.references.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"foo"), "expected 'foo' in {names:?}");
        assert!(names.contains(&"bar"), "expected 'bar' in {names:?}");
    }

    #[test]
    fn lang_tag() {
        let facts = extract("fun foo() {}", "src/Foo.kt");
        assert_eq!(facts.lang, "kotlin");
    }

    // Test 10: class with superclass call + interface → both Inherit refs
    #[test]
    fn class_inherits_base_and_interface() {
        let src = "class Sub : Base(), Iface { }";
        let facts = extract(src, "src/Sub.kt");
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

    // Test 11: dotted parent name → leaf only
    #[test]
    fn class_inherits_dotted_name_simplified() {
        let src = "class C : com.x.Base() { }";
        let facts = extract(src, "src/C.kt");
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
    }

    // Test 12: object declaration inherits interface → Inherit ref
    #[test]
    fn object_inherits_service() {
        let src = "object O : Service { }";
        let facts = extract(src, "src/O.kt");
        let inherit_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            inherit_names.contains(&"Service"),
            "expected 'Service' in {inherit_names:?}"
        );
    }

    // Test 13: qualified import → Import ref with leaf name only
    #[test]
    fn import_qualified_emits_leaf() {
        let src = "import com.example.Service\nclass C";
        let facts = extract(src, "src/C.kt");
        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(
            import_names,
            vec!["Service"],
            "expected exactly ['Service'], got {import_names:?}"
        );
    }

    // Test 14: simple (unqualified) import → Import ref
    #[test]
    fn import_simple_emits_name() {
        let src = "import Foo\nclass C";
        let facts = extract(src, "src/C.kt");
        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(
            import_names,
            vec!["Foo"],
            "expected exactly ['Foo'], got {import_names:?}"
        );
    }

    // Test 15: wildcard import → NO Import refs
    #[test]
    fn import_wildcard_skipped() {
        let src = "import com.example.*\nclass C";
        let facts = extract(src, "src/C.kt");
        let import_refs: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            import_refs.is_empty(),
            "expected no Import refs for wildcard, got {import_refs:?}"
        );
    }
}
