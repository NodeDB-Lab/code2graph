// SPDX-License-Identifier: Apache-2.0

//! C++ extractor — one tree-sitter pass yielding definitions and references.
//!
//! Definitions: namespaces, classes/structs/unions and their **visible**
//! members, free functions and variables, enums, type aliases (`typedef` /
//! `using T = X`), and preprocessor macros (`#define`). Qualified identity is
//! derived from the file path (`src/net/sock.cpp` → namespaces `net`, `sock`),
//! then extended by `namespace` blocks and class scopes. The same stem is
//! shared by source and header files so paired translation units share a
//! namespace.
//! References: callee identifiers of `call_expression` nodes (free calls,
//! method calls, and qualified calls).
//!
//! Emits neutral [`FileFacts`] — no storage entries, no source bodies.

use tree_sitter::{Language as TsLanguage, Node, Parser};

use crate::error::{CodegraphError, Result};
use crate::graph::types::{ByteSpan, FileFacts, RefRole, Reference, Symbol, SymbolKind};
use crate::lang::Language;
use crate::symbol::{Descriptor, SymbolId};

use super::{
    Extractor, collect_call_references, field_text, is_static, node_text, one_line_signature,
};

// NOTE: SymbolKind has no Union variant; unions map to Struct. Preprocessor
// macros use Descriptor::Macro (renders with `!`), paired with SymbolKind::Const
// or SymbolKind::Function — same convention as the C extractor.

/// Tree-sitter query capturing call-callee identifiers: free calls, method
/// calls (`obj.f()` / `obj->f()`), and qualified calls (`Ns::f()`).
const CALL_QUERY: &str = r#"
[
  (call_expression function: (identifier) @callee)
  (call_expression function: (field_expression field: (field_identifier) @callee))
  (call_expression function: (qualified_identifier name: (identifier) @callee))
]
"#;

/// Extracts C++ symbols and references.
pub struct CppExtractor;

impl Extractor for CppExtractor {
    fn lang(&self) -> Language {
        Language::Cpp
    }

    fn extract(&self, source: &str, file: &str) -> Result<FileFacts> {
        let ts_language = TsLanguage::from(tree_sitter_cpp::LANGUAGE);
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
        let namespaces = cpp_namespaces(file);

        let mut symbols = Vec::new();
        collect_defs(&root, &namespaces, bytes, file, &mut symbols);
        symbols.push(super::module_symbol(
            Language::Cpp,
            &namespaces,
            file,
            source.len(),
        ));
        let mut references =
            collect_call_references(&root, &ts_language, CALL_QUERY, Language::Cpp, bytes, file)?;
        collect_inheritance(&root, bytes, file, &mut references);

        Ok(FileFacts {
            file: file.to_owned(),
            lang: Language::Cpp.as_str().to_owned(),
            symbols,
            references,
            scopes: Vec::new(),
            bindings: Vec::new(),
            ffi_exports: Vec::new(),
        })
    }
}

/// Derive the C++ namespace path from a file path.
///
/// Strips a C++ or C source/header extension, strips a leading `src/` prefix,
/// then splits on `/`. The file stem is kept as the last namespace segment, so
/// paired source/header files share a namespace via the common stem.
fn cpp_namespaces(file: &str) -> Vec<String> {
    let p = [".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx", ".c", ".h"]
        .iter()
        .find_map(|ext| file.strip_suffix(ext))
        .unwrap_or(file);
    let p = p.strip_prefix("src/").unwrap_or(p);
    p.split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Walk a declarator subtree to the inner name; returns `(name, is_function)`.
///
/// Like C, C++ nests names inside declarator chains. Beyond C, the base name
/// may also be a `field_identifier` (member), `destructor_name` (`~Foo`),
/// `operator_name` (`operator+`), or `qualified_identifier` (`Ns::Cls::fn`,
/// whose last `::` segment is taken as the name). `is_function` is `true` only
/// when a `function_declarator` is encountered on the path.
fn declarator_name(node: &Node, bytes: &[u8]) -> Option<(String, bool)> {
    match node.kind() {
        "identifier" | "type_identifier" | "field_identifier" | "destructor_name"
        | "operator_name" => Some((node_text(node, bytes).to_owned(), false)),
        "qualified_identifier" => {
            let text = node_text(node, bytes);
            let last = text.rsplit("::").next().unwrap_or(text);
            Some((last.to_owned(), false))
        }
        "function_declarator" => {
            let inner = node.child_by_field_name("declarator")?;
            let (name, _) = declarator_name(&inner, bytes)?;
            Some((name, true))
        }
        _ => {
            // pointer_declarator / init_declarator / array_declarator /
            // reference_declarator / attributed_declarator — all expose a
            // "declarator" named field.
            if let Some(d) = node.child_by_field_name("declarator") {
                return declarator_name(&d, bytes);
            }
            // parenthesized_declarator has no named field — scan children.
            for c in node.children(&mut node.walk()) {
                if let Some(r) = declarator_name(&c, bytes) {
                    return Some(r);
                }
            }
            None
        }
    }
}

/// The leaf type name of a class/struct/union name node, which may be a bare
/// `type_identifier`, a `template_type` (templated class), or a
/// `qualified_identifier` (take the last `::` segment).
fn type_leaf_name(node: &Node, bytes: &[u8]) -> Option<String> {
    match node.kind() {
        "type_identifier" => Some(node_text(node, bytes).to_owned()),
        "template_type" => node
            .child_by_field_name("name")
            .and_then(|n| type_leaf_name(&n, bytes)),
        "qualified_identifier" => {
            let text = node_text(node, bytes);
            text.rsplit("::").next().map(str::to_owned)
        }
        _ => None,
    }
}

/// Push a symbol whose leaf descriptor extends `prefix` (a namespace/type chain).
/// The symbol's display name is derived from `leaf.name()`.
fn push_symbol(
    out: &mut Vec<Symbol>,
    node: &Node,
    prefix: &[Descriptor],
    leaf: Descriptor,
    kind: SymbolKind,
    bytes: &[u8],
    file: &str,
) {
    let name = leaf.name().to_owned();
    let mut descriptors = prefix.to_vec();
    descriptors.push(leaf);
    out.push(Symbol {
        id: SymbolId::global(Language::Cpp.as_str(), descriptors),
        name,
        kind,
        file: file.to_owned(),
        line: (node.start_position().row + 1) as u32,
        span: ByteSpan {
            start: node.start_byte(),
            end: node.end_byte(),
        },
        signature: one_line_signature(node_text(node, bytes), &['{', ';']),
    });
}

/// Build the descriptor prefix for a list of namespace segments.
fn namespace_prefix(namespaces: &[String]) -> Vec<Descriptor> {
    namespaces
        .iter()
        .cloned()
        .map(Descriptor::Namespace)
        .collect()
}

/// Process a container node (translation unit or `declaration_list`), handling
/// namespace blocks, top-level defs, and class/struct/union/enum/alias defs.
/// `namespaces` is the current namespace descriptor chain (as plain strings).
fn collect_defs(
    container: &Node,
    namespaces: &[String],
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    for child in container.children(&mut container.walk()) {
        process_node(&child, namespaces, bytes, file, out);
    }
}

/// Process a single declaration-level node.
fn process_node(
    node: &Node,
    namespaces: &[String],
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    match node.kind() {
        "namespace_definition" => {
            // Extend the namespace chain with the (possibly nested or absent) name.
            let mut nested = namespaces.to_vec();
            if let Some(name) = node.child_by_field_name("name") {
                for seg in node_text(&name, bytes).split("::") {
                    if !seg.is_empty() {
                        nested.push(seg.to_owned());
                    }
                }
            }
            if let Some(body) = node.child_by_field_name("body") {
                collect_defs(&body, &nested, bytes, file, out);
            }
        }

        "function_definition" => {
            if is_static(node, bytes) {
                return;
            }
            let Some(decl) = node.child_by_field_name("declarator") else {
                return;
            };
            let Some((name, _)) = declarator_name(&decl, bytes) else {
                return;
            };
            let prefix = namespace_prefix(namespaces);
            push_symbol(
                out,
                node,
                &prefix,
                Descriptor::Method {
                    name,
                    disambiguator: String::new(),
                },
                SymbolKind::Function,
                bytes,
                file,
            );
        }

        "declaration" => {
            if is_static(node, bytes) {
                return;
            }
            // A class/struct/union/enum specifier in the `type` field with a
            // body is an aggregate definition; emit it (and its members).
            if let Some(spec) = node.child_by_field_name("type") {
                emit_aggregate(&spec, namespaces, bytes, file, out);
            }
            let prefix = namespace_prefix(namespaces);
            let mut cursor = node.walk();
            for decl in node.children_by_field_name("declarator", &mut cursor) {
                let Some((name, is_function)) = declarator_name(&decl, bytes) else {
                    continue;
                };
                if is_function {
                    push_symbol(
                        out,
                        node,
                        &prefix,
                        Descriptor::Method {
                            name,
                            disambiguator: String::new(),
                        },
                        SymbolKind::Function,
                        bytes,
                        file,
                    );
                } else {
                    push_symbol(
                        out,
                        node,
                        &prefix,
                        Descriptor::Term(name),
                        SymbolKind::Static,
                        bytes,
                        file,
                    );
                }
            }
        }

        // A bare top-level `class/struct/union/enum Name { ... };`.
        "class_specifier" | "struct_specifier" | "union_specifier" | "enum_specifier" => {
            emit_aggregate(node, namespaces, bytes, file, out);
        }

        "type_definition" => {
            if let Some(spec) = node.child_by_field_name("type") {
                emit_aggregate(&spec, namespaces, bytes, file, out);
            }
            let Some(decl) = node.child_by_field_name("declarator") else {
                return;
            };
            let Some((name, _)) = declarator_name(&decl, bytes) else {
                return;
            };
            let prefix = namespace_prefix(namespaces);
            push_symbol(
                out,
                node,
                &prefix,
                Descriptor::Type(name),
                SymbolKind::TypeAlias,
                bytes,
                file,
            );
        }

        // `using T = X;`
        "alias_declaration" => {
            let Some(name) = field_text(node, "name", bytes) else {
                return;
            };
            let prefix = namespace_prefix(namespaces);
            push_symbol(
                out,
                node,
                &prefix,
                Descriptor::Type(name),
                SymbolKind::TypeAlias,
                bytes,
                file,
            );
        }

        // `template<...> <decl>` — unwrap and process the inner declaration.
        "template_declaration" => {
            for c in node.children(&mut node.walk()) {
                if matches!(
                    c.kind(),
                    "function_definition"
                        | "declaration"
                        | "alias_declaration"
                        | "class_specifier"
                        | "struct_specifier"
                        | "union_specifier"
                ) {
                    process_node(&c, namespaces, bytes, file, out);
                }
            }
        }

        "preproc_def" => {
            if let Some(name) = field_text(node, "name", bytes) {
                let prefix = namespace_prefix(namespaces);
                push_symbol(
                    out,
                    node,
                    &prefix,
                    Descriptor::Macro(name),
                    SymbolKind::Const,
                    bytes,
                    file,
                );
            }
        }

        "preproc_function_def" => {
            if let Some(name) = field_text(node, "name", bytes) {
                let prefix = namespace_prefix(namespaces);
                push_symbol(
                    out,
                    node,
                    &prefix,
                    Descriptor::Macro(name),
                    SymbolKind::Function,
                    bytes,
                    file,
                );
            }
        }

        _ => {}
    }
}

/// If `spec` is a class/struct/union/enum specifier with a body (a definition,
/// not a forward declaration), emit the type symbol and recurse into members.
fn emit_aggregate(
    spec: &Node,
    namespaces: &[String],
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    let (kind, default_public, is_enum) = match spec.kind() {
        "class_specifier" => (SymbolKind::Class, false, false),
        "struct_specifier" => (SymbolKind::Struct, true, false),
        // NOTE: no Union variant — unions map to Struct.
        "union_specifier" => (SymbolKind::Struct, true, false),
        "enum_specifier" => (SymbolKind::Enum, true, true),
        _ => return,
    };

    let body = spec.child_by_field_name("body");
    // No body = forward declaration: emit nothing.
    let Some(body) = body else {
        return;
    };
    let Some(name_node) = spec.child_by_field_name("name") else {
        return;
    };
    let Some(name) = type_leaf_name(&name_node, bytes) else {
        return;
    };

    let prefix = namespace_prefix(namespaces);
    push_symbol(
        out,
        spec,
        &prefix,
        Descriptor::Type(name.clone()),
        kind,
        bytes,
        file,
    );

    // Enumerators are not emitted individually (mirrors the C extractor).
    if is_enum {
        return;
    }

    // The type's own descriptor prefix for nested members.
    let mut type_prefix = prefix;
    type_prefix.push(Descriptor::Type(name));
    collect_members(&body, &type_prefix, default_public, bytes, file, out);
}

/// Collect visible members of a `field_declaration_list`, tracking visibility
/// statefully via `access_specifier` nodes encountered in order.
fn collect_members(
    body: &Node,
    type_prefix: &[Descriptor],
    default_public: bool,
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Symbol>,
) {
    let mut current_public = default_public;
    for member in body.children(&mut body.walk()) {
        match member.kind() {
            "access_specifier" => {
                current_public = node_text(&member, bytes).starts_with("public");
            }
            _ if !current_public => {}
            "function_definition" => {
                let Some(decl) = member.child_by_field_name("declarator") else {
                    continue;
                };
                let Some((name, _)) = declarator_name(&decl, bytes) else {
                    continue;
                };
                push_symbol(
                    out,
                    &member,
                    type_prefix,
                    Descriptor::Method {
                        name,
                        disambiguator: String::new(),
                    },
                    SymbolKind::Method,
                    bytes,
                    file,
                );
            }
            "field_declaration" => {
                let Some(decl) = member.child_by_field_name("declarator") else {
                    continue;
                };
                let Some((name, is_function)) = declarator_name(&decl, bytes) else {
                    continue;
                };
                if is_function {
                    push_symbol(
                        out,
                        &member,
                        type_prefix,
                        Descriptor::Method {
                            name,
                            disambiguator: String::new(),
                        },
                        SymbolKind::Method,
                        bytes,
                        file,
                    );
                } else {
                    push_symbol(
                        out,
                        &member,
                        type_prefix,
                        Descriptor::Term(name),
                        SymbolKind::Static,
                        bytes,
                        file,
                    );
                }
            }
            // A nested type (struct inside a class etc.) — recurse, nesting
            // under the outer type.
            "class_specifier" | "struct_specifier" | "union_specifier" | "enum_specifier" => {
                // type_prefix is a namespace+type chain; treat its segments as
                // the "namespaces" for the nested aggregate.
                let nested_ns: Vec<String> =
                    type_prefix.iter().map(|d| d.name().to_owned()).collect();
                emit_aggregate(&member, &nested_ns, bytes, file, out);
            }
            _ => {}
        }
    }
}

/// Recursively walk `node` collecting `Inherit` references for every
/// `class_specifier` and `struct_specifier` in the tree (including nested
/// classes and those inside namespace blocks).
fn collect_inheritance(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    match node.kind() {
        "class_specifier" | "struct_specifier" => {
            // Find the base_class_clause child (may be absent for types with no bases).
            if let Some(clause) = node
                .children(&mut node.walk())
                .find(|c| c.kind() == "base_class_clause")
            {
                for base in clause.children(&mut clause.walk()) {
                    match base.kind() {
                        "type_identifier" | "qualified_identifier" | "template_type" => {
                            super::push_ref(
                                out,
                                super::simple_type_name(node_text(&base, bytes), "::"),
                                &base,
                                file,
                                RefRole::IsImplementation,
                            );
                        }
                        _ => {}
                    }
                }
            }
        }
        _ => {}
    }

    // Recurse into all children so nested classes and namespace bodies are covered.
    for child in node.children(&mut node.walk()) {
        collect_inheritance(&child, bytes, file, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn by_name<'a>(facts: &'a FileFacts, n: &str) -> Option<&'a Symbol> {
        facts.symbols.iter().find(|s| s.name == n)
    }

    #[test]
    fn free_function_in_namespace() {
        let src = r#"
namespace io {
    int connect(const char *host) { return 0; }
}
"#;
        let facts = CppExtractor.extract(src, "src/net/sock.cpp").unwrap();
        let f = by_name(&facts, "connect").unwrap();
        assert_eq!(f.kind, SymbolKind::Function);
        assert_eq!(
            f.id.to_scip_string(),
            "codegraph . . . net/sock/io/connect()."
        );
        assert_eq!(facts.lang, "cpp");
    }

    #[test]
    fn class_visibility() {
        let src = r#"
namespace io {
    class Sock {
    public:
        void open();
    private:
        void shutdown();
    };
}
"#;
        let facts = CppExtractor.extract(src, "src/net/sock.cpp").unwrap();

        let sock = by_name(&facts, "Sock").unwrap();
        assert_eq!(sock.kind, SymbolKind::Class);
        assert_eq!(
            sock.id.to_scip_string(),
            "codegraph . . . net/sock/io/Sock#"
        );

        let open = by_name(&facts, "open").unwrap();
        assert_eq!(open.kind, SymbolKind::Method);
        assert_eq!(
            open.id.to_scip_string(),
            "codegraph . . . net/sock/io/Sock#open()."
        );

        // private method — must be absent
        assert!(by_name(&facts, "shutdown").is_none());
    }

    #[test]
    fn struct_field_default_public() {
        let src = r#"
struct Point {
    int x;
    int y;
};
"#;
        let facts = CppExtractor.extract(src, "src/geo.cpp").unwrap();

        let point = by_name(&facts, "Point").unwrap();
        assert_eq!(point.kind, SymbolKind::Struct);
        assert_eq!(point.id.to_scip_string(), "codegraph . . . geo/Point#");

        let x = by_name(&facts, "x").unwrap();
        assert_eq!(x.kind, SymbolKind::Static);
        assert_eq!(x.id.to_scip_string(), "codegraph . . . geo/Point#x.");
    }

    #[test]
    fn enum_and_alias() {
        let src = r#"
enum Color { Red, Green };
using Id = int;
typedef int Handle;
"#;
        let facts = CppExtractor.extract(src, "src/types.cpp").unwrap();

        let color = by_name(&facts, "Color").unwrap();
        assert_eq!(color.kind, SymbolKind::Enum);
        assert_eq!(color.id.to_scip_string(), "codegraph . . . types/Color#");

        let id = by_name(&facts, "Id").unwrap();
        assert_eq!(id.kind, SymbolKind::TypeAlias);
        assert_eq!(id.id.to_scip_string(), "codegraph . . . types/Id#");

        let handle = by_name(&facts, "Handle").unwrap();
        assert_eq!(handle.kind, SymbolKind::TypeAlias);
        assert_eq!(handle.id.to_scip_string(), "codegraph . . . types/Handle#");
    }

    #[test]
    fn define_macro() {
        let src = r#"
#define MAX_CONN 64
"#;
        let facts = CppExtractor.extract(src, "src/conf.hpp").unwrap();
        let m = by_name(&facts, "MAX_CONN").unwrap();
        assert_eq!(m.kind, SymbolKind::Const);
        assert_eq!(m.id.to_scip_string(), "codegraph . . . conf/MAX_CONN!");
    }

    #[test]
    fn extracts_call_references() {
        let src = r#"
void run() {
    connect("host");
    obj.handle();
}
"#;
        let facts = CppExtractor.extract(src, "src/main.cpp").unwrap();
        let names: Vec<&str> = facts.references.iter().map(|r| r.name.as_str()).collect();
        assert!(
            names.contains(&"connect"),
            "expected 'connect' in {names:?}"
        );
        assert!(names.contains(&"handle"), "expected 'handle' in {names:?}");
    }

    #[test]
    fn inherit_single_public_base() {
        let src = "class Derived : public Base {};";
        let facts = CppExtractor.extract(src, "src/foo.cpp").unwrap();
        let inherit: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(inherit, vec!["Base"], "expected [Base], got {inherit:?}");
    }

    #[test]
    fn inherit_struct_multiple_bases() {
        let src = "struct S : A, B {};";
        let facts = CppExtractor.extract(src, "src/foo.cpp").unwrap();
        let mut inherit: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();
        inherit.sort_unstable();
        assert_eq!(inherit, vec!["A", "B"], "expected [A, B], got {inherit:?}");
    }

    #[test]
    fn inherit_qualified_base_strips_namespace() {
        let src = "class X : public ns::Base {};";
        let facts = CppExtractor.extract(src, "src/foo.cpp").unwrap();
        let inherit: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(inherit, vec!["Base"], "expected [Base], got {inherit:?}");
    }
}
