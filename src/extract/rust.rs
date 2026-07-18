// SPDX-License-Identifier: Apache-2.0

//! Rust extractor — one tree-sitter pass yielding definitions and references.
//!
//! Definitions: ALL top-level items (`fn/struct/enum/trait/type/const/static/mod`)
//! plus inherent-impl members. Impl blocks are identity-less containers. Every
//! definition is tagged with its real [`Visibility`]. `pub` items get
//! `Visibility::Public`; `pub(crate)` / `pub(super)` / `pub(in …)` get
//! `Visibility::Internal`; items with no visibility modifier get `Visibility::Private`.
//! Qualified identity follows the module path derived from the file path
//! (`src/auth/session.rs` → namespaces `auth`,`session`). References: callee
//! identifiers of `call_expression` nodes.
//!
//! Emits neutral [`FileFacts`] — no storage entries, no source bodies.

use tree_sitter::{Language as TsLanguage, Node, Parser, Query, QueryCursor, StreamingIterator};

use crate::error::{CodegraphError, Result};
use crate::graph::types::{
    Binding, BindingKind, ByteSpan, EntryPoint, FfiAbi, FfiExport, FileFacts, RefRole, Reference,
    Scope, ScopeId, ScopeKind, Symbol, SymbolKind, TypeRefContext, Visibility,
};
use crate::lang::Language;
use crate::symbol::Descriptor;

#[cfg(feature = "sql")]
use super::emit_embedded_sql_refs;
use super::{
    BindingRules, ExtractCtx, Extractor, MIN_REF_LEN, attach_reference_scopes, child_text,
    collect_call_references, definition_bindings, import_bindings, make_symbol,
    mark_receiver_qualifier_calls, mark_self_receiver_calls, member_descriptors, node_occurrence,
    node_span, node_text, one_line_signature, push_binding, push_ref, push_scope,
    push_typed_binding, simple_type_name,
};

/// Tree-sitter query capturing call-callee identifiers (and optional qualifier).
const CALL_QUERY: &str = r#"
(call_expression
  function: [
    (identifier) @callee
    (field_expression field: (field_identifier) @callee)
    (scoped_identifier path: (_) @qualifier name: (identifier) @callee)
  ]
)
"#;

/// Type-like path written as the subject of an associated call.
const ASSOCIATED_CALL_SUBJECT_QUERY: &str = r#"
(call_expression
  function: (scoped_identifier path: (_) @subject name: (identifier)))
"#;

/// Method calls whose receiver is written as the `self` keyword (`self.foo()`).
///
/// Deliberately a *separate* query from [`CALL_QUERY`] rather than an extra
/// alternation branch there: `field_expression value: (self) …` and
/// `field_expression field: (field_identifier) …` (the existing branch) both
/// structurally match the same `self.foo()` node, and tree-sitter's
/// alternation explores every branch that fits — combining them in one `[ ]`
/// would double-emit the reference. Run as a second pass and correlate back to
/// [`CALL_QUERY`]'s output by the `field_identifier`'s byte offset (identical
/// node in both queries), the same technique
/// [`collect_associated_call_type_references`] uses for a second query over
/// [`ASSOCIATED_CALL_SUBJECT_QUERY`].
const SELF_CALL_QUERY: &str = r#"
(call_expression
  function: (field_expression
    value: (self)
    field: (field_identifier) @callee))
"#;

/// Method calls whose receiver is written as a bare local identifier
/// (`x.foo()`), captured to populate [`Reference::qualifier`] with the
/// receiver's name — the fact [`crate::resolve::LocalTypedCallResolver`] needs
/// to map the receiver to its binding's declared type.
///
/// Deliberately a *separate* query from [`CALL_QUERY`], for the same
/// double-emission reason documented on [`SELF_CALL_QUERY`]: combining this
/// into `CALL_QUERY`'s alternation would match the same `field_expression`
/// node twice. `value: (identifier)` structurally excludes both the `self`
/// keyword (a distinct `(self)` node kind — [`SELF_CALL_QUERY`] stays the
/// receiver-free path for it) and any non-identifier receiver (method chains
/// `a().foo()`, nested field access `a.b.foo()`), so only a bare local/param
/// name is ever captured.
const RECEIVER_CALL_QUERY: &str = r#"
(call_expression
  function: (field_expression
    value: (identifier) @receiver
    field: (field_identifier) @callee))
"#;

/// Tree-sitter query capturing type-position nodes for [`RefRole::TypeRef`] extraction.
///
/// Field names verified against `tree-sitter-rust-0.23.3/src/node-types.json`:
/// - `parameter` has field `type: _type`
/// - `function_item` has field `return_type: _type`
/// - `field_declaration` has field `type: _type`
/// - `ordered_field_declaration_list` has field `type: _type` (multiple = true, for tuple structs)
const TYPE_QUERY: &str = r#"
(parameter type: (_) @parameter_ty)
(function_item return_type: (_) @return_ty)
(field_declaration type: (_) @field_ty)
(ordered_field_declaration_list type: (_) @field_ty)
"#;

/// Extracts Rust symbols and references.
pub struct RustExtractor;

impl Extractor for RustExtractor {
    fn lang(&self) -> Language {
        Language::Rust
    }

    fn extract(&self, source: &str, file: &str) -> Result<FileFacts> {
        self.extract_impl(source, file, None)
    }

    fn extract_with_bindings(
        &self,
        source: &str,
        file: &str,
        rules: &BindingRules,
    ) -> Result<FileFacts> {
        self.extract_impl(source, file, Some(rules))
    }
}

impl RustExtractor {
    fn extract_impl(
        &self,
        source: &str,
        file: &str,
        rules: Option<&BindingRules>,
    ) -> Result<FileFacts> {
        let ts_language = crate::grammar::rust();
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
        let namespaces = rust_namespaces(file);

        let ctx = ExtractCtx {
            bytes,
            file,
            lang: Language::Rust,
        };
        let defs = collect_symbols(&root, &ctx, &namespaces);
        let def_bindings = definition_bindings(&defs);
        let ffi_exports = collect_ffi_exports(&root, bytes, &defs);
        let mut symbols = defs;
        let mod_sym = super::module_symbol(Language::Rust, &namespaces, file, source.len());
        let module_id = mod_sym.id.to_scip_string();
        symbols.push(mod_sym);
        let mut references =
            collect_call_references(&root, &ts_language, CALL_QUERY, Language::Rust, bytes, file)?;
        mark_self_receiver_calls(
            &root,
            &ts_language,
            SELF_CALL_QUERY,
            Language::Rust,
            bytes,
            &mut references,
            None,
        )?;
        mark_receiver_qualifier_calls(
            &root,
            &ts_language,
            RECEIVER_CALL_QUERY,
            Language::Rust,
            bytes,
            &mut references,
        )?;
        collect_inheritance(&root, bytes, file, &mut references);
        collect_module_decl_refs(&root, bytes, file, &mut references);
        collect_imports(&root, bytes, file, &mut references, &module_id);
        collect_type_references(&root, &ts_language, bytes, file, &mut references)?;
        collect_associated_call_type_references(&root, &ts_language, bytes, file, &mut references)?;
        collect_read_references(&root, bytes, file, &mut references);
        collect_write_references(&root, bytes, file, &mut references);
        #[cfg(feature = "sql")]
        if let Some(rules) = rules {
            collect_query_bindings(&root, bytes, file, rules, &mut references);
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
            lang: Language::Rust.as_str().to_owned(),
            symbols,
            references,
            scopes,
            bindings,
            ffi_exports,
        })
    }
}

/// Derive the Rust module path (namespace descriptors) from a file path.
fn rust_namespaces(file: &str) -> Vec<String> {
    let p = file.strip_suffix(".rs").unwrap_or(file);
    let p = p.strip_prefix("src/").unwrap_or(p);
    let mut segs: Vec<String> = p
        .split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    if let Some(last) = segs.last() {
        match last.as_str() {
            // `foo/mod.rs` always denotes module `foo`: the stem is never part of
            // the path.
            "mod" => {
                segs.pop();
            }
            // `lib.rs`/`main.rs` are crate roots ONLY at the crate source root,
            // where popping the stem leaves an empty namespace and the module is
            // named by its stem in `module_symbol`. Pop only in that case. When
            // the crate is nested (a workspace member, e.g. `<crate>/src/lib.rs`,
            // whose leading `src/` was not stripped), popping would collapse
            // `lib.rs` and `main.rs` onto the SAME `<crate>/src` namespace and mint
            // colliding crate-root module symbols; keep the stem to keep the two
            // roots distinct. A deeper `foo/lib.rs` is likewise a real submodule
            // named `lib`, not a crate root, so keeping its stem is also correct.
            "lib" | "main" if segs.len() == 1 => {
                segs.pop();
            }
            _ => {}
        }
    }
    segs
}

fn collect_symbols(root: &Node, ctx: &ExtractCtx, namespaces: &[String]) -> Vec<Symbol> {
    let bytes = ctx.bytes;
    let mut out = Vec::new();
    for child in root.children(&mut root.walk()) {
        let (kind, leaf) = match child.kind() {
            "function_item" => {
                let Some(name) = child_text(&child, "identifier", bytes) else {
                    continue;
                };
                (
                    SymbolKind::Function,
                    Descriptor::Method {
                        name: name.clone(),
                        disambiguator: crate::symbol::MethodDisambiguator::empty(),
                    },
                )
            }
            "struct_item" => {
                let Some(name) = child_text(&child, "type_identifier", bytes) else {
                    continue;
                };
                (SymbolKind::Struct, Descriptor::Type(name))
            }
            "enum_item" => {
                let Some(name) = child_text(&child, "type_identifier", bytes) else {
                    continue;
                };
                (SymbolKind::Enum, Descriptor::Type(name))
            }
            "trait_item" => {
                let Some(name) = child_text(&child, "type_identifier", bytes) else {
                    continue;
                };
                (SymbolKind::Trait, Descriptor::Type(name))
            }
            "type_item" => {
                let Some(name) = child_text(&child, "type_identifier", bytes) else {
                    continue;
                };
                (SymbolKind::TypeAlias, Descriptor::Type(name))
            }
            "const_item" => {
                let Some(name) = child_text(&child, "identifier", bytes) else {
                    continue;
                };
                (SymbolKind::Const, Descriptor::Term(name))
            }
            "static_item" => {
                let Some(name) = child_text(&child, "identifier", bytes) else {
                    continue;
                };
                (SymbolKind::Static, Descriptor::Term(name))
            }
            "mod_item" => {
                // Only inline modules (`mod foo { … }`) produce a Module symbol.
                // A body-less declaration (`mod foo;`) is purely a ModuleRef
                // reference (emitted by `collect_module_decl_refs`) and must NOT
                // emit a duplicate Module symbol — that would create two `foo`
                // definitions and break `unique_match` resolution.
                if child.child_by_field_name("body").is_none() {
                    continue;
                }
                let Some(name) = child_text(&child, "identifier", bytes) else {
                    continue;
                };
                (SymbolKind::Module, Descriptor::Namespace(name))
            }
            // An impl block is a lexical container, not a SCIP definition. Its
            // members are emitted below under the existing self-type identity.
            "impl_item" => {
                let type_name = impl_type_name(&child, bytes);
                if child.child_by_field_name("trait").is_none() {
                    collect_impl_members(&child, ctx, namespaces, &type_name, &mut out);
                }
                continue;
            }
            _ => continue,
        };

        let visibility = read_visibility(&child, bytes);

        // Extract the name before moving `leaf` into `descriptors` so no clone is needed.
        let sym_name = leaf.name().to_owned();
        let mut descriptors: Vec<Descriptor> = namespaces
            .iter()
            .cloned()
            .map(Descriptor::Namespace)
            .collect();
        descriptors.push(leaf);

        let signature = one_line_signature(node_text(&child, bytes), &['{']);
        out.push(make_symbol(
            ctx,
            &child,
            // Cloned because `sym_name` is reused below as the type/trait name
            // when descending into impl/trait members.
            sym_name.clone(),
            kind,
            visibility,
            descriptors,
            signature,
        ));
        // Populate entry-point markers for function definitions only.
        if kind == SymbolKind::Function {
            if let Some(sym) = out.last_mut() {
                sym.entry_points = entry_points_for_rust(&sym_name, &child, bytes);
            }
        }

        // For trait definitions, emit symbols for their member methods and
        // associated consts so the conformance resolver can link inherited-method
        // calls to the trait's own definition. Trait items have no `pub` modifier
        // — they are implicitly public whenever the trait is public, so we pass
        // `Visibility::Public` for all trait members.
        if kind == SymbolKind::Trait {
            collect_trait_members(&child, ctx, namespaces, &sym_name, &mut out);
        }
    }
    out
}

/// Walk an inherent `impl_item` node and emit member symbols (all visibilities).
///
/// Covers `function_item` members (→ [`SymbolKind::Method`]) and `const_item`
/// members (→ [`SymbolKind::Const`]) found in the `declaration_list` body.
/// Each member's real [`Visibility`] is read from its own `visibility_modifier`
/// child via [`read_visibility`] and recorded on the emitted symbol.
///
/// Descriptors: `namespaces.map(Namespace) ++ [Type(type_name), Method/Term(member_name)]`.
/// SCIP renders e.g. `…/Foo#new().` for a method and `…/Foo#MAX.` for a const.
fn collect_impl_members(
    impl_node: &Node,
    ctx: &ExtractCtx,
    namespaces: &[String],
    type_name: &str,
    out: &mut Vec<Symbol>,
) {
    let bytes = ctx.bytes;
    // The `body` field is the `declaration_list` — use the field accessor
    // (idiomatic here; `scope_dfs` / `collect_bindings_dfs` do the same).
    let Some(body) = impl_node.child_by_field_name("body") else {
        return;
    };

    for member in body.children(&mut body.walk()) {
        let (kind, leaf) = match member.kind() {
            "function_item" => {
                // Reuse the same name-extraction the top-level function_item arm uses.
                let Some(name) = child_text(&member, "identifier", bytes) else {
                    continue;
                };
                (
                    SymbolKind::Method,
                    Descriptor::Method {
                        name,
                        disambiguator: crate::symbol::MethodDisambiguator::empty(),
                    },
                )
            }
            "const_item" => {
                // Reuse the same name-extraction the top-level const_item arm uses.
                let Some(name) = child_text(&member, "identifier", bytes) else {
                    continue;
                };
                (SymbolKind::Const, Descriptor::Term(name))
            }
            _ => continue,
        };

        let visibility = read_visibility(&member, bytes);
        let member_name = leaf.name().to_owned();
        let descriptors = member_descriptors(namespaces, type_name, leaf);
        let signature = one_line_signature(node_text(&member, bytes), &['{']);
        out.push(make_symbol(
            ctx,
            &member,
            member_name,
            kind,
            visibility,
            descriptors,
            signature,
        ));
    }
}

/// Walk a `trait_item` node and emit member symbols for its body.
///
/// Covers three node kinds found inside a `declaration_list` (the `body` field
/// of `trait_item`):
/// - `function_signature_item` — a required method with no default body
///   (e.g. `fn hello(&self);`) → [`SymbolKind::Method`].
/// - `function_item` — a method with a default body
///   (e.g. `fn greet(&self) { … }`) → [`SymbolKind::Method`].
/// - `const_item` — an associated constant → [`SymbolKind::Const`].
///
/// Trait items carry no `pub` visibility modifier — their effective visibility
/// follows the trait itself. All trait members are therefore emitted with
/// [`Visibility::Public`].
///
/// Descriptors: `namespaces.map(Namespace) ++ [Type(trait_name), Method/Term(member)]`.
/// SCIP renders e.g. `…/Greet#hello().` for a method and `…/Greet#MAX.` for a const.
fn collect_trait_members(
    trait_node: &Node,
    ctx: &ExtractCtx,
    namespaces: &[String],
    trait_name: &str,
    out: &mut Vec<Symbol>,
) {
    let bytes = ctx.bytes;
    let Some(body) = trait_node.child_by_field_name("body") else {
        return;
    };

    for member in body.children(&mut body.walk()) {
        let (kind, leaf) = match member.kind() {
            // Both required methods (`fn hello(&self);`) and default-bodied methods
            // (`fn greet(&self) { … }`) map to SymbolKind::Method with identical
            // descriptor structure, so they share one arm.
            "function_signature_item" | "function_item" => {
                let Some(name) = child_text(&member, "identifier", bytes) else {
                    continue;
                };
                (
                    SymbolKind::Method,
                    Descriptor::Method {
                        name,
                        disambiguator: crate::symbol::MethodDisambiguator::empty(),
                    },
                )
            }
            // Associated constant: `const LIMIT: usize = 10;`
            "const_item" => {
                let Some(name) = child_text(&member, "identifier", bytes) else {
                    continue;
                };
                (SymbolKind::Const, Descriptor::Term(name))
            }
            _ => continue,
        };

        // Trait items have no visibility modifier; their visibility follows the
        // trait, so we tag them Public.
        let member_name = leaf.name().to_owned();
        let descriptors = member_descriptors(namespaces, trait_name, leaf);
        let signature = one_line_signature(node_text(&member, bytes), &['{']);
        out.push(make_symbol(
            ctx,
            &member,
            member_name,
            kind,
            Visibility::Public,
            descriptors,
            signature,
        ));
    }
}

/// Read the real [`Visibility`] from a node's `visibility_modifier` child.
///
/// - `"pub"` (bare) → [`Visibility::Public`].
/// - Any `pub(…)` restricted form (`pub(crate)`, `pub(super)`, `pub(self)`,
///   `pub(in …)`) → [`Visibility::Internal`]: restricted but not fully private.
/// - No `visibility_modifier` child → [`Visibility::Private`] (Rust default).
fn read_visibility(node: &Node, bytes: &[u8]) -> Visibility {
    let modifier = node
        .children(&mut node.walk())
        .find(|c| c.kind() == "visibility_modifier")
        .map(|c| node_text(&c, bytes));
    match modifier {
        Some("pub") => Visibility::Public,
        Some(text) if text.starts_with("pub(") => Visibility::Internal,
        _ => Visibility::Private,
    }
}

/// Attribute path terminal identifiers that mark a Rust function as an HTTP route
/// handler.
///
/// Detection rule (honest boundary): a function is an HTTP-route entry point when
/// one of its outer `#[...]` attributes has a path whose terminal identifier is in
/// this set. Terminal extraction: for a bare path like `#[get("/")]` the terminal
/// is the text of the first named child of `attribute` (an `identifier`); for a
/// qualified path like `#[actix_web::get("/")]` it is the `name:` field of the
/// `scoped_identifier` first named child. Attributes NOT in this set (`#[derive(...)]`,
/// `#[tokio::main]`, `#[no_mangle]`, `#[inline]`, `#[cfg(...)]`) produce no
/// marker. Note that `#[tokio::main]` has terminal `main`, which is NOT in this
/// set — it is correctly excluded. The `fn main` NAME check handles the
/// entry-function regardless of such attributes.
///
/// Covers Actix-web and Rocket route attribute conventions. Cannot detect
/// dynamically constructed route registrations or non-standard attribute aliases.
const RUST_ROUTE_ATTRS: &[&str] = &[
    "get", "post", "put", "delete", "patch", "head", "options", "route", "connect", "trace",
];

/// Compute entry-point markers for a top-level Rust function symbol.
///
/// `fn_name` is the bare function name (for `Main` detection).
/// `func` is the `function_item` node whose outer attributes (preceding
/// `attribute_item` siblings) are inspected for HTTP-route markers.
///
/// Node-kind path for route attribute detection (tree-sitter-rust grammar verified):
/// ```text
/// attribute_item                  ← preceding sibling of function_item
///   attribute                     ← single named child (no field name)
///     identifier                  ← first named child, bare: #[get("/")]
///     OR
///     scoped_identifier           ← first named child, qualified: #[actix_web::get("/")]
///       name: identifier          ← `name` field → terminal = "get"
/// ```
/// The attribute node has no `path:` field in the grammar; the path node is the
/// first named child of `attribute`. Attributes NOT in [`RUST_ROUTE_ATTRS`] (e.g.
/// `#[derive(...)]`, `#[no_mangle]`, `#[inline]`) produce no marker.  Multiple
/// matching attributes are all emitted (preserve order).
///
/// This reuses the same preceding-sibling walk that [`fn_ffi_exports`] uses —
/// the only per-attribute difference is which terminal string we match.
fn entry_points_for_rust(fn_name: &str, func: &Node, bytes: &[u8]) -> Vec<EntryPoint> {
    let mut markers: Vec<EntryPoint> = Vec::new();

    // (a) Name-based: a function literally named `main` → EntryPoint::Main.
    if fn_name == "main" {
        markers.push(EntryPoint::Main);
    }

    // (b) HTTP-route outer-attribute detection — walk preceding attribute_item siblings.
    // Outer attributes in tree-sitter-rust are preceding siblings of the item node, not
    // its children.  We walk backward until we encounter a non-attribute_item sibling,
    // matching the same traversal used by fn_ffi_exports.
    let mut sib = func.prev_sibling();
    while let Some(node) = sib {
        if node.kind() != "attribute_item" {
            break;
        }
        // attribute_item has a single named child: the `attribute` node.
        // The `attribute` node's path is its FIRST named child (an `identifier`
        // or `scoped_identifier`) — tree-sitter-rust has no `path:` field on
        // `attribute`; verified against node-types.json.
        if let Some(attr) = node.named_children(&mut node.walk()).next() {
            if attr.kind() == "attribute" {
                // First named child of `attribute` is the macro path node.
                if let Some(path_node) = attr.named_children(&mut attr.walk()).next() {
                    // Extract the terminal identifier:
                    //   - `identifier`        → its own text (bare #[get(...)])
                    //   - `scoped_identifier` → its `name` field (qualified #[a::b::get(...)])
                    let terminal = match path_node.kind() {
                        "identifier" => node_text(&path_node, bytes),
                        "scoped_identifier" => path_node
                            .child_by_field_name("name")
                            .map_or("", |n| node_text(&n, bytes)),
                        _ => "",
                    };
                    if !terminal.is_empty() && RUST_ROUTE_ATTRS.contains(&terminal) {
                        markers.push(EntryPoint::HttpRoute(terminal.to_owned()));
                    }
                }
            }
        }
        sib = node.prev_sibling();
    }

    // The preceding-sibling walk visits attributes in bottom-up order (closest
    // attribute first).  Reverse so markers appear in top-down source order.
    // Main (from the name check) is always first regardless.
    let main_count = markers
        .iter()
        .take_while(|m| matches!(m, EntryPoint::Main))
        .count();
    markers[main_count..].reverse();

    markers
}

/// Collect cross-language export markers from top-level functions.
///
/// Detected today:
/// - **C ABI** — `#[no_mangle]` / `#[unsafe(no_mangle)]` (exported under the
///   function name) and `#[export_name = "…"]` (name override). A plain
///   `extern "C"` *without* such a marker is mangled and intentionally not an
///   export.
/// - **Python ABI** — PyO3 `#[pyfunction]` (exported under the function name, or
///   a `#[pyo3(name = "…")]` / `#[pyfunction(name = "…")]` override).
/// - **Wasm/JS ABI** — `#[wasm_bindgen]` (exported under the function name, or a
///   `#[wasm_bindgen(js_name = "…")]` override).
/// - **Node.js ABI** — `#[napi]` (exported under the function name, or a
///   `#[napi(js_name = "…")]` override).
///
/// Only functions extracted as symbols (the public ones) are bridged; each
/// export is matched to its symbol by definition span, so the SCIP identity is
/// exactly the one the resolver will see. A function may export under more than
/// one ABI.
fn collect_ffi_exports(root: &Node, bytes: &[u8], defs: &[Symbol]) -> Vec<FfiExport> {
    let mut out = Vec::new();
    for child in root.children(&mut root.walk()) {
        if child.kind() != "function_item" {
            continue;
        }
        let Some(sym) = defs
            .iter()
            .find(|s| s.kind == SymbolKind::Function && s.span.start == child.start_byte())
        else {
            continue; // not an extracted symbol — no identity to bridge
        };
        for (abi, export_name) in fn_ffi_exports(&child, bytes, &sym.name) {
            out.push(FfiExport {
                symbol: sym.id.clone(),
                abi,
                export_name,
            });
        }
    }
    out
}

/// The FFI exports a function declares, derived from its attributes.
///
/// In tree-sitter-rust an item's outer attributes are its **preceding siblings**
/// (not children), so we walk back over the run of `attribute_item` nodes,
/// collecting their texts. The marker→ABI classification lives in the neutral
/// per-ABI registry ([`crate::ffi::rust_exports`]); reading attribute text keeps
/// it robust to spelling variants (`#[no_mangle]` vs `#[unsafe(no_mangle)]`).
fn fn_ffi_exports(func: &Node, bytes: &[u8], fn_name: &str) -> Vec<(FfiAbi, String)> {
    let mut attr_texts: Vec<&str> = Vec::new();
    let mut sib = func.prev_sibling();
    while let Some(node) = sib {
        if node.kind() != "attribute_item" {
            break;
        }
        attr_texts.push(node_text(&node, bytes));
        sib = node.prev_sibling();
    }
    crate::ffi::rust_exports(&attr_texts, fn_name)
}

/// Bare self-type name for an impl block.
fn impl_type_name(node: &Node, bytes: &[u8]) -> String {
    node.child_by_field_name("type")
        .map(|self_type| super::simple_type_name(node_text(&self_type, bytes), "::").to_owned())
        .unwrap_or_else(|| "impl".to_owned())
}

/// Recursively walk `node` collecting `Inherit` references for every
/// `impl_item` (trait implementation) and `trait_item` (supertrait bound) in
/// the tree (including items inside `mod` blocks).
fn collect_inheritance(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    match node.kind() {
        "impl_item" => {
            // Only trait impls have a `trait` field; inherent impls do not.
            if let Some(trait_node) = node.child_by_field_name("trait") {
                super::push_ref(
                    out,
                    super::simple_type_name(node_text(&trait_node, bytes), "::"),
                    &trait_node,
                    file,
                    RefRole::IsImplementation,
                );
                if let Some(reference) = out.last_mut() {
                    reference.qualifier = Some(impl_type_name(node, bytes));
                }
            }
        }
        "trait_item" => {
            // `bounds` field is a `trait_bounds` node listing supertraits.
            let subject = child_text(node, "type_identifier", bytes);
            if let Some(bounds) = node.child_by_field_name("bounds") {
                for child in bounds.children(&mut bounds.walk()) {
                    match child.kind() {
                        "type_identifier" | "generic_type" | "scoped_type_identifier" => {
                            super::push_ref(
                                out,
                                super::simple_type_name(node_text(&child, bytes), "::"),
                                &child,
                                file,
                                RefRole::IsImplementation,
                            );
                            if let (Some(reference), Some(subject)) = (out.last_mut(), &subject) {
                                reference.qualifier = Some(subject.clone());
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        _ => {}
    }

    // Recurse into all children so items inside `mod` blocks are covered.
    for child in node.children(&mut node.walk()) {
        collect_inheritance(&child, bytes, file, out);
    }
}

/// Recursively walk `node` and emit a [`RefRole::ModuleRef`] reference for every
/// `mod x;` / `pub mod x;` declaration (`mod_item`), regardless of visibility.
///
/// This is a *reference* (a module-dependency fact). A body-less `mod x;`
/// declaration does NOT produce a Module [`Symbol`] — its defining symbol is
/// the file `x.rs` (emitted there via [`super::module_symbol`]). An inline
/// `mod x { … }` DOES produce a Module symbol from `collect_symbols`.
/// The resolver connects the two; the extractor only states the facts. The
/// occurrence is positioned at the module-name identifier (the `name` field) so
/// location-based oracle matching lines up with the `mod x;` site. Recurses into
/// `mod` blocks so nested declarations are also captured.
fn collect_module_decl_refs(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    if node.kind() == "mod_item" {
        if let Some(name_node) = node.child_by_field_name("name") {
            push_ref(
                out,
                node_text(&name_node, bytes),
                &name_node,
                file,
                RefRole::ModuleRef,
            );
        }
    }
    for child in node.children(&mut node.walk()) {
        collect_module_decl_refs(&child, bytes, file, out);
    }
}

/// Emit a [`RefRole::ModuleRef`] for **every** module segment that precedes the
/// imported leaf of a use-path. Given the `path` field of a leaf
/// `scoped_identifier{ path, name }` (where `name` is the imported leaf, already
/// emitted as an `Import`), this walks the entire `path` chain and emits one
/// `ModuleRef` per module segment. For `crate::a::b::helper` the leaf is
/// `helper` and the segments are `crate`, `a`, `b`; for `a::b::c::Thing` they are
/// `a`, `b`, `c`. Each occurrence is positioned at *that* segment's own node, so
/// edge locations point at the precise segment rather than the whole path.
///
/// The chain is processed deepest-first: when `path` is itself a
/// `scoped_identifier{ path: inner, name: seg }` we recurse into `inner` before
/// emitting `seg`. The innermost node determines the base case by kind:
/// - `identifier` → emit a `ModuleRef` named after it.
/// - `crate` → in a **crate-root file** (`lib.rs`, `main.rs`, `mod.rs`) it names
///   *this very file's* module, so emit a `ModuleRef` named after this file's own
///   module symbol, positioned at the `crate` keyword — letting Tier-B resolve it
///   to the file's per-file module. In a **non-root** file `crate` refers to a
///   *different* file (the crate root, which this extractor cannot identify from a
///   single file), so it is skipped — an honest limitation, not a wrong edge.
/// - `self` / `super` / `Self` / `metavariable` / anything else → skip; they
///   never name a resolvable local module.
///
/// (External roots like `std` are *not* anchors and are still emitted as plain
/// `identifier` segments; the resolver simply finds no matching local module and
/// emits no edge — an honest no-op.)
fn push_path_module_refs(path: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    match path.kind() {
        "scoped_identifier" => {
            // Process the deeper prefix first so segments are emitted in path
            // order, then the segment named by this node's `name` field.
            if let Some(inner) = path.child_by_field_name("path") {
                push_path_module_refs(&inner, bytes, file, out);
            }
            let Some(seg) = path.child_by_field_name("name") else {
                return;
            };
            let name = node_text(&seg, bytes);
            if matches!(name, "crate" | "self" | "super" | "Self") {
                return;
            }
            push_ref(out, name, &seg, file, RefRole::ModuleRef);
        }
        "identifier" => {
            push_ref(out, node_text(path, bytes), path, file, RefRole::ModuleRef);
        }
        // The `crate` keyword anchor: in a crate-root file it names this file's
        // own module, so emit a ModuleRef for it positioned at the keyword.
        "crate" if is_crate_root(file) => {
            push_ref(out, &self_module_name(file), path, file, RefRole::ModuleRef);
        }
        // `self`/`super`/`Self`/`crate`(non-root)/`metavariable`/other: skip.
        _ => {}
    }
}

/// Whether `file` is a crate-root file — its basename is `lib.rs`, `main.rs`, or
/// `mod.rs` (matches both a bare `lib.rs` and a path like `src/lib.rs`).
fn is_crate_root(file: &str) -> bool {
    let base = file.rsplit('/').next().unwrap_or(file);
    matches!(base, "lib.rs" | "main.rs" | "mod.rs")
}

/// This file's own module-symbol name, derived through the shared
/// [`super::module_name`] so the emitted ModuleRef name equals the file's module
/// symbol and therefore resolves against the Tier-B module index.
fn self_module_name(file: &str) -> String {
    super::module_name(&rust_namespaces(file), file)
}

/// Recursively collect leaf import names from a use-tree node and push an
/// [`RefRole::Import`] reference for each one.
///
/// `prefix` is the accumulated path prefix from enclosing `scoped_use_list`
/// nodes (e.g. `"std::collections"` when processing the list in
/// `use std::collections::{HashMap, BTreeMap}`). It is threaded downward so
/// bare `identifier` leaves inside a `use_list` can report their `from_path`.
///
/// The leaf is always the concrete identifier being imported:
/// - `identifier`         → `from_path = prefix` (the received prefix).
/// - `scoped_identifier`  → `from_path` = its own `path` field (authoritative).
/// - `use_as_clause`      → recurse into the `path` field (alias ignored), passing `prefix` through.
/// - `scoped_use_list`    → compute `new_prefix` from the node's `path` field, then recurse into `list`.
/// - `use_list`           → recurse each named child, passing `prefix` through.
/// - `use_wildcard` / `crate` / `self` / `super` / anything else → skip.
fn collect_use_leaves(
    node: &Node,
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Reference>,
    module_id: &str,
    prefix: &str,
) {
    match node.kind() {
        "identifier" => {
            // Bare leaf inside a use_list — from_path is the enclosing prefix.
            super::push_import_ref(
                out,
                super::node_text(node, bytes),
                node,
                file,
                module_id,
                prefix,
            );
        }
        "scoped_identifier" => {
            // The node's `path` field is the authoritative from-path.
            // Bind once: used both for from_path text and for ModuleRef emission.
            let path_node = node.child_by_field_name("path");
            let from_path = path_node
                .as_ref()
                .map_or("", |n| super::node_text(n, bytes));
            // Emit a ModuleRef for every module segment preceding the leaf
            // (e.g. `crate`/`alpha` in `crate::alpha::helper`); anchors are
            // resolved/skipped inside per the file's crate-root status.
            if let Some(ref pn) = path_node {
                push_path_module_refs(pn, bytes, file, out);
            }
            if let Some(name_node) = node.child_by_field_name("name") {
                super::push_import_ref(
                    out,
                    super::node_text(&name_node, bytes),
                    &name_node,
                    file,
                    module_id,
                    from_path,
                );
            }
        }
        "use_as_clause" => {
            // Preserve the local alias: it is the public name re-exported by
            // `pub use path::Item as Alias`, while `from_path` remains the
            // source path collected from the child.
            let first = out.len();
            if let Some(path_node) = node.child_by_field_name("path") {
                collect_use_leaves(&path_node, bytes, file, out, module_id, prefix);
            }
            if let Some(alias) = node.child_by_field_name("alias") {
                let alias = node_text(&alias, bytes).to_owned();
                for reference in out[first..]
                    .iter_mut()
                    .filter(|reference| reference.role == RefRole::Import)
                {
                    reference.imported_name = Some(reference.name.clone());
                    reference.name = alias.clone();
                }
            }
        }
        "scoped_use_list" => {
            // Compute a fresh prefix from this node's `path` field, then recurse
            // into the list with that prefix so bare identifiers inside the list
            // can report the correct from_path.
            let new_prefix = node
                .child_by_field_name("path")
                .map_or("", |n| super::node_text(&n, bytes));
            if let Some(list_node) = node.child_by_field_name("list") {
                collect_use_leaves(&list_node, bytes, file, out, module_id, new_prefix);
            }
        }
        "use_list" => {
            for child in node.named_children(&mut node.walk()) {
                collect_use_leaves(&child, bytes, file, out, module_id, prefix);
            }
        }
        // use_wildcard, crate, self, super, metavariable → skip
        _ => {}
    }
}

/// Walk the full tree and emit [`RefRole::Import`] references for every
/// `use_declaration`. Recurses into `mod` blocks and function bodies so nested
/// `use` items are also captured.
fn collect_imports(
    node: &Node,
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Reference>,
    module_id: &str,
) {
    if node.kind() == "use_declaration" {
        let first = out.len();
        if let Some(arg) = node.child_by_field_name("argument") {
            collect_use_leaves(&arg, bytes, file, out, module_id, "");
        }
        if read_visibility(node, bytes) == Visibility::Public {
            for reference in out[first..]
                .iter_mut()
                .filter(|reference| reference.role == RefRole::Import)
            {
                reference.is_reexport = true;
            }
        }
        // No need to recurse further inside a use_declaration.
        return;
    }
    for child in node.children(&mut node.walk()) {
        collect_imports(&child, bytes, file, out, module_id);
    }
}

// ── Type reference capture ────────────────────────────────────────────────────

/// Recursively collect every named type component. Primitive and lifetime nodes
/// are deliberately ignored. Child type arguments are marked `GenericArg`.
fn collect_named_type_nodes(
    node: &Node,
    bytes: &[u8],
    context: TypeRefContext,
    file: &str,
    out: &mut Vec<Reference>,
) {
    match node.kind() {
        "primitive_type" | "lifetime" => {}
        "type_identifier" => out.push(Reference {
            name: node_text(node, bytes).to_owned(),
            occ: node_occurrence(node, file),
            role: RefRole::TypeRef,
            source_module: None,
            from_path: None,
            is_reexport: false,
            imported_name: None,
            qualifier: None,
            scope: None,
            type_ref_ctx: Some(context),
            cross_artifact: false,
            self_receiver: false,
        }),
        "scoped_type_identifier" => {
            let Some(name_node) = node.child_by_field_name("name") else {
                return;
            };
            out.push(Reference {
                name: node_text(&name_node, bytes).to_owned(),
                occ: node_occurrence(&name_node, file),
                role: RefRole::TypeRef,
                source_module: None,
                from_path: None,
                is_reexport: false,
                imported_name: None,
                qualifier: node
                    .child_by_field_name("path")
                    .map(|path| node_text(&path, bytes).to_owned()),
                scope: None,
                type_ref_ctx: Some(context),
                cross_artifact: false,
                self_receiver: false,
            });
        }
        "generic_type" => {
            if let Some(base) = node.child_by_field_name("type") {
                collect_named_type_nodes(&base, bytes, context, file, out);
            }
            if let Some(args) = node.child_by_field_name("type_arguments") {
                for child in args.named_children(&mut args.walk()) {
                    collect_named_type_nodes(&child, bytes, TypeRefContext::GenericArg, file, out);
                }
            }
        }
        _ => {
            for child in node.named_children(&mut node.walk()) {
                collect_named_type_nodes(&child, bytes, context, file, out);
            }
        }
    }
}

/// Run [`TYPE_QUERY`] over the tree and push one [`RefRole::TypeRef`]
/// [`Reference`] per resolved base named type.
///
/// Mirrors [`collect_call_references`] in structure (Query + QueryCursor).
/// `primitive_type` nodes are deferred by [`base_type_name`] — they produce
/// no reference. All other unrecognised type forms (tuples, slices, …) are
/// also silently skipped per the v1 boundary.
fn collect_associated_call_type_references(
    root: &Node,
    ts_lang: &TsLanguage,
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Reference>,
) -> Result<()> {
    let query =
        Query::new(ts_lang, ASSOCIATED_CALL_SUBJECT_QUERY).map_err(|e| CodegraphError::Query {
            lang: "rust".to_owned(),
            msg: e.to_string(),
        })?;
    let subject_idx =
        query
            .capture_index_for_name("subject")
            .ok_or_else(|| CodegraphError::Query {
                lang: "rust".to_owned(),
                msg: "missing @subject capture".to_owned(),
            })?;
    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&query, *root, bytes);
    while let Some(m) = matches.next() {
        for capture in m
            .captures
            .iter()
            .filter(|capture| capture.index == subject_idx)
        {
            let written = node_text(&capture.node, bytes);
            let name = super::simple_type_name(written, "::");
            if name.len() < MIN_REF_LEN {
                continue;
            }
            let qualifier = written
                .rsplit_once("::")
                .map(|(prefix, _)| prefix.to_owned());
            out.push(Reference {
                name: name.to_owned(),
                occ: node_occurrence(&capture.node, file),
                role: RefRole::TypeRef,
                source_module: None,
                from_path: None,
                is_reexport: false,
                imported_name: None,
                qualifier,
                scope: None,
                type_ref_ctx: Some(TypeRefContext::Other),
                cross_artifact: false,
                self_receiver: false,
            });
        }
    }
    Ok(())
}

fn collect_type_references(
    root: &Node,
    ts_lang: &TsLanguage,
    bytes: &[u8],
    file: &str,
    out: &mut Vec<Reference>,
) -> Result<()> {
    let query = Query::new(ts_lang, TYPE_QUERY).map_err(|e| CodegraphError::Query {
        lang: "rust".to_owned(),
        msg: e.to_string(),
    })?;
    let capture_context = |index| {
        if Some(index) == query.capture_index_for_name("parameter_ty") {
            Some(TypeRefContext::ParameterType)
        } else if Some(index) == query.capture_index_for_name("return_ty") {
            Some(TypeRefContext::ReturnType)
        } else if Some(index) == query.capture_index_for_name("field_ty") {
            Some(TypeRefContext::Field)
        } else {
            None
        }
    };
    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&query, *root, bytes);
    while let Some(m) = matches.next() {
        for cap in m.captures {
            if let Some(context) = capture_context(cap.index) {
                collect_named_type_nodes(&cap.node, bytes, context, file, out);
            }
        }
    }
    // Multiple grammar productions can expose the same type node. Keep only one
    // neutral fact per written occurrence/context, preserving source order.
    let mut seen = std::collections::HashSet::new();
    out.retain(|reference| {
        reference.role != RefRole::TypeRef
            || seen.insert((
                reference.occ.byte,
                reference.name.clone(),
                reference.type_ref_ctx,
            ))
    });
    Ok(())
}

// ── Edge richness: Read / Write ──────────────────────────────────────────────

/// Returns `true` when `node` (an `identifier`) is in a Rust position that is
/// already captured by another collector and must NOT also be emitted as a Read.
///
/// Skipped positions:
/// - Call callee (`call_expression` `function:` field)
/// - Declaration name (`function_item`, `struct_item`, `enum_item`, `const_item`,
///   `static_item`, `mod_item`, `trait_item`, `type_item` → `name:` field)
/// - `let_declaration` pattern binding (the bound `identifier`)
/// - `parameter` pattern (`pattern:` field)
/// - `use_declaration` / `use_list` / `scoped_use_list` descendants — already
///   [`RefRole::Import`]
/// - `scoped_identifier` child (path segment — only the final tail is a read,
///   and only when the `scoped_identifier` itself is not a callee; deferred in
///   v1: skip all children of `scoped_identifier` to avoid false positives)
/// - Assignment LHS (`assignment_expression` / `compound_assignment_expr` `left:`)
///   — handled by [`collect_write_references`]
fn is_non_read_position(node: &Node) -> bool {
    let parent = match node.parent() {
        Some(p) => p,
        None => return true, // root — not a read
    };
    match parent.kind() {
        // Call callee: `helper()` — `function:` field of call_expression.
        "call_expression" => parent.child_by_field_name("function").as_ref() == Some(node),
        // Declaration names.
        "function_item" | "struct_item" | "enum_item" | "const_item" | "static_item"
        | "mod_item" | "trait_item" | "type_item" => {
            parent.child_by_field_name("name").as_ref() == Some(node)
        }
        // let binding pattern — the bound identifier.
        "let_declaration" => parent.child_by_field_name("pattern").as_ref() == Some(node),
        // parameter pattern — the bound identifier.
        "parameter" => parent.child_by_field_name("pattern").as_ref() == Some(node),
        // Bare identifier directly inside closure_parameters: `|x| …` — a binding, not a read.
        "closure_parameters" => true,
        // Pattern wrappers inside let/param patterns — the identifier is a binding, not a read.
        "mut_pattern" | "ref_pattern" => true,
        // Path segments inside scoped_identifier — skip all children to avoid
        // false positives from path qualifiers in v1.
        "scoped_identifier" => true,
        // Imports — already RefRole::Import.
        "use_declaration" | "use_list" | "scoped_use_list" | "use_as_clause" => true,
        // Assignment LHS — handled by collect_write_references.
        "assignment_expression" | "compound_assignment_expr" => {
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
/// - Declaration names (function/struct/enum/const/static/mod/trait/type `name:` field)
/// - `let_declaration` and `parameter` pattern bindings
/// - Inside use-trees (already [`RefRole::Import`])
/// - Children of `scoped_identifier` (path qualifiers — deferred in v1)
/// - Assignment LHS (handled by [`collect_write_references`])
///
/// Note: `field_identifier` and `type_identifier` are distinct node kinds and
/// are naturally excluded — this function only examines `identifier` nodes.
/// Applies [`MIN_REF_LEN`].
fn collect_read_references(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    // Skip macro bodies — their AST is unreliable.
    if matches!(node.kind(), "macro_definition" | "macro_invocation") {
        return;
    }
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
/// bare-identifier LHS of `assignment_expression` and `compound_assignment_expr`
/// nodes (e.g. `x = 5`, `x += 1`).
///
/// Member / index LHS (`obj.field = …`, `arr[i] = …`) are not covered in v1 —
/// only bare `identifier` nodes. Applies [`MIN_REF_LEN`].
///
/// Note: `let_declaration` is a declaration, not an assignment; it is correctly
/// excluded — only `assignment_expression` / `compound_assignment_expr` are handled.
fn collect_write_references(node: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    // Skip macro bodies — their AST is unreliable.
    if matches!(node.kind(), "macro_definition" | "macro_invocation") {
        return;
    }
    if matches!(
        node.kind(),
        "assignment_expression" | "compound_assignment_expr"
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

/// Recursively walk `node` looking for call/macro sites matching one of
/// `rules`'s Rust constructs (e.g. `sqlx::query`, `sqlx::query!`), and emit a
/// [`RefRole::TypeRef`] reference (`cross_artifact: true`) for every SQL
/// entity (table/view) named in the embedded SQL argument.
///
/// Never fails extraction: a construct that doesn't match the expected shape
/// (unexpected argument kind, no string literal, malformed SQL, …) is simply
/// skipped.
#[cfg(feature = "sql")]
fn collect_query_bindings(
    node: &Node,
    bytes: &[u8],
    file: &str,
    rules: &BindingRules,
    out: &mut Vec<Reference>,
) {
    match node.kind() {
        "call_expression" => {
            if let Some(func) = node.child_by_field_name("function") {
                if func.kind() == "scoped_identifier" {
                    let callee = node_text(&func, bytes);
                    for rule in rules.for_language(Language::Rust) {
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
                        emit_bound_sql_refs(&arg, bytes, file, out);
                    }
                }
            }
        }
        "macro_invocation" => {
            if let Some(mac) = node.child_by_field_name("macro") {
                let callee = node_text(&mac, bytes);
                for rule in rules.for_language(Language::Rust) {
                    if rule.construct != callee {
                        continue;
                    }
                    let Some(token_tree) = node
                        .children(&mut node.walk())
                        .find(|c| c.kind() == "token_tree")
                    else {
                        continue;
                    };
                    let Some(arg) = nth_macro_string_arg(&token_tree, rule.sql_arg) else {
                        continue;
                    };
                    emit_bound_sql_refs(&arg, bytes, file, out);
                }
            }
        }
        _ => {}
    }
    for child in node.children(&mut node.walk()) {
        collect_query_bindings(&child, bytes, file, rules, out);
    }
}

/// Find the `index`-th (0-based) comma-separated group's string-literal token
/// inside a macro `token_tree`, e.g. `("SELECT …", a, b)` at index 0 yields
/// the first string literal, index 1 the group after the first top-level `,`.
#[cfg(feature = "sql")]
fn nth_macro_string_arg<'a>(token_tree: &Node<'a>, index: usize) -> Option<Node<'a>> {
    let mut group = 0usize;
    for child in token_tree.children(&mut token_tree.walk()) {
        if child.kind() == "," {
            group += 1;
            continue;
        }
        if group == index && matches!(child.kind(), "string_literal" | "raw_string_literal") {
            return Some(child);
        }
    }
    None
}

/// Given a string-literal argument node believed to hold embedded SQL, emit a
/// [`RefRole::TypeRef`] reference (`cross_artifact: true`) for each entity
/// use-site found, anchored at the entity's position within the original Rust
/// source. Delegates to the shared [`super::emit_embedded_sql_refs`] once the
/// Rust-specific string-literal guard is satisfied.
#[cfg(feature = "sql")]
fn emit_bound_sql_refs(arg: &Node, bytes: &[u8], file: &str, out: &mut Vec<Reference>) {
    if !matches!(arg.kind(), "string_literal" | "raw_string_literal") {
        return;
    }
    emit_embedded_sql_refs(arg, "string_content", bytes, file, out);
}

// ── Scope tree ───────────────────────────────────────────────────────────────

/// DFS that builds the scope tree for one file.
///
/// The file-root scope (`scopes[0]`) must already be pushed before calling
/// this for the root node's children. `scope_dfs` is called once per node:
/// it inspects `node`'s own kind, opens a new scope for `node` when
/// appropriate, and then recurses into whichever children carry nested scopes.
///
/// `parent_id` is the [`ScopeId`] of the innermost scope already open when
/// this node is visited; new scopes opened for `node` itself use it as their
/// parent.
fn scope_dfs(node: &Node, parent_id: ScopeId, scopes: &mut Vec<Scope>) {
    match node.kind() {
        "function_item" | "closure_expression" => {
            let fn_id = push_scope(
                scopes,
                Some(parent_id),
                node_span(node),
                ScopeKind::Function,
            );
            // Recurse into body's children to avoid double-opening the block.
            if let Some(body) = node.child_by_field_name("body") {
                for child in body.children(&mut body.walk()) {
                    scope_dfs(&child, fn_id, scopes);
                }
            } else {
                for child in node.children(&mut node.walk()) {
                    scope_dfs(&child, fn_id, scopes);
                }
            }
        }
        "mod_item" | "impl_item" | "trait_item" | "struct_item" | "enum_item" => {
            if let Some(body) = node.child_by_field_name("body") {
                let kind = if node.kind() == "mod_item" {
                    ScopeKind::Module
                } else {
                    ScopeKind::Type
                };
                let body_id = push_scope(scopes, Some(parent_id), node_span(&body), kind);
                for child in body.children(&mut body.walk()) {
                    scope_dfs(&child, body_id, scopes);
                }
            } else {
                // No body (e.g. `mod foo;` declaration) — recurse with the same parent.
                for child in node.children(&mut node.walk()) {
                    scope_dfs(&child, parent_id, scopes);
                }
            }
        }
        "block" => {
            let block_id = push_scope(scopes, Some(parent_id), node_span(node), ScopeKind::Block);
            for child in node.children(&mut node.walk()) {
                scope_dfs(&child, block_id, scopes);
            }
        }
        // Macro bodies are not reliable AST — skip entirely.
        "macro_definition" | "macro_invocation" => {}
        // All other nodes: open no scope, recurse children with the same parent.
        _ => {
            for child in node.children(&mut node.walk()) {
                scope_dfs(&child, parent_id, scopes);
            }
        }
    }
}

/// Build and return the full lexical scope tree for `source_len` bytes.
///
/// `scopes[0]` is always the file-root `Module` scope spanning `[0, source_len)`.
fn collect_scopes(root: &Node, source_len: usize) -> Vec<Scope> {
    let mut scopes = Vec::new();
    // Push the file-root scope first (index 0).
    push_scope(
        &mut scopes,
        None,
        ByteSpan {
            start: 0,
            end: source_len,
        },
        ScopeKind::Module,
    );
    // DFS from each top-level child of source_file with parent = 0.
    for child in root.children(&mut root.walk()) {
        scope_dfs(&child, 0, &mut scopes);
    }
    scopes
}

/// Resolve the bare identifier node for a pattern, unwrapping one level of
/// `mut_pattern` or `ref_pattern` if necessary.
///
/// Returns `None` for destructuring patterns (`tuple_pattern`,
/// `tuple_struct_pattern`, `struct_pattern`, slice patterns, …).
///
/// # NOTE
/// Destructuring-pattern bindings (tuple, tuple-struct, struct, slice, or-
/// pattern branches, etc.) are a known gap — this unit handles only simple
/// identifiers and single-level `mut`/`ref` wrappers.  A later unit should
/// walk the pattern recursively and emit a `Binding` for each bound leaf name.
fn resolve_pattern_ident<'tree>(pattern: &Node<'tree>) -> Option<Node<'tree>> {
    match pattern.kind() {
        "identifier" => Some(*pattern),
        "mut_pattern" | "ref_pattern" => {
            // The inner pattern is a named child (no field name); find the
            // first child that is itself an identifier.
            pattern
                .named_children(&mut pattern.walk())
                .find(|c| c.kind() == "identifier")
        }
        // Destructuring patterns — not handled in this unit (see NOTE above).
        _ => None,
    }
}

/// Walk `node` recursively, collecting parameter and local-variable [`Binding`]s.
///
/// Covers:
/// - `function_item` / `closure_expression` parameters: `parameter` children
///   of the `parameters`/`closure_parameters` node, plus `self_parameter`.
/// - `let_declaration` bindings: the `pattern` field.
///
/// All emitted bindings have `target = BindingTarget::Local`.
///
/// `intro` is always the start byte of the **identifier token** (the bound
/// name) — a neutral positional fact; visibility is the resolver's concern.
fn collect_bindings(root: &Node, bytes: &[u8], scopes: &[Scope]) -> Vec<Binding> {
    let mut out = Vec::new();
    collect_bindings_dfs(root, bytes, scopes, &mut out);
    out
}

fn collect_bindings_dfs(node: &Node, bytes: &[u8], scopes: &[Scope], out: &mut Vec<Binding>) {
    match node.kind() {
        "function_item" | "closure_expression" => {
            // Both node kinds expose their parameter list via the "parameters"
            // field (function_item → `parameters` node; closure_expression →
            // `closure_parameters` node).
            if let Some(params_node) = node.child_by_field_name("parameters") {
                collect_params(&params_node, bytes, scopes, out);
            }
            // Recurse into the body (and any other children).
            for child in node.children(&mut node.walk()) {
                collect_bindings_dfs(&child, bytes, scopes, out);
            }
        }
        "let_declaration" => {
            if let Some(pattern_node) = node.child_by_field_name("pattern") {
                if let Some(ident_node) = resolve_pattern_ident(&pattern_node) {
                    let intro = ident_node.start_byte();
                    let name = node_text(&ident_node, bytes).to_owned();
                    let type_name = let_declaration_type_name(node, bytes);
                    push_typed_binding(out, name, intro, BindingKind::Local, scopes, type_name);
                }
                // NOTE: destructuring patterns (tuple, struct, slice, …) are
                // not handled in this unit — see `resolve_pattern_ident`.
            }
            // Recurse into children (e.g. the value expression may contain
            // closures with their own params).
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

/// The declared/constructed type of a `let_declaration`, as bare written text
/// (see [`Binding::type_name`]) — a purely syntactic fact, never guessed.
/// Prefers an explicit type annotation (`let r: Repo = …`); else, when the
/// value is a trivial constructor whose type is written directly — a struct
/// literal (`Repo { .. }`) or a path-qualified call (`Repo::new()`) — the
/// constructed type's leaf name. Any other value shape (a bare identifier, a
/// method chain, …) yields `None`.
fn let_declaration_type_name(let_decl: &Node, bytes: &[u8]) -> Option<String> {
    if let Some(type_node) = let_decl.child_by_field_name("type") {
        return Some(simple_type_name(node_text(&type_node, bytes), "::").to_owned());
    }
    let value_node = let_decl.child_by_field_name("value")?;
    match value_node.kind() {
        "struct_expression" => {
            let name_node = value_node.child_by_field_name("name")?;
            Some(simple_type_name(node_text(&name_node, bytes), "::").to_owned())
        }
        "call_expression" => {
            let function_node = value_node.child_by_field_name("function")?;
            (function_node.kind() == "scoped_identifier")
                .then(|| function_node.child_by_field_name("path"))
                .flatten()
                .map(|path_node| simple_type_name(node_text(&path_node, bytes), "::").to_owned())
        }
        _ => None,
    }
}

/// Emit a [`Binding`] for each parameter in a `parameters` or
/// `closure_parameters` node.
fn collect_params(params_node: &Node, bytes: &[u8], scopes: &[Scope], out: &mut Vec<Binding>) {
    for child in params_node.named_children(&mut params_node.walk()) {
        match child.kind() {
            "parameter" => {
                if let Some(pattern_node) = child.child_by_field_name("pattern") {
                    // `pattern` field can be `self` (the keyword node) or any `_pattern`.
                    if pattern_node.kind() == "self" {
                        // `fn f(self)` — typed self, no `&`.
                        let intro = pattern_node.start_byte();
                        push_binding(out, "self".to_owned(), intro, BindingKind::Param, scopes);
                    } else if let Some(ident_node) = resolve_pattern_ident(&pattern_node) {
                        let intro = ident_node.start_byte();
                        let name = node_text(&ident_node, bytes).to_owned();
                        let type_name = child
                            .child_by_field_name("type")
                            .map(|t| simple_type_name(node_text(&t, bytes), "::").to_owned());
                        push_typed_binding(out, name, intro, BindingKind::Param, scopes, type_name);
                    }
                    // NOTE: destructuring patterns in params not handled — see
                    // `resolve_pattern_ident`.
                }
            }
            "self_parameter" => {
                // `&self`, `&mut self`, or `self` with a lifetime — the `self`
                // keyword is a named child (no field).
                if let Some(self_node) = child
                    .named_children(&mut child.walk())
                    .find(|c| c.kind() == "self")
                {
                    let intro = self_node.start_byte();
                    push_binding(out, "self".to_owned(), intro, BindingKind::Param, scopes);
                }
            }
            // Bare `identifier` directly inside `closure_parameters` (e.g.
            // `|x| …` where `x` has no explicit type annotation).
            "identifier" => {
                let intro = child.start_byte();
                let name = node_text(&child, bytes).to_owned();
                push_binding(out, name, intro, BindingKind::Param, scopes);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::types::BindingTarget;

    #[test]
    fn extracts_defs_with_scip_ids() {
        let src = r#"
pub fn validate_token(tok: &str) -> bool { helper() }
fn private_helper() {}
pub struct Config { pub value: u32 }
"#;
        let facts = RustExtractor.extract(src, "src/auth/session.rs").unwrap();
        let names: Vec<&str> = facts.symbols.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"validate_token"));
        assert!(names.contains(&"Config"));
        // private_helper is now emitted (all visibilities are extracted)
        assert!(names.contains(&"private_helper"));

        let vt = facts
            .symbols
            .iter()
            .find(|s| s.name == "validate_token")
            .unwrap();
        assert_eq!(
            vt.id.to_scip_string(),
            "codegraph . . . auth/session/validate_token()."
        );
        assert_eq!(vt.kind, SymbolKind::Function);
        assert_eq!(vt.visibility, Visibility::Public);

        let ph = facts
            .symbols
            .iter()
            .find(|s| s.name == "private_helper")
            .unwrap();
        assert_eq!(ph.visibility, Visibility::Private);
    }

    #[test]
    fn extracts_call_references() {
        let src = "pub fn main() { validate_token(\"t\"); helper(); }";
        let facts = RustExtractor.extract(src, "src/main.rs").unwrap();
        let names: Vec<&str> = facts.references.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"validate_token"));
        assert!(names.contains(&"helper"));
    }

    #[test]
    fn impl_block_does_not_duplicate_its_type_definition() {
        let facts = RustExtractor
            .extract("pub struct Point; impl Point {}", "src/point.rs")
            .unwrap();

        let point_ids: Vec<_> = facts
            .symbols
            .iter()
            .filter(|symbol| symbol.id.leaf_name() == Some("Point"))
            .map(|symbol| symbol.id.clone())
            .collect();
        assert_eq!(point_ids.len(), 1, "impl containers must not mint symbols");
    }

    #[test]
    fn multiple_impl_blocks_share_one_type_definition() {
        let facts = RustExtractor
            .extract(
                "pub struct Point; impl Point { pub fn x(&self) {} } impl Point { pub fn y(&self) {} }",
                "src/point.rs",
            )
            .unwrap();

        let point_ids: Vec<_> = facts
            .symbols
            .iter()
            .filter(|symbol| symbol.id.leaf_name() == Some("Point"))
            .map(|symbol| symbol.id.clone())
            .collect();
        assert_eq!(point_ids.len(), 1, "impl containers must not mint symbols");
    }

    #[test]
    fn generic_impl_members_use_the_declared_type_identity() {
        let facts = RustExtractor
            .extract(
                "pub struct Wrapper<T>(T); impl<T> Wrapper<T> { pub fn get(&self) -> &T { &self.0 } }",
                "src/wrapper.rs",
            )
            .unwrap();

        let get = facts
            .symbols
            .iter()
            .find(|symbol| symbol.name == "get")
            .expect("impl member");
        assert!(get.id.to_scip_string().contains("Wrapper#get()."));
        assert!(!get.id.to_scip_string().contains("Wrapper<T>"));
    }

    #[test]
    fn trait_and_inherent_impls_share_one_type_definition() {
        let facts = RustExtractor
            .extract(
                "pub trait Draw {} pub struct Point; impl Draw for Point {} impl Point {}",
                "src/point.rs",
            )
            .unwrap();

        let point_ids: Vec<_> = facts
            .symbols
            .iter()
            .filter(|symbol| symbol.id.leaf_name() == Some("Point"))
            .map(|symbol| symbol.id.clone())
            .collect();
        assert_eq!(point_ids.len(), 1, "impl containers must not mint symbols");
        assert!(facts.references.iter().any(|reference| {
            reference.role == RefRole::IsImplementation && reference.name == "Draw"
        }));
    }

    #[test]
    fn trait_impl_emits_inherit_ref_and_inherent_impl_does_not() {
        // Trait impl → one Inherit ref named "Display".
        let src_trait_impl = r#"
use std::fmt;
pub struct Point;
impl fmt::Display for Point {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { Ok(()) }
}
"#;
        let facts = RustExtractor
            .extract(src_trait_impl, "src/point.rs")
            .unwrap();
        let inherit_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            inherit_names.contains(&"Display"),
            "expected 'Display' in {inherit_names:?}"
        );

        // Inherent impl → no Inherit ref.
        let src_inherent = "pub struct Point; impl Point { pub fn new() -> Self { Point } }";
        let facts2 = RustExtractor.extract(src_inherent, "src/point.rs").unwrap();
        let inherit2: Vec<&str> = facts2
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            inherit2.is_empty(),
            "expected no Inherit refs, got {inherit2:?}"
        );
    }

    #[test]
    fn supertrait_bounds_emit_inherit_refs() {
        let src = "pub trait Foo: Bar + Baz {}";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
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
    fn scoped_trait_path_emits_leaf_name() {
        // `impl std::fmt::Display for Point {}` → leaf name "Display"
        let src = r#"
pub struct Point;
impl std::fmt::Display for Point {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { Ok(()) }
}
"#;
        let facts = RustExtractor.extract(src, "src/point.rs").unwrap();
        let inherit_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::IsImplementation)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            inherit_names.contains(&"Display"),
            "expected 'Display' in {inherit_names:?}"
        );
    }

    // ── Import reference tests ────────────────────────────────────────────────

    #[test]
    fn import_scoped_identifier_emits_leaf() {
        // `use a::b::Config;` → one Import ref `Config`
        let src = "use a::b::Config;";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(
            import_names,
            vec!["Config"],
            "expected ['Config'], got {import_names:?}"
        );
    }

    #[test]
    fn import_use_list_emits_all_leaves() {
        // `use std::collections::{HashMap, HashSet};` → Import refs `HashMap` and `HashSet`
        let src = "use std::collections::{HashMap, HashSet};";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let mut import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        import_names.sort_unstable();
        assert_eq!(
            import_names,
            vec!["HashMap", "HashSet"],
            "expected ['HashMap', 'HashSet'], got {import_names:?}"
        );
    }

    #[test]
    fn import_use_as_clause_preserves_alias_and_source_leaf() {
        // `use a::b as c;` → local Import ref `c` with source leaf `b`.
        let src = "use a::b as c;";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(
            import_names,
            vec!["c"],
            "expected ['c'], got {import_names:?}"
        );
        assert_eq!(
            facts
                .references
                .iter()
                .find(|reference| reference.role == RefRole::Import)
                .and_then(|reference| reference.imported_name.as_deref()),
            Some("b")
        );
    }

    #[test]
    fn qualified_reexport_metadata_is_confined_to_import_leaves() {
        for src in [
            "pub use inner::Thing as T;",
            "pub use inner::deep;",
            "pub use inner::deep::d;",
            "pub use crate::inner::helper;",
        ] {
            let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
            crate::validate_file_facts_with_context(
                &facts,
                crate::FileFactsValidationContext {
                    expected_file: "src/lib.rs",
                    expected_language: Language::Rust,
                    source_len: src.len(),
                },
            )
            .unwrap();
            assert!(
                facts.references.iter().any(|reference| {
                    reference.role == RefRole::Import && reference.is_reexport
                })
            );
            assert!(facts.references.iter().all(|reference| {
                reference.role == RefRole::Import
                    || (!reference.is_reexport && reference.imported_name.is_none())
            }));
        }
    }

    #[test]
    fn import_wildcard_emits_nothing() {
        // `use a::*;` → NO Import refs
        let src = "use a::*;";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            import_names.is_empty(),
            "expected no Import refs, got {import_names:?}"
        );
    }

    #[test]
    fn import_simple_scoped_path_emits_leaf() {
        // `use std::io::Result;` → Import ref `Result`
        let src = "use std::io::Result;";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(
            import_names,
            vec!["Result"],
            "expected ['Result'], got {import_names:?}"
        );
    }

    #[test]
    fn nested_crate_root_lib_and_main_have_distinct_module_ids() {
        // A workspace member (`<crate>/src/lib.rs` + `<crate>/src/main.rs`) is a
        // package with both a library and a binary crate. Their crate-root module
        // symbols must NOT collide — a shared id fails cache publication with a
        // duplicate-symbol error, blocking any multi-crate workspace index.
        let lib = crate::extract::module_symbol(
            Language::Rust,
            &rust_namespaces("app/src/lib.rs"),
            "app/src/lib.rs",
            0,
        );
        let main = crate::extract::module_symbol(
            Language::Rust,
            &rust_namespaces("app/src/main.rs"),
            "app/src/main.rs",
            0,
        );
        assert_ne!(
            lib.id.to_scip_string(),
            main.id.to_scip_string(),
            "nested lib.rs and main.rs must have distinct crate-root module ids"
        );
    }

    #[test]
    fn crate_root_lib_and_main_collapse_to_empty_namespace() {
        // At the true crate source root the stem is popped: contained items keep
        // their crate-relative identity (`helper().`, not `lib/helper().`).
        assert!(rust_namespaces("src/lib.rs").is_empty());
        assert!(rust_namespaces("src/main.rs").is_empty());
        // A deeper file literally named lib.rs is a real submodule, not a crate
        // root, so its stem is retained.
        assert_eq!(rust_namespaces("src/util/lib.rs"), vec!["util", "lib"]);
    }

    #[test]
    fn import_refs_carry_source_module() {
        // `use std::io::Result;` in src/net/client.rs → Import ref carries
        // the module SCIP id of net/client.
        let src = "use std::io::Result;";
        let file = "src/net/client.rs";
        let facts = RustExtractor.extract(src, file).unwrap();

        let namespaces = rust_namespaces(file);
        let expected_module_id =
            crate::extract::module_symbol(Language::Rust, &namespaces, file, src.len())
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
    fn import_scoped_identifier_carries_from_path() {
        // `use std::io::Result;` → from_path == "std::io"
        let src = "use std::io::Result;";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let r = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Import && r.name == "Result")
            .expect("expected Import ref for 'Result'");
        assert_eq!(
            r.from_path,
            Some("std::io".to_owned()),
            "from_path should be 'std::io', got {:?}",
            r.from_path
        );
    }

    #[test]
    fn import_use_list_leaves_carry_prefix_as_from_path() {
        // `use std::collections::{HashMap, BTreeMap};`
        // Both leaf refs must have from_path == "std::collections".
        let src = "use std::collections::{HashMap, BTreeMap};";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let import_refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .collect();
        assert_eq!(
            import_refs.len(),
            2,
            "expected 2 Import refs, got {:?}",
            import_refs.iter().map(|r| &r.name).collect::<Vec<_>>()
        );
        for r in &import_refs {
            assert_eq!(
                r.from_path,
                Some("std::collections".to_owned()),
                "from_path for '{}' should be 'std::collections', got {:?}",
                r.name,
                r.from_path
            );
        }
    }

    // ── ModuleRef reference tests ─────────────────────────────────────────────

    #[test]
    fn mod_declaration_emits_module_ref() {
        // `mod util;` → a ModuleRef named "util" (even though it is not `pub`).
        let src = "mod util;\npub fn run() {}";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let module_refs: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::ModuleRef)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(
            module_refs,
            vec!["util"],
            "expected ['util'], got {module_refs:?}"
        );
    }

    #[test]
    fn use_path_segment_emits_module_ref_and_keeps_import_leaf() {
        // `use crate::alpha::helper;` in a NON-root file → ModuleRef("alpha")
        // (the `crate` anchor is skipped on non-root files) + Import("helper").
        // Uses src/foo.rs so the assertion isolates the path-segment emission
        // from the crate-root self-module ref (covered separately).
        let src = "use crate::alpha::helper;";
        let facts = RustExtractor.extract(src, "src/foo.rs").unwrap();

        let module_refs: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::ModuleRef)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(
            module_refs,
            vec!["alpha"],
            "expected ModuleRef ['alpha'], got {module_refs:?}"
        );

        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(
            import_names,
            vec!["helper"],
            "expected Import ['helper'], got {import_names:?}"
        );
    }

    #[test]
    fn use_path_anchor_emits_no_module_ref() {
        // `use crate::helper;` in a NON-root file → only the Import for
        // "helper"; the `crate` anchor produces NO ModuleRef (in a non-root
        // file `crate` names a different file, not this one).
        let src = "use crate::helper;";
        let facts = RustExtractor.extract(src, "src/foo.rs").unwrap();

        let module_refs: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::ModuleRef)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            module_refs.is_empty(),
            "expected no ModuleRef for an anchor, got {module_refs:?}"
        );

        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(
            import_names,
            vec!["helper"],
            "expected Import ['helper'], got {import_names:?}"
        );
    }

    #[test]
    fn crate_anchor_in_root_file_emits_self_module_ref() {
        // `use crate::alpha::helper;` in a crate-root file (lib.rs) → the
        // `crate` anchor names THIS file's own module, so we emit a ModuleRef
        // "lib" (the crate root's module-symbol name) alongside the existing
        // ModuleRef "alpha" and the Import "helper".
        let src = "use crate::alpha::helper;";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();

        let module_refs: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::ModuleRef)
            .map(|r| r.name.as_str())
            .collect();
        let mut sorted = module_refs.clone();
        sorted.sort_unstable();
        assert_eq!(
            sorted,
            vec!["alpha", "lib"],
            "expected ModuleRefs == {{lib, alpha}}, got {module_refs:?}"
        );

        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(
            import_names,
            vec!["helper"],
            "expected Import ['helper'], got {import_names:?}"
        );
    }

    #[test]
    fn crate_anchor_root_file_single_segment() {
        // `use crate::helper;` in a crate-root file (lib.rs) → the only module
        // segment is the `crate` anchor, which resolves to this file's own
        // module "lib"; the leaf "helper" stays an Import.
        let src = "use crate::helper;";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();

        let module_refs: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::ModuleRef)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(
            module_refs,
            vec!["lib"],
            "expected ModuleRef ['lib'], got {module_refs:?}"
        );

        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(
            import_names,
            vec!["helper"],
            "expected Import ['helper'], got {import_names:?}"
        );
    }

    #[test]
    fn deep_use_path_emits_every_module_segment() {
        // `use a::b::c::Thing;` → a ModuleRef for each of the three module
        // segments (a, b, c) and a single Import for the leaf `Thing`. The
        // recursive walk must reach the innermost `a`, not just the pre-leaf `c`.
        let src = "use a::b::c::Thing;";
        let facts = RustExtractor.extract(src, "src/foo.rs").unwrap();

        let mut module_refs: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::ModuleRef)
            .map(|r| r.name.as_str())
            .collect();
        module_refs.sort_unstable();
        assert_eq!(
            module_refs,
            vec!["a", "b", "c"],
            "expected ModuleRefs ['a','b','c'], got {module_refs:?}"
        );

        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(
            import_names,
            vec!["Thing"],
            "expected Import ['Thing'], got {import_names:?}"
        );
    }

    #[test]
    fn crate_anchor_in_non_root_file_skipped() {
        // Same source in a NON-root file (src/foo.rs) → the `crate` anchor
        // refers to a DIFFERENT file (the crate root), which this extractor
        // cannot identify, so NO ModuleRef is emitted for it. Only the "alpha"
        // segment ModuleRef and the "helper" Import remain.
        let src = "use crate::alpha::helper;";
        let facts = RustExtractor.extract(src, "src/foo.rs").unwrap();

        let module_refs: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::ModuleRef)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(
            module_refs,
            vec!["alpha"],
            "expected only ModuleRef ['alpha'] (crate anchor skipped), got {module_refs:?}"
        );

        let import_names: Vec<&str> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Import)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(
            import_names,
            vec!["helper"],
            "expected Import ['helper'], got {import_names:?}"
        );
    }

    // ── Scope tree tests ──────────────────────────────────────────────────────

    #[test]
    fn scope_fn_with_call_has_function_scope_and_ref_attaches_to_it() {
        // A function containing a call: assert root Module scope (index 0) and a
        // Function scope; the call reference's scope should be Some(fn_scope_id),
        // not Some(0) (the root).
        let src = "pub fn greet() { helper(); }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();

        // scopes[0] must be the file-root Module.
        assert!(!facts.scopes.is_empty(), "scopes must not be empty");
        assert_eq!(
            facts.scopes[0].kind,
            ScopeKind::Module,
            "scopes[0] must be Module"
        );
        assert_eq!(facts.scopes[0].parent, None, "root scope has no parent");

        // There must be at least one Function scope.
        let fn_scope_pos = facts
            .scopes
            .iter()
            .position(|s| s.kind == ScopeKind::Function)
            .expect("expected a Function scope");

        // The call reference to `helper` must be attributed to the Function scope,
        // not the root.
        let helper_ref = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Call && r.name == "helper")
            .expect("expected a Call ref for 'helper'");
        assert_eq!(
            helper_ref.scope,
            Some(fn_scope_pos),
            "helper call should be attributed to the Function scope ({}), got {:?}",
            fn_scope_pos,
            helper_ref.scope
        );
    }

    #[test]
    fn nested_block_scope_parent_chains_correctly() {
        // A function whose body contains an inner bare `{ }` block:
        //   fn outer() { { inner_call(); } }
        // Scopes expected: root Module (0), Function (1), Block (2).
        // A ref inside the block must attribute to the Block scope,
        // and the Block scope's parent must be the Function scope.
        let src = "fn outer() { { inner_call(); } }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();

        let fn_scope_id = facts
            .scopes
            .iter()
            .position(|s| s.kind == ScopeKind::Function)
            .expect("expected a Function scope");
        let block_scope_id = facts
            .scopes
            .iter()
            .position(|s| s.kind == ScopeKind::Block)
            .expect("expected a Block scope");

        // Block's parent must be the Function scope.
        assert_eq!(
            facts.scopes[block_scope_id].parent,
            Some(fn_scope_id),
            "Block scope parent should be the Function scope"
        );

        // The call ref inside the block must attribute to the Block scope (innermost).
        let inner_ref = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Call && r.name == "inner_call")
            .expect("expected a Call ref for 'inner_call'");
        assert_eq!(
            inner_ref.scope,
            Some(block_scope_id),
            "inner_call should attribute to the Block scope ({}), got {:?}",
            block_scope_id,
            inner_ref.scope
        );
    }

    #[test]
    fn empty_source_produces_exactly_one_root_scope() {
        // Empty source → collect_scopes returns exactly one scope (the file root),
        // does not panic.
        let ts_language = crate::grammar::rust();
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&ts_language).unwrap();
        let tree = parser.parse("", None).unwrap();
        let root = tree.root_node();

        let scopes = collect_scopes(&root, 0);
        assert_eq!(
            scopes.len(),
            1,
            "empty source should produce exactly one scope"
        );
        assert_eq!(scopes[0].kind, ScopeKind::Module);
        assert_eq!(scopes[0].parent, None);
    }

    // ── Binding tests ─────────────────────────────────────────────────────────

    #[test]
    fn fn_params_emit_param_bindings() {
        // `fn f(a: u32, b: u32) { }` → two Param bindings named `a` and `b`,
        // both attributed to the Function scope, both targeting Local.
        let src = "fn f(a: u32, b: u32) { }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();

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
            "expected Param bindings for a and b in the Function scope, got {param_names:?}"
        );
        for b in facts
            .bindings
            .iter()
            .filter(|b| b.kind == BindingKind::Param)
        {
            assert_eq!(
                b.target,
                BindingTarget::Local,
                "param binding target must be Local"
            );
        }
    }

    #[test]
    fn self_parameter_emits_param_binding() {
        // `impl S { fn m(&self) {} }` → a Param binding named `"self"`.
        let src = "pub struct S; impl S { fn m(&self) {} }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();

        let self_binding = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Param && b.name == "self")
            .expect("expected a Param binding named 'self'");
        assert_eq!(self_binding.target, BindingTarget::Local);
        // The scope must be a Function scope.
        assert_eq!(
            facts.scopes[self_binding.scope].kind,
            ScopeKind::Function,
            "self binding should be in a Function scope"
        );
    }

    #[test]
    fn let_binding_emits_local_binding() {
        // `fn f() { let x = 1; }` → a Local binding for `x` in the Function scope.
        let src = "fn f() { let x = 1; }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();

        let fn_scope_id = facts
            .scopes
            .iter()
            .position(|s| s.kind == ScopeKind::Function)
            .expect("expected a Function scope");

        let x_binding = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Local && b.name == "x")
            .expect("expected a Local binding for 'x'");

        assert_eq!(
            x_binding.scope, fn_scope_id,
            "x should be in the Function scope"
        );
        assert_eq!(x_binding.target, BindingTarget::Local);

        // intro must equal the start byte of the `x` identifier in the source.
        let expected_intro = src.find('x').expect("'x' not in src");
        assert_eq!(
            x_binding.intro, expected_intro,
            "intro should point at the 'x' token"
        );
    }

    #[test]
    fn shadowing_produces_two_local_bindings_with_different_intros() {
        // `fn f() { let x = 1; let x = 2; }` → two Local bindings both named
        // `x` with DIFFERENT intro offsets (the neutral fact enabling later
        // shadowing resolution).
        let src = "fn f() { let x = 1; let x = 2; }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();

        let x_bindings: Vec<_> = facts
            .bindings
            .iter()
            .filter(|b| b.kind == BindingKind::Local && b.name == "x")
            .collect();

        assert_eq!(
            x_bindings.len(),
            2,
            "expected exactly two Local bindings for 'x', got {}",
            x_bindings.len()
        );
        assert_ne!(
            x_bindings[0].intro, x_bindings[1].intro,
            "shadowed bindings must have different intro offsets"
        );
    }

    #[test]
    fn nested_block_let_binding_attributes_to_inner_block_scope() {
        // `fn f() { { let y = 1; } }` → the `y` Local binding's scope is the
        // inner Block scope, not the Function scope.
        let src = "fn f() { { let y = 1; } }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();

        let block_scope_id = facts
            .scopes
            .iter()
            .position(|s| s.kind == ScopeKind::Block)
            .expect("expected a Block scope");

        let y_binding = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Local && b.name == "y")
            .expect("expected a Local binding for 'y'");

        assert_eq!(
            y_binding.scope, block_scope_id,
            "y should be attributed to the inner Block scope ({}), got {}",
            block_scope_id, y_binding.scope
        );
    }

    #[test]
    fn impl_block_with_method_nests_type_then_function_scope() {
        // `impl Foo { fn bar() { call(); } }`
        // Expected nesting: root Module (0) → Type (impl body) → Function (method)
        // A call inside the method attributes to the Function scope (innermost).
        let src = "pub struct Foo; impl Foo { pub fn bar(&self) { call(); } }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();

        let type_scope_id = facts
            .scopes
            .iter()
            .position(|s| s.kind == ScopeKind::Type)
            .expect("expected a Type scope for the impl body");
        let fn_scope_id = facts
            .scopes
            .iter()
            .position(|s| s.kind == ScopeKind::Function)
            .expect("expected a Function scope for the method");

        // Type scope's parent must be the root (0).
        assert_eq!(
            facts.scopes[type_scope_id].parent,
            Some(0),
            "impl body Type scope parent should be root (0)"
        );
        // Function scope's parent must be the Type scope.
        assert_eq!(
            facts.scopes[fn_scope_id].parent,
            Some(type_scope_id),
            "method Function scope parent should be the Type scope"
        );

        // The call ref must attribute to the Function scope (innermost).
        let call_ref = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Call && r.name == "call")
            .expect("expected a Call ref for 'call'");
        assert_eq!(
            call_ref.scope,
            Some(fn_scope_id),
            "call() should attribute to the Function scope ({}), got {:?}",
            fn_scope_id,
            call_ref.scope
        );
    }

    // ── Receiver qualifier / binding type-name tests ────────────────────────────

    #[test]
    fn field_expression_call_captures_receiver_as_qualifier() {
        // `r.save()` → exactly one Call ref for "save", with qualifier = "r"
        // (the receiver identifier) and self_receiver = false.
        let src = "fn f() { let r: Repo = Repo; r.save(); }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();

        let save_refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Call && r.name == "save")
            .collect();
        assert_eq!(
            save_refs.len(),
            1,
            "expected exactly one Call ref for 'save', got {save_refs:?}"
        );
        assert_eq!(save_refs[0].qualifier.as_deref(), Some("r"));
        assert!(!save_refs[0].self_receiver);
    }

    #[test]
    fn self_receiver_call_keeps_qualifier_none() {
        // `self.hello()` must remain self_receiver = true, qualifier = None —
        // the bare-identifier receiver query must not match the `self` node.
        let src = "impl Person { fn greet(&self) { self.hello(); } }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();

        let hello_ref = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Call && r.name == "hello")
            .expect("expected a Call ref for 'hello'");
        assert!(hello_ref.self_receiver);
        assert_eq!(hello_ref.qualifier, None);
    }

    #[test]
    fn let_with_type_annotation_sets_binding_type_name() {
        let src = "fn f() { let r: Repo = Repo; r.save(); }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();

        let r_binding = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Local && b.name == "r")
            .expect("expected a Local binding for 'r'");
        assert_eq!(r_binding.type_name.as_deref(), Some("Repo"));
    }

    #[test]
    fn param_type_sets_binding_type_name() {
        let src = "fn f(r: Repo) {}";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();

        let r_binding = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Param && b.name == "r")
            .expect("expected a Param binding for 'r'");
        assert_eq!(r_binding.type_name.as_deref(), Some("Repo"));
    }

    #[test]
    fn let_without_annotation_or_recognized_constructor_leaves_type_name_none() {
        // Bare-value `let r = Repo;` (no type annotation, no `{}`/`()`
        // constructor) is not a recognized shape — fail closed.
        let src = "fn f() { let r = Repo; r.save(); }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();

        let r_binding = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Local && b.name == "r")
            .expect("expected a Local binding for 'r'");
        assert_eq!(r_binding.type_name, None);
    }

    // ── Definition binding tests ──────────────────────────────────────────────

    #[test]
    fn pub_fn_emits_definition_binding() {
        // `pub fn foo() {}` → a Definition binding: name "foo", scope 0,
        // kind Definition, target Def(_).
        let src = "pub fn foo() {}";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();

        let b = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Definition && b.name == "foo")
            .expect("expected a Definition binding named 'foo'");
        assert_eq!(b.scope, 0, "top-level def must bind in scope 0");
        assert!(
            matches!(b.target, BindingTarget::Def(_)),
            "Definition binding target must be Def(_), got {:?}",
            b.target
        );
    }

    #[test]
    fn pub_struct_emits_definition_binding_in_root_scope() {
        // `pub struct Bar {}` → a Definition binding named "Bar" in scope 0
        // (not in the struct body's Type scope).
        let src = "pub struct Bar {}";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();

        let b = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Definition && b.name == "Bar")
            .expect("expected a Definition binding named 'Bar'");
        assert_eq!(b.scope, 0, "struct def must bind in root scope 0");
        assert!(
            matches!(b.target, BindingTarget::Def(_)),
            "Definition binding target must be Def(_)"
        );
    }

    #[test]
    fn use_stmt_emits_import_binding() {
        // `use std::io::Result;` → an Import binding: name "Result",
        // kind Import, target Import("std::io").
        let src = "use std::io::Result;";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();

        let b = facts
            .bindings
            .iter()
            .find(|b| b.kind == BindingKind::Import && b.name == "Result")
            .expect("expected an Import binding named 'Result'");
        assert_eq!(
            b.target,
            BindingTarget::Import("std::io".to_owned()),
            "import binding target should be Import(\"std::io\"), got {:?}",
            b.target
        );
    }

    #[test]
    fn module_file_symbol_does_not_produce_definition_binding() {
        // The synthetic module symbol pushed last in `extract` must NOT get a
        // Definition binding. Here we have exactly one real top-level def
        // (`pub fn foo`), so there must be exactly one Definition binding and
        // its name must be "foo", not the file-stem "lib".
        let src = "pub fn foo() {}";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();

        let def_bindings: Vec<_> = facts
            .bindings
            .iter()
            .filter(|b| b.kind == BindingKind::Definition)
            .collect();
        assert_eq!(
            def_bindings.len(),
            1,
            "expected exactly one Definition binding, got {}: {:?}",
            def_bindings.len(),
            def_bindings.iter().map(|b| &b.name).collect::<Vec<_>>()
        );
        assert_eq!(
            def_bindings[0].name, "foo",
            "the sole Definition binding must be 'foo', not the module stem"
        );
    }

    // ── qualifier capture tests (unit 8a) ────────────────────────────────────

    #[test]
    fn qualified_call_single_segment_captures_qualifier() {
        // `mod_a::process()` → leaf "process", qualifier Some("mod_a")
        let src = "pub fn caller() { mod_a::process(); }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let r = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Call && r.name == "process")
            .expect("expected a Call ref for 'process'");
        assert_eq!(
            r.qualifier,
            Some("mod_a".to_owned()),
            "qualifier should be 'mod_a', got {:?}",
            r.qualifier
        );
    }

    #[test]
    fn qualified_call_nested_segments_captures_full_qualifier() {
        // `a::b::process()` → leaf "process", qualifier Some("a::b")
        let src = "pub fn caller() { a::b::process(); }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let r = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Call && r.name == "process")
            .expect("expected a Call ref for 'process'");
        assert_eq!(
            r.qualifier,
            Some("a::b".to_owned()),
            "qualifier should be 'a::b', got {:?}",
            r.qualifier
        );
    }

    #[test]
    fn unqualified_call_has_no_qualifier() {
        // `helper()` → qualifier None
        let src = "pub fn caller() { helper(); }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let r = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Call && r.name == "helper")
            .expect("expected a Call ref for 'helper'");
        assert_eq!(
            r.qualifier, None,
            "unqualified call should have qualifier == None, got {:?}",
            r.qualifier
        );
    }

    #[test]
    fn method_call_via_field_expression_captures_receiver_as_qualifier() {
        // `obj.method()` — field_expression arm captures the receiver identifier
        // `obj` as the `qualifier` (a receiver, resolved by the local-typed-call
        // resolver to `obj`'s binding type; the resolver, not the extractor,
        // decides whether the qualifier is a type path or a local variable).
        let src = "pub fn caller(obj: Foo) { obj.method(); }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let r = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Call && r.name == "method")
            .expect("expected a Call ref for 'method'");
        assert_eq!(
            r.qualifier.as_deref(),
            Some("obj"),
            "method call via field_expression should capture the receiver `obj` as qualifier, got {:?}",
            r.qualifier
        );
        assert!(
            !r.self_receiver,
            "a non-self receiver must not be marked self_receiver"
        );
    }

    #[test]
    fn self_receiver_method_call_is_marked_self_receiver() {
        // `self.foo()` — field_expression arm with a `self` value → leaf "foo",
        // qualifier None, self_receiver true.
        let src = "impl Person { fn caller(&self) { self.foo(); } }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let r = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::Call && r.name == "foo")
            .expect("expected a Call ref for 'foo'");
        assert!(
            r.self_receiver,
            "self.foo() should have self_receiver == true"
        );
        assert_eq!(
            r.qualifier, None,
            "self.foo() should still have qualifier == None, got {:?}",
            r.qualifier
        );
    }

    #[test]
    fn non_self_method_call_is_not_marked_self_receiver() {
        // `x.foo()` on a local variable — must NOT be marked self_receiver.
        let src = "impl Person { fn caller(&self, x: Foo) { x.foo(); } }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
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

    #[test]
    fn combined_def_and_use_emit_both_kinds_and_locals_still_work() {
        // A file with a top-level def + a `use` + a local let:
        // → a Definition binding for `foo`
        // → an Import binding for `Result`
        // → a Param binding (from prior unit) for the function param
        // → a Local binding for the let variable
        let src = "use std::io::Result;\npub fn foo(x: u32) { let y = 1; }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();

        // Definition binding present.
        assert!(
            facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Definition && b.name == "foo"),
            "expected a Definition binding for 'foo'"
        );
        // Import binding present.
        assert!(
            facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Import && b.name == "Result"),
            "expected an Import binding for 'Result'"
        );
        // Param binding from prior unit still works.
        assert!(
            facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Param && b.name == "x"),
            "expected a Param binding for 'x' (regression check)"
        );
        // Local binding from prior unit still works.
        assert!(
            facts
                .bindings
                .iter()
                .any(|b| b.kind == BindingKind::Local && b.name == "y"),
            "expected a Local binding for 'y' (regression check)"
        );
    }

    // ── TypeRef tests ─────────────────────────────────────────────────────────

    fn type_refs(facts: &crate::graph::FileFacts) -> Vec<&Reference> {
        facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::TypeRef)
            .collect()
    }

    #[test]
    fn typeref_param_and_return_types_captured() {
        // `fn validate(cfg: Config) -> Outcome {}` → TypeRef refs for `Config` (param)
        // and `Outcome` (return type).
        let src = "fn validate(cfg: Config) -> Outcome {}";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let names: Vec<&str> = type_refs(&facts).iter().map(|r| r.name.as_str()).collect();
        assert!(
            names.contains(&"Config"),
            "expected TypeRef for 'Config' in {names:?}"
        );
        assert!(
            names.contains(&"Outcome"),
            "expected TypeRef for 'Outcome' in {names:?}"
        );
        for r in type_refs(&facts) {
            assert_eq!(
                r.role,
                RefRole::TypeRef,
                "role should be TypeRef, got {:?}",
                r.role
            );
        }
    }

    #[test]
    fn typeref_struct_field_type_captured() {
        // `struct Holder { item: Widget }` → TypeRef ref named `Widget`.
        let src = "struct Holder { item: Widget }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let names: Vec<&str> = type_refs(&facts).iter().map(|r| r.name.as_str()).collect();
        assert!(
            names.contains(&"Widget"),
            "expected TypeRef for 'Widget' in {names:?}"
        );
    }

    #[test]
    fn typeref_generic_base_and_argument_are_captured() {
        // `fn f(v: Vec<Config>) {}` captures both base and generic argument.
        let src = "fn f(v: Vec<Config>) {}";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let names: Vec<&str> = type_refs(&facts).iter().map(|r| r.name.as_str()).collect();
        assert!(
            names.contains(&"Vec"),
            "expected TypeRef for 'Vec' (base generic) in {names:?}"
        );
        assert!(
            names.contains(&"Config"),
            "expected generic argument in {names:?}"
        );
        assert_eq!(
            type_refs(&facts)
                .into_iter()
                .find(|reference| reference.name == "Config")
                .and_then(|reference| reference.type_ref_ctx),
            Some(TypeRefContext::GenericArg)
        );
    }

    #[test]
    fn typeref_scoped_type_emits_leaf_and_qualifier() {
        // `fn f(r: std::io::Result) {}` → TypeRef ref `name == "Result"`,
        // `qualifier == Some("std::io")`.
        let src = "fn f(r: std::io::Result) {}";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let r = type_refs(&facts)
            .into_iter()
            .find(|r| r.name == "Result")
            .expect("expected a TypeRef ref named 'Result'");
        assert_eq!(
            r.qualifier,
            Some("std::io".to_owned()),
            "qualifier should be 'std::io', got {:?}",
            r.qualifier
        );
    }

    #[test]
    fn typeref_compound_types_capture_all_named_components() {
        let facts = RustExtractor
            .extract(
                "struct Holder { value: Option<Vec<Config>>, pair: (Left, Right) }",
                "src/lib.rs",
            )
            .unwrap();
        let references = type_refs(&facts);
        for name in ["Option", "Vec", "Config", "Left", "Right"] {
            assert!(
                references.iter().any(|reference| reference.name == name),
                "missing {name}"
            );
        }
        assert_eq!(
            references
                .iter()
                .find(|reference| reference.name == "Config")
                .and_then(|reference| reference.type_ref_ctx),
            Some(TypeRefContext::GenericArg)
        );
    }

    #[test]
    fn associated_call_subject_emits_type_reference() {
        let src = "fn parse(node: &Node) { crate::params::FusionParams::extract(node); }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let reference = type_refs(&facts)
            .into_iter()
            .find(|reference| reference.name == "FusionParams")
            .expect("associated call subject TypeRef");
        assert_eq!(reference.qualifier.as_deref(), Some("crate::params"));
    }

    #[test]
    fn typeref_reference_type_descends_through_borrow() {
        // `fn f(c: &Config) {}` → TypeRef ref named `Config` (descended through `&`).
        let src = "fn f(c: &Config) {}";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let names: Vec<&str> = type_refs(&facts).iter().map(|r| r.name.as_str()).collect();
        assert!(
            names.contains(&"Config"),
            "expected TypeRef for 'Config' through '&' in {names:?}"
        );
    }

    #[test]
    fn typeref_primitive_type_not_captured() {
        // Primitives (u32, bool, i64, …) are skipped — they never resolve to a
        // user-defined Symbol, so capturing them only adds noise.
        let src = "fn f(n: u32, b: bool) -> i64 { 0 }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let names: Vec<&str> = type_refs(&facts).iter().map(|r| r.name.as_str()).collect();
        assert!(
            !names.contains(&"u32"),
            "primitive 'u32' should NOT be captured as TypeRef (got {names:?})"
        );
        assert!(
            !names.contains(&"bool"),
            "primitive 'bool' should NOT be captured as TypeRef (got {names:?})"
        );
        assert!(
            !names.contains(&"i64"),
            "primitive 'i64' should NOT be captured as TypeRef (got {names:?})"
        );
    }

    #[test]
    fn typeref_empty_fn_no_types_emits_no_typeref() {
        // `fn f() {}` with no type annotations → zero TypeRef refs.
        let src = "fn f() {}";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let trefs = type_refs(&facts);
        assert!(
            trefs.is_empty(),
            "fn with no types should produce no TypeRef refs, got {:?}",
            trefs.iter().map(|r| &r.name).collect::<Vec<_>>()
        );
    }

    // ── Read / Write reference tests ──────────────────────────────────────────

    #[test]
    fn read_ref_emitted_for_tail_use_not_declaration() {
        // `fn f() -> i32 { let base = 1; base }` →
        //   - a Read ref for the tail `base` expression
        //   - the `let base` binding name is NOT a Read
        let src = "fn f() -> i32 { let base = 1; base }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let read_refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Read && r.name == "base")
            .collect();
        // There must be at least one Read ref (the tail `base` expression).
        assert!(
            !read_refs.is_empty(),
            "expected at least one Read ref for 'base', got none"
        );
        // The `let base` token is at the first `base` in source ("let base = 1").
        // The tail use `base` appears after the `=` and `;`.
        let decl_offset = src.find("let base").unwrap() + "let ".len();
        // All Read refs must be AFTER the declaration offset (not the let binding itself).
        for r in &read_refs {
            assert!(
                r.occ.byte > decl_offset,
                "Read ref for 'base' at byte {} should be after declaration offset {}",
                r.occ.byte,
                decl_offset
            );
        }
    }

    #[test]
    fn write_ref_emitted_for_assignment_not_let() {
        // `fn f() { let mut cnt = 0; cnt = 5; }` →
        //   - a Write ref for the `cnt = 5` assignment LHS
        //   - the `let mut cnt` declaration name is NOT a Write
        let src = "fn f() { let mut cnt = 0; cnt = 5; }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let write_refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Write && r.name == "cnt")
            .collect();
        assert!(
            !write_refs.is_empty(),
            "expected at least one Write ref for 'cnt', got none — all refs: {:?}",
            facts
                .references
                .iter()
                .map(|r| (&r.name, r.role))
                .collect::<Vec<_>>()
        );
        // `cnt = 5` starts after the declaration — byte offset > the `let` start.
        let assign_offset = src.find("cnt = 5").unwrap();
        for r in &write_refs {
            assert!(
                r.occ.byte >= assign_offset,
                "Write ref for 'cnt' at byte {} should be at/after the assignment at {}",
                r.occ.byte,
                assign_offset
            );
        }
    }

    #[test]
    fn compound_assignment_emits_write_ref() {
        // `fn f() { let mut num = 0; num += 1; }` → a Write ref "num" for `num += 1`.
        let src = "fn f() { let mut num = 0; num += 1; }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let write_refs: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Write && r.name == "num")
            .collect();
        assert!(
            !write_refs.is_empty(),
            "expected a Write ref for 'num' from compound assignment, got none — all refs: {:?}",
            facts
                .references
                .iter()
                .map(|r| (&r.name, r.role))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn call_not_also_read() {
        // `fn f() { helper(); }` → a Call ref "helper", NOT also a Read for "helper".
        let src = "fn f() { helper(); }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
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
    fn field_access_not_a_read_of_field() {
        // `fn f(c: C) -> i32 { c.field }` →
        //   - a Read ref "c" (the receiver) is acceptable
        //   - NO Read ref "field" (field_identifier is a different node kind)
        let src = "fn f(c: C) -> i32 { c.field }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let field_reads: Vec<_> = facts
            .references
            .iter()
            .filter(|r| r.role == RefRole::Read && r.name == "field")
            .collect();
        assert!(
            field_reads.is_empty(),
            "field 'field' in field_expression must NOT be a Read ref; got: {field_reads:?}"
        );
    }

    // ── assoc fn / assoc const extraction (unit C3) ───────────────────────────

    #[test]
    fn assoc_fn_symbol_emitted_for_pub_new() {
        // `pub fn new()` in an inherent impl → SymbolKind::Method, SCIP ends `Foo#new().`
        let src = "pub struct Foo; impl Foo { pub fn new() -> Self { Foo } }";
        let facts = RustExtractor.extract(src, "src/foo.rs").unwrap();
        let sym = facts
            .symbols
            .iter()
            .find(|s| s.name == "new" && s.kind == SymbolKind::Method)
            .expect("expected a Method symbol named 'new'");
        assert!(
            sym.id.to_scip_string().ends_with("Foo#new()."),
            "SCIP string should end with 'Foo#new().', got: {}",
            sym.id.to_scip_string()
        );
    }

    #[test]
    fn assoc_const_symbol_emitted_for_pub_const() {
        // `pub const MAX: u32 = 3;` in an inherent impl → SymbolKind::Const, SCIP ends `Foo#MAX.`
        let src = "pub struct Foo; impl Foo { pub const MAX: u32 = 3; }";
        let facts = RustExtractor.extract(src, "src/foo.rs").unwrap();
        let sym = facts
            .symbols
            .iter()
            .find(|s| s.name == "MAX" && s.kind == SymbolKind::Const)
            .expect("expected a Const symbol named 'MAX'");
        assert!(
            sym.id.to_scip_string().ends_with("Foo#MAX."),
            "SCIP string should end with 'Foo#MAX.', got: {}",
            sym.id.to_scip_string()
        );
    }

    #[test]
    fn method_with_self_is_emitted() {
        // `pub fn run(&self)` in an inherent impl → SymbolKind::Method, SCIP ends `Foo#run().`
        let src = "pub struct Foo; impl Foo { pub fn run(&self) {} }";
        let facts = RustExtractor.extract(src, "src/foo.rs").unwrap();
        let sym = facts
            .symbols
            .iter()
            .find(|s| s.name == "run" && s.kind == SymbolKind::Method)
            .expect("expected a Method symbol named 'run'");
        assert!(
            sym.id.to_scip_string().ends_with("Foo#run()."),
            "SCIP string should end with 'Foo#run().', got: {}",
            sym.id.to_scip_string()
        );
    }

    #[test]
    fn non_pub_member_emitted_with_private_visibility() {
        // `fn secret(&self) {}` (no `pub`) → symbol IS emitted, tagged Private.
        let src = "pub struct Foo; impl Foo { fn secret(&self) {} }";
        let facts = RustExtractor.extract(src, "src/foo.rs").unwrap();
        let secret = facts
            .symbols
            .iter()
            .find(|s| s.name == "secret")
            .expect("private method 'secret' must now be emitted as a symbol");
        assert_eq!(
            secret.visibility,
            Visibility::Private,
            "private method 'secret' must have Visibility::Private, got {:?}",
            secret.visibility
        );
        assert_eq!(secret.kind, SymbolKind::Method);
    }

    #[test]
    fn trait_impl_members_and_container_are_excluded() {
        // `impl std::fmt::Display for Point { fn fmt(...) }` emits neither a
        // member definition under `Point#` nor a symbol for the impl container.
        let src = r#"pub struct Point;
impl std::fmt::Display for Point {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result { Ok(()) }
}"#;
        let facts = RustExtractor.extract(src, "src/foo.rs").unwrap();

        assert!(
            !facts.symbols.iter().any(|s| s.kind == SymbolKind::Impl),
            "impl containers must not mint symbols"
        );
        // No symbol named "fmt" under Point# should be emitted.
        let fmt_under_point: Vec<_> = facts
            .symbols
            .iter()
            .filter(|s| s.name == "fmt" && s.id.to_scip_string().contains("Point#"))
            .collect();
        assert!(
            fmt_under_point.is_empty(),
            "trait-impl method 'fmt' must NOT be emitted under Point#, got: {:?}",
            fmt_under_point
                .iter()
                .map(|s| s.id.to_scip_string())
                .collect::<Vec<_>>()
        );
    }

    // ── Visibility tests (unit F2) ────────────────────────────────────────────

    #[test]
    fn pub_fn_has_public_visibility() {
        // `pub fn f() {}` → symbol with Visibility::Public.
        let src = "pub fn f() {}";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let sym = facts
            .symbols
            .iter()
            .find(|s| s.name == "f" && s.kind == SymbolKind::Function)
            .expect("expected a Function symbol named 'f'");
        assert_eq!(
            sym.visibility,
            Visibility::Public,
            "pub fn should have Visibility::Public, got {:?}",
            sym.visibility
        );
    }

    #[test]
    fn private_fn_has_private_visibility() {
        // `fn g() {}` (no modifier) → symbol IS emitted with Visibility::Private.
        let src = "fn g() {}";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let sym = facts
            .symbols
            .iter()
            .find(|s| s.name == "g" && s.kind == SymbolKind::Function)
            .expect("expected a Function symbol named 'g'");
        assert_eq!(
            sym.visibility,
            Visibility::Private,
            "fn with no modifier should have Visibility::Private, got {:?}",
            sym.visibility
        );
    }

    #[test]
    fn pub_crate_fn_has_internal_visibility() {
        // `pub(crate) fn h() {}` → symbol with Visibility::Internal.
        let src = "pub(crate) fn h() {}";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let sym = facts
            .symbols
            .iter()
            .find(|s| s.name == "h" && s.kind == SymbolKind::Function)
            .expect("expected a Function symbol named 'h'");
        assert_eq!(
            sym.visibility,
            Visibility::Internal,
            "pub(crate) fn should have Visibility::Internal, got {:?}",
            sym.visibility
        );
    }

    #[test]
    fn private_impl_method_emitted_with_private_visibility() {
        // `fn inner(&self) {}` in an inherent impl (no `pub`) →
        // symbol IS emitted with Visibility::Private.
        let src = "pub struct Bar; impl Bar { fn inner(&self) {} }";
        let facts = RustExtractor.extract(src, "src/lib.rs").unwrap();
        let sym = facts
            .symbols
            .iter()
            .find(|s| s.name == "inner" && s.kind == SymbolKind::Method)
            .expect("expected a Method symbol named 'inner'");
        assert_eq!(
            sym.visibility,
            Visibility::Private,
            "private impl method should have Visibility::Private, got {:?}",
            sym.visibility
        );
    }

    // ── Entry-point detection (E2) ────────────────────────────────────────────

    /// Find a symbol by bare name in the extracted facts (panics if absent).
    fn sym_by_name(facts: &crate::graph::types::FileFacts, name: &str) -> Symbol {
        facts
            .symbols
            .iter()
            .find(|s| s.name == name)
            .unwrap_or_else(|| {
                panic!(
                    "symbol '{name}' not found; symbols: {:?}",
                    facts
                        .symbols
                        .iter()
                        .map(|s| s.name.as_str())
                        .collect::<Vec<_>>()
                )
            })
            .clone()
    }

    /// Render entry_points as a compact string for assertion messages.
    fn ep_str(eps: &[EntryPoint]) -> String {
        eps.iter()
            .map(|ep| match ep {
                EntryPoint::Main => "Main".to_owned(),
                EntryPoint::HttpRoute(m) => format!("HttpRoute({m})"),
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    #[test]
    fn rust_entry_point_get_route() {
        // `#[get("/")]` is an Actix-web/Rocket route attribute; terminal = "get".
        let src = "#[get(\"/\")]\npub fn index() -> String { String::new() }";
        let facts = RustExtractor.extract(src, "src/routes.rs").unwrap();
        let sym = sym_by_name(&facts, "index");
        assert_eq!(
            sym.entry_points.len(),
            1,
            "expected exactly 1 entry point, got [{}]",
            ep_str(&sym.entry_points)
        );
        assert!(
            matches!(&sym.entry_points[0], EntryPoint::HttpRoute(m) if m == "get"),
            "expected HttpRoute(\"get\"), got [{}]",
            ep_str(&sym.entry_points)
        );
    }

    #[test]
    fn rust_entry_point_post_route() {
        // `#[post("/users")]` → HttpRoute("post").
        let src = "#[post(\"/users\")]\npub fn create() {}";
        let facts = RustExtractor.extract(src, "src/routes.rs").unwrap();
        let sym = sym_by_name(&facts, "create");
        assert_eq!(
            sym.entry_points.len(),
            1,
            "expected exactly 1 entry point, got [{}]",
            ep_str(&sym.entry_points)
        );
        assert!(
            matches!(&sym.entry_points[0], EntryPoint::HttpRoute(m) if m == "post"),
            "expected HttpRoute(\"post\"), got [{}]",
            ep_str(&sym.entry_points)
        );
    }

    #[test]
    fn rust_entry_point_non_route_attr_ignored() {
        // `#[derive(Debug)]` and `#[inline]` are not route attrs — entry_points must be empty.
        let src = "#[derive(Debug)]\n#[inline]\npub fn helper() {}";
        let facts = RustExtractor.extract(src, "src/util.rs").unwrap();
        let sym = sym_by_name(&facts, "helper");
        assert!(
            sym.entry_points.is_empty(),
            "non-route attributes must not produce entry points; got [{}]",
            ep_str(&sym.entry_points)
        );
    }

    #[test]
    fn rust_entry_point_main_fn_name() {
        // A function literally named `main` → EntryPoint::Main.
        let src = "pub fn main() {}";
        let facts = RustExtractor.extract(src, "src/main.rs").unwrap();
        let sym = sym_by_name(&facts, "main");
        assert_eq!(
            sym.entry_points.len(),
            1,
            "expected exactly 1 entry point, got [{}]",
            ep_str(&sym.entry_points)
        );
        assert!(
            matches!(&sym.entry_points[0], EntryPoint::Main),
            "expected Main, got [{}]",
            ep_str(&sym.entry_points)
        );
    }

    #[test]
    fn rust_entry_point_plain_fn_empty() {
        // A plain function with no special attribute or name → empty entry_points.
        let src = "pub fn process() {}";
        let facts = RustExtractor.extract(src, "src/util.rs").unwrap();
        let sym = sym_by_name(&facts, "process");
        assert!(
            sym.entry_points.is_empty(),
            "plain function must have no entry points; got [{}]",
            ep_str(&sym.entry_points)
        );
    }

    #[test]
    fn rust_entry_point_qualified_path_terminal() {
        // `#[actix_web::get("/")]` — qualified path; terminal identifier = "get".
        let src = "#[actix_web::get(\"/\")]\npub fn scoped() {}";
        let facts = RustExtractor.extract(src, "src/routes.rs").unwrap();
        let sym = sym_by_name(&facts, "scoped");
        assert_eq!(
            sym.entry_points.len(),
            1,
            "expected exactly 1 entry point, got [{}]",
            ep_str(&sym.entry_points)
        );
        assert!(
            matches!(&sym.entry_points[0], EntryPoint::HttpRoute(m) if m == "get"),
            "expected HttpRoute(\"get\"), got [{}]",
            ep_str(&sym.entry_points)
        );
    }

    #[test]
    fn rust_entry_point_tokio_main_not_a_route() {
        // `#[tokio::main]` has terminal `main` which is NOT in RUST_ROUTE_ATTRS,
        // so it does NOT produce an HttpRoute. But `fn main` name → EntryPoint::Main.
        let src = "#[tokio::main]\nasync fn main() {}";
        let facts = RustExtractor.extract(src, "src/main.rs").unwrap();
        let sym = sym_by_name(&facts, "main");
        // Should have exactly Main, not an HttpRoute for "main".
        assert_eq!(
            sym.entry_points.len(),
            1,
            "expected exactly 1 entry point (Main), got [{}]",
            ep_str(&sym.entry_points)
        );
        assert!(
            matches!(&sym.entry_points[0], EntryPoint::Main),
            "expected Main, got [{}]",
            ep_str(&sym.entry_points)
        );
    }

    #[test]
    fn ffi_exports_require_exact_unconditional_attributes() {
        let cases = [
            (
                "#[doc = \"no_mangle\"]\npub extern \"C\" fn documented() {}",
                "documented",
            ),
            (
                "#[other_no_mangle]\npub extern \"C\" fn lookalike() {}",
                "lookalike",
            ),
            (
                "#[export_name_note = \"ffi_name\"]\npub extern \"C\" fn note() {}",
                "note",
            ),
            (
                "#[cfg_attr(feature = \"ffi\", no_mangle)]\npub extern \"C\" fn conditional() {}",
                "conditional",
            ),
            (
                "#[cfg_attr(feature = \"ffi\", doc = \"no_mangle\")]\npub extern \"C\" fn quoted() {}",
                "quoted",
            ),
            (
                "#[cfg_attr(feature = \"ffi\", unrelated::no_mangle)]\npub extern \"C\" fn nested_unrelated() {}",
                "nested_unrelated",
            ),
        ];

        let incorrectly_exported: Vec<_> = cases
            .iter()
            .filter_map(|(source, name)| {
                let facts = RustExtractor.extract(source, "src/ffi.rs").unwrap();
                (!facts.ffi_exports.is_empty()).then_some(*name)
            })
            .collect();

        assert!(
            incorrectly_exported.is_empty(),
            "only exact, unconditional supported attributes may create FFI facts; got {incorrectly_exported:?}"
        );
    }

    #[test]
    fn cross_file_assoc_fn_call_resolves_to_impl_member() {
        // The point of unit C3: `Point::new()` in main.rs must resolve to the
        // `new` symbol in point.rs via a Call edge whose `to` ends with `Point#new().`.
        use crate::resolve::{Resolver, SymbolTableResolver};

        let point = RustExtractor
            .extract(
                "pub struct Point; impl Point { pub fn new() -> Self { Point } }",
                "src/point.rs",
            )
            .unwrap();
        let main = RustExtractor
            .extract("pub fn run() { let _ = Point::new(); }", "src/main.rs")
            .unwrap();

        let graph = SymbolTableResolver.resolve(&[point, main]).unwrap();

        let call_to_new: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.role == RefRole::Call && e.to.to_scip_string().ends_with("Point#new()."))
            .collect();
        assert_eq!(
            call_to_new.len(),
            1,
            "expected exactly one Call edge to Point#new().(), got: {:?}",
            call_to_new
                .iter()
                .map(|e| format!("{} -> {}", e.from.to_scip_string(), e.to.to_scip_string()))
                .collect::<Vec<_>>()
        );
    }

    // ── Query-binding cross-artifact refs (code→SQL) ─────────────────────────

    #[cfg(feature = "sql")]
    #[test]
    fn sqlx_query_call_emits_cross_artifact_typeref() {
        let src = r#"pub fn f() { sqlx::query("SELECT id FROM users"); }"#;
        let facts = RustExtractor
            .extract_with_bindings(src, "src/app.rs", &BindingRules::with_defaults())
            .unwrap();

        let found = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::TypeRef && r.name == "users" && r.cross_artifact);
        let r = found.expect("expected a cross-artifact TypeRef reference named 'users'");

        let select_byte = src.find("SELECT").expect("fixture contains SELECT");
        assert!(
            r.occ.byte >= select_byte,
            "reference byte {} should point at/after 'SELECT' at {}",
            r.occ.byte,
            select_byte
        );
    }

    #[cfg(feature = "sql")]
    #[test]
    fn sqlx_query_macro_emits_cross_artifact_typeref() {
        let src = r#"pub fn f() { sqlx::query!("SELECT id FROM users"); }"#;
        let facts = RustExtractor
            .extract_with_bindings(src, "src/app.rs", &BindingRules::with_defaults())
            .unwrap();

        let found = facts
            .references
            .iter()
            .find(|r| r.role == RefRole::TypeRef && r.name == "users" && r.cross_artifact);
        let r = found.expect(
            "expected a cross-artifact TypeRef reference named 'users' from the macro form",
        );

        let select_byte = src.find("SELECT").expect("fixture contains SELECT");
        assert!(
            r.occ.byte >= select_byte,
            "reference byte {} should point at/after 'SELECT' at {}",
            r.occ.byte,
            select_byte
        );
    }

    #[cfg(feature = "sql")]
    #[test]
    fn empty_binding_rules_yield_no_cross_artifact_reference() {
        let src = r#"pub fn f() { sqlx::query("SELECT id FROM users"); }"#;
        let file = "src/app.rs";

        let with_empty_rules = RustExtractor
            .extract_with_bindings(src, file, &BindingRules::empty())
            .unwrap();
        assert!(
            !with_empty_rules.references.iter().any(|r| r.cross_artifact),
            "an empty binding-rule registry must yield no cross-artifact references"
        );

        let plain = RustExtractor.extract(src, file).unwrap();
        assert!(
            !plain.references.iter().any(|r| r.cross_artifact),
            "the plain extract() path must yield no cross-artifact references"
        );
    }

    #[cfg(feature = "sql")]
    #[test]
    fn cross_artifact_query_binding_resolves_to_sql_table() {
        use crate::extract::SqlExtractor;
        use crate::graph::{Confidence, Provenance};
        use crate::resolve::{Resolver, SymbolTableResolver};

        let schema = SqlExtractor
            .extract("CREATE TABLE users (id INT);", "db/schema.sql")
            .unwrap();

        let src = r#"pub fn f() { sqlx::query("SELECT id FROM users"); }"#;
        let rust_file = RustExtractor
            .extract_with_bindings(src, "src/app.rs", &BindingRules::with_defaults())
            .unwrap();

        let graph = SymbolTableResolver.resolve(&[schema, rust_file]).unwrap();

        let edges_to_users: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.role == RefRole::TypeRef && e.to.to_scip_string().ends_with("users#"))
            .collect();
        assert_eq!(
            edges_to_users.len(),
            1,
            "expected one Code→SQL TypeRef edge to 'users#', got: {:?}",
            edges_to_users
                .iter()
                .map(|e| format!("{} -> {}", e.from.to_scip_string(), e.to.to_scip_string()))
                .collect::<Vec<_>>()
        );

        let e = edges_to_users[0];
        assert_eq!(
            e.provenance,
            Provenance::CrossArtifact,
            "query-binding edge must carry Provenance::CrossArtifact, got {:?}",
            e.provenance
        );
        assert_eq!(
            e.confidence,
            Confidence::NameOnly,
            "query-binding edge must carry Confidence::NameOnly, got {:?}",
            e.confidence
        );
    }
}
