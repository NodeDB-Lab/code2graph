// SPDX-License-Identifier: Apache-2.0

//! Neutral structural-fact types — the output of code2graph.
//!
//! Identity lives in [`crate::symbol`] (SCIP-aligned). These types are the
//! facts a consumer reasons over: [`Symbol`] definitions, [`Reference`] sites,
//! resolved [`Edge`]s, and the per-file [`FileFacts`] / whole-graph [`CodeGraph`]
//! aggregates. No storage, no scores, no source bodies (symbols carry a span).

use crate::symbol::SymbolId;

/// Persistence schema for extracted per-file facts.
pub const FILE_FACTS_SCHEMA_VERSION: u32 = 1;
/// Persistence schema for resolved whole-project graphs.
pub const CODE_GRAPH_SCHEMA_VERSION: u32 = 1;

/// A half-open byte range `[start, end)` into a source file. Consumers slice
/// their own text from this — code2graph never carries source bodies.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteSpan {
    pub start: usize,
    pub end: usize,
}

impl ByteSpan {
    pub fn contains(&self, byte: usize) -> bool {
        self.start <= byte && byte < self.end
    }

    pub fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    pub fn is_empty(&self) -> bool {
        self.end <= self.start
    }
}

/// A location in a file. 1-based line, 0-based column, plus the byte offset
/// (used to attribute a reference to its enclosing symbol).
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Occurrence {
    pub file: String,
    pub line: u32,
    pub col: u32,
    pub byte: usize,
}

/// What kind of program element a symbol is. Cross-language superset; not every
/// variant applies to every language.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolKind {
    Function,
    Method,
    Struct,
    Enum,
    Trait,
    Interface,
    Class,
    TypeAlias,
    Const,
    Static,
    Module,
    Impl,
    /// A SQL table definition (`CREATE TABLE`).
    Table,
    /// A SQL view definition (`CREATE VIEW`).
    View,
    /// A SQL column (a member of a table/view).
    Column,
    /// An HCL/Terraform resource or data-source block.
    Resource,
    /// Escape hatch while the taxonomy settles.
    Other,
}

/// A deterministic syntactic entry-point marker on a definition — a neutral FACT,
/// never a judgement. code2graph records that a symbol carries the marker (e.g. an
/// HTTP-route decorator, or the name `main`); deciding whether that constitutes an
/// "attack surface" is the consumer's policy. Only emitted when the syntax is
/// unambiguously present — never guessed. The set is intentionally minimal and
/// additively extensible (event handlers etc. may be added later without breaking
/// consumers).
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone)]
pub enum EntryPoint {
    /// The definition is a language entry point. Emitted for:
    /// - a function/method named `main`: Rust/Go/C/C++ `main` (Go gated to
    ///   `package main`; Go/C++ require a free function, not a method), Python
    ///   `def main`, Kotlin top-level `fun main`, Scala/Swift `main`;
    /// - a `static` method named `Main` in C# (case-sensitive) and Java's
    ///   `public static void main`;
    /// - a Python module containing a top-level `if __name__ == "__main__":`
    ///   guard (the marker is attached to the module symbol).
    ///
    /// Honest syntactic markers only — never `@main`/`App`-style or framework
    /// conventions that need more than the name + an immediate modifier.
    Main,
    /// An HTTP route / request handler, identified by a framework decorator,
    /// annotation, or attribute. Carries the raw marker IDENTIFIER as written
    /// (e.g. `"app.route"`, `"GetMapping"`, `"get"`) — NOT the full call text or
    /// path argument — so a consumer can distinguish framework/method without
    /// reparsing. The path/body is recoverable from the symbol's span if needed.
    HttpRoute(String),
}

/// The declared visibility of a [`Symbol`] — a neutral fact, not a policy. The
/// extractor records what the syntax says; the consumer decides what to filter.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Visibility {
    /// Visible across module/package boundaries (Rust `pub`, Go capitalized,
    /// Java/PHP/C#/Kotlin `public`, exported, …).
    Public,
    /// Module/crate/package-scoped: `pub(crate)`/`pub(super)`, Java package-private,
    /// Swift/Kotlin/C#/Solidity `internal`, Scala `private[pkg]`.
    Internal,
    /// Visible to subclasses only (`protected`).
    Protected,
    /// Visible only within the defining scope (`private`, C internal linkage).
    Private,
    /// The AST cannot determine visibility syntactically (Ruby runtime visibility,
    /// dynamic languages, conventions like Dart's `_` prefix). Never guessed.
    Unknown,
}

/// A symbol definition found in a source file.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone)]
pub struct Symbol {
    /// SCIP-aligned identity.
    pub id: SymbolId,
    /// Bare (unqualified) name, e.g. `validate_token`.
    pub name: String,
    /// Element kind.
    pub kind: SymbolKind,
    /// Declared visibility (a neutral fact; consumers apply their own public/private policy).
    pub visibility: Visibility,
    /// Syntactic entry-point markers on this definition (route handlers, `main`,
    /// …). A neutral fact set — empty for most symbols; consumers apply their own
    /// attack-surface policy. See [`EntryPoint`].
    pub entry_points: Vec<EntryPoint>,
    /// File path relative to the project root.
    pub file: String,
    /// 1-based line of the definition.
    pub line: u32,
    /// Byte range of the whole definition in the source file.
    pub span: ByteSpan,
    /// One-line signature (declaration up to the body), whitespace-collapsed.
    pub signature: String,
}

/// The role a reference plays. `Call`, `IsImplementation`, `Import`, `TypeRef`,
/// and `ModuleRef` are live; `Read`/`Write` arrive with richer extractors.
///
/// Declaration order is the stable structural sort order used by [`EdgeKey`].
/// New variants must be appended rather than reordered.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefRole {
    /// The reference is a call or object-creation site.
    Call,
    /// The enclosing type extends or implements the referenced type — SCIP `is_implementation`.
    IsImplementation,
    /// The enclosing module imports the referenced symbol (an `import`/`use`
    /// statement). Its source resolves to the file's module symbol.
    Import,
    /// The reference names a *module* itself rather than an item within it — a
    /// module-declaration site (`mod x;`) or an intermediate module segment of
    /// an import path (the `alpha` in `use crate::alpha::helper`). It resolves
    /// to the referenced module's [`SymbolKind::Module`] symbol, yielding a
    /// file/module dependency graph distinct from item-level [`Import`](Self::Import)s.
    ModuleRef,
    /// The enclosing symbol references the named type in a signature or
    /// declaration position (parameter type, return type, field type, …) — a
    /// structural type-usage fact. The resolver links it to the type's
    /// definition like any other name reference.
    TypeRef,
    /// A plain name read in expression position (variable/param/const use).
    Read,
    /// An assignment write to a name (LHS of an assignment).
    Write,
}

/// Sub-type position for a [`RefRole::TypeRef`] reference — lets consumers ask
/// "what uses T as a return type" without splitting the `TypeRef` role.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TypeRefContext {
    /// The type appears as a function or method parameter type.
    ParameterType,
    /// The type appears as a function or method return type.
    ReturnType,
    /// The type appears as a struct/class/record field type.
    Field,
    /// The type appears as a generic type argument (e.g. `Vec<T>`).
    GenericArg,
    /// The type appears inside an attribute or annotation.
    Attribute,
    /// Any other type-reference position not covered by the above variants.
    Other,
}

/// A reference (call site / usage) found in a source file. Pre-resolution it
/// carries only the written `name`; the resolver links it to a [`Symbol`].
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone)]
pub struct Reference {
    /// The bare identifier as written at the use site.
    pub name: String,
    /// Where it occurs.
    pub occ: Occurrence,
    /// What kind of reference.
    pub role: RefRole,
    /// For [`RefRole::Import`] references: the SCIP display string of the
    /// importing file's module symbol. `None` for all other reference roles.
    pub source_module: Option<String>,
    /// For [`RefRole::Import`] references: the module path the symbol is imported
    /// from, as written in the source (e.g. `"pkg.models"`, `"std::io"`,
    /// `"./svc"`). `None` for non-import refs or when unavailable.
    pub from_path: Option<String>,
    /// For an aliased import, the source leaf before it was renamed locally.
    /// `None` when the local and source names are identical or unavailable.
    #[cfg_attr(feature = "serde", serde(default))]
    pub imported_name: Option<String>,
    /// Whether this import republishes its local name as part of the enclosing
    /// module's public API. Resolvers may follow these neutral alias facts when
    /// binding a later qualified reference; `false` for ordinary imports.
    #[cfg_attr(feature = "serde", serde(default))]
    pub is_reexport: bool,
    /// Written context that narrows the referenced relationship. For a
    /// path-qualified call or type reference (`mod_a::process()`, `a::b::Type`),
    /// this is the qualifier immediately before the leaf (for example `"mod_a"`
    /// or `"a::b"`). For [`RefRole::IsImplementation`], this is the written
    /// subject type that implements or extends `name`. `None` when no narrowing
    /// context is available. The extractor preserves syntax; resolvers interpret
    /// it according to the reference role.
    pub qualifier: Option<String>,
    /// The innermost scope enclosing this reference site; `None` until a
    /// scope-aware extractor populates it.
    pub scope: Option<ScopeId>,
    /// Sub-type context for [`RefRole::TypeRef`] references; `None` for all other roles.
    pub type_ref_ctx: Option<TypeRefContext>,
    /// True when this reference was derived from a secondary artifact embedded in
    /// the source (e.g. SQL inside a code string). The resolver attributes such
    /// references to [`Provenance::CrossArtifact`] with [`Confidence::NameOnly`].
    /// Extractors leave this false unless they emit a cross-artifact reference.
    #[cfg_attr(feature = "serde", serde(default))]
    pub cross_artifact: bool,
}

// ── Scope / binding data model ──────────────────────────────────────────────

/// Index into a file's [`FileFacts::scopes`] vector. Stable within one file's facts.
pub type ScopeId = usize;

/// What kind of lexical name-resolution region a scope is. Cross-language
/// superset; not every variant applies to every language.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScopeKind {
    /// A file-level or explicit module/namespace scope.
    Module,
    /// A function or method body scope.
    Function,
    /// A generic block scope (e.g. `if`/`for`/`{…}` bodies).
    Block,
    /// A type body scope (class, struct, enum, trait, interface, …).
    Type,
    /// Escape hatch while the taxonomy settles.
    Other,
}

/// A lexical scope: a nested name-resolution region within one file.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    /// The enclosing scope, or `None` for the file/module root scope.
    pub parent: Option<ScopeId>,
    /// Source range this scope governs.
    pub span: ByteSpan,
    /// What kind of lexical region this scope represents.
    pub kind: ScopeKind,
}

/// What kind of binding a name introduces — drives lexical visibility rules.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BindingKind {
    /// A local variable introduced by a `let`/`var`/assignment.
    Local,
    /// A function or method parameter.
    Param,
    /// A name brought into scope via an `import`/`use`/`require` statement.
    Import,
    /// A top-level definition (function, class, constant, …) participating in
    /// lexical lookup.
    Definition,
}

/// What a binding resolves to — the target of a name introduced by a [`Binding`].
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingTarget {
    /// File-local binding (parameter or `let`/`var`) — no global [`Symbol`].
    Local,
    /// An import: the module path as written in source (mirrors
    /// [`Reference::from_path`]).
    Import(String),
    /// Points at an extracted top-level [`Symbol`] by structural identity.
    Def(SymbolId),
}

/// A name introduced into a scope — a parameter, local variable, import alias,
/// or a top-level definition that participates in lexical lookup.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    /// The scope in which this name is introduced.
    pub scope: ScopeId,
    /// The bare identifier as written at the introduction site.
    pub name: String,
    /// Byte offset where the binding becomes visible (used to enforce
    /// declaration-order and detect shadowing).
    pub intro: usize,
    /// What kind of binding this is.
    pub kind: BindingKind,
    /// What the binding resolves to.
    pub target: BindingTarget,
}

// ── Confidence / Edge ────────────────────────────────────────────────────────

/// How confident the resolver is in an [`Edge`] — the precision marker that lets
/// consumers (e.g. a quality analyzer) gate on resolution quality.
///
/// Variants are ordered from least to most precise:
/// `Heuristic < NameOnly < Scoped < Exact`.
/// More-precise compares greater, so consumers can write threshold filters such
/// as `edge.confidence >= Confidence::Scoped` to drop `NameOnly` edges, or
/// `edge.confidence >= Confidence::NameOnly` to drop the lowest `Heuristic` tier.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Confidence {
    /// Lowest tier: a synthesized or normalized-name guess (e.g. case-folded
    /// name match). Present so consumers can opt into maximum recall, never
    /// dressed as a precise fact — filter it out for strict precision.
    Heuristic,
    /// Matched by name only — may be one of several same-named symbols.
    NameOnly,
    /// Narrowed by lexical scope / imports, or the referenced name has a unique
    /// global candidate — not type-checked.
    Scoped,
    /// Type/scope-precise (e.g. stack-graphs or type inference): exactly one binding.
    Exact,
}

/// Which analysis derived an [`Edge`] — its provenance.
///
/// Declaration order is the stable structural sort order used by [`EdgeKey`].
/// New variants must be appended rather than reordered.
///
/// This is **orthogonal to [`Confidence`]**: confidence answers "how sure are we
/// this binding is correct?", provenance answers "which mechanism produced it?".
/// A consumer uses provenance to filter or weight edges by *how* they were found
/// — e.g. trust scope-resolved edges over name-matched ones, or treat the
/// deterministic-but-cross-runtime FFI bridges specially — independently of the
/// per-edge confidence.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Provenance {
    /// Derived by name-based matching against the global symbol table (the
    /// recall-first resolver). May over-connect on ambiguous names.
    SymbolTable,
    /// Derived by lexical scope-graph resolution through scopes, imports, and
    /// qualified paths (the scope-aware resolver).
    ScopeGraph,
    /// Derived by matching a cross-language FFI boundary (e.g. `#[no_mangle]`
    /// / `extern` C ABI, PyO3, wasm-bindgen, NAPI, JNI). Links a symbol in one
    /// language to its counterpart across a runtime boundary.
    FfiBridge,
    /// Derived by an inheritance-chain walk — an inherited/implemented member
    /// found by traversing `IsImplementation` relationships up the type
    /// hierarchy (structural, not type-inferred).
    Conformance,
    /// Derived by case-insensitive / normalized name matching — a low-confidence
    /// recall tier that catches references differing from the definition only by
    /// case. Never fuzzy beyond case folding (no edit-distance/LSH).
    NormalizedName,
    /// Edge to a symbol OUTSIDE the analyzed set — an unresolved reference into a
    /// dependency, identified via import metadata. The call name was found in the
    /// file's import map (`RefRole::Import` with a `from_path`) but has no matching
    /// definition in the extracted files. The target's package coordinate is left
    /// empty for the consumer to enrich (e.g. a software-composition-analysis tool
    /// that maps `from_path` to a CVE advisory).
    External,
    /// Derived by matching a reference to a secondary artifact embedded in source
    /// (e.g. a SQL query string inside code) to that artifact's symbol by name.
    /// Always paired with [`Confidence::NameOnly`] — a bare embedded name is
    /// inherently ambiguous, never type/scope-precise.
    CrossArtifact,
}

// ── FFI / cross-language boundary facts ──────────────────────────────────────

/// The application binary interface a symbol is exported under for
/// cross-language linkage. Cross-language superset; grows as binding generators
/// are recognised.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FfiAbi {
    /// The C ABI — the lingua-franca FFI boundary (`#[no_mangle]` / `extern "C"`
    /// in Rust, `extern` declarations in C).
    C,
    /// A native Python extension binding (e.g. Rust PyO3 `#[pyfunction]`),
    /// callable from Python under the exported name.
    Python,
    /// A WebAssembly/JavaScript binding (e.g. Rust `#[wasm_bindgen]`), callable
    /// from JavaScript or TypeScript under the exported name.
    Wasm,
    /// A Node.js native addon binding (e.g. Rust `#[napi]`), callable from
    /// JavaScript or TypeScript under the exported name.
    NodeApi,
    /// A Java Native Interface binding: a Java `native` method backed by a C/Rust
    /// function whose name follows the `Java_<pkg>_<Class>_<method>` mangling.
    Jni,
}

/// A neutral cross-language export fact: the definition identified by [`symbol`]
/// is callable from another language under [`export_name`] via [`abi`]. The
/// extractor records it from a deterministic syntactic marker (e.g. Rust's
/// `#[no_mangle]`); a resolver bridges it to use-sites in other languages.
///
/// [`symbol`]: Self::symbol
/// [`export_name`]: Self::export_name
/// [`abi`]: Self::abi
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FfiExport {
    /// The exported definition's structural identity.
    pub symbol: SymbolId,
    /// The ABI the symbol is exposed under.
    pub abi: FfiAbi,
    /// The symbol name as seen across the boundary (the stable linker/ABI name).
    pub export_name: String,
}

/// A lossless identity key for a resolved [`Edge`].
///
/// Confidence is deliberately excluded: changing confidence updates the same
/// derived edge. Provenance is included because distinct resolver mechanisms can
/// produce distinct facts at the same occurrence. [`Ord`] compares exactly these
/// fields lexicographically in their documented order.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EdgeKey {
    /// Structural identity of the source symbol.
    pub from: SymbolId,
    /// Structural identity of the target symbol.
    pub to: SymbolId,
    /// Relationship expressed by the resolved reference.
    pub role: RefRole,
    /// File containing the reference occurrence.
    pub occurrence_file: String,
    /// Byte offset of the reference occurrence within [`Self::occurrence_file`].
    pub occurrence_byte: usize,
    /// Resolver mechanism that derived the edge.
    pub provenance: Provenance,
}

impl Ord for EdgeKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (
            &self.from,
            &self.to,
            self.role,
            &self.occurrence_file,
            self.occurrence_byte,
            self.provenance,
        )
            .cmp(&(
                &other.from,
                &other.to,
                other.role,
                &other.occurrence_file,
                other.occurrence_byte,
                other.provenance,
            ))
    }
}

impl PartialOrd for EdgeKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// A resolved directed edge between two symbols.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone)]
pub struct Edge {
    pub from: SymbolId,
    pub to: SymbolId,
    /// The relationship this edge expresses, mapped directly from the originating
    /// [`Reference::role`]. Consumers filter on this field — e.g.
    /// `e.role == RefRole::Call` to walk only call edges.
    pub role: RefRole,
    /// Resolver precision for this edge.
    pub confidence: Confidence,
    /// Which analysis derived this edge — orthogonal to [`confidence`](Self::confidence).
    pub provenance: Provenance,
    /// The reference site that produced the edge — the evidence trail.
    pub occ: Occurrence,
}

impl Edge {
    /// Return this edge's lossless identity, excluding its confidence attribute.
    pub fn key(&self) -> EdgeKey {
        EdgeKey {
            from: self.from.clone(),
            to: self.to.clone(),
            role: self.role,
            occurrence_file: self.occ.file.clone(),
            occurrence_byte: self.occ.byte,
            provenance: self.provenance,
        }
    }
}

/// The neutral facts extracted from a single file (extractor output, resolver input).
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone)]
pub struct FileFacts {
    /// File path relative to the project root.
    pub file: String,
    /// Language tag (see [`crate::lang::Language::as_str`]).
    pub lang: String,
    /// Top-level symbol definitions found in this file.
    pub symbols: Vec<Symbol>,
    /// Reference (use) sites found in this file.
    pub references: Vec<Reference>,
    /// Lexical scopes discovered in this file; indexed by [`ScopeId`].
    /// Empty until a scope-aware extractor populates it.
    pub scopes: Vec<Scope>,
    /// Name bindings discovered in this file. Empty until a scope-aware
    /// extractor populates it.
    pub bindings: Vec<Binding>,
    /// Cross-language export markers discovered in this file (e.g. Rust
    /// `#[no_mangle]` functions). Empty unless the language has FFI exports.
    pub ffi_exports: Vec<FfiExport>,
}

/// The resolved whole-project graph: definitions plus cross-file edges.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Default)]
pub struct CodeGraph {
    pub symbols: Vec<Symbol>,
    pub edges: Vec<Edge>,
}

impl CodeGraph {
    /// Borrowing iterator over edges whose confidence is at or above `threshold`
    /// (the zero-alloc tiered-retrieval primitive). E.g. `Confidence::Scoped`
    /// yields `Scoped` and `Exact` edges, dropping `NameOnly` and `Heuristic`.
    pub fn edges_min_confidence(&self, threshold: Confidence) -> impl Iterator<Item = &Edge> {
        self.edges.iter().filter(move |e| e.confidence >= threshold)
    }

    /// A new graph keeping only edges at or above `threshold` (dense-by-default,
    /// dial precision up). Symbols are retained unchanged. Pure filtering, no policy.
    pub fn min_confidence(&self, threshold: Confidence) -> CodeGraph {
        CodeGraph {
            symbols: self.symbols.clone(),
            edges: self.edges_min_confidence(threshold).cloned().collect(),
        }
    }
}

#[cfg(test)]
mod schema_tests {
    use super::*;

    #[test]
    fn cache_schema_epochs_are_stable() {
        assert_eq!(FILE_FACTS_SCHEMA_VERSION, 1);
        assert_eq!(CODE_GRAPH_SCHEMA_VERSION, 1);
    }
}

#[cfg(test)]
mod confidence_tests {
    use super::*;
    use crate::symbol::{Descriptor, SymbolId};

    fn make_id(name: &str) -> SymbolId {
        SymbolId::global(
            "rust",
            vec![
                Descriptor::Namespace("pkg".into()),
                Descriptor::Term(name.into()),
            ],
        )
    }

    fn make_edge(from: &str, to: &str, confidence: Confidence) -> Edge {
        Edge {
            from: make_id(from),
            to: make_id(to),
            role: RefRole::Call,
            confidence,
            provenance: Provenance::SymbolTable,
            occ: Occurrence {
                file: "src/a.rs".into(),
                line: 1,
                col: 0,
                byte: 0,
            },
        }
    }

    fn make_graph_with_one_of_each() -> (CodeGraph, Vec<Symbol>) {
        let symbols = vec![Symbol {
            id: make_id("sym"),
            name: "sym".into(),
            kind: SymbolKind::Function,
            visibility: Visibility::Public,
            entry_points: Vec::new(),
            file: "src/a.rs".into(),
            line: 1,
            span: ByteSpan { start: 0, end: 10 },
            signature: "pub fn sym()".into(),
        }];
        let graph = CodeGraph {
            symbols: symbols.clone(),
            edges: vec![
                make_edge("a", "b", Confidence::NameOnly),
                make_edge("c", "d", Confidence::Scoped),
                make_edge("e", "f", Confidence::Exact),
            ],
        };
        (graph, symbols)
    }

    #[test]
    fn edge_key_uses_every_identity_dimension_except_confidence() {
        let edge = make_edge("from", "to", Confidence::NameOnly);
        let key = edge.key();
        assert_eq!(key.from, edge.from);
        assert_eq!(key.to, edge.to);
        assert_eq!(key.role, edge.role);
        assert_eq!(key.occurrence_file, edge.occ.file);
        assert_eq!(key.occurrence_byte, edge.occ.byte);
        assert_eq!(key.provenance, edge.provenance);

        let mut changed = edge.clone();
        changed.confidence = Confidence::Exact;
        assert_eq!(changed.key(), key, "confidence is not edge identity");

        changed.from = SymbolId::global(
            "python",
            vec![
                Descriptor::Namespace("pkg".into()),
                Descriptor::Term("from".into()),
            ],
        );
        assert_eq!(changed.from.to_scip_string(), edge.from.to_scip_string());
        assert_ne!(
            changed.key(),
            key,
            "structural SymbolId coordinates are identity"
        );

        let mut changed = edge.clone();
        changed.to = make_id("other");
        assert_ne!(changed.key(), key);
        changed = edge.clone();
        changed.role = RefRole::Read;
        assert_ne!(changed.key(), key);
        changed = edge.clone();
        changed.occ.file = "src/b.rs".into();
        assert_ne!(changed.key(), key);
        changed = edge.clone();
        changed.occ.byte = 1;
        assert_ne!(changed.key(), key);
        changed = edge.clone();
        changed.provenance = Provenance::ScopeGraph;
        assert_ne!(changed.key(), key);
    }

    #[test]
    fn edge_key_component_enum_orders_are_stable() {
        let roles = [
            RefRole::Call,
            RefRole::IsImplementation,
            RefRole::Import,
            RefRole::ModuleRef,
            RefRole::TypeRef,
            RefRole::Read,
            RefRole::Write,
        ];
        assert!(roles.windows(2).all(|pair| pair[0] < pair[1]));

        let provenances = [
            Provenance::SymbolTable,
            Provenance::ScopeGraph,
            Provenance::FfiBridge,
            Provenance::Conformance,
            Provenance::NormalizedName,
            Provenance::External,
            Provenance::CrossArtifact,
        ];
        assert!(provenances.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn edge_key_ordering_uses_all_key_dimensions_and_ignores_confidence() {
        use std::collections::BTreeSet;

        let base = make_edge("from", "to", Confidence::NameOnly);
        let same_key_different_confidence = make_edge("from", "to", Confidence::Exact);
        assert_eq!(base.key(), same_key_different_confidence.key());

        let mut changed_from = base.clone();
        changed_from.from = make_id("other-from");
        let mut changed_to = base.clone();
        changed_to.to = make_id("other-to");
        let mut changed_role = base.clone();
        changed_role.role = RefRole::Read;
        let mut changed_file = base.clone();
        changed_file.occ.file = "src/b.rs".into();
        let mut changed_byte = base.clone();
        changed_byte.occ.byte = 1;
        let mut changed_provenance = base.clone();
        changed_provenance.provenance = Provenance::ScopeGraph;

        let keys = [
            base.key(),
            changed_from.key(),
            changed_to.key(),
            changed_role.key(),
            changed_file.key(),
            changed_byte.key(),
            changed_provenance.key(),
        ];
        let forward: BTreeSet<_> = keys.iter().cloned().collect();
        let reverse: BTreeSet<_> = keys.iter().rev().cloned().collect();

        assert_eq!(
            forward.len(),
            keys.len(),
            "every key dimension participates"
        );
        assert_eq!(
            forward, reverse,
            "ordering is independent of insertion order"
        );
        assert_eq!(
            forward.into_iter().collect::<Vec<_>>(),
            reverse.into_iter().collect::<Vec<_>>(),
            "ordered output is stable across insertion permutations"
        );
    }

    #[test]
    fn confidence_ordering_exact_gt_scoped() {
        assert!(Confidence::Exact > Confidence::Scoped);
    }

    #[test]
    fn confidence_ordering_scoped_gt_name_only() {
        assert!(Confidence::Scoped > Confidence::NameOnly);
    }

    #[test]
    fn confidence_ordering_exact_gt_name_only() {
        assert!(Confidence::Exact > Confidence::NameOnly);
    }

    #[test]
    fn edges_min_confidence_scoped_yields_two() {
        let (graph, _) = make_graph_with_one_of_each();
        let result: Vec<&Edge> = graph.edges_min_confidence(Confidence::Scoped).collect();
        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|e| e.confidence >= Confidence::Scoped));
        assert!(result.iter().any(|e| e.confidence == Confidence::Scoped));
        assert!(result.iter().any(|e| e.confidence == Confidence::Exact));
    }

    #[test]
    fn min_confidence_exact_keeps_one_edge_and_all_symbols() {
        let (graph, symbols) = make_graph_with_one_of_each();
        let filtered = graph.min_confidence(Confidence::Exact);
        assert_eq!(filtered.edges.len(), 1);
        assert_eq!(filtered.edges[0].confidence, Confidence::Exact);
        assert_eq!(filtered.symbols.len(), symbols.len());
    }
}

#[cfg(all(test, feature = "serde"))]
mod serde_tests {
    use super::*;
    use crate::symbol::{Descriptor, SymbolId};

    fn make_symbol_id() -> SymbolId {
        SymbolId::global(
            "rust",
            vec![
                Descriptor::Namespace("auth".into()),
                Descriptor::Term("validate".into()),
            ],
        )
    }

    #[test]
    fn symbol_id_serializes_as_lossless_scip_wire_object() {
        let id = make_symbol_id();
        let json = serde_json::to_value(&id).expect("serialize SymbolId");
        assert_eq!(json["version"], 1);
        assert_eq!(json["scip"], id.to_scip_string());
        assert_eq!(json["lang"], "rust");
    }

    #[test]
    fn symbol_id_serde_preserves_complete_structural_identity() {
        let id = SymbolId::global(
            "python",
            vec![
                Descriptor::Namespace("auth".into()),
                Descriptor::Term("validate".into()),
            ],
        );
        let json = serde_json::to_string(&id).expect("serialize");
        let restored: SymbolId = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(
            restored, id,
            "serde must preserve every identity coordinate, including language"
        );
    }

    #[test]
    fn symbol_id_round_trips() {
        let id = make_symbol_id();
        let json = serde_json::to_string(&id).expect("serialize");
        let id2: SymbolId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(id, id2, "the versioned wire format is lossless");
    }

    #[test]
    fn entry_point_variants_round_trip() {
        let id = make_symbol_id();
        let sym = Symbol {
            id,
            name: "handler".into(),
            kind: SymbolKind::Function,
            visibility: Visibility::Public,
            entry_points: vec![EntryPoint::Main, EntryPoint::HttpRoute("app.route".into())],
            file: "src/main.rs".into(),
            line: 1,
            span: ByteSpan { start: 0, end: 10 },
            signature: "pub fn handler()".into(),
        };
        let json = serde_json::to_string(&sym).expect("serialize Symbol");
        let sym2: Symbol = serde_json::from_str(&json).expect("deserialize Symbol");
        let json2 = serde_json::to_string(&sym2).expect("re-serialize Symbol");
        assert_eq!(json, json2);
    }

    #[test]
    fn file_facts_round_trips_via_json() {
        let id = make_symbol_id();
        let facts = FileFacts {
            file: "src/auth.rs".into(),
            lang: "rust".into(),
            symbols: vec![Symbol {
                id: id.clone(),
                name: "validate".into(),
                kind: SymbolKind::Function,
                visibility: Visibility::Public,
                entry_points: Vec::new(),
                file: "src/auth.rs".into(),
                line: 1,
                span: ByteSpan { start: 0, end: 20 },
                signature: "pub fn validate()".into(),
            }],
            references: vec![Reference {
                name: "validate".into(),
                occ: Occurrence {
                    file: "src/main.rs".into(),
                    line: 5,
                    col: 4,
                    byte: 80,
                },
                role: RefRole::Call,
                is_reexport: false,
                imported_name: None,
                source_module: None,
                from_path: None,
                qualifier: None,
                scope: None,
                type_ref_ctx: None,
                cross_artifact: false,
            }],
            scopes: vec![],
            bindings: vec![],
            ffi_exports: vec![],
        };

        let json = serde_json::to_string(&facts).expect("serialize FileFacts");
        let facts2: FileFacts = serde_json::from_str(&json).expect("deserialize FileFacts");
        // FileFacts does not derive PartialEq; assert JSON stability instead.
        let json2 = serde_json::to_string(&facts2).expect("re-serialize FileFacts");
        assert_eq!(json, json2);
    }
}
