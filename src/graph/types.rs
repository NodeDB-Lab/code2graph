// SPDX-License-Identifier: Apache-2.0

//! Neutral structural-fact types — the output of codegraph.
//!
//! Identity lives in [`crate::symbol`] (SCIP-aligned). These types are the
//! facts a consumer reasons over: [`Symbol`] definitions, [`Reference`] sites,
//! resolved [`Edge`]s, and the per-file [`FileFacts`] / whole-graph [`CodeGraph`]
//! aggregates. No storage, no scores, no source bodies (symbols carry a span).

use crate::symbol::SymbolId;

/// A half-open byte range `[start, end)` into a source file. Consumers slice
/// their own text from this — codegraph never carries source bodies.
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Occurrence {
    pub file: String,
    pub line: u32,
    pub col: u32,
    pub byte: usize,
}

/// What kind of program element a symbol is. Cross-language superset; not every
/// variant applies to every language.
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

/// A symbol definition found in a source file.
#[derive(Debug, Clone)]
pub struct Symbol {
    /// SCIP-aligned identity.
    pub id: SymbolId,
    /// Bare (unqualified) name, e.g. `validate_token`.
    pub name: String,
    /// Element kind.
    pub kind: SymbolKind,
    /// File path relative to the project root.
    pub file: String,
    /// 1-based line of the definition.
    pub line: u32,
    /// Byte range of the whole definition in the source file.
    pub span: ByteSpan,
    /// One-line signature (declaration up to the body), whitespace-collapsed.
    pub signature: String,
}

/// The role a reference plays. `Call`, `IsImplementation`, `Import`, and `TypeRef` are live;
/// `Read`/`Write` arrive with richer extractors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefRole {
    /// The reference is a call or object-creation site.
    Call,
    /// The enclosing type extends or implements the referenced type — SCIP `is_implementation`.
    IsImplementation,
    /// The enclosing module imports the referenced symbol (an `import`/`use`
    /// statement). Its source resolves to the file's module symbol.
    Import,
    /// The enclosing symbol references the named type in a signature or
    /// declaration position (parameter type, return type, field type, …) — a
    /// structural type-usage fact. The resolver links it to the type's
    /// definition like any other name reference.
    TypeRef,
}

/// A reference (call site / usage) found in a source file. Pre-resolution it
/// carries only the written `name`; the resolver links it to a [`Symbol`].
#[derive(Debug, Clone)]
pub struct Reference {
    /// The bare identifier as written at the use site.
    pub name: String,
    /// Where it occurs.
    pub occ: Occurrence,
    /// What kind of reference.
    pub role: RefRole,
    /// For [`RefRole::Import`] references: the SCIP identity string of the
    /// importing file's module symbol. `None` for all other reference roles.
    pub source_module: Option<String>,
    /// For [`RefRole::Import`] references: the module path the symbol is imported
    /// from, as written in the source (e.g. `"pkg.models"`, `"std::io"`,
    /// `"./svc"`). `None` for non-import refs or when unavailable.
    pub from_path: Option<String>,
    /// For a path-qualified call (`mod_a::process()`, `a::b::f()`): the qualifier
    /// written immediately before the leaf, exactly as in source (e.g. `"mod_a"`,
    /// `"a::b"`). `None` for unqualified calls and all non-call references. The
    /// resolver matches this against a candidate symbol's namespace-path suffix;
    /// the extractor never interprets it.
    pub qualifier: Option<String>,
    /// The innermost scope enclosing this reference site; `None` until a
    /// scope-aware extractor populates it.
    pub scope: Option<ScopeId>,
}

// ── Scope / binding data model ──────────────────────────────────────────────

/// Index into a file's [`FileFacts::scopes`] vector. Stable within one file's facts.
pub type ScopeId = usize;

/// What kind of lexical name-resolution region a scope is. Cross-language
/// superset; not every variant applies to every language.
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingTarget {
    /// File-local binding (parameter or `let`/`var`) — no global [`Symbol`].
    Local,
    /// An import: the module path as written in source (mirrors
    /// [`Reference::from_path`]).
    Import(String),
    /// Points at an extracted top-level [`Symbol`]'s SCIP identity.
    Def(SymbolId),
}

/// A name introduced into a scope — a parameter, local variable, import alias,
/// or a top-level definition that participates in lexical lookup.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Confidence {
    /// Type/scope-precise (e.g. stack-graphs or type inference): exactly one binding.
    Exact,
    /// Narrowed by lexical scope / imports, or the referenced name has a unique
    /// global candidate — not type-checked.
    Scoped,
    /// Matched by name only — may be one of several same-named symbols.
    NameOnly,
}

/// Which analysis derived an [`Edge`] — its provenance.
///
/// This is **orthogonal to [`Confidence`]**: confidence answers "how sure are we
/// this binding is correct?", provenance answers "which mechanism produced it?".
/// A consumer uses provenance to filter or weight edges by *how* they were found
/// — e.g. trust scope-resolved edges over name-matched ones, or treat the
/// deterministic-but-cross-runtime FFI bridges specially — independently of the
/// per-edge confidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
}

// ── FFI / cross-language boundary facts ──────────────────────────────────────

/// The application binary interface a symbol is exported under for
/// cross-language linkage. Cross-language superset; only the C ABI is detected
/// today.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FfiAbi {
    /// The C ABI — the lingua-franca FFI boundary (`#[no_mangle]` / `extern "C"`
    /// in Rust, `extern` declarations in C, callable from most languages).
    C,
}

/// A neutral cross-language export fact: the definition identified by [`symbol`]
/// is callable from another language under [`export_name`] via [`abi`]. The
/// extractor records it from a deterministic syntactic marker (e.g. Rust's
/// `#[no_mangle]`); a resolver bridges it to use-sites in other languages.
///
/// [`symbol`]: Self::symbol
/// [`export_name`]: Self::export_name
/// [`abi`]: Self::abi
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FfiExport {
    /// The exported definition's SCIP identity.
    pub symbol: SymbolId,
    /// The ABI the symbol is exposed under.
    pub abi: FfiAbi,
    /// The symbol name as seen across the boundary (the stable linker/ABI name).
    pub export_name: String,
}

/// A resolved directed edge between two symbols.
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

/// The neutral facts extracted from a single file (extractor output, resolver input).
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
#[derive(Debug, Clone, Default)]
pub struct CodeGraph {
    pub symbols: Vec<Symbol>,
    pub edges: Vec<Edge>,
}
