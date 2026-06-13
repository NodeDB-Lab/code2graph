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

/// The role a reference plays. `Call`, `Inherit`, and `Import` are live;
/// `Read`/`Write` arrive with richer extractors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefRole {
    /// The reference is a call or object-creation site.
    Call,
    /// The enclosing type extends or implements the referenced type.
    Inherit,
    /// The enclosing module imports the referenced symbol (an `import`/`use`
    /// statement). Its source resolves to the file's module symbol.
    Import,
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
}

/// How confident the resolver is in an [`Edge`] — the precision marker that lets
/// consumers (e.g. a quality analyzer) gate on resolution quality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Confidence {
    /// Type/scope-precise (e.g. stack-graphs or type inference): exactly one binding.
    Exact,
    /// Narrowed by lexical scope / imports but not type-checked.
    Scoped,
    /// Matched by name only — may be one of several same-named symbols.
    NameOnly,
}

/// The kind of relationship an [`Edge`] expresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EdgeKind {
    /// A symbol calls or constructs another symbol.
    Calls,
    /// A type inherits from / implements another type (subclass → parent).
    Inherits,
    /// A module imports a symbol (module → imported symbol).
    Imports,
}

/// A resolved directed edge between two symbols.
#[derive(Debug, Clone)]
pub struct Edge {
    pub from: SymbolId,
    pub to: SymbolId,
    pub kind: EdgeKind,
    /// Resolver precision for this edge.
    pub confidence: Confidence,
    /// The reference site that produced the edge — the evidence trail.
    pub occ: Occurrence,
}

/// The neutral facts extracted from a single file (extractor output, resolver input).
#[derive(Debug, Clone)]
pub struct FileFacts {
    pub file: String,
    pub lang: String,
    pub symbols: Vec<Symbol>,
    pub references: Vec<Reference>,
}

/// The resolved whole-project graph: definitions plus cross-file edges.
#[derive(Debug, Clone, Default)]
pub struct CodeGraph {
    pub symbols: Vec<Symbol>,
    pub edges: Vec<Edge>,
}
