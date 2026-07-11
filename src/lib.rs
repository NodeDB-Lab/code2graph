// SPDX-License-Identifier: Apache-2.0

//! # code2graph
//!
//! Source files → structural facts. A purpose-neutral, language-agnostic
//! code-graph extraction library: it turns source code into **symbols**,
//! **references**, and **cross-file edges** as plain data — no storage, no
//! scoring, no embeddings, no judgement. See `README.md` for the design boundary.
//!
//! ## Pipeline
//!
//! ```text
//! source ──[extract]──▶ FileFacts (symbols + references) ──[resolve]──▶ CodeGraph (symbols + edges)
//! ```
//!
//! ```
//! # #[cfg(feature = "rust")]
//! # {
//! use code2graph::{extract_path, resolve::{Resolver, SymbolTableResolver}};
//!
//! let a = extract_path("src/util.rs", "pub fn helper() {}").unwrap();
//! let b = extract_path("src/main.rs", "pub fn run() { helper() }").unwrap();
//! let graph = SymbolTableResolver.resolve(&[a, b]).unwrap();
//! assert_eq!(graph.edges.len(), 1); // run --calls--> helper
//! # }
//! ```
//!
//! ## Design
//!
//! - **Identity** ([`symbol`]) is SCIP-aligned: structural [`SymbolId`] equality
//!   includes language/local-file coordinates, while its stable human-readable
//!   SCIP rendering is display/interoperability only.
//! - **Resolution** ([`resolve`]) is a tier seam: the fast recall-first
//!   [`SymbolTableResolver`] (name matching, all languages, `NameOnly` edges) and
//!   the precise scope-aware [`ScopeGraphResolver`] (lexical-scope + import +
//!   qualified-path resolution, `Scoped`/`Exact` edges, Rust/Python/TypeScript)
//!   emit the
//!   **same** schema, tagging every edge with a [`graph::Confidence`] and a
//!   [`graph::Provenance`] (which analysis derived it, orthogonal to confidence).
//!   A consumer picks the tier; the output shape is identical.
//! - **Cross-language bridges** ([`FfiBridgeResolver`]) link call sites to FFI
//!   exports (Rust `#[no_mangle]` → C, today) across a language boundary,
//!   deterministically and with honest confidence — composable on top of any tier.
//! - **Incremental maintenance** ([`IncrementalGraph`]) keeps a resolved graph
//!   current as files change: each file is resolved in isolation and cross-file
//!   edges are stitched on demand, so re-extracting one file rebuilds only that
//!   file's subgraph — never the whole workspace.
//! - **No storage, no source bodies** — [`graph::Symbol`]s carry a byte span;
//!   consumers slice what they need.
//!
//! ## Coverage
//!
//! All 23 languages ([`lang::Language`]) are implemented end-to-end, each
//! behind a Cargo feature that is enabled by default. Use
//! [`Language::availability`] (and its [`LanguageAvailability`] result) before
//! extraction when building with a selected feature subset.

pub mod error;
pub mod extract;
mod ffi;
pub mod grammar;
pub mod graph;
pub mod lang;
pub mod package;
pub mod resolve;
pub mod symbol;

pub use error::{CodegraphError, Result};
pub use extract::{Extractor, extract_file, extract_path};
pub use graph::{
    Binding, BindingKind, BindingTarget, ByteSpan, CodeGraph, Confidence, Edge, EdgeKey,
    EntryPoint, FfiAbi, FfiExport, FileFacts, FileFactsValidationContext, Occurrence, Provenance,
    RefRole, Reference, Scope, ScopeId, ScopeKind, Symbol, SymbolKind, TypeRefContext, Visibility,
    validate_file_facts, validate_file_facts_with_context,
};
pub use lang::{Language, LanguageAvailability};
pub use resolve::{
    FILE_SUBGRAPH_SCHEMA_VERSION, FfiBridgeResolver, FileChange, FileSubgraph, IncrementalGraph,
    LayeredResolver, Resolver, ScopeGraphDelta, ScopeGraphResolver, ScopeSnapshotToken,
    SymbolTableResolver, TrackedIncrementalGraph,
};
pub use symbol::{Descriptor, Package, SymbolId, SymbolIdWire, SymbolIdWireError};
