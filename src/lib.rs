// SPDX-License-Identifier: Apache-2.0

//! # codegraph
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
//! use codegraph::{extract_path, resolve::{Resolver, SymbolTableResolver}};
//!
//! let a = extract_path("src/util.rs", "pub fn helper() {}").unwrap();
//! let b = extract_path("src/main.rs", "pub fn run() { helper() }").unwrap();
//! let graph = SymbolTableResolver.resolve(&[a, b]);
//! assert_eq!(graph.edges.len(), 1); // run --calls--> helper
//! ```
//!
//! ## Design
//!
//! - **Identity** ([`symbol`]) is SCIP-aligned: a symbol is a descriptor path
//!   rendering to a stable, human-readable string, so cross-file matching is
//!   string equality.
//! - **Resolution** ([`resolve`]) is a tier seam: the fast [`SymbolTableResolver`]
//!   (name/scope, all languages) and a future precise stack-graphs resolver emit
//!   the **same** schema, tagging every edge with a [`graph::Confidence`].
//! - **No storage, no source bodies** — [`graph::Symbol`]s carry a byte span;
//!   consumers slice what they need.
//!
//! ## Coverage
//!
//! Rust, Python, and TypeScript are implemented end-to-end. The remaining
//! languages ([`lang::Language`] enumerates 14) are added one at a time behind
//! the [`extract::Extractor`] trait.

pub mod error;
pub mod extract;
pub mod graph;
pub mod lang;
pub mod resolve;
pub mod symbol;

pub use error::{CodegraphError, Result};
pub use extract::{Extractor, extract_file, extract_path};
pub use graph::{
    ByteSpan, CodeGraph, Confidence, Edge, EdgeKind, FileFacts, Occurrence, RefRole, Reference,
    Symbol, SymbolKind,
};
pub use lang::Language;
pub use resolve::{Resolver, SymbolTableResolver};
pub use symbol::{Descriptor, Package, SymbolId};
