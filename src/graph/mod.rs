// SPDX-License-Identifier: Apache-2.0

//! Neutral graph data model — the facts codegraph produces.

pub mod types;

pub use types::{
    ByteSpan, CodeGraph, Confidence, Edge, EdgeKind, FileFacts, Occurrence, RefRole, Reference,
    Symbol, SymbolKind,
};
