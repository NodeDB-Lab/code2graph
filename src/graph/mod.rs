// SPDX-License-Identifier: Apache-2.0

//! Neutral graph data model — the facts codegraph produces.

pub mod types;

pub use types::{
    Binding, BindingKind, BindingTarget, ByteSpan, CodeGraph, Confidence, Edge, FfiAbi, FfiExport,
    FileFacts, Occurrence, Provenance, RefRole, Reference, Scope, ScopeId, ScopeKind, Symbol,
    SymbolKind,
};
