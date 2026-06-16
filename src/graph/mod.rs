// SPDX-License-Identifier: Apache-2.0

//! Neutral graph data model — the facts code2graph produces.

pub mod types;

pub use types::{
    Binding, BindingKind, BindingTarget, ByteSpan, CodeGraph, Confidence, Edge, FfiAbi, FfiExport,
    FileFacts, Occurrence, Provenance, RefRole, Reference, Scope, ScopeId, ScopeKind, Symbol,
    SymbolKind, TypeRefContext, Visibility,
};
