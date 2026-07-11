// SPDX-License-Identifier: Apache-2.0

//! Neutral graph data model — the facts code2graph produces.

pub mod types;
mod validate;

pub use types::{
    Binding, BindingKind, BindingTarget, ByteSpan, CODE_GRAPH_SCHEMA_VERSION, CodeGraph,
    Confidence, Edge, EdgeKey, EntryPoint, FILE_FACTS_SCHEMA_VERSION, FfiAbi, FfiExport, FileFacts,
    Occurrence, Provenance, RefRole, Reference, Scope, ScopeId, ScopeKind, Symbol, SymbolKind,
    TypeRefContext, Visibility,
};
pub use validate::{
    FileFactsValidationContext, validate_file_facts, validate_file_facts_with_context,
};
