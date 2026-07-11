// SPDX-License-Identifier: Apache-2.0

//! Owned selector request and result contracts.

use std::collections::HashMap;

use code2graph::{Symbol, SymbolId, SymbolKind};
use code2graph_query::GraphIndex;

use crate::{
    Cancellation, Deadline, ProjectPath, ProjectSelection, Selector, cache::LoadedSnapshot,
};

/// The graph population a selector is permitted to address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectorPurpose {
    /// Select only locally defined symbols.
    DefinitionOnly,
    /// Select any known structural identity, including edge-only endpoints.
    AnyGraphId,
}

/// Optional narrowing applied to definition-bearing selector results.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SelectorOptions {
    /// Exact project-relative definition file restriction.
    pub file: Option<ProjectPath>,
    /// Exact definition kind restriction.
    pub kind: Option<SymbolKind>,
    /// Require exactly one match before a caller applies any output limit.
    pub require_unique: bool,
}

/// Stable resources shared by selector evaluation.
///
/// The loaded snapshot is retained alongside project selection and the graph
/// index so position selectors can prove that current source bytes still match
/// the spans being queried.
pub struct SelectorContext<'a> {
    pub index: &'a GraphIndex,
    pub selection: &'a ProjectSelection,
    pub snapshot: &'a LoadedSnapshot,
    /// Candidate content hashes keyed by normalized project-relative path.
    /// Built once at command setup so position resolution does not linearly scan
    /// untrusted cached file records for every selector.
    pub candidate_hashes: &'a HashMap<String, [u8; 32]>,
    pub max_file_bytes: usize,
    pub deadline: &'a Deadline,
    pub cancellation: &'a dyn Cancellation,
}

/// One selector and its definition-filtering policy.
pub struct SelectorRequest<'a> {
    pub selector: &'a Selector,
    pub purpose: SelectorPurpose,
    pub options: &'a SelectorOptions,
}

/// Counts computed from the complete untruncated selector result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectorSummary {
    /// Number of matching structural IDs.
    pub matched_count: usize,
    /// Whether the selection was ambiguous.
    pub ambiguous: bool,
}

/// Owned, structurally ordered result of resolving a selector.
#[derive(Debug, Clone)]
pub struct SelectorResolution {
    /// Every matched structural identity, never keyed by its potentially lossy SCIP display.
    pub ids: Vec<SymbolId>,
    /// Locally defined symbols in the result, when applicable. Endpoint-only IDs
    /// intentionally have no symbol record.
    pub symbols: Option<Vec<Symbol>>,
    /// Untruncated match information for rendering and policy decisions.
    pub summary: SelectorSummary,
}
