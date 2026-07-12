// SPDX-License-Identifier: Apache-2.0

//! Implemented query command handlers.

use std::collections::HashMap;

use code2graph::{FileFacts, SymbolKind};
use code2graph_query::{GraphIndex, GraphRead};

use crate::{Cancellation, CliError, Deadline, LoadedGraph, Selector};

mod definition;
mod diff_impact;
mod impact;
mod imports;
mod module_deps;
mod references;
mod relations;
mod shared;
mod symbols;

pub(crate) struct QueryCommandContext<'a, G: GraphRead + ?Sized = GraphIndex> {
    pub loaded: &'a LoadedGraph,
    pub index: &'a G,
    pub deadline: &'a Deadline,
    pub cancellation: &'a dyn Cancellation,
    pub max_file_bytes: usize,
    pub candidate_hashes: HashMap<String, [u8; 32]>,
    /// The single file decoded for a raw `references` query, if applicable.
    pub reference_facts: Option<FileFacts>,
}

impl<'a, G: GraphRead + ?Sized> QueryCommandContext<'a, G> {
    pub(crate) fn new(
        loaded: &'a LoadedGraph,
        index: &'a G,
        deadline: &'a Deadline,
        cancellation: &'a dyn Cancellation,
        max_file_bytes: usize,
    ) -> Result<Self, CliError> {
        let candidate_hashes = loaded
            .snapshot
            .files
            .iter()
            .map(|candidate| (candidate.path.clone(), candidate.content_hash))
            .collect();
        Self::with_candidate_hashes(
            loaded,
            index,
            deadline,
            cancellation,
            max_file_bytes,
            candidate_hashes,
            None,
        )
    }

    pub(crate) fn with_candidate_hashes(
        loaded: &'a LoadedGraph,
        index: &'a G,
        deadline: &'a Deadline,
        cancellation: &'a dyn Cancellation,
        max_file_bytes: usize,
        candidate_hashes: HashMap<String, [u8; 32]>,
        reference_facts: Option<FileFacts>,
    ) -> Result<Self, CliError> {
        Ok(Self {
            loaded,
            index,
            deadline,
            cancellation,
            max_file_bytes,
            candidate_hashes,
            reference_facts,
        })
    }
}

pub(crate) struct SymbolsCommandRequest<'a> {
    pub text: &'a str,
    pub file: Option<&'a str>,
    pub kind: Option<SymbolKind>,
    pub case_sensitive: bool,
    pub result_limit: usize,
}

pub(crate) struct DefinitionCommandRequest<'a> {
    pub selector: &'a Selector,
    pub file: Option<&'a str>,
    pub kind: Option<SymbolKind>,
    pub require_unique: bool,
    pub result_limit: usize,
}

pub(crate) use definition::execute_definition;
pub(crate) use diff_impact::{DiffImpactCommandRequest, execute_diff_impact};
pub(crate) use impact::{ImpactCommandRequest, execute_impact};
pub(crate) use imports::{ImportsCommandRequest, execute_imports};
pub(crate) use module_deps::{ModuleDepsCommandRequest, execute_module_deps};
pub(crate) use references::{ReferencesCommandRequest, execute_references};
pub(crate) use relations::{
    RelationCommandRequest, RelationDirection, execute_relations, relation_output,
};
pub(crate) use symbols::execute_symbols;
