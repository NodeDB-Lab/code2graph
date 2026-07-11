// SPDX-License-Identifier: Apache-2.0

//! Implemented query command handlers.

use std::collections::HashMap;

use code2graph::SymbolKind;
use code2graph_query::GraphIndex;

use crate::{Cancellation, CliError, Deadline, LoadedGraph, Selector};

mod definition;
mod shared;
mod symbols;

pub(crate) struct QueryCommandContext<'a> {
    pub loaded: &'a LoadedGraph,
    pub index: &'a GraphIndex,
    pub deadline: &'a Deadline,
    pub cancellation: &'a dyn Cancellation,
    pub max_file_bytes: usize,
    pub candidate_hashes: HashMap<String, [u8; 32]>,
}

impl<'a> QueryCommandContext<'a> {
    pub(crate) fn new(
        loaded: &'a LoadedGraph,
        index: &'a GraphIndex,
        deadline: &'a Deadline,
        cancellation: &'a dyn Cancellation,
        max_file_bytes: usize,
    ) -> Result<Self, CliError> {
        let mut candidate_hashes = HashMap::with_capacity(loaded.snapshot.files.len());
        for candidate in &loaded.snapshot.files {
            if candidate_hashes
                .insert(candidate.path.clone(), candidate.content_hash)
                .is_some()
            {
                return Err(CliError::Index(format!(
                    "loaded snapshot contains duplicate candidate path: {}",
                    candidate.path
                )));
            }
        }
        Ok(Self {
            loaded,
            index,
            deadline,
            cancellation,
            max_file_bytes,
            candidate_hashes,
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
pub(crate) use symbols::execute_symbols;
