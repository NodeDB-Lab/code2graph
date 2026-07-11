// SPDX-License-Identifier: Apache-2.0

//! Shared owned-output conversion and query envelope construction.

use code2graph::Symbol;

use crate::result::{OutputEnvelope, SymbolOutput, success_status};
use crate::{LoadedGraph, ProjectPath};

pub(super) fn symbol_output(symbol: &Symbol) -> SymbolOutput {
    let mut output = SymbolOutput::from(symbol);
    output.file = ProjectPath::new(std::path::Path::new(&symbol.file))
        .map_or_else(|_| symbol.file.clone(), |path| path.to_string());
    output
}

pub(super) fn query_envelope<T>(loaded: &LoadedGraph, results: T) -> OutputEnvelope<T> {
    let mut envelope = OutputEnvelope::new(
        success_status(loaded.snapshot.completeness, loaded.project.freshness),
        results,
    );
    envelope.project = Some(loaded.project.clone());
    envelope
}

pub(super) fn limit<T>(values: &mut Vec<T>, maximum: usize) -> (usize, bool) {
    let total = values.len();
    let truncated = total > maximum;
    values.truncate(maximum);
    (total, truncated)
}
