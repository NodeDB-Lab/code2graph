// SPDX-License-Identifier: Apache-2.0

//! Definition selector command.

use std::path::Path;

use crate::commands::shared::{limit, query_envelope, symbol_output};
use crate::commands::{DefinitionCommandRequest, QueryCommandContext};
use crate::result::{OutputEnvelope, SelectorOutput, SymbolOutput};
use crate::{
    ProjectPath, Result, SelectorContext, SelectorOptions, SelectorPurpose, SelectorRequest,
    resolve_selector,
};

/// Executes the definition-only `def` selector query.
pub(crate) fn execute_definition(
    context: &QueryCommandContext<'_>,
    request: DefinitionCommandRequest<'_>,
) -> Result<OutputEnvelope<Vec<SymbolOutput>>> {
    context.deadline.check(context.cancellation)?;
    let options = SelectorOptions {
        file: request
            .file
            .map(|value| ProjectPath::new(Path::new(value)))
            .transpose()?,
        kind: request.kind,
        require_unique: request.require_unique,
    };
    let selector_context = SelectorContext {
        index: context.index,
        selection: &context.loaded.selection,
        snapshot: &context.loaded.snapshot,
        candidate_hashes: &context.candidate_hashes,
        max_file_bytes: context.max_file_bytes,
        deadline: context.deadline,
        cancellation: context.cancellation,
    };
    let resolution = resolve_selector(
        &selector_context,
        &SelectorRequest {
            selector: request.selector,
            purpose: SelectorPurpose::DefinitionOnly,
            options: &options,
        },
    )?;
    let symbols = resolution.symbols.unwrap_or_default();
    let complete = symbols.iter().map(symbol_output).collect::<Vec<_>>();
    let mut results = complete.clone();
    let (total, truncated) = limit(&mut results, request.result_limit);
    let mut envelope = query_envelope(context.loaded, results);
    envelope.selector = Some(SelectorOutput {
        matched: resolution.summary.matched_count,
        ambiguous: resolution.summary.ambiguous,
        ids: resolution.ids,
        symbols: complete,
    });
    envelope.total = total;
    envelope.returned = envelope.results.len();
    envelope.truncated = truncated;
    Ok(envelope)
}
