// SPDX-License-Identifier: Apache-2.0

//! Deterministic human rendering for implemented command outputs.

use crate::result::{CacheCompletenessOutput, CacheDisposition, Freshness};

use super::lifecycle::CommandOutput;

/// Renders concise human output without exposing debug or JSON representations.
pub fn render_human(output: &CommandOutput) -> String {
    match output {
        CommandOutput::Index(envelope) => format!(
            "indexed {} files; {} changed, {} deleted; {}\n",
            envelope.results.inventory_file_count,
            envelope.results.changed,
            envelope.results.deleted,
            completeness(envelope.results.completeness)
        ),
        CommandOutput::Status(envelope) => format!(
            "{}: {} files; {}\n",
            freshness(envelope.results.project.freshness),
            envelope.results.inventory.admitted_files,
            cache(envelope.results.project.cache)
        ),
        CommandOutput::LoadedGraph(graph) => format!(
            "loaded {} symbols and {} edges\n",
            graph.graph.symbols.len(),
            graph.graph.edges.len()
        ),
    }
}

fn completeness(value: CacheCompletenessOutput) -> &'static str {
    match value {
        CacheCompletenessOutput::Complete => "complete",
        CacheCompletenessOutput::Partial => "partial",
    }
}

fn freshness(value: Freshness) -> &'static str {
    match value {
        Freshness::Fresh => "fresh",
        Freshness::Frozen => "frozen",
        Freshness::Stale => "stale",
    }
}

fn cache(value: CacheDisposition) -> &'static str {
    match value {
        CacheDisposition::Hit => "cache hit",
        CacheDisposition::Miss => "cache miss",
        CacheDisposition::Disabled => "cache disabled",
    }
}
