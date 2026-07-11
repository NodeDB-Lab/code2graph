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
        CommandOutput::Symbols(envelope) | CommandOutput::Def(envelope) => {
            let mut output = envelope
                .results
                .iter()
                .map(|symbol| format!("{}:{}  {}\n", symbol.file, symbol.line, symbol.signature))
                .collect::<String>();
            if envelope.truncated {
                output.push_str(&format!(
                    "truncated: returned {} of {} results\n",
                    envelope.returned, envelope.total
                ));
            }
            output
        }
        CommandOutput::Callers(envelope)
        | CommandOutput::Callees(envelope)
        | CommandOutput::Usages(envelope)
        | CommandOutput::Imports(envelope) => render_relations(envelope),
        CommandOutput::References(envelope) => render_references(envelope),
        CommandOutput::ModuleDeps(envelope) => render_module_deps(envelope),
        CommandOutput::Impact(envelope) => {
            let mut output = envelope
                .results
                .iter()
                .map(|row| {
                    format!(
                        "seed {} depth {} {} -> {} via {}\n",
                        row.seed.to_scip_string(),
                        row.depth,
                        row.symbol.to_scip_string(),
                        row.parent.to_scip_string(),
                        relation_text(&row.via)
                    )
                })
                .collect::<String>();
            if envelope.truncated {
                output.push_str("truncated: traversal bound omitted reachable results\n");
            }
            output
        }
        CommandOutput::LoadedGraph(graph) => format!(
            "loaded {} symbols and {} edges\n",
            graph.graph.symbols.len(),
            graph.graph.edges.len()
        ),
    }
}

fn render_relations(envelope: &crate::OutputEnvelope<Vec<crate::RelationOutput>>) -> String {
    let mut output = envelope
        .results
        .iter()
        .map(|relation| format!("{}\n", relation_text(relation)))
        .collect::<String>();
    if envelope.truncated {
        output.push_str(&format!(
            "truncated: returned {} of {} results\n",
            envelope.returned, envelope.total
        ));
    }
    output
}

fn render_references(envelope: &crate::OutputEnvelope<Vec<crate::ReferenceOutput>>) -> String {
    let mut output = envelope
        .results
        .iter()
        .map(|reference| {
            format!(
                "{}:{}:{} {} {} qualifier={} from-path={}\n",
                reference.occurrence.file,
                reference.occurrence.line,
                reference.occurrence.column.saturating_add(1),
                reference.name,
                role(reference.role),
                reference.qualifier.as_deref().unwrap_or("-"),
                reference.from_path.as_deref().unwrap_or("-"),
            )
        })
        .collect::<String>();
    if envelope.truncated {
        output.push_str(&format!(
            "truncated: returned {} of {} results\n",
            envelope.returned, envelope.total
        ));
    }
    output
}

fn render_module_deps(
    envelope: &crate::OutputEnvelope<Vec<crate::ModuleDependencyOutput>>,
) -> String {
    let mut output = envelope
        .results
        .iter()
        .map(|dependency| {
            let target = match &dependency.target {
                crate::ModuleDependencyTargetOutput::File { file } => file.clone(),
                crate::ModuleDependencyTargetOutput::External { id_display, .. } => {
                    id_display.clone()
                }
            };
            format!(
                "{} -> {} {} count={} evidence={}\n",
                dependency.source_file,
                target,
                role(dependency.role),
                dependency.count,
                dependency.evidence.len()
            )
        })
        .collect::<String>();
    if envelope.truncated {
        output.push_str(&format!(
            "truncated: returned {} of {} results\n",
            envelope.returned, envelope.total
        ));
    }
    output
}

fn relation_text(relation: &crate::RelationOutput) -> String {
    format!(
        "{}:{}:{} {} -> {} {} [{}/{}]",
        relation.occurrence.file,
        relation.occurrence.line,
        relation.occurrence.column.saturating_add(1),
        relation.from.to_scip_string(),
        relation.to.to_scip_string(),
        role(relation.role),
        confidence(relation.confidence),
        provenance(relation.provenance),
    )
}

fn role(value: crate::RefRoleOutput) -> &'static str {
    match value {
        crate::RefRoleOutput::Call => "call",
        crate::RefRoleOutput::IsImplementation => "is-implementation",
        crate::RefRoleOutput::Import => "import",
        crate::RefRoleOutput::ModuleRef => "module-ref",
        crate::RefRoleOutput::TypeRef => "type-ref",
        crate::RefRoleOutput::Read => "read",
        crate::RefRoleOutput::Write => "write",
    }
}
fn confidence(value: crate::ConfidenceOutput) -> &'static str {
    match value {
        crate::ConfidenceOutput::Heuristic => "heuristic",
        crate::ConfidenceOutput::NameOnly => "name-only",
        crate::ConfidenceOutput::Scoped => "scoped",
        crate::ConfidenceOutput::Exact => "exact",
    }
}
fn provenance(value: crate::ProvenanceOutput) -> &'static str {
    match value {
        crate::ProvenanceOutput::SymbolTable => "symbol-table",
        crate::ProvenanceOutput::ScopeGraph => "scope-graph",
        crate::ProvenanceOutput::FfiBridge => "ffi-bridge",
        crate::ProvenanceOutput::Conformance => "conformance",
        crate::ProvenanceOutput::NormalizedName => "normalized-name",
        crate::ProvenanceOutput::External => "external",
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
