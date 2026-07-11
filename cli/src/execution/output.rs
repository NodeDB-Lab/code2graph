// SPDX-License-Identifier: Apache-2.0

//! Deterministic human rendering for implemented command outputs.

use crate::result::{
    CacheCompletenessOutput, CacheDisposition, Freshness, ProjectOutput, SelectorOutput,
};

use super::lifecycle::CommandOutput;

/// Renders concise human output without exposing debug representations.
pub fn render_human(output: &CommandOutput) -> String {
    match output {
        CommandOutput::Index(envelope) => render_index(envelope),
        CommandOutput::Status(envelope) => render_status(&envelope.results),
        CommandOutput::Symbols(envelope) | CommandOutput::Def(envelope) => {
            with_query_warning(envelope.project.as_ref(), render_symbols(envelope))
        }
        CommandOutput::Callers(envelope)
        | CommandOutput::Callees(envelope)
        | CommandOutput::Usages(envelope)
        | CommandOutput::Imports(envelope) => {
            with_query_warning(envelope.project.as_ref(), render_relations(envelope))
        }
        CommandOutput::References(envelope) => {
            with_query_warning(envelope.project.as_ref(), render_references(envelope))
        }
        CommandOutput::ModuleDeps(envelope) => {
            with_query_warning(envelope.project.as_ref(), render_module_deps(envelope))
        }
        CommandOutput::Impact(envelope) => {
            with_query_warning(envelope.project.as_ref(), render_impact(envelope))
        }
        CommandOutput::LoadedGraph(graph) => format!(
            "loaded {} symbols and {} edges\n",
            graph.graph.symbols.len(),
            graph.graph.edges.len()
        ),
    }
}

fn with_query_warning(project: Option<&ProjectOutput>, body: String) -> String {
    format!("{}{}", query_warning(project), body)
}

fn query_warning(project: Option<&ProjectOutput>) -> String {
    let Some(project) = project else {
        return String::new();
    };
    if project.freshness == Freshness::Fresh
        && project.completeness == CacheCompletenessOutput::Complete
    {
        return String::new();
    }
    let mut output = String::new();
    match project.freshness {
        Freshness::Fresh => {}
        Freshness::Stale => {
            output.push_str("warning: stale snapshot; results may not reflect current source\n")
        }
        Freshness::Frozen => output
            .push_str("warning: frozen snapshot; results were read without refreshing source\n"),
    }
    if project.completeness == CacheCompletenessOutput::Partial {
        output.push_str(&format!(
            "warning: partial snapshot; {} source files omitted\n",
            project.omitted_files
        ));
        for omission in sorted_omissions(&project.omissions) {
            output.push_str(&format!(
                "warning: omitted {} reason={} detail={}\n",
                omission.path, omission.reason, omission.detail
            ));
        }
    }
    output
}

fn render_index(envelope: &crate::OutputEnvelope<crate::IndexOutput>) -> String {
    let mut output = format!(
        "indexed {} files; {} changed, {} deleted; {}\n",
        envelope.results.inventory_file_count,
        envelope.results.changed,
        envelope.results.deleted,
        completeness(envelope.results.completeness)
    );
    if let Some(project) = &envelope.project {
        output.push_str(&format!(
            "publication freshness={} cache={}\n",
            freshness(project.freshness),
            cache(project.cache)
        ));
    }
    output.push_str(&format!(
        "omitted files={}\n",
        envelope.results.omissions.len()
    ));
    let omissions = sorted_omissions(&envelope.results.omissions);
    let mut counts = std::collections::BTreeMap::<&str, usize>::new();
    for omission in &omissions {
        *counts.entry(&omission.reason).or_default() += 1;
    }
    for (reason, count) in counts {
        output.push_str(&format!("omission reason={} count={}\n", reason, count));
    }
    for omission in omissions {
        output.push_str(&format!(
            "omitted {} reason={} detail={}\n",
            omission.path, omission.reason, omission.detail
        ));
    }
    output
}

fn sorted_omissions(omissions: &[crate::CacheOmissionOutput]) -> Vec<&crate::CacheOmissionOutput> {
    let mut omissions = omissions.iter().collect::<Vec<_>>();
    omissions.sort_by(|left, right| {
        (&left.path, &left.reason, &left.detail).cmp(&(&right.path, &right.reason, &right.detail))
    });
    omissions
}

fn render_status(status: &crate::StatusOutput) -> String {
    let mut output = format!(
        "freshness={} cache={} completeness={}\nadmitted files={} bytes={} omitted={}\ncaps max-files={} per-file-bytes={} total-bytes={} max-depth={} result-limit={} impact-depth={} timeout-millis={}\n",
        freshness(status.project.freshness),
        cache(status.project.cache),
        completeness(status.project.completeness),
        status.inventory.admitted_files,
        status.inventory.admitted_bytes,
        status.project.omitted_files,
        status.max_files,
        status.max_file_bytes,
        status.max_total_bytes,
        status.max_depth,
        status.result_limit,
        status.impact_depth,
        status
            .timeout_millis
            .map_or_else(|| "none".into(), |value| value.to_string()),
    );
    let mut counts = std::collections::BTreeMap::<&str, usize>::new();
    let omissions = sorted_omissions(&status.project.omissions);
    for omission in &omissions {
        *counts.entry(&omission.reason).or_default() += 1;
    }
    for (reason, count) in counts {
        output.push_str(&format!("omission reason={} count={}\n", reason, count));
    }
    for omission in omissions {
        output.push_str(&format!(
            "omitted {} reason={} detail={}\n",
            omission.path, omission.reason, omission.detail
        ));
    }
    output
}

fn render_symbols(envelope: &crate::OutputEnvelope<Vec<crate::SymbolOutput>>) -> String {
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

fn render_relations(envelope: &crate::OutputEnvelope<Vec<crate::RelationOutput>>) -> String {
    let mut output = unavailable_definitions(envelope.selector.as_ref());
    output.push_str(
        &envelope
            .results
            .iter()
            .map(|relation| format!("{}\n", relation_text(relation)))
            .collect::<String>(),
    );
    if envelope.truncated {
        output.push_str(&format!(
            "truncated: returned {} of {} results\n",
            envelope.returned, envelope.total
        ));
    }
    output
}

fn render_impact(envelope: &crate::OutputEnvelope<Vec<crate::ImpactOutput>>) -> String {
    let mut output = unavailable_definitions(envelope.selector.as_ref());
    output.push_str(
        &envelope
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
            .collect::<String>(),
    );
    if envelope.truncated {
        output.push_str("truncated: traversal bound omitted reachable results\n");
    }
    output
}

fn unavailable_definitions(selector: Option<&SelectorOutput>) -> String {
    let Some(selector) = selector else {
        return String::new();
    };
    let mut output = String::new();
    for id in &selector.ids {
        if !selector.symbols.iter().any(|symbol| symbol.id == *id) {
            let identity = serde_json::to_string(id).expect("SymbolId serialization is infallible");
            output.push_str(&format!(
                "selected identity: {identity}\nselected scip: {}\ndefinition: unavailable\n",
                id.to_scip_string()
            ));
        }
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
        provenance(relation.provenance)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CacheOmissionOutput, IndexOutput, InventoryCompletenessOutput, InventorySummaryOutput,
        OutputEnvelope, OutputStatus, PlanDecisionCountsOutput, ResolverTier, StatusOutput,
    };
    use code2graph::SymbolId;

    fn project(freshness: Freshness, completeness: CacheCompletenessOutput) -> ProjectOutput {
        ProjectOutput {
            root: "/project".into(),
            snapshot: "snapshot".into(),
            tier: ResolverTier::Scope,
            freshness,
            cache: CacheDisposition::Hit,
            completeness,
            omitted_files: 2,
            omissions: vec![
                CacheOmissionOutput {
                    path: "z.rs".into(),
                    reason: "read-error:other".into(),
                    detail: "io-error=other".into(),
                },
                CacheOmissionOutput {
                    path: "a.rs".into(),
                    reason: "file-too-large".into(),
                    detail: "limit=12".into(),
                },
            ],
        }
    }

    #[test]
    fn query_warning_is_an_exact_complete_partial_stale_frozen_contract() {
        assert_eq!(
            query_warning(Some(&project(
                Freshness::Fresh,
                CacheCompletenessOutput::Complete
            ))),
            ""
        );
        assert_eq!(
            query_warning(Some(&project(
                Freshness::Fresh,
                CacheCompletenessOutput::Partial
            ))),
            "warning: partial snapshot; 2 source files omitted\nwarning: omitted a.rs reason=file-too-large detail=limit=12\nwarning: omitted z.rs reason=read-error:other detail=io-error=other\n"
        );
        assert_eq!(
            query_warning(Some(&project(
                Freshness::Stale,
                CacheCompletenessOutput::Complete
            ))),
            "warning: stale snapshot; results may not reflect current source\n"
        );
        assert_eq!(
            query_warning(Some(&project(
                Freshness::Frozen,
                CacheCompletenessOutput::Complete
            ))),
            "warning: frozen snapshot; results were read without refreshing source\n"
        );
    }

    #[test]
    fn index_human_output_exactly_reports_publication_and_every_omission() {
        let mut envelope = OutputEnvelope::new(
            OutputStatus::Partial,
            IndexOutput {
                candidate: "candidate".into(),
                snapshot: "snapshot".into(),
                tier: ResolverTier::Scope,
                completeness: CacheCompletenessOutput::Partial,
                inventory_file_count: 3,
                inventory_total_bytes: 42,
                omissions: project(Freshness::Fresh, CacheCompletenessOutput::Partial).omissions,
                changed: 2,
                deleted: 1,
                ignored_omissions: 0,
                attempts: 1,
                plan_decisions: PlanDecisionCountsOutput::default(),
            },
        );
        envelope.project = Some(project(Freshness::Fresh, CacheCompletenessOutput::Partial));
        assert_eq!(
            render_human(&CommandOutput::Index(envelope)),
            "indexed 3 files; 2 changed, 1 deleted; partial\npublication freshness=fresh cache=cache hit\nomitted files=2\nomission reason=file-too-large count=1\nomission reason=read-error:other count=1\nomitted a.rs reason=file-too-large detail=limit=12\nomitted z.rs reason=read-error:other detail=io-error=other\n"
        );
    }

    #[test]
    fn status_human_output_exactly_reports_caps_and_omission_counts() {
        let project = project(Freshness::Frozen, CacheCompletenessOutput::Partial);
        let status = StatusOutput {
            project: project.clone(),
            inventory: InventorySummaryOutput {
                completeness: InventoryCompletenessOutput::Partial,
                admitted_files: 3,
                admitted_bytes: 42,
                omitted_files: 2,
                omission_reasons: Vec::new(),
            },
            cached_omissions: project.omissions.clone(),
            max_files: 10,
            max_file_bytes: 20,
            max_total_bytes: 30,
            max_depth: 4,
            result_limit: 5,
            impact_depth: 6,
            timeout_millis: Some(7),
        };
        assert_eq!(
            render_status(&status),
            "freshness=frozen cache=cache hit completeness=partial\nadmitted files=3 bytes=42 omitted=2\ncaps max-files=10 per-file-bytes=20 total-bytes=30 max-depth=4 result-limit=5 impact-depth=6 timeout-millis=7\nomission reason=file-too-large count=1\nomission reason=read-error:other count=1\nomitted a.rs reason=file-too-large detail=limit=12\nomitted z.rs reason=read-error:other detail=io-error=other\n"
        );
    }

    #[test]
    fn endpoint_only_selected_identity_is_lossless_for_relations_and_impact() {
        let id = SymbolId::local("vendor/api.rs", "remote");
        let selector = SelectorOutput {
            matched: 1,
            ambiguous: false,
            ids: vec![id.clone()],
            symbols: Vec::new(),
        };
        let identity = serde_json::to_string(&id).unwrap();
        let expected = format!(
            "selected identity: {identity}\nselected scip: {}\ndefinition: unavailable\n",
            id.to_scip_string()
        );

        let mut relations = OutputEnvelope::new(OutputStatus::Ok, Vec::new());
        relations.selector = Some(selector.clone());
        assert_eq!(render_human(&CommandOutput::Callers(relations)), expected);

        let mut impact = OutputEnvelope::new(OutputStatus::Ok, Vec::new());
        impact.selector = Some(selector);
        assert_eq!(render_human(&CommandOutput::Impact(impact)), expected);
    }
}
