// SPDX-License-Identifier: Apache-2.0

//! Whole-project resolved module dependency aggregation.

use std::collections::BTreeMap;

use code2graph::{CodeGraph, Confidence, Edge, RefRole, SymbolId};
use code2graph_query::GraphIndex;

use crate::Result;
use crate::commands::QueryCommandContext;
use crate::commands::relation_output;
use crate::commands::shared::{limit, normalized_project_path, query_envelope};
use crate::result::{ModuleDependencyOutput, ModuleDependencyTargetOutput, OutputEnvelope};

pub(crate) struct ModuleDepsCommandRequest {
    pub result_limit: usize,
    pub min_confidence: Confidence,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
enum TargetKey {
    File(String),
    External(SymbolId),
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct AggregateKey {
    source_file: String,
    target: TargetKey,
    role: RefRole,
}

/// Aggregates complete, exact edge evidence before applying the global row limit.
pub(crate) fn execute_module_deps(
    context: &QueryCommandContext<'_>,
    request: ModuleDepsCommandRequest,
) -> Result<OutputEnvelope<Vec<ModuleDependencyOutput>>> {
    context.deadline.check(context.cancellation)?;
    let mut results =
        aggregate_module_deps(&context.loaded.graph, context.index, request.min_confidence);
    context.deadline.check(context.cancellation)?;
    if results.is_empty() {
        return Err(crate::CliError::NoMatch);
    }
    let (total, truncated) = limit(&mut results, request.result_limit);
    let mut envelope = query_envelope(context.loaded, results);
    envelope.total = total;
    envelope.returned = envelope.results.len();
    envelope.truncated = truncated;
    Ok(envelope)
}

fn aggregate_module_deps(
    graph: &CodeGraph,
    index: &GraphIndex,
    min_confidence: Confidence,
) -> Vec<ModuleDependencyOutput> {
    let mut groups = BTreeMap::<AggregateKey, Vec<&Edge>>::new();
    for edge in &graph.edges {
        if !matches!(edge.role, RefRole::Import | RefRole::ModuleRef)
            || edge.confidence < min_confidence
        {
            continue;
        }
        let target = match index.symbol(&edge.to) {
            Some(symbol) => TargetKey::File(normalized_project_path(&symbol.file)),
            None => TargetKey::External(edge.to.clone()),
        };
        let key = AggregateKey {
            source_file: normalized_project_path(&edge.occ.file),
            target,
            role: edge.role,
        };
        groups.entry(key).or_default().push(edge);
    }

    groups
        .into_iter()
        .map(|(key, mut edges)| {
            edges.sort_by_key(|edge| edge.key());
            let evidence = edges.into_iter().map(relation_output).collect::<Vec<_>>();
            let target = match key.target {
                TargetKey::File(file) => ModuleDependencyTargetOutput::File { file },
                TargetKey::External(id) => ModuleDependencyTargetOutput::External {
                    id_display: id.to_scip_string(),
                    id,
                },
            };
            ModuleDependencyOutput {
                source_file: key.source_file,
                target,
                role: key.role.into(),
                count: evidence.len(),
                evidence,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use code2graph::{
        ByteSpan, CodeGraph, Confidence, Descriptor, Edge, EntryPoint, Occurrence, Provenance,
        RefRole, Symbol, SymbolId, SymbolKind, Visibility,
    };
    use code2graph_query::GraphIndex;

    use super::aggregate_module_deps;
    use crate::{ModuleDependencyTargetOutput, RefRoleOutput};

    fn id(name: &str) -> SymbolId {
        SymbolId::global("rust", vec![Descriptor::Term(name.into())])
    }

    fn edge(to: &SymbolId, role: RefRole, byte: usize, provenance: Provenance) -> Edge {
        Edge {
            from: id("source"),
            to: to.clone(),
            role,
            confidence: Confidence::Scoped,
            provenance,
            occ: Occurrence {
                file: "src//main.rs".into(),
                line: 1,
                col: byte as u32,
                byte,
            },
        }
    }

    #[test]
    fn aggregation_distinguishes_definition_files_external_ids_and_roles_without_evidence_loss() {
        let local = id("local");
        let external = SymbolId::local("vendor/api.rs", "external");
        let symbol = Symbol {
            id: local.clone(),
            name: "local".into(),
            kind: SymbolKind::Function,
            visibility: Visibility::Public,
            entry_points: Vec::<EntryPoint>::new(),
            file: "src//dep.rs".into(),
            line: 1,
            span: ByteSpan { start: 0, end: 1 },
            signature: "fn local()".into(),
        };
        let graph = CodeGraph {
            symbols: vec![symbol],
            edges: vec![
                edge(&local, RefRole::Import, 4, Provenance::ScopeGraph),
                edge(&local, RefRole::Import, 2, Provenance::External),
                edge(&local, RefRole::Import, 2, Provenance::ScopeGraph),
                edge(&local, RefRole::ModuleRef, 8, Provenance::ScopeGraph),
                edge(&external, RefRole::Import, 6, Provenance::External),
                edge(&local, RefRole::Call, 9, Provenance::ScopeGraph),
            ],
        };
        let index = GraphIndex::from_graph(graph.clone()).unwrap();
        let rows = aggregate_module_deps(&graph, &index, Confidence::Scoped);

        assert_eq!(rows.len(), 3);
        assert!(aggregate_module_deps(&graph, &index, Confidence::Exact).is_empty());
        let local_import = rows
            .iter()
            .find(|row| {
                row.role == RefRoleOutput::Import
                    && matches!(&row.target, ModuleDependencyTargetOutput::File { file } if file == "src/dep.rs")
            })
            .unwrap();
        assert_eq!(local_import.source_file, "src/main.rs");
        assert_eq!(local_import.count, 3);
        assert_eq!(local_import.evidence.len(), 3);
        assert_eq!(
            local_import
                .evidence
                .iter()
                .map(|edge| edge.occurrence.byte)
                .collect::<Vec<_>>(),
            vec![2, 2, 4]
        );
        assert!(rows.iter().any(|row| row.role == RefRoleOutput::ModuleRef));
        assert!(rows.iter().any(|row| {
            matches!(&row.target, ModuleDependencyTargetOutput::External { id, .. } if id == &external)
        }));

        let mut reversed = graph.clone();
        reversed.edges.reverse();
        let reversed_index = GraphIndex::from_graph(reversed.clone()).unwrap();
        assert_eq!(
            aggregate_module_deps(&reversed, &reversed_index, Confidence::Scoped),
            rows,
            "graph input order must not affect rows or full evidence ordering"
        );

        let duplicate = edge(&local, RefRole::Import, 12, Provenance::ScopeGraph);
        let invalid = CodeGraph {
            symbols: Vec::new(),
            edges: vec![duplicate.clone(), duplicate],
        };
        assert!(
            GraphIndex::from_graph(invalid).is_err(),
            "GraphIndex must reject duplicate structural evidence before command execution"
        );
    }
}
