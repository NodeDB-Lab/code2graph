// SPDX-License-Identifier: Apache-2.0

//! Resolved import and module-reference relations originating in one file.

use std::path::Path;

#[cfg(test)]
use code2graph::CodeGraph;
use code2graph::{Confidence, Edge, EdgeKey, RefRole};
use code2graph_query::{EdgeFilter, GraphRead};

use crate::commands::QueryCommandContext;
use crate::commands::relation_output;
use crate::commands::shared::{limit, normalized_project_path, query_envelope};
use crate::result::{OutputEnvelope, RelationOutput};
use crate::{CliError, ProjectPath, Result};

pub(crate) struct ImportsCommandRequest<'a> {
    pub file: &'a str,
    pub result_limit: usize,
    pub min_confidence: Confidence,
}

/// Returns every resolved import/module-reference edge whose occurrence is in
/// the requested snapshot file.  Structural edge keys retain parallel evidence.
pub(crate) fn execute_imports<R>(
    context: &QueryCommandContext<'_, R>,
    request: ImportsCommandRequest<'_>,
) -> Result<OutputEnvelope<Vec<RelationOutput>>>
where
    R: GraphRead,
    R::Error: Into<CliError>,
{
    context.deadline.check(context.cancellation)?;
    let file = ProjectPath::new(Path::new(request.file))?;
    if !context
        .candidate_hashes
        .keys()
        .any(|path| normalized_project_path(path) == file.as_str())
    {
        return Err(CliError::NoMatch);
    }

    let mut results = collect_imports_read(context.index, file.as_str(), request.min_confidence)?
        .into_iter()
        .map(|edge| relation_output(&edge))
        .collect::<Vec<_>>();
    context.deadline.check(context.cancellation)?;
    if results.is_empty() {
        return Err(CliError::NoMatch);
    }
    let (total, truncated) = limit(&mut results, request.result_limit);
    let mut envelope = query_envelope(context.loaded, results);
    envelope.total = total;
    envelope.returned = envelope.results.len();
    envelope.truncated = truncated;
    Ok(envelope)
}

fn collect_imports_read<R>(
    graph: &R,
    normalized_file: &str,
    min_confidence: Confidence,
) -> Result<Vec<Edge>>
where
    R: GraphRead,
    R::Error: Into<CliError>,
{
    let filter = EdgeFilter {
        role: None,
        min_confidence,
        provenance: None,
    };
    let mut after: Option<EdgeKey> = None;
    let mut evidence = Vec::new();
    loop {
        let page = graph
            .edges(filter, after.as_ref(), 256)
            .map_err(Into::into)?;
        evidence.extend(page.items.into_iter().filter(|edge| {
            normalized_project_path(&edge.occ.file) == normalized_file
                && matches!(edge.role, RefRole::Import | RefRole::ModuleRef)
        }));
        let Some(next) = page.next else { break };
        after = Some(next);
    }
    Ok(evidence)
}

#[cfg(test)]
fn collect_imports<'a>(
    graph: &'a CodeGraph,
    normalized_file: &str,
    min_confidence: Confidence,
) -> Vec<&'a Edge> {
    let mut evidence = graph
        .edges
        .iter()
        .filter(|edge| {
            normalized_project_path(&edge.occ.file) == normalized_file
                && matches!(edge.role, RefRole::Import | RefRole::ModuleRef)
                && edge.confidence >= min_confidence
        })
        .collect::<Vec<_>>();
    evidence.sort_by_key(|edge| edge.key());
    evidence
}

#[cfg(test)]
mod tests {
    use code2graph::{
        CodeGraph, Confidence, Descriptor, Edge, Occurrence, Provenance, RefRole, SymbolId,
    };

    use super::{collect_imports, collect_imports_read};

    fn edge(role: RefRole, confidence: Confidence, byte: usize, provenance: Provenance) -> Edge {
        Edge {
            from: SymbolId::global("rust", vec![Descriptor::Term("caller".into())]),
            to: SymbolId::global("rust", vec![Descriptor::Term("target".into())]),
            role,
            confidence,
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
    fn imports_normalize_file_filter_roles_confidence_and_retain_parallel_evidence() {
        let graph = CodeGraph {
            symbols: Vec::new(),
            edges: vec![
                edge(RefRole::Call, Confidence::Exact, 0, Provenance::ScopeGraph),
                edge(
                    RefRole::Import,
                    Confidence::NameOnly,
                    1,
                    Provenance::SymbolTable,
                ),
                edge(
                    RefRole::ModuleRef,
                    Confidence::Scoped,
                    4,
                    Provenance::External,
                ),
                edge(RefRole::Import, Confidence::Scoped, 2, Provenance::External),
                edge(
                    RefRole::Import,
                    Confidence::Scoped,
                    2,
                    Provenance::ScopeGraph,
                ),
            ],
        };

        let evidence = collect_imports(&graph, "src/main.rs", Confidence::Scoped);
        let index = code2graph_query::GraphIndex::from_graph(graph.clone()).unwrap();
        let paged = collect_imports_read(&index, "src/main.rs", Confidence::Scoped).unwrap();
        assert_eq!(
            evidence.iter().map(|edge| edge.key()).collect::<Vec<_>>(),
            paged.iter().map(|edge| edge.key()).collect::<Vec<_>>(),
            "paged GraphRead path preserves in-memory import evidence"
        );
        assert_eq!(evidence.len(), 3);
        assert!(
            evidence
                .windows(2)
                .all(|pair| pair[0].key() < pair[1].key())
        );
        assert_eq!(
            evidence
                .iter()
                .map(|edge| edge.occ.byte)
                .collect::<Vec<_>>(),
            vec![2, 2, 4]
        );
        assert!(evidence.iter().any(|edge| edge.role == RefRole::ModuleRef));
        assert_eq!(
            evidence.iter().filter(|edge| edge.occ.byte == 2).count(),
            2,
            "parallel evidence differing only by provenance must not be lost"
        );
    }
}
