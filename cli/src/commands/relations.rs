// SPDX-License-Identifier: Apache-2.0

//! Incoming and outgoing resolved-relation selector commands.

use std::collections::BTreeMap;
use std::path::Path;

use code2graph::{Edge, EdgeKey, RefRole, SymbolId};
#[cfg(test)]
use code2graph_query::GraphIndex;
use code2graph_query::{EdgeFilter, GraphRead};

use crate::commands::QueryCommandContext;
use crate::commands::shared::{limit, query_envelope, symbol_output};
use crate::result::{OccurrenceOutput, OutputEnvelope, RelationOutput, SelectorOutput};
use crate::{
    ProjectPath, Result, Selector, SelectorContext, SelectorOptions, SelectorPurpose,
    SelectorRequest, resolve_selector,
};

/// Direction used by a relationship selector command.
#[derive(Clone, Copy)]
pub(crate) enum RelationDirection {
    Incoming,
    Outgoing,
}

pub(crate) struct RelationCommandRequest<'a> {
    pub selector: &'a Selector,
    pub file: Option<&'a str>,
    pub kind: Option<code2graph::SymbolKind>,
    pub require_unique: bool,
    pub role: Option<RefRole>,
    pub direction: RelationDirection,
    pub result_limit: usize,
    pub min_confidence: code2graph::Confidence,
}

/// Executes callers, callees, and usages over the complete selector result.
pub(crate) fn execute_relations<R>(
    context: &QueryCommandContext<'_, R>,
    request: RelationCommandRequest<'_>,
) -> Result<OutputEnvelope<Vec<RelationOutput>>>
where
    R: GraphRead,
    R::Error: Into<crate::CliError>,
{
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
        graph: context.index,
        selection: &context.loaded.selection,
        candidate_hashes: &context.candidate_hashes,
        max_file_bytes: context.max_file_bytes,
        deadline: context.deadline,
        cancellation: context.cancellation,
    };
    let resolution = resolve_selector(
        &selector_context,
        &SelectorRequest {
            selector: request.selector,
            purpose: SelectorPurpose::AnyGraphId,
            options: &options,
        },
    )?;
    let filter = EdgeFilter {
        role: request.role,
        min_confidence: request.min_confidence,
        provenance: None,
    };
    let complete =
        collect_relation_evidence_read(context.index, &resolution.ids, request.direction, filter)?
            .into_iter()
            .map(|edge| relation_output(&edge))
            .collect::<Vec<_>>();
    context.deadline.check(context.cancellation)?;
    let mut results = complete.clone();
    let (total, truncated) = limit(&mut results, request.result_limit);
    let mut envelope = query_envelope(context.loaded, results);
    envelope.selector = Some(SelectorOutput {
        matched: resolution.summary.matched_count,
        ambiguous: resolution.summary.ambiguous,
        ids: resolution.ids,
        symbols: resolution
            .symbols
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(symbol_output)
            .collect(),
    });
    envelope.total = total;
    envelope.returned = envelope.results.len();
    envelope.truncated = truncated;
    Ok(envelope)
}

#[cfg(test)]
fn collect_relation_evidence<'a>(
    index: &'a GraphIndex,
    ids: &[SymbolId],
    direction: RelationDirection,
    filter: EdgeFilter,
) -> Vec<&'a Edge> {
    // BTreeMap retains one value per exact EdgeKey only. The index itself has
    // already validated that a key cannot carry conflicting edge payloads.
    // Consequently both deduplication and output order use all structural edge
    // evidence, including occurrence and provenance rather than lossy endpoints.
    let mut evidence = BTreeMap::<EdgeKey, &Edge>::new();
    for id in ids {
        let edges = match direction {
            RelationDirection::Incoming => index.incoming(id, filter),
            RelationDirection::Outgoing => index.outgoing(id, filter),
        };
        for edge in edges {
            evidence.insert(edge.key(), edge);
        }
    }
    evidence.into_values().collect()
}

fn collect_relation_evidence_read<R>(
    graph: &R,
    ids: &[SymbolId],
    direction: RelationDirection,
    filter: EdgeFilter,
) -> Result<Vec<Edge>>
where
    R: GraphRead,
    R::Error: Into<crate::CliError>,
{
    let mut evidence = BTreeMap::<EdgeKey, Edge>::new();
    for id in ids {
        let mut after = None;
        loop {
            let page = match direction {
                RelationDirection::Incoming => graph.incoming(id, filter, after.as_ref(), 256),
                RelationDirection::Outgoing => graph.outgoing(id, filter, after.as_ref(), 256),
            }
            .map_err(Into::into)?;
            for edge in page.items {
                evidence.insert(edge.key(), edge);
            }
            let Some(next) = page.next else { break };
            after = Some(next);
        }
    }
    Ok(evidence.into_values().collect())
}

pub(crate) fn relation_output(edge: &Edge) -> RelationOutput {
    RelationOutput {
        from: edge.from.clone(),
        to: edge.to.clone(),
        role: edge.role.into(),
        confidence: edge.confidence.into(),
        provenance: edge.provenance.into(),
        occurrence: OccurrenceOutput {
            file: ProjectPath::new(Path::new(&edge.occ.file))
                .map_or_else(|_| edge.occ.file.clone(), |path| path.to_string()),
            line: edge.occ.line,
            column: edge.occ.col,
            byte: edge.occ.byte,
        },
    }
}

#[cfg(test)]
mod tests {
    use code2graph::{
        CodeGraph, Confidence, Descriptor, Edge, Occurrence, Provenance, RefRole, SymbolId,
    };
    use code2graph_query::{EdgeFilter, GraphIndex};

    use super::{
        RelationDirection, collect_relation_evidence, collect_relation_evidence_read,
        relation_output,
    };

    #[test]
    fn relation_output_preserves_lossless_ids_and_zero_based_json_coordinates() {
        let from = SymbolId::global("rust", vec![Descriptor::Term("caller".into())]);
        let to = SymbolId::local("vendor/api.rs", "callee");
        let edge = Edge {
            from: from.clone(),
            to: to.clone(),
            role: RefRole::Read,
            confidence: Confidence::Scoped,
            provenance: Provenance::ScopeGraph,
            occ: Occurrence {
                file: "src//caller.rs".into(),
                line: 7,
                col: 0,
                byte: 19,
            },
        };
        let output = relation_output(&edge);
        assert_eq!(output.from, from);
        assert_eq!(output.to, to);
        assert_eq!(output.occurrence.file, "src/caller.rs");
        assert_eq!(output.occurrence.line, 7);
        assert_eq!(output.occurrence.column, 0);
        assert_eq!(output.occurrence.byte, 19);
    }

    #[test]
    fn evidence_uses_complete_edge_keys_for_deduplication_and_order() {
        let caller = SymbolId::global("rust", vec![Descriptor::Term("caller".into())]);
        let endpoint = SymbolId::local("vendor/api.rs", "callee");
        let make_edge = |byte, provenance| Edge {
            from: caller.clone(),
            to: endpoint.clone(),
            role: RefRole::Call,
            confidence: Confidence::Scoped,
            provenance,
            occ: Occurrence {
                file: "src/caller.rs".into(),
                line: 1,
                col: byte as u32,
                byte,
            },
        };
        let index = GraphIndex::from_graph(CodeGraph {
            symbols: Vec::new(),
            edges: vec![
                make_edge(9, Provenance::ScopeGraph),
                make_edge(2, Provenance::External),
                make_edge(2, Provenance::ScopeGraph),
            ],
        })
        .unwrap();
        assert!(
            index.symbol(&endpoint).is_none(),
            "the endpoint has no definition"
        );

        let evidence = collect_relation_evidence(
            &index,
            &[endpoint.clone(), endpoint.clone()],
            RelationDirection::Incoming,
            EdgeFilter::new(Confidence::Scoped).with_role(RefRole::Call),
        );
        let paged = collect_relation_evidence_read(
            &index,
            &[endpoint.clone(), endpoint],
            RelationDirection::Incoming,
            EdgeFilter::new(Confidence::Scoped).with_role(RefRole::Call),
        )
        .unwrap();
        assert_eq!(
            evidence.iter().map(|edge| edge.key()).collect::<Vec<_>>(),
            paged.iter().map(|edge| edge.key()).collect::<Vec<_>>(),
            "paged GraphRead evidence preserves in-memory relation ordering"
        );
        assert_eq!(
            evidence.len(),
            3,
            "repeated selected IDs do not duplicate rows"
        );
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
            vec![2, 2, 9],
            "distinct provenance at one occurrence remains distinct evidence"
        );
    }
}
