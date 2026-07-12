// SPDX-License-Identifier: Apache-2.0

//! Bounded reverse-reachability impact selector command.

use std::path::Path;

use code2graph::{EdgeKey, RefRole, SymbolId, SymbolKind};
use code2graph_query::{EdgeFilter, GraphRead, ImpactOptions};

use crate::commands::QueryCommandContext;
use crate::commands::relations::relation_output;
use crate::commands::shared::{query_envelope, symbol_output};
use crate::result::{ImpactOutput, OutputEnvelope, SelectorOutput};
use crate::{
    ProjectPath, Result, Selector, SelectorContext, SelectorOptions, SelectorPurpose,
    SelectorRequest, resolve_selector,
};

pub(crate) struct ImpactCommandRequest<'a> {
    pub selector: &'a Selector,
    pub file: Option<&'a str>,
    pub kind: Option<code2graph::SymbolKind>,
    pub require_unique: bool,
    pub role: Option<RefRole>,
    pub depth: u32,
    pub max_nodes: usize,
    pub min_confidence: code2graph::Confidence,
}

/// Executes a separate bounded traversal for every selected seed.
pub(crate) fn execute_impact<R>(
    context: &QueryCommandContext<'_, R>,
    request: ImpactCommandRequest<'_>,
) -> Result<OutputEnvelope<Vec<ImpactOutput>>>
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
    let mut rows: Vec<(ImpactOutput, EdgeKey)> = Vec::new();
    let mut truncated = false;
    // `--limit` is a command-wide output bound, not a fresh allowance for each
    // ambiguous seed. Preserve independent traversals while allocating the
    // remaining capacity in the selector's stable structural-ID order. Even at
    // zero capacity every seed is traversed so `truncated` honestly reports
    // whether that seed had matching reachable work.
    for seed in &resolution.ids {
        context.deadline.check(context.cancellation)?;
        let implicit_role = default_impact_role(context.index, seed)?;
        let filter = EdgeFilter {
            role: request.role.or(implicit_role),
            min_confidence: request.min_confidence,
            provenance: None,
        };
        truncated |= append_seed_impact(
            context.index,
            seed,
            filter,
            request.depth,
            request.max_nodes,
            &mut rows,
        )?;
    }
    rows.sort_by(|(left, left_edge), (right, right_edge)| {
        (&left.seed, left.depth, &left.symbol, left_edge).cmp(&(
            &right.seed,
            right.depth,
            &right.symbol,
            right_edge,
        ))
    });
    let results = rows.into_iter().map(|(row, _)| row).collect::<Vec<_>>();
    let total = results.len();
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

fn default_impact_role<R>(index: &R, seed: &SymbolId) -> Result<Option<RefRole>>
where
    R: GraphRead,
    R::Error: Into<crate::CliError>,
{
    match index.symbol(seed).map_err(Into::into)? {
        Some(symbol)
            if matches!(
                symbol.kind,
                SymbolKind::Struct
                    | SymbolKind::Enum
                    | SymbolKind::Trait
                    | SymbolKind::Class
                    | SymbolKind::Interface
                    | SymbolKind::TypeAlias
            ) =>
        {
            Ok(None)
        }
        _ => Ok(Some(RefRole::Call)),
    }
}

fn append_seed_impact<R>(
    index: &R,
    seed: &SymbolId,
    filter: EdgeFilter,
    max_depth: u32,
    global_max_nodes: usize,
    rows: &mut Vec<(ImpactOutput, EdgeKey)>,
) -> Result<bool>
where
    R: GraphRead,
    R::Error: Into<crate::CliError>,
{
    let impact = code2graph_query::impact(
        index,
        seed,
        ImpactOptions {
            filter,
            max_depth,
            max_nodes: global_max_nodes.saturating_sub(rows.len()),
        },
    )
    .map_err(Into::into)?;
    let truncated = impact.truncated;
    rows.extend(impact.steps.into_iter().map(|step| {
        let key = step.via.key();
        (
            ImpactOutput {
                seed: seed.clone(),
                symbol: step.symbol,
                parent: step.parent,
                depth: step.depth,
                path_confidence: step.path_confidence.into(),
                via: relation_output(&step.via),
            },
            key,
        )
    }));
    Ok(truncated)
}

#[cfg(test)]
mod tests {
    use code2graph::{
        ByteSpan, CodeGraph, Confidence, Descriptor, Edge, Occurrence, Provenance, RefRole, Symbol,
        SymbolId, SymbolKind, Visibility,
    };
    use code2graph_query::{EdgeFilter, GraphIndex};

    use super::{append_seed_impact, default_impact_role};

    fn id(name: &str) -> SymbolId {
        SymbolId::global("rust", vec![Descriptor::Term(name.into())])
    }

    fn edge(from: &SymbolId, to: &SymbolId, byte: usize) -> Edge {
        Edge {
            from: from.clone(),
            to: to.clone(),
            role: RefRole::Call,
            confidence: Confidence::Scoped,
            provenance: Provenance::ScopeGraph,
            occ: Occurrence {
                file: "src/lib.rs".into(),
                line: 1,
                col: 0,
                byte,
            },
        }
    }

    #[test]
    fn type_seeds_default_to_all_roles_and_functions_default_to_calls() {
        let type_id = SymbolId::global("rust", vec![Descriptor::Type("Config".into())]);
        let function_id = id("run");
        let symbol = |id: SymbolId, name: &str, kind: SymbolKind| Symbol {
            id,
            name: name.into(),
            kind,
            visibility: Visibility::Public,
            entry_points: vec![],
            file: "src/lib.rs".into(),
            line: 1,
            span: ByteSpan { start: 0, end: 1 },
            signature: name.into(),
        };
        let index = GraphIndex::from_graph(CodeGraph {
            symbols: vec![
                symbol(type_id.clone(), "Config", SymbolKind::Struct),
                symbol(function_id.clone(), "run", SymbolKind::Function),
            ],
            edges: vec![],
        })
        .unwrap();

        assert_eq!(default_impact_role(&index, &type_id).unwrap(), None);
        assert_eq!(
            default_impact_role(&index, &function_id).unwrap(),
            Some(RefRole::Call)
        );
        assert_eq!(
            default_impact_role(&index, &id("external")).unwrap(),
            Some(RefRole::Call)
        );
    }

    #[test]
    fn plural_seeds_share_one_global_bound_without_merging_traversals() {
        let seed_a = id("seed_a");
        let seed_b = id("seed_b");
        let caller_a = id("caller_a");
        let caller_b = id("caller_b");
        let index = GraphIndex::from_graph(CodeGraph {
            symbols: Vec::new(),
            edges: vec![edge(&caller_b, &seed_b, 2), edge(&caller_a, &seed_a, 1)],
        })
        .unwrap();
        let filter = EdgeFilter::new(Confidence::Scoped).with_role(RefRole::Call);
        let mut rows = Vec::new();
        let mut truncated = false;
        for seed in [&seed_a, &seed_b] {
            truncated |= append_seed_impact(&index, seed, filter, 5, 1, &mut rows).unwrap();
        }

        assert_eq!(rows.len(), 1, "the limit is global rather than per seed");
        assert_eq!(rows[0].0.seed, seed_a);
        assert_eq!(rows[0].0.symbol, caller_a);
        assert!(truncated, "the omitted second traversal must be reported");
    }

    #[test]
    fn independent_seed_rows_survive_cycles_and_diamond_deduplication() {
        let seed_a = id("seed_a");
        let seed_b = id("seed_b");
        let shared = id("shared");
        let left = id("left");
        let right = id("right");
        let index = GraphIndex::from_graph(CodeGraph {
            symbols: Vec::new(),
            edges: vec![
                edge(&shared, &seed_a, 1),
                edge(&seed_a, &shared, 2),
                edge(&shared, &seed_b, 3),
                edge(&left, &shared, 4),
                edge(&right, &shared, 5),
                edge(&left, &right, 6),
            ],
        })
        .unwrap();
        let filter = EdgeFilter::new(Confidence::Scoped).with_role(RefRole::Call);
        let mut rows = Vec::new();
        let mut truncated = false;
        for seed in [&seed_a, &seed_b] {
            truncated |= append_seed_impact(&index, seed, filter, 10, 20, &mut rows).unwrap();
        }

        assert!(!truncated);
        assert_eq!(rows.iter().filter(|(row, _)| row.seed == seed_a).count(), 3);
        assert_eq!(rows.iter().filter(|(row, _)| row.seed == seed_b).count(), 4);
        assert_eq!(
            rows.iter()
                .filter(|(row, _)| row.seed == seed_b && row.symbol == left)
                .count(),
            1,
            "a diamond yields one deterministic row per symbol per traversal"
        );
    }
}
