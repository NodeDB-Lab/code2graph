// SPDX-License-Identifier: Apache-2.0

//! Runs a case through code2graph and scores the result.
//!
//! This is the only part of the harness that touches code2graph's pipeline:
//! extract every source file in the case, resolve with the chosen tier, and
//! score the resulting graph against the case's ground truth. Everything else
//! (loading, scoring) is independent of the library.

use crate::corpus::Case;
use crate::score::{Scorecard, TieredScorecard, score, score_oracle};
use code2graph::{Confidence, LayeredResolver, Resolver, extract_path};
use std::collections::BTreeMap;

/// Extract every file in `case`, resolve with `resolver`, and score the graph
/// against the case's ground truth.
///
/// Dispatches to [`score_oracle`] when the case has SCIP-oracle location pairs
/// (i.e. `oracle.edges` was present), and to [`score`] otherwise.
pub fn score_case<R: Resolver>(case: &Case, resolver: &R) -> Scorecard {
    let facts: Vec<_> = case
        .files
        .iter()
        .filter_map(|(name, src)| extract_path(name, src).ok())
        .collect();
    let graph = resolver
        .resolve(&facts)
        .expect("extractors must produce resolver-valid FileFacts");
    score_graph_for_case(&graph, case)
}

/// Aggregate scorecard over every case, grouped by language directory.
pub fn per_language<R: Resolver>(cases: &[Case], resolver: &R) -> BTreeMap<String, Scorecard> {
    let mut by_lang: BTreeMap<String, Scorecard> = BTreeMap::new();
    for case in cases {
        by_lang
            .entry(case.lang.clone())
            .or_default()
            .merge(&score_case(case, resolver));
    }
    by_lang
}

/// Single aggregate scorecard over the whole corpus.
pub fn corpus_total<R: Resolver>(cases: &[Case], resolver: &R) -> Scorecard {
    let mut total = Scorecard::default();
    for case in cases {
        total.merge(&score_case(case, resolver));
    }
    total
}

// ── Tiered scoring for LayeredResolver ───────────────────────────────────────

/// Helper: score a pre-built graph against a case's oracle or expected edges.
fn score_graph_for_case(graph: &code2graph::CodeGraph, case: &Case) -> Scorecard {
    if !case.oracle.is_empty() {
        let sources: std::collections::HashMap<String, String> =
            case.files.iter().cloned().collect();
        score_oracle(graph, &case.oracle, &sources)
    } else {
        score(graph, &case.expected)
    }
}

/// Score one case's `LayeredResolver::default_dense()` graph at all four
/// confidence tiers.
///
/// The graph is resolved **once**; the four tiers are obtained by calling
/// [`CodeGraph::min_confidence`] with each threshold before scoring, so only the
/// cheap filter + score step is repeated per tier.
pub fn score_case_tiered(case: &Case) -> TieredScorecard {
    let facts: Vec<_> = case
        .files
        .iter()
        .filter_map(|(name, src)| extract_path(name, src).ok())
        .collect();
    let graph = LayeredResolver::default_dense()
        .resolve(&facts)
        .expect("extractors must produce resolver-valid FileFacts");

    TieredScorecard {
        heuristic: score_graph_for_case(&graph.min_confidence(Confidence::Heuristic), case),
        name_only: score_graph_for_case(&graph.min_confidence(Confidence::NameOnly), case),
        scoped: score_graph_for_case(&graph.min_confidence(Confidence::Scoped), case),
        exact: score_graph_for_case(&graph.min_confidence(Confidence::Exact), case),
    }
}

/// Aggregate `TieredScorecard` over every case, grouped by language directory.
pub fn per_language_tiered(cases: &[Case]) -> BTreeMap<String, TieredScorecard> {
    let mut by_lang: BTreeMap<String, TieredScorecard> = BTreeMap::new();
    for case in cases {
        by_lang
            .entry(case.lang.clone())
            .or_default()
            .merge(&score_case_tiered(case));
    }
    by_lang
}

/// Single aggregate `TieredScorecard` over the whole corpus.
pub fn corpus_total_tiered(cases: &[Case]) -> TieredScorecard {
    let mut total = TieredScorecard::default();
    for case in cases {
        total.merge(&score_case_tiered(case));
    }
    total
}
