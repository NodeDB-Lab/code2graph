// SPDX-License-Identifier: Apache-2.0

//! Bounded, deterministic reverse-reachability impact traversal.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use code2graph::{Confidence, Edge, EdgeKey, SymbolId};

use crate::{EdgeFilter, GraphIndex, GraphRead, order};

const IMPACT_READ_PAGE_SIZE: usize = 256;

/// Bounds and relationship constraints for a [`GraphIndex::impact`] traversal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImpactOptions {
    /// Constraints applied to every traversed edge.
    pub filter: EdgeFilter,
    /// Maximum number of edges from the seed to a returned symbol.
    pub max_depth: u32,
    /// Maximum number of returned non-seed symbols.
    pub max_nodes: usize,
}

/// One reverse-reachability result row.
#[derive(Debug, Clone)]
pub struct ImpactStep {
    /// The structurally identified symbol impacted by the seed.
    pub symbol: SymbolId,
    /// The next symbol on the selected path toward the seed.
    pub parent: SymbolId,
    /// The selected edge, for which `from == symbol` and `to == parent`.
    pub via: Edge,
    /// The selected path's minimum edge distance from the seed.
    pub depth: u32,
    /// The minimum confidence of all edges on the selected path.
    pub path_confidence: Confidence,
}

/// The result of a bounded reverse-reachability traversal.
///
/// Edges are owned so the result remains valid after a database cursor advances
/// or an in-memory index is replaced.
#[derive(Debug, Clone)]
pub struct ImpactResult {
    /// One selected path row per reachable non-seed structural identity.
    pub steps: Vec<ImpactStep>,
    /// Whether a matching reachable non-seed symbol was omitted by a bound.
    pub truncated: bool,
}

struct Candidate {
    parent: SymbolId,
    via: Edge,
    path_confidence: Confidence,
}

impl Candidate {
    fn is_better_than(&self, other: &Self) -> bool {
        self.path_confidence > other.path_confidence
            || (self.path_confidence == other.path_confidence
                && order::cmp_edge_keys(&self.via.key(), &other.via.key()) == Ordering::Less)
            || (self.path_confidence == other.path_confidence
                && order::cmp_edge_keys(&self.via.key(), &other.via.key()) == Ordering::Equal
                && self.parent < other.parent)
    }
}

struct FrontierStep {
    symbol: SymbolId,
    path_confidence: Confidence,
}

/// Traverse matching incoming edges from `seed`, returning reverse-reachable
/// callers/consumers in deterministic breadth-first order.
///
/// Reads are paged and fallible so this has the same semantics for in-memory and
/// database-backed graph readers. The seed is never returned and is permanently
/// visited. Each structural ID has one row: minimum depth wins, then the greatest
/// path bottleneck confidence, then full stable edge order and parent identity.
pub fn impact<R: GraphRead>(
    reader: &R,
    seed: &SymbolId,
    options: ImpactOptions,
) -> Result<ImpactResult, R::Error> {
    let mut steps = Vec::new();
    let mut visited = BTreeSet::new();
    visited.insert(seed.clone());
    let mut frontier = vec![FrontierStep {
        symbol: seed.clone(),
        path_confidence: Confidence::Exact,
    }];
    let mut depth = 0_u32;

    loop {
        let mut candidates = BTreeMap::<SymbolId, Candidate>::new();
        for parent in &frontier {
            let mut after: Option<EdgeKey> = None;
            loop {
                let page = reader.incoming(
                    &parent.symbol,
                    options.filter,
                    after.as_ref(),
                    IMPACT_READ_PAGE_SIZE,
                )?;
                for edge in page.items {
                    if visited.contains(&edge.from) {
                        continue;
                    }
                    let symbol = edge.from.clone();
                    let candidate = Candidate {
                        parent: parent.symbol.clone(),
                        path_confidence: parent.path_confidence.min(edge.confidence),
                        via: edge,
                    };
                    match candidates.get_mut(&symbol) {
                        Some(existing) if candidate.is_better_than(existing) => {
                            *existing = candidate
                        }
                        Some(_) => {}
                        None => {
                            candidates.insert(symbol, candidate);
                        }
                    }
                }
                let Some(next) = page.next else { break };
                after = Some(next);
            }
        }

        if candidates.is_empty() {
            return Ok(ImpactResult {
                steps,
                truncated: false,
            });
        }

        if depth >= options.max_depth {
            return Ok(ImpactResult {
                steps,
                truncated: true,
            });
        }
        let next_depth = match depth.checked_add(1) {
            Some(next_depth) => next_depth,
            None => {
                return Ok(ImpactResult {
                    steps,
                    truncated: true,
                });
            }
        };

        let remaining = options.max_nodes.saturating_sub(steps.len());
        let node_bound_omits_work = candidates.len() > remaining;
        let mut next_frontier = Vec::with_capacity(candidates.len().min(remaining));
        for (symbol, candidate) in candidates.into_iter().take(remaining) {
            visited.insert(symbol.clone());
            next_frontier.push(FrontierStep {
                symbol: symbol.clone(),
                path_confidence: candidate.path_confidence,
            });
            steps.push(ImpactStep {
                symbol,
                parent: candidate.parent,
                via: candidate.via,
                depth: next_depth,
                path_confidence: candidate.path_confidence,
            });
        }
        if node_bound_omits_work {
            return Ok(ImpactResult {
                steps,
                truncated: true,
            });
        }
        frontier = next_frontier;
        depth = next_depth;
    }
}

impl GraphIndex {
    /// In-memory convenience wrapper around the generic, fallible traversal.
    pub fn impact(&self, seed: &SymbolId, options: ImpactOptions) -> ImpactResult {
        match impact(self, seed, options) {
            Ok(result) => result,
            Err(never) => match never {},
        }
    }
}

#[cfg(test)]
mod tests {
    use code2graph::{
        CodeGraph, Confidence, Descriptor, Edge, Occurrence, Provenance, RefRole, SymbolId,
    };

    use crate::{EdgeFilter, GraphIndex, GraphPage, GraphRead, ImpactOptions, impact};

    fn id(name: &str) -> SymbolId {
        SymbolId::global(
            "rust",
            vec![
                Descriptor::Namespace("pkg".into()),
                Descriptor::Term(name.into()),
            ],
        )
    }

    fn edge(from: &SymbolId, to: &SymbolId, confidence: Confidence, byte: usize) -> Edge {
        Edge {
            from: from.clone(),
            to: to.clone(),
            role: RefRole::Call,
            confidence,
            provenance: Provenance::ScopeGraph,
            occ: Occurrence {
                file: "src/a.rs".into(),
                line: 1,
                col: 0,
                byte,
            },
        }
    }

    fn options(max_depth: u32, max_nodes: usize) -> ImpactOptions {
        ImpactOptions {
            filter: EdgeFilter::new(Confidence::Heuristic),
            max_depth,
            max_nodes,
        }
    }

    fn index(edges: Vec<Edge>) -> GraphIndex {
        GraphIndex::from_graph(CodeGraph {
            symbols: vec![],
            edges,
        })
        .expect("valid graph")
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct ReadFailure;

    struct FailingReader;

    impl GraphRead for FailingReader {
        type Error = ReadFailure;

        fn symbol(&self, _: &SymbolId) -> Result<Option<code2graph::Symbol>, Self::Error> {
            Err(ReadFailure)
        }
        fn contains_id(&self, _: &SymbolId) -> Result<bool, Self::Error> {
            Err(ReadFailure)
        }
        fn symbols(
            &self,
            _: Option<&SymbolId>,
            _: usize,
        ) -> Result<GraphPage<code2graph::Symbol, SymbolId>, Self::Error> {
            Err(ReadFailure)
        }
        fn symbols_named(
            &self,
            _: &str,
            _: Option<&SymbolId>,
            _: usize,
        ) -> Result<GraphPage<code2graph::Symbol, SymbolId>, Self::Error> {
            Err(ReadFailure)
        }
        fn symbols_with_scip(
            &self,
            _: &str,
            _: Option<&SymbolId>,
            _: usize,
        ) -> Result<GraphPage<code2graph::Symbol, SymbolId>, Self::Error> {
            Err(ReadFailure)
        }
        fn ids_with_scip(
            &self,
            _: &str,
            _: Option<&SymbolId>,
            _: usize,
        ) -> Result<GraphPage<SymbolId, SymbolId>, Self::Error> {
            Err(ReadFailure)
        }
        fn symbols_in_file(
            &self,
            _: &str,
            _: Option<&SymbolId>,
            _: usize,
        ) -> Result<GraphPage<code2graph::Symbol, SymbolId>, Self::Error> {
            Err(ReadFailure)
        }
        fn symbol_at_byte(
            &self,
            _: &str,
            _: usize,
        ) -> Result<Option<code2graph::Symbol>, Self::Error> {
            Err(ReadFailure)
        }
        fn edges(
            &self,
            _: EdgeFilter,
            _: Option<&code2graph::EdgeKey>,
            _: usize,
        ) -> Result<GraphPage<Edge, code2graph::EdgeKey>, Self::Error> {
            Err(ReadFailure)
        }
        fn edges_in_file(
            &self,
            _: &str,
            _: EdgeFilter,
            _: Option<&code2graph::EdgeKey>,
            _: usize,
        ) -> Result<GraphPage<Edge, code2graph::EdgeKey>, Self::Error> {
            Err(ReadFailure)
        }
        fn incoming(
            &self,
            _: &SymbolId,
            _: EdgeFilter,
            _: Option<&code2graph::EdgeKey>,
            _: usize,
        ) -> Result<GraphPage<Edge, code2graph::EdgeKey>, Self::Error> {
            Err(ReadFailure)
        }
        fn outgoing(
            &self,
            _: &SymbolId,
            _: EdgeFilter,
            _: Option<&code2graph::EdgeKey>,
            _: usize,
        ) -> Result<GraphPage<Edge, code2graph::EdgeKey>, Self::Error> {
            Err(ReadFailure)
        }
    }

    struct OneEdgePages(GraphIndex);

    impl GraphRead for OneEdgePages {
        type Error = std::convert::Infallible;

        fn symbol(&self, id: &SymbolId) -> Result<Option<code2graph::Symbol>, Self::Error> {
            GraphRead::symbol(&self.0, id)
        }
        fn contains_id(&self, id: &SymbolId) -> Result<bool, Self::Error> {
            GraphRead::contains_id(&self.0, id)
        }
        fn symbols(
            &self,
            after: Option<&SymbolId>,
            _: usize,
        ) -> Result<GraphPage<code2graph::Symbol, SymbolId>, Self::Error> {
            GraphRead::symbols(&self.0, after, 1)
        }
        fn symbols_named(
            &self,
            name: &str,
            after: Option<&SymbolId>,
            _: usize,
        ) -> Result<GraphPage<code2graph::Symbol, SymbolId>, Self::Error> {
            GraphRead::symbols_named(&self.0, name, after, 1)
        }
        fn symbols_with_scip(
            &self,
            scip: &str,
            after: Option<&SymbolId>,
            _: usize,
        ) -> Result<GraphPage<code2graph::Symbol, SymbolId>, Self::Error> {
            GraphRead::symbols_with_scip(&self.0, scip, after, 1)
        }
        fn ids_with_scip(
            &self,
            scip: &str,
            after: Option<&SymbolId>,
            _: usize,
        ) -> Result<GraphPage<SymbolId, SymbolId>, Self::Error> {
            GraphRead::ids_with_scip(&self.0, scip, after, 1)
        }
        fn symbols_in_file(
            &self,
            file: &str,
            after: Option<&SymbolId>,
            _: usize,
        ) -> Result<GraphPage<code2graph::Symbol, SymbolId>, Self::Error> {
            GraphRead::symbols_in_file(&self.0, file, after, 1)
        }
        fn symbol_at_byte(
            &self,
            file: &str,
            byte: usize,
        ) -> Result<Option<code2graph::Symbol>, Self::Error> {
            GraphRead::symbol_at_byte(&self.0, file, byte)
        }
        fn edges(
            &self,
            filter: EdgeFilter,
            after: Option<&code2graph::EdgeKey>,
            _: usize,
        ) -> Result<GraphPage<Edge, code2graph::EdgeKey>, Self::Error> {
            GraphRead::edges(&self.0, filter, after, 1)
        }
        fn edges_in_file(
            &self,
            file: &str,
            filter: EdgeFilter,
            after: Option<&code2graph::EdgeKey>,
            _: usize,
        ) -> Result<GraphPage<Edge, code2graph::EdgeKey>, Self::Error> {
            GraphRead::edges_in_file(&self.0, file, filter, after, 1)
        }
        fn incoming(
            &self,
            id: &SymbolId,
            filter: EdgeFilter,
            after: Option<&code2graph::EdgeKey>,
            _: usize,
        ) -> Result<GraphPage<Edge, code2graph::EdgeKey>, Self::Error> {
            GraphRead::incoming(&self.0, id, filter, after, 1)
        }
        fn outgoing(
            &self,
            id: &SymbolId,
            filter: EdgeFilter,
            after: Option<&code2graph::EdgeKey>,
            _: usize,
        ) -> Result<GraphPage<Edge, code2graph::EdgeKey>, Self::Error> {
            GraphRead::outgoing(&self.0, id, filter, after, 1)
        }
    }

    #[test]
    fn generic_impact_propagates_reader_failure() {
        assert!(matches!(
            impact(&FailingReader, &id("seed"), options(1, 1)),
            Err(ReadFailure)
        ));
    }

    #[test]
    fn generic_impact_matches_in_memory_across_reader_pages() {
        let seed = id("seed");
        let graph = index(vec![
            edge(&id("a"), &seed, Confidence::Exact, 1),
            edge(&id("b"), &seed, Confidence::Exact, 2),
            edge(&id("c"), &seed, Confidence::Exact, 3),
        ]);
        let expected = graph.impact(&seed, options(4, 10));
        let paged = impact(&OneEdgePages(graph), &seed, options(4, 10)).expect("infallible");
        assert_eq!(
            expected
                .steps
                .iter()
                .map(|step| &step.symbol)
                .collect::<Vec<_>>(),
            paged
                .steps
                .iter()
                .map(|step| &step.symbol)
                .collect::<Vec<_>>()
        );
        assert_eq!(expected.truncated, paged.truncated);
    }

    #[test]
    fn cycles_terminate_without_returning_the_seed() {
        let seed = id("seed");
        let a = id("a");
        let b = id("b");
        let graph = index(vec![
            edge(&seed, &seed, Confidence::Exact, 0),
            edge(&a, &seed, Confidence::Exact, 1),
            edge(&b, &a, Confidence::Exact, 2),
            edge(&a, &b, Confidence::Exact, 3),
        ]);

        let result = graph.impact(&seed, options(10, 10));
        assert_eq!(result.steps.len(), 2);
        assert_eq!(result.steps[0].symbol, a);
        assert_eq!(result.steps[1].symbol, b);
        assert_eq!(result.steps[0].depth, 1);
        assert_eq!(result.steps[1].depth, 2);
        assert!(!result.truncated);
    }

    #[test]
    fn long_cycles_terminate_after_each_structural_id_once() {
        let seed = id("seed");
        let a = id("a");
        let b = id("b");
        let c = id("c");
        let graph = index(vec![
            edge(&a, &seed, Confidence::Exact, 1),
            edge(&b, &a, Confidence::Exact, 2),
            edge(&c, &b, Confidence::Exact, 3),
            edge(&a, &c, Confidence::Exact, 4),
        ]);

        let result = graph.impact(&seed, options(10, 10));
        assert_eq!(
            result
                .steps
                .iter()
                .map(|step| &step.symbol)
                .collect::<Vec<_>>(),
            vec![&a, &b, &c]
        );
        assert!(!result.truncated);
    }

    #[test]
    fn weaker_shorter_path_beats_a_stronger_deeper_path() {
        let seed = id("seed");
        let middle = id("middle");
        let source = id("source");
        let short = edge(&source, &seed, Confidence::NameOnly, 1);
        let graph = index(vec![
            short.clone(),
            edge(&middle, &seed, Confidence::Exact, 2),
            edge(&source, &middle, Confidence::Exact, 3),
        ]);

        let result = graph.impact(&seed, options(10, 10));
        let source_step = result
            .steps
            .iter()
            .find(|step| step.symbol == source)
            .unwrap();
        assert_eq!(source_step.depth, 1);
        assert_eq!(source_step.parent, seed);
        assert_eq!(source_step.path_confidence, Confidence::NameOnly);
        assert_eq!(source_step.via.key(), short.key());
    }

    #[test]
    fn equal_depth_uses_strongest_bottleneck_then_stable_edge_order() {
        let seed = id("seed");
        let a = id("a");
        let b = id("b");
        let source = id("source");
        let weaker = edge(&source, &a, Confidence::NameOnly, 9);
        let stable_first = edge(&source, &a, Confidence::Exact, 1);
        let stable_second = edge(&source, &b, Confidence::Exact, 2);
        let graph = index(vec![
            edge(&a, &seed, Confidence::Exact, 3),
            edge(&b, &seed, Confidence::Exact, 4),
            weaker,
            stable_second.clone(),
            stable_first.clone(),
        ]);

        let result = graph.impact(&seed, options(10, 10));
        let step = result
            .steps
            .iter()
            .find(|step| step.symbol == source)
            .unwrap();
        assert_eq!(step.path_confidence, Confidence::Exact);
        assert_eq!(step.parent, a);
        assert_eq!(step.via.key(), stable_first.key());
    }

    #[test]
    fn bounds_report_only_proven_omissions_including_zero_bounds() {
        let seed = id("seed");
        let a = id("a");
        let b = id("b");
        let empty = index(vec![]);
        assert!(!empty.impact(&seed, options(0, 0)).truncated);

        let self_cycle = index(vec![edge(&seed, &seed, Confidence::Exact, 0)]);
        assert!(!self_cycle.impact(&seed, options(0, 0)).truncated);

        let leaf = index(vec![edge(&a, &seed, Confidence::Exact, 1)]);
        assert!(!leaf.impact(&seed, options(1, 1)).truncated);
        assert!(leaf.impact(&seed, options(0, 1)).truncated);
        assert!(leaf.impact(&seed, options(1, 0)).truncated);

        let chain = index(vec![
            edge(&a, &seed, Confidence::Exact, 1),
            edge(&b, &a, Confidence::Exact, 2),
        ]);
        assert!(chain.impact(&seed, options(1, 10)).truncated);
        assert!(chain.impact(&seed, options(10, 1)).truncated);

        let bounded_leaf = index(vec![edge(&a, &seed, Confidence::Exact, 1)]);
        let result = bounded_leaf.impact(&seed, options(10, 1));
        assert_eq!(result.steps.len(), 1);
        assert!(
            !result.truncated,
            "reaching max_nodes is not itself proof of omitted work"
        );
    }

    #[test]
    fn node_bound_detects_an_omitted_frontier_even_when_accepted_node_is_a_leaf() {
        let seed = id("seed");
        let accepted_leaf = id("a");
        let omitted = id("z");
        let omitted_descendant = id("zz");
        let graph = index(vec![
            edge(&omitted_descendant, &omitted, Confidence::Exact, 3),
            edge(&omitted, &seed, Confidence::Exact, 2),
            edge(&accepted_leaf, &seed, Confidence::Exact, 1),
        ]);

        let result = graph.impact(&seed, options(10, 1));
        assert_eq!(result.steps.len(), 1);
        assert_eq!(result.steps[0].symbol, accepted_leaf);
        assert!(result.truncated);
    }

    #[test]
    fn parent_and_via_point_from_impacted_symbol_toward_seed() {
        let seed = id("seed");
        let parent = id("parent");
        let impacted = id("impacted");
        let selected = edge(&impacted, &parent, Confidence::Scoped, 2);
        let graph = index(vec![
            selected.clone(),
            edge(&parent, &seed, Confidence::Exact, 1),
        ]);

        let result = graph.impact(&seed, options(10, 10));
        let step = result
            .steps
            .iter()
            .find(|step| step.symbol == impacted)
            .unwrap();
        assert_eq!(step.parent, parent);
        assert_eq!(step.via.from, step.symbol);
        assert_eq!(step.via.to, step.parent);
        assert_eq!(step.via.key(), selected.key());
        assert_eq!(step.path_confidence, Confidence::Scoped);
    }

    #[test]
    fn supports_endpoint_only_ids_filters_and_shuffled_input_deterministically() {
        let seed = SymbolId::local("vendor/api.rs", "seed");
        let call = SymbolId::local("vendor/a.rs", "call");
        let ignored = SymbolId::local("vendor/b.rs", "ignored");
        let accepted = edge(&call, &seed, Confidence::Exact, 2);
        let rejected = Edge {
            role: RefRole::Import,
            ..edge(&ignored, &seed, Confidence::Exact, 1)
        };
        let first = index(vec![rejected.clone(), accepted.clone()]);
        let second = index(vec![accepted.clone(), rejected]);
        let mut filtered = options(1, 10);
        filtered.filter = EdgeFilter::new(Confidence::Exact).with_role(RefRole::Call);

        let left = first.impact(&seed, filtered);
        let right = second.impact(&seed, filtered);
        assert_eq!(left.steps.len(), 1);
        assert_eq!(left.steps[0].symbol, call);
        assert_eq!(left.steps[0].via.key(), accepted.key());
        assert_eq!(
            left.steps
                .iter()
                .map(|step| (
                    step.symbol.clone(),
                    step.parent.clone(),
                    step.via.key(),
                    step.depth,
                    step.path_confidence,
                ))
                .collect::<Vec<_>>(),
            right
                .steps
                .iter()
                .map(|step| (
                    step.symbol.clone(),
                    step.parent.clone(),
                    step.via.key(),
                    step.depth,
                    step.path_confidence,
                ))
                .collect::<Vec<_>>()
        );
        assert_eq!(left.truncated, right.truncated);
    }

    #[test]
    fn applies_every_filter_constraint_at_every_depth() {
        let seed = id("seed");
        let accepted_parent = SymbolId::local("vendor/accepted.rs", "parent");
        let accepted_child = SymbolId::local("vendor/accepted.rs", "child");
        let wrong_role = id("wrong_role");
        let wrong_confidence = id("wrong_confidence");
        let wrong_provenance = id("wrong_provenance");
        let graph = index(vec![
            edge(&accepted_parent, &seed, Confidence::Exact, 1),
            edge(&accepted_child, &accepted_parent, Confidence::Scoped, 2),
            Edge {
                role: RefRole::Import,
                ..edge(&wrong_role, &accepted_parent, Confidence::Exact, 3)
            },
            edge(&wrong_confidence, &accepted_parent, Confidence::NameOnly, 4),
            Edge {
                provenance: Provenance::SymbolTable,
                ..edge(&wrong_provenance, &accepted_parent, Confidence::Exact, 5)
            },
        ]);
        let filter = EdgeFilter::new(Confidence::Scoped)
            .with_role(RefRole::Call)
            .with_provenance(Provenance::ScopeGraph);

        let result = graph.impact(
            &seed,
            ImpactOptions {
                filter,
                max_depth: 10,
                max_nodes: 10,
            },
        );
        assert_eq!(
            result
                .steps
                .iter()
                .map(|step| &step.symbol)
                .collect::<Vec<_>>(),
            vec![&accepted_parent, &accepted_child]
        );
        assert!(!result.truncated);
    }
}
