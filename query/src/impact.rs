// SPDX-License-Identifier: Apache-2.0

//! Bounded, deterministic reverse-reachability impact traversal.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use code2graph::{Confidence, Edge, SymbolId};

use crate::{EdgeFilter, GraphIndex, order};

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
#[derive(Debug)]
pub struct ImpactStep<'a> {
    /// The structurally identified symbol impacted by the seed.
    pub symbol: SymbolId,
    /// The next symbol on the selected path toward the seed.
    pub parent: SymbolId,
    /// The selected edge, for which `from == symbol` and `to == parent`.
    pub via: &'a Edge,
    /// The selected path's minimum edge distance from the seed.
    pub depth: u32,
    /// The minimum confidence of all edges on the selected path.
    pub path_confidence: Confidence,
}

/// The result of a bounded reverse-reachability traversal.
///
/// Its edge references borrow the [`GraphIndex`], so it cannot outlive that
/// index or survive a mutable borrow that changes the index.
#[derive(Debug)]
pub struct ImpactResult<'a> {
    /// One selected path row per reachable non-seed structural identity.
    pub steps: Vec<ImpactStep<'a>>,
    /// Whether a matching reachable non-seed symbol was omitted by a bound.
    pub truncated: bool,
}

struct Candidate<'a> {
    parent: SymbolId,
    via: &'a Edge,
    path_confidence: Confidence,
}

impl<'a> Candidate<'a> {
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

impl GraphIndex {
    /// Traverse matching incoming edges from `seed`, returning reverse-reachable
    /// callers/consumers in deterministic breadth-first order.
    ///
    /// The seed is never returned and is permanently visited. Each structural ID
    /// has one row: minimum depth wins, then the greatest path bottleneck
    /// confidence, then full stable edge order and parent structural identity.
    /// Each breadth level is finalized before any of its IDs are expanded; those
    /// finalized IDs expand in structural-ID order. Endpoint-only IDs participate
    /// exactly like locally defined symbols.
    ///
    /// Returned edges borrow this index; the result cannot outlive it or survive
    /// mutation of the index.
    pub fn impact<'a>(&'a self, seed: &SymbolId, options: ImpactOptions) -> ImpactResult<'a> {
        let mut steps = Vec::new();
        let mut visited = BTreeSet::new();
        visited.insert(seed.clone());
        let mut frontier = vec![FrontierStep {
            symbol: seed.clone(),
            path_confidence: Confidence::Exact,
        }];
        let mut depth = 0_u32;

        loop {
            let mut candidates = BTreeMap::<SymbolId, Candidate<'a>>::new();
            for parent in &frontier {
                for edge in self.incoming(&parent.symbol, options.filter) {
                    if visited.contains(&edge.from) {
                        continue;
                    }
                    let candidate = Candidate {
                        parent: parent.symbol.clone(),
                        via: edge,
                        path_confidence: parent.path_confidence.min(edge.confidence),
                    };
                    match candidates.get_mut(&edge.from) {
                        Some(existing) if candidate.is_better_than(existing) => {
                            *existing = candidate
                        }
                        Some(_) => {}
                        None => {
                            candidates.insert(edge.from.clone(), candidate);
                        }
                    }
                }
            }

            if candidates.is_empty() {
                return ImpactResult {
                    steps,
                    truncated: false,
                };
            }

            if depth >= options.max_depth {
                return ImpactResult {
                    steps,
                    truncated: true,
                };
            }
            let next_depth = match depth.checked_add(1) {
                Some(next_depth) => next_depth,
                None => {
                    return ImpactResult {
                        steps,
                        truncated: true,
                    };
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
                return ImpactResult {
                    steps,
                    truncated: true,
                };
            }
            frontier = next_frontier;
            depth = next_depth;
        }
    }
}

#[cfg(test)]
mod tests {
    use code2graph::{
        CodeGraph, Confidence, Descriptor, Edge, Occurrence, Provenance, RefRole, SymbolId,
    };

    use crate::{EdgeFilter, GraphIndex, ImpactOptions};

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
