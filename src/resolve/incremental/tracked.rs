// SPDX-License-Identifier: Apache-2.0

//! Snapshot-lineage tracking for incremental scope-graph transitions.

use std::collections::HashMap;

use crate::error::Result;
use crate::graph::{CodeGraph, Edge, EdgeKey, EntryPoint, Symbol};
use crate::symbol::SymbolId;

use super::FileSubgraph;
use super::delta::{FileChange, ScopeGraphDelta, ScopeSnapshotToken};
use super::store::{IncrementalGraph, MutationBounds};

/// An [`IncrementalGraph`] bound to the opaque token of its current snapshot.
///
/// The token is consumer-owned: this type preserves exact transition lineage but
/// deliberately does not interpret, validate, or derive token bytes.
pub struct TrackedIncrementalGraph {
    inner: IncrementalGraph,
    snapshot: ScopeSnapshotToken,
}

impl IncrementalGraph {
    /// Bind this complete graph state to its consumer-provided snapshot token.
    pub fn into_tracked(self, snapshot: ScopeSnapshotToken) -> TrackedIncrementalGraph {
        TrackedIncrementalGraph {
            inner: self,
            snapshot,
        }
    }
}

impl TrackedIncrementalGraph {
    /// The token for the graph currently held by this value.
    pub fn snapshot(&self) -> ScopeSnapshotToken {
        self.snapshot
    }

    /// Return the complete current scope-tier graph.
    pub fn graph(&self) -> CodeGraph {
        self.inner.graph()
    }

    /// Borrow an opaque persisted subgraph by its file key.
    pub fn subgraph(&self, file: &str) -> Option<&FileSubgraph> {
        self.inner.subgraph(file)
    }

    /// Atomically apply one complete file-set transition and return its exact,
    /// bounded scope-tier delta.
    ///
    /// All inputs are validated before the store mutates. The delta compares
    /// changed-file facts plus only unchanged pending references selected by the
    /// reverse pending index; it never materializes or diffs whole graphs.
    pub fn apply_batch_with_delta(
        &mut self,
        changes: &[FileChange<'_>],
        snapshot: ScopeSnapshotToken,
    ) -> Result<ScopeGraphDelta> {
        let base_snapshot = self.snapshot;
        let bounds = self.inner.try_apply_changes_bounded(changes)?;
        let delta = delta_from_bounds(base_snapshot, snapshot, bounds);
        // Store mutation and delta construction have completed; this is the
        // infallible lineage commit point. Opaque tokens may repeat or skip.
        self.snapshot = snapshot;
        Ok(delta)
    }
}

fn delta_from_bounds(
    base_snapshot: ScopeSnapshotToken,
    snapshot: ScopeSnapshotToken,
    bounds: MutationBounds,
) -> ScopeGraphDelta {
    let before_symbols = symbol_map(bounds.before_symbols);
    let after_symbols = symbol_map(bounds.after_symbols);
    let before_edges = edge_map(bounds.before_edges);
    let after_edges = edge_map(bounds.after_edges);

    let mut removed_symbols: Vec<_> = before_symbols
        .keys()
        .filter(|id| !after_symbols.contains_key(*id))
        .cloned()
        .collect();
    let mut upserted_symbols: Vec<_> = after_symbols
        .iter()
        .filter(|(id, symbol)| {
            before_symbols
                .get(*id)
                .is_none_or(|before| !same_symbol(before, symbol))
        })
        .map(|(_, symbol)| (*symbol).clone())
        .collect();
    let mut removed_edges: Vec<_> = before_edges
        .keys()
        .filter(|key| !after_edges.contains_key(*key))
        .cloned()
        .collect();
    let mut upserted_edges: Vec<_> = after_edges
        .iter()
        .filter(|(key, edge)| {
            before_edges
                .get(*key)
                .is_none_or(|before| !same_edge(before, edge))
        })
        .map(|(_, edge)| (*edge).clone())
        .collect();

    removed_symbols.sort();
    upserted_symbols.sort_by(|left, right| left.id.cmp(&right.id));
    removed_edges.sort();
    upserted_edges.sort_by(|left, right| {
        left.key()
            .cmp(&right.key())
            .then(left.confidence.cmp(&right.confidence))
    });

    ScopeGraphDelta {
        base_snapshot,
        snapshot,
        removed_symbols,
        upserted_symbols,
        removed_edges,
        upserted_edges,
    }
}

fn same_symbol(left: &Symbol, right: &Symbol) -> bool {
    left.id == right.id
        && left.name == right.name
        && left.kind == right.kind
        && left.visibility == right.visibility
        && left.file == right.file
        && left.line == right.line
        && left.span == right.span
        && left.signature == right.signature
        && left.entry_points.len() == right.entry_points.len()
        && left
            .entry_points
            .iter()
            .zip(&right.entry_points)
            .all(|(left, right)| match (left, right) {
                (EntryPoint::Main, EntryPoint::Main) => true,
                (EntryPoint::HttpRoute(left), EntryPoint::HttpRoute(right)) => left == right,
                _ => false,
            })
}

fn same_edge(left: &Edge, right: &Edge) -> bool {
    left.from == right.from
        && left.to == right.to
        && left.role == right.role
        && left.confidence == right.confidence
        && left.provenance == right.provenance
        && left.occ == right.occ
}

fn symbol_map(symbols: Vec<Symbol>) -> HashMap<SymbolId, Symbol> {
    // First-wins by id, matching `IncrementalGraph::graph`'s dedup policy for
    // the shared namespace-only symbol a multi-file package/module emits in
    // each of its files — otherwise a diff built here could disagree with
    // which copy the cold `graph()` build keeps.
    let mut map = HashMap::new();
    for symbol in symbols {
        map.entry(symbol.id.clone()).or_insert(symbol);
    }
    map
}

fn edge_map(edges: Vec<Edge>) -> HashMap<EdgeKey, Edge> {
    edges.into_iter().map(|edge| (edge.key(), edge)).collect()
}

#[cfg(all(test, feature = "rust"))]
mod tests {
    use super::*;
    use crate::extract::{Extractor, RustExtractor};
    use crate::graph::{Confidence, RefRole};
    use crate::resolve::FileChange;

    fn assert_delta_parity(before: &CodeGraph, after: &CodeGraph, delta: &ScopeGraphDelta) {
        let mut symbols = symbol_map(before.symbols.clone());
        let mut edges = edge_map(before.edges.clone());
        for id in &delta.removed_symbols {
            symbols.remove(id);
        }
        for symbol in &delta.upserted_symbols {
            symbols.insert(symbol.id.clone(), symbol.clone());
        }
        for key in &delta.removed_edges {
            edges.remove(key);
        }
        for edge in &delta.upserted_edges {
            edges.insert(edge.key(), edge.clone());
        }

        let expected_symbols = symbol_map(after.symbols.clone());
        let expected_edges = edge_map(after.edges.clone());
        assert_eq!(symbols.len(), expected_symbols.len());
        assert_eq!(edges.len(), expected_edges.len());
        for (id, expected) in expected_symbols {
            assert!(
                symbols
                    .get(&id)
                    .is_some_and(|actual| same_symbol(actual, &expected)),
                "symbol payload differs for {id:?}"
            );
        }
        for (key, expected) in expected_edges {
            assert!(
                edges
                    .get(&key)
                    .is_some_and(|actual| same_edge(actual, &expected)),
                "edge payload differs for {key:?}"
            );
        }
    }

    fn assert_sorted(delta: &ScopeGraphDelta) {
        assert!(
            delta
                .removed_symbols
                .windows(2)
                .all(|pair| pair[0] <= pair[1])
        );
        assert!(
            delta
                .upserted_symbols
                .windows(2)
                .all(|pair| pair[0].id <= pair[1].id)
        );
        assert!(
            delta
                .removed_edges
                .windows(2)
                .all(|pair| pair[0] <= pair[1])
        );
        assert!(delta.upserted_edges.windows(2).all(|pair| {
            (pair[0].key(), pair[0].confidence) <= (pair[1].key(), pair[1].confidence)
        }));
    }

    #[test]
    fn empty_and_identical_transitions_advance_lineage_with_empty_deltas() {
        let facts = RustExtractor
            .extract("pub fn provider() {}", "src/provider.rs")
            .expect("provider facts");
        let initial = ScopeSnapshotToken::new([1; 32]);
        let middle = ScopeSnapshotToken::new([2; 32]);
        let final_token = ScopeSnapshotToken::new([3; 32]);
        let mut graph =
            IncrementalGraph::from_files(std::slice::from_ref(&facts)).into_tracked(initial);

        for (changes, expected_base, token) in [
            (Vec::new(), initial, middle),
            (vec![FileChange::Upsert(&facts)], middle, final_token),
        ] {
            let before = graph.graph();
            let delta = graph
                .apply_batch_with_delta(&changes, token)
                .expect("no-op transition");
            assert_eq!(delta.base_snapshot, expected_base);
            assert_eq!(delta.snapshot, token);
            assert!(delta.removed_symbols.is_empty());
            assert!(delta.upserted_symbols.is_empty());
            assert!(delta.removed_edges.is_empty());
            assert!(delta.upserted_edges.is_empty());
            assert_delta_parity(&before, &graph.graph(), &delta);
            assert_eq!(graph.snapshot(), token);
        }
    }

    #[test]
    fn mixed_multi_file_add_replace_delete_delta_has_keyed_parity() {
        let old = RustExtractor
            .extract("pub fn old() {}", "src/old.rs")
            .expect("old facts");
        let prior = RustExtractor
            .extract("pub fn prior() {}", "src/replaced.rs")
            .expect("prior facts");
        let replacement = RustExtractor
            .extract("pub fn replacement() {}", "src/replaced.rs")
            .expect("replacement facts");
        let added = RustExtractor
            .extract("pub fn added() {}", "src/added.rs")
            .expect("added facts");
        let mut graph = IncrementalGraph::from_files(&[old, prior])
            .into_tracked(ScopeSnapshotToken::new([4; 32]));
        let before = graph.graph();
        let delta = graph
            .apply_batch_with_delta(
                &[
                    FileChange::Upsert(&replacement),
                    FileChange::Remove("src/old.rs"),
                    FileChange::Upsert(&added),
                ],
                ScopeSnapshotToken::new([5; 32]),
            )
            .expect("mixed transition");
        let after = graph.graph();

        assert_delta_parity(&before, &after, &delta);
        assert_sorted(&delta);
        assert!(
            delta
                .removed_symbols
                .iter()
                .any(|id| id.leaf_name() == Some("old"))
        );
        assert!(
            delta
                .upserted_symbols
                .iter()
                .any(|s| s.name == "replacement")
        );
        assert!(delta.upserted_symbols.iter().any(|s| s.name == "added"));
    }

    #[test]
    fn unchanged_caller_tracks_unique_ambiguous_unique_provider_transitions() {
        let consumer = RustExtractor
            .extract("pub fn run() { a::process() }", "src/consumer.rs")
            .expect("consumer facts");
        let first = RustExtractor
            .extract("pub fn process() {}", "src/a.rs")
            .expect("first provider");
        let second = RustExtractor
            .extract("pub fn process() {}", "src/other/a.rs")
            .expect("second provider");
        let mut graph = IncrementalGraph::from_files(&[consumer, first])
            .into_tracked(ScopeSnapshotToken::new([6; 32]));

        let before_ambiguous = graph.graph();
        let ambiguous = graph
            .apply_batch_with_delta(
                &[FileChange::Upsert(&second)],
                ScopeSnapshotToken::new([7; 32]),
            )
            .expect("make ambiguous");
        let after_ambiguous = graph.graph();
        assert_delta_parity(&before_ambiguous, &after_ambiguous, &ambiguous);
        assert!(
            ambiguous.removed_edges.iter().any(|key| {
                key.role == RefRole::Call && key.occurrence_file == "src/consumer.rs"
            })
        );

        let before_unique = graph.graph();
        let unique = graph
            .apply_batch_with_delta(
                &[FileChange::Remove("src/other/a.rs")],
                ScopeSnapshotToken::new([8; 32]),
            )
            .expect("restore uniqueness");
        let after_unique = graph.graph();
        assert_delta_parity(&before_unique, &after_unique, &unique);
        assert!(
            unique
                .upserted_edges
                .iter()
                .any(|edge| { edge.role == RefRole::Call && edge.occ.file == "src/consumer.rs" })
        );
    }

    #[test]
    fn unchanged_module_and_typeref_callers_are_selectively_restitched() {
        let module_consumer = RustExtractor
            .extract("mod util;\npub fn run() {}", "src/lib.rs")
            .expect("module consumer");
        let type_consumer = RustExtractor
            .extract("pub struct Order { value: Config }", "src/order.rs")
            .expect("type consumer");
        let ordinary = RustExtractor
            .extract("pub struct Config {}", "src/types.rs")
            .expect("ordinary Config");
        let util = RustExtractor
            .extract("pub fn helper() {}", "src/util.rs")
            .expect("util module");
        let config_module = RustExtractor
            .extract("", "src/Config.rs")
            .expect("Config module");
        let mut graph = IncrementalGraph::from_files(&[module_consumer, type_consumer, ordinary])
            .into_tracked(ScopeSnapshotToken::new([9; 32]));
        let before = graph.graph();
        let delta = graph
            .apply_batch_with_delta(
                &[
                    FileChange::Upsert(&util),
                    FileChange::Upsert(&config_module),
                ],
                ScopeSnapshotToken::new([10; 32]),
            )
            .expect("add preferred targets");
        let after = graph.graph();

        assert_delta_parity(&before, &after, &delta);
        assert!(
            delta
                .upserted_edges
                .iter()
                .any(|edge| { edge.role == RefRole::ModuleRef && edge.occ.file == "src/lib.rs" })
        );
        assert!(
            !delta.removed_edges.iter().any(|key| {
                key.role == RefRole::TypeRef && key.occurrence_file == "src/order.rs"
            }),
            "a same-named module must not change a type annotation edge"
        );
        assert!(
            !delta
                .upserted_edges
                .iter()
                .any(|edge| { edge.role == RefRole::TypeRef && edge.occ.file == "src/order.rs" }),
            "the existing type-definition edge remains stable"
        );
    }

    #[test]
    fn provider_delete_and_rename_remove_unchanged_cross_file_caller_edge() {
        let consumer = RustExtractor
            .extract(
                "use provider::helper;\npub fn run() { helper(); }",
                "src/consumer.rs",
            )
            .expect("consumer facts");
        let provider = RustExtractor
            .extract("pub fn helper() {}", "src/provider.rs")
            .expect("provider facts");
        let renamed = RustExtractor
            .extract("pub fn renamed() {}", "src/provider.rs")
            .expect("renamed provider");
        let mut graph = IncrementalGraph::from_files(&[consumer, provider])
            .into_tracked(ScopeSnapshotToken::new([11; 32]));
        let before = graph.graph();
        let delta = graph
            .apply_batch_with_delta(
                &[FileChange::Upsert(&renamed)],
                ScopeSnapshotToken::new([12; 32]),
            )
            .expect("rename provider");
        assert_delta_parity(&before, &graph.graph(), &delta);
        assert!(
            delta
                .removed_symbols
                .iter()
                .any(|id| id.leaf_name() == Some("helper"))
        );
        assert!(
            delta
                .upserted_symbols
                .iter()
                .any(|symbol| symbol.name == "renamed")
        );
        assert!(
            delta.removed_edges.iter().any(|key| {
                key.role == RefRole::Call && key.occurrence_file == "src/consumer.rs"
            })
        );

        let before_delete = graph.graph();
        let deleted = graph
            .apply_batch_with_delta(
                &[FileChange::Remove("src/provider.rs")],
                ScopeSnapshotToken::new([13; 32]),
            )
            .expect("delete provider");
        assert_delta_parity(&before_delete, &graph.graph(), &deleted);
        assert!(
            deleted
                .removed_symbols
                .iter()
                .any(|id| id.leaf_name() == Some("renamed"))
        );
    }

    #[test]
    fn symbol_and_edge_payload_changes_are_upserts_and_confidence_is_not_edge_identity() {
        let consumer = RustExtractor
            .extract("pub fn run() { a::process() }", "src/consumer.rs")
            .expect("consumer facts");
        let provider = RustExtractor
            .extract("pub fn process() {}", "src/a.rs")
            .expect("provider facts");
        let graph = IncrementalGraph::from_files(&[consumer, provider]).graph();
        let before_symbol = graph
            .symbols
            .iter()
            .find(|symbol| symbol.name == "process")
            .expect("process symbol")
            .clone();
        let mut after_symbol = before_symbol.clone();
        after_symbol.signature.push_str(" changed");
        let before_edge = graph
            .edges
            .iter()
            .find(|edge| edge.role == RefRole::Call)
            .expect("call edge")
            .clone();
        let mut after_edge = before_edge.clone();
        after_edge.confidence = match before_edge.confidence {
            Confidence::Exact => Confidence::Scoped,
            _ => Confidence::Exact,
        };

        let delta = delta_from_bounds(
            ScopeSnapshotToken::new([14; 32]),
            ScopeSnapshotToken::new([15; 32]),
            MutationBounds {
                before_symbols: vec![before_symbol],
                after_symbols: vec![after_symbol.clone()],
                before_edges: vec![before_edge.clone()],
                after_edges: vec![after_edge.clone()],
            },
        );
        assert!(delta.removed_symbols.is_empty());
        assert_eq!(delta.upserted_symbols.len(), 1);
        assert!(same_symbol(&delta.upserted_symbols[0], &after_symbol));
        assert!(delta.removed_edges.is_empty());
        assert_eq!(delta.upserted_edges.len(), 1);
        assert_eq!(before_edge.key(), after_edge.key());
        assert!(same_edge(&delta.upserted_edges[0], &after_edge));
    }

    #[test]
    fn delta_order_is_independent_of_batch_change_order() {
        let alpha = RustExtractor
            .extract("pub fn alpha() {}", "src/alpha.rs")
            .expect("alpha facts");
        let zeta = RustExtractor
            .extract("pub fn zeta() {}", "src/zeta.rs")
            .expect("zeta facts");
        let initial = ScopeSnapshotToken::new([16; 32]);
        let next = ScopeSnapshotToken::new([17; 32]);
        let mut forward = IncrementalGraph::new().into_tracked(initial);
        let mut reverse = IncrementalGraph::new().into_tracked(initial);
        let forward_delta = forward
            .apply_batch_with_delta(
                &[FileChange::Upsert(&zeta), FileChange::Upsert(&alpha)],
                next,
            )
            .expect("forward batch");
        let reverse_delta = reverse
            .apply_batch_with_delta(
                &[FileChange::Upsert(&alpha), FileChange::Upsert(&zeta)],
                next,
            )
            .expect("reverse batch");

        assert_sorted(&forward_delta);
        assert_sorted(&reverse_delta);
        assert_eq!(forward_delta.removed_symbols, reverse_delta.removed_symbols);
        assert_eq!(forward_delta.removed_edges, reverse_delta.removed_edges);
        assert_eq!(
            forward_delta
                .upserted_symbols
                .iter()
                .map(|symbol| &symbol.id)
                .collect::<Vec<_>>(),
            reverse_delta
                .upserted_symbols
                .iter()
                .map(|symbol| &symbol.id)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            forward_delta
                .upserted_edges
                .iter()
                .map(Edge::key)
                .collect::<Vec<_>>(),
            reverse_delta
                .upserted_edges
                .iter()
                .map(Edge::key)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn malformed_later_change_preserves_graph_and_lineage() {
        let facts = RustExtractor
            .extract("pub fn provider() {}", "src/provider.rs")
            .expect("provider facts");
        let mut graph =
            IncrementalGraph::from_files(&[facts]).into_tracked(ScopeSnapshotToken::new([18; 32]));
        let before = format!("{:?}", graph.graph());
        let token = graph.snapshot();
        let invalid = crate::FileFacts {
            file: "src/bad.rs".into(),
            lang: "rust".into(),
            symbols: Vec::new(),
            references: Vec::new(),
            scopes: vec![crate::Scope {
                parent: Some(4),
                kind: crate::ScopeKind::Module,
                span: crate::ByteSpan { start: 0, end: 0 },
            }],
            bindings: Vec::new(),
            ffi_exports: Vec::new(),
        };

        assert!(
            graph
                .apply_batch_with_delta(
                    &[
                        FileChange::Remove("src/provider.rs"),
                        FileChange::Upsert(&invalid),
                    ],
                    ScopeSnapshotToken::new([19; 32]),
                )
                .is_err()
        );
        assert_eq!(graph.snapshot(), token);
        assert_eq!(format!("{:?}", graph.graph()), before);
    }

    #[test]
    fn duplicate_target_preserves_graph_and_lineage() {
        let facts = RustExtractor
            .extract("pub fn provider() {}", "src/provider.rs")
            .expect("provider facts");
        let replacement = RustExtractor
            .extract("pub fn replacement() {}", "src/provider.rs")
            .expect("replacement facts");
        let mut graph =
            IncrementalGraph::from_files(&[facts]).into_tracked(ScopeSnapshotToken::new([20; 32]));
        let before = format!("{:?}", graph.graph());
        let token = graph.snapshot();

        assert!(
            graph
                .apply_batch_with_delta(
                    &[
                        FileChange::Upsert(&replacement),
                        FileChange::Remove("src/provider.rs"),
                    ],
                    ScopeSnapshotToken::new([21; 32]),
                )
                .is_err()
        );
        assert_eq!(graph.snapshot(), token);
        assert_eq!(format!("{:?}", graph.graph()), before);
    }
}
