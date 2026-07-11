// SPDX-License-Identifier: Apache-2.0

//! Atomic application of tracked scope-graph snapshot deltas.

use std::collections::BTreeSet;

use code2graph::{CodeGraph, EdgeKey, ScopeGraphDelta};

use crate::{QueryError, Result};

use super::GraphIndex;

impl GraphIndex {
    /// Return the tracked scope snapshot, if this index is lineage-aware.
    pub fn scope_snapshot(&self) -> Option<code2graph::ScopeSnapshotToken> {
        self.snapshot
    }

    /// Apply a complete scope-graph delta atomically.
    ///
    /// This operation is available only on indexes constructed with
    /// [`Self::from_scope_graph`]. The complete delta is checked before a
    /// replacement index is built and swapped in, so an error leaves both facts
    /// and snapshot lineage unchanged.
    pub fn apply_scope_delta(&mut self, delta: &ScopeGraphDelta) -> Result<()> {
        let current = self
            .snapshot
            .ok_or(QueryError::ScopeDeltaRequiresTrackedIndex)?;
        if delta.base_snapshot != current {
            return Err(QueryError::SnapshotMismatch {
                expected: current,
                actual: delta.base_snapshot,
            });
        }
        if delta.snapshot == current {
            return Err(QueryError::ScopeDeltaSnapshotDoesNotAdvance);
        }
        validate_symbols(self, delta)?;
        validate_edges(self, delta)?;

        let mut symbols = self.definitions.clone();
        for id in &delta.removed_symbols {
            symbols.remove(id);
        }
        for symbol in &delta.upserted_symbols {
            symbols.insert(symbol.id.clone(), symbol.clone());
        }

        let mut edges = self.edges.clone();
        for key in &delta.removed_edges {
            edges.remove(key);
        }
        for edge in &delta.upserted_edges {
            edges.insert(edge.key(), edge.clone());
        }

        // Rebuilding is deliberately the commit preparation step: it reconciles
        // every derived index and endpoint-only identity from the final facts.
        let replacement = Self::from_scope_graph(
            CodeGraph {
                symbols: symbols.into_values().collect(),
                edges: edges.into_values().collect(),
            },
            delta.snapshot,
        )?;
        *self = replacement;
        Ok(())
    }
}

fn validate_symbols(index: &GraphIndex, delta: &ScopeGraphDelta) -> Result<()> {
    let mut removed = BTreeSet::new();
    for id in &delta.removed_symbols {
        if !removed.insert(id.clone()) {
            return Err(QueryError::DuplicateRemovedSymbol(id.clone()));
        }
        if !index.definitions.contains_key(id) {
            return Err(QueryError::MissingRemovedSymbol(id.clone()));
        }
    }

    let mut upserted = BTreeSet::new();
    for symbol in &delta.upserted_symbols {
        if !upserted.insert(symbol.id.clone()) {
            return Err(QueryError::DuplicateUpsertedSymbol(symbol.id.clone()));
        }
    }
    Ok(())
}

fn validate_edges(index: &GraphIndex, delta: &ScopeGraphDelta) -> Result<()> {
    let mut removed = BTreeSet::new();
    for key in &delta.removed_edges {
        if !removed.insert(key.clone()) {
            return Err(QueryError::DuplicateRemovedEdge(key.clone()));
        }
        if !index.edges.contains_key(key) {
            return Err(QueryError::MissingRemovedEdge(key.clone()));
        }
    }

    let mut upserted = BTreeSet::<EdgeKey>::new();
    for edge in &delta.upserted_edges {
        let key = edge.key();
        if !upserted.insert(key.clone()) {
            return Err(QueryError::DuplicateUpsertedEdge(key));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use code2graph::{
        ByteSpan, CodeGraph, Confidence, Descriptor, Edge, Extractor, FileChange, FileFacts,
        IncrementalGraph, Occurrence, Provenance, RefRole, ScopeGraphDelta, ScopeSnapshotToken,
        Symbol, SymbolId, SymbolKind, Visibility, extract::RustExtractor,
    };

    use crate::{EdgeFilter, GraphIndex, ImpactOptions, QueryError};

    fn token(byte: u8) -> ScopeSnapshotToken {
        ScopeSnapshotToken::new([byte; 32])
    }

    fn id(name: &str) -> SymbolId {
        SymbolId::global(
            "rust",
            vec![
                Descriptor::Namespace("pkg".into()),
                Descriptor::Term(name.into()),
            ],
        )
    }

    fn symbol(id: SymbolId, name: &str) -> Symbol {
        Symbol {
            id,
            name: name.into(),
            kind: SymbolKind::Function,
            visibility: Visibility::Public,
            entry_points: Vec::new(),
            file: "src/lib.rs".into(),
            line: 1,
            span: ByteSpan { start: 0, end: 1 },
            signature: format!("fn {name}()"),
        }
    }

    fn edge(from: SymbolId, to: SymbolId, confidence: Confidence) -> Edge {
        Edge {
            from,
            to,
            role: RefRole::Call,
            confidence,
            provenance: Provenance::ScopeGraph,
            occ: Occurrence {
                file: "src/lib.rs".into(),
                line: 1,
                col: 0,
                byte: 0,
            },
        }
    }

    fn delta(base: u8, snapshot: u8) -> ScopeGraphDelta {
        ScopeGraphDelta {
            base_snapshot: token(base),
            snapshot: token(snapshot),
            removed_symbols: Vec::new(),
            upserted_symbols: Vec::new(),
            removed_edges: Vec::new(),
            upserted_edges: Vec::new(),
        }
    }

    #[test]
    fn enforces_exact_base_lineage_and_rejects_repeated_transitions() {
        let a = id("a");
        let graph = CodeGraph {
            symbols: vec![symbol(a.clone(), "a")],
            edges: vec![],
        };
        let mut untracked = GraphIndex::from_graph(graph.clone()).expect("valid graph");
        assert!(matches!(
            untracked.apply_scope_delta(&delta(1, 2)),
            Err(QueryError::ScopeDeltaRequiresTrackedIndex)
        ));

        let mut tracked = GraphIndex::from_scope_graph(graph, token(1)).expect("valid graph");
        assert!(matches!(
            tracked.apply_scope_delta(&delta(2, 3)),
            Err(QueryError::SnapshotMismatch { .. })
        ));
        assert_eq!(tracked.scope_snapshot(), Some(token(1)));

        let before = format!("{tracked:?}");
        let mut same_token = delta(1, 1);
        same_token.upserted_symbols.push(symbol(id("new"), "new"));
        assert!(matches!(
            tracked.apply_scope_delta(&same_token),
            Err(QueryError::ScopeDeltaSnapshotDoesNotAdvance)
        ));
        assert_eq!(format!("{tracked:?}"), before);
        assert_eq!(tracked.scope_snapshot(), Some(token(1)));
        assert!(tracked.symbol(&id("new")).is_none());

        // Opaque tokens need not be sequential, but every accepted transition
        // must produce a distinct result token.
        let normal = delta(1, 3);
        tracked
            .apply_scope_delta(&normal)
            .expect("distinct opaque result token");
        assert_eq!(tracked.scope_snapshot(), Some(token(3)));
        assert!(matches!(
            tracked.apply_scope_delta(&normal),
            Err(QueryError::SnapshotMismatch {
                expected,
                actual
            }) if expected == token(3) && actual == token(1)
        ));

        for invalid in [delta(1, 4), delta(4, 5)] {
            assert!(matches!(
                tracked.apply_scope_delta(&invalid),
                Err(QueryError::SnapshotMismatch { .. })
            ));
            assert_eq!(tracked.scope_snapshot(), Some(token(3)));
            assert!(tracked.symbol(&a).is_some());
        }
    }

    #[test]
    fn validates_duplicates_and_missing_removals_atomically() {
        let a = id("a");
        let existing = edge(a.clone(), id("external"), Confidence::Scoped);
        let mut index = GraphIndex::from_scope_graph(
            CodeGraph {
                symbols: vec![symbol(a.clone(), "a")],
                edges: vec![existing.clone()],
            },
            token(1),
        )
        .expect("valid graph");
        let before = format!("{index:?}");
        let mut duplicate = delta(1, 2);
        duplicate.removed_symbols = vec![a.clone(), a.clone()];
        assert!(matches!(
            index.apply_scope_delta(&duplicate),
            Err(QueryError::DuplicateRemovedSymbol(_))
        ));
        assert!(index.symbol(&a).is_some());

        let mut missing_symbol = delta(1, 2);
        missing_symbol.removed_symbols = vec![id("missing")];
        assert!(matches!(
            index.apply_scope_delta(&missing_symbol),
            Err(QueryError::MissingRemovedSymbol(_))
        ));

        let mut duplicate_symbol_upsert = delta(1, 2);
        duplicate_symbol_upsert.upserted_symbols =
            vec![symbol(id("new"), "new"), symbol(id("new"), "replacement")];
        assert!(matches!(
            index.apply_scope_delta(&duplicate_symbol_upsert),
            Err(QueryError::DuplicateUpsertedSymbol(_))
        ));

        let mut missing_edge = delta(1, 2);
        missing_edge.removed_edges =
            vec![edge(id("other"), id("missing"), Confidence::Exact).key()];
        assert!(matches!(
            index.apply_scope_delta(&missing_edge),
            Err(QueryError::MissingRemovedEdge(_))
        ));

        let mut duplicate_edge_removal = delta(1, 2);
        duplicate_edge_removal.removed_edges = vec![existing.key(), existing.key()];
        assert!(matches!(
            index.apply_scope_delta(&duplicate_edge_removal),
            Err(QueryError::DuplicateRemovedEdge(_))
        ));

        let mut duplicate_edge_upsert = delta(1, 2);
        duplicate_edge_upsert.upserted_edges = vec![existing.clone(), existing];
        assert!(matches!(
            index.apply_scope_delta(&duplicate_edge_upsert),
            Err(QueryError::DuplicateUpsertedEdge(_))
        ));

        assert_eq!(format!("{index:?}"), before);
        assert_eq!(index.scope_snapshot(), Some(token(1)));
        assert!(index.symbol(&a).is_some());
        assert_eq!(
            index
                .outgoing(&a, EdgeFilter::new(Confidence::Heuristic))
                .len(),
            1
        );
        index
            .apply_scope_delta(&delta(1, 2))
            .expect("failures did not advance snapshot");
        assert_eq!(index.scope_snapshot(), Some(token(2)));
    }

    #[test]
    fn replacement_upserts_reconcile_indexes_and_endpoint_only_ids() {
        let a = id("a");
        let endpoint = SymbolId::local("vendor/api.rs", "remote");
        let relation = edge(a.clone(), endpoint.clone(), Confidence::Scoped);
        let mut index = GraphIndex::from_scope_graph(
            CodeGraph {
                symbols: vec![symbol(a.clone(), "a")],
                edges: vec![],
            },
            token(1),
        )
        .expect("valid graph");

        let mut add = delta(1, 2);
        add.upserted_edges.push(relation.clone());
        index.apply_scope_delta(&add).expect("edge insertion");
        assert!(index.contains_id(&endpoint));
        assert_eq!(
            index
                .outgoing(&a, EdgeFilter::new(Confidence::Heuristic))
                .len(),
            1
        );

        let mut replace = delta(2, 3);
        replace.removed_symbols.push(a.clone());
        replace.upserted_symbols.push(symbol(a.clone(), "renamed"));
        // Removing and upserting the same structural key is a valid payload
        // replacement; EdgeKey deliberately excludes confidence.
        replace.removed_edges.push(relation.key());
        replace
            .upserted_edges
            .push(edge(a.clone(), endpoint.clone(), Confidence::Exact));
        index
            .apply_scope_delta(&replace)
            .expect("replacement upserts");
        assert!(index.symbols_named("a").is_empty());
        assert_eq!(index.symbols_named("renamed").len(), 1);
        assert_eq!(
            index.outgoing(&a, EdgeFilter::new(Confidence::Exact)).len(),
            1
        );

        let mut remove = delta(3, 4);
        remove.removed_edges.push(relation.key());
        index.apply_scope_delta(&remove).expect("edge removal");
        assert!(!index.contains_id(&endpoint));
        assert!(index.ids_with_scip(&endpoint.to_scip_string()).is_empty());
        assert!(
            index
                .incoming(&endpoint, EdgeFilter::new(Confidence::Heuristic))
                .is_empty()
        );
        assert!(
            index
                .outgoing(&endpoint, EdgeFilter::new(Confidence::Heuristic))
                .is_empty()
        );
    }

    fn assert_query_parity(left: &GraphIndex, right: &GraphIndex) {
        assert_eq!(
            left.definitions.keys().collect::<Vec<_>>(),
            right.definitions.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            left.edges.keys().collect::<Vec<_>>(),
            right.edges.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            format!("{:?}", left.definitions),
            format!("{:?}", right.definitions)
        );
        assert_eq!(format!("{:?}", left.edges), format!("{:?}", right.edges));
        assert_eq!(left.known_ids, right.known_ids);
        assert_eq!(left.definitions_by_name, right.definitions_by_name);
        assert_eq!(left.ids_by_scip, right.ids_by_scip);
        assert_eq!(left.definitions_by_scip, right.definitions_by_scip);
        assert_eq!(left.definitions_by_file, right.definitions_by_file);

        let filter = EdgeFilter::new(Confidence::Heuristic);
        for id in &right.known_ids {
            assert_eq!(left.contains_id(id), right.contains_id(id));
            assert_eq!(
                format!("{:?}", left.symbol(id)),
                format!("{:?}", right.symbol(id))
            );
            assert_eq!(
                left.outgoing(id, filter)
                    .iter()
                    .map(|edge| (edge.key(), edge.confidence))
                    .collect::<Vec<_>>(),
                right
                    .outgoing(id, filter)
                    .iter()
                    .map(|edge| (edge.key(), edge.confidence))
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                left.incoming(id, filter)
                    .iter()
                    .map(|edge| (edge.key(), edge.confidence))
                    .collect::<Vec<_>>(),
                right
                    .incoming(id, filter)
                    .iter()
                    .map(|edge| (edge.key(), edge.confidence))
                    .collect::<Vec<_>>()
            );
            let options = ImpactOptions {
                filter,
                max_depth: 16,
                max_nodes: usize::MAX,
            };
            let left_impact = left.impact(id, options);
            let right_impact = right.impact(id, options);
            assert_eq!(left_impact.truncated, right_impact.truncated);
            assert_eq!(
                left_impact
                    .steps
                    .iter()
                    .map(|step| {
                        (
                            &step.symbol,
                            &step.parent,
                            step.via.key(),
                            step.depth,
                            step.path_confidence,
                        )
                    })
                    .collect::<Vec<_>>(),
                right_impact
                    .steps
                    .iter()
                    .map(|step| {
                        (
                            &step.symbol,
                            &step.parent,
                            step.via.key(),
                            step.depth,
                            step.path_confidence,
                        )
                    })
                    .collect::<Vec<_>>()
            );
        }

        for (name, ids) in &right.definitions_by_name {
            assert_eq!(
                left.symbols_named(name)
                    .iter()
                    .map(|symbol| &symbol.id)
                    .collect::<Vec<_>>(),
                ids.iter().collect::<Vec<_>>()
            );
        }
        for (scip, ids) in &right.ids_by_scip {
            assert_eq!(left.ids_with_scip(scip), ids.iter().collect::<Vec<_>>());
            assert_eq!(
                left.symbols_with_scip(scip)
                    .iter()
                    .map(|symbol| &symbol.id)
                    .collect::<Vec<_>>(),
                right
                    .symbols_with_scip(scip)
                    .iter()
                    .map(|symbol| &symbol.id)
                    .collect::<Vec<_>>()
            );
        }
        for (file, ids) in &right.definitions_by_file {
            assert_eq!(
                left.symbols_in_file(file)
                    .iter()
                    .map(|symbol| &symbol.id)
                    .collect::<Vec<_>>(),
                ids.iter().collect::<Vec<_>>()
            );
            for id in ids {
                let symbol = right.symbol(id).expect("definition indexed by file");
                if !symbol.span.is_empty() {
                    assert_eq!(
                        left.symbol_at_byte(file, symbol.span.start)
                            .map(|found| &found.id),
                        right
                            .symbol_at_byte(file, symbol.span.start)
                            .map(|found| &found.id)
                    );
                }
            }
        }
    }

    #[test]
    fn real_tracked_delta_matches_a_rebuilt_index_across_query_surfaces() {
        let consumer = RustExtractor
            .extract(
                "use provider::helper;\npub fn run() { helper(); helper(); }",
                "src/consumer.rs",
            )
            .expect("initial consumer facts");
        let provider = RustExtractor
            .extract("pub fn helper() {}", "src/provider.rs")
            .expect("initial provider facts");
        let obsolete = RustExtractor
            .extract("pub fn obsolete() {}", "src/obsolete.rs")
            .expect("obsolete facts");
        let rust_collision = id("collision");
        let python_collision = SymbolId::global(
            "python",
            vec![
                Descriptor::Namespace("pkg".into()),
                Descriptor::Term("collision".into()),
            ],
        );
        let collision_facts = FileFacts {
            file: "src/collisions.rs".into(),
            lang: "rust".into(),
            symbols: vec![
                symbol(rust_collision.clone(), "collision"),
                symbol(python_collision.clone(), "collision"),
            ],
            references: Vec::new(),
            scopes: Vec::new(),
            bindings: Vec::new(),
            ffi_exports: Vec::new(),
        };
        let initial = token(21);
        let mut tracked =
            IncrementalGraph::from_files(&[consumer, provider, obsolete, collision_facts])
                .into_tracked(initial);
        let mut incremental =
            GraphIndex::from_scope_graph(tracked.graph(), initial).expect("initial index");

        let replacement_consumer = RustExtractor
            .extract(
                "use provider::helper;\npub fn run() { helper(); helper(); }\npub fn second() { helper(); }",
                "src/consumer.rs",
            )
            .expect("replacement consumer facts");
        let replacement_provider = RustExtractor
            .extract(
                "pub fn helper() { let _changed = true; }\npub fn added() {}",
                "src/provider.rs",
            )
            .expect("replacement provider facts");
        let next = token(22);
        let delta = tracked
            .apply_batch_with_delta(
                &[
                    FileChange::Upsert(&replacement_consumer),
                    FileChange::Upsert(&replacement_provider),
                    FileChange::Remove("src/obsolete.rs"),
                ],
                next,
            )
            .expect("real core delta");
        incremental
            .apply_scope_delta(&delta)
            .expect("atomic query update");
        let rebuilt = GraphIndex::from_scope_graph(tracked.graph(), next).expect("rebuilt index");

        assert_query_parity(&incremental, &rebuilt);
        assert_eq!(incremental.scope_snapshot(), Some(next));
        let collision_display = rust_collision.to_scip_string();
        assert_eq!(collision_display, python_collision.to_scip_string());
        assert_eq!(
            incremental.ids_with_scip(&collision_display),
            vec![&python_collision, &rust_collision]
        );
        let run = incremental.symbols_named("run")[0];
        let helper = incremental.symbols_named("helper")[0];
        let parallel = incremental
            .outgoing(&run.id, EdgeFilter::new(Confidence::Heuristic))
            .into_iter()
            .filter(|edge| edge.to == helper.id && edge.role == RefRole::Call)
            .collect::<Vec<_>>();
        assert_eq!(
            parallel.len(),
            2,
            "lossless occurrence keys retain parallel calls"
        );
        assert_ne!(parallel[0].key(), parallel[1].key());
    }
}
