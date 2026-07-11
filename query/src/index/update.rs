// SPDX-License-Identifier: Apache-2.0

//! Atomic application of tracked scope-graph snapshot deltas.

use std::collections::{BTreeMap, BTreeSet};

use code2graph::{Edge, EdgeKey, ScopeGraphDelta, Symbol, SymbolId};

use crate::{QueryError, Result, order};

use super::GraphIndex;

impl GraphIndex {
    /// Return the tracked scope snapshot, if this index is lineage-aware.
    pub fn scope_snapshot(&self) -> Option<code2graph::ScopeSnapshotToken> {
        self.snapshot
    }

    /// Apply a complete scope-graph delta atomically.
    ///
    /// This operation is available only on indexes constructed with
    /// [`Self::from_scope_graph`]. The complete delta is checked, then applied
    /// to a clone and swapped in only after every affected bucket is updated.
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

        let mut replacement = self.clone();
        for id in &delta.removed_symbols {
            remove_symbol(&mut replacement, id)?;
        }
        for key in &delta.removed_edges {
            remove_edge(&mut replacement, key)?;
        }
        for symbol in &delta.upserted_symbols {
            upsert_symbol(&mut replacement, symbol.clone())?;
        }
        for edge in &delta.upserted_edges {
            upsert_edge(&mut replacement, edge.clone())?;
        }
        replacement.snapshot = Some(delta.snapshot);
        *self = replacement;
        Ok(())
    }
}

fn upsert_symbol(index: &mut GraphIndex, symbol: Symbol) -> Result<()> {
    if index.definitions.contains_key(&symbol.id) {
        remove_symbol(index, &symbol.id)?;
    }
    ensure_known(index, &symbol.id)?;
    insert_sorted(
        index
            .definitions_by_name
            .entry(symbol.name.clone())
            .or_default(),
        symbol.id.clone(),
        order::cmp_symbol_ids,
    )?;
    insert_sorted(
        index
            .definitions_by_scip
            .entry(symbol.id.to_scip_string())
            .or_default(),
        symbol.id.clone(),
        order::cmp_symbol_ids,
    )?;
    insert_sorted(
        index
            .definitions_by_file
            .entry(symbol.file.clone())
            .or_default(),
        symbol.id.clone(),
        order::cmp_symbol_ids,
    )?;
    index.definitions.insert(symbol.id.clone(), symbol);
    Ok(())
}

fn remove_symbol(index: &mut GraphIndex, id: &SymbolId) -> Result<()> {
    let symbol = index.definitions.remove(id).ok_or_else(|| {
        QueryError::IndexInvariant(format!("missing definition while removing {id}"))
    })?;
    remove_sorted_bucket(
        &mut index.definitions_by_name,
        &symbol.name,
        id,
        order::cmp_symbol_ids,
    )?;
    remove_sorted_bucket(
        &mut index.definitions_by_scip,
        &id.to_scip_string(),
        id,
        order::cmp_symbol_ids,
    )?;
    remove_sorted_bucket(
        &mut index.definitions_by_file,
        &symbol.file,
        id,
        order::cmp_symbol_ids,
    )?;
    remove_known_if_unreferenced(index, id)
}

fn upsert_edge(index: &mut GraphIndex, edge: Edge) -> Result<()> {
    let key = edge.key();
    if let Some(existing) = index.edges.get_mut(&key) {
        *existing = edge;
        return Ok(());
    }
    add_endpoint(index, &edge.from)?;
    add_endpoint(index, &edge.to)?;
    insert_sorted(
        index.outgoing.entry(edge.from.clone()).or_default(),
        key.clone(),
        order::cmp_edge_keys,
    )?;
    insert_sorted(
        index.incoming.entry(edge.to.clone()).or_default(),
        key.clone(),
        order::cmp_edge_keys,
    )?;
    index.edges.insert(key, edge);
    Ok(())
}

fn remove_edge(index: &mut GraphIndex, key: &EdgeKey) -> Result<()> {
    let edge = index.edges.remove(key).ok_or_else(|| {
        QueryError::IndexInvariant(format!("missing edge while removing {key:?}"))
    })?;
    remove_sorted_bucket(&mut index.outgoing, &edge.from, key, order::cmp_edge_keys)?;
    remove_sorted_bucket(&mut index.incoming, &edge.to, key, order::cmp_edge_keys)?;
    remove_endpoint(index, &edge.from)?;
    remove_endpoint(index, &edge.to)
}

fn ensure_known(index: &mut GraphIndex, id: &SymbolId) -> Result<()> {
    if index.known_ids.insert(id.clone()) {
        insert_sorted(
            index.ids_by_scip.entry(id.to_scip_string()).or_default(),
            id.clone(),
            order::cmp_symbol_ids,
        )?;
    }
    Ok(())
}

fn add_endpoint(index: &mut GraphIndex, id: &SymbolId) -> Result<()> {
    let count = index.endpoint_refcounts.entry(id.clone()).or_default();
    *count = count.checked_add(1).ok_or_else(|| {
        QueryError::IndexInvariant(format!("endpoint reference count overflow for {id}"))
    })?;
    ensure_known(index, id)
}

fn remove_endpoint(index: &mut GraphIndex, id: &SymbolId) -> Result<()> {
    let remove_count = {
        let count = index.endpoint_refcounts.get_mut(id).ok_or_else(|| {
            QueryError::IndexInvariant(format!("endpoint reference count missing for {id}"))
        })?;
        *count = count.checked_sub(1).ok_or_else(|| {
            QueryError::IndexInvariant(format!("endpoint reference count underflow for {id}"))
        })?;
        *count == 0
    };
    if remove_count {
        index.endpoint_refcounts.remove(id);
        remove_known_if_unreferenced(index, id)?;
    }
    Ok(())
}

fn remove_known_if_unreferenced(index: &mut GraphIndex, id: &SymbolId) -> Result<()> {
    if index.definitions.contains_key(id) || index.endpoint_refcounts.contains_key(id) {
        return Ok(());
    }
    if !index.known_ids.remove(id) {
        return Err(QueryError::IndexInvariant(format!(
            "known id missing for {id}"
        )));
    }
    remove_sorted_bucket(
        &mut index.ids_by_scip,
        &id.to_scip_string(),
        id,
        order::cmp_symbol_ids,
    )
}

fn insert_sorted<T, F>(values: &mut Vec<T>, value: T, compare: F) -> Result<()>
where
    F: Fn(&T, &T) -> std::cmp::Ordering,
{
    match values.binary_search_by(|existing| compare(existing, &value)) {
        Ok(_) => Err(QueryError::IndexInvariant(
            "duplicate secondary index entry".into(),
        )),
        Err(position) => {
            values.insert(position, value);
            Ok(())
        }
    }
}

fn remove_sorted_bucket<K, T, F>(
    buckets: &mut BTreeMap<K, Vec<T>>,
    bucket: &K,
    value: &T,
    compare: F,
) -> Result<()>
where
    K: Ord,
    F: Fn(&T, &T) -> std::cmp::Ordering,
{
    let remove_bucket = {
        let values = buckets
            .get_mut(bucket)
            .ok_or_else(|| QueryError::IndexInvariant("missing secondary index bucket".into()))?;
        let position = values
            .binary_search_by(|existing| compare(existing, value))
            .map_err(|_| QueryError::IndexInvariant("missing secondary index entry".into()))?;
        values.remove(position);
        values.is_empty()
    };
    if remove_bucket {
        buckets.remove(bucket);
    }
    Ok(())
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

        // Opaque tokens need not be sequential, but this consumer requires a
        // distinct result token so replayed transitions cannot appear valid.
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
        assert_eq!(left.endpoint_refcounts, right.endpoint_refcounts);
        assert_eq!(left.definitions_by_name, right.definitions_by_name);
        assert_eq!(left.ids_by_scip, right.ids_by_scip);
        assert_eq!(left.definitions_by_scip, right.definitions_by_scip);
        assert_eq!(left.definitions_by_file, right.definitions_by_file);
        assert_eq!(left.outgoing, right.outgoing);
        assert_eq!(left.incoming, right.incoming);
        assert_eq!(left.snapshot, right.snapshot);

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
    fn incremental_mutation_matches_rebuild_for_secondary_buckets_and_self_edges() {
        let a = id("a");
        let b = id("b");
        let external = id("external");
        let added = id("added");
        let old_relation = edge(a.clone(), external.clone(), Confidence::Scoped);
        let self_relation = edge(b.clone(), b.clone(), Confidence::NameOnly);
        let added_relation = edge(b.clone(), added.clone(), Confidence::Scoped);
        let initial_graph = CodeGraph {
            symbols: vec![symbol(a.clone(), "a"), symbol(b.clone(), "b")],
            edges: vec![old_relation.clone(), self_relation.clone()],
        };
        let mut incremental =
            GraphIndex::from_scope_graph(initial_graph.clone(), token(40)).expect("initial index");

        let mut renamed = symbol(a.clone(), "renamed");
        renamed.file = "src/renamed.rs".into();
        let mut first = delta(40, 41);
        first.upserted_symbols.push(renamed.clone());
        first.removed_edges.push(old_relation.key());
        first
            .upserted_edges
            .push(edge(a.clone(), external.clone(), Confidence::Exact));
        first
            .upserted_edges
            .push(edge(b.clone(), b.clone(), Confidence::Exact));
        first.upserted_edges.push(added_relation.clone());
        incremental.apply_scope_delta(&first).expect("first update");
        let rebuilt = GraphIndex::from_scope_graph(
            CodeGraph {
                symbols: vec![renamed.clone(), symbol(b.clone(), "b")],
                edges: vec![
                    edge(a.clone(), external.clone(), Confidence::Exact),
                    edge(b.clone(), b.clone(), Confidence::Exact),
                    added_relation.clone(),
                ],
            },
            token(41),
        )
        .expect("rebuilt index");
        assert_query_parity(&incremental, &rebuilt);
        assert_eq!(incremental.endpoint_refcounts[&b], 3);
        assert_eq!(incremental.definitions_by_name["renamed"], vec![a.clone()]);
        assert_eq!(
            incremental.definitions_by_file["src/renamed.rs"],
            vec![a.clone()]
        );
        assert!(!incremental.definitions_by_name.contains_key("a"));

        let mut second = delta(41, 42);
        second.removed_edges = vec![old_relation.key(), added_relation.key()];
        incremental
            .apply_scope_delta(&second)
            .expect("endpoint removal");
        let rebuilt = GraphIndex::from_scope_graph(
            CodeGraph {
                symbols: vec![renamed, symbol(b.clone(), "b")],
                edges: vec![edge(b.clone(), b.clone(), Confidence::Exact)],
            },
            token(42),
        )
        .expect("rebuilt index");
        assert_query_parity(&incremental, &rebuilt);
        assert!(!incremental.contains_id(&external));
        assert!(!incremental.contains_id(&added));
        assert_eq!(incremental.endpoint_refcounts[&b], 2);
    }

    #[test]
    fn deterministic_delta_sequence_matches_rebuild_for_colliding_endpoints_and_moved_symbols() {
        let anchor = id("anchor");
        let old_id = SymbolId::local("src/old.rs", "worker");
        let moved_id = SymbolId::local("src/new.rs", "renamed");
        let rust_endpoint = id("collision");
        let python_endpoint = SymbolId::global(
            "python",
            vec![
                Descriptor::Namespace("pkg".into()),
                Descriptor::Term("collision".into()),
            ],
        );
        assert_eq!(
            rust_endpoint.to_scip_string(),
            python_endpoint.to_scip_string()
        );

        let mut old_symbol = symbol(old_id.clone(), "worker");
        old_symbol.file = "src/old.rs".into();
        let anchor_symbol = symbol(anchor.clone(), "anchor");
        let rust_relation = edge(anchor.clone(), rust_endpoint.clone(), Confidence::Scoped);
        let python_relation = edge(anchor.clone(), python_endpoint.clone(), Confidence::Scoped);
        let old_self = edge(old_id.clone(), old_id.clone(), Confidence::NameOnly);
        let old_endpoint = edge(old_id.clone(), rust_endpoint.clone(), Confidence::NameOnly);
        let initial_graph = CodeGraph {
            symbols: vec![anchor_symbol.clone(), old_symbol],
            edges: vec![
                rust_relation.clone(),
                python_relation.clone(),
                old_self.clone(),
                old_endpoint.clone(),
            ],
        };
        let mut incremental =
            GraphIndex::from_scope_graph(initial_graph, token(50)).expect("initial index");

        let mut moved_symbol = symbol(moved_id.clone(), "renamed");
        moved_symbol.file = "src/new.rs".into();
        let moved_self = edge(moved_id.clone(), moved_id.clone(), Confidence::Exact);
        let moved_endpoint = edge(moved_id.clone(), python_endpoint.clone(), Confidence::Exact);
        let mut replaced_rust_relation = rust_relation.clone();
        replaced_rust_relation.confidence = Confidence::Exact;
        replaced_rust_relation.occ.line = 99;
        replaced_rust_relation.occ.col = 7;
        let mut first = delta(50, 51);
        first.removed_symbols.push(old_id.clone());
        first.upserted_symbols.push(moved_symbol.clone());
        first.removed_edges = vec![old_self.key(), old_endpoint.key()];
        first.upserted_edges = vec![
            replaced_rust_relation.clone(),
            moved_self.clone(),
            moved_endpoint.clone(),
        ];
        incremental
            .apply_scope_delta(&first)
            .expect("move and rename");
        let rebuilt = GraphIndex::from_scope_graph(
            CodeGraph {
                symbols: vec![anchor_symbol.clone(), moved_symbol.clone()],
                edges: vec![
                    replaced_rust_relation.clone(),
                    python_relation.clone(),
                    moved_self.clone(),
                    moved_endpoint.clone(),
                ],
            },
            token(51),
        )
        .expect("first rebuild");
        assert_query_parity(&incremental, &rebuilt);
        assert!(!incremental.contains_id(&old_id));
        assert_eq!(
            incremental.ids_with_scip(&rust_endpoint.to_scip_string()),
            vec![&python_endpoint, &rust_endpoint]
        );
        assert_eq!(
            incremental.outgoing(&anchor, EdgeFilter::new(Confidence::Exact))[0]
                .occ
                .line,
            99,
            "same-key upsert must replace the complete edge payload"
        );

        let mut moved_again = moved_symbol.clone();
        moved_again.name = "renamed_again".into();
        moved_again.file = "src/final.rs".into();
        let mut replaced_python_relation = python_relation.clone();
        replaced_python_relation.confidence = Confidence::Exact;
        let mut second = delta(51, 52);
        second.removed_symbols.push(moved_id.clone());
        second.upserted_symbols.push(moved_again.clone());
        second.removed_edges = vec![rust_relation.key(), python_relation.key()];
        second.upserted_edges.push(replaced_python_relation.clone());
        incremental
            .apply_scope_delta(&second)
            .expect("remove plus upsert replacements");
        let rebuilt = GraphIndex::from_scope_graph(
            CodeGraph {
                symbols: vec![anchor_symbol.clone(), moved_again.clone()],
                edges: vec![
                    replaced_python_relation.clone(),
                    moved_self.clone(),
                    moved_endpoint.clone(),
                ],
            },
            token(52),
        )
        .expect("second rebuild");
        assert_query_parity(&incremental, &rebuilt);
        assert!(!incremental.contains_id(&rust_endpoint));
        assert_eq!(
            incremental.ids_with_scip(&python_endpoint.to_scip_string()),
            vec![&python_endpoint]
        );
        assert!(incremental.symbols_named("renamed").is_empty());
        assert_eq!(incremental.symbols_in_file("src/final.rs").len(), 1);

        let mut third = delta(52, 53);
        third.removed_symbols.push(moved_id.clone());
        third.removed_edges = vec![moved_self.key(), moved_endpoint.key()];
        incremental
            .apply_scope_delta(&third)
            .expect("remove moved definition and its edges");
        let rebuilt = GraphIndex::from_scope_graph(
            CodeGraph {
                symbols: vec![anchor_symbol],
                edges: vec![replaced_python_relation],
            },
            token(53),
        )
        .expect("third rebuild");
        assert_query_parity(&incremental, &rebuilt);
        assert!(!incremental.contains_id(&moved_id));
        assert_eq!(incremental.endpoint_refcounts[&python_endpoint], 1);
    }

    #[test]
    fn endpoint_count_failures_roll_back_every_partial_mutation() {
        let anchor = id("anchor");
        let endpoint = id("endpoint");
        let existing = edge(anchor.clone(), endpoint.clone(), Confidence::Scoped);
        let mut index = GraphIndex::from_scope_graph(
            CodeGraph {
                symbols: vec![symbol(anchor.clone(), "anchor")],
                edges: vec![existing.clone()],
            },
            token(60),
        )
        .expect("initial index");

        index
            .endpoint_refcounts
            .insert(endpoint.clone(), usize::MAX);
        let before_overflow = format!("{index:?}");
        let mut overflow = delta(60, 61);
        overflow
            .upserted_edges
            .push(edge(id("other"), endpoint.clone(), Confidence::Exact));
        assert!(matches!(
            index.apply_scope_delta(&overflow),
            Err(QueryError::IndexInvariant(message))
                if message.contains("endpoint reference count overflow")
        ));
        assert_eq!(format!("{index:?}"), before_overflow);
        assert_eq!(index.scope_snapshot(), Some(token(60)));

        index.endpoint_refcounts.insert(endpoint, 0);
        let before_underflow = format!("{index:?}");
        let mut underflow = delta(60, 61);
        underflow.removed_edges.push(existing.key());
        assert!(matches!(
            index.apply_scope_delta(&underflow),
            Err(QueryError::IndexInvariant(message))
                if message.contains("endpoint reference count underflow")
        ));
        assert_eq!(format!("{index:?}"), before_underflow);
        assert_eq!(index.scope_snapshot(), Some(token(60)));
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
