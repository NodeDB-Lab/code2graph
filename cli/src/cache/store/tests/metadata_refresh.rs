// SPDX-License-Identifier: Apache-2.0

use super::*;

pub(super) struct Fixture {
    pub store: CacheStore,
    _temp: tempfile::TempDir,
}

impl Fixture {
    pub fn new() -> Self {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("project");
        fs::create_dir(&root).expect("project");
        let store =
            CacheStore::open_writable(&location(&root, temp.path()), &root, &Deadline::new(None))
                .expect("open");
        Self { store, _temp: temp }
    }

    pub fn publish(&self, snapshot: &CandidateSnapshot) {
        self.store
            .publish_candidate(snapshot, &Deadline::new(None))
            .expect("publish");
    }

    pub fn metadata(
        &self,
        snapshot: &CandidateSnapshot,
    ) -> Vec<super::super::super::CachedFileMetadata> {
        self.store
            .candidate_file_metadata(snapshot.candidate_id, &Deadline::new(None))
            .expect("metadata")
    }
}

pub(super) fn hint(seconds: i64, nanoseconds: u32) -> Option<MtimeHint> {
    Some(MtimeHint {
        seconds_since_unix_epoch: seconds,
        nanoseconds,
    })
}

pub(super) fn add_scope(snapshot: &mut CandidateSnapshot) {
    let mut incremental = IncrementalGraph::new();
    for file in &mut snapshot.files {
        incremental.upsert(&file.facts);
        file.subgraph = incremental.subgraph(&file.path).cloned();
    }
    snapshot.tier_graphs = vec![(
        ResolverCacheTier::Scope,
        CodeGraph {
            symbols: Vec::new(),
            edges: Vec::new(),
        },
    )];
}

pub(super) fn two_files() -> CandidateSnapshot {
    let mut snapshot = candidate(CacheCompleteness::Complete, ResolverCacheTier::Name);
    let mut second = snapshot.files[0].clone();
    second.path = "src/b.rs".into();
    second.facts = empty_facts(&second.path);
    second.package_assignment = "10:assignment8:src/b.rs4:none".into();
    snapshot.files.push(second);
    snapshot.input_digest = ProjectInputDigest::from_inputs(
        snapshot
            .files
            .iter()
            .map(|file| (&file.path, &file.language, file.content_hash)),
    );
    snapshot.candidate_id = CandidateId::new(
        snapshot.compatibility.id,
        snapshot.input_digest,
        snapshot.completeness,
        &snapshot.omissions,
    );
    snapshot.inventory_file_count = 2;
    snapshot.inventory_total_bytes = 2;
    snapshot
}

#[test]
fn republication_updates_mtime_hints_without_replacing_content_identity() {
    let transitions = [
        (None, hint(1_000_000_000, 0)),
        (hint(1_000_000_000, 0), None),
        (hint(1_000_000_001, 0), hint(1_000_000_000, 0)),
        (hint(1_000_000_000, 1), hint(1_000_000_000, 2)),
        (hint(1, 0), hint(-1, 999_999_999)),
    ];
    for (before, after) in transitions {
        let fixture = Fixture::new();
        let mut original = candidate(CacheCompleteness::Complete, ResolverCacheTier::Name);
        original.files[0].mtime = before;
        fixture.publish(&original);
        let original_metadata = fixture.metadata(&original);
        let mut incoming = original.clone();
        incoming.files[0].mtime = after;
        incoming.created_at_ns += 10;
        incoming.compatibility.created_at_ns += 10;
        fixture.publish(&incoming);
        fixture.publish(&incoming);
        let loaded = fixture
            .store
            .load_candidate(original.candidate_id, &Deadline::new(None))
            .expect("load");
        assert_eq!(loaded.candidate_id, original.candidate_id);
        assert_eq!(loaded.input_digest, original.input_digest);
        assert_eq!(loaded.created_at_ns, original.created_at_ns);
        assert_eq!(loaded.compatibility, original.compatibility);
        assert_eq!(loaded.files[0].mtime, after);
        let mut expected_metadata = original_metadata;
        expected_metadata[0].mtime = after;
        assert_eq!(fixture.metadata(&incoming), expected_metadata);
        assert_eq!(loaded.tier_graphs.len(), 1);
        assert_eq!(loaded.tier_graphs[0].0, original.tier_graphs[0].0);
        assert_eq!(
            serde_json::to_value(&loaded.tier_graphs[0].1).expect("loaded graph"),
            serde_json::to_value(&original.tier_graphs[0].1).expect("original graph")
        );
        let counts: (i64, i64) = fixture
            .store
            .connection
            .query_row(
                "SELECT (SELECT count(*) FROM candidates), (SELECT count(*) FROM graph_snapshots)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("row counts");
        assert_eq!(counts, (1, 1));
    }
}

#[test]
fn name_scope_name_publication_keeps_graphs_and_enriched_subgraphs() {
    let fixture = Fixture::new();
    let name = candidate(CacheCompleteness::Complete, ResolverCacheTier::Name);
    fixture.publish(&name);
    let mut scope = name.clone();
    add_scope(&mut scope);
    scope.files[0].mtime = hint(1_000_000_001, 0);
    fixture.publish(&scope);
    let mut refreshed_name = name.clone();
    refreshed_name.files[0].mtime = hint(1_000_000_000, 0);
    fixture.publish(&refreshed_name);
    let loaded = fixture
        .store
        .load_candidate(name.candidate_id, &Deadline::new(None))
        .expect("load");
    assert_eq!(loaded.files[0].mtime, refreshed_name.files[0].mtime);
    assert!(loaded.files[0].subgraph.is_some());
    assert_eq!(loaded.tier_graphs.len(), 2);
    for ((tier, graph), (expected_tier, expected_graph)) in loaded
        .tier_graphs
        .iter()
        .zip([&name.tier_graphs[0], &scope.tier_graphs[0]])
    {
        assert_eq!(tier, expected_tier);
        assert_eq!(
            serde_json::to_value(graph).expect("loaded graph"),
            serde_json::to_value(expected_graph).expect("expected graph")
        );
    }
    let hydrated = fixture
        .store
        .hydrate_scope_subgraphs(name.candidate_id, &Deadline::new(None))
        .expect("hydrate");
    assert!(hydrated.subgraph("src/a.rs").is_some());
    for tier in [ResolverCacheTier::Name, ResolverCacheTier::Scope] {
        let active = fixture
            .store
            .load_active(
                tier,
                CacheCompleteness::Complete,
                name.compatibility.id,
                &Deadline::new(None),
            )
            .expect("active load")
            .expect("active");
        assert_eq!(active.candidate_id, name.candidate_id);
        assert_eq!(active.files[0].mtime, refreshed_name.files[0].mtime);
    }
}
