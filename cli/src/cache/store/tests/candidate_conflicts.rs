// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn rejects_inconsistent_candidates_and_conflicting_republication() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("project");
    fs::create_dir(&root).expect("project");
    let cache_location = location(&root, temp.path());
    let store =
        CacheStore::open_writable(&cache_location, &root, &Deadline::new(None)).expect("open");

    let mut unsorted = candidate(CacheCompleteness::Partial, ResolverCacheTier::Name);
    unsorted.omissions = vec![
        crate::cache::CacheOmission {
            path: "z".into(),
            reason: "x".into(),
            detail: "detail".into(),
        },
        crate::cache::CacheOmission {
            path: "a".into(),
            reason: "x".into(),
            detail: "detail".into(),
        },
    ];
    unsorted.candidate_id = CandidateId::new(
        unsorted.compatibility.id,
        unsorted.input_digest,
        unsorted.completeness,
        &unsorted.omissions,
    );
    assert!(matches!(
        store.publish_candidate(&unsorted, &Deadline::new(None)),
        Err(CacheError::InvalidCandidate)
    ));

    let mut overflow = candidate(CacheCompleteness::Complete, ResolverCacheTier::Name);
    overflow.created_at_ns = u64::MAX;
    assert!(matches!(
        store.publish_candidate(&overflow, &Deadline::new(None)),
        Err(CacheError::InvalidCandidate)
    ));

    let original = candidate(CacheCompleteness::Complete, ResolverCacheTier::Name);
    store
        .publish_candidate(&original, &Deadline::new(None))
        .expect("publish");
    let mut republished = original.clone();
    republished.created_at_ns += 1;
    republished.compatibility.created_at_ns += 1;
    store
        .publish_candidate(&republished, &Deadline::new(None))
        .expect("timestamps are store-owned and do not conflict");
    assert_eq!(
        store
            .load_active(
                ResolverCacheTier::Name,
                CacheCompleteness::Complete,
                original.compatibility.id,
                &Deadline::new(None),
            )
            .expect("load")
            .expect("active")
            .created_at_ns,
        original.created_at_ns
    );
}

#[test]
fn scope_publication_requires_and_restores_every_owned_subgraph() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("project");
    fs::create_dir(&root).expect("project");
    let cache_location = location(&root, temp.path());
    let store =
        CacheStore::open_writable(&cache_location, &root, &Deadline::new(None)).expect("open");
    let mut snapshot = candidate(CacheCompleteness::Complete, ResolverCacheTier::Scope);
    assert!(matches!(
        store.publish_candidate(&snapshot, &Deadline::new(None)),
        Err(CacheError::InvalidCandidate)
    ));
    // A Name snapshot may be published first; a later Scope publication
    // for the identical candidate augments its per-file subgraphs.
    let mut name = snapshot.clone();
    name.tier_graphs = vec![(
        ResolverCacheTier::Name,
        CodeGraph {
            symbols: Vec::new(),
            edges: Vec::new(),
        },
    )];
    store
        .publish_candidate(&name, &Deadline::new(None))
        .expect("publish name");
    let mut incremental = IncrementalGraph::new();
    incremental.upsert(&snapshot.files[0].facts);
    snapshot.files[0].subgraph = incremental.subgraph("src/a.rs").cloned();
    store
        .publish_candidate(&snapshot, &Deadline::new(None))
        .expect("augment with scope");
    let restored = store
        .hydrate_scope_subgraphs(snapshot.candidate_id, &Deadline::new(None))
        .expect("hydrate");
    assert!(restored.subgraph("src/a.rs").is_some());
}

#[test]
fn metadata_refresh_rejects_each_conflicting_immutable_file_payload() {
    use super::metadata_refresh::{Fixture, add_scope, hint};

    let changes = [
        "size_bytes = size_bytes + 1",
        "language = 'python'",
        "content_hash = zeroblob(32)",
        "package_assignment = 'different-package'",
        "file_facts = X'00'",
        "file_subgraph = X'00'",
    ];
    for change in changes {
        let fixture = Fixture::new();
        let mut original = candidate(CacheCompleteness::Complete, ResolverCacheTier::Scope);
        add_scope(&mut original);
        fixture.publish(&original);
        fixture
            .store
            .connection
            .execute(
                &format!("UPDATE candidate_files SET {change} WHERE candidate_id = ?1"),
                [original.candidate_id.as_bytes().as_slice()],
            )
            .expect("conflicting payload");
        let mut incoming = original.clone();
        incoming.files[0].mtime = hint(1_000_000_000, 0);
        assert!(
            matches!(
                fixture
                    .store
                    .publish_candidate(&incoming, &Deadline::new(None)),
                Err(CacheError::CandidateConflict)
            ),
            "{change}"
        );
        let stored: (Option<i64>, Option<i64>) = fixture.store.connection.query_row(
            "SELECT mtime_seconds, mtime_nanoseconds FROM candidate_files WHERE candidate_id = ?1",
            [original.candidate_id.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).expect("stored hint");
        assert_eq!(stored, (Some(0), Some(4)), "{change}");
    }
}
