// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn failed_graph_write_rolls_back_candidate_and_active_publication() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("project");
    fs::create_dir(&root).expect("project");
    let cache_location = location(&root, temp.path());
    let store =
        CacheStore::open_writable(&cache_location, &root, &Deadline::new(None)).expect("open");
    let candidate = candidate(CacheCompleteness::Complete, ResolverCacheTier::Name);
    store.connection.execute_batch(
        "CREATE TEMP TRIGGER fail_graph BEFORE INSERT ON graph_snapshots BEGIN SELECT RAISE(ABORT, 'injected graph failure'); END",
    ).expect("failure trigger");
    assert!(matches!(
        store.publish_candidate(&candidate, &Deadline::new(None)),
        Err(CacheError::Access)
    ));
    let candidate_count: i64 = store
        .connection
        .query_row(
            "SELECT count(*) FROM candidates WHERE candidate_id = ?1",
            [candidate.candidate_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("candidate count");
    let active_count: i64 = store
        .connection
        .query_row("SELECT count(*) FROM active_snapshots", [], |row| {
            row.get(0)
        })
        .expect("active count");
    assert_eq!((candidate_count, active_count), (0, 0));
    store
        .connection
        .execute_batch("DROP TRIGGER fail_graph")
        .expect("drop trigger");
    store
        .publish_candidate(&candidate, &Deadline::new(None))
        .expect("retry");
}

#[test]
fn later_file_conflict_rolls_back_earlier_metadata_updates() {
    use super::metadata_refresh::{Fixture, hint, two_files};

    let fixture = Fixture::new();
    let original = two_files();
    fixture.publish(&original);
    let mut incoming = original.clone();
    incoming.files[0].mtime = hint(1_000_000_000, 0);
    incoming.files[1].mtime = hint(1_000_000_001, 0);
    fixture.store.connection.execute(
        "UPDATE candidate_files SET size_bytes = size_bytes + 1 WHERE candidate_id = ?1 AND path = 'src/b.rs'",
        [original.candidate_id.as_bytes().as_slice()],
    ).expect("conflicting second file size");
    assert!(matches!(
        fixture
            .store
            .publish_candidate(&incoming, &Deadline::new(None)),
        Err(CacheError::CandidateConflict)
    ));
    let metadata = fixture.metadata(&original);
    assert_eq!(metadata[0].mtime, original.files[0].mtime);
    assert_eq!(metadata[1].mtime, original.files[1].mtime);
    fixture.store.connection.execute(
        "UPDATE candidate_files SET size_bytes = ?1 WHERE candidate_id = ?2 AND path = 'src/b.rs'",
        params![i64::try_from(original.files[1].size_bytes).expect("SQLite size"), original.candidate_id.as_bytes().as_slice()],
    ).expect("restore second file size");
    fixture.publish(&original);
}

#[test]
fn graph_rejection_rolls_back_metadata_and_subgraphs_and_preserves_active_slots() {
    use super::metadata_refresh::{Fixture, add_scope, hint};

    let fixture = Fixture::new();
    let original = candidate(CacheCompleteness::Complete, ResolverCacheTier::Name);
    fixture.publish(&original);
    let mut scope = original.clone();
    add_scope(&mut scope);
    scope.files[0].mtime = hint(1_000_000_000, 0);
    fixture.store.connection.execute_batch(
        "CREATE TEMP TRIGGER reject_scope BEFORE INSERT ON graph_snapshots BEGIN SELECT RAISE(ABORT, 'rejected graph insert'); END",
    ).expect("graph trigger");
    assert!(matches!(
        fixture
            .store
            .publish_candidate(&scope, &Deadline::new(None)),
        Err(CacheError::Access)
    ));
    let metadata = fixture.metadata(&original);
    assert_eq!(metadata[0].mtime, original.files[0].mtime);
    assert!(!metadata[0].has_subgraph);
    let active = fixture
        .store
        .load_active(
            ResolverCacheTier::Name,
            CacheCompleteness::Complete,
            original.compatibility.id,
            &Deadline::new(None),
        )
        .expect("name load")
        .expect("name active");
    assert_eq!(active.candidate_id, original.candidate_id);
    assert!(
        fixture
            .store
            .load_active(
                ResolverCacheTier::Scope,
                CacheCompleteness::Complete,
                original.compatibility.id,
                &Deadline::new(None)
            )
            .expect("scope load")
            .is_none()
    );
    let graph_count: i64 = fixture
        .store
        .connection
        .query_row("SELECT count(*) FROM graph_snapshots", [], |row| row.get(0))
        .expect("graph count");
    assert_eq!(graph_count, 1);
    fixture
        .store
        .connection
        .execute_batch("DROP TRIGGER reject_scope")
        .expect("drop trigger");
    fixture.publish(&scope);
    let metadata = fixture.metadata(&scope);
    assert_eq!(metadata[0].mtime, scope.files[0].mtime);
    assert!(metadata[0].has_subgraph);
    assert!(
        fixture
            .store
            .load_active(
                ResolverCacheTier::Scope,
                CacheCompleteness::Complete,
                scope.compatibility.id,
                &Deadline::new(None)
            )
            .expect("scope load")
            .is_some()
    );
}
