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
