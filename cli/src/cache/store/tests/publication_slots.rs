// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn candidate_publication_keeps_complete_and_partial_slots_independent() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("project");
    fs::create_dir(&root).expect("project");
    let cache_location = location(&root, temp.path());
    let store =
        CacheStore::open_writable(&cache_location, &root, &Deadline::new(None)).expect("open");
    let complete = candidate(CacheCompleteness::Complete, ResolverCacheTier::Name);
    let partial = candidate(CacheCompleteness::Partial, ResolverCacheTier::Name);
    store
        .publish_candidate(&complete, &Deadline::new(None))
        .expect("publish complete");
    store
        .publish_candidate(&partial, &Deadline::new(None))
        .expect("publish partial");
    assert_eq!(
        store
            .load_active(
                ResolverCacheTier::Name,
                CacheCompleteness::Complete,
                complete.compatibility.id,
                &Deadline::new(None)
            )
            .expect("load")
            .expect("active")
            .candidate_id,
        complete.candidate_id
    );
    assert_eq!(
        store
            .load_active(
                ResolverCacheTier::Name,
                CacheCompleteness::Partial,
                partial.compatibility.id,
                &Deadline::new(None)
            )
            .expect("load")
            .expect("active")
            .candidate_id,
        partial.candidate_id
    );
    let incompatible = CompatibilityFingerprint::new(
        crate::cache::LanguageFeatureFingerprint::current(),
        crate::cache::PackageFingerprint::from_normalized(["different-package"]),
    );
    let loaded_complete = store
        .load_active(
            ResolverCacheTier::Name,
            CacheCompleteness::Complete,
            complete.compatibility.id,
            &Deadline::new(None),
        )
        .expect("load")
        .expect("active");
    assert_eq!(
        loaded_complete.compatibility.language_fingerprint,
        complete.compatibility.language_fingerprint
    );
    assert_eq!(
        loaded_complete.compatibility.package_fingerprint,
        complete.compatibility.package_fingerprint
    );
    assert!(
        store
            .load_active(
                ResolverCacheTier::Name,
                CacheCompleteness::Complete,
                incompatible,
                &Deadline::new(None),
            )
            .expect("compatibility miss")
            .is_none()
    );
    store
        .publish_candidate(&complete, &Deadline::new(None))
        .expect("idempotent publish");
}

#[test]
fn superseding_a_slot_garbage_collects_the_prior_snapshot_and_candidate() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("project");
    fs::create_dir(&root).expect("project");
    let cache_location = location(&root, temp.path());
    let store =
        CacheStore::open_writable(&cache_location, &root, &Deadline::new(None)).expect("open");
    // Two distinct candidates (different input digests) target the same
    // (tier, completeness) slot; publishing B flips active away from A.
    let a = candidate_with_hash(
        CacheCompleteness::Complete,
        ResolverCacheTier::Name,
        [3; 32],
    );
    let b = candidate_with_hash(
        CacheCompleteness::Complete,
        ResolverCacheTier::Name,
        [7; 32],
    );
    assert_ne!(a.candidate_id, b.candidate_id);
    store
        .publish_candidate(&a, &Deadline::new(None))
        .expect("publish a");
    store
        .publish_candidate(&b, &Deadline::new(None))
        .expect("publish b");

    // Only B's snapshot survives; A's snapshot and candidate rows are gone.
    let snapshot_count: i64 = store
        .connection
        .query_row("SELECT count(*) FROM graph_snapshots", [], |row| row.get(0))
        .expect("snapshot count");
    assert_eq!(snapshot_count, 1);
    let surviving_candidate: Vec<u8> = store
        .connection
        .query_row("SELECT candidate_id FROM graph_snapshots", [], |row| {
            row.get(0)
        })
        .expect("surviving candidate");
    assert_eq!(
        surviving_candidate.as_slice(),
        b.candidate_id.as_bytes().as_slice()
    );
    let a_candidate_count: i64 = store
        .connection
        .query_row(
            "SELECT count(*) FROM candidates WHERE candidate_id = ?1",
            [a.candidate_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("a candidate count");
    assert_eq!(a_candidate_count, 0);

    // B remains the queryable active snapshot for the slot.
    assert_eq!(
        store
            .load_active(
                ResolverCacheTier::Name,
                CacheCompleteness::Complete,
                b.compatibility.id,
                &Deadline::new(None),
            )
            .expect("load")
            .expect("active")
            .candidate_id,
        b.candidate_id
    );
}

#[test]
fn concurrent_publishers_commit_whole_candidates() {
    use std::sync::{Arc, Barrier};

    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("project");
    fs::create_dir(&root).expect("project");
    let cache_location = location(&root, temp.path());
    CacheStore::open_writable(&cache_location, &root, &Deadline::new(None)).expect("initialize");
    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = [CacheCompleteness::Complete, CacheCompleteness::Partial]
        .into_iter()
        .map(|completeness| {
            let barrier = Arc::clone(&barrier);
            let root = root.clone();
            let cache_location = cache_location.clone();
            std::thread::spawn(move || {
                let store =
                    CacheStore::open_writable(&cache_location, &root, &Deadline::new(None))?;
                let candidate = candidate(completeness, ResolverCacheTier::Name);
                barrier.wait();
                store.publish_candidate(&candidate, &Deadline::new(None))?;
                Ok::<_, CacheError>(candidate.candidate_id)
            })
        })
        .collect();
    let ids: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().expect("publisher thread").expect("publish"))
        .collect();
    let store =
        CacheStore::open_frozen(&cache_location, &root, &Deadline::new(None)).expect("frozen");
    for (completeness, id) in [CacheCompleteness::Complete, CacheCompleteness::Partial]
        .into_iter()
        .zip(ids)
    {
        assert_eq!(
            store
                .load_active(
                    ResolverCacheTier::Name,
                    completeness,
                    candidate(completeness, ResolverCacheTier::Name)
                        .compatibility
                        .id,
                    &Deadline::new(None),
                )
                .expect("load")
                .expect("active")
                .candidate_id,
            id
        );
    }
}
