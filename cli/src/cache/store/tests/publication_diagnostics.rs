// SPDX-License-Identifier: Apache-2.0

use super::metadata_refresh::{Fixture, add_scope, hint, two_files};
use super::*;

fn conflict(store: &CacheStore, snapshot: &CandidateSnapshot) -> PublicationConflict {
    match store.publish_candidate_detailed(snapshot, &Deadline::new(None)) {
        Err(CachePublicationFailure::Conflict(conflict)) => conflict,
        result => panic!("expected structured conflict, got {result:?}"),
    }
}

#[test]
fn stored_header_and_compatibility_differences_identify_named_fields() {
    let changes = [
        (
            "compatibility",
            "language_fingerprint = zeroblob(32)",
            PublicationField::LanguageFingerprint,
        ),
        (
            "compatibility",
            "package_fingerprint = zeroblob(32)",
            PublicationField::PackageFingerprint,
        ),
        (
            "candidates",
            "compatibility_id = zeroblob(32)",
            PublicationField::CompatibilityId,
        ),
        (
            "candidates",
            "input_digest = zeroblob(32)",
            PublicationField::InputDigest,
        ),
        (
            "candidates",
            "completeness = 1",
            PublicationField::Completeness,
        ),
        (
            "candidates",
            "inventory_file_count = 2",
            PublicationField::InventoryFileCount,
        ),
        (
            "candidates",
            "inventory_total_bytes = 2",
            PublicationField::InventoryTotalBytes,
        ),
    ];
    for (table, change, field) in changes {
        let fixture = Fixture::new();
        let snapshot = candidate(CacheCompleteness::Complete, ResolverCacheTier::Name);
        fixture.publish(&snapshot);
        fixture
            .store
            .connection
            .execute_batch("PRAGMA foreign_keys = OFF")
            .expect("controlled mutation");
        fixture
            .store
            .connection
            .execute(&format!("UPDATE {table} SET {change}"), [])
            .expect("stored field");
        let diagnostic = conflict(&fixture.store, &snapshot);
        assert_eq!(diagnostic.candidate_id, snapshot.candidate_id);
        assert_eq!(diagnostic.field, field);
        assert!(diagnostic.file.is_none());
        assert!(diagnostic.tier.is_none());
        assert!(matches!(
            fixture
                .store
                .publish_candidate(&snapshot, &Deadline::new(None)),
            Err(CacheError::CandidateConflict)
        ));
    }
}

#[test]
fn immutable_file_differences_identify_fields_and_roll_back_prior_mtime_updates() {
    let changes = [
        ("language = 'python'", PublicationField::Language),
        ("content_hash = zeroblob(32)", PublicationField::ContentHash),
        ("size_bytes = size_bytes + 1", PublicationField::SizeBytes),
        (
            "package_assignment = 'secret-package'",
            PublicationField::PackageAssignment,
        ),
        ("file_facts = X'736563726574'", PublicationField::FileFacts),
        (
            "file_subgraph = X'736563726574'",
            PublicationField::FileSubgraph,
        ),
    ];
    for (change, field) in changes {
        let fixture = Fixture::new();
        let mut snapshot = two_files();
        add_scope(&mut snapshot);
        fixture.publish(&snapshot);
        fixture
            .store
            .connection
            .execute(
                &format!("UPDATE candidate_files SET {change} WHERE path = 'src/b.rs'"),
                [],
            )
            .expect("stored file field");
        let mut incoming = snapshot.clone();
        incoming.files[0].mtime = hint(1_000_000_000, 0);
        let diagnostic = conflict(&fixture.store, &incoming);
        assert_eq!(diagnostic.field, field);
        assert_eq!(diagnostic.file.as_deref(), Some("\"src/b.rs\""));
        assert!(diagnostic.tier.is_none());
        assert_eq!(
            fixture.metadata(&snapshot)[0].mtime,
            snapshot.files[0].mtime
        );
    }
}

#[test]
fn file_presence_preserves_row_count_and_names_the_incoming_file() {
    let fixture = Fixture::new();
    let snapshot = two_files();
    fixture.publish(&snapshot);
    fixture
        .store
        .connection
        .execute(
            "UPDATE candidate_files SET path = 'other.rs' WHERE path = 'src/b.rs'",
            [],
        )
        .expect("stored path");
    let diagnostic = conflict(&fixture.store, &snapshot);
    assert_eq!(diagnostic.field, PublicationField::FilePresence);
    assert_eq!(diagnostic.file.as_deref(), Some("\"src/b.rs\""));
    let count: i64 = fixture
        .store
        .connection
        .query_row("SELECT count(*) FROM candidate_files", [], |row| row.get(0))
        .expect("row count");
    assert_eq!(count, 2);
}

#[test]
fn file_count_and_omissions_have_payload_free_categories() {
    for (sql, field) in [
        ("DELETE FROM candidate_files", PublicationField::FileCount),
        (
            "INSERT INTO candidate_omissions SELECT candidate_id, 'secret.rs', 'secret-reason', 'secret-detail' FROM candidates",
            PublicationField::Omissions,
        ),
    ] {
        let fixture = Fixture::new();
        let snapshot = candidate(CacheCompleteness::Complete, ResolverCacheTier::Name);
        fixture.publish(&snapshot);
        fixture
            .store
            .connection
            .execute(sql, [])
            .expect("stored collection");
        let diagnostic = conflict(&fixture.store, &snapshot);
        assert_eq!(diagnostic.field, field);
        assert!(diagnostic.file.is_none());
        assert!(diagnostic.tier.is_none());
    }
}

#[test]
fn graph_differences_name_the_tier_and_roll_back_metadata_updates() {
    let changes = [
        (
            "INSERT INTO graph_symbols SELECT snapshot_id, 0, X'01', 'id', 'secret-name', 'secret.rs', 0, 0, 'function', X'736563726574' FROM graph_snapshots",
            PublicationField::GraphSymbols,
        ),
        (
            "INSERT INTO graph_edges SELECT snapshot_id, 0, zeroblob(32), 0, 0, 'call', 'exact', 3, 'scope', 'secret.rs', 0, 0, 0 FROM graph_snapshots",
            PublicationField::GraphEdges,
        ),
    ];
    for (sql, field) in changes {
        let fixture = Fixture::new();
        let snapshot = candidate(CacheCompleteness::Complete, ResolverCacheTier::Name);
        fixture.publish(&snapshot);
        fixture
            .store
            .connection
            .execute(sql, [])
            .expect("stored graph rows");
        let mut incoming = snapshot.clone();
        incoming.files[0].mtime = hint(1_000_000_000, 0);
        let diagnostic = conflict(&fixture.store, &incoming);
        assert_eq!(diagnostic.field, field);
        assert_eq!(diagnostic.tier, Some("name"));
        assert!(diagnostic.file.is_none());
        assert_eq!(
            fixture.metadata(&snapshot)[0].mtime,
            snapshot.files[0].mtime
        );
    }
}

#[test]
fn ordinary_publication_errors_keep_the_original_category() {
    let fixture = Fixture::new();
    let snapshot = candidate(CacheCompleteness::Complete, ResolverCacheTier::Name);
    assert!(matches!(
        fixture
            .store
            .publish_candidate_detailed(&snapshot, &Deadline::new(Some(Duration::ZERO))),
        Err(CachePublicationFailure::Cache(CacheError::Timeout))
    ));
    fixture.store.connection.execute_batch("CREATE TEMP TRIGGER reject_candidate BEFORE INSERT ON candidates BEGIN SELECT RAISE(ABORT, 'secret SQL detail'); END").expect("SQL trigger");
    assert!(matches!(
        fixture
            .store
            .publish_candidate_detailed(&snapshot, &Deadline::new(None)),
        Err(CachePublicationFailure::Cache(CacheError::Access))
    ));
    fixture
        .store
        .connection
        .execute_batch("DROP TRIGGER reject_candidate")
        .expect("remove trigger");
    let mut readonly = fixture.store;
    readonly.writable = false;
    assert!(matches!(
        readonly.publish_candidate_detailed(&snapshot, &Deadline::new(None)),
        Err(CachePublicationFailure::Cache(CacheError::ReadOnly))
    ));
}

#[test]
fn graph_confidence_difference_keeps_edge_identity_and_names_the_tier() {
    let fixture = Fixture::new();
    let mut snapshot = candidate(CacheCompleteness::Complete, ResolverCacheTier::Name);
    snapshot.tier_graphs[0].1.edges.push(Edge {
        from: SymbolId::global("rust", vec![Descriptor::Term("from".into())]),
        to: SymbolId::global("rust", vec![Descriptor::Term("to".into())]),
        role: RefRole::Call,
        confidence: Confidence::Scoped,
        provenance: Provenance::ScopeGraph,
        occ: Occurrence {
            file: "src/a.rs".into(),
            byte: 0,
            line: 1,
            col: 0,
        },
    });
    fixture.publish(&snapshot);
    fixture
        .store
        .connection
        .execute(
            "UPDATE graph_edges SET confidence = 'secret-confidence'",
            [],
        )
        .expect("stored confidence");
    let diagnostic = conflict(&fixture.store, &snapshot);
    assert_eq!(diagnostic.field, PublicationField::GraphConfidence);
    assert_eq!(diagnostic.tier, Some("name"));
    assert!(diagnostic.file.is_none());
}

#[test]
fn multiple_stored_differences_choose_the_first_named_field() {
    let fixture = Fixture::new();
    let snapshot = candidate(CacheCompleteness::Complete, ResolverCacheTier::Name);
    fixture.publish(&snapshot);
    fixture.store.connection.execute("UPDATE candidate_files SET language = 'python', content_hash = zeroblob(32), file_facts = X'00'", []).expect("stored differences");
    assert_eq!(
        conflict(&fixture.store, &snapshot).field,
        PublicationField::Language
    );
}
