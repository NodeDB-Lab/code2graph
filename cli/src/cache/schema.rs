// SPDX-License-Identifier: Apache-2.0

//! SQLite schema contract for the derived project cache.

use rusqlite::{Connection, OptionalExtension};

use super::CacheError;

#[cfg(test)]
use std::cell::Cell;

#[cfg(test)]
std::thread_local! {
    static FAIL_NEXT_CREATE: Cell<bool> = const { Cell::new(false) };
}

#[cfg(test)]
pub(super) fn fail_next_create_for_test() {
    FAIL_NEXT_CREATE.with(|fail_next_create| fail_next_create.set(true));
}

pub(super) const SCHEMA_VERSION: i64 = 1;
pub(super) const APPLICATION_ID: i64 = 0x4332_4731;
pub(super) const APPLICATION_IDENTITY: &str = "code2graph-cache";

const TABLES: &[(&str, &str)] = &[
    (
        "meta",
        "CREATE TABLE meta (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), application_identity TEXT NOT NULL CHECK (application_identity = 'code2graph-cache'), canonical_root BLOB NOT NULL, project_key BLOB NOT NULL CHECK (length(project_key) = 32))",
    ),
    (
        "compatibility",
        "CREATE TABLE compatibility (compatibility_id BLOB PRIMARY KEY CHECK (length(compatibility_id) = 32), language_fingerprint BLOB NOT NULL CHECK (length(language_fingerprint) = 32), package_fingerprint BLOB NOT NULL CHECK (length(package_fingerprint) = 32), created_at_ns INTEGER NOT NULL CHECK (created_at_ns >= 0), UNIQUE (language_fingerprint, package_fingerprint))",
    ),
    (
        "candidates",
        "CREATE TABLE candidates (candidate_id BLOB PRIMARY KEY CHECK (length(candidate_id) = 32), compatibility_id BLOB NOT NULL REFERENCES compatibility(compatibility_id), input_digest BLOB NOT NULL CHECK (length(input_digest) = 32), completeness INTEGER NOT NULL CHECK (completeness IN (0, 1)), created_at_ns INTEGER NOT NULL CHECK (created_at_ns >= 0), inventory_file_count INTEGER NOT NULL CHECK (inventory_file_count >= 0), inventory_total_bytes INTEGER NOT NULL CHECK (inventory_total_bytes >= 0))",
    ),
    (
        "candidate_omissions",
        "CREATE TABLE candidate_omissions (candidate_id BLOB NOT NULL REFERENCES candidates(candidate_id) ON DELETE CASCADE, path TEXT NOT NULL CHECK (path <> '' AND instr(path, '\\') = 0), reason TEXT NOT NULL CHECK (reason <> ''), detail TEXT NOT NULL, PRIMARY KEY (candidate_id, path, reason, detail))",
    ),
    (
        "candidate_files",
        "CREATE TABLE candidate_files (candidate_id BLOB NOT NULL REFERENCES candidates(candidate_id) ON DELETE CASCADE, path TEXT NOT NULL CHECK (path <> '' AND instr(path, '\\') = 0), language TEXT NOT NULL CHECK (language <> ''), content_hash BLOB NOT NULL CHECK (length(content_hash) = 32), size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0), mtime_seconds INTEGER, mtime_nanoseconds INTEGER CHECK (mtime_nanoseconds IS NULL OR (mtime_nanoseconds >= 0 AND mtime_nanoseconds < 1000000000)), package_assignment TEXT NOT NULL CHECK (package_assignment <> ''), file_facts BLOB NOT NULL CHECK (length(file_facts) <= 16777216), file_subgraph BLOB CHECK (file_subgraph IS NULL OR length(file_subgraph) <= 16777216), CHECK ((mtime_seconds IS NULL) = (mtime_nanoseconds IS NULL)), PRIMARY KEY (candidate_id, path))",
    ),
    (
        "graph_snapshots",
        "CREATE TABLE graph_snapshots (snapshot_id INTEGER PRIMARY KEY, candidate_id BLOB NOT NULL REFERENCES candidates(candidate_id) ON DELETE CASCADE, resolver_tier TEXT NOT NULL CHECK (resolver_tier IN ('name', 'scope', 'dense')), created_at_ns INTEGER NOT NULL CHECK (created_at_ns >= 0), UNIQUE (candidate_id, resolver_tier))",
    ),
    (
        "graph_symbols",
        "CREATE TABLE graph_symbols (snapshot_id INTEGER NOT NULL REFERENCES graph_snapshots(snapshot_id) ON DELETE CASCADE, ordinal INTEGER NOT NULL CHECK (ordinal >= 0), id BLOB NOT NULL, scip TEXT NOT NULL, name TEXT NOT NULL, file TEXT NOT NULL, span_start INTEGER NOT NULL CHECK (span_start >= 0), span_end INTEGER NOT NULL CHECK (span_end >= span_start), kind TEXT NOT NULL, symbol BLOB NOT NULL CHECK (length(symbol) <= 16777216), PRIMARY KEY (snapshot_id, ordinal), UNIQUE (snapshot_id, id))",
    ),
    (
        "graph_edges",
        "CREATE TABLE graph_edges (snapshot_id INTEGER NOT NULL REFERENCES graph_snapshots(snapshot_id) ON DELETE CASCADE, ordinal INTEGER NOT NULL CHECK (ordinal >= 0), edge_key BLOB NOT NULL, from_id BLOB NOT NULL, to_id BLOB NOT NULL, role TEXT NOT NULL, confidence TEXT NOT NULL, confidence_rank INTEGER NOT NULL CHECK (confidence_rank BETWEEN 0 AND 3), provenance TEXT NOT NULL, occurrence_file TEXT NOT NULL, occurrence_byte INTEGER NOT NULL CHECK (occurrence_byte >= 0), edge BLOB NOT NULL CHECK (length(edge) <= 16777216), PRIMARY KEY (snapshot_id, ordinal), UNIQUE (snapshot_id, edge_key))",
    ),
    (
        "graph_ids",
        "CREATE TABLE graph_ids (snapshot_id INTEGER NOT NULL REFERENCES graph_snapshots(snapshot_id) ON DELETE CASCADE, ordinal INTEGER NOT NULL CHECK (ordinal >= 0), id BLOB NOT NULL, scip TEXT NOT NULL, PRIMARY KEY (snapshot_id, ordinal), UNIQUE (snapshot_id, id))",
    ),
    (
        "active_snapshots",
        "CREATE TABLE active_snapshots (resolver_tier TEXT NOT NULL CHECK (resolver_tier IN ('name', 'scope', 'dense')), completeness INTEGER NOT NULL CHECK (completeness IN (0, 1)), snapshot_id INTEGER NOT NULL REFERENCES graph_snapshots(snapshot_id) ON DELETE CASCADE, PRIMARY KEY (resolver_tier, completeness))",
    ),
];

pub(super) const LEGACY_GRAPH_SNAPSHOTS: &str = "CREATE TABLE graph_snapshots (snapshot_id INTEGER PRIMARY KEY, candidate_id BLOB NOT NULL REFERENCES candidates(candidate_id) ON DELETE CASCADE, resolver_tier TEXT NOT NULL CHECK (resolver_tier IN ('name', 'scope', 'dense')), graph BLOB NOT NULL CHECK (length(graph) <= 16777216), created_at_ns INTEGER NOT NULL CHECK (created_at_ns >= 0), UNIQUE (candidate_id, resolver_tier))";

const INDEXES: &[(&str, &str)] = &[
    (
        "candidates_compatibility_idx",
        "CREATE INDEX candidates_compatibility_idx ON candidates (compatibility_id)",
    ),
    (
        "candidate_files_path_idx",
        "CREATE INDEX candidate_files_path_idx ON candidate_files (path)",
    ),
    (
        "graph_snapshots_candidate_idx",
        "CREATE INDEX graph_snapshots_candidate_idx ON graph_snapshots (candidate_id)",
    ),
    (
        "graph_symbols_snapshot_idx",
        "CREATE INDEX graph_symbols_snapshot_idx ON graph_symbols (snapshot_id, ordinal)",
    ),
    (
        "graph_symbols_name_idx",
        "CREATE INDEX graph_symbols_name_idx ON graph_symbols (snapshot_id, name, ordinal)",
    ),
    (
        "graph_symbols_scip_idx",
        "CREATE INDEX graph_symbols_scip_idx ON graph_symbols (snapshot_id, scip, ordinal)",
    ),
    (
        "graph_symbols_file_idx",
        "CREATE INDEX graph_symbols_file_idx ON graph_symbols (snapshot_id, file, ordinal)",
    ),
    (
        "graph_edges_snapshot_idx",
        "CREATE INDEX graph_edges_snapshot_idx ON graph_edges (snapshot_id, ordinal)",
    ),
    (
        "graph_edges_file_idx",
        "CREATE INDEX graph_edges_file_idx ON graph_edges (snapshot_id, occurrence_file, role, confidence_rank, provenance, ordinal)",
    ),
    (
        "graph_edges_filter_idx",
        "CREATE INDEX graph_edges_filter_idx ON graph_edges (snapshot_id, role, confidence_rank, provenance, ordinal)",
    ),
    (
        "graph_ids_scip_idx",
        "CREATE INDEX graph_ids_scip_idx ON graph_ids (snapshot_id, scip, ordinal)",
    ),
    (
        "graph_edges_from_idx",
        "CREATE INDEX graph_edges_from_idx ON graph_edges (snapshot_id, from_id, role, confidence, provenance, ordinal)",
    ),
    (
        "graph_edges_to_idx",
        "CREATE INDEX graph_edges_to_idx ON graph_edges (snapshot_id, to_id, role, confidence, provenance, ordinal)",
    ),
];

pub(super) fn create_v1(
    connection: &Connection,
    root: &[u8],
    project_key: &[u8; 32],
) -> Result<(), CacheError> {
    for (_, sql) in TABLES {
        connection
            .execute(sql, [])
            .map_err(|_| CacheError::Access)?;
    }
    for (_, sql) in INDEXES {
        connection
            .execute(sql, [])
            .map_err(|_| CacheError::Access)?;
    }
    #[cfg(test)]
    if FAIL_NEXT_CREATE.with(|fail_next_create| fail_next_create.replace(false)) {
        return Err(CacheError::Access);
    }
    connection
        .execute(
            "INSERT INTO meta (singleton, application_identity, canonical_root, project_key) VALUES (1, ?1, ?2, ?3)",
            (APPLICATION_IDENTITY, root, project_key.as_slice()),
        )
        .map_err(|_| CacheError::Access)?;
    connection
        .pragma_update(None, "application_id", APPLICATION_ID)
        .map_err(|_| CacheError::Access)?;
    connection
        .pragma_update(None, "user_version", SCHEMA_VERSION)
        .map_err(|_| CacheError::Access)
}

/// Transactionally replaces only the exact unreleased monolithic-graph layout.
/// The caller owns `BEGIN IMMEDIATE`/commit so readers observe either layout.
pub(super) fn reset_legacy_graph_layout(connection: &Connection) -> Result<bool, CacheError> {
    let graph_sql: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'graph_snapshots'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(map_validation_error)?;
    if graph_sql.as_deref() != Some(LEGACY_GRAPH_SNAPSHOTS) {
        return Ok(false);
    }
    connection
        .execute_batch(
            "DROP TABLE active_snapshots; DROP TABLE graph_snapshots; \
             DROP INDEX IF EXISTS graph_snapshots_candidate_idx;",
        )
        .map_err(map_validation_error)?;
    for (name, sql) in TABLES.iter().filter(|(name, _)| {
        matches!(
            *name,
            "graph_snapshots" | "graph_symbols" | "graph_edges" | "graph_ids" | "active_snapshots"
        )
    }) {
        let _ = name;
        connection.execute(sql, []).map_err(map_validation_error)?;
    }
    for (name, sql) in INDEXES
        .iter()
        .filter(|(name, _)| name.starts_with("graph_"))
    {
        let _ = name;
        connection.execute(sql, []).map_err(map_validation_error)?;
    }
    Ok(true)
}

pub(super) fn validate_v1(
    connection: &Connection,
    root: &[u8],
    project_key: &[u8; 32],
) -> Result<(), CacheError> {
    let application_id: i64 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(map_validation_error)?;
    if application_id != APPLICATION_ID {
        return Err(CacheError::Incompatible);
    }

    for (name, expected) in TABLES {
        validate_object(connection, "table", name, expected)?;
    }
    for (name, expected) in INDEXES {
        validate_object(connection, "index", name, expected)?;
    }

    let meta = connection
        .query_row(
            "SELECT application_identity, canonical_root, project_key FROM meta WHERE singleton = 1",
            [],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, Vec<u8>>(2)?)),
        )
        .optional()
        .map_err(map_validation_error)?;
    let Some((identity, stored_root, stored_key)) = meta else {
        return Err(CacheError::Incompatible);
    };
    if identity != APPLICATION_IDENTITY {
        return Err(CacheError::Incompatible);
    }
    if stored_key.as_slice() != project_key || stored_root != root {
        return Err(CacheError::RootMismatch);
    }
    Ok(())
}

fn validate_object(
    connection: &Connection,
    object_type: &str,
    name: &str,
    expected: &str,
) -> Result<(), CacheError> {
    let sql = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = ?1 AND name = ?2",
            (object_type, name),
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()
        .map_err(map_validation_error)?
        .flatten();
    // sqlite_master preserves CREATE statements issued by this unit. Comparing
    // the complete statement is deliberate: token-level whitespace folding can
    // hide changes inside string literals and therefore weaken CHECK clauses.
    if sql.as_deref() != Some(expected) {
        return Err(CacheError::Incompatible);
    }
    Ok(())
}

fn map_validation_error(error: rusqlite::Error) -> CacheError {
    match error {
        rusqlite::Error::SqliteFailure(failure, _) => match failure.code {
            rusqlite::ErrorCode::NotADatabase | rusqlite::ErrorCode::DatabaseCorrupt => {
                CacheError::Corrupt
            }
            rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked => {
                CacheError::LockContention
            }
            rusqlite::ErrorCode::ReadOnly => CacheError::ReadOnly,
            _ => CacheError::Incompatible,
        },
        _ => CacheError::Incompatible,
    }
}
