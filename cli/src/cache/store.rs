// SPDX-License-Identifier: Apache-2.0

//! SQLite cache opening, schema migration, and identity validation.

use std::fs;
use std::io;
use std::path::Path;
use std::time::Duration;

use code2graph::{CodeGraph, IncrementalGraph};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};

use crate::Deadline;
use crate::inventory::MtimeHint;

use super::schema::{self, SCHEMA_VERSION};
use super::{
    CacheCompleteness, CacheError, CacheLocation, CandidateFileRecord, CandidateId,
    CandidateSnapshot, CompatibilityFingerprint, CompatibilityRecord, LoadedSnapshot,
    ProjectInputDigest, ResolverCacheTier, decode_file_facts, decode_graph, encode_file_facts,
    encode_graph, encode_subgraph, restore_subgraph,
};

const LOCK_WAIT_CAP: Duration = Duration::from_secs(2);

#[derive(Debug)]
struct CandidateFileRow {
    language: String,
    content_hash: Vec<u8>,
    size_bytes: i64,
    mtime_seconds: Option<i64>,
    mtime_nanoseconds: Option<i64>,
    package_assignment: String,
    file_facts: Vec<u8>,
    file_subgraph: Option<Vec<u8>>,
}

#[derive(Debug)]
struct LoadedCandidateFileRow {
    path: String,
    language: String,
    content_hash: Vec<u8>,
    size_bytes: i64,
    mtime_seconds: Option<i64>,
    mtime_nanoseconds: Option<i64>,
    package_assignment: String,
    file_facts: Vec<u8>,
    file_subgraph: Option<Vec<u8>>,
}

#[derive(Debug)]
struct CandidateSnapshotRow {
    compatibility_id: Vec<u8>,
    language_fingerprint: Vec<u8>,
    package_fingerprint: Vec<u8>,
    input_digest: Vec<u8>,
    completeness: i64,
    created_at_ns: i64,
    compatibility_created_at_ns: i64,
    inventory_file_count: i64,
    inventory_total_bytes: i64,
}

#[derive(Debug)]
struct ExistingCandidateRow {
    compatibility_id: Vec<u8>,
    input_digest: Vec<u8>,
    completeness: i64,
    inventory_file_count: i64,
    inventory_total_bytes: i64,
}

/// An open project-cache database. The SQLite connection remains private so
/// future cache publication can preserve the transaction protocol.
pub struct CacheStore {
    connection: Connection,
    writable: bool,
}

impl CacheStore {
    /// Opens a writable cache, creating and atomically initializing the current database schema.
    pub fn open_writable(
        location: &CacheLocation,
        canonical_root: &Path,
        deadline: &Deadline,
    ) -> Result<Self, CacheError> {
        ensure_time(deadline)?;
        fs::create_dir_all(&location.directory).map_err(map_io_error)?;
        let connection = Connection::open_with_flags(
            &location.database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        )
        .map_err(|error| map_sqlite_error(error, deadline))?;

        // Install the bounded lock wait before the first database read. This is
        // connection-local and does not mutate a future-version database.
        set_busy_timeout(&connection, deadline)?;
        let root = native_path_bytes(canonical_root);
        let key = location.project_key.as_bytes();
        let version = user_version(&connection, deadline)?;
        match version {
            0 => {
                // Do not inspect pristine-v0 state outside the initialization
                // lock. This connection may have observed v0 just before a
                // concurrent opener committed v1.
                initialize_or_join_v1(&connection, &root, &key, deadline)?;
                configure_writable(&connection, deadline)?;
            }
            SCHEMA_VERSION => {
                schema::validate_v1(&connection, &root, &key)?;
                configure_writable(&connection, deadline)?;
            }
            _ => return Err(CacheError::UnsupportedSchema),
        }
        Ok(Self {
            connection,
            writable: true,
        })
    }

    /// Opens an existing cache without creating files, directories, or changing SQLite state.
    pub fn open_read_only(
        location: &CacheLocation,
        canonical_root: &Path,
        deadline: &Deadline,
    ) -> Result<Self, CacheError> {
        ensure_time(deadline)?;
        if !location.database_path.is_file() {
            return Err(CacheError::Missing);
        }
        let connection =
            Connection::open_with_flags(&location.database_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
                .map_err(|error| map_sqlite_error(error, deadline))?;
        set_busy_timeout(&connection, deadline)?;
        let root = native_path_bytes(canonical_root);
        let key = location.project_key.as_bytes();
        match user_version(&connection, deadline)? {
            SCHEMA_VERSION => schema::validate_v1(&connection, &root, &key)?,
            0 => return Err(CacheError::Incompatible),
            _ => return Err(CacheError::UnsupportedSchema),
        }
        Ok(Self {
            connection,
            writable: false,
        })
    }

    /// Alias for frozen callers: this has the same no-mutation contract as read-only open.
    pub fn open_frozen(
        location: &CacheLocation,
        canonical_root: &Path,
        deadline: &Deadline,
    ) -> Result<Self, CacheError> {
        Self::open_read_only(location, canonical_root, deadline)
    }

    /// Whether this handle may publish snapshots.
    pub fn is_writable(&self) -> bool {
        self.writable
    }

    /// Atomically persists a fully validated candidate and makes each supplied
    /// tier active only for the candidate's own completeness class.
    pub fn publish_candidate(
        &self,
        candidate: &CandidateSnapshot,
        deadline: &Deadline,
    ) -> Result<(), CacheError> {
        if !self.writable {
            return Err(CacheError::ReadOnly);
        }
        ensure_time(deadline)?;
        let encoded = PreparedCandidate::new(candidate, deadline)?;
        ensure_time(deadline)?;
        set_busy_timeout(&self.connection, deadline)?;
        self.connection
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|error| map_sqlite_error(error, deadline))?;
        let result = (|| {
            ensure_time(deadline)?;
            self.connection.execute(
                "INSERT OR IGNORE INTO compatibility (compatibility_id, language_fingerprint, package_fingerprint, created_at_ns) VALUES (?1, ?2, ?3, ?4)",
                params![encoded.compatibility_id.as_slice(), encoded.language_fingerprint.as_slice(), encoded.package_fingerprint.as_slice(), encoded.compatibility_created_at],
            ).map_err(|error| map_sqlite_error(error, deadline))?;
            let stored_compatibility: (Vec<u8>, Vec<u8>, i64) = self
                .connection
                .query_row(
                    "SELECT language_fingerprint, package_fingerprint, created_at_ns FROM compatibility WHERE compatibility_id = ?1",
                    [encoded.compatibility_id.as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(|error| map_sqlite_error(error, deadline))?;
            // Publication timestamps are store-owned. Fingerprint components,
            // unlike timestamps, are exact compatibility content and conflicts
            // must be rejected even when the derived compatibility id matches.
            if stored_compatibility.0 != encoded.language_fingerprint
                || stored_compatibility.1 != encoded.package_fingerprint
            {
                return Err(CacheError::CandidateConflict);
            }
            let existing: Option<ExistingCandidateRow> = self.connection.query_row(
                "SELECT compatibility_id, input_digest, completeness, inventory_file_count, inventory_total_bytes FROM candidates WHERE candidate_id = ?1",
                [encoded.candidate_id.as_slice()],
                |row| {
                    Ok(ExistingCandidateRow {
                        compatibility_id: row.get(0)?,
                        input_digest: row.get(1)?,
                        completeness: row.get(2)?,
                        inventory_file_count: row.get(3)?,
                        inventory_total_bytes: row.get(4)?,
                    })
                },
            ).optional().map_err(|error| map_sqlite_error(error, deadline))?;
            if let Some(existing) = existing {
                if existing.compatibility_id != encoded.compatibility_id
                    || existing.input_digest != encoded.input_digest
                    || existing.completeness != encoded.completeness
                    || existing.inventory_file_count != encoded.inventory_file_count
                    || existing.inventory_total_bytes != encoded.inventory_total_bytes
                {
                    return Err(CacheError::CandidateConflict);
                }
                self.verify_existing_candidate(&encoded, deadline)?;
            } else {
                self.connection.execute(
                    "INSERT INTO candidates (candidate_id, compatibility_id, input_digest, completeness, created_at_ns, inventory_file_count, inventory_total_bytes) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![encoded.candidate_id.as_slice(), encoded.compatibility_id.as_slice(), encoded.input_digest.as_slice(), encoded.completeness, encoded.created_at, encoded.inventory_file_count, encoded.inventory_total_bytes],
                ).map_err(|error| map_sqlite_error(error, deadline))?;
                for omission in &encoded.omissions {
                    ensure_time(deadline)?;
                    self.connection.execute(
                        "INSERT INTO candidate_omissions (candidate_id, path, reason, detail) VALUES (?1, ?2, ?3, ?4)",
                        params![encoded.candidate_id.as_slice(), omission.path, omission.reason, omission.detail],
                    ).map_err(|error| map_sqlite_error(error, deadline))?;
                }
                for file in &encoded.files {
                    ensure_time(deadline)?;
                    self.connection.execute(
                        "INSERT INTO candidate_files (candidate_id, path, language, content_hash, size_bytes, mtime_seconds, mtime_nanoseconds, package_assignment, file_facts, file_subgraph) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                        params![encoded.candidate_id.as_slice(), file.path, file.language, file.content_hash.as_slice(), file.size_bytes, file.mtime_seconds, file.mtime_nanoseconds, file.package_assignment, file.facts, file.subgraph],
                    ).map_err(|error| map_sqlite_error(error, deadline))?;
                }
            }
            let candidate_created_at: i64 = self
                .connection
                .query_row(
                    "SELECT created_at_ns FROM candidates WHERE candidate_id = ?1",
                    [encoded.candidate_id.as_slice()],
                    |row| row.get(0),
                )
                .map_err(|error| map_sqlite_error(error, deadline))?;
            for graph in &encoded.graphs {
                ensure_time(deadline)?;
                let existing: Option<Vec<u8>> = self.connection.query_row(
                    "SELECT graph FROM graph_snapshots WHERE candidate_id = ?1 AND resolver_tier = ?2",
                    params![encoded.candidate_id.as_slice(), graph.tier], |row| row.get(0),
                ).optional().map_err(|error| map_sqlite_error(error, deadline))?;
                if let Some(existing) = existing {
                    if existing != graph.blob {
                        return Err(CacheError::CandidateConflict);
                    }
                    let stored_created_at: i64 = self.connection.query_row(
                        "SELECT created_at_ns FROM graph_snapshots WHERE candidate_id = ?1 AND resolver_tier = ?2",
                        params![encoded.candidate_id.as_slice(), graph.tier],
                        |row| row.get(0),
                    ).map_err(|error| map_sqlite_error(error, deadline))?;
                    let _ = stored_created_at;
                } else {
                    self.connection.execute(
                        "INSERT INTO graph_snapshots (candidate_id, resolver_tier, graph, created_at_ns) VALUES (?1, ?2, ?3, ?4)",
                        params![encoded.candidate_id.as_slice(), graph.tier, graph.blob, candidate_created_at],
                    ).map_err(|error| map_sqlite_error(error, deadline))?;
                }
                // Do this last: a failed file/graph write cannot change visibility.
                self.connection.execute(
                    "INSERT INTO active_snapshots (resolver_tier, completeness, snapshot_id) SELECT resolver_tier, ?1, snapshot_id FROM graph_snapshots WHERE candidate_id = ?2 AND resolver_tier = ?3 ON CONFLICT(resolver_tier, completeness) DO UPDATE SET snapshot_id = excluded.snapshot_id",
                    params![encoded.completeness, encoded.candidate_id.as_slice(), graph.tier],
                ).map_err(|error| map_sqlite_error(error, deadline))?;
            }
            ensure_time(deadline)
        })();
        match result {
            Ok(()) => match self.connection.execute_batch("COMMIT") {
                Ok(()) => Ok(()),
                Err(error) => {
                    let mapped = map_sqlite_error(error, deadline);
                    let _ = self.connection.execute_batch("ROLLBACK");
                    Err(mapped)
                }
            },
            Err(error) => {
                let _ = self.connection.execute_batch("ROLLBACK");
                Err(error)
            }
        }
    }

    /// Loads the currently active graph for an isolated `(tier, completeness)` slot
    /// when it has the requested compatibility fingerprint.
    pub fn load_active(
        &self,
        tier: ResolverCacheTier,
        completeness: CacheCompleteness,
        compatibility: CompatibilityFingerprint,
        deadline: &Deadline,
    ) -> Result<Option<LoadedSnapshot>, CacheError> {
        self.with_read_transaction(deadline, || {
            self.load_active_inner(
                tier,
                completeness,
                Some(compatibility),
                Some(tier),
                deadline,
            )
        })
    }

    /// Loads the newest active candidate for an isolated `(tier, completeness)`
    /// slot without requiring a compatibility match. The returned snapshot contains
    /// all persisted resolver graphs, not only the graph that selected the slot.
    ///
    /// This is safe for frozen callers: it uses the same coherent read transaction
    /// and does not mutate the cache.
    pub fn load_latest_active(
        &self,
        tier: ResolverCacheTier,
        completeness: CacheCompleteness,
        deadline: &Deadline,
    ) -> Result<Option<LoadedSnapshot>, CacheError> {
        self.with_read_transaction(deadline, || {
            self.load_active_inner(tier, completeness, None, None, deadline)
        })
    }

    /// Loads one candidate's facts, files, subgraphs, and every persisted graph.
    pub fn load_candidate(
        &self,
        candidate_id: CandidateId,
        deadline: &Deadline,
    ) -> Result<LoadedSnapshot, CacheError> {
        self.with_read_transaction(deadline, || {
            self.load_candidate_inner(candidate_id, None, deadline)
        })
    }

    /// Loads a single resolver graph without silently accepting a missing row.
    pub fn load_graph(
        &self,
        candidate_id: CandidateId,
        tier: ResolverCacheTier,
        deadline: &Deadline,
    ) -> Result<CodeGraph, CacheError> {
        self.with_read_transaction(deadline, || {
            let blob: Option<Vec<u8>> = self.connection.query_row(
                "SELECT graph FROM graph_snapshots WHERE candidate_id = ?1 AND resolver_tier = ?2",
                params![candidate_id.as_bytes().as_slice(), tier.as_sql()], |row| row.get(0),
            ).optional().map_err(|error| map_sqlite_error(error, deadline))?;
            decode_graph(&blob.ok_or(CacheError::SnapshotMissing)?)
        })
    }

    /// Restores every Scope subgraph through the checked incremental-store seam.
    pub fn hydrate_scope_subgraphs(
        &self,
        candidate_id: CandidateId,
        deadline: &Deadline,
    ) -> Result<IncrementalGraph, CacheError> {
        self.with_read_transaction(deadline, || {
            let loaded = self.load_candidate_inner(candidate_id, None, deadline)?;
            if !loaded
                .tier_graphs
                .iter()
                .any(|(tier, _)| *tier == ResolverCacheTier::Scope)
            {
                return Err(CacheError::SnapshotMissing);
            }
            let mut graph = IncrementalGraph::new();
            for file in loaded.files {
                ensure_time(deadline)?;
                let subgraph = file.subgraph.ok_or(CacheError::SnapshotMissing)?;
                let blob = encode_subgraph(&subgraph)?;
                restore_subgraph(&blob, file.path, &mut graph)?;
            }
            Ok(graph)
        })
    }

    fn with_read_transaction<T>(
        &self,
        deadline: &Deadline,
        operation: impl FnOnce() -> Result<T, CacheError>,
    ) -> Result<T, CacheError> {
        ensure_time(deadline)?;
        self.connection
            .execute_batch("BEGIN")
            .map_err(|error| map_sqlite_error(error, deadline))?;
        let result = operation();
        match result {
            Ok(value) => match self.connection.execute_batch("COMMIT") {
                Ok(()) => Ok(value),
                Err(error) => {
                    let mapped = map_sqlite_error(error, deadline);
                    let _ = self.connection.execute_batch("ROLLBACK");
                    Err(mapped)
                }
            },
            Err(error) => {
                let _ = self.connection.execute_batch("ROLLBACK");
                Err(error)
            }
        }
    }

    fn load_active_inner(
        &self,
        tier: ResolverCacheTier,
        completeness: CacheCompleteness,
        compatibility: Option<CompatibilityFingerprint>,
        only_tier: Option<ResolverCacheTier>,
        deadline: &Deadline,
    ) -> Result<Option<LoadedSnapshot>, CacheError> {
        let active: Option<(Vec<u8>, String, i64, Vec<u8>)> = self.connection.query_row(
            "SELECT c.candidate_id, g.resolver_tier, c.completeness, c.compatibility_id FROM active_snapshots a JOIN graph_snapshots g ON g.snapshot_id = a.snapshot_id JOIN candidates c ON c.candidate_id = g.candidate_id WHERE a.resolver_tier = ?1 AND a.completeness = ?2",
            params![tier.as_sql(), completeness.as_sql()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        ).optional().map_err(|error| map_sqlite_error(error, deadline))?;
        let Some((bytes, graph_tier, candidate_completeness, compatibility_id)) = active else {
            return Ok(None);
        };
        if ResolverCacheTier::from_sql(graph_tier)? != tier
            || CacheCompleteness::from_sql(candidate_completeness)? != completeness
        {
            return Err(CacheError::Corrupt);
        }
        // Validate the persisted fingerprint even if no caller supplied one.
        let compatibility_id = CompatibilityFingerprint::from_bytes(fixed_32(compatibility_id)?);
        if compatibility.is_some_and(|expected| expected != compatibility_id) {
            return Ok(None);
        }
        self.load_candidate_inner(fingerprint_from_blob(bytes)?, only_tier, deadline)
            .map(Some)
    }

    fn verify_existing_candidate(
        &self,
        candidate: &PreparedCandidate,
        deadline: &Deadline,
    ) -> Result<(), CacheError> {
        let count: i64 = self
            .connection
            .query_row(
                "SELECT count(*) FROM candidate_files WHERE candidate_id = ?1",
                [candidate.candidate_id.as_slice()],
                |row| row.get(0),
            )
            .map_err(|error| map_sqlite_error(error, deadline))?;
        if count
            != i64::try_from(candidate.files.len()).map_err(|_| CacheError::InvalidCandidate)?
        {
            return Err(CacheError::CandidateConflict);
        }
        let omissions = {
            let mut statement = self
                .connection
                .prepare("SELECT path, reason, detail FROM candidate_omissions WHERE candidate_id = ?1 ORDER BY path ASC, reason ASC, detail ASC")
                .map_err(|error| map_sqlite_error(error, deadline))?;
            statement
                .query_map([candidate.candidate_id.as_slice()], |row| {
                    Ok(super::CacheOmission {
                        path: row.get(0)?,
                        reason: row.get(1)?,
                        detail: row.get(2)?,
                    })
                })
                .map_err(|error| map_sqlite_error(error, deadline))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| map_sqlite_error(error, deadline))?
        };
        if omissions != candidate.omissions {
            return Err(CacheError::CandidateConflict);
        }
        for file in &candidate.files {
            ensure_time(deadline)?;
            let found: Option<CandidateFileRow> = self
                .connection
                .query_row(
                    "SELECT language, content_hash, size_bytes, mtime_seconds, mtime_nanoseconds, package_assignment, file_facts, file_subgraph FROM candidate_files WHERE candidate_id = ?1 AND path = ?2",
                    params![candidate.candidate_id.as_slice(), file.path],
                    |row| {
                        Ok(CandidateFileRow {
                            language: row.get(0)?,
                            content_hash: row.get(1)?,
                            size_bytes: row.get(2)?,
                            mtime_seconds: row.get(3)?,
                            mtime_nanoseconds: row.get(4)?,
                            package_assignment: row.get(5)?,
                            file_facts: row.get(6)?,
                            file_subgraph: row.get(7)?,
                        })
                    },
                )
                .optional()
                .map_err(|error| map_sqlite_error(error, deadline))?;
            let Some(found) = found else {
                return Err(CacheError::CandidateConflict);
            };
            if found.language != file.language
                || found.content_hash != file.content_hash
                || found.size_bytes != file.size_bytes
                || found.mtime_seconds != file.mtime_seconds
                || found.mtime_nanoseconds != file.mtime_nanoseconds
                || found.package_assignment != file.package_assignment
                || found.file_facts != file.facts
            {
                return Err(CacheError::CandidateConflict);
            }
            match (found.file_subgraph, &file.subgraph) {
                (None, Some(subgraph)) => {
                    self.connection.execute(
                        "UPDATE candidate_files SET file_subgraph = ?1 WHERE candidate_id = ?2 AND path = ?3 AND file_subgraph IS NULL",
                        params![subgraph, candidate.candidate_id.as_slice(), file.path],
                    ).map_err(|error| map_sqlite_error(error, deadline))?;
                }
                (Some(stored), Some(incoming)) if stored != *incoming => {
                    return Err(CacheError::CandidateConflict);
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn load_candidate_inner(
        &self,
        candidate_id: CandidateId,
        only_tier: Option<ResolverCacheTier>,
        deadline: &Deadline,
    ) -> Result<LoadedSnapshot, CacheError> {
        ensure_time(deadline)?;
        let row: Option<CandidateSnapshotRow> = self
            .connection
            .query_row(
                "SELECT c.compatibility_id, k.language_fingerprint, k.package_fingerprint, c.input_digest, c.completeness, c.created_at_ns, k.created_at_ns, c.inventory_file_count, c.inventory_total_bytes FROM candidates c JOIN compatibility k ON k.compatibility_id = c.compatibility_id WHERE c.candidate_id = ?1",
                [candidate_id.as_bytes().as_slice()],
                |row| {
                    Ok(CandidateSnapshotRow {
                        compatibility_id: row.get(0)?,
                        language_fingerprint: row.get(1)?,
                        package_fingerprint: row.get(2)?,
                        input_digest: row.get(3)?,
                        completeness: row.get(4)?,
                        created_at_ns: row.get(5)?,
                        compatibility_created_at_ns: row.get(6)?,
                        inventory_file_count: row.get(7)?,
                        inventory_total_bytes: row.get(8)?,
                    })
                },
            )
            .optional()
            .map_err(|error| map_sqlite_error(error, deadline))?;
        let Some(row) = row else {
            return Err(CacheError::SnapshotMissing);
        };
        let compatibility = CompatibilityFingerprint::from_bytes(fixed_32(row.compatibility_id)?);
        let language_fingerprint =
            super::LanguageFeatureFingerprint::from_bytes(fixed_32(row.language_fingerprint)?);
        let package_fingerprint =
            super::PackageFingerprint::from_bytes(fixed_32(row.package_fingerprint)?);
        if compatibility != CompatibilityFingerprint::new(language_fingerprint, package_fingerprint)
        {
            return Err(CacheError::Corrupt);
        }
        let input_digest = ProjectInputDigest::from_bytes(fixed_32(row.input_digest)?);
        let completeness = CacheCompleteness::from_sql(row.completeness)?;
        let created_at = row.created_at_ns;
        let compatibility_created_at = row.compatibility_created_at_ns;
        let inventory_file_count = nonnegative(row.inventory_file_count)?;
        let inventory_total_bytes = nonnegative(row.inventory_total_bytes)?;
        let omissions = {
            let mut statement = self.connection.prepare(
                "SELECT path, reason, detail FROM candidate_omissions WHERE candidate_id = ?1 ORDER BY path ASC, reason ASC, detail ASC",
            ).map_err(|error| map_sqlite_error(error, deadline))?;
            statement
                .query_map([candidate_id.as_bytes().as_slice()], |row| {
                    Ok(super::CacheOmission {
                        path: row.get(0)?,
                        reason: row.get(1)?,
                        detail: row.get(2)?,
                    })
                })
                .map_err(|error| map_sqlite_error(error, deadline))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| map_sqlite_error(error, deadline))?
        };
        let mut statement = self.connection.prepare("SELECT path, language, content_hash, size_bytes, mtime_seconds, mtime_nanoseconds, package_assignment, file_facts, file_subgraph FROM candidate_files WHERE candidate_id = ?1 ORDER BY path ASC").map_err(|error| map_sqlite_error(error, deadline))?;
        let rows = statement
            .query_map([candidate_id.as_bytes().as_slice()], |row| {
                Ok(LoadedCandidateFileRow {
                    path: row.get::<_, String>(0)?,
                    language: row.get::<_, String>(1)?,
                    content_hash: row.get::<_, Vec<u8>>(2)?,
                    size_bytes: row.get::<_, i64>(3)?,
                    mtime_seconds: row.get::<_, Option<i64>>(4)?,
                    mtime_nanoseconds: row.get::<_, Option<i64>>(5)?,
                    package_assignment: row.get::<_, String>(6)?,
                    file_facts: row.get::<_, Vec<u8>>(7)?,
                    file_subgraph: row.get::<_, Option<Vec<u8>>>(8)?,
                })
            })
            .map_err(|error| map_sqlite_error(error, deadline))?;
        let mut files = Vec::new();
        for row in rows {
            ensure_time(deadline)?;
            let row = row.map_err(|error| map_sqlite_error(error, deadline))?;
            let facts = decode_file_facts(&row.file_facts, None)?;
            if facts.file != row.path || facts.lang != row.language {
                return Err(CacheError::InvalidFacts);
            }
            let subgraph = match row.file_subgraph {
                Some(blob) => {
                    let mut restored = IncrementalGraph::new();
                    restore_subgraph(&blob, row.path.clone(), &mut restored)?;
                    Some(
                        restored
                            .subgraph(&row.path)
                            .cloned()
                            .ok_or(CacheError::InvalidSubgraph)?,
                    )
                }
                None => None,
            };
            files.push(CandidateFileRecord {
                path: row.path,
                language: row.language,
                content_hash: fixed_32(row.content_hash)?,
                size_bytes: nonnegative(row.size_bytes)?,
                mtime: decode_mtime(row.mtime_seconds, row.mtime_nanoseconds)?,
                package_assignment: row.package_assignment,
                facts,
                subgraph,
            });
        }
        let sql = if only_tier.is_some() {
            "SELECT resolver_tier, graph, created_at_ns FROM graph_snapshots WHERE candidate_id = ?1 AND resolver_tier = ?2 ORDER BY resolver_tier ASC"
        } else {
            "SELECT resolver_tier, graph, created_at_ns FROM graph_snapshots WHERE candidate_id = ?1 ORDER BY resolver_tier ASC"
        };
        let mut statement = self
            .connection
            .prepare(sql)
            .map_err(|error| map_sqlite_error(error, deadline))?;
        let mut tier_graphs = Vec::new();
        let mut rows = if let Some(tier) = only_tier {
            statement.query(params![candidate_id.as_bytes().as_slice(), tier.as_sql()])
        } else {
            statement.query([candidate_id.as_bytes().as_slice()])
        }
        .map_err(|error| map_sqlite_error(error, deadline))?;
        while let Some(row) = rows
            .next()
            .map_err(|error| map_sqlite_error(error, deadline))?
        {
            ensure_time(deadline)?;
            let graph_created_at = row
                .get::<_, i64>(2)
                .map_err(|error| map_sqlite_error(error, deadline))?;
            if graph_created_at != created_at {
                return Err(CacheError::Corrupt);
            }
            tier_graphs.push((
                ResolverCacheTier::from_sql(
                    row.get::<_, String>(0)
                        .map_err(|error| map_sqlite_error(error, deadline))?,
                )?,
                decode_graph(
                    &row.get::<_, Vec<u8>>(1)
                        .map_err(|error| map_sqlite_error(error, deadline))?,
                )?,
            ));
        }
        if only_tier.is_some() && tier_graphs.is_empty() {
            return Err(CacheError::SnapshotMissing);
        }
        if tier_graphs
            .iter()
            .any(|(tier, _)| *tier == ResolverCacheTier::Scope)
            && files.iter().any(|file| file.subgraph.is_none())
        {
            return Err(CacheError::Corrupt);
        }
        let computed_file_count = u64::try_from(files.len()).map_err(|_| CacheError::Corrupt)?;
        let computed_total_bytes = files.iter().try_fold(0_u64, |sum, file| {
            sum.checked_add(file.size_bytes).ok_or(CacheError::Corrupt)
        })?;
        let computed_input = ProjectInputDigest::from_inputs(files.iter().map(|file| {
            (
                file.path.as_str(),
                file.language.as_str(),
                file.content_hash,
            )
        }));
        if inventory_file_count != computed_file_count
            || inventory_total_bytes != computed_total_bytes
            || input_digest != computed_input
            || candidate_id
                != CandidateId::new(compatibility, input_digest, completeness, &omissions)
            || !strictly_sorted(
                omissions
                    .iter()
                    .map(|omission| (omission.path.as_str(), omission.reason.as_str())),
            )
        {
            return Err(CacheError::Corrupt);
        }
        Ok(LoadedSnapshot {
            candidate_id,
            compatibility: CompatibilityRecord {
                id: compatibility,
                language_fingerprint,
                package_fingerprint,
                created_at_ns: nonnegative(compatibility_created_at)?,
            },
            input_digest,
            completeness,
            omissions,
            created_at_ns: nonnegative(created_at)?,
            inventory_file_count,
            inventory_total_bytes,
            files,
            tier_graphs,
        })
    }

    /// Reads the current SQLite schema version without mutating the database.
    pub fn schema_version(&self) -> Result<u32, CacheError> {
        self.connection
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .map_err(|error| map_sqlite_error(error, &Deadline::new(None)))
            .and_then(|version| u32::try_from(version).map_err(|_| CacheError::Incompatible))
    }
}

struct PreparedFile {
    path: String,
    language: String,
    content_hash: [u8; 32],
    size_bytes: i64,
    mtime_seconds: Option<i64>,
    mtime_nanoseconds: Option<i64>,
    package_assignment: String,
    facts: Vec<u8>,
    subgraph: Option<Vec<u8>>,
}

struct PreparedGraph {
    tier: &'static str,
    blob: Vec<u8>,
}

struct PreparedCandidate {
    candidate_id: [u8; 32],
    compatibility_id: [u8; 32],
    language_fingerprint: [u8; 32],
    package_fingerprint: [u8; 32],
    input_digest: [u8; 32],
    completeness: i64,
    compatibility_created_at: i64,
    created_at: i64,
    inventory_file_count: i64,
    inventory_total_bytes: i64,
    omissions: Vec<super::CacheOmission>,
    files: Vec<PreparedFile>,
    graphs: Vec<PreparedGraph>,
}

impl PreparedCandidate {
    fn new(candidate: &CandidateSnapshot, deadline: &Deadline) -> Result<Self, CacheError> {
        ensure_time(deadline)?;
        if candidate.compatibility.id
            != CompatibilityFingerprint::new(
                candidate.compatibility.language_fingerprint,
                candidate.compatibility.package_fingerprint,
            )
        {
            return Err(CacheError::InvalidCandidate);
        }
        if candidate.inventory_file_count
            != u64::try_from(candidate.files.len()).map_err(|_| CacheError::InvalidCandidate)?
            || candidate.inventory_total_bytes
                != candidate.files.iter().try_fold(0_u64, |sum, file| {
                    sum.checked_add(file.size_bytes)
                        .ok_or(CacheError::InvalidCandidate)
                })?
        {
            return Err(CacheError::InvalidCandidate);
        }
        let computed_input = ProjectInputDigest::from_inputs(candidate.files.iter().map(|file| {
            (
                file.path.as_str(),
                file.language.as_str(),
                file.content_hash,
            )
        }));
        if candidate.input_digest != computed_input
            || candidate.candidate_id
                != CandidateId::new(
                    candidate.compatibility.id,
                    candidate.input_digest,
                    candidate.completeness,
                    &candidate.omissions,
                )
        {
            return Err(CacheError::InvalidCandidate);
        }
        if !strictly_sorted(candidate.files.iter().map(|file| file.path.as_str()))
            || !strictly_sorted(candidate.tier_graphs.iter().map(|(tier, _)| *tier))
            || !strictly_sorted(
                candidate
                    .omissions
                    .iter()
                    .map(|omission| (omission.path.as_str(), omission.reason.as_str())),
            )
            || candidate.omissions.iter().any(|omission| {
                omission.path.is_empty()
                    || omission.path.contains('\\')
                    || omission.reason.is_empty()
            })
            || (candidate.completeness == CacheCompleteness::Complete
                && !candidate.omissions.is_empty())
        {
            return Err(CacheError::InvalidCandidate);
        }
        let has_scope_graph = candidate
            .tier_graphs
            .iter()
            .any(|(tier, _)| *tier == ResolverCacheTier::Scope);
        if has_scope_graph && candidate.files.iter().any(|file| file.subgraph.is_none()) {
            return Err(CacheError::InvalidCandidate);
        }
        let mut files = Vec::with_capacity(candidate.files.len());
        for file in &candidate.files {
            ensure_time(deadline)?;
            if file.path.is_empty()
                || file.path.contains('\\')
                || file.language.is_empty()
                || !crate::package_assignment::SourcePackageAssignment::is_canonical_identity_for_path(
                    &file.package_assignment,
                    &file.path,
                )
                || file.facts.file != file.path
                || file.facts.lang != file.language
            {
                return Err(CacheError::InvalidCandidate);
            }
            let size_bytes =
                i64::try_from(file.size_bytes).map_err(|_| CacheError::InvalidCandidate)?;
            let (mtime_seconds, mtime_nanoseconds) = encode_mtime(file.mtime)?;
            let facts = encode_file_facts(&file.facts)?;
            let subgraph = match &file.subgraph {
                Some(subgraph) => {
                    let mut check = IncrementalGraph::new();
                    check
                        .try_upsert_subgraph(file.path.clone(), subgraph.clone())
                        .map_err(|_| CacheError::InvalidSubgraph)?;
                    Some(encode_subgraph(subgraph)?)
                }
                None => None,
            };
            files.push(PreparedFile {
                path: file.path.clone(),
                language: file.language.clone(),
                content_hash: file.content_hash,
                size_bytes,
                mtime_seconds,
                mtime_nanoseconds,
                package_assignment: file.package_assignment.clone(),
                facts,
                subgraph,
            });
        }
        let mut graphs = Vec::with_capacity(candidate.tier_graphs.len());
        for (tier, graph) in &candidate.tier_graphs {
            ensure_time(deadline)?;
            graphs.push(PreparedGraph {
                tier: tier.as_sql(),
                blob: encode_graph(graph)?,
            });
        }
        Ok(Self {
            candidate_id: *candidate.candidate_id.as_bytes(),
            compatibility_id: *candidate.compatibility.id.as_bytes(),
            language_fingerprint: *candidate.compatibility.language_fingerprint.as_bytes(),
            package_fingerprint: *candidate.compatibility.package_fingerprint.as_bytes(),
            input_digest: *candidate.input_digest.as_bytes(),
            completeness: candidate.completeness.as_sql(),
            compatibility_created_at: i64::try_from(candidate.compatibility.created_at_ns)
                .map_err(|_| CacheError::InvalidCandidate)?,
            created_at: i64::try_from(candidate.created_at_ns)
                .map_err(|_| CacheError::InvalidCandidate)?,
            inventory_file_count: i64::try_from(candidate.inventory_file_count)
                .map_err(|_| CacheError::InvalidCandidate)?,
            inventory_total_bytes: i64::try_from(candidate.inventory_total_bytes)
                .map_err(|_| CacheError::InvalidCandidate)?,
            omissions: candidate.omissions.clone(),
            files,
            graphs,
        })
    }
}

fn strictly_sorted<T: Ord>(mut values: impl Iterator<Item = T>) -> bool {
    let Some(mut previous) = values.next() else {
        return true;
    };
    for value in values {
        if previous >= value {
            return false;
        }
        previous = value;
    }
    true
}

fn fixed_32(value: Vec<u8>) -> Result<[u8; 32], CacheError> {
    value.try_into().map_err(|_| CacheError::Corrupt)
}

fn fingerprint_from_blob(value: Vec<u8>) -> Result<CandidateId, CacheError> {
    Ok(CandidateId::from_bytes(fixed_32(value)?))
}

fn nonnegative(value: i64) -> Result<u64, CacheError> {
    u64::try_from(value).map_err(|_| CacheError::Corrupt)
}

fn encode_mtime(mtime: Option<MtimeHint>) -> Result<(Option<i64>, Option<i64>), CacheError> {
    match mtime {
        None => Ok((None, None)),
        Some(value) if value.nanoseconds < 1_000_000_000 => Ok((
            Some(value.seconds_since_unix_epoch),
            Some(i64::from(value.nanoseconds)),
        )),
        Some(_) => Err(CacheError::InvalidCandidate),
    }
}

fn decode_mtime(
    seconds: Option<i64>,
    nanoseconds: Option<i64>,
) -> Result<Option<MtimeHint>, CacheError> {
    match (seconds, nanoseconds) {
        (None, None) => Ok(None),
        (Some(seconds_since_unix_epoch), Some(nanoseconds)) => Ok(Some(MtimeHint {
            seconds_since_unix_epoch,
            nanoseconds: u32::try_from(nanoseconds)
                .ok()
                .filter(|value| *value < 1_000_000_000)
                .ok_or(CacheError::Corrupt)?,
        })),
        _ => Err(CacheError::Corrupt),
    }
}

impl ResolverCacheTier {
    fn as_sql(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Scope => "scope",
            Self::Dense => "dense",
        }
    }
    fn from_sql(value: String) -> Result<Self, CacheError> {
        match value.as_str() {
            "name" => Ok(Self::Name),
            "scope" => Ok(Self::Scope),
            "dense" => Ok(Self::Dense),
            _ => Err(CacheError::Corrupt),
        }
    }
}
impl CacheCompleteness {
    fn as_sql(self) -> i64 {
        match self {
            Self::Complete => 0,
            Self::Partial => 1,
        }
    }
    fn from_sql(value: i64) -> Result<Self, CacheError> {
        match value {
            0 => Ok(Self::Complete),
            1 => Ok(Self::Partial),
            _ => Err(CacheError::Corrupt),
        }
    }
}

fn configure_writable(connection: &Connection, deadline: &Deadline) -> Result<(), CacheError> {
    set_busy_timeout(connection, deadline)?;
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(|error| map_sqlite_error(error, deadline))?;
    // These settings intentionally occur outside a transaction: SQLite rejects
    // journal-mode transitions while a transaction is active.
    connection
        .pragma_update(None, "journal_mode", "WAL")
        .map_err(|error| map_sqlite_error(error, deadline))?;
    connection
        .pragma_update(None, "synchronous", "NORMAL")
        .map_err(|error| map_sqlite_error(error, deadline))?;

    let foreign_keys: i64 = connection
        .pragma_query_value(None, "foreign_keys", |row| row.get(0))
        .map_err(|error| map_sqlite_error(error, deadline))?;
    let journal_mode: String = connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .map_err(|error| map_sqlite_error(error, deadline))?;
    let synchronous: i64 = connection
        .pragma_query_value(None, "synchronous", |row| row.get(0))
        .map_err(|error| map_sqlite_error(error, deadline))?;
    if foreign_keys != 1 || !journal_mode.eq_ignore_ascii_case("wal") || synchronous != 1 {
        return Err(CacheError::Access);
    }
    Ok(())
}

fn initialize_or_join_v1(
    connection: &Connection,
    root: &[u8],
    key: &[u8; 32],
    deadline: &Deadline,
) -> Result<(), CacheError> {
    set_busy_timeout(connection, deadline)?;
    connection
        .execute_batch("BEGIN IMMEDIATE")
        .map_err(|error| map_sqlite_error(error, deadline))?;
    // Another opener may have completed initialization while this connection
    // waited for the write lock. Re-read under the lock so two v0 observers do
    // not race into duplicate CREATE statements.
    let result = user_version(connection, deadline).and_then(|version| match version {
        0 => ensure_pristine_v0(connection, deadline)
            .and_then(|()| schema::create_v1(connection, root, key)),
        SCHEMA_VERSION => schema::validate_v1(connection, root, key),
        _ => Err(CacheError::UnsupportedSchema),
    });
    match result {
        Ok(()) => match connection.execute_batch("COMMIT") {
            Ok(()) => Ok(()),
            Err(error) => {
                let mapped = map_sqlite_error(error, deadline);
                let _ = connection.execute_batch("ROLLBACK");
                Err(mapped)
            }
        },
        Err(error) => {
            let _ = connection.execute_batch("ROLLBACK");
            Err(error)
        }
    }
}

fn ensure_pristine_v0(connection: &Connection, deadline: &Deadline) -> Result<(), CacheError> {
    let application_id: i64 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(|error| map_sqlite_error(error, deadline))?;
    let object_count: i64 = connection
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite_error(error, deadline))?;
    if application_id != 0 || object_count != 0 {
        return Err(CacheError::Incompatible);
    }
    Ok(())
}

fn user_version(connection: &Connection, deadline: &Deadline) -> Result<i64, CacheError> {
    connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| map_sqlite_error(error, deadline))
}

fn set_busy_timeout(connection: &Connection, deadline: &Deadline) -> Result<(), CacheError> {
    let timeout = deadline
        .remaining()
        .map_or(LOCK_WAIT_CAP, |remaining| remaining.min(LOCK_WAIT_CAP));
    if timeout.is_zero() {
        return Err(CacheError::Timeout);
    }
    connection
        .busy_timeout(timeout)
        .map_err(|error| map_sqlite_error(error, deadline))
}

fn ensure_time(deadline: &Deadline) -> Result<(), CacheError> {
    if deadline
        .remaining()
        .is_some_and(|remaining| remaining.is_zero())
    {
        Err(CacheError::Timeout)
    } else {
        Ok(())
    }
}

fn map_io_error(error: io::Error) -> CacheError {
    match error.kind() {
        io::ErrorKind::PermissionDenied => CacheError::ReadOnly,
        _ => CacheError::Access,
    }
}

fn map_sqlite_error(error: rusqlite::Error, deadline: &Deadline) -> CacheError {
    if deadline
        .remaining()
        .is_some_and(|remaining| remaining.is_zero())
    {
        return CacheError::Timeout;
    }
    match error {
        rusqlite::Error::SqliteFailure(failure, _) => match failure.code {
            rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked => {
                CacheError::LockContention
            }
            rusqlite::ErrorCode::ReadOnly => CacheError::ReadOnly,
            rusqlite::ErrorCode::NotADatabase | rusqlite::ErrorCode::DatabaseCorrupt => {
                CacheError::Corrupt
            }
            _ => CacheError::Access,
        },
        rusqlite::Error::InvalidColumnType(..)
        | rusqlite::Error::IntegralValueOutOfRange(..)
        | rusqlite::Error::FromSqlConversionFailure(..)
        | rusqlite::Error::Utf8Error(..) => CacheError::Corrupt,
        _ => CacheError::Access,
    }
}

fn native_path_bytes(path: &Path) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        path.as_os_str().as_bytes().to_vec()
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        path.as_os_str()
            .encode_wide()
            .flat_map(u16::to_le_bytes)
            .collect()
    }
    #[cfg(not(any(unix, windows)))]
    {
        path.as_os_str().as_encoded_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::OptionalExtension;
    use tempfile::tempdir;

    fn location(root: &Path, base: &Path) -> CacheLocation {
        CacheLocation::for_project(Some(base), root).expect("injected cache base")
    }

    fn empty_facts(path: &str) -> code2graph::FileFacts {
        code2graph::FileFacts {
            file: path.into(),
            lang: "rust".into(),
            symbols: Vec::new(),
            references: Vec::new(),
            scopes: Vec::new(),
            bindings: Vec::new(),
            ffi_exports: Vec::new(),
        }
    }

    fn candidate(completeness: CacheCompleteness, tier: ResolverCacheTier) -> CandidateSnapshot {
        use super::super::{
            CandidateId, CompatibilityFingerprint, LanguageFeatureFingerprint, PackageFingerprint,
            ProjectInputDigest,
        };
        let file = CandidateFileRecord {
            path: "src/a.rs".into(),
            language: "rust".into(),
            content_hash: [3; 32],
            size_bytes: 0,
            mtime: Some(MtimeHint {
                seconds_since_unix_epoch: 0,
                nanoseconds: 4,
            }),
            package_assignment: "10:assignment8:src/a.rs4:none".into(),
            facts: empty_facts("src/a.rs"),
            subgraph: None,
        };
        let input_digest = ProjectInputDigest::from_inputs([("src/a.rs", "rust", [3; 32])]);
        let omissions = Vec::new();
        let language_fingerprint = LanguageFeatureFingerprint::current();
        let package_fingerprint = PackageFingerprint::from_normalized(["test"]);
        let compatibility_id =
            CompatibilityFingerprint::new(language_fingerprint, package_fingerprint);
        CandidateSnapshot {
            candidate_id: CandidateId::new(
                compatibility_id,
                input_digest,
                completeness,
                &omissions,
            ),
            compatibility: CompatibilityRecord {
                id: compatibility_id,
                language_fingerprint,
                package_fingerprint,
                created_at_ns: 1,
            },
            input_digest,
            completeness,
            omissions,
            created_at_ns: 2,
            inventory_file_count: 1,
            inventory_total_bytes: 0,
            files: vec![file],
            tier_graphs: vec![(
                tier,
                CodeGraph {
                    symbols: Vec::new(),
                    edges: Vec::new(),
                },
            )],
        }
    }

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
            super::super::LanguageFeatureFingerprint::current(),
            super::super::PackageFingerprint::from_normalized(["different-package"]),
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
    fn latest_active_loads_full_snapshot_without_compatibility_or_mutation() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("project");
        fs::create_dir(&root).expect("project");
        let cache_location = location(&root, temp.path());
        let store =
            CacheStore::open_writable(&cache_location, &root, &Deadline::new(None)).expect("open");
        let mut complete = candidate(CacheCompleteness::Complete, ResolverCacheTier::Name);
        complete.tier_graphs.push((
            ResolverCacheTier::Dense,
            CodeGraph {
                symbols: Vec::new(),
                edges: Vec::new(),
            },
        ));
        let partial = candidate(CacheCompleteness::Partial, ResolverCacheTier::Dense);
        store
            .publish_candidate(&complete, &Deadline::new(None))
            .expect("publish complete");
        store
            .publish_candidate(&partial, &Deadline::new(None))
            .expect("publish partial");
        let loaded = store
            .load_latest_active(
                ResolverCacheTier::Name,
                CacheCompleteness::Complete,
                &Deadline::new(None),
            )
            .expect("load")
            .expect("active");
        assert_eq!(loaded.candidate_id, complete.candidate_id);
        assert_eq!(loaded.tier_graphs.len(), 2);
        assert_eq!(
            store
                .load_latest_active(
                    ResolverCacheTier::Dense,
                    CacheCompleteness::Partial,
                    &Deadline::new(None),
                )
                .expect("load partial tier")
                .expect("active")
                .candidate_id,
            partial.candidate_id
        );
        assert!(
            store
                .load_latest_active(
                    ResolverCacheTier::Scope,
                    CacheCompleteness::Complete,
                    &Deadline::new(None),
                )
                .expect("load missing slot")
                .is_none()
        );

        drop(store);
        let database_before = fs::read(&cache_location.database_path).expect("read database");
        let frozen = CacheStore::open_frozen(&cache_location, &root, &Deadline::new(None))
            .expect("open frozen");
        assert_eq!(
            frozen
                .load_latest_active(
                    ResolverCacheTier::Name,
                    CacheCompleteness::Complete,
                    &Deadline::new(None),
                )
                .expect("frozen load")
                .expect("active")
                .candidate_id,
            complete.candidate_id
        );
        assert_eq!(
            fs::read(&cache_location.database_path).expect("read database"),
            database_before
        );
    }

    #[test]
    fn latest_active_rejects_a_corrupt_active_row() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("project");
        fs::create_dir(&root).expect("project");
        let cache_location = location(&root, temp.path());
        let store =
            CacheStore::open_writable(&cache_location, &root, &Deadline::new(None)).expect("open");
        let snapshot = candidate(CacheCompleteness::Complete, ResolverCacheTier::Name);
        store
            .publish_candidate(&snapshot, &Deadline::new(None))
            .expect("publish");
        store
            .connection
            .execute_batch("PRAGMA ignore_check_constraints = ON")
            .expect("allow corruption fixture");
        store
            .connection
            .execute(
                "UPDATE candidates SET completeness = 99 WHERE candidate_id = ?1",
                [snapshot.candidate_id.as_bytes().as_slice()],
            )
            .expect("corrupt row");
        assert!(matches!(
            store.load_latest_active(
                ResolverCacheTier::Name,
                CacheCompleteness::Complete,
                &Deadline::new(None),
            ),
            Err(CacheError::Corrupt)
        ));
    }

    #[test]
    fn signed_mtime_round_trips_before_the_unix_epoch() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("project");
        fs::create_dir(&root).expect("project");
        let cache_location = location(&root, temp.path());
        let store =
            CacheStore::open_writable(&cache_location, &root, &Deadline::new(None)).expect("open");
        let mut snapshot = candidate(CacheCompleteness::Complete, ResolverCacheTier::Name);
        snapshot.files[0].mtime = Some(MtimeHint {
            seconds_since_unix_epoch: -2,
            nanoseconds: 999_999_999,
        });
        store
            .publish_candidate(&snapshot, &Deadline::new(None))
            .expect("publish");
        let loaded = store
            .load_active(
                ResolverCacheTier::Name,
                CacheCompleteness::Complete,
                snapshot.compatibility.id,
                &Deadline::new(None),
            )
            .expect("load")
            .expect("active");
        assert_eq!(loaded.files[0].mtime, snapshot.files[0].mtime);

        let mut invalid = candidate(CacheCompleteness::Partial, ResolverCacheTier::Name);
        invalid.files[0].mtime = Some(MtimeHint {
            seconds_since_unix_epoch: -1,
            nanoseconds: 1_000_000_000,
        });
        assert!(matches!(
            store.publish_candidate(&invalid, &Deadline::new(None)),
            Err(CacheError::InvalidCandidate)
        ));
    }

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
            super::super::CacheOmission {
                path: "z".into(),
                reason: "x".into(),
                detail: "detail".into(),
            },
            super::super::CacheOmission {
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
    fn malformed_and_missing_graph_blobs_are_typed() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("project");
        fs::create_dir(&root).expect("project");
        let cache_location = location(&root, temp.path());
        let store =
            CacheStore::open_writable(&cache_location, &root, &Deadline::new(None)).expect("open");
        let snapshot = candidate(CacheCompleteness::Complete, ResolverCacheTier::Name);
        assert!(matches!(
            store.load_graph(
                snapshot.candidate_id,
                ResolverCacheTier::Name,
                &Deadline::new(None)
            ),
            Err(CacheError::SnapshotMissing)
        ));
        store
            .publish_candidate(&snapshot, &Deadline::new(None))
            .expect("publish");
        store.connection.execute(
            "UPDATE graph_snapshots SET graph = ?1 WHERE candidate_id = ?2 AND resolver_tier = 'name'",
            params![b"not-json".as_slice(), snapshot.candidate_id.as_bytes().as_slice()],
        ).expect("corrupt graph");
        assert!(matches!(
            store.load_graph(
                snapshot.candidate_id,
                ResolverCacheTier::Name,
                &Deadline::new(None)
            ),
            Err(CacheError::Malformed)
        ));
    }

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
    fn concurrent_publishers_commit_whole_candidates() {
        use std::sync::{Arc, Barrier};

        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("project");
        fs::create_dir(&root).expect("project");
        let cache_location = location(&root, temp.path());
        CacheStore::open_writable(&cache_location, &root, &Deadline::new(None))
            .expect("initialize");
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

    #[test]
    fn frozen_missing_cache_creates_nothing() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("project");
        fs::create_dir(&root).expect("project");
        let cache_base = temp.path().join("cache");
        let cache_location = location(&root, &cache_base);
        assert!(matches!(
            CacheStore::open_frozen(&cache_location, &root, &Deadline::new(None)),
            Err(CacheError::Missing)
        ));
        assert!(!cache_base.exists());
    }

    #[test]
    fn creates_and_reopens_exact_v1_identity() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("project");
        fs::create_dir(&root).expect("project");
        let cache_location = location(&root, temp.path());
        let store = CacheStore::open_writable(&cache_location, &root, &Deadline::new(None))
            .expect("create");
        let version = store.schema_version().expect("version");
        assert_eq!(version, SCHEMA_VERSION as u32);
        drop(store);
        CacheStore::open_writable(&cache_location, &root, &Deadline::new(None)).expect("reopen");
        let read_only = CacheStore::open_read_only(&cache_location, &root, &Deadline::new(None))
            .expect("read only");
        assert_eq!(
            read_only.schema_version().expect("read only version"),
            SCHEMA_VERSION as u32
        );
    }

    #[test]
    fn future_schema_does_not_mutate_database() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("project");
        fs::create_dir(&root).expect("project");
        let cache_location = location(&root, temp.path());
        let store = CacheStore::open_writable(&cache_location, &root, &Deadline::new(None))
            .expect("create");
        store
            .connection
            .pragma_update(None, "journal_mode", "DELETE")
            .expect("disable wal");
        store
            .connection
            .pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .expect("future version");
        drop(store);
        assert!(matches!(
            CacheStore::open_writable(&cache_location, &root, &Deadline::new(None)),
            Err(CacheError::UnsupportedSchema)
        ));
        let connection = Connection::open(&cache_location.database_path).expect("inspect");
        assert_eq!(
            user_version(&connection, &Deadline::new(None)).expect("version"),
            SCHEMA_VERSION + 1
        );
        let journal_mode: String = connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .expect("journal mode");
        assert_eq!(journal_mode, "delete");
    }

    #[test]
    fn unrelated_v0_database_is_rejected_without_wal_or_schema_mutation() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("project");
        fs::create_dir(&root).expect("project");
        let cache_location = location(&root, temp.path());
        fs::create_dir_all(&cache_location.directory).expect("cache directory");
        let connection = Connection::open(&cache_location.database_path).expect("unrelated db");
        connection
            .execute_batch("CREATE TABLE unrelated (value INTEGER)")
            .expect("table");
        drop(connection);
        assert!(matches!(
            CacheStore::open_writable(&cache_location, &root, &Deadline::new(None)),
            Err(CacheError::Incompatible)
        ));
        let connection = Connection::open(&cache_location.database_path).expect("inspect");
        let journal_mode: String = connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .expect("journal mode");
        assert_eq!(journal_mode, "delete");
        let exists: i64 = connection
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'unrelated'",
                [],
                |row| row.get(0),
            )
            .expect("unrelated table");
        assert_eq!(exists, 1);
    }

    #[test]
    fn rejects_wrong_root_and_project_key() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("project");
        let other = temp.path().join("other");
        fs::create_dir(&root).expect("project");
        fs::create_dir(&other).expect("other");
        let cache_location = location(&root, temp.path());
        CacheStore::open_writable(&cache_location, &root, &Deadline::new(None)).expect("create");
        assert!(matches!(
            CacheStore::open_read_only(&cache_location, &other, &Deadline::new(None)),
            Err(CacheError::RootMismatch)
        ));
        let other_location = location(&other, temp.path());
        let wrong_key = CacheLocation {
            database_path: cache_location.database_path.clone(),
            ..other_location
        };
        assert!(matches!(
            CacheStore::open_read_only(&wrong_key, &root, &Deadline::new(None)),
            Err(CacheError::RootMismatch)
        ));
    }

    #[test]
    fn rejects_malformed_shape_and_application_id() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("project");
        fs::create_dir(&root).expect("project");
        let cache_location = location(&root, temp.path());
        let store = CacheStore::open_writable(&cache_location, &root, &Deadline::new(None))
            .expect("create");
        store
            .connection
            .pragma_update(None, "application_id", 7_i64)
            .expect("tamper id");
        drop(store);
        assert!(matches!(
            CacheStore::open_read_only(&cache_location, &root, &Deadline::new(None)),
            Err(CacheError::Incompatible)
        ));

        let connection = Connection::open(&cache_location.database_path).expect("tamper");
        connection
            .pragma_update(None, "application_id", schema::APPLICATION_ID)
            .expect("restore id");
        connection
            .execute_batch(
                "DROP TABLE active_snapshots; CREATE TABLE active_snapshots (snapshot_id INTEGER)",
            )
            .expect("malform");
        drop(connection);
        assert!(matches!(
            CacheStore::open_read_only(&cache_location, &root, &Deadline::new(None)),
            Err(CacheError::Incompatible)
        ));
    }

    #[test]
    fn writable_configures_wal_and_foreign_keys() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("project");
        fs::create_dir(&root).expect("project");
        let cache_location = location(&root, temp.path());
        let store = CacheStore::open_writable(&cache_location, &root, &Deadline::new(None))
            .expect("create");
        let foreign_keys: i64 = store
            .connection
            .pragma_query_value(None, "foreign_keys", |row| row.get(0))
            .expect("foreign keys");
        let journal_mode: String = store
            .connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .expect("journal mode");
        assert_eq!(foreign_keys, 1);
        assert_eq!(journal_mode, "wal");
    }

    #[test]
    fn competing_initialization_reports_bounded_lock_contention() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("project");
        fs::create_dir(&root).expect("project");
        let cache_location = location(&root, temp.path());
        fs::create_dir_all(&cache_location.directory).expect("cache directory");
        let blocker = Connection::open(&cache_location.database_path).expect("blocker");
        blocker.execute_batch("BEGIN IMMEDIATE").expect("lock");
        assert!(matches!(
            CacheStore::open_writable(&cache_location, &root, &Deadline::new(None)),
            Err(CacheError::LockContention)
        ));
        blocker.execute_batch("ROLLBACK").expect("unlock");
    }

    #[test]
    fn injected_migration_failure_rolls_back() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("project");
        fs::create_dir(&root).expect("project");
        let cache_location = location(&root, temp.path());
        schema::fail_next_create_for_test();
        assert!(matches!(
            CacheStore::open_writable(&cache_location, &root, &Deadline::new(None)),
            Err(CacheError::Access)
        ));
        let connection = Connection::open(&cache_location.database_path).expect("inspect rollback");
        let meta: Option<String> = connection
            .query_row(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'meta'",
                [],
                |row| row.get(0),
            )
            .optional()
            .expect("inspect schema");
        assert_eq!(meta, None);
        drop(connection);
        CacheStore::open_writable(&cache_location, &root, &Deadline::new(None))
            .expect("retry create");
    }

    fn assert_schema_tamper_rejected(tamper: impl FnOnce(&Connection)) {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("project");
        fs::create_dir(&root).expect("project");
        let cache_location = location(&root, temp.path());
        CacheStore::open_writable(&cache_location, &root, &Deadline::new(None)).expect("create");
        let connection = Connection::open(&cache_location.database_path).expect("tamper");
        tamper(&connection);
        drop(connection);
        assert!(matches!(
            CacheStore::open_frozen(&cache_location, &root, &Deadline::new(None)),
            Err(CacheError::Incompatible)
        ));
    }

    #[test]
    fn rejects_malformed_index_and_foreign_key_contracts() {
        assert_schema_tamper_rejected(|connection| {
            connection
                .execute_batch(
                    "DROP INDEX candidate_files_path_idx;\
                     CREATE INDEX candidate_files_path_idx ON candidate_files (path, candidate_id)",
                )
                .expect("malform index");
        });
        assert_schema_tamper_rejected(|connection| {
            connection
                .execute_batch(
                    "DROP TABLE active_snapshots;\
                     CREATE TABLE active_snapshots (resolver_tier TEXT PRIMARY KEY CHECK (resolver_tier IN ('name', 'scope', 'dense')), snapshot_id INTEGER NOT NULL REFERENCES graph_snapshots(snapshot_id))",
                )
                .expect("malform foreign key");
        });
        assert_schema_tamper_rejected(|connection| {
            connection
                .execute_batch(
                    "DROP TABLE active_snapshots;\
                     CREATE TABLE active_snapshots (resolver_tier TEXT PRIMARY KEY CHECK (resolver_tier IN ('name ', 'scope', 'dense')), snapshot_id INTEGER NOT NULL REFERENCES graph_snapshots(snapshot_id) ON DELETE CASCADE)",
                )
                .expect("malform check literal");
        });
    }

    #[test]
    fn zero_deadline_precedes_candidate_validation_and_publication() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("project");
        fs::create_dir(&root).expect("project");
        let cache_location = location(&root, temp.path());
        let store =
            CacheStore::open_writable(&cache_location, &root, &Deadline::new(None)).expect("store");
        let mut invalid = candidate(CacheCompleteness::Complete, ResolverCacheTier::Name);
        invalid.inventory_file_count = 99;
        assert!(matches!(
            store.publish_candidate(&invalid, &Deadline::new(Some(Duration::ZERO))),
            Err(CacheError::Timeout)
        ));
        let count: i64 = store
            .connection
            .query_row("SELECT count(*) FROM candidates", [], |row| row.get(0))
            .expect("candidate count");
        assert_eq!(count, 0);
    }

    #[test]
    fn zero_deadline_precedes_directory_or_database_creation() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("project");
        fs::create_dir(&root).expect("project");
        let cache_base = temp.path().join("cache");
        let cache_location = location(&root, &cache_base);
        assert!(matches!(
            CacheStore::open_writable(&cache_location, &root, &Deadline::new(Some(Duration::ZERO)),),
            Err(CacheError::Timeout)
        ));
        assert!(!cache_base.exists());
    }

    #[test]
    fn stale_v0_observer_joins_an_already_committed_initialization() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("project");
        fs::create_dir(&root).expect("project");
        let cache_location = location(&root, temp.path());
        fs::create_dir_all(&cache_location.directory).expect("cache directory");
        let stale = Connection::open(&cache_location.database_path).expect("stale observer");
        assert_eq!(
            user_version(&stale, &Deadline::new(None)).expect("observe v0"),
            0
        );

        CacheStore::open_writable(&cache_location, &root, &Deadline::new(None))
            .expect("concurrent initializer");
        initialize_or_join_v1(
            &stale,
            &native_path_bytes(&root),
            &cache_location.project_key.as_bytes(),
            &Deadline::new(None),
        )
        .expect("stale observer joins v1");
    }

    #[test]
    fn concurrent_v0_openers_join_one_atomic_migration() {
        use std::sync::{Arc, Barrier};

        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("project");
        fs::create_dir(&root).expect("project");
        let cache_location = location(&root, temp.path());
        fs::create_dir_all(&cache_location.directory).expect("cache directory");
        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                let root = root.clone();
                let cache_location = cache_location.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    CacheStore::open_writable(&cache_location, &root, &Deadline::new(None))
                })
            })
            .collect();
        for handle in handles {
            handle
                .join()
                .expect("opener thread")
                .expect("joined migration");
        }
        CacheStore::open_frozen(&cache_location, &root, &Deadline::new(None))
            .expect("valid final schema");
    }

    #[test]
    fn migration_failure_hook_is_parallel_thread_local() {
        use std::sync::{Arc, Barrier};

        let temp = tempdir().expect("tempdir");
        let failed_root = temp.path().join("failed-project");
        let normal_root = temp.path().join("normal-project");
        fs::create_dir(&failed_root).expect("failed project");
        fs::create_dir(&normal_root).expect("normal project");
        let failed_location = location(&failed_root, &temp.path().join("failed-cache"));
        let normal_location = location(&normal_root, &temp.path().join("normal-cache"));
        let barrier = Arc::new(Barrier::new(2));
        let failed_barrier = Arc::clone(&barrier);
        let failed = std::thread::spawn(move || {
            schema::fail_next_create_for_test();
            failed_barrier.wait();
            CacheStore::open_writable(&failed_location, &failed_root, &Deadline::new(None))
        });
        let normal = std::thread::spawn(move || {
            barrier.wait();
            CacheStore::open_writable(&normal_location, &normal_root, &Deadline::new(None))
        });
        assert!(matches!(
            failed.join().expect("failure thread"),
            Err(CacheError::Access)
        ));
        normal
            .join()
            .expect("normal thread")
            .expect("unaffected migration");
    }

    #[test]
    fn corrupt_database_has_typed_error_without_sql_text() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("project");
        fs::create_dir(&root).expect("project");
        let cache_location = location(&root, temp.path());
        fs::create_dir_all(&cache_location.directory).expect("cache directory");
        fs::write(&cache_location.database_path, b"not a sqlite database")
            .expect("corrupt database");
        let error = match CacheStore::open_frozen(&cache_location, &root, &Deadline::new(None)) {
            Err(error) => error,
            Ok(_) => panic!("must reject corruption"),
        };
        assert!(matches!(&error, CacheError::Corrupt));
        assert_eq!(error.to_string(), "cache database is corrupt");
    }

    #[test]
    fn frozen_reads_committed_wal_without_sidecar_mutation() {
        fn directory_state(path: &Path) -> Vec<(std::ffi::OsString, u64, std::time::SystemTime)> {
            let mut state: Vec<_> = fs::read_dir(path)
                .expect("read cache directory")
                .map(|entry| {
                    let entry = entry.expect("directory entry");
                    let metadata = entry.metadata().expect("metadata");
                    (
                        entry.file_name(),
                        metadata.len(),
                        metadata.modified().expect("modified time"),
                    )
                })
                .collect();
            state.sort_by(|left, right| left.0.cmp(&right.0));
            state
        }

        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("project");
        fs::create_dir(&root).expect("project");
        let cache_location = location(&root, temp.path());
        let writer = CacheStore::open_writable(&cache_location, &root, &Deadline::new(None))
            .expect("writer");
        writer
            .connection
            .execute(
                "INSERT INTO compatibility (compatibility_id, language_fingerprint, package_fingerprint, created_at_ns) VALUES (?1, ?2, ?3, 0)",
                params![vec![7_u8; 32], vec![8_u8; 32], vec![9_u8; 32]],
            )
            .expect("committed WAL row");
        let before = directory_state(&cache_location.directory);
        let frozen = CacheStore::open_frozen(&cache_location, &root, &Deadline::new(None))
            .expect("frozen WAL reader");
        let rows: i64 = frozen
            .connection
            .query_row("SELECT count(*) FROM compatibility", [], |row| row.get(0))
            .expect("read WAL row");
        assert_eq!(rows, 1);
        assert_eq!(directory_state(&cache_location.directory), before);
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn stores_non_utf8_root_as_native_bytes() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let temp = tempdir().expect("tempdir");
        let root = temp.path().join(OsStr::from_bytes(b"project-\xff"));
        fs::create_dir(&root).expect("project");
        let cache_location = location(&root, temp.path());
        let store = CacheStore::open_writable(&cache_location, &root, &Deadline::new(None))
            .expect("create");
        let stored: Vec<u8> = store
            .connection
            .query_row("SELECT canonical_root FROM meta", [], |row| row.get(0))
            .expect("stored root");
        assert_eq!(stored, root.as_os_str().as_bytes());
    }

    #[cfg(unix)]
    #[test]
    fn native_path_bytes_preserve_invalid_unix_bytes_without_filesystem_access() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let path = Path::new(OsStr::from_bytes(b"/canonical/project-\xff"));
        assert_eq!(native_path_bytes(path), b"/canonical/project-\xff");
    }

    #[cfg(unix)]
    #[test]
    fn readonly_directory_is_a_typed_error() {
        use std::os::unix::fs::PermissionsExt;

        // Unix superusers bypass mode bits, so this filesystem assertion is not
        // meaningful in root-run containers.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("project");
        let base = temp.path().join("readonly");
        fs::create_dir(&root).expect("project");
        fs::create_dir(&base).expect("base");
        fs::set_permissions(&base, fs::Permissions::from_mode(0o555)).expect("read only");
        let cache_location = location(&root, &base);
        let result = CacheStore::open_writable(&cache_location, &root, &Deadline::new(None));
        fs::set_permissions(&base, fs::Permissions::from_mode(0o755)).expect("restore permissions");
        assert!(matches!(result, Err(CacheError::ReadOnly)));
    }
}
