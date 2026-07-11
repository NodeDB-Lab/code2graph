// SPDX-License-Identifier: Apache-2.0

//! SQLite cache opening, schema migration, and identity validation.

use std::fs;
use std::io;
use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags};

use crate::Deadline;

use super::schema::{self, SCHEMA_VERSION};
use super::{CacheError, CacheLocation};

const LOCK_WAIT_CAP: Duration = Duration::from_secs(2);

/// An open project-cache database. The SQLite connection remains private so
/// future cache publication can preserve the transaction protocol.
pub struct CacheStore {
    connection: Connection,
}

impl CacheStore {
    /// Opens a writable cache, creating and atomically initializing a new v1 database.
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
                configure_writable(&connection, deadline)?;
                initialize_or_join_v1(&connection, &root, &key, deadline)?;
            }
            SCHEMA_VERSION => {
                schema::validate_v1(&connection, &root, &key)?;
                configure_writable(&connection, deadline)?;
            }
            _ => return Err(CacheError::UnsupportedSchema),
        }
        Ok(Self { connection })
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
        let root = native_path_bytes(canonical_root);
        let key = location.project_key.as_bytes();
        match user_version(&connection, deadline)? {
            SCHEMA_VERSION => schema::validate_v1(&connection, &root, &key)?,
            0 => return Err(CacheError::Incompatible),
            _ => return Err(CacheError::UnsupportedSchema),
        }
        Ok(Self { connection })
    }

    /// Alias for frozen callers: this has the same no-mutation contract as read-only open.
    pub fn open_frozen(
        location: &CacheLocation,
        canonical_root: &Path,
        deadline: &Deadline,
    ) -> Result<Self, CacheError> {
        Self::open_read_only(location, canonical_root, deadline)
    }

    /// Reads the current SQLite schema version without mutating the database.
    pub fn schema_version(&self) -> Result<u32, CacheError> {
        self.connection
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .map_err(|error| map_sqlite_error(error, &Deadline::new(None)))
            .and_then(|version| u32::try_from(version).map_err(|_| CacheError::Incompatible))
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
        0 => schema::create_v1(connection, root, key),
        SCHEMA_VERSION => schema::validate_v1(connection, root, key),
        _ => Err(CacheError::UnsupportedSchema),
    });
    match result {
        Ok(()) => connection
            .execute_batch("COMMIT")
            .map_err(|error| map_sqlite_error(error, deadline)),
        Err(error) => {
            let _ = connection.execute_batch("ROLLBACK");
            Err(error)
        }
    }
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
                "INSERT INTO compatibility (compatibility_id, created_at_ns) VALUES (?1, 0)",
                [vec![7_u8; 32]],
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

    #[cfg(unix)]
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
