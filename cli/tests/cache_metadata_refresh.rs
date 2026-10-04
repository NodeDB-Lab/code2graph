// SPDX-License-Identifier: Apache-2.0

use std::fs::{self, File, FileTimes};
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::Connection;
use serde_json::Value;

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    _home: PathBuf,
    cache_directory: PathBuf,
    database: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("project");
        let home = temp.path().join("home");
        fs::create_dir(&root).expect("project directory");
        fs::create_dir(&home).expect("home directory");
        for (path, source) in [
            ("a.rs", "pub fn alpha() {}\n"),
            ("b.rs", "pub fn bravo() { alpha(); }\n"),
            ("c.rs", "pub fn charlie() { bravo(); }\n"),
        ] {
            let path = root.join(path);
            fs::write(&path, source).expect("source");
            set_mtime(&path, 1_000_000_000);
        }
        let mut fixture = Self {
            _temp: temp,
            root: root.canonicalize().expect("canonical project"),
            _home: home,
            cache_directory: PathBuf::new(),
            database: PathBuf::new(),
        };
        let paths = fixture.run(&["cache", "path"]);
        fixture.cache_directory =
            PathBuf::from(paths["cache_dir"].as_str().expect("cache directory"));
        fixture.database = PathBuf::from(paths["database_path"].as_str().expect("database path"));
        #[cfg(unix)]
        assert!(fixture.cache_directory.starts_with(&fixture._home));
        fixture
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_c2g"));
        command.current_dir(&self.root);
        #[cfg(unix)]
        command
            .env("HOME", &self._home)
            .env("XDG_CACHE_HOME", self._home.join("cache"));
        // Windows known folders use unique canonical roots to isolate project keys.
        // Drop removes only this partition.
        command.env("CODE2GRAPH_AUTO_PRUNE", "off");
        command
    }

    fn run(&self, args: &[&str]) -> Value {
        let output = self
            .command()
            .args(args)
            .arg("--json")
            .output()
            .expect("run c2g");
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.stderr.is_empty(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).expect("JSON output")
    }

    fn touch(&self, seconds: u64) -> SystemTime {
        let path = self.root.join("a.rs");
        let before = fs::metadata(&path)
            .expect("metadata")
            .modified()
            .expect("mtime");
        let after = set_mtime(&path, seconds);
        assert_ne!(before, after);
        after
    }

    fn stored_mtime(&self) -> SystemTime {
        let connection = Connection::open(&self.database).expect("cache database");
        let (seconds, nanoseconds): (i64, u32) = connection
            .query_row(
                "SELECT mtime_seconds, mtime_nanoseconds FROM candidate_files WHERE path = 'a.rs'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("stored mtime");
        UNIX_EPOCH
            + Duration::new(
                u64::try_from(seconds).expect("nonnegative seconds"),
                nanoseconds,
            )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if !self.cache_directory.as_os_str().is_empty()
            && self.cache_directory.exists()
            && let Err(error) = fs::remove_dir_all(&self.cache_directory)
        {
            if std::thread::panicking() {
                eprintln!("remove fixture cache partition: {error}");
            } else {
                panic!("remove fixture cache partition: {error}");
            }
        }
    }
}

fn set_mtime(path: &std::path::Path, seconds: u64) -> SystemTime {
    let desired = UNIX_EPOCH + Duration::from_secs(seconds);
    File::options()
        .write(true)
        .open(path)
        .expect("source file")
        .set_times(FileTimes::new().set_modified(desired))
        .expect("set mtime");
    let actual = fs::metadata(path)
        .expect("metadata")
        .modified()
        .expect("mtime");
    assert_eq!(actual, desired);
    actual
}

fn assert_identity(value: &Value, snapshot: &Value) {
    assert_eq!(value["status"], "ok");
    assert_eq!(value["project"]["snapshot"], *snapshot);
    assert_eq!(value["project"]["freshness"], "fresh");
}

#[test]
fn timestamp_only_changes_refresh_index_symbols_and_status_then_reuse_cache() {
    let fixture = Fixture::new();
    let initial = fixture.run(&["index"]);
    assert_eq!(initial["results"]["inventory_file_count"], 3);
    let snapshot = &initial["project"]["snapshot"];
    for (index, args) in [&["index"][..], &["symbols", "alpha"][..], &["status"][..]]
        .into_iter()
        .enumerate()
    {
        let actual = fixture.touch(1_000_000_010 + index as u64 * 10);
        let refreshed = fixture.run(args);
        assert_identity(&refreshed, snapshot);
        assert_eq!(fixture.stored_mtime(), actual);
        let repeated = fixture.run(args);
        assert_identity(&repeated, snapshot);
        assert_eq!(repeated["project"]["cache"], "hit");
        assert_eq!(fixture.stored_mtime(), actual);
        if args[0] == "index" {
            assert_eq!(refreshed["results"]["changed"], 0);
            assert_eq!(repeated["results"]["changed"], 0);
        }
        if args[0] == "symbols" {
            assert_eq!(refreshed["total"], 1);
            assert_eq!(repeated["results"], refreshed["results"]);
        }
    }
}

#[test]
fn trust_mtime_refreshes_changed_hints_and_reuses_unchanged_hints() {
    let fixture = Fixture::new();
    let initial = fixture.run(&["index", "--trust-mtime"]);
    let snapshot = &initial["project"]["snapshot"];
    let actual = fixture.touch(1_000_000_100);
    let refreshed = fixture.run(&["index", "--trust-mtime"]);
    assert_identity(&refreshed, snapshot);
    assert_eq!(fixture.stored_mtime(), actual);
    assert_eq!(refreshed["results"]["changed"], 0);
    assert_eq!(refreshed["results"]["plan_decisions"]["reuse_facts"], 3);
    assert_eq!(refreshed["results"]["plan_decisions"]["extract"], 0);
    let repeated = fixture.run(&["index", "--trust-mtime"]);
    assert_identity(&repeated, snapshot);
    assert_eq!(repeated["project"]["cache"], "hit");
    assert_eq!(repeated["results"]["changed"], 0);
    assert_eq!(repeated["results"]["attempts"], 0);
    assert_eq!(
        repeated["results"]["plan_decisions"],
        serde_json::json!({
            "need_hash": 0, "reuse_facts": 0, "extract": 0,
            "remove": 0, "omit": 0,
        })
    );
    assert_eq!(fixture.stored_mtime(), actual);
}

#[test]
fn default_refresh_detects_same_size_content_changes_with_unchanged_mtime() {
    let fixture = Fixture::new();
    let initial = fixture.run(&["index"]);
    let path = fixture.root.join("a.rs");
    let before = fs::metadata(&path).expect("metadata");
    fs::write(&path, "pub fn delta() {}\n").expect("changed source");
    assert_eq!(fs::metadata(&path).expect("metadata").len(), before.len());
    let restored = set_mtime(&path, 1_000_000_000);
    assert_eq!(restored, before.modified().expect("mtime"));
    let refreshed = fixture.run(&["index"]);
    assert_eq!(refreshed["status"], "ok");
    assert_ne!(
        refreshed["project"]["snapshot"],
        initial["project"]["snapshot"]
    );
    assert_eq!(refreshed["results"]["changed"], 1);
    let symbols = fixture.run(&["symbols", "delta"]);
    assert_eq!(symbols["total"], 1);
    assert_eq!(
        symbols["project"]["snapshot"],
        refreshed["project"]["snapshot"]
    );
    let repeated = fixture.run(&["index"]);
    assert_eq!(repeated["results"]["changed"], 0);
    assert_eq!(repeated["project"]["cache"], "hit");
}
