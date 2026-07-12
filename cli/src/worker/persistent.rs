// SPDX-License-Identifier: Apache-2.0

//! A long-lived worker subprocess that services many extraction requests over
//! one stdin/stdout pipe. Spawning the worker binary (a large executable) once
//! and streaming files through it removes the per-file spawn cost that dominates
//! a cold index, while preserving the one-worker-per-request process isolation:
//! a crash still contains to the worker, and the pool respawns a fresh one.

use std::io::{BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::thread::{self, JoinHandle};

use code2graph::{FileFacts, QueryBindingRule};

use crate::InventoryFile;

use super::WORKER_SENTINEL;
use super::frame::{decode_response_frame, encode_frame, read_frame};
use super::platform::{self, Containment, KillHandle};
use super::process::{STDERR_TAIL_MAX, WorkerFailure, classify_response_error, drain_tail};
use super::protocol::{
    REQUEST_FRAME_MAX, RESPONSE_FRAME_MAX, RequestId, WorkerRequest, validate_response,
};

/// A handle owning one persistent worker subprocess plus the plumbing that keeps
/// it alive: its stdin, a buffered stdout reader, the process-group containment,
/// and a thread continuously draining stderr (an undrained stderr pipe would
/// eventually fill and block the worker).
pub struct PersistentWorker {
    child: Child,
    /// `Option` so `Drop` can close stdin (signalling EOF) before terminating.
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    containment: Containment,
    stderr: Option<JoinHandle<std::io::Result<Vec<u8>>>>,
}

impl PersistentWorker {
    /// Spawns a fresh contained worker and starts draining its stderr. No request
    /// is written here; the worker blocks reading its first frame.
    pub fn spawn(executable: &Path) -> Result<Self, WorkerFailure> {
        let mut command = Command::new(executable);
        command
            .arg(WORKER_SENTINEL)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        platform::configure_command(&mut command);
        let mut child = command.spawn().map_err(|_| WorkerFailure::Spawn)?;
        let mut containment = match platform::contain(&mut child) {
            Ok(value) => value,
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(WorkerFailure::Spawn);
            }
        };
        let (stdin, stdout, stderr) =
            match (child.stdin.take(), child.stdout.take(), child.stderr.take()) {
                (Some(stdin), Some(stdout), Some(stderr)) => (stdin, stdout, stderr),
                _ => {
                    platform::terminate(&mut containment, &mut child);
                    let _ = child.wait();
                    return Err(WorkerFailure::Transport);
                }
            };
        let stderr = match thread::Builder::new()
            .name("code2graph-worker-stderr".into())
            .spawn(move || drain_tail(stderr, STDERR_TAIL_MAX))
        {
            Ok(handle) => handle,
            Err(_) => {
                platform::terminate(&mut containment, &mut child);
                let _ = child.wait();
                return Err(WorkerFailure::Transport);
            }
        };
        Ok(Self {
            child,
            stdin: Some(stdin),
            stdout: BufReader::new(stdout),
            containment,
            stderr: Some(stderr),
        })
    }

    /// A cheap, `Send` capability to kill this worker's process group without
    /// `&mut self`. A blocked [`extract_one`](Self::extract_one) read unblocks
    /// (the worker's stdout closes) when this fires.
    pub fn kill_handle(&self) -> KillHandle {
        platform::kill_handle(&self.containment)
    }

    /// Kills this worker's process group immediately. Idempotent.
    pub fn kill(&self) {
        self.kill_handle().kill();
    }

    /// Services one file on the live worker: writes its request frame, then reads
    /// exactly one response frame. Any transport failure means the worker died
    /// (a killed worker makes the response read return EOF), surfaced as
    /// [`WorkerFailure::Transport`]; a surviving worker's typed extraction error
    /// surfaces as [`WorkerFailure::Remote`]. This does not enforce a deadline —
    /// the pool's monitor kills the worker on a breach, unblocking the read here.
    pub fn extract_one(
        &mut self,
        file: &InventoryFile,
        request_id: RequestId,
        rules: &[QueryBindingRule],
    ) -> Result<FileFacts, WorkerFailure> {
        let request = WorkerRequest::from_inventory_file(request_id, file, rules)
            .map_err(|_| WorkerFailure::Protocol)?;
        let frame =
            encode_frame(&request, REQUEST_FRAME_MAX).map_err(|_| WorkerFailure::Protocol)?;
        let stdin = self.stdin.as_mut().ok_or(WorkerFailure::Transport)?;
        // A write failure means the worker has already gone away.
        if stdin
            .write_all(&frame)
            .and_then(|()| stdin.flush())
            .is_err()
        {
            return Err(WorkerFailure::Transport);
        }
        match read_frame(&mut self.stdout, RESPONSE_FRAME_MAX) {
            // Clean EOF or a truncated/undecodable stream both mean the worker
            // died or desynced; either way the connection is no longer usable.
            Ok(None) | Err(_) => Err(WorkerFailure::Transport),
            Ok(Some(frame)) => {
                let response =
                    decode_response_frame(&frame).map_err(|_| WorkerFailure::Protocol)?;
                validate_response(&response, &request)
                    .map_err(classify_response_error)?
                    .map_err(|remote| WorkerFailure::Remote(remote.code))
            }
        }
    }
}

impl Drop for PersistentWorker {
    fn drop(&mut self) {
        // Close stdin first so a healthy worker sees EOF and exits its loop.
        drop(self.stdin.take());
        // Defensively terminate the whole group in case the worker is wedged
        // mid-extraction; this also closes the child's stderr so the drain
        // thread's read returns and its join cannot hang.
        platform::terminate(&mut self.containment, &mut self.child);
        let _ = self.child.wait();
        if let Some(handle) = self.stderr.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    use code2graph::Language;
    use tempfile::TempDir;

    use super::*;
    use crate::ProjectPath;
    use crate::worker::WorkerErrorCode;

    // A canned worker response frame (length prefix + msgpack) carrying a typed
    // remote extraction error for `request_id == 17`. Reused for every request a
    // fake worker services, so a healthy stream yields `Remote(Extraction)`.
    const CANNED_RESPONSE: &str = "\\000\\000\\000\\020\\205\\000\\001\\001\\002\\002\\021\\003\\300\\004\\202\\000\\001\\001\\241x";

    // A POSIX helper that reads one big-endian u32 length prefix, then consumes
    // exactly that many payload bytes. `bs=1` prevents dd from over-reading past
    // a single frame on the shared pipe.
    const READ_FRAME: &str = "read_frame() {\n  set -- $(dd bs=1 count=4 2>/dev/null | od -An -tu1)\n  [ \"$#\" -eq 4 ] || return 1\n  n=$(( $1 * 16777216 + $2 * 65536 + $3 * 256 + $4 ))\n  dd bs=1 count=\"$n\" 2>/dev/null >/dev/null\n  return 0\n}\n";

    fn script(body: &str) -> (TempDir, PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("persistent-fixture.sh");
        fs::write(&path, format!("#!/bin/sh\n{READ_FRAME}{body}\n")).unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&path, permissions).unwrap();
        (directory, path)
    }

    fn inventory_file() -> InventoryFile {
        let bytes = b"fn run() {}".to_vec();
        InventoryFile {
            path: ProjectPath::new(Path::new("src/a.rs")).unwrap(),
            language: Language::Rust,
            text: String::from_utf8(bytes.clone()).unwrap(),
            blake3: blake3::hash(&bytes).to_hex().to_string(),
            bytes,
            mtime: None,
        }
    }

    #[test]
    fn one_worker_services_multiple_requests_on_a_single_process() {
        // Loops: read a frame, emit the canned response, repeat until stdin EOF.
        let (_dir, path) = script(&format!(
            "while read_frame; do printf '{CANNED_RESPONSE}'; done"
        ));
        let mut worker = PersistentWorker::spawn(&path).expect("spawn persistent worker");
        let file = inventory_file();
        let first = worker.extract_one(&file, 17, &[]);
        let second = worker.extract_one(&file, 17, &[]);
        assert!(
            matches!(
                first,
                Err(WorkerFailure::Remote(WorkerErrorCode::Extraction))
            ),
            "first request should be serviced, got {first:?}"
        );
        assert!(
            matches!(
                second,
                Err(WorkerFailure::Remote(WorkerErrorCode::Extraction))
            ),
            "second request proves the same process persisted, got {second:?}"
        );
    }

    #[test]
    fn a_worker_that_exits_after_one_frame_fails_the_next_request_as_transport() {
        // Services one frame, then exits — the stream closes for the next request.
        let (_dir, path) = script(&format!("read_frame; printf '{CANNED_RESPONSE}'; exit 0"));
        let mut worker = PersistentWorker::spawn(&path).expect("spawn persistent worker");
        let file = inventory_file();
        let first = worker.extract_one(&file, 17, &[]);
        assert!(
            matches!(
                first,
                Err(WorkerFailure::Remote(WorkerErrorCode::Extraction))
            ),
            "first request should be serviced, got {first:?}"
        );
        let second = worker.extract_one(&file, 17, &[]);
        assert!(
            matches!(second, Err(WorkerFailure::Transport)),
            "a dead worker must surface as Transport, got {second:?}"
        );
    }

    #[test]
    fn killing_the_process_group_unblocks_a_stuck_response_read() {
        // Consumes the request but never responds, so the read below blocks until
        // the kill handle fires and the worker's stdout closes.
        let (_dir, path) = script("read_frame; sleep 30");
        let mut worker = PersistentWorker::spawn(&path).expect("spawn persistent worker");
        let kill = worker.kill_handle();
        let killer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            kill.kill();
        });
        let started = Instant::now();
        let outcome = worker.extract_one(&inventory_file(), 17, &[]);
        assert!(
            outcome.is_err(),
            "a killed worker must not return facts, got {outcome:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "the kill must unblock the read promptly"
        );
        killer.join().unwrap();
    }

    #[test]
    fn spawning_a_missing_executable_is_a_spawn_failure() {
        let missing = PathBuf::from("/nonexistent/code2graph-worker-fixture");
        assert!(matches!(
            PersistentWorker::spawn(&missing),
            Err(WorkerFailure::Spawn)
        ));
    }

    #[test]
    fn dropping_a_stuck_worker_terminates_and_reaps_without_hanging() {
        let (_dir, path) = script("read_frame; sleep 30");
        let mut worker = PersistentWorker::spawn(&path).expect("spawn persistent worker");
        // Prime the worker so it is blocked in `sleep 30` with a full stderr-free
        // pipe; dropping must terminate the group and join the stderr thread.
        let _ = worker.stdin.as_mut().map(|stdin| {
            let request = WorkerRequest::from_inventory_file(17, &inventory_file(), &[]).unwrap();
            let frame = encode_frame(&request, REQUEST_FRAME_MAX).unwrap();
            let _ = stdin.write_all(&frame).and_then(|()| stdin.flush());
        });
        let started = Instant::now();
        drop(worker);
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "drop must not wait for the worker's own timeout"
        );
    }
}
