// SPDX-License-Identifier: Apache-2.0

//! Parent-side isolated worker process execution.

use std::io::{Read, Write};
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use code2graph::{FileFacts, QueryBindingRule};

use crate::{Cancellation, CliError, Deadline, InventoryFile};

use super::WORKER_SENTINEL;
use super::frame::{decode_response_frame, encode_frame};
use super::platform;
use super::protocol::{
    REQUEST_FRAME_MAX, RESPONSE_FRAME_MAX, RequestId, WorkerErrorCode, WorkerProtocolError,
    WorkerRequest, validate_response,
};

pub(super) const STDERR_TAIL_MAX: usize = 64 * 1024;

/// Source-free failures at the worker process boundary.
#[derive(Debug, thiserror::Error)]
pub enum WorkerFailure {
    #[error("worker could not be started")]
    Spawn,
    #[error("worker transport failed")]
    Transport,
    #[error("worker protocol failed")]
    Protocol,
    #[error("worker exited unsuccessfully")]
    Exit,
    #[error("worker timed out")]
    Timeout,
    #[error("worker was cancelled")]
    Cancelled,
    #[error("worker returned a typed error ({0:?})")]
    Remote(WorkerErrorCode),
}

impl From<WorkerFailure> for CliError {
    fn from(value: WorkerFailure) -> Self {
        match value {
            WorkerFailure::Timeout => Self::Timeout,
            WorkerFailure::Cancelled => Self::Cancelled,
            other => Self::Worker(other),
        }
    }
}

/// Extracts one admitted file in a fresh worker using the current executable.
/// `rules` are project-supplied custom query-binding rules (from
/// `code2graph.toml`) carried to the worker alongside the built-in defaults.
pub fn extract_inventory_file(
    file: &InventoryFile,
    request_id: RequestId,
    deadline: &Deadline,
    cancellation: &dyn Cancellation,
    rules: &[QueryBindingRule],
) -> Result<FileFacts, CliError> {
    let executable = std::env::current_exe().map_err(|_| WorkerFailure::Spawn)?;
    extract_with_executable(&executable, file, request_id, deadline, cancellation, rules)
        .map_err(Into::into)
}

fn extract_with_executable(
    executable: &Path,
    file: &InventoryFile,
    request_id: RequestId,
    deadline: &Deadline,
    cancellation: &dyn Cancellation,
    rules: &[QueryBindingRule],
) -> Result<FileFacts, WorkerFailure> {
    deadline.check(cancellation).map_err(check_failure)?;
    let request = WorkerRequest::from_inventory_file(request_id, file, rules)
        .map_err(|_| WorkerFailure::Protocol)?;
    let frame = encode_frame(&request, REQUEST_FRAME_MAX).map_err(|_| WorkerFailure::Protocol)?;
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
    let writer = match thread::Builder::new()
        .name("code2graph-worker-stdin".into())
        .spawn(move || -> std::io::Result<()> {
            let mut stdin = stdin;
            stdin.write_all(&frame)?;
            stdin.flush()
        }) {
        Ok(handle) => handle,
        Err(_) => {
            platform::terminate(&mut containment, &mut child);
            let _ = child.wait();
            return Err(WorkerFailure::Transport);
        }
    };
    let output = match thread::Builder::new()
        .name("code2graph-worker-stdout".into())
        .spawn(move || drain_bounded(stdout, RESPONSE_FRAME_MAX.saturating_add(1)))
    {
        Ok(handle) => handle,
        Err(_) => {
            platform::terminate(&mut containment, &mut child);
            let _ = child.wait();
            let _ = writer.join();
            return Err(WorkerFailure::Transport);
        }
    };
    let errors = match thread::Builder::new()
        .name("code2graph-worker-stderr".into())
        .spawn(move || drain_tail(stderr, STDERR_TAIL_MAX))
    {
        Ok(handle) => handle,
        Err(_) => {
            platform::terminate(&mut containment, &mut child);
            let _ = child.wait();
            let _ = writer.join();
            let _ = output.join();
            return Err(WorkerFailure::Transport);
        }
    };

    let mut termination = None;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) => match deadline.check(cancellation) {
                Ok(()) => thread::sleep(Duration::from_millis(5)),
                Err(error) => {
                    termination = Some(check_failure(error));
                    platform::terminate(&mut containment, &mut child);
                    break child.wait().map_err(|_| WorkerFailure::Transport);
                }
            },
            Err(_) => {
                termination = Some(WorkerFailure::Transport);
                platform::terminate(&mut containment, &mut child);
                break child.wait().map_err(|_| WorkerFailure::Transport);
            }
        }
    };

    // Kill the complete containment even after a clean leader exit. A descendant
    // retaining a pipe must not keep any of the drain/writer joins blocked.
    platform::terminate(&mut containment, &mut child);
    let writer_result = writer.join();
    let stdout_result = output.join();
    let stderr_result = errors.join();

    if let Some(failure) = termination {
        return Err(failure);
    }
    let status = status?;
    let writer_result = writer_result.map_err(|_| WorkerFailure::Transport)?;
    let stdout = stdout_result
        .map_err(|_| WorkerFailure::Transport)?
        .map_err(|_| WorkerFailure::Transport)?;
    stderr_result
        .map_err(|_| WorkerFailure::Transport)?
        .map_err(|_| WorkerFailure::Transport)?;
    writer_result.map_err(|_| WorkerFailure::Transport)?;
    if !status.success() {
        return Err(WorkerFailure::Exit);
    }
    if stdout.len() > RESPONSE_FRAME_MAX {
        return Err(WorkerFailure::Protocol);
    }
    let response = decode_response_frame(&stdout).map_err(|_| WorkerFailure::Protocol)?;
    validate_response(&response, &request)
        .map_err(classify_response_error)?
        .map_err(|remote| WorkerFailure::Remote(remote.code))
}

pub(super) fn classify_response_error(error: WorkerProtocolError) -> WorkerFailure {
    match error {
        WorkerProtocolError::Facts(_) => WorkerFailure::Remote(WorkerErrorCode::Extraction),
        _ => WorkerFailure::Protocol,
    }
}

fn check_failure(error: CliError) -> WorkerFailure {
    match error {
        CliError::Cancelled => WorkerFailure::Cancelled,
        CliError::Timeout => WorkerFailure::Timeout,
        _ => WorkerFailure::Transport,
    }
}

fn drain_bounded<R: Read>(mut reader: R, max: usize) -> std::io::Result<Vec<u8>> {
    let mut kept = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            return Ok(kept);
        }
        let room = max.saturating_sub(kept.len());
        kept.extend_from_slice(&buffer[..count.min(room)]);
    }
}

pub(super) fn drain_tail<R: Read>(mut reader: R, max: usize) -> std::io::Result<Vec<u8>> {
    let mut tail = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            return Ok(tail);
        }
        if count >= max {
            tail.clear();
            tail.extend_from_slice(&buffer[count - max..count]);
        } else {
            let excess = tail.len().saturating_add(count).saturating_sub(max);
            if excess > 0 {
                tail.drain(..excess);
            }
            tail.extend_from_slice(&buffer[..count]);
        }
    }
}

#[cfg(test)]
pub(crate) fn extract_with_test_executable(
    executable: PathBuf,
    file: &InventoryFile,
    request_id: RequestId,
    deadline: &Deadline,
    cancellation: &dyn Cancellation,
) -> Result<FileFacts, WorkerFailure> {
    extract_with_executable(&executable, file, request_id, deadline, cancellation, &[])
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use code2graph::Language;
    use tempfile::TempDir;

    use super::*;
    use crate::{NeverCancelled, ProjectPath};

    struct AtomicCancellation(Arc<AtomicBool>);

    impl Cancellation for AtomicCancellation {
        fn is_cancelled(&self) -> bool {
            self.0.load(Ordering::SeqCst)
        }
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

    fn script(body: &str) -> (TempDir, PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("worker-fixture.sh");
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&path, permissions).unwrap();
        (directory, path)
    }

    fn run_script(body: &str, deadline: Deadline) -> Result<FileFacts, WorkerFailure> {
        let (_directory, executable) = script(body);
        extract_with_test_executable(
            executable,
            &inventory_file(),
            17,
            &deadline,
            &NeverCancelled,
        )
    }

    #[test]
    fn invalid_worker_facts_are_classified_as_omittable_extraction_failures() {
        assert!(matches!(
            classify_response_error(WorkerProtocolError::Facts("invalid facts".into())),
            WorkerFailure::Remote(WorkerErrorCode::Extraction)
        ));
        assert!(matches!(
            classify_response_error(WorkerProtocolError::Malformed("bad frame")),
            WorkerFailure::Protocol
        ));
    }

    #[test]
    fn test_executable_reports_crash_malformed_and_streaming_output_without_diagnostics() {
        let crash = run_script(
            "cat >/dev/null; echo secret-diagnostic >&2; exit 9",
            Deadline::new(None),
        );
        assert!(matches!(&crash, Err(WorkerFailure::Exit)));
        assert_eq!(
            crash.unwrap_err().to_string(),
            "worker exited unsuccessfully"
        );

        assert!(matches!(
            run_script("cat >/dev/null", Deadline::new(None)),
            Err(WorkerFailure::Protocol)
        ));
        assert!(matches!(
            run_script("cat >/dev/null; printf x", Deadline::new(None)),
            Err(WorkerFailure::Protocol)
        ));
        assert!(
            run_script(
                "sleep 30 & exit 0",
                Deadline::new(Some(Duration::from_secs(5)))
            )
            .is_err()
        );
        assert!(matches!(
            run_script(
                "dd if=/dev/zero bs=4096 count=256 2>/dev/null",
                Deadline::new(Some(Duration::from_secs(5)))
            ),
            Err(WorkerFailure::Protocol)
        ));
    }

    #[test]
    fn stderr_is_drained_past_its_tail_cap_without_blocking_exit() {
        let body = "i=0; while [ $i -lt 10000 ]; do printf 'stderr-flood-marker-0123456789\\n' >&2; i=$((i + 1)); done; exit 7";
        assert!(matches!(
            run_script(body, Deadline::new(Some(Duration::from_secs(5)))),
            Err(WorkerFailure::Exit)
        ));

        let input = vec![b'a'; STDERR_TAIL_MAX + 4096];
        let tail = drain_tail(std::io::Cursor::new(input), STDERR_TAIL_MAX).unwrap();
        assert_eq!(tail.len(), STDERR_TAIL_MAX);
        assert!(tail.iter().all(|byte| *byte == b'a'));
    }

    #[test]
    fn deadline_and_polling_cancellation_kill_the_process_group_and_join_pipes() {
        assert!(matches!(
            run_script(
                "sleep 30 & wait",
                Deadline::new(Some(Duration::from_millis(50)))
            ),
            Err(WorkerFailure::Timeout)
        ));

        let flag = Arc::new(AtomicBool::new(false));
        let cancellation = AtomicCancellation(Arc::clone(&flag));
        let (_directory, executable) = script("sleep 30 & wait");
        let setter = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            flag.store(true, Ordering::SeqCst);
        });
        let result = extract_with_test_executable(
            executable,
            &inventory_file(),
            17,
            &Deadline::new(None),
            &cancellation,
        );
        setter.join().unwrap();
        assert!(matches!(result, Err(WorkerFailure::Cancelled)));
    }

    #[test]
    fn typed_remote_error_requires_a_clean_exit_and_trailing_data_is_rejected() {
        let response = "printf '\\000\\000\\000\\020\\205\\000\\001\\001\\002\\002\\021\\003\\300\\004\\202\\000\\001\\001\\241x'";
        assert!(matches!(
            run_script(&format!("cat >/dev/null; {response}"), Deadline::new(None)),
            Err(WorkerFailure::Remote(WorkerErrorCode::Extraction))
        ));
        assert!(matches!(
            run_script(
                &format!("cat >/dev/null; {response}; exit 9"),
                Deadline::new(None)
            ),
            Err(WorkerFailure::Exit)
        ));
        assert!(matches!(
            run_script(
                &format!("cat >/dev/null; {response}; printf x"),
                Deadline::new(None)
            ),
            Err(WorkerFailure::Protocol)
        ));
    }
}
