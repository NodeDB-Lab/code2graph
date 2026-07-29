// SPDX-License-Identifier: Apache-2.0

//! Per-file worker crash recovery.

use super::api::ExtractionOutcome;
use crate::Result;
use crate::deadline::{Cancellation, Deadline};
use crate::inventory::InventoryFile;
use crate::worker::{RequestId, WorkerAttemptFailure, WorkerErrorCode, WorkerFailure};
use code2graph::FileFacts;
fn is_worker_death(failure: &WorkerAttemptFailure) -> bool {
    matches!(
        failure,
        WorkerAttemptFailure::Failure(WorkerFailure::Transport | WorkerFailure::Exit)
    )
}

fn detailed_omission(failure: WorkerAttemptFailure) -> Result<ExtractionOutcome> {
    match failure {
        WorkerAttemptFailure::Remote {
            code: WorkerErrorCode::Extraction,
            message,
        } => Ok(ExtractionOutcome::Omitted {
            detail: super::pipeline::bounded_detail("worker-extraction", &message),
        }),
        WorkerAttemptFailure::InvalidFacts { message } => Ok(ExtractionOutcome::Omitted {
            detail: super::pipeline::bounded_detail("worker-validation", &message),
        }),
        failure => Err(failure.legacy().into()),
    }
}

/// A one-file worker with respawn, abstracting the persistent subprocess so the
/// crash-recovery policy in [`extract_with_recovery`] can be driven
/// deterministically without a real subprocess.
pub(super) trait RecoverableWorker {
    /// Attempts one file; a worker-death failure signals the process must be
    /// replaced (via [`respawn`](Self::respawn)) before the next attempt.
    fn attempt(
        &mut self,
        file: &InventoryFile,
        request_id: RequestId,
    ) -> std::result::Result<FileFacts, WorkerAttemptFailure>;
    /// Replaces the underlying worker with a fresh one; a spawn failure is fatal.
    fn respawn(&mut self) -> Result<()>;
}

/// The crash-recovery policy for one file. Deadline/cancellation breaches stay
/// fatal; a first worker death triggers one respawn-and-retry; a retry that also
/// dies marks the file as poison — reclassified as the existing per-file
/// extraction omission — and spawns a fresh worker for subsequent files.
pub(super) fn extract_with_recovery<W: RecoverableWorker>(
    worker: &mut W,
    file: &InventoryFile,
    request_id: RequestId,
    deadline: &Deadline,
    cancellation: &dyn Cancellation,
) -> Result<ExtractionOutcome> {
    deadline.check(cancellation)?;
    let failure = match worker.attempt(file, request_id) {
        Ok(facts) => return Ok(ExtractionOutcome::Facts(facts)),
        Err(failure) => failure,
    };
    // A surviving worker's typed error is a per-file omission when it has a
    // supported extraction classification; other typed errors remain fatal.
    if !is_worker_death(&failure) {
        return detailed_omission(failure);
    }
    deadline.check(cancellation)?;
    worker.respawn()?;
    match worker.attempt(file, request_id) {
        Ok(facts) => Ok(ExtractionOutcome::Facts(facts)),
        Err(retry) if is_worker_death(&retry) => {
            deadline.check(cancellation)?;
            worker.respawn()?;
            Ok(ExtractionOutcome::Omitted {
                detail: "stage=worker-crash error=worker repeatedly crashed".into(),
            })
        }
        Err(retry) => detailed_omission(retry),
    }
}
