// SPDX-License-Identifier: Apache-2.0

//! Public preparation API and persistent worker session implementation.

use super::super::RefreshPlan;
use super::recovery::{RecoverableWorker, extract_with_recovery};
use super::*;
use crate::cache::{CacheOmission, CandidateSnapshot, LoadedSnapshot};
use crate::config::{ResolverTier, ResourceLimits};
use crate::deadline::{Cancellation, Deadline};
use crate::inventory::InventoryFile;
use crate::project::ProjectSelection;
use crate::worker::{PersistentWorker, RequestId, WorkerFailure};
use crate::{CliError, Result};
use code2graph::{FileFacts, QueryBindingRule};
use std::path::PathBuf;
use std::sync::Arc;
pub struct PrepareCandidateInputs<'a> {
    pub selection: &'a ProjectSelection,
    pub limits: &'a ResourceLimits,
    pub include_hidden: bool,
    pub force: bool,
    pub trust_mtime: bool,
    pub tier: ResolverTier,
    pub prior: Option<&'a LoadedSnapshot>,
    pub prepared_at_ns: u64,
    pub deadline: &'a Deadline,
    pub cancellation: &'a dyn Cancellation,
}
pub struct PreparedRefreshCandidate {
    pub snapshot: CandidateSnapshot,
    pub plan: RefreshPlan,
    pub changed_paths: Vec<String>,
    pub deleted_paths: Vec<String>,
    pub ignored_omissions: Vec<CacheOmission>,
    pub attempts: u8,
}
/// Produces a reusable extraction session for one pool thread. A session owns a
/// long-lived worker and survives across files, so the expensive worker spawn is
/// paid once per thread — not once per file, which dominated a cold index.
pub trait FactsExtractor: Sync {
    /// A reusable per-thread extraction context.
    type Session: ExtractSession;
    /// Creates a session, publishing its worker's kill handle into `slot` so the
    /// run's deadline monitor can terminate a worker whose owning thread is
    /// blocked in [`ExtractSession::extract`].
    fn session(&self, slot: WorkerSlot) -> Result<Self::Session>;
}

/// Result of one isolated extraction attempt.
///
/// The detailed outcome supplements the legacy [`ExtractSession::extract`]
/// method without changing its error contract. External session implementations
/// inherit the default facts-only behavior.
pub enum ExtractionOutcome {
    /// Valid facts extracted for the requested file.
    Facts(FileFacts),
    /// A recoverable per-file omission with bounded, source-free detail.
    Omitted { detail: String },
}

/// A per-thread extraction session. Each `extract` services exactly one file and
/// owns its own crash recovery: a repeatable single-file crash degrades to a
/// per-file omission, while genuine infrastructure failures stay fatal.
pub trait ExtractSession {
    fn extract(
        &mut self,
        file: &InventoryFile,
        request_id: RequestId,
        deadline: &Deadline,
        cancellation: &dyn Cancellation,
    ) -> Result<FileFacts>;

    /// Provides internal omission detail when available. The default retains
    /// source compatibility for external `ExtractSession` implementations.
    fn extract_outcome(
        &mut self,
        file: &InventoryFile,
        request_id: RequestId,
        deadline: &Deadline,
        cancellation: &dyn Cancellation,
    ) -> Result<ExtractionOutcome> {
        self.extract(file, request_id, deadline, cancellation)
            .map(ExtractionOutcome::Facts)
    }
}

/// One pool thread's slot in the deadline monitor's registry of live workers. A
/// session publishes its current worker's kill handle here on every (re)spawn
/// and clears it when the thread finishes, all under the registry lock, so the
/// monitor never signals a worker whose process has already been reaped.
#[derive(Clone)]
pub struct ProcessFactsExtractor {
    custom_rules: Arc<Vec<QueryBindingRule>>,
}
impl ProcessFactsExtractor {
    pub fn new(custom_rules: Vec<QueryBindingRule>) -> Self {
        Self {
            custom_rules: Arc::new(custom_rules),
        }
    }
}
impl FactsExtractor for ProcessFactsExtractor {
    type Session = ProcessSession;
    fn session(&self, slot: WorkerSlot) -> Result<ProcessSession> {
        let executable =
            std::env::current_exe().map_err(|_| CliError::from(WorkerFailure::Spawn))?;
        let worker = PersistentWorker::spawn(&executable).map_err(CliError::from)?;
        slot.set(worker.kill_handle());
        Ok(ProcessSession {
            worker,
            executable,
            rules: Arc::clone(&self.custom_rules),
            slot,
        })
    }
}

/// A live persistent worker plus what it needs to respawn after a crash.
pub struct ProcessSession {
    worker: PersistentWorker,
    executable: PathBuf,
    rules: Arc<Vec<QueryBindingRule>>,
    slot: WorkerSlot,
}

impl RecoverableWorker for ProcessSession {
    fn attempt(
        &mut self,
        file: &InventoryFile,
        request_id: RequestId,
    ) -> std::result::Result<FileFacts, crate::worker::WorkerAttemptFailure> {
        self.worker
            .extract_one_detailed(file, request_id, &self.rules)
    }

    fn respawn(&mut self) -> Result<()> {
        let worker = PersistentWorker::spawn(&self.executable).map_err(CliError::from)?;
        let handle = worker.kill_handle();
        // Clear the slot before dropping the old worker (which closes its stdin,
        // terminates its group, reaps it, and — on Windows — closes its Job
        // Object handle). Otherwise the registry would briefly hold a stale
        // handle the monitor could signal after it closes.
        self.slot.clear();
        drop(std::mem::replace(&mut self.worker, worker));
        self.slot.set(handle);
        Ok(())
    }
}

impl ExtractSession for ProcessSession {
    fn extract(
        &mut self,
        file: &InventoryFile,
        request_id: RequestId,
        deadline: &Deadline,
        cancellation: &dyn Cancellation,
    ) -> Result<FileFacts> {
        match self.extract_outcome(file, request_id, deadline, cancellation)? {
            ExtractionOutcome::Facts(facts) => Ok(facts),
            // The legacy method has no detail channel. Every omission it can
            // observe — a worker extraction failure, facts that fail their
            // request context, or a repeatedly-crashing poison file — was
            // reported as a remote extraction failure before the detail channel
            // existed, so collapse to that same code rather than inventing a
            // transport failure the worker never had.
            ExtractionOutcome::Omitted { .. } => Err(CliError::Worker(WorkerFailure::Remote(
                crate::worker::WorkerErrorCode::Extraction,
            ))),
        }
    }

    fn extract_outcome(
        &mut self,
        file: &InventoryFile,
        request_id: RequestId,
        deadline: &Deadline,
        cancellation: &dyn Cancellation,
    ) -> Result<ExtractionOutcome> {
        extract_with_recovery(self, file, request_id, deadline, cancellation)
    }
}
