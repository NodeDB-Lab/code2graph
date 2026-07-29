// SPDX-License-Identifier: Apache-2.0

//! Bounded extraction worker pool and deadline monitor.

use super::*;
use crate::Result;
use crate::deadline::{Cancellation, Deadline};
use crate::inventory::InventoryFile;
use crate::worker::{KillHandle, RequestId};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
#[derive(Clone)]
pub struct WorkerSlot {
    registry: Arc<Mutex<Vec<Option<KillHandle>>>>,
    index: usize,
}

impl WorkerSlot {
    /// Publishes the current worker's kill handle for the monitor to use.
    pub fn set(&self, handle: KillHandle) {
        let mut slots = self
            .registry
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(slot) = slots.get_mut(self.index) {
            *slot = Some(handle);
        }
    }

    /// Clears the slot; the monitor will no longer target this thread's worker.
    pub fn clear(&self) {
        let mut slots = self
            .registry
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(slot) = slots.get_mut(self.index) {
            *slot = None;
        }
    }
}

/// The single deadline/cancellation monitor for one extraction run. Because a
/// session's response read blocks, a hung file would otherwise pin a pool thread
/// forever; the monitor kills every registered worker once the deadline or a
/// cancellation trips, unblocking those reads (a killed worker's stdout closes).
struct ExtractMonitor {
    registry: Arc<Mutex<Vec<Option<KillHandle>>>>,
    shutdown: AtomicBool,
}

impl ExtractMonitor {
    fn new(registry: Arc<Mutex<Vec<Option<KillHandle>>>>) -> Self {
        Self {
            registry,
            shutdown: AtomicBool::new(false),
        }
    }

    fn kill_all(&self) {
        let slots = self
            .registry
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        for handle in slots.iter().flatten() {
            handle.kill();
        }
    }
}

/// Signals the monitor to stop when it drops, so the monitor thread is joined
/// promptly on every exit path — including an unwinding panic in a pool thread —
/// and `thread::scope` can never hang waiting on a still-looping monitor.
struct MonitorStop<'a>(&'a ExtractMonitor);

impl Drop for MonitorStop<'_> {
    fn drop(&mut self) {
        self.0.shutdown.store(true, Ordering::SeqCst);
    }
}

/// Polls the deadline/cancellation in small increments; on breach it kills all
/// registered workers (repeatedly, to catch any still finishing) and keeps
/// polling until the pool signals shutdown after its threads have joined.
fn run_monitor(monitor: &ExtractMonitor, deadline: &Deadline, cancellation: &dyn Cancellation) {
    while !monitor.shutdown.load(Ordering::SeqCst) {
        if deadline.check(cancellation).is_err() {
            monitor.kill_all();
        }
        thread::sleep(Duration::from_millis(5));
    }
}

/// Whether a failure means the worker process died or its stream desynced (so
/// the connection is unusable and a fresh worker is required), as opposed to a
/// surviving worker's typed error or a fatal deadline/cancellation.
pub(super) struct ExtractWorkItem<'a> {
    pub(super) index: usize,
    pub(super) file: &'a InventoryFile,
    pub(super) request_id: RequestId,
}

/// Runs the per-file extractions across a bounded pool of persistent workers
/// (`available_parallelism`, capped by the work count). Each pool thread keeps
/// one worker alive across the files it pulls; a single-file crash is contained
/// and recovered per [`extract_with_recovery`]. A shared cursor guarantees no
/// file is lost — a thread only ever holds one in-flight file. Results come back
/// keyed by plan-entry index and are sorted, so the outcome and its ordering are
/// identical to a serial run.
pub(super) fn parallel_extract<E: FactsExtractor>(
    extractor: &E,
    work: &[ExtractWorkItem<'_>],
    deadline: &Deadline,
    cancellation: &dyn Cancellation,
) -> Vec<(usize, Result<ExtractionOutcome>)> {
    if work.is_empty() {
        return Vec::new();
    }
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(work.len())
        .max(1);
    let cursor = AtomicUsize::new(0);
    let results: Mutex<Vec<(usize, Result<ExtractionOutcome>)>> =
        Mutex::new(Vec::with_capacity(work.len()));
    let registry: Arc<Mutex<Vec<Option<KillHandle>>>> = Arc::new(Mutex::new(vec![None; workers]));
    let monitor = ExtractMonitor::new(Arc::clone(&registry));

    thread::scope(|scope| {
        // Dropping this guard (on normal return or an unwinding panic below) sets
        // the monitor's shutdown flag before `thread::scope` joins the monitor.
        let _stop = MonitorStop(&monitor);
        scope.spawn(|| run_monitor(&monitor, deadline, cancellation));
        let mut handles = Vec::with_capacity(workers);
        for index in 0..workers {
            let slot = WorkerSlot {
                registry: Arc::clone(&registry),
                index,
            };
            let cursor = &cursor;
            let results = &results;
            handles.push(scope.spawn(move || {
                run_pool_thread(
                    extractor,
                    work,
                    deadline,
                    cancellation,
                    slot,
                    cursor,
                    results,
                );
            }));
        }
        // The monitor keeps running (killing any stuck worker) until every pool
        // thread has finished; only then does `_stop` drop and stop it.
        for handle in handles {
            let _ = handle.join();
        }
    });

    let mut results = results
        .into_inner()
        .unwrap_or_else(|error| error.into_inner());
    results.sort_by_key(|(index, _)| *index);
    results
}

/// One pool thread: lazily create a session (one persistent worker), then pull
/// files off the shared cursor and extract each. A session that cannot even be
/// created is a fatal infrastructure failure attributed to the claimed file.
fn run_pool_thread<E: FactsExtractor>(
    extractor: &E,
    work: &[ExtractWorkItem<'_>],
    deadline: &Deadline,
    cancellation: &dyn Cancellation,
    slot: WorkerSlot,
    cursor: &AtomicUsize,
    results: &Mutex<Vec<(usize, Result<ExtractionOutcome>)>>,
) {
    let mut session: Option<E::Session> = None;
    loop {
        let next = cursor.fetch_add(1, Ordering::Relaxed);
        let Some(item) = work.get(next) else {
            break;
        };
        if session.is_none() {
            match extractor.session(slot.clone()) {
                Ok(created) => session = Some(created),
                Err(error) => {
                    push_result(results, item.index, Err(error));
                    continue;
                }
            }
        }
        let Some(active) = session.as_mut() else {
            continue;
        };
        let outcome = active.extract_outcome(item.file, item.request_id, deadline, cancellation);
        push_result(results, item.index, outcome);
    }
    // Clear the registry slot before dropping the worker so the monitor cannot
    // target a worker whose process is being reaped.
    slot.clear();
    drop(session);
}

fn push_result(
    results: &Mutex<Vec<(usize, Result<ExtractionOutcome>)>>,
    index: usize,
    outcome: Result<ExtractionOutcome>,
) {
    results
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .push((index, outcome));
}

/// Runs a single-file extraction under its own deadline monitor, so a hung
/// worker cannot pin the caller. Used by revalidation, which re-extracts a few
/// omitted files outside the main pool.
pub(crate) fn monitored_extract<E: FactsExtractor>(
    extractor: &E,
    file: &InventoryFile,
    request_id: RequestId,
    deadline: &Deadline,
    cancellation: &dyn Cancellation,
) -> Result<ExtractionOutcome> {
    let registry: Arc<Mutex<Vec<Option<KillHandle>>>> = Arc::new(Mutex::new(vec![None]));
    let monitor = ExtractMonitor::new(Arc::clone(&registry));
    thread::scope(|scope| {
        // Dropping this guard stops the monitor before `thread::scope` joins it,
        // on the normal path and on an unwinding panic in `extract`.
        let _stop = MonitorStop(&monitor);
        scope.spawn(|| run_monitor(&monitor, deadline, cancellation));
        let slot = WorkerSlot {
            registry: Arc::clone(&registry),
            index: 0,
        };
        (|| {
            let mut session = extractor.session(slot.clone())?;
            let facts = session.extract_outcome(file, request_id, deadline, cancellation);
            slot.clear();
            drop(session);
            facts
        })()
    })
}
