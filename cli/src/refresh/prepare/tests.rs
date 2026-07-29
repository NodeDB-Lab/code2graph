// SPDX-License-Identifier: Apache-2.0

//! Refresh preparation regression tests.

use super::super::RefreshDecision;
use super::*;
use crate::cache::{
    CacheCompleteness, CandidateId, CandidateSnapshot, CompatibilityFingerprint, LoadedSnapshot,
    PackageFingerprint, ResolverCacheTier,
};
use crate::config::{ResolverTier, ResourceLimits};
use crate::deadline::{Cancellation, Deadline};
use crate::inventory::InventoryFile;
use crate::project::{ProjectPath, ProjectSelection};
use crate::worker::{RequestId, WorkerErrorCode, WorkerFailure};
use crate::{CliError, Result};
use code2graph::FileFacts;
use std::cell::Cell;
use std::fs;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use code2graph::{Resolver, ScopeGraphResolver};
use tempfile::{TempDir, tempdir};

use super::pipeline::{AttemptError, retry_drift};
use super::recovery::{RecoverableWorker, extract_with_recovery};
use crate::NeverCancelled;
use crate::cache::{CacheLocation, CacheStore};
use crate::project::SelectionProvenance;

#[derive(Clone, Copy)]
enum ExtractBehavior {
    Normal,
    InvalidFacts,
    RemoteExtractionError,
    InfrastructureError,
}

struct FakeExtractor {
    calls: Arc<AtomicUsize>,
    behavior: ExtractBehavior,
}

impl FakeExtractor {
    fn normal() -> Self {
        Self::with_behavior(ExtractBehavior::Normal)
    }

    fn with_behavior(behavior: ExtractBehavior) -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            behavior,
        }
    }
}

struct FakeSession {
    calls: Arc<AtomicUsize>,
    behavior: ExtractBehavior,
}

impl FactsExtractor for FakeExtractor {
    type Session = FakeSession;
    fn session(&self, _slot: WorkerSlot) -> Result<FakeSession> {
        Ok(FakeSession {
            calls: Arc::clone(&self.calls),
            behavior: self.behavior,
        })
    }
}

impl ExtractSession for FakeSession {
    fn extract(
        &mut self,
        file: &crate::inventory::InventoryFile,
        _request_id: RequestId,
        _deadline: &Deadline,
        _cancellation: &dyn Cancellation,
    ) -> Result<FileFacts> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        match self.behavior {
            ExtractBehavior::Normal => code2graph::extract_path(file.path.as_str(), &file.text)
                .map_err(|error| CliError::Index(error.to_string())),
            ExtractBehavior::InvalidFacts => {
                let mut facts = code2graph::extract_path(file.path.as_str(), &file.text)
                    .map_err(|error| CliError::Index(error.to_string()))?;
                facts.symbols.push(facts.symbols[0].clone());
                Ok(facts)
            }
            ExtractBehavior::RemoteExtractionError => Err(CliError::Worker(WorkerFailure::Remote(
                WorkerErrorCode::Extraction,
            ))),
            ExtractBehavior::InfrastructureError => Err(CliError::Worker(WorkerFailure::Protocol)),
        }
    }
}

/// A deterministic [`RecoverableWorker`] for driving the crash-recovery
/// policy without a real subprocess.
#[derive(Clone)]
enum CrashKind {
    /// The worker dies (a fresh process every attempt) for this exact path,
    /// and extracts every other file normally.
    PoisonPath(String),
    /// The worker returns malformed protocol data for this exact path.
    MalformedPath(String),
    /// The worker dies on its first attempt, then succeeds after a respawn.
    DieOnceThenRecover,
}

struct FakeRecoverableWorker {
    behavior: CrashKind,
    respawned: bool,
    respawns: Arc<AtomicUsize>,
}

impl RecoverableWorker for FakeRecoverableWorker {
    fn attempt(
        &mut self,
        file: &InventoryFile,
        _request_id: RequestId,
    ) -> std::result::Result<FileFacts, crate::worker::WorkerAttemptFailure> {
        let failure = match &self.behavior {
            CrashKind::PoisonPath(path) if file.path.as_str() == path => {
                Some(WorkerFailure::Transport)
            }
            CrashKind::MalformedPath(path) if file.path.as_str() == path => {
                Some(WorkerFailure::Protocol)
            }
            CrashKind::DieOnceThenRecover if !self.respawned => Some(WorkerFailure::Transport),
            _ => None,
        };
        if let Some(failure) = failure {
            return Err(crate::worker::WorkerAttemptFailure::Failure(failure));
        }
        code2graph::extract_path(file.path.as_str(), &file.text).map_err(|_| {
            crate::worker::WorkerAttemptFailure::Remote {
                code: WorkerErrorCode::Extraction,
                message: "fake extraction failure".into(),
            }
        })
    }

    fn respawn(&mut self) -> Result<()> {
        self.respawned = true;
        self.respawns.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

struct CrashExtractor {
    behavior: CrashKind,
    respawns: Arc<AtomicUsize>,
}

struct CrashSession {
    worker: FakeRecoverableWorker,
}

impl FactsExtractor for CrashExtractor {
    type Session = CrashSession;
    fn session(&self, _slot: WorkerSlot) -> Result<CrashSession> {
        Ok(CrashSession {
            worker: FakeRecoverableWorker {
                behavior: self.behavior.clone(),
                respawned: false,
                respawns: Arc::clone(&self.respawns),
            },
        })
    }
}

impl ExtractSession for CrashSession {
    fn extract(
        &mut self,
        file: &InventoryFile,
        request_id: RequestId,
        deadline: &Deadline,
        cancellation: &dyn Cancellation,
    ) -> Result<FileFacts> {
        match self.extract_outcome(file, request_id, deadline, cancellation)? {
            ExtractionOutcome::Facts(facts) => Ok(facts),
            ExtractionOutcome::Omitted { .. } => Err(CliError::Worker(WorkerFailure::Transport)),
        }
    }

    fn extract_outcome(
        &mut self,
        file: &InventoryFile,
        request_id: RequestId,
        deadline: &Deadline,
        cancellation: &dyn Cancellation,
    ) -> Result<ExtractionOutcome> {
        extract_with_recovery(&mut self.worker, file, request_id, deadline, cancellation)
    }
}

fn project(files: &[(&str, &str)]) -> (TempDir, ProjectSelection) {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("project");
    fs::create_dir(&root).expect("project root");
    for (path, contents) in files {
        let absolute = root.join(path);
        if let Some(parent) = absolute.parent() {
            fs::create_dir_all(parent).expect("source parent");
        }
        fs::write(absolute, contents).expect("source");
    }
    let root = fs::canonicalize(root).expect("canonical root");
    (
        temp,
        ProjectSelection {
            canonical_root: root,
            canonical_source: None,
            provenance: SelectionProvenance::RootArgument,
        },
    )
}

#[derive(Clone, Copy)]
struct PrepareTestOptions<'a> {
    prior: Option<&'a LoadedSnapshot>,
    tier: ResolverTier,
    force: bool,
    trust_mtime: bool,
}

impl<'a> Default for PrepareTestOptions<'a> {
    fn default() -> Self {
        Self {
            prior: None,
            tier: ResolverTier::Name,
            force: false,
            trust_mtime: false,
        }
    }
}

fn prepare<'a, E: FactsExtractor>(
    extractor: &E,
    selection: &'a ProjectSelection,
    limits: &'a ResourceLimits,
    options: PrepareTestOptions<'a>,
    deadline: &'a Deadline,
    cancellation: &'a dyn Cancellation,
) -> Result<PreparedRefreshCandidate> {
    prepare_refresh_candidate_with(
        extractor,
        PrepareCandidateInputs {
            selection,
            limits,
            include_hidden: false,
            force: options.force,
            trust_mtime: options.trust_mtime,
            tier: options.tier,
            prior: options.prior,
            prepared_at_ns: 42,
            deadline,
            cancellation,
        },
    )
}

#[test]
fn fresh_candidate_has_canonical_identity_metadata_and_no_source_body() {
    let (_temp, selection) = project(&[
        ("Cargo.toml", "[package]\nname='fixture'\nversion='0.1.0'\n"),
        ("src/lib.rs", "pub fn answer() -> u8 { 42 }\n"),
    ]);
    let extractor = FakeExtractor::normal();
    let prepared = prepare(
        &extractor,
        &selection,
        &ResourceLimits::default(),
        PrepareTestOptions::default(),
        &Deadline::new(None),
        &NeverCancelled,
    )
    .expect("prepare");
    assert_eq!(extractor.calls.load(Ordering::Relaxed), 1);
    assert_eq!(prepared.snapshot.created_at_ns, 42);
    assert_eq!(prepared.snapshot.compatibility.created_at_ns, 42);
    assert_eq!(prepared.snapshot.inventory_file_count, 1);
    assert_eq!(
        prepared.snapshot.inventory_total_bytes,
        "pub fn answer() -> u8 { 42 }\n".len() as u64
    );
    let file = &prepared.snapshot.files[0];
    assert_eq!(file.path, "src/lib.rs");
    assert_eq!(file.language, "rust");
    assert_eq!(file.facts.file, file.path);
    assert_eq!(file.facts.lang, file.language);
    assert!(file.package_assignment.contains("fixture"));
    assert_eq!(
        prepared.snapshot.candidate_id,
        CandidateId::new(
            prepared.snapshot.compatibility.id,
            prepared.snapshot.input_digest,
            prepared.snapshot.completeness,
            &prepared.snapshot.omissions,
        )
    );
}

#[test]
fn default_hash_and_trusted_mtime_reuse_while_force_extracts() {
    let (_temp, selection) = project(&[("a.rs", "fn a() {}\n")]);
    let limits = ResourceLimits::default();
    let deadline = Deadline::new(None);
    let first_extractor = FakeExtractor::normal();
    let first = prepare(
        &first_extractor,
        &selection,
        &limits,
        PrepareTestOptions::default(),
        &deadline,
        &NeverCancelled,
    )
    .expect("first");

    let prior = loaded(first.snapshot.clone());
    let default_extractor = FakeExtractor::normal();
    let default = prepare(
        &default_extractor,
        &selection,
        &limits,
        PrepareTestOptions {
            prior: Some(&prior),
            ..Default::default()
        },
        &deadline,
        &NeverCancelled,
    )
    .expect("hash reuse");
    assert_eq!(default_extractor.calls.load(Ordering::Relaxed), 0);
    assert!(matches!(
        default.plan.entries[0].decision,
        RefreshDecision::ReuseFacts
    ));

    let trust_extractor = FakeExtractor::normal();
    prepare(
        &trust_extractor,
        &selection,
        &limits,
        PrepareTestOptions {
            prior: Some(&prior),
            trust_mtime: true,
            ..Default::default()
        },
        &deadline,
        &NeverCancelled,
    )
    .expect("mtime reuse");
    assert_eq!(trust_extractor.calls.load(Ordering::Relaxed), 0);

    let force_extractor = FakeExtractor::normal();
    prepare(
        &force_extractor,
        &selection,
        &limits,
        PrepareTestOptions {
            prior: Some(&prior),
            force: true,
            trust_mtime: true,
            ..Default::default()
        },
        &deadline,
        &NeverCancelled,
    )
    .expect("forced extraction");
    assert_eq!(force_extractor.calls.load(Ordering::Relaxed), 1);
}

fn loaded(snapshot: CandidateSnapshot) -> LoadedSnapshot {
    LoadedSnapshot {
        candidate_id: snapshot.candidate_id,
        compatibility: snapshot.compatibility,
        input_digest: snapshot.input_digest,
        completeness: snapshot.completeness,
        omissions: snapshot.omissions,
        created_at_ns: snapshot.created_at_ns,
        inventory_file_count: snapshot.inventory_file_count,
        inventory_total_bytes: snapshot.inventory_total_bytes,
        files: snapshot.files,
        tier_graphs: snapshot.tier_graphs,
    }
}

#[test]
fn incompatible_prior_is_never_reused_even_with_trusted_metadata() {
    let (_temp, selection) = project(&[("a.rs", "fn a() {}\n")]);
    let limits = ResourceLimits::default();
    let deadline = Deadline::new(None);
    let initial = prepare(
        &FakeExtractor::normal(),
        &selection,
        &limits,
        PrepareTestOptions::default(),
        &deadline,
        &NeverCancelled,
    )
    .expect("initial");
    let mut prior = loaded(initial.snapshot);
    prior.compatibility.package_fingerprint = PackageFingerprint::from_normalized(["foreign"]);
    prior.compatibility.id = CompatibilityFingerprint::new(
        prior.compatibility.language_fingerprint,
        prior.compatibility.package_fingerprint,
    );
    let extractor = FakeExtractor::normal();
    let prepared = prepare(
        &extractor,
        &selection,
        &limits,
        PrepareTestOptions {
            prior: Some(&prior),
            trust_mtime: true,
            ..Default::default()
        },
        &deadline,
        &NeverCancelled,
    )
    .expect("incompatible refresh");
    assert_eq!(extractor.calls.load(Ordering::Relaxed), 1);
    assert_eq!(prepared.changed_paths, ["a.rs"]);
    assert!(prepared.deleted_paths.is_empty());
}

#[test]
fn changed_and_deleted_paths_are_exact_and_scope_matches_fresh_resolution() {
    let (_temp, selection) = project(&[
        ("caller.rs", "fn caller() { helper(); }\n"),
        ("helper.rs", "fn helper() {}\n"),
    ]);
    let limits = ResourceLimits::default();
    let deadline = Deadline::new(None);
    let initial = prepare(
        &FakeExtractor::normal(),
        &selection,
        &limits,
        PrepareTestOptions {
            tier: ResolverTier::Scope,
            ..Default::default()
        },
        &deadline,
        &NeverCancelled,
    )
    .expect("initial");
    fs::write(
        selection.canonical_root.join("caller.rs"),
        "fn caller() { replacement(); }\n",
    )
    .expect("change caller");
    fs::remove_file(selection.canonical_root.join("helper.rs")).expect("delete helper");
    let prior = loaded(initial.snapshot);
    let updated = prepare(
        &FakeExtractor::normal(),
        &selection,
        &limits,
        PrepareTestOptions {
            prior: Some(&prior),
            tier: ResolverTier::Scope,
            ..Default::default()
        },
        &deadline,
        &NeverCancelled,
    )
    .expect("updated");
    assert_eq!(updated.changed_paths, ["caller.rs"]);
    assert_eq!(updated.deleted_paths, ["helper.rs"]);
    assert!(
        updated
            .snapshot
            .files
            .iter()
            .all(|file| file.subgraph.is_some())
    );
    let facts: Vec<_> = updated
        .snapshot
        .files
        .iter()
        .map(|file| file.facts.clone())
        .collect();
    let direct = ScopeGraphResolver.resolve(&facts).expect("direct scope");
    assert_eq!(
        format!("{:?}", updated.snapshot.tier_graphs[0].1),
        format!("{:?}", direct)
    );
}

#[test]
fn budgets_and_extraction_failures_produce_truthful_partial_candidates() {
    let (_temp, selection) = project(&[("a.rs", "fn a() {}"), ("b.rs", "fn b() {}")]);
    let limits = ResourceLimits {
        max_files: 1,
        ..ResourceLimits::default()
    };
    let budgeted = prepare(
        &FakeExtractor::normal(),
        &selection,
        &limits,
        PrepareTestOptions::default(),
        &Deadline::new(None),
        &NeverCancelled,
    )
    .expect("budgeted");
    assert_eq!(budgeted.snapshot.completeness, CacheCompleteness::Partial);
    assert_eq!(budgeted.snapshot.files.len(), 1);
    assert_eq!(budgeted.snapshot.omissions.len(), 1);
    assert_eq!(budgeted.snapshot.omissions[0].reason, "file-count-limit");

    let failure = FakeExtractor::with_behavior(ExtractBehavior::RemoteExtractionError);
    let omitted = prepare(
        &failure,
        &selection,
        &ResourceLimits::default(),
        PrepareTestOptions::default(),
        &Deadline::new(None),
        &NeverCancelled,
    )
    .expect("remote extraction omission");
    assert!(omitted.snapshot.files.is_empty());
    assert_eq!(omitted.snapshot.completeness, CacheCompleteness::Partial);
    assert!(
        omitted
            .snapshot
            .omissions
            .iter()
            .all(|o| o.reason == "extraction-error")
    );

    let invalid = FakeExtractor::with_behavior(ExtractBehavior::InvalidFacts);
    let omitted = prepare(
        &invalid,
        &selection,
        &ResourceLimits::default(),
        PrepareTestOptions::default(),
        &Deadline::new(None),
        &NeverCancelled,
    )
    .expect("invalid facts omission");
    assert!(omitted.snapshot.files.is_empty());
    assert_eq!(omitted.snapshot.completeness, CacheCompleteness::Partial);
    assert!(
        omitted
            .snapshot
            .omissions
            .iter()
            .all(|o| o.reason == "extraction-error")
    );

    let infrastructure = FakeExtractor::with_behavior(ExtractBehavior::InfrastructureError);
    assert!(matches!(
        prepare(
            &infrastructure,
            &selection,
            &ResourceLimits::default(),
            PrepareTestOptions::default(),
            &Deadline::new(None),
            &NeverCancelled,
        ),
        Err(CliError::Worker(WorkerFailure::Protocol))
    ));
}

#[test]
fn rejected_extracted_facts_report_the_validation_rule() {
    let (_temp, selection) = project(&[("a.rs", "fn a() {}")]);
    let invalid = FakeExtractor::with_behavior(ExtractBehavior::InvalidFacts);
    let prepared = prepare(
        &invalid,
        &selection,
        &ResourceLimits::default(),
        PrepareTestOptions::default(),
        &Deadline::new(None),
        &NeverCancelled,
    )
    .expect("invalid extracted facts become a partial candidate");

    assert_eq!(prepared.snapshot.omissions.len(), 1);
    let omission = &prepared.snapshot.omissions[0];
    assert_eq!(omission.reason, "extraction-error");
    assert!(
        omission.detail.contains("duplicates structural identity"),
        "validation detail must identify the rejected invariant: {}",
        omission.detail
    );
    assert_ne!(omission.detail, "isolated extraction failed");
}

#[test]
fn worker_extraction_failures_are_distinct_from_fact_validation_failures() {
    let (_temp, selection) = project(&[("a.rs", "fn a() {}")]);
    let failure = FakeExtractor::with_behavior(ExtractBehavior::RemoteExtractionError);
    let prepared = prepare(
        &failure,
        &selection,
        &ResourceLimits::default(),
        PrepareTestOptions::default(),
        &Deadline::new(None),
        &NeverCancelled,
    )
    .expect("worker extraction failure becomes a partial candidate");

    assert_eq!(prepared.snapshot.omissions.len(), 1);
    let omission = &prepared.snapshot.omissions[0];
    assert_eq!(omission.reason, "extraction-error");
    assert!(
        omission.detail.contains("worker"),
        "detail must identify the worker extraction stage: {}",
        omission.detail
    );
    assert!(!omission.detail.contains("validation"));
}

#[test]
fn prepared_scope_candidate_publishes_and_loads_roundtrip() {
    let (temp, selection) = project(&[("a.rs", "fn a() {}\n")]);
    let prepared = prepare(
        &FakeExtractor::normal(),
        &selection,
        &ResourceLimits::default(),
        PrepareTestOptions {
            tier: ResolverTier::Scope,
            ..Default::default()
        },
        &Deadline::new(None),
        &NeverCancelled,
    )
    .expect("prepare");
    let location = CacheLocation::for_project(Some(temp.path()), &selection.canonical_root)
        .expect("cache location");
    let store =
        CacheStore::open_writable(&location, &selection.canonical_root, &Deadline::new(None))
            .expect("store");
    store
        .publish_candidate(&prepared.snapshot, &Deadline::new(None))
        .expect("publish");
    let loaded = store
        .load_active(
            ResolverCacheTier::Scope,
            prepared.snapshot.completeness,
            prepared.snapshot.compatibility.id,
            &Deadline::new(None),
        )
        .expect("load")
        .expect("active");
    assert_eq!(loaded.candidate_id, prepared.snapshot.candidate_id);
    assert_eq!(
        loaded.inventory_file_count,
        prepared.snapshot.inventory_file_count
    );
    assert_eq!(
        loaded.inventory_total_bytes,
        prepared.snapshot.inventory_total_bytes
    );
    assert_eq!(
        loaded.files[0].package_assignment,
        prepared.snapshot.files[0].package_assignment
    );
    assert!(loaded.files[0].subgraph.is_some());
}

#[test]
fn drift_retries_the_whole_attempt_and_exhaustion_is_fatal() {
    let calls = Cell::new(0_u8);
    let result = retry_drift(&Deadline::new(None), &NeverCancelled, |attempt| {
        calls.set(calls.get() + 1);
        if attempt < 2 {
            Err(AttemptError::Drift)
        } else {
            Ok(attempt)
        }
    })
    .expect("second whole attempt succeeds");
    assert_eq!(result, 2);
    assert_eq!(calls.get(), 2);

    let calls = Cell::new(0_u8);
    let exhausted = retry_drift::<()>(&Deadline::new(None), &NeverCancelled, |_| {
        calls.set(calls.get() + 1);
        Err(AttemptError::Drift)
    });
    assert!(matches!(exhausted, Err(CliError::Index(_))));
    assert_eq!(calls.get(), super::super::super::MAX_REFRESH_ATTEMPTS);
}

#[test]
fn deadline_and_cancellation_abort_before_extraction() {
    struct Cancelled;
    impl Cancellation for Cancelled {
        fn is_cancelled(&self) -> bool {
            true
        }
    }
    let (_temp, selection) = project(&[("a.rs", "fn a() {}")]);
    let extractor = FakeExtractor::normal();
    assert!(matches!(
        prepare(
            &extractor,
            &selection,
            &ResourceLimits::default(),
            PrepareTestOptions::default(),
            &Deadline::new(Some(Duration::ZERO)),
            &NeverCancelled,
        ),
        Err(CliError::Timeout)
    ));
    assert!(matches!(
        prepare(
            &extractor,
            &selection,
            &ResourceLimits::default(),
            PrepareTestOptions::default(),
            &Deadline::new(None),
            &Cancelled,
        ),
        Err(CliError::Cancelled)
    ));
    assert_eq!(extractor.calls.load(Ordering::Relaxed), 0);
}

fn inventory_file(name: &str) -> crate::inventory::InventoryFile {
    let bytes = b"fn helper() {}".to_vec();
    crate::inventory::InventoryFile {
        path: ProjectPath::new(std::path::Path::new(name)).unwrap(),
        language: code2graph::Language::Rust,
        text: String::from_utf8(bytes.clone()).unwrap(),
        blake3: blake3::hash(&bytes).to_hex().to_string(),
        bytes,
        mtime: None,
    }
}

#[test]
fn recovery_returns_facts_omits_poison_and_stays_fatal_on_deadline() {
    // A healthy worker extracts without any respawn.
    let respawns = Arc::new(AtomicUsize::new(0));
    let mut healthy = FakeRecoverableWorker {
        behavior: CrashKind::DieOnceThenRecover,
        respawned: true,
        respawns: Arc::clone(&respawns),
    };
    assert!(
        extract_with_recovery(
            &mut healthy,
            &inventory_file("a.rs"),
            1,
            &Deadline::new(None),
            &NeverCancelled,
        )
        .is_ok()
    );
    assert_eq!(respawns.load(Ordering::Relaxed), 0);

    // A transient crash recovers after exactly one respawn.
    let respawns = Arc::new(AtomicUsize::new(0));
    let mut transient = FakeRecoverableWorker {
        behavior: CrashKind::DieOnceThenRecover,
        respawned: false,
        respawns: Arc::clone(&respawns),
    };
    assert!(
        extract_with_recovery(
            &mut transient,
            &inventory_file("a.rs"),
            1,
            &Deadline::new(None),
            &NeverCancelled,
        )
        .is_ok()
    );
    assert_eq!(respawns.load(Ordering::Relaxed), 1);

    // A file that crashes a second, fresh worker is poison: it degrades to an
    // extraction omission and a fresh worker is spawned for the next file
    // (retry respawn + poison respawn == 2).
    let respawns = Arc::new(AtomicUsize::new(0));
    let mut poison = FakeRecoverableWorker {
        behavior: CrashKind::PoisonPath("a.rs".into()),
        respawned: false,
        respawns: Arc::clone(&respawns),
    };
    assert!(matches!(
        extract_with_recovery(
            &mut poison,
            &inventory_file("a.rs"),
            1,
            &Deadline::new(None),
            &NeverCancelled,
        ),
        Ok(ExtractionOutcome::Omitted { detail }) if detail.contains("worker repeatedly crashed")
    ));
    assert_eq!(respawns.load(Ordering::Relaxed), 2);

    // An already-expired deadline is fatal, never a recoverable crash.
    let respawns = Arc::new(AtomicUsize::new(0));
    let mut expired = FakeRecoverableWorker {
        behavior: CrashKind::PoisonPath("a.rs".into()),
        respawned: false,
        respawns: Arc::clone(&respawns),
    };
    assert!(matches!(
        extract_with_recovery(
            &mut expired,
            &inventory_file("a.rs"),
            1,
            &Deadline::new(Some(Duration::ZERO)),
            &NeverCancelled,
        ),
        Err(CliError::Timeout)
    ));
    assert_eq!(respawns.load(Ordering::Relaxed), 0);
}

#[test]
fn malformed_pooled_worker_failure_is_fatal_without_crash_omission() {
    let (_temp, selection) = project(&[("bad.rs", "fn bad() {}\n"), ("good.rs", "fn good() {}\n")]);
    let respawns = Arc::new(AtomicUsize::new(0));
    let extractor = CrashExtractor {
        behavior: CrashKind::MalformedPath("bad.rs".into()),
        respawns: Arc::clone(&respawns),
    };

    assert!(matches!(
        prepare(
            &extractor,
            &selection,
            &ResourceLimits::default(),
            PrepareTestOptions::default(),
            &Deadline::new(None),
            &NeverCancelled,
        ),
        Err(CliError::Worker(WorkerFailure::Protocol))
    ));
    assert_eq!(respawns.load(Ordering::Relaxed), 0);
}

#[test]
fn a_poison_file_omits_itself_while_other_files_still_extract() {
    let (_temp, selection) = project(&[
        ("good_one.rs", "fn good_one() {}\n"),
        ("poison.rs", "fn poison() {}\n"),
        ("good_two.rs", "fn good_two() {}\n"),
    ]);
    let extractor = CrashExtractor {
        behavior: CrashKind::PoisonPath("poison.rs".into()),
        respawns: Arc::new(AtomicUsize::new(0)),
    };
    let prepared = prepare(
        &extractor,
        &selection,
        &ResourceLimits::default(),
        PrepareTestOptions::default(),
        &Deadline::new(None),
        &NeverCancelled,
    )
    .expect("a single poison file must not abort the whole run");
    let files: Vec<_> = prepared
        .snapshot
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect();
    assert_eq!(files, ["good_one.rs", "good_two.rs"]);
    assert_eq!(prepared.snapshot.completeness, CacheCompleteness::Partial);
    let omission = prepared
        .snapshot
        .omissions
        .iter()
        .find(|omission| omission.path == "poison.rs")
        .expect("poison file omission");
    assert_eq!(omission.reason, "extraction-error");
    assert!(
        omission.detail.contains("crash"),
        "a repeatable worker crash must remain distinguishable: {}",
        omission.detail
    );
}

#[test]
fn a_transient_crash_recovers_and_the_file_is_kept() {
    let (_temp, selection) = project(&[("a.rs", "fn a() {}\n")]);
    let respawns = Arc::new(AtomicUsize::new(0));
    let extractor = CrashExtractor {
        behavior: CrashKind::DieOnceThenRecover,
        respawns: Arc::clone(&respawns),
    };
    let prepared = prepare(
        &extractor,
        &selection,
        &ResourceLimits::default(),
        PrepareTestOptions::default(),
        &Deadline::new(None),
        &NeverCancelled,
    )
    .expect("a transient crash must recover on retry");
    assert_eq!(prepared.snapshot.completeness, CacheCompleteness::Complete);
    assert_eq!(prepared.snapshot.files.len(), 1);
    assert_eq!(prepared.snapshot.files[0].path, "a.rs");
    assert_eq!(respawns.load(Ordering::Relaxed), 1);
}

// `prepare_refresh_candidate` (the production, non-`_with` entry point) is
// exercised here for the config-loading seam only: does it load
// `code2graph.toml` from `selection.canonical_root` and propagate a load
// failure? A full round trip through real extraction (proving the rule
// reaches a cross-artifact reference) requires a worker subprocess dispatch
// that only exists in the compiled `code2graph` binary (`main.rs`), not in
// this crate's unit-test binary (`std::env::current_exe()` there is the
// test harness itself) — that combination is covered instead by the
// extractor-level tests in `code2graph::extract::rust` (e.g.
// `cross_artifact_query_binding_resolves_to_sql_table`) and by
// `worker::runtime`'s tests that the wire `custom_rules` merge into
// `BindingRules::with_defaults()`.
#[test]
fn production_entry_point_loads_project_config_with_no_source_to_extract() {
    // No source files admit an `Extract` decision, so `parallel_extract`
    // never spawns a worker subprocess; this isolates the config-loading
    // seam from subprocess dispatch while still exercising the real
    // `prepare_refresh_candidate` entry point end to end.
    let (_temp, selection) = project(&[(
        "code2graph.toml",
        "[[query_binding]]\nlang = \"rust\"\nconstruct = \"mydb::sql\"\nsql_arg = 0\n",
    )]);
    let prepared = prepare_refresh_candidate(PrepareCandidateInputs {
        selection: &selection,
        limits: &ResourceLimits::default(),
        include_hidden: false,
        force: false,
        trust_mtime: false,
        tier: ResolverTier::Name,
        prior: None,
        prepared_at_ns: 1,
        deadline: &Deadline::new(None),
        cancellation: &NeverCancelled,
    })
    .expect("a valid project config must not block preparation");
    assert!(prepared.snapshot.files.is_empty());
}

#[test]
fn production_entry_point_propagates_a_malformed_project_config() {
    let (_temp, selection) =
        project(&[("code2graph.toml", "not = [valid"), ("a.rs", "fn a() {}\n")]);
    assert!(matches!(
        prepare_refresh_candidate(PrepareCandidateInputs {
            selection: &selection,
            limits: &ResourceLimits::default(),
            include_hidden: false,
            force: false,
            trust_mtime: false,
            tier: ResolverTier::Name,
            prior: None,
            prepared_at_ns: 1,
            deadline: &Deadline::new(None),
            cancellation: &NeverCancelled,
        }),
        Err(CliError::Fatal(_))
    ));
}
