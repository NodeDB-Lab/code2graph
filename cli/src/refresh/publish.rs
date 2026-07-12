// SPDX-License-Identifier: Apache-2.0

//! Refresh candidate revalidation and atomic cache publication.

use std::collections::{BTreeMap, BTreeSet};

use crate::cache::{
    CacheCompleteness, CacheOmission, CacheStore, CandidateFileRecord, LoadedSnapshot,
    PackageFingerprint,
};
use crate::config::load_query_binding_rules;
use crate::inventory::{
    MaterializedCandidate, OmissionImpact, SourceCandidate, discover_sources_checked,
    materialize_candidate_checked,
};
use crate::package_assignment::{PackageDiagnosticKind, assign_packages_checked};
use crate::{CliError, Result};

use super::prepare::apply_metadata_budgets;
use super::{
    FactsExtractor, MAX_REFRESH_ATTEMPTS, PrepareCandidateInputs, PreparedRefreshCandidate,
    ProcessFactsExtractor, prepare_refresh_candidate_with,
};

/// The result of preparing, revalidating, and atomically publishing a refresh.
pub struct PublishedRefresh {
    /// The exact candidate that was published.
    pub prepared: PreparedRefreshCandidate,
    /// The candidate as decoded from the cache after publication.
    pub loaded: LoadedSnapshot,
}

/// Prepares a candidate with the production extractor, revalidates all of its
/// source and package inputs, then atomically publishes it.
///
/// Revalidation occurs immediately before `CacheStore::publish_candidate`, but
/// it cannot lock the filesystem. There is no filesystem generation token: a
/// writer can still change a path after that check and before SQLite begins its
/// transaction. Publication is atomic only for the internally coherent cache
/// snapshot; it does not claim a race-free snapshot of the live filesystem.
pub fn prepare_and_publish(
    store: &CacheStore,
    inputs: PrepareCandidateInputs<'_>,
    allow_partial: bool,
) -> Result<PublishedRefresh> {
    let rules = load_query_binding_rules(&inputs.selection.canonical_root)?;
    prepare_and_publish_with(
        &ProcessFactsExtractor::new(rules),
        store,
        inputs,
        allow_partial,
    )
}

/// Equivalent to [`prepare_and_publish`], with an injectable extractor for
/// deterministic callers and unit tests.
pub fn prepare_and_publish_with(
    extractor: &dyn FactsExtractor,
    store: &CacheStore,
    inputs: PrepareCandidateInputs<'_>,
    allow_partial: bool,
) -> Result<PublishedRefresh> {
    prepare_and_publish_inner(extractor, store, inputs, allow_partial, &NoPublicationHook)
}

trait PublicationHook {
    fn before_revalidate(&self) -> Result<()> {
        Ok(())
    }

    fn before_publish(&self) -> Result<()> {
        Ok(())
    }
}

struct NoPublicationHook;
impl PublicationHook for NoPublicationHook {}

fn prepare_and_publish_inner(
    extractor: &dyn FactsExtractor,
    store: &CacheStore,
    inputs: PrepareCandidateInputs<'_>,
    allow_partial: bool,
    hook: &dyn PublicationHook,
) -> Result<PublishedRefresh> {
    if !store.is_writable() {
        return Err(CliError::Cache("cache store is read-only".into()));
    }
    for _ in 1..=MAX_REFRESH_ATTEMPTS {
        inputs.deadline.check(inputs.cancellation)?;
        let prepared = prepare_refresh_candidate_with(
            extractor,
            PrepareCandidateInputs {
                selection: inputs.selection,
                limits: inputs.limits,
                include_hidden: inputs.include_hidden,
                force: inputs.force,
                trust_mtime: inputs.trust_mtime,
                tier: inputs.tier,
                prior: inputs.prior,
                prepared_at_ns: inputs.prepared_at_ns,
                deadline: inputs.deadline,
                cancellation: inputs.cancellation,
            },
        )?;
        if prepared.snapshot.completeness == CacheCompleteness::Partial && !allow_partial {
            return Err(CliError::PartialNotAllowed);
        }
        inputs.deadline.check(inputs.cancellation)?;
        hook.before_revalidate()?;
        if !revalidate_candidate(extractor, &prepared, &inputs)? {
            continue;
        }
        inputs.deadline.check(inputs.cancellation)?;
        hook.before_publish()?;
        inputs.deadline.check(inputs.cancellation)?;
        // CacheStore begins its SQLite write transaction only here. All
        // filesystem discovery, bounded reads, extraction, and revalidation
        // above deliberately happen outside that transaction.
        store.publish_candidate(&prepared.snapshot, inputs.deadline)?;
        inputs.deadline.check(inputs.cancellation)?;
        let loaded = store.load_candidate(prepared.snapshot.candidate_id, inputs.deadline)?;
        return Ok(PublishedRefresh { prepared, loaded });
    }
    Err(CliError::Index(
        "refresh source or manifest continued to drift before publication".into(),
    ))
}

fn revalidate_candidate(
    extractor: &dyn FactsExtractor,
    prepared: &PreparedRefreshCandidate,
    inputs: &PrepareCandidateInputs<'_>,
) -> Result<bool> {
    inputs.deadline.check(inputs.cancellation)?;
    let mut discovery = discover_sources_checked(
        inputs.selection,
        inputs.limits,
        inputs.include_hidden,
        inputs.deadline,
        inputs.cancellation,
    )?;
    apply_metadata_budgets(&mut discovery, inputs.limits);

    let candidate_paths: BTreeSet<_> = prepared
        .snapshot
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect();
    let current_paths: BTreeSet<_> = discovery
        .candidates
        .iter()
        .filter(|candidate| candidate.language.is_some())
        .map(|candidate| candidate.path.as_str())
        .collect();
    let current_omissions: Vec<_> = discovery
        .omitted
        .iter()
        .filter(|omission| omission.impact == OmissionImpact::IncompleteSourceSet)
        .map(cache_omission)
        .collect();
    let omission_paths: BTreeSet<_> = prepared
        .snapshot
        .omissions
        .iter()
        .map(|omission| omission.path.as_str())
        .collect();

    // Every discovered source must be represented either by stored facts or by
    // the candidate's recorded omission. Every recorded omission must still be
    // explained by a discovered source or the same deterministic omission.
    if current_paths
        .iter()
        .any(|path| !candidate_paths.contains(path) && !omission_paths.contains(path))
        || prepared.snapshot.omissions.iter().any(|omission| {
            !current_paths.contains(omission.path.as_str()) && !current_omissions.contains(omission)
        })
        || current_omissions
            .iter()
            .any(|omission| !prepared.snapshot.omissions.contains(omission))
    {
        return Ok(false);
    }

    let candidates: BTreeMap<_, _> = discovery
        .candidates
        .iter()
        .map(|candidate| (candidate.path.as_str(), candidate))
        .collect();
    for record in &prepared.snapshot.files {
        inputs.deadline.check(inputs.cancellation)?;
        let Some(candidate) = candidates.get(record.path.as_str()) else {
            return Ok(false);
        };
        if !matches_record(candidate, record, inputs)? {
            return Ok(false);
        }
    }
    // A candidate-backed omission has no persisted file row. Re-materialize it
    // and require the same current outcome; extraction failures are rerun so a
    // source that has become extractable cannot retain a stale partial slot.
    // Metadata-budget omissions were removed from the candidate map and were
    // compared exactly in `current_omissions` above.
    let mut revalidation_request_id: crate::worker::RequestId = 1;
    for omission in &prepared.snapshot.omissions {
        inputs.deadline.check(inputs.cancellation)?;
        let Some(candidate) = candidates.get(omission.path.as_str()) else {
            continue;
        };
        match materialize_candidate_checked(
            candidate,
            inputs.limits,
            inputs.deadline,
            inputs.cancellation,
        )? {
            MaterializedCandidate::Omitted(current) if cache_omission(&current) == *omission => {}
            MaterializedCandidate::File(file) if omission.reason == "extraction-error" => {
                match extractor.extract(
                    &file,
                    revalidation_request_id,
                    inputs.deadline,
                    inputs.cancellation,
                ) {
                    Err(CliError::Worker(crate::worker::WorkerFailure::Remote(
                        crate::worker::WorkerErrorCode::Extraction,
                    ))) => {}
                    Ok(_) => return Ok(false),
                    Err(error) => return Err(error),
                }
                revalidation_request_id = revalidation_request_id
                    .checked_add(1)
                    .ok_or_else(|| CliError::Index("worker request id exhausted".into()))?;
            }
            _ => return Ok(false),
        }
    }

    let packages = assign_packages_checked(
        &inputs.selection.canonical_root,
        &discovery.candidates,
        inputs.limits.max_file_bytes,
        inputs.deadline,
        inputs.cancellation,
    )?;
    if packages
        .diagnostics
        .iter()
        .any(|diagnostic| matches!(diagnostic.kind, PackageDiagnosticKind::ChangedDuringRead))
    {
        return Ok(false);
    }
    let package_fingerprint = PackageFingerprint::from_selection(
        packages.manifest_fingerprint_records(),
        packages.assignment_fingerprint_records(),
    );
    if package_fingerprint != prepared.snapshot.compatibility.package_fingerprint
        || prepared.snapshot.compatibility.language_fingerprint
            != crate::cache::LanguageFeatureFingerprint::current()
    {
        return Ok(false);
    }
    let assignments: BTreeMap<_, _> = packages
        .assignments
        .iter()
        .map(|assignment| {
            (
                assignment.source_path.as_str(),
                assignment.canonical_identity(),
            )
        })
        .collect();
    Ok(prepared.snapshot.files.iter().all(|record| {
        assignments
            .get(record.path.as_str())
            .is_some_and(|assignment| assignment == &record.package_assignment)
    }))
}

fn matches_record(
    candidate: &SourceCandidate,
    record: &CandidateFileRecord,
    inputs: &PrepareCandidateInputs<'_>,
) -> Result<bool> {
    if candidate.path.as_str() != record.path
        || candidate.language.map(|language| language.as_str()) != Some(record.language.as_str())
    {
        return Ok(false);
    }
    let MaterializedCandidate::File(file) = materialize_candidate_checked(
        candidate,
        inputs.limits,
        inputs.deadline,
        inputs.cancellation,
    )?
    else {
        return Ok(false);
    };
    let size_bytes = u64::try_from(file.bytes.len())
        .map_err(|_| CliError::Index("source size exceeds cache representation".into()))?;
    Ok(file.path.as_str() == record.path
        && file.language.as_str() == record.language
        && file.mtime == record.mtime
        && size_bytes == record.size_bytes
        && *blake3::hash(&file.bytes).as_bytes() == record.content_hash)
}

fn cache_omission(omission: &crate::inventory::OmittedFile) -> CacheOmission {
    CacheOmission {
        path: omission.path.as_str().to_owned(),
        reason: omission.reason.tag(),
        detail: omission.reason.detail(),
    }
}

#[cfg(test)]
fn prepare_and_publish_with_hook(
    extractor: &dyn FactsExtractor,
    store: &CacheStore,
    inputs: PrepareCandidateInputs<'_>,
    allow_partial: bool,
    hook: &dyn PublicationHook,
) -> Result<PublishedRefresh> {
    prepare_and_publish_inner(extractor, store, inputs, allow_partial, hook)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::fs;
    use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
    use std::time::Duration;

    use tempfile::{TempDir, tempdir};

    use super::*;
    use crate::cache::{CacheError, CacheLocation};
    use crate::config::{ResolverTier, ResourceLimits};
    use crate::project::{ProjectSelection, SelectionProvenance};
    use crate::worker::RequestId;
    use crate::{Cancellation, Deadline, NeverCancelled};

    struct Extractor;
    impl FactsExtractor for Extractor {
        fn extract(
            &self,
            file: &crate::inventory::InventoryFile,
            _request_id: RequestId,
            _deadline: &Deadline,
            _cancellation: &dyn Cancellation,
        ) -> Result<code2graph::FileFacts> {
            code2graph::extract_path(file.path.as_str(), &file.text)
                .map_err(|error| CliError::Index(error.to_string()))
        }
    }

    fn project(contents: &str) -> (TempDir, ProjectSelection) {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("project");
        fs::create_dir(&root).expect("root");
        fs::write(root.join("a.rs"), contents).expect("source");
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

    fn store(temp: &TempDir, selection: &ProjectSelection) -> CacheStore {
        let location = CacheLocation::for_project(Some(temp.path()), &selection.canonical_root)
            .expect("location");
        CacheStore::open_writable(&location, &selection.canonical_root, &Deadline::new(None))
            .expect("store")
    }

    fn inputs<'a>(
        selection: &'a ProjectSelection,
        limits: &'a ResourceLimits,
        deadline: &'a Deadline,
    ) -> PrepareCandidateInputs<'a> {
        inputs_with_cancellation(selection, limits, deadline, &NeverCancelled)
    }

    fn inputs_with_cancellation<'a>(
        selection: &'a ProjectSelection,
        limits: &'a ResourceLimits,
        deadline: &'a Deadline,
        cancellation: &'a dyn Cancellation,
    ) -> PrepareCandidateInputs<'a> {
        PrepareCandidateInputs {
            selection,
            limits,
            include_hidden: false,
            force: false,
            trust_mtime: true,
            tier: ResolverTier::Name,
            prior: None,
            prepared_at_ns: 7,
            deadline,
            cancellation,
        }
    }

    #[test]
    fn complete_candidate_publishes_and_loads() {
        let (temp, selection) = project("fn old() {}\n");
        let limits = ResourceLimits::default();
        let deadline = Deadline::new(None);
        let result = prepare_and_publish_with(
            &Extractor,
            &store(&temp, &selection),
            inputs(&selection, &limits, &deadline),
            false,
        )
        .expect("publish");
        assert_eq!(
            result.loaded.candidate_id,
            result.prepared.snapshot.candidate_id
        );
        assert_eq!(result.loaded.completeness, CacheCompleteness::Complete);
    }

    #[test]
    fn partial_candidate_is_not_published_without_explicit_permission() {
        let (temp, selection) = project("fn old() {}\n");
        let limits = ResourceLimits {
            max_files: 0,
            ..ResourceLimits::default()
        };
        let deadline = Deadline::new(None);
        let candidate =
            prepare_refresh_candidate_with(&Extractor, inputs(&selection, &limits, &deadline))
                .expect("candidate");
        let store = store(&temp, &selection);
        assert!(matches!(
            prepare_and_publish_with(
                &Extractor,
                &store,
                inputs(&selection, &limits, &deadline),
                false,
            ),
            Err(CliError::PartialNotAllowed)
        ));
        assert!(matches!(
            store.load_candidate(candidate.snapshot.candidate_id, &deadline),
            Err(CacheError::SnapshotMissing)
        ));
    }

    struct MutateOnce {
        path: std::path::PathBuf,
        done: Cell<bool>,
    }
    impl PublicationHook for MutateOnce {
        fn before_revalidate(&self) -> Result<()> {
            if !self.done.replace(true) {
                fs::write(&self.path, "fn new() {}\n")
                    .map_err(|error| CliError::Index(error.to_string()))?;
            }
            Ok(())
        }
    }

    #[test]
    fn source_drift_retries_and_publishes_the_new_candidate() {
        let (temp, selection) = project("fn old() {}\n");
        let limits = ResourceLimits::default();
        let deadline = Deadline::new(None);
        let before =
            prepare_refresh_candidate_with(&Extractor, inputs(&selection, &limits, &deadline))
                .expect("before");
        let result = prepare_and_publish_with_hook(
            &Extractor,
            &store(&temp, &selection),
            inputs(&selection, &limits, &deadline),
            false,
            &MutateOnce {
                path: selection.canonical_root.join("a.rs"),
                done: Cell::new(false),
            },
        )
        .expect("retry publish");
        assert_ne!(result.loaded.candidate_id, before.snapshot.candidate_id);
        assert_eq!(
            result.loaded.files[0].content_hash,
            *blake3::hash(b"fn new() {}\n").as_bytes()
        );
    }

    struct ContentSensitiveExtractor;
    impl FactsExtractor for ContentSensitiveExtractor {
        fn extract(
            &self,
            file: &crate::inventory::InventoryFile,
            request_id: RequestId,
            deadline: &Deadline,
            cancellation: &dyn Cancellation,
        ) -> Result<code2graph::FileFacts> {
            if file.text.contains("bad") {
                Err(CliError::Worker(crate::worker::WorkerFailure::Remote(
                    crate::worker::WorkerErrorCode::Extraction,
                )))
            } else {
                Extractor.extract(file, request_id, deadline, cancellation)
            }
        }
    }

    #[test]
    fn drifted_extraction_omission_is_not_accepted_as_current() {
        let (temp, selection) = project("fn bad() {}\n");
        let limits = ResourceLimits::default();
        let deadline = Deadline::new(None);
        let result = prepare_and_publish_with_hook(
            &ContentSensitiveExtractor,
            &store(&temp, &selection),
            inputs(&selection, &limits, &deadline),
            true,
            &MutateOnce {
                path: selection.canonical_root.join("a.rs"),
                done: Cell::new(false),
            },
        )
        .expect("changed source must be reprepared instead of preserving the omission");
        assert_eq!(result.loaded.completeness, CacheCompleteness::Complete);
        assert!(result.loaded.omissions.is_empty());
        assert_eq!(result.loaded.files.len(), 1);
    }

    struct AddSourceOnce {
        root: std::path::PathBuf,
        done: Cell<bool>,
    }
    impl PublicationHook for AddSourceOnce {
        fn before_revalidate(&self) -> Result<()> {
            if !self.done.replace(true) {
                fs::write(self.root.join("b.rs"), "fn b() {}\n")
                    .map_err(|error| CliError::Index(error.to_string()))?;
            }
            Ok(())
        }
    }

    #[test]
    fn candidate_source_list_drift_reruns_preparation() {
        let (temp, selection) = project("fn a() {}\n");
        let limits = ResourceLimits::default();
        let deadline = Deadline::new(None);
        let result = prepare_and_publish_with_hook(
            &Extractor,
            &store(&temp, &selection),
            inputs(&selection, &limits, &deadline),
            false,
            &AddSourceOnce {
                root: selection.canonical_root.clone(),
                done: Cell::new(false),
            },
        )
        .expect("retry publish");
        assert_eq!(
            result
                .loaded
                .files
                .iter()
                .map(|file| file.path.as_str())
                .collect::<Vec<_>>(),
            ["a.rs", "b.rs"]
        );
    }

    enum ManifestMutation {
        Add,
        Delete,
        RepairDiagnostic,
    }

    struct MutateManifestOnce {
        path: std::path::PathBuf,
        mutation: ManifestMutation,
        done: Cell<bool>,
    }
    impl PublicationHook for MutateManifestOnce {
        fn before_revalidate(&self) -> Result<()> {
            if self.done.replace(true) {
                return Ok(());
            }
            match self.mutation {
                ManifestMutation::Add => {
                    fs::write(&self.path, "[package]\nname='added'\nversion='1'\n")
                }
                ManifestMutation::Delete => fs::remove_file(&self.path),
                ManifestMutation::RepairDiagnostic => {
                    fs::write(&self.path, "[package]\nname='repaired'\nversion='1'\n")
                }
            }
            .map_err(|error| CliError::Index(error.to_string()))
        }
    }

    fn assert_manifest_mutation_is_reprepared(
        initial_manifest: Option<&str>,
        mutation: ManifestMutation,
    ) {
        let (temp, selection) = project("pub fn a() {}\n");
        let manifest = selection.canonical_root.join("Cargo.toml");
        if let Some(contents) = initial_manifest {
            fs::write(&manifest, contents).expect("initial manifest");
        }
        let limits = ResourceLimits::default();
        let deadline = Deadline::new(None);
        let before =
            prepare_refresh_candidate_with(&Extractor, inputs(&selection, &limits, &deadline))
                .expect("before");
        let result = prepare_and_publish_with_hook(
            &Extractor,
            &store(&temp, &selection),
            inputs(&selection, &limits, &deadline),
            false,
            &MutateManifestOnce {
                path: manifest,
                mutation,
                done: Cell::new(false),
            },
        )
        .expect("retry publish");
        assert_ne!(
            result.loaded.compatibility.package_fingerprint,
            before.snapshot.compatibility.package_fingerprint
        );
        assert_ne!(result.loaded.candidate_id, before.snapshot.candidate_id);
    }

    #[test]
    fn new_deleted_and_diagnostic_manifest_inputs_are_reprepared() {
        assert_manifest_mutation_is_reprepared(None, ManifestMutation::Add);
        assert_manifest_mutation_is_reprepared(
            Some("[package]\nname='deleted'\nversion='1'\n"),
            ManifestMutation::Delete,
        );
        assert_manifest_mutation_is_reprepared(
            Some("not = [valid"),
            ManifestMutation::RepairDiagnostic,
        );
    }

    struct DriftEveryTime {
        path: std::path::PathBuf,
        generation: Cell<u8>,
    }
    impl PublicationHook for DriftEveryTime {
        fn before_revalidate(&self) -> Result<()> {
            let generation = self.generation.get().saturating_add(1);
            self.generation.set(generation);
            fs::write(&self.path, format!("fn generation_{generation}() {{}}\n"))
                .map_err(|error| CliError::Index(error.to_string()))
        }
    }

    struct CountingExtractor {
        calls: AtomicU8,
    }
    impl FactsExtractor for CountingExtractor {
        fn extract(
            &self,
            file: &crate::inventory::InventoryFile,
            request_id: RequestId,
            deadline: &Deadline,
            cancellation: &dyn Cancellation,
        ) -> Result<code2graph::FileFacts> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Extractor.extract(file, request_id, deadline, cancellation)
        }
    }

    #[test]
    fn repeated_revalidation_exhaustion_is_bounded_and_reprepares_every_attempt() {
        let (temp, selection) = project("fn generation_0() {}\n");
        let limits = ResourceLimits::default();
        let deadline = Deadline::new(None);
        let extractor = CountingExtractor {
            calls: AtomicU8::new(0),
        };
        let hook = DriftEveryTime {
            path: selection.canonical_root.join("a.rs"),
            generation: Cell::new(0),
        };
        let store = store(&temp, &selection);
        assert!(matches!(
            prepare_and_publish_with_hook(
                &extractor,
                &store,
                inputs(&selection, &limits, &deadline),
                false,
                &hook,
            ),
            Err(CliError::Index(message)) if message.contains("continued to drift")
        ));
        assert_eq!(hook.generation.get(), MAX_REFRESH_ATTEMPTS);
        assert_eq!(
            extractor.calls.load(Ordering::Relaxed),
            MAX_REFRESH_ATTEMPTS
        );
    }

    #[test]
    fn allowed_partial_publication_preserves_the_complete_slot() {
        let (temp, selection) = project("fn a() {}\n");
        let complete_limits = ResourceLimits::default();
        let partial_limits = ResourceLimits {
            max_files: 0,
            ..ResourceLimits::default()
        };
        let deadline = Deadline::new(None);
        let store = store(&temp, &selection);
        let complete = prepare_and_publish_with(
            &Extractor,
            &store,
            inputs(&selection, &complete_limits, &deadline),
            false,
        )
        .expect("complete");
        let partial = prepare_and_publish_with(
            &Extractor,
            &store,
            inputs(&selection, &partial_limits, &deadline),
            true,
        )
        .expect("partial");
        assert_eq!(partial.loaded.completeness, CacheCompleteness::Partial);
        let still_complete = store
            .load_active(
                crate::cache::ResolverCacheTier::Name,
                CacheCompleteness::Complete,
                complete.loaded.compatibility.id,
                &deadline,
            )
            .expect("load complete")
            .expect("complete slot");
        assert_eq!(still_complete.candidate_id, complete.loaded.candidate_id);
    }

    struct FailBeforePublish;
    impl PublicationHook for FailBeforePublish {
        fn before_publish(&self) -> Result<()> {
            Err(CliError::Index("injected pre-publication failure".into()))
        }
    }

    #[test]
    fn prepublication_failure_leaves_no_candidate_and_retry_is_idempotent() {
        let (temp, selection) = project("fn a() {}\n");
        let limits = ResourceLimits::default();
        let deadline = Deadline::new(None);
        let prepared =
            prepare_refresh_candidate_with(&Extractor, inputs(&selection, &limits, &deadline))
                .expect("prepared");
        let store = store(&temp, &selection);
        assert!(
            prepare_and_publish_with_hook(
                &Extractor,
                &store,
                inputs(&selection, &limits, &deadline),
                false,
                &FailBeforePublish,
            )
            .is_err()
        );
        assert!(matches!(
            store.load_candidate(prepared.snapshot.candidate_id, &deadline),
            Err(CacheError::SnapshotMissing)
        ));
        let first = prepare_and_publish_with(
            &Extractor,
            &store,
            inputs(&selection, &limits, &deadline),
            false,
        )
        .expect("retry");
        let second = prepare_and_publish_with(
            &Extractor,
            &store,
            inputs(&selection, &limits, &deadline),
            false,
        )
        .expect("idempotent retry");
        assert_eq!(first.loaded.candidate_id, second.loaded.candidate_id);
    }

    struct TestCancellation(AtomicBool);
    impl Cancellation for TestCancellation {
        fn is_cancelled(&self) -> bool {
            self.0.load(Ordering::SeqCst)
        }
    }

    struct CancelBeforePublish<'a>(&'a TestCancellation);
    impl PublicationHook for CancelBeforePublish<'_> {
        fn before_publish(&self) -> Result<()> {
            self.0.0.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn cancellation_and_deadline_stop_before_publication() {
        let (temp, selection) = project("fn a() {}\n");
        let limits = ResourceLimits::default();
        let deadline = Deadline::new(None);
        let cancellation = TestCancellation(AtomicBool::new(false));
        let store = store(&temp, &selection);
        assert!(matches!(
            prepare_and_publish_with_hook(
                &Extractor,
                &store,
                inputs_with_cancellation(&selection, &limits, &deadline, &cancellation,),
                false,
                &CancelBeforePublish(&cancellation),
            ),
            Err(CliError::Cancelled)
        ));

        let expired = Deadline::new(Some(Duration::ZERO));
        assert!(matches!(
            prepare_and_publish_with(
                &Extractor,
                &store,
                inputs(&selection, &limits, &expired),
                false,
            ),
            Err(CliError::Timeout)
        ));
    }
}
