// SPDX-License-Identifier: Apache-2.0

//! Publication-ready, in-memory refresh candidate preparation.

use super::{
    PriorFileRecord, PriorScopeState, RefreshDecision, RefreshInputs, RefreshPlan,
    ResolveCandidateInputs, resolve_candidate,
};
use crate::cache::{
    CacheCompleteness, CacheOmission, CandidateFileRecord, CandidateId, CandidateSnapshot,
    CompatibilityFingerprint, CompatibilityRecord, LanguageFeatureFingerprint, LoadedSnapshot,
    PackageFingerprint, ProjectInputDigest, ResolverCacheTier,
};
use crate::config::{ResolverTier, ResourceLimits};
use crate::deadline::{Cancellation, Deadline};
use crate::inventory::{
    MaterializedCandidate, OmissionImpact, OmissionReason, OmittedFile, SourceCandidate,
    SourceDiscovery, discover_sources_checked, materialize_candidate_checked,
};
use crate::package_assignment::assign_packages_checked;
use crate::project::{ProjectPath, ProjectSelection};
use crate::worker::{RequestId, WorkerErrorCode, WorkerFailure, extract_inventory_file};
use crate::{CliError, Result};
use code2graph::{FileFacts, validate_file_facts};
use std::collections::{BTreeMap, BTreeSet};

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
pub trait FactsExtractor {
    fn extract(
        &self,
        file: &crate::inventory::InventoryFile,
        request_id: RequestId,
        deadline: &Deadline,
        cancellation: &dyn Cancellation,
    ) -> Result<FileFacts>;
}
pub struct ProcessFactsExtractor;
impl FactsExtractor for ProcessFactsExtractor {
    fn extract(
        &self,
        file: &crate::inventory::InventoryFile,
        request_id: RequestId,
        deadline: &Deadline,
        cancellation: &dyn Cancellation,
    ) -> Result<FileFacts> {
        extract_inventory_file(file, request_id, deadline, cancellation)
    }
}
pub fn prepare_refresh_candidate(
    inputs: PrepareCandidateInputs<'_>,
) -> Result<PreparedRefreshCandidate> {
    prepare_refresh_candidate_with(&ProcessFactsExtractor, inputs)
}
pub fn prepare_refresh_candidate_with(
    extractor: &dyn FactsExtractor,
    inputs: PrepareCandidateInputs<'_>,
) -> Result<PreparedRefreshCandidate> {
    retry_drift(inputs.deadline, inputs.cancellation, |attempt| {
        prepare(extractor, &inputs, attempt)
    })
}

fn retry_drift<T>(
    deadline: &Deadline,
    cancellation: &dyn Cancellation,
    mut attempt_fn: impl FnMut(u8) -> std::result::Result<T, AttemptError>,
) -> Result<T> {
    for attempt in 1..=super::MAX_REFRESH_ATTEMPTS {
        deadline.check(cancellation)?;
        match attempt_fn(attempt) {
            Err(AttemptError::Drift) => continue,
            Err(AttemptError::Fatal(error)) => return Err(error),
            Ok(candidate) => return Ok(candidate),
        }
    }
    Err(CliError::Index(
        "refresh source continued to drift after bounded retries".into(),
    ))
}
enum AttemptError {
    Drift,
    Fatal(CliError),
}
impl From<CliError> for AttemptError {
    fn from(value: CliError) -> Self {
        Self::Fatal(value)
    }
}

fn prepare(
    extractor: &dyn FactsExtractor,
    inputs: &PrepareCandidateInputs<'_>,
    attempts: u8,
) -> std::result::Result<PreparedRefreshCandidate, AttemptError> {
    inputs.deadline.check(inputs.cancellation)?;
    let mut discovery = discover_sources_checked(
        inputs.selection,
        inputs.limits,
        inputs.include_hidden,
        inputs.deadline,
        inputs.cancellation,
    )?;
    apply_metadata_budgets(&mut discovery, inputs.limits);
    let packages = assign_packages_checked(
        &inputs.selection.canonical_root,
        &discovery.candidates,
        inputs.limits.max_file_bytes,
        inputs.deadline,
        inputs.cancellation,
    )?;
    if packages.diagnostics.iter().any(|d| {
        matches!(
            d.kind,
            crate::package_assignment::PackageDiagnosticKind::ChangedDuringRead
        )
    }) {
        return Err(AttemptError::Drift);
    }
    let assignments: BTreeMap<_, _> = packages
        .assignments
        .iter()
        .map(|a| (a.source_path.clone(), a.canonical_identity()))
        .collect();
    let language_fp = LanguageFeatureFingerprint::current();
    let package_fp = PackageFingerprint::from_selection(
        packages.manifest_fingerprint_records(),
        packages.assignment_fingerprint_records(),
    );
    let compatibility = CompatibilityFingerprint::new(language_fp, package_fp);
    let compatible_prior = inputs.prior.filter(|p| {
        p.compatibility.id == compatibility
            && p.compatibility.language_fingerprint == language_fp
            && p.compatibility.package_fingerprint == package_fp
    });
    let prior_records = match compatible_prior {
        Some(p) => PriorFileRecord::from_loaded_snapshot(p, inputs.tier)?,
        None => Vec::new(),
    };
    let mut plan = RefreshPlan::from_metadata(RefreshInputs {
        discovery: &discovery,
        prior: &prior_records,
        package_assignments: &assignments,
        force: inputs.force,
        trust_mtime: inputs.trust_mtime,
        tier: inputs.tier,
    });
    let prior_files: BTreeMap<_, _> = compatible_prior
        .into_iter()
        .flat_map(|s| s.files.iter())
        .map(|f| (f.path.as_str(), f))
        .collect();
    let candidates: BTreeMap<_, _> = discovery
        .candidates
        .iter()
        .map(|c| (c.path.clone(), c))
        .collect();
    let mut materialized = BTreeMap::new();
    let mut hashes = BTreeMap::new();
    let mut extra_omissions = Vec::new();
    for entry in &plan.entries {
        inputs.deadline.check(inputs.cancellation)?;
        if !matches!(
            entry.decision,
            RefreshDecision::NeedHash | RefreshDecision::Extract
        ) {
            continue;
        }
        let Some(candidate) = candidates.get(&entry.path) else {
            continue;
        };
        match materialize_candidate_checked(
            candidate,
            inputs.limits,
            inputs.deadline,
            inputs.cancellation,
        )? {
            MaterializedCandidate::File(file) => {
                hashes.insert(entry.path.clone(), *blake3::hash(&file.bytes).as_bytes());
                materialized.insert(entry.path.clone(), file);
            }
            MaterializedCandidate::Omitted(o)
                if matches!(o.reason, OmissionReason::ChangedDuringRead) =>
            {
                return Err(AttemptError::Drift);
            }
            MaterializedCandidate::Omitted(o) => extra_omissions.push(o),
        }
    }
    plan.finalize_hashes(&hashes, &prior_records, &assignments, &discovery.candidates);
    for omission in &extra_omissions {
        if let Some(entry) = plan.entries.iter_mut().find(|e| e.path == omission.path) {
            entry.decision = RefreshDecision::Omit {
                reason: omission.reason.clone(),
                impact: omission.impact,
            };
        }
    }
    let mut facts = BTreeMap::new();
    let mut changed = BTreeSet::new();
    let mut request_id: RequestId = 1;
    for entry in &mut plan.entries {
        inputs.deadline.check(inputs.cancellation)?;
        match entry.decision {
            RefreshDecision::ReuseFacts => {
                let prior = prior_files.get(entry.path.as_str()).ok_or_else(|| {
                    CliError::Cache("refresh plan selected missing prior facts".into())
                })?;
                validate_reused(
                    prior,
                    candidates.get(&entry.path),
                    assignments.get(&entry.path),
                )?;
                facts.insert(entry.path.clone(), prior.facts.clone());
            }
            RefreshDecision::Extract => {
                let file = materialized.get(&entry.path).ok_or_else(|| {
                    CliError::Index("extract action lacks materialized source".into())
                })?;
                match extractor.extract(file, request_id, inputs.deadline, inputs.cancellation) {
                    Ok(mut value) => {
                        packages.enrich_file_facts(&mut value);
                        if validate_file_facts(std::slice::from_ref(&value)).is_err() {
                            let omission = OmittedFile::new(
                                entry.path.clone(),
                                OmissionReason::ExtractionError,
                            );
                            entry.decision = RefreshDecision::Omit {
                                reason: omission.reason.clone(),
                                impact: omission.impact,
                            };
                            extra_omissions.push(omission);
                        } else {
                            facts.insert(entry.path.clone(), value);
                            changed.insert(entry.path.as_str().to_owned());
                        }
                    }
                    Err(CliError::Worker(WorkerFailure::Remote(WorkerErrorCode::Extraction))) => {
                        let omission =
                            OmittedFile::new(entry.path.clone(), OmissionReason::ExtractionError);
                        entry.decision = RefreshDecision::Omit {
                            reason: omission.reason.clone(),
                            impact: omission.impact,
                        };
                        extra_omissions.push(omission);
                    }
                    Err(error) => return Err(AttemptError::Fatal(error)),
                }
                request_id = request_id
                    .checked_add(1)
                    .ok_or_else(|| CliError::Index("worker request id exhausted".into()))?;
            }
            _ => {}
        }
    }
    finish(
        inputs,
        attempts,
        AttemptState {
            compatibility,
            language_fp,
            package_fp,
            assignments,
            prior: compatible_prior,
            plan,
            candidates,
            materialized,
            facts,
            changed,
            discovered_omissions: discovery.omitted,
            extra_omissions,
        },
    )
    .map_err(AttemptError::Fatal)
}

struct AttemptState<'a> {
    compatibility: CompatibilityFingerprint,
    language_fp: LanguageFeatureFingerprint,
    package_fp: PackageFingerprint,
    assignments: BTreeMap<ProjectPath, String>,
    prior: Option<&'a LoadedSnapshot>,
    plan: RefreshPlan,
    candidates: BTreeMap<ProjectPath, &'a SourceCandidate>,
    materialized: BTreeMap<ProjectPath, crate::inventory::InventoryFile>,
    facts: BTreeMap<ProjectPath, FileFacts>,
    changed: BTreeSet<String>,
    discovered_omissions: Vec<OmittedFile>,
    extra_omissions: Vec<OmittedFile>,
}

fn finish(
    inputs: &PrepareCandidateInputs<'_>,
    attempts: u8,
    state: AttemptState<'_>,
) -> Result<PreparedRefreshCandidate> {
    inputs.deadline.check(inputs.cancellation)?;
    let AttemptState {
        compatibility,
        language_fp,
        package_fp,
        assignments,
        prior,
        plan,
        candidates,
        materialized,
        facts,
        changed,
        mut discovered_omissions,
        mut extra_omissions,
    } = state;
    discovered_omissions.append(&mut extra_omissions);
    discovered_omissions.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then_with(|| a.reason.tag().cmp(&b.reason.tag()))
    });
    discovered_omissions
        .dedup_by(|a, b| a.path == b.path && a.reason == b.reason && a.impact == b.impact);
    let ignored_omissions: Vec<_> = discovered_omissions
        .iter()
        .filter(|o| o.impact == OmissionImpact::IgnoredNonSource)
        .map(cache_omission)
        .collect();
    let omissions: Vec<_> = discovered_omissions
        .iter()
        .filter(|o| o.impact == OmissionImpact::IncompleteSourceSet)
        .map(cache_omission)
        .collect();
    let mut rows = Vec::new();
    for (path, file_facts) in &facts {
        inputs.deadline.check(inputs.cancellation)?;
        let candidate = candidates
            .get(path)
            .ok_or_else(|| CliError::Index("facts lack current metadata".into()))?;
        let hash = if let Some(file) = materialized.get(path) {
            *blake3::hash(&file.bytes).as_bytes()
        } else {
            prior
                .and_then(|snapshot| {
                    snapshot
                        .files
                        .iter()
                        .find(|file| file.path == path.as_str())
                })
                .map(|file| file.content_hash)
                .ok_or_else(|| CliError::Cache("reused facts lack prior hash".into()))?
        };
        rows.push((
            path.as_str().to_owned(),
            candidate
                .language
                .ok_or_else(|| CliError::Index("admitted facts have no language".into()))?
                .as_str()
                .to_owned(),
            hash,
            candidate.size_bytes,
            candidate.mtime,
            assignments
                .get(path)
                .cloned()
                .ok_or_else(|| CliError::Index("source lacks package assignment".into()))?,
            file_facts.clone(),
        ));
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    let input_digest = ProjectInputDigest::from_inputs(
        rows.iter()
            .map(|row| (row.0.as_str(), row.1.as_str(), row.2)),
    );
    let completeness = if omissions.is_empty() {
        CacheCompleteness::Complete
    } else {
        CacheCompleteness::Partial
    };
    let candidate_id = CandidateId::new(compatibility, input_digest, completeness, &omissions);
    let cache_tier = cache_tier(inputs.tier);
    let prior_scope = if cache_tier == ResolverCacheTier::Scope {
        prior.map(scope_state).transpose()?.flatten()
    } else {
        None
    };
    let deleted: BTreeSet<String> = inputs
        .prior
        .map(|snapshot| {
            snapshot
                .files
                .iter()
                .map(|file| file.path.clone())
                .filter(|path| !facts.keys().any(|current| current.as_str() == path))
                .collect()
        })
        .unwrap_or_default();
    let ordered_facts: Vec<_> = rows.iter().map(|row| row.6.clone()).collect();
    let resolved = resolve_candidate(ResolveCandidateInputs {
        tier: cache_tier,
        files: &ordered_facts,
        candidate_id,
        prior_scope: prior_scope.as_ref(),
        changed_paths: Some(&changed),
        deleted_paths: Some(&deleted),
        deadline: inputs.deadline,
        cancellation: inputs.cancellation,
    })?;
    let files = rows
        .into_iter()
        .map(
            |(path, language, content_hash, size_bytes, mtime, package_assignment, facts)| {
                CandidateFileRecord {
                    subgraph: resolved.file_subgraphs.get(&path).cloned().flatten(),
                    path,
                    language,
                    content_hash,
                    size_bytes,
                    mtime,
                    package_assignment,
                    facts,
                }
            },
        )
        .collect();
    let snapshot = CandidateSnapshot {
        candidate_id,
        compatibility: CompatibilityRecord {
            id: compatibility,
            language_fingerprint: language_fp,
            package_fingerprint: package_fp,
            created_at_ns: inputs.prepared_at_ns,
        },
        input_digest,
        completeness,
        omissions,
        created_at_ns: inputs.prepared_at_ns,
        inventory_file_count: u64::try_from(ordered_facts.len())
            .map_err(|_| CliError::Index("inventory file count overflow".into()))?,
        inventory_total_bytes: rows_total_bytes(&ordered_facts, &candidates)?,
        files,
        tier_graphs: vec![(cache_tier, resolved.graph)],
    };
    Ok(PreparedRefreshCandidate {
        snapshot,
        plan,
        changed_paths: changed.into_iter().collect(),
        deleted_paths: deleted.into_iter().collect(),
        ignored_omissions,
        attempts,
    })
}

fn rows_total_bytes(
    facts: &[FileFacts],
    candidates: &BTreeMap<ProjectPath, &SourceCandidate>,
) -> Result<u64> {
    facts.iter().try_fold(0_u64, |total, facts| {
        let path = ProjectPath::new(std::path::Path::new(&facts.file))?;
        let bytes = candidates
            .get(&path)
            .ok_or_else(|| CliError::Index("resolved file metadata disappeared".into()))?
            .size_bytes;
        total
            .checked_add(bytes)
            .ok_or_else(|| CliError::Index("inventory byte count overflow".into()))
    })
}

fn cache_omission(omission: &OmittedFile) -> CacheOmission {
    CacheOmission {
        path: omission.path.as_str().to_owned(),
        reason: omission.reason.tag(),
        detail: omission.reason.detail(),
    }
}
fn cache_tier(tier: ResolverTier) -> ResolverCacheTier {
    tier.into()
}

fn scope_state(snapshot: &LoadedSnapshot) -> Result<Option<PriorScopeState>> {
    if !snapshot
        .tier_graphs
        .iter()
        .any(|(tier, _)| *tier == ResolverCacheTier::Scope)
    {
        return Ok(None);
    }
    let file_paths = snapshot
        .files
        .iter()
        .map(|file| file.path.clone())
        .collect();
    let subgraphs = snapshot
        .files
        .iter()
        .filter_map(|file| {
            file.subgraph
                .clone()
                .map(|subgraph| (file.path.clone(), subgraph))
        })
        .collect();
    Ok(Some(PriorScopeState {
        candidate_id: snapshot.candidate_id,
        file_paths,
        subgraphs,
    }))
}

fn validate_reused(
    prior: &CandidateFileRecord,
    candidate: Option<&&SourceCandidate>,
    assignment: Option<&String>,
) -> Result<()> {
    let candidate =
        candidate.ok_or_else(|| CliError::Cache("reused facts lack current metadata".into()))?;
    let language = candidate
        .language
        .ok_or_else(|| CliError::Cache("reused facts lack current language".into()))?;
    if prior.path != candidate.path.as_str()
        || prior.language != language.as_str()
        || assignment != Some(&prior.package_assignment)
        || prior.facts.file != prior.path
        || prior.facts.lang != prior.language
    {
        return Err(CliError::Cache(
            "reused facts identity does not match current source".into(),
        ));
    }
    Ok(())
}

pub(crate) fn apply_metadata_budgets(discovery: &mut SourceDiscovery, limits: &ResourceLimits) {
    let mut retained = Vec::new();
    let mut total = 0usize;
    for candidate in discovery.candidates.drain(..) {
        let reason = if candidate.language.is_none() {
            None
        } else if candidate.size_bytes > limits.max_file_bytes as u64 {
            Some(OmissionReason::FileTooLarge {
                limit: limits.max_file_bytes,
            })
        } else if retained.len() >= limits.max_files {
            Some(OmissionReason::FileCountLimit {
                limit: limits.max_files,
            })
        } else if usize::try_from(candidate.size_bytes)
            .ok()
            .and_then(|size| total.checked_add(size))
            .filter(|next| *next <= limits.max_total_bytes)
            .is_none()
        {
            Some(OmissionReason::TotalBytesLimit {
                limit: limits.max_total_bytes,
            })
        } else {
            total += usize::try_from(candidate.size_bytes)
                .expect("file size was checked against the platform-sized limit");
            None
        };
        if let Some(reason) = reason {
            discovery
                .omitted
                .push(OmittedFile::new(candidate.path, reason));
        } else {
            retained.push(candidate);
        }
    }
    discovery.candidates = retained;
    discovery.omitted.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then_with(|| a.reason.tag().cmp(&b.reason.tag()))
    });
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::fs;
    use std::time::Duration;

    use code2graph::{Resolver, ScopeGraphResolver};
    use tempfile::{TempDir, tempdir};

    use super::*;
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
        calls: Cell<usize>,
        behavior: ExtractBehavior,
    }

    impl FakeExtractor {
        fn normal() -> Self {
            Self {
                calls: Cell::new(0),
                behavior: ExtractBehavior::Normal,
            }
        }
    }

    impl FactsExtractor for FakeExtractor {
        fn extract(
            &self,
            file: &crate::inventory::InventoryFile,
            _request_id: RequestId,
            _deadline: &Deadline,
            _cancellation: &dyn Cancellation,
        ) -> Result<FileFacts> {
            self.calls.set(self.calls.get() + 1);
            match self.behavior {
                ExtractBehavior::Normal => code2graph::extract_path(file.path.as_str(), &file.text)
                    .map_err(|error| CliError::Index(error.to_string())),
                ExtractBehavior::InvalidFacts => {
                    let mut facts = code2graph::extract_path(file.path.as_str(), &file.text)
                        .map_err(|error| CliError::Index(error.to_string()))?;
                    facts.symbols.push(facts.symbols[0].clone());
                    Ok(facts)
                }
                ExtractBehavior::RemoteExtractionError => Err(CliError::Worker(
                    WorkerFailure::Remote(WorkerErrorCode::Extraction),
                )),
                ExtractBehavior::InfrastructureError => {
                    Err(CliError::Worker(WorkerFailure::Protocol))
                }
            }
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

    fn prepare<'a>(
        extractor: &dyn FactsExtractor,
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
        assert_eq!(extractor.calls.get(), 1);
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
        assert_eq!(default_extractor.calls.get(), 0);
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
        assert_eq!(trust_extractor.calls.get(), 0);

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
        assert_eq!(force_extractor.calls.get(), 1);
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
        assert_eq!(extractor.calls.get(), 1);
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

        let failure = FakeExtractor {
            calls: Cell::new(0),
            behavior: ExtractBehavior::RemoteExtractionError,
        };
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

        let invalid = FakeExtractor {
            calls: Cell::new(0),
            behavior: ExtractBehavior::InvalidFacts,
        };
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

        let infrastructure = FakeExtractor {
            calls: Cell::new(0),
            behavior: ExtractBehavior::InfrastructureError,
        };
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
        assert_eq!(calls.get(), super::super::MAX_REFRESH_ATTEMPTS);
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
        assert_eq!(extractor.calls.get(), 0);
    }
}
