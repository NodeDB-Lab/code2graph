// SPDX-License-Identifier: Apache-2.0

//! Candidate assembly, retry handling, and resolution pipeline.

use super::super::{
    PriorFileRecord, PriorScopeState, RefreshDecision, RefreshInputs, RefreshPlan,
    ResolveCandidateInputs, resolve_candidate,
};
use super::api::ExtractionOutcome;
use super::pool::{ExtractWorkItem, parallel_extract};
use super::*;
use crate::cache::{
    CacheCompleteness, CacheOmission, CandidateFileRecord, CandidateId, CandidateSnapshot,
    CompatibilityFingerprint, CompatibilityRecord, LanguageFeatureFingerprint, LoadedSnapshot,
    PackageFingerprint, ProjectInputDigest, ResolverCacheTier,
};
use crate::config::{ResolverTier, load_query_binding_rules};
use crate::deadline::{Cancellation, Deadline};
use crate::inventory::{
    MaterializedCandidate, OmissionImpact, OmissionReason, OmittedFile, SourceCandidate,
    discover_sources_checked, materialize_candidate_checked,
};
use crate::package_assignment::assign_packages_checked;
use crate::project::ProjectPath;
use crate::worker::{RequestId, WorkerErrorCode, WorkerFailure};
use crate::{CliError, Result};
use code2graph::{FileFacts, validate_file_facts};
use std::collections::{BTreeMap, BTreeSet};
pub fn prepare_refresh_candidate(
    inputs: PrepareCandidateInputs<'_>,
) -> Result<PreparedRefreshCandidate> {
    let rules = load_query_binding_rules(&inputs.selection.canonical_root)?;
    prepare_refresh_candidate_with(&ProcessFactsExtractor::new(rules), inputs)
}
pub fn prepare_refresh_candidate_with<E: FactsExtractor>(
    extractor: &E,
    inputs: PrepareCandidateInputs<'_>,
) -> Result<PreparedRefreshCandidate> {
    retry_drift(inputs.deadline, inputs.cancellation, |attempt| {
        prepare(extractor, &inputs, attempt)
    })
}

pub(super) fn retry_drift<T>(
    deadline: &Deadline,
    cancellation: &dyn Cancellation,
    mut attempt_fn: impl FnMut(u8) -> std::result::Result<T, AttemptError>,
) -> Result<T> {
    for attempt in 1..=super::super::MAX_REFRESH_ATTEMPTS {
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
pub(super) enum AttemptError {
    Drift,
    Fatal(CliError),
}
impl From<CliError> for AttemptError {
    fn from(value: CliError) -> Self {
        Self::Fatal(value)
    }
}

fn prepare<E: FactsExtractor>(
    extractor: &E,
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
    let mut omission_details = BTreeMap::new();
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

    // Pass 1 (sequential): apply the cheap `ReuseFacts` decisions in place and
    // gather the `Extract` decisions — each a fresh worker subprocess — into a
    // work list. Request ids are assigned here, in plan order, so the outcome is
    // independent of the concurrent execution order below.
    let mut extract_work: Vec<ExtractWorkItem<'_>> = Vec::new();
    let mut request_id: RequestId = 1;
    for (index, entry) in plan.entries.iter().enumerate() {
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
                extract_work.push(ExtractWorkItem {
                    index,
                    file,
                    request_id,
                });
                request_id = request_id
                    .checked_add(1)
                    .ok_or_else(|| CliError::Index("worker request id exhausted".into()))?;
            }
            _ => {}
        }
    }

    // Pass 2 (parallel): run the independent per-file extractions across a bounded
    // pool. Results come back keyed by plan index and are merged in that order, so
    // `facts`, `changed`, and `extra_omissions` are identical to a serial run.
    let extracted = parallel_extract(
        extractor,
        &extract_work,
        inputs.deadline,
        inputs.cancellation,
    );

    // Pass 3 (sequential, in plan order): apply each extraction outcome.
    for (index, result) in extracted {
        inputs.deadline.check(inputs.cancellation)?;
        let path = plan.entries[index].path.clone();
        match result {
            Ok(ExtractionOutcome::Facts(mut value)) => {
                packages.enrich_file_facts(&mut value);
                if let Err(error) = validate_file_facts(std::slice::from_ref(&value)) {
                    let omission = OmittedFile::new(path.clone(), OmissionReason::ExtractionError);
                    omission_details.insert(
                        path,
                        bounded_detail("post-enrichment-validation", &error.to_string()),
                    );
                    plan.entries[index].decision = RefreshDecision::Omit {
                        reason: omission.reason.clone(),
                        impact: omission.impact,
                    };
                    extra_omissions.push(omission);
                } else {
                    changed.insert(path.as_str().to_owned());
                    facts.insert(path, value);
                }
            }
            Ok(ExtractionOutcome::Omitted { detail }) => {
                let omission = OmittedFile::new(path.clone(), OmissionReason::ExtractionError);
                omission_details.insert(path, detail);
                plan.entries[index].decision = RefreshDecision::Omit {
                    reason: omission.reason.clone(),
                    impact: omission.impact,
                };
                extra_omissions.push(omission);
            }
            Err(CliError::Worker(WorkerFailure::Remote(WorkerErrorCode::Extraction))) => {
                let omission = OmittedFile::new(path.clone(), OmissionReason::ExtractionError);
                omission_details.insert(
                    path,
                    "stage=worker-extraction error=worker returned extraction failure".into(),
                );
                plan.entries[index].decision = RefreshDecision::Omit {
                    reason: omission.reason.clone(),
                    impact: omission.impact,
                };
                extra_omissions.push(omission);
            }
            Err(error) => return Err(AttemptError::Fatal(error)),
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
            omission_details,
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
    omission_details: BTreeMap<crate::project::ProjectPath, String>,
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
        omission_details,
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
        .map(|o| cache_omission(o, omission_details.get(&o.path)))
        .collect();
    let omissions: Vec<_> = discovered_omissions
        .iter()
        .filter(|o| o.impact == OmissionImpact::IncompleteSourceSet)
        .map(|o| cache_omission(o, omission_details.get(&o.path)))
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

pub(crate) fn bounded_detail(stage: &str, error: &str) -> String {
    const MAX_DETAIL_BYTES: usize = 512;
    let mut detail = format!("stage={stage} error={error}");
    if detail.len() > MAX_DETAIL_BYTES {
        detail.truncate(MAX_DETAIL_BYTES);
        while !detail.is_char_boundary(detail.len()) {
            detail.pop();
        }
    }
    detail
}

fn cache_omission(omission: &OmittedFile, detail_override: Option<&String>) -> CacheOmission {
    CacheOmission {
        path: omission.path.as_str().to_owned(),
        reason: omission.reason.tag(),
        detail: detail_override
            .cloned()
            .unwrap_or_else(|| omission.reason.detail()),
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
