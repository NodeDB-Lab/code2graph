// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};

use code2graph::Language;

use crate::cache::{LoadedSnapshot, ResolverCacheTier};
use crate::config::ResolverTier;
use crate::inventory::{
    MtimeHint, OmissionImpact, OmissionReason, OmittedFile, SourceCandidate, SourceDiscovery,
};
use crate::project::ProjectPath;
use crate::{CliError, Result};

/// Maximum bounded attempts allowed when a filesystem input drifts during refresh.
pub const MAX_REFRESH_ATTEMPTS: u8 = 3;

/// Stable source-free extraction failure for refresh orchestration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtractionError {
    /// The source changed while it was being materialized.
    Drift,
}

/// Cached per-file facts metadata sufficient for refresh planning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriorFileRecord {
    pub path: ProjectPath,
    pub language: Language,
    pub content_hash: [u8; 32],
    pub size_bytes: u64,
    pub mtime: Option<MtimeHint>,
    /// Canonical package-assignment identity, including selected manifest path.
    pub package_assignment: String,
    pub tier: ResolverTier,
}

impl PriorFileRecord {
    /// Converts a loaded cache candidate into refresh metadata only after
    /// validating the persistence invariants needed for reuse.
    pub fn from_loaded_snapshot(
        snapshot: &LoadedSnapshot,
        requested_tier: ResolverTier,
    ) -> Result<Vec<Self>> {
        let requested_cache_tier: ResolverCacheTier = requested_tier.into();
        if !snapshot
            .tier_graphs
            .iter()
            .any(|(tier, _)| *tier == requested_cache_tier)
        {
            return Err(CliError::Cache(
                "requested resolver tier is absent from snapshot".into(),
            ));
        }
        let mut records = Vec::with_capacity(snapshot.files.len());
        let mut previous: Option<&str> = None;
        for file in &snapshot.files {
            if previous.is_some_and(|path| path >= file.path.as_str()) {
                return Err(CliError::Cache(
                    "snapshot file paths are not strictly sorted and unique".into(),
                ));
            }
            let path = ProjectPath::new(std::path::Path::new(&file.path))
                .map_err(|_| CliError::Cache("snapshot contains an invalid project path".into()))?;
            let language = Language::ALL
                .iter()
                .copied()
                .find(|language| language.as_str() == file.language)
                .ok_or_else(|| CliError::Cache("snapshot contains an unknown language".into()))?;
            if !crate::package_assignment::SourcePackageAssignment::is_canonical_identity_for_path(
                &file.package_assignment,
                path.as_str(),
            ) {
                return Err(CliError::Cache(
                    "snapshot contains a non-canonical package assignment".into(),
                ));
            }
            records.push(Self {
                path,
                language,
                content_hash: file.content_hash,
                size_bytes: file.size_bytes,
                mtime: file.mtime,
                package_assignment: file.package_assignment.clone(),
                tier: requested_tier,
            });
            previous = Some(file.path.as_str());
        }
        Ok(records)
    }
}

/// Immutable inputs to the filesystem-free refresh planner.
#[derive(Debug, Clone)]
pub struct RefreshInputs<'a> {
    pub discovery: &'a SourceDiscovery,
    pub prior: &'a [PriorFileRecord],
    /// Canonical assignment identities keyed by source path.
    pub package_assignments: &'a BTreeMap<ProjectPath, String>,
    pub force: bool,
    pub trust_mtime: bool,
    pub tier: ResolverTier,
}

/// A planned action. `NeedHash` explicitly means no reuse claim has been made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshDecision {
    NeedHash,
    ReuseFacts,
    Extract,
    Remove,
    Omit {
        reason: OmissionReason,
        impact: OmissionImpact,
    },
}

/// One deterministic per-path refresh action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshEntry {
    pub path: ProjectPath,
    pub decision: RefreshDecision,
}

/// A sorted refresh plan. Planning itself performs no filesystem reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshPlan {
    pub entries: Vec<RefreshEntry>,
}

impl RefreshPlan {
    /// Produces the metadata plan. Default mode requires materialization before reuse.
    pub fn from_metadata(inputs: RefreshInputs<'_>) -> Self {
        let prior: BTreeMap<_, _> = inputs
            .prior
            .iter()
            .map(|record| (record.path.clone(), record))
            .collect();
        let mut entries = Vec::new();
        let mut current = BTreeSet::new();
        for candidate in &inputs.discovery.candidates {
            current.insert(candidate.path.clone());
            let decision = metadata_decision(
                candidate,
                prior.get(&candidate.path).copied(),
                inputs.package_assignments.get(&candidate.path),
                inputs.force,
                inputs.trust_mtime,
                inputs.tier,
            );
            entries.push(RefreshEntry {
                path: candidate.path.clone(),
                decision,
            });
        }
        for omission in &inputs.discovery.omitted {
            current.insert(omission.path.clone());
            entries.push(RefreshEntry {
                path: omission.path.clone(),
                decision: omission_decision(omission),
            });
        }
        for record in prior.values() {
            if !current.contains(&record.path) {
                entries.push(RefreshEntry {
                    path: record.path.clone(),
                    decision: RefreshDecision::Remove,
                });
            }
        }
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        Self { entries }
    }

    /// Finalizes `NeedHash` actions after bounded materialization produced exact hashes.
    pub fn finalize_hashes(
        &mut self,
        materialized_hashes: &BTreeMap<ProjectPath, [u8; 32]>,
        prior: &[PriorFileRecord],
        package_assignments: &BTreeMap<ProjectPath, String>,
        candidates: &[SourceCandidate],
    ) {
        let prior: BTreeMap<_, _> = prior
            .iter()
            .map(|record| (record.path.clone(), record))
            .collect();
        let candidates: BTreeMap<_, _> = candidates
            .iter()
            .map(|candidate| (candidate.path.clone(), candidate))
            .collect();
        for entry in &mut self.entries {
            if entry.decision != RefreshDecision::NeedHash {
                continue;
            }
            let Some(candidate) = candidates.get(&entry.path) else {
                entry.decision = RefreshDecision::Extract;
                continue;
            };
            let Some(record) = prior.get(&entry.path) else {
                entry.decision = RefreshDecision::Extract;
                continue;
            };
            entry.decision = if candidate.language == Some(record.language)
                && package_assignments
                    .get(&entry.path)
                    .is_some_and(|assignment| assignment == &record.package_assignment)
                && materialized_hashes
                    .get(&entry.path)
                    .is_some_and(|hash| hash == &record.content_hash)
            {
                RefreshDecision::ReuseFacts
            } else {
                RefreshDecision::Extract
            };
        }
    }
}

fn omission_decision(omission: &OmittedFile) -> RefreshDecision {
    RefreshDecision::Omit {
        reason: omission.reason.clone(),
        impact: omission.impact,
    }
}

fn metadata_decision(
    candidate: &SourceCandidate,
    prior: Option<&PriorFileRecord>,
    assignment: Option<&String>,
    force: bool,
    trust_mtime: bool,
    tier: ResolverTier,
) -> RefreshDecision {
    let Some(language) = candidate.language else {
        let reason = match candidate.classification {
            crate::inventory::FileClassification::FeatureDisabled(language) => {
                OmissionReason::FeatureDisabled { language }
            }
            crate::inventory::FileClassification::UnrecognizedExtension => {
                OmissionReason::UnrecognizedExtension
            }
            crate::inventory::FileClassification::Enabled(_) => {
                OmissionReason::UnrecognizedExtension
            }
        };
        return omission_decision(&OmittedFile::new(candidate.path.clone(), reason));
    };
    if force {
        return RefreshDecision::Extract;
    }
    let Some(prior) = prior else {
        return RefreshDecision::Extract;
    };
    if prior.language != language
        || prior.tier != tier
        || assignment != Some(&prior.package_assignment)
    {
        return RefreshDecision::Extract;
    }
    let exact_mtime = prior
        .mtime
        .zip(candidate.mtime)
        .is_some_and(|(prior, current)| prior == current);
    if trust_mtime && prior.size_bytes == candidate.size_bytes && exact_mtime {
        RefreshDecision::ReuseFacts
    } else {
        RefreshDecision::NeedHash
    }
}
