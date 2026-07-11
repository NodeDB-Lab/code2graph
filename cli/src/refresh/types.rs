// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};

use code2graph::Language;

use crate::config::ResolverTier;
use crate::inventory::{MtimeHint, OmissionReason, SourceCandidate, SourceDiscovery};
use crate::project::ProjectPath;

/// Cached per-file facts metadata sufficient for refresh planning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriorFileRecord {
    pub path: ProjectPath,
    pub language: Language,
    pub content_hash: String,
    pub size_bytes: u64,
    pub mtime: Option<MtimeHint>,
    /// Canonical package-assignment identity, including selected manifest path.
    pub package_assignment: String,
    pub tier: ResolverTier,
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
    Omit(OmissionReason),
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
                decision: RefreshDecision::Omit(omission.reason.clone()),
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
        materialized_hashes: &BTreeMap<ProjectPath, String>,
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

fn metadata_decision(
    candidate: &SourceCandidate,
    prior: Option<&PriorFileRecord>,
    assignment: Option<&String>,
    force: bool,
    trust_mtime: bool,
    tier: ResolverTier,
) -> RefreshDecision {
    let Some(language) = candidate.language else {
        return RefreshDecision::Omit(match candidate.classification {
            crate::inventory::FileClassification::FeatureDisabled(language) => {
                OmissionReason::FeatureDisabled { language }
            }
            crate::inventory::FileClassification::UnrecognizedExtension => {
                OmissionReason::UnrecognizedExtension
            }
            crate::inventory::FileClassification::Enabled(_) => {
                OmissionReason::UnrecognizedExtension
            }
        });
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
