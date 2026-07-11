// SPDX-License-Identifier: Apache-2.0

//! Pure refresh-plan construction and hash finalization.

pub use super::types::{
    PriorFileRecord, RefreshDecision, RefreshEntry, RefreshInputs, RefreshPlan,
};

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use code2graph::Language;

    use super::*;
    use crate::cache::{
        CacheCompleteness, CandidateFileRecord, CandidateId, CompatibilityFingerprint,
        CompatibilityRecord, LanguageFeatureFingerprint, LoadedSnapshot, PackageFingerprint,
        ProjectInputDigest, ResolverCacheTier,
    };
    use crate::config::ResolverTier;
    use crate::inventory::{
        FileClassification, MtimeHint, OmissionImpact, OmissionReason, OmittedFile,
        SourceCandidate, SourceDiscovery, StableIdentity,
    };
    use crate::project::ProjectPath;

    fn path(value: &str) -> ProjectPath {
        ProjectPath::new(std::path::Path::new(value)).expect("path")
    }
    fn candidate(value: &str) -> SourceCandidate {
        SourceCandidate {
            path: path(value),
            language: Some(Language::Rust),
            classification: FileClassification::Enabled(Language::Rust),
            size_bytes: 3,
            mtime: Some(MtimeHint {
                seconds_since_unix_epoch: -1,
                nanoseconds: 2,
            }),
            identity: StableIdentity {
                device: Some(1),
                inode: Some(2),
            },
            absolute_path: PathBuf::from(value),
        }
    }
    fn prior(value: &str) -> PriorFileRecord {
        PriorFileRecord {
            path: path(value),
            language: Language::Rust,
            content_hash: [1; 32],
            size_bytes: 3,
            mtime: Some(MtimeHint {
                seconds_since_unix_epoch: -1,
                nanoseconds: 2,
            }),
            package_assignment: "package".into(),
            tier: ResolverTier::Scope,
        }
    }

    fn loaded_snapshot(path_value: &str, assignment: String) -> LoadedSnapshot {
        let language = LanguageFeatureFingerprint::current();
        let package = PackageFingerprint::from_normalized(["package"]);
        let compatibility = CompatibilityFingerprint::new(language, package);
        let input = ProjectInputDigest::from_inputs([(path_value, "rust", [7_u8; 32])]);
        let candidate_id = CandidateId::new(compatibility, input, CacheCompleteness::Complete, &[]);
        LoadedSnapshot {
            candidate_id,
            compatibility: CompatibilityRecord {
                id: compatibility,
                language_fingerprint: language,
                package_fingerprint: package,
                created_at_ns: 1,
            },
            input_digest: input,
            completeness: CacheCompleteness::Complete,
            omissions: Vec::new(),
            created_at_ns: 2,
            inventory_file_count: 1,
            inventory_total_bytes: 3,
            files: vec![CandidateFileRecord {
                path: path_value.into(),
                language: "rust".into(),
                content_hash: [7; 32],
                size_bytes: 3,
                mtime: None,
                package_assignment: assignment,
                facts: code2graph::FileFacts {
                    file: path_value.into(),
                    lang: "rust".into(),
                    symbols: Vec::new(),
                    references: Vec::new(),
                    scopes: Vec::new(),
                    bindings: Vec::new(),
                    ffi_exports: Vec::new(),
                },
                subgraph: None,
            }],
            tier_graphs: vec![(
                ResolverCacheTier::Name,
                code2graph::CodeGraph {
                    symbols: Vec::new(),
                    edges: Vec::new(),
                },
            )],
        }
    }

    #[test]
    fn loaded_snapshot_conversion_preserves_exact_hash_and_rejects_wrong_tier_or_assignment() {
        let assignment = crate::package_assignment::SourcePackageAssignment {
            source_path: path("src/a.rs"),
            manifest_path: None,
            package: None,
        }
        .canonical_identity();
        let snapshot = loaded_snapshot("src/a.rs", assignment);
        let records = PriorFileRecord::from_loaded_snapshot(&snapshot, ResolverTier::Name)
            .expect("valid loaded snapshot");
        assert_eq!(records[0].content_hash, [7; 32]);
        assert_eq!(records[0].tier, ResolverTier::Name);
        assert!(matches!(
            PriorFileRecord::from_loaded_snapshot(&snapshot, ResolverTier::Scope),
            Err(crate::CliError::Cache(_))
        ));

        let aliased =
            snapshot.files[0]
                .package_assignment
                .replacen("10:assignment", "010:assignment", 1);
        let malformed = loaded_snapshot("src/a.rs", aliased);
        assert!(matches!(
            PriorFileRecord::from_loaded_snapshot(&malformed, ResolverTier::Name),
            Err(crate::CliError::Cache(_))
        ));
    }

    #[test]
    fn trust_mtime_reuses_without_hash_and_default_requires_hash() {
        let discovery = SourceDiscovery {
            candidates: vec![candidate("a.rs")],
            omitted: Vec::new(),
        };
        let assignments = BTreeMap::from([(path("a.rs"), "package".into())]);
        let trust = RefreshPlan::from_metadata(RefreshInputs {
            discovery: &discovery,
            prior: &[prior("a.rs")],
            package_assignments: &assignments,
            force: false,
            trust_mtime: true,
            tier: ResolverTier::Scope,
        });
        assert_eq!(trust.entries[0].decision, RefreshDecision::ReuseFacts);
        let default = RefreshPlan::from_metadata(RefreshInputs {
            discovery: &discovery,
            prior: &[prior("a.rs")],
            package_assignments: &assignments,
            force: false,
            trust_mtime: false,
            tier: ResolverTier::Scope,
        });
        assert_eq!(default.entries[0].decision, RefreshDecision::NeedHash);
    }

    #[test]
    fn trust_mtime_requires_present_exact_size_time_language_tier_and_package() {
        let assignments = BTreeMap::from([(path("a.rs"), "package".into())]);
        let plan_for = |candidate: SourceCandidate,
                        prior: PriorFileRecord,
                        assignments: &BTreeMap<ProjectPath, String>,
                        tier| {
            let discovery = SourceDiscovery {
                candidates: vec![candidate],
                omitted: Vec::new(),
            };
            RefreshPlan::from_metadata(RefreshInputs {
                discovery: &discovery,
                prior: &[prior],
                package_assignments: assignments,
                force: false,
                trust_mtime: true,
                tier,
            })
            .entries
            .remove(0)
            .decision
        };
        assert_eq!(
            plan_for(
                candidate("a.rs"),
                prior("a.rs"),
                &assignments,
                ResolverTier::Scope
            ),
            RefreshDecision::ReuseFacts
        );
        let mut changed = candidate("a.rs");
        changed.size_bytes += 1;
        assert_eq!(
            plan_for(changed, prior("a.rs"), &assignments, ResolverTier::Scope),
            RefreshDecision::NeedHash
        );
        let mut changed = candidate("a.rs");
        changed.mtime = Some(MtimeHint {
            seconds_since_unix_epoch: -2,
            nanoseconds: 999_999_999,
        });
        assert_eq!(
            plan_for(changed, prior("a.rs"), &assignments, ResolverTier::Scope),
            RefreshDecision::NeedHash
        );
        let mut no_times = candidate("a.rs");
        no_times.mtime = None;
        let mut no_prior_time = prior("a.rs");
        no_prior_time.mtime = None;
        assert_eq!(
            plan_for(no_times, no_prior_time, &assignments, ResolverTier::Scope),
            RefreshDecision::NeedHash
        );
        let mut wrong_language = prior("a.rs");
        wrong_language.language = Language::Python;
        assert_eq!(
            plan_for(
                candidate("a.rs"),
                wrong_language,
                &assignments,
                ResolverTier::Scope
            ),
            RefreshDecision::Extract
        );
        assert_eq!(
            plan_for(
                candidate("a.rs"),
                prior("a.rs"),
                &assignments,
                ResolverTier::Name
            ),
            RefreshDecision::Extract
        );
        assert_eq!(
            plan_for(
                candidate("a.rs"),
                prior("a.rs"),
                &BTreeMap::new(),
                ResolverTier::Scope
            ),
            RefreshDecision::Extract
        );
        let changed_assignment = BTreeMap::from([(path("a.rs"), "other".into())]);
        assert_eq!(
            plan_for(
                candidate("a.rs"),
                prior("a.rs"),
                &changed_assignment,
                ResolverTier::Scope,
            ),
            RefreshDecision::Extract
        );
    }

    #[test]
    fn hash_finalization_is_authoritative_and_removals_are_deterministic() {
        let discovery = SourceDiscovery {
            candidates: vec![candidate("z.rs")],
            omitted: Vec::new(),
        };
        let assignments = BTreeMap::from([(path("z.rs"), "package".into())]);
        let prior_records = vec![prior("a.rs"), prior("z.rs")];
        let original_prior = prior_records.clone();
        let make_plan = || {
            RefreshPlan::from_metadata(RefreshInputs {
                discovery: &discovery,
                prior: &prior_records,
                package_assignments: &assignments,
                force: false,
                trust_mtime: false,
                tier: ResolverTier::Scope,
            })
        };
        let mut matching = make_plan();
        assert_eq!(
            matching
                .entries
                .iter()
                .map(|entry| entry.path.as_str())
                .collect::<Vec<_>>(),
            ["a.rs", "z.rs"]
        );
        assert_eq!(matching.entries[1].decision, RefreshDecision::NeedHash);
        matching.finalize_hashes(
            &BTreeMap::from([(path("z.rs"), [1; 32])]),
            &prior_records,
            &assignments,
            &discovery.candidates,
        );
        assert_eq!(matching.entries[0].decision, RefreshDecision::Remove);
        assert_eq!(matching.entries[1].decision, RefreshDecision::ReuseFacts);

        let mut changed = make_plan();
        changed.finalize_hashes(
            &BTreeMap::from([(path("z.rs"), [2; 32])]),
            &prior_records,
            &assignments,
            &discovery.candidates,
        );
        assert_eq!(changed.entries[1].decision, RefreshDecision::Extract);

        let mut absent = make_plan();
        absent.finalize_hashes(
            &BTreeMap::new(),
            &prior_records,
            &assignments,
            &discovery.candidates,
        );
        assert_eq!(absent.entries[1].decision, RefreshDecision::Extract);
        assert_eq!(
            prior_records, original_prior,
            "planning must not restamp cached records"
        );
    }

    #[test]
    fn force_new_delete_omit_and_duplicate_prior_paths_are_truthful() {
        let discovery = SourceDiscovery {
            candidates: vec![candidate("new.rs"), candidate("old.rs")],
            omitted: vec![OmittedFile::new(
                path("denied.rs"),
                OmissionReason::ReadError {
                    kind: crate::inventory::StableIoErrorKind::PermissionDenied,
                },
            )],
        };
        let assignments = BTreeMap::from([
            (path("new.rs"), "package".into()),
            (path("old.rs"), "package".into()),
        ]);
        let prior_records = vec![prior("deleted.rs"), prior("deleted.rs"), prior("old.rs")];
        let plan = RefreshPlan::from_metadata(RefreshInputs {
            discovery: &discovery,
            prior: &prior_records,
            package_assignments: &assignments,
            force: true,
            trust_mtime: true,
            tier: ResolverTier::Scope,
        });
        assert_eq!(
            plan.entries,
            vec![
                RefreshEntry {
                    path: path("deleted.rs"),
                    decision: RefreshDecision::Remove,
                },
                RefreshEntry {
                    path: path("denied.rs"),
                    decision: RefreshDecision::Omit {
                        reason: OmissionReason::ReadError {
                            kind: crate::inventory::StableIoErrorKind::PermissionDenied,
                        },
                        impact: OmissionImpact::IncompleteSourceSet,
                    },
                },
                RefreshEntry {
                    path: path("new.rs"),
                    decision: RefreshDecision::Extract,
                },
                RefreshEntry {
                    path: path("old.rs"),
                    decision: RefreshDecision::Extract,
                },
            ]
        );
    }

    #[test]
    fn plan_preserves_directory_omission_impact_that_cannot_be_rederived_from_path() {
        let directory_omission = OmittedFile::traversal_directory(
            path("vendor"),
            OmissionReason::ReadError {
                kind: crate::inventory::StableIoErrorKind::PermissionDenied,
            },
        );
        let ordinary_non_source = OmittedFile::new(
            path("vendor"),
            OmissionReason::ReadError {
                kind: crate::inventory::StableIoErrorKind::PermissionDenied,
            },
        );
        assert_eq!(
            directory_omission.impact,
            OmissionImpact::IncompleteSourceSet
        );
        assert_eq!(ordinary_non_source.impact, OmissionImpact::IgnoredNonSource);

        for (omission, expected) in [
            (directory_omission, OmissionImpact::IncompleteSourceSet),
            (ordinary_non_source, OmissionImpact::IgnoredNonSource),
        ] {
            let discovery = SourceDiscovery {
                candidates: Vec::new(),
                omitted: vec![omission],
            };
            let plan = RefreshPlan::from_metadata(RefreshInputs {
                discovery: &discovery,
                prior: &[],
                package_assignments: &BTreeMap::new(),
                force: false,
                trust_mtime: false,
                tier: ResolverTier::Scope,
            });
            assert!(matches!(
                &plan.entries[0].decision,
                RefreshDecision::Omit { impact, .. } if *impact == expected
            ));
        }
    }
}
