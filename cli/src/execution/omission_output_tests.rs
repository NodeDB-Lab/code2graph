// SPDX-License-Identifier: Apache-2.0

use crate::cache::{
    CacheCompleteness, CacheOmission, CandidateId, CompatibilityFingerprint, CompatibilityRecord,
    LanguageFeatureFingerprint, LoadedSnapshot, PackageFingerprint, ProjectInputDigest,
};
use crate::config::{DEFAULT_MAX_OMISSIONS, ResourceLimits};
use crate::result::{CacheReasonCountOutput, IndexOutput, PlanDecisionCountsOutput};
use crate::{
    CacheDisposition, Freshness, OutputEnvelope, OutputStatus, ProjectSelection, ResolverTier,
    SelectionProvenance, StatusOutput,
};

use super::super::lifecycle::{CommandOutput, project_output};
use super::render_human;

fn mixed_snapshot() -> LoadedSnapshot {
    let omissions = (0..265)
        .rev()
        .map(|index| CacheOmission {
            path: format!("src/file{index:04}.rs"),
            reason: match index {
                0..250 => "file-count-limit",
                250..260 => "file-too-large",
                _ => "read-error:other",
            }
            .into(),
            detail: "resource limit".into(),
        })
        .collect::<Vec<_>>();
    let language = LanguageFeatureFingerprint::current();
    let package = PackageFingerprint::from_normalized(["test"]);
    let compatibility = CompatibilityFingerprint::new(language, package);
    let digest = ProjectInputDigest::from_inputs([] as [(&str, &str, [u8; 32]); 0]);
    LoadedSnapshot {
        candidate_id: CandidateId::new(
            compatibility,
            digest,
            CacheCompleteness::Partial,
            &omissions,
        ),
        compatibility: CompatibilityRecord {
            id: compatibility,
            language_fingerprint: language,
            package_fingerprint: package,
            created_at_ns: 1,
        },
        input_digest: digest,
        completeness: CacheCompleteness::Partial,
        omissions,
        created_at_ns: 2,
        inventory_file_count: 3,
        inventory_total_bytes: 42,
        files: Vec::new(),
        tier_graphs: Vec::new(),
    }
}

#[test]
fn index_and_cached_status_count_reasons_outside_capped_entries() {
    let snapshot = mixed_snapshot();
    let expected = vec![
        CacheReasonCountOutput {
            reason: "file-count-limit".into(),
            count: 250,
        },
        CacheReasonCountOutput {
            reason: "file-too-large".into(),
            count: 10,
        },
        CacheReasonCountOutput {
            reason: "read-error:other".into(),
            count: 5,
        },
    ];
    let index = IndexOutput::from_loaded_snapshot(
        &snapshot,
        ResolverTier::Scope,
        0,
        0,
        0,
        1,
        PlanDecisionCountsOutput::default(),
    );
    let selection = ProjectSelection {
        canonical_root: "/project".into(),
        canonical_source: None,
        provenance: SelectionProvenance::RootArgument,
    };
    let project = project_output(
        &selection,
        &snapshot,
        ResolverTier::Scope,
        Freshness::Frozen,
        CacheDisposition::Hit,
    );
    assert_eq!(index.omission_reasons, expected);
    assert_eq!(project.omission_reasons, expected);
    assert_eq!(index.omissions.len(), DEFAULT_MAX_OMISSIONS);
    assert_eq!(index.omissions, project.omissions);
    assert_eq!(index.omitted_files, 265);
    assert_eq!(project.omitted_files, 265);
    assert!(index.omissions_truncated);
    assert!(project.omissions_truncated);
    assert!(
        index
            .omissions
            .iter()
            .all(|entry| entry.reason != "read-error:other")
    );
    assert_eq!(index.omissions[0].path, "src/file0000.rs");
    assert_eq!(index.omissions[255].path, "src/file0255.rs");

    let status = StatusOutput::from_loaded_snapshot(project, &snapshot, &ResourceLimits::default());
    assert_eq!(status.cached_omissions, index.omissions);
    assert_eq!(status.project.omission_reasons, expected);
    assert_eq!(status.inventory.omitted_files, 265);
    let expected_json = serde_json::json!([
        {"reason": "file-count-limit", "count": 250},
        {"reason": "file-too-large", "count": 10},
        {"reason": "read-error:other", "count": 5},
    ]);
    let mut index_json = serde_json::to_value(&index).expect("index JSON");
    let mut project_json = serde_json::to_value(&status.project).expect("project JSON");
    assert_eq!(index_json["omission_reasons"], expected_json);
    assert_eq!(project_json["omissionReasons"], expected_json);
    index_json
        .as_object_mut()
        .expect("index object")
        .remove("omission_reasons");
    project_json
        .as_object_mut()
        .expect("project object")
        .remove("omissionReasons");
    assert!(
        serde_json::from_value::<IndexOutput>(index_json)
            .expect("older index contract")
            .omission_reasons
            .is_empty()
    );
    assert!(
        serde_json::from_value::<crate::ProjectOutput>(project_json)
            .expect("older project contract")
            .omission_reasons
            .is_empty()
    );

    for output in [
        CommandOutput::Index(OutputEnvelope::new(OutputStatus::Partial, index)),
        CommandOutput::Status(OutputEnvelope::new(OutputStatus::Partial, status)),
    ] {
        let rendered = render_human(&output);
        assert!(rendered.contains("warning: omission entries truncated; listing 256 of 265\n"));
        let reasons = rendered
            .lines()
            .filter(|line| line.starts_with("omission reason="))
            .collect::<Vec<_>>();
        assert_eq!(
            reasons,
            [
                "omission reason=file-count-limit count=250",
                "omission reason=file-too-large count=10",
                "omission reason=read-error:other count=5",
            ]
        );
        assert_eq!(
            rendered
                .lines()
                .filter(|line| line.starts_with("omitted src/"))
                .count(),
            DEFAULT_MAX_OMISSIONS
        );
        assert!(!rendered.contains("omitted src/file0260.rs"));
    }
}
