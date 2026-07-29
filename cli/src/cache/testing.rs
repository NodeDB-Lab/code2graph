// SPDX-License-Identifier: Apache-2.0

//! Publishable cache fixtures shared by tests across the crate.

use code2graph::{CodeGraph, FileFacts};

use super::{
    CacheCompleteness, CandidateFileRecord, CandidateId, CandidateSnapshot,
    CompatibilityFingerprint, CompatibilityRecord, LanguageFeatureFingerprint, PackageFingerprint,
    ProjectInputDigest, ResolverCacheTier,
};
use crate::inventory::MtimeHint;

/// A minimal complete candidate holding one Rust file's empty facts, published
/// under `tier`. Tests that need a cache with real content to corrupt or reload
/// start here instead of driving a full index, which cannot run in-process (the
/// worker executable would be the test harness).
pub(crate) fn single_file_candidate(path: &str, tier: ResolverCacheTier) -> CandidateSnapshot {
    let facts = FileFacts {
        file: path.to_owned(),
        lang: "rust".into(),
        symbols: Vec::new(),
        references: Vec::new(),
        scopes: Vec::new(),
        bindings: Vec::new(),
        ffi_exports: Vec::new(),
    };
    let hash = [3; 32];
    let input_digest = ProjectInputDigest::from_inputs([(path, "rust", hash)]);
    let language_fingerprint = LanguageFeatureFingerprint::current();
    let package_fingerprint = PackageFingerprint::from_normalized(["test"]);
    let compatibility = CompatibilityFingerprint::new(language_fingerprint, package_fingerprint);
    let omissions = Vec::new();
    CandidateSnapshot {
        candidate_id: CandidateId::new(
            compatibility,
            input_digest,
            CacheCompleteness::Complete,
            &omissions,
        ),
        compatibility: CompatibilityRecord {
            id: compatibility,
            language_fingerprint,
            package_fingerprint,
            created_at_ns: 1,
        },
        input_digest,
        completeness: CacheCompleteness::Complete,
        omissions,
        created_at_ns: 2,
        inventory_file_count: 1,
        inventory_total_bytes: 1,
        files: vec![CandidateFileRecord {
            path: path.to_owned(),
            language: "rust".into(),
            content_hash: hash,
            size_bytes: 1,
            mtime: Some(MtimeHint {
                seconds_since_unix_epoch: 0,
                nanoseconds: 0,
            }),
            package_assignment: format!("10:assignment{}:{path}4:none", path.len()),
            facts,
            subgraph: None,
        }],
        tier_graphs: vec![(
            tier,
            CodeGraph {
                symbols: Vec::new(),
                edges: Vec::new(),
            },
        )],
    }
}
