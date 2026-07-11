// SPDX-License-Identifier: Apache-2.0

//! Public, owned values used to publish and load derived cache snapshots.

use code2graph::{CodeGraph, FileFacts, FileSubgraph};

use crate::inventory::MtimeHint;

use super::{CandidateId, CompatibilityFingerprint, ProjectInputDigest};

/// Resolver output stored in a cache graph snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResolverCacheTier {
    Name,
    Scope,
    Dense,
}

/// Whether a candidate covers every discovered project input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CacheCompleteness {
    Complete,
    Partial,
}

/// Backwards-compatible name for [`CacheCompleteness`].
pub type CandidateCompleteness = CacheCompleteness;

/// A canonical omission included in a partial candidate identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CacheOmission {
    pub path: String,
    pub reason: String,
}

/// Compatibility provenance recorded alongside a candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatibilityRecord {
    pub id: CompatibilityFingerprint,
    pub created_at_ns: u64,
}

/// One source file's structural facts and optional Tier-B incremental state.
#[derive(Clone)]
pub struct CandidateFileRecord {
    pub path: String,
    pub language: String,
    pub content_hash: [u8; 32],
    pub size_bytes: u64,
    pub mtime: Option<MtimeHint>,
    pub facts: FileFacts,
    pub subgraph: Option<FileSubgraph>,
}

/// A self-contained publication candidate. `files` and `tier_graphs` must be
/// sorted and unique by path and tier respectively.
#[derive(Clone)]
pub struct CandidateSnapshot {
    pub candidate_id: CandidateId,
    pub compatibility: CompatibilityRecord,
    pub input_digest: ProjectInputDigest,
    pub completeness: CacheCompleteness,
    pub omissions: Vec<CacheOmission>,
    pub created_at_ns: u64,
    pub inventory_file_count: u64,
    pub inventory_total_bytes: u64,
    pub files: Vec<CandidateFileRecord>,
    pub tier_graphs: Vec<(ResolverCacheTier, CodeGraph)>,
}

/// A coherently loaded candidate and its available resolver graphs.
#[derive(Clone)]
pub struct LoadedSnapshot {
    pub candidate_id: CandidateId,
    pub compatibility: CompatibilityRecord,
    pub input_digest: ProjectInputDigest,
    pub completeness: CacheCompleteness,
    pub omissions: Vec<CacheOmission>,
    pub created_at_ns: u64,
    pub inventory_file_count: u64,
    pub inventory_total_bytes: u64,
    pub files: Vec<CandidateFileRecord>,
    pub tier_graphs: Vec<(ResolverCacheTier, CodeGraph)>,
}
