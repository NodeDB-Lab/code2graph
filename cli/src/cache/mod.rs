// SPDX-License-Identifier: Apache-2.0

//! Deterministic cache identity and bounded persistence codecs.

mod codec;
mod fingerprint;
mod location;
mod schema;
mod store;
mod types;

pub use codec::{
    CACHE_BLOB_MAX_BYTES, CacheError, decode_file_facts, decode_graph, encode_file_facts,
    encode_graph, encode_subgraph, restore_subgraph,
};
pub use fingerprint::{
    CACHE_IMPLEMENTATION_EPOCH, CandidateId, CompatibilityFingerprint, LanguageFeatureFingerprint,
    PackageFingerprint, ProjectInputDigest,
};
pub use location::{CacheLocation, ProjectKey};
pub use store::CacheStore;
pub use types::{
    CacheCompleteness, CacheOmission, CandidateCompleteness, CandidateFileRecord,
    CandidateSnapshot, CompatibilityRecord, LoadedSnapshot, ResolverCacheTier,
};
