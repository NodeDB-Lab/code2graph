// SPDX-License-Identifier: Apache-2.0

//! Resolution: link references to definitions, producing cross-file edges.
//!
//! A [`Resolver`] takes per-file [`FileFacts`] and returns a resolved
//! [`CodeGraph`]. The trait is the **tier seam**: every resolver emits the same
//! schema, tagging each edge with a [`Confidence`]. code2graph ships a fast,
//! broad [`SymbolTableResolver`] (Tier A — name/scope matching across all
//! languages); a precise stack-graphs resolver (Tier B) can slot in behind the
//! same trait per language without changing the output shape.
//!
//! [`Confidence`]: crate::graph::Confidence
//! [`FileFacts`]: crate::graph::FileFacts
//! [`CodeGraph`]: crate::graph::CodeGraph

pub mod conformance;
pub mod external;
pub mod ffi_bridge;
mod incremental;
pub mod layered;
pub mod normalized_name;
mod resolver;
pub mod scope_graph;
mod support;
pub mod symbol_table;

pub use conformance::ConformanceResolver;
pub use external::ExternalResolver;
pub use ffi_bridge::FfiBridgeResolver;
pub use incremental::{
    FILE_SUBGRAPH_SCHEMA_VERSION, FileChange, FileSubgraph, IncrementalGraph, ScopeGraphDelta,
    ScopeSnapshotToken, TrackedIncrementalGraph,
};
pub use layered::LayeredResolver;
pub use normalized_name::NormalizedNameResolver;
pub use resolver::Resolver;
pub use scope_graph::ScopeGraphResolver;
pub(crate) use support::{
    dedup_files_last_wins, enclosing_path_ends_with, enclosing_symbol_index, namespaces_end_with,
    normalize_from_path, retain_first_symbol_by_id,
};
pub use symbol_table::SymbolTableResolver;
