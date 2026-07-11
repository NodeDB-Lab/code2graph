// SPDX-License-Identifier: Apache-2.0

//! Deterministic, bounded source inventory construction.

mod types;
mod walk;

pub use types::{
    FileClassification, InventoryCompleteness, InventoryFile, InventorySummary,
    MaterializedCandidate, MtimeHint, OmissionImpact, OmissionReason, OmittedFile, SourceCandidate,
    SourceDiscovery, SourceInventory, StableIdentity, StableIoErrorKind,
};
pub use walk::{
    build_inventory, discover_sources, discover_sources_checked, materialize_candidate,
    materialize_candidate_checked,
};
