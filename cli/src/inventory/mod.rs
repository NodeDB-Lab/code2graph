// SPDX-License-Identifier: Apache-2.0

//! Deterministic, bounded source inventory construction.

mod types;
mod walk;

pub use types::{
    FileClassification, InventoryCompleteness, InventoryFile, InventorySummary, MtimeHint,
    OmissionReason, OmittedFile, SourceInventory, StableIoErrorKind,
};
pub use walk::build_inventory;
