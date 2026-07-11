// SPDX-License-Identifier: Apache-2.0

//! Structural graph-index construction and lookup.

mod build;
mod lookup;

pub use crate::impact::{ImpactOptions, ImpactResult, ImpactStep};
pub use crate::relation::EdgeFilter;
pub use build::GraphIndex;
