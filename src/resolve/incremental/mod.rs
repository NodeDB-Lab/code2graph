// SPDX-License-Identifier: Apache-2.0

//! Incremental resolution building blocks shared by the batch resolver.
//!
//! Tier-B resolution splits cleanly into a per-file (intra-file) phase and a
//! cross-file (stitch) phase. This module factors those two phases out of the
//! batch [`ScopeGraphResolver`] so they form **one** reusable resolution code
//! path: [`build_subgraph`] does all isolated per-file work and defers any
//! cross-file reference as a [`PendingRef`]; [`stitch`] later resolves those
//! deferred refs against a [`GlobalIndex`]. The batch resolver is re-expressed
//! on top of both, and the stateful [`IncrementalGraph`] store wraps the same
//! pieces — so the two paths never drift.
//!
//! [`ScopeGraphResolver`]: super::ScopeGraphResolver

mod stitch;
mod store;
mod subgraph;

pub(crate) use stitch::{GlobalIndex, stitch};
pub use store::IncrementalGraph;
pub(crate) use subgraph::{FileSubgraph, build_subgraph};
