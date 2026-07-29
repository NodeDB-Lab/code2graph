// SPDX-License-Identifier: Apache-2.0

//! Publication-ready, in-memory refresh candidate preparation.

mod api;
mod budgets;
mod pipeline;
mod pool;
mod recovery;
#[cfg(test)]
mod tests;

pub use api::{
    ExtractSession, ExtractionOutcome, FactsExtractor, PrepareCandidateInputs,
    PreparedRefreshCandidate, ProcessFactsExtractor, ProcessSession,
};
pub(crate) use budgets::apply_metadata_budgets;
pub use pipeline::{prepare_refresh_candidate, prepare_refresh_candidate_with};
pub use pool::WorkerSlot;
pub(crate) use pool::monitored_extract;
