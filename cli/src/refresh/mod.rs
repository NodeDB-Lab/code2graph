// SPDX-License-Identifier: Apache-2.0

//! Deterministic metadata-first source refresh planning.

mod plan;
mod prepare;
mod resolve;
mod types;

pub use plan::{PriorFileRecord, RefreshDecision, RefreshEntry, RefreshInputs, RefreshPlan};
pub use prepare::{
    FactsExtractor, PrepareCandidateInputs, PreparedRefreshCandidate, ProcessFactsExtractor,
    prepare_refresh_candidate, prepare_refresh_candidate_with,
};
pub use resolve::{PriorScopeState, ResolveCandidateInputs, ResolvedCandidate, resolve_candidate};
pub use types::{ExtractionError, MAX_REFRESH_ATTEMPTS};
