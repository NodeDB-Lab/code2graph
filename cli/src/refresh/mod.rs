// SPDX-License-Identifier: Apache-2.0

//! Deterministic metadata-first source refresh planning.

mod plan;
mod resolve;
mod types;

pub use plan::{PriorFileRecord, RefreshDecision, RefreshEntry, RefreshInputs, RefreshPlan};
pub use resolve::{PriorScopeState, ResolveCandidateInputs, ResolvedCandidate, resolve_candidate};
pub use types::{ExtractionError, MAX_REFRESH_ATTEMPTS};
