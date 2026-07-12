// SPDX-License-Identifier: Apache-2.0

//! Cache selection rules shared by refresh and graph-loading lifecycles.

use crate::cache::{CacheCompleteness, CacheError, CacheStore, LoadedSnapshot, ResolverCacheTier};
use crate::{CliError, Deadline, Result};

/// Selects a refresh prior without claiming compatibility before preparation has
/// computed the current package and language fingerprints.
pub(super) fn refresh_prior(
    store: &CacheStore,
    tier: ResolverCacheTier,
    allow_partial: bool,
    deadline: &Deadline,
) -> Result<Option<LoadedSnapshot>> {
    let complete = load_or_invalidate(store, tier, CacheCompleteness::Complete, deadline)?;
    if complete.is_some() || !allow_partial {
        return Ok(complete);
    }
    load_or_invalidate(store, tier, CacheCompleteness::Partial, deadline)
}

fn load_or_invalidate(
    store: &CacheStore,
    tier: ResolverCacheTier,
    completeness: CacheCompleteness,
    deadline: &Deadline,
) -> Result<Option<LoadedSnapshot>> {
    match store.load_latest_active(tier, completeness, deadline) {
        Ok(snapshot) => Ok(snapshot),
        Err(error)
            if store.is_writable()
                && matches!(
                    error,
                    CacheError::Malformed
                        | CacheError::Incompatible
                        | CacheError::Limits
                        | CacheError::InvalidFacts
                        | CacheError::InvalidSubgraph
                        | CacheError::Corrupt
                        | CacheError::InvalidCandidate
                ) =>
        {
            store.invalidate_derived(deadline)?;
            Ok(None)
        }
        Err(error) => Err(error.into()),
    }
}

/// Selects a frozen or stale snapshot without filesystem-derived compatibility.
pub(super) fn latest_active(
    store: &CacheStore,
    tier: ResolverCacheTier,
    allow_partial: bool,
    deadline: &Deadline,
) -> Result<Option<LoadedSnapshot>> {
    refresh_prior(store, tier, allow_partial, deadline)
}

/// Converts a missing frozen selection into a distinct, actionable error.
pub(super) fn frozen_missing() -> CliError {
    CliError::FrozenSnapshotMissing
}
