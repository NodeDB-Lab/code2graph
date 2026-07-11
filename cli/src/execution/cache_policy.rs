// SPDX-License-Identifier: Apache-2.0

//! Cache selection rules shared by refresh and graph-loading lifecycles.

use crate::cache::{CacheCompleteness, CacheStore, LoadedSnapshot, ResolverCacheTier};
use crate::{CliError, Deadline, Result};

/// Selects a refresh prior without claiming compatibility before preparation has
/// computed the current package and language fingerprints.
pub(super) fn refresh_prior(
    store: &CacheStore,
    tier: ResolverCacheTier,
    allow_partial: bool,
    deadline: &Deadline,
) -> Result<Option<LoadedSnapshot>> {
    let complete = store.load_latest_active(tier, CacheCompleteness::Complete, deadline)?;
    if complete.is_some() || !allow_partial {
        return Ok(complete);
    }
    store
        .load_latest_active(tier, CacheCompleteness::Partial, deadline)
        .map_err(Into::into)
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
