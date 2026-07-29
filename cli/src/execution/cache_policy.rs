// SPDX-License-Identifier: Apache-2.0

//! Cache selection rules shared by refresh and graph-loading lifecycles.

use crate::cache::{
    CacheCompleteness, CacheError, CacheLoadFailure, CacheStore, LoadedSnapshot, ResolverCacheTier,
};
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
    // A load attempt never exposes a diagnostic from an earlier attempt.
    store.set_recovery_diagnostic(None);
    match store.load_latest_active_detailed(tier, completeness, deadline) {
        Ok(snapshot) => Ok(snapshot),
        Err(CacheLoadFailure::InvalidFacts { detail }) if store.is_writable() => {
            store.set_recovery_diagnostic(Some(detail));
            store.invalidate_derived(deadline)?;
            Ok(None)
        }
        Err(CacheLoadFailure::Cache(error))
            if store.is_writable() && is_recoverable_cache_error(&error) =>
        {
            store.invalidate_derived(deadline)?;
            Ok(None)
        }
        Err(error) => Err(CacheError::from(error).into()),
    }
}

fn is_recoverable_cache_error(error: &CacheError) -> bool {
    matches!(
        error,
        CacheError::Malformed
            | CacheError::Incompatible
            | CacheError::Limits
            | CacheError::InvalidFacts
            | CacheError::InvalidSubgraph
            | CacheError::Corrupt
            | CacheError::InvalidCandidate
    )
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

#[cfg(test)]
mod tests {
    use std::fs;

    use code2graph::FileFacts;
    use rusqlite::Connection;
    use tempfile::tempdir;

    use super::*;
    use crate::cache::{CacheLocation, CandidateSnapshot, single_file_candidate};

    fn candidate() -> CandidateSnapshot {
        single_file_candidate("src/a.rs", ResolverCacheTier::Name)
    }

    #[test]
    fn refresh_prior_retains_invalid_facts_detail_after_invalidation() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("project");
        fs::create_dir(&root).expect("project root");
        let location = CacheLocation::for_project(Some(temp.path()), &root).expect("location");
        let deadline = Deadline::new(None);
        let store = CacheStore::open_writable(&location, &root, &deadline).expect("store");
        let candidate = candidate();
        store
            .publish_candidate(&candidate, &deadline)
            .expect("publish");

        let malformed_facts = FileFacts {
            file: "wrong.rs".into(),
            lang: "rust".into(),
            symbols: Vec::new(),
            references: Vec::new(),
            scopes: Vec::new(),
            bindings: Vec::new(),
            ffi_exports: Vec::new(),
        };
        let blob = crate::cache::encode_file_facts(&malformed_facts).expect("encode");
        Connection::open(&location.database_path)
            .expect("sqlite")
            .execute(
                "UPDATE candidate_files SET file_facts = ?1 WHERE candidate_id = ?2 AND path = ?3",
                rusqlite::params![
                    blob,
                    candidate.candidate_id.as_bytes().as_slice(),
                    "src/a.rs"
                ],
            )
            .expect("corrupt facts");

        let expected_detail = match store.load_latest_active_detailed(
            ResolverCacheTier::Name,
            CacheCompleteness::Complete,
            &deadline,
        ) {
            Err(CacheLoadFailure::InvalidFacts { detail }) => detail,
            _ => panic!("expected invalid facts"),
        };
        assert!(matches!(
            refresh_prior(&store, ResolverCacheTier::Name, false, &deadline),
            Ok(None)
        ));
        assert_eq!(store.recovery_diagnostic(), Some(expected_detail));
        assert!(
            store
                .active_metadata(
                    ResolverCacheTier::Name,
                    CacheCompleteness::Complete,
                    &deadline,
                )
                .expect("metadata")
                .is_none()
        );
    }

    #[test]
    fn normal_load_clears_stale_recovery_diagnostic() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("project");
        fs::create_dir(&root).expect("project root");
        let location = CacheLocation::for_project(Some(temp.path()), &root).expect("location");
        let deadline = Deadline::new(None);
        let store = CacheStore::open_writable(&location, &root, &deadline).expect("store");
        store
            .publish_candidate(&candidate(), &deadline)
            .expect("publish");
        store.set_recovery_diagnostic(Some("stale validation detail".into()));

        assert!(matches!(
            refresh_prior(&store, ResolverCacheTier::Name, false, &deadline),
            Ok(Some(_))
        ));
        assert_eq!(store.recovery_diagnostic(), None);
    }
}
