// SPDX-License-Identifier: Apache-2.0

//! Pure assembly of a complete refresh candidate's resolved graph.

use std::collections::{BTreeMap, BTreeSet};

use code2graph::{
    CodeGraph, FileChange, FileFacts, FileSubgraph, IncrementalGraph, LayeredResolver, Resolver,
    ScopeGraphDelta, ScopeSnapshotToken, SymbolTableResolver, validate_file_facts,
};

use crate::cache::{CandidateId, ResolverCacheTier};
use crate::deadline::{Cancellation, Deadline};
use crate::{CliError, Result};

/// Independently persisted scope state for a compatible prior candidate.
///
/// This deliberately contains no cached whole-graph row: per-file subgraphs are
/// the complete hydration source for the incremental resolver.
#[derive(Clone)]
pub struct PriorScopeState {
    pub candidate_id: CandidateId,
    /// The complete path set owned by the prior candidate, independent of
    /// whether every persisted subgraph was available to hydrate.
    pub file_paths: BTreeSet<String>,
    pub subgraphs: BTreeMap<String, FileSubgraph>,
}

/// Inputs for assembling one complete resolved candidate.
pub struct ResolveCandidateInputs<'a> {
    pub tier: ResolverCacheTier,
    /// The complete current file set, sorted strictly by `FileFacts::file`.
    pub files: &'a [FileFacts],
    pub candidate_id: CandidateId,
    /// Compatible state from the immediately preceding candidate, if available.
    pub prior_scope: Option<&'a PriorScopeState>,
    /// Changed current paths. `None` safely treats every current file as changed.
    pub changed_paths: Option<&'a BTreeSet<String>>,
    /// Paths deleted from the prior candidate. `None` is derived from its complete path set.
    pub deleted_paths: Option<&'a BTreeSet<String>>,
    pub deadline: &'a Deadline,
    pub cancellation: &'a dyn Cancellation,
}

/// Resolution output suitable for candidate persistence.
pub struct ResolvedCandidate {
    pub graph: CodeGraph,
    /// One entry for every current file. Scope entries contain their opaque
    /// persistence blob; Name and Dense entries are explicitly `None`.
    pub file_subgraphs: BTreeMap<String, Option<FileSubgraph>>,
    /// Present only when a complete compatible scope state was incrementally
    /// transitioned to this candidate.
    pub scope_delta: Option<ScopeGraphDelta>,
}

/// Resolves a complete candidate without publishing cache or inventory state.
pub fn resolve_candidate(inputs: ResolveCandidateInputs<'_>) -> Result<ResolvedCandidate> {
    check(inputs.deadline, inputs.cancellation)?;
    validate_current_files(inputs.files, inputs.deadline, inputs.cancellation)?;
    check(inputs.deadline, inputs.cancellation)?;

    match inputs.tier {
        ResolverCacheTier::Name => resolve_full(
            &SymbolTableResolver,
            inputs.files,
            inputs.deadline,
            inputs.cancellation,
        ),
        ResolverCacheTier::Dense => resolve_full(
            &LayeredResolver::default_dense(),
            inputs.files,
            inputs.deadline,
            inputs.cancellation,
        ),
        ResolverCacheTier::Scope => resolve_scope(inputs),
    }
}

fn resolve_full(
    resolver: &dyn Resolver,
    files: &[FileFacts],
    deadline: &Deadline,
    cancellation: &dyn Cancellation,
) -> Result<ResolvedCandidate> {
    check(deadline, cancellation)?;
    let graph = resolver.resolve(files).map_err(index_error)?;
    check(deadline, cancellation)?;
    Ok(ResolvedCandidate {
        graph,
        file_subgraphs: empty_subgraphs(files),
        scope_delta: None,
    })
}

fn resolve_scope(inputs: ResolveCandidateInputs<'_>) -> Result<ResolvedCandidate> {
    let Some(prior) = inputs.prior_scope else {
        return fresh_scope(inputs);
    };

    let hydrated_paths: BTreeSet<_> = prior.subgraphs.keys().cloned().collect();
    if !hydrated_paths.is_subset(&prior.file_paths) {
        return Err(CliError::Cache(
            "scope cache contains a subgraph outside its candidate file set".into(),
        ));
    }

    // Validate every present unit before choosing a fresh fallback: missing
    // units are an ordinary cache miss, but malformed present data is corruption.
    check(inputs.deadline, inputs.cancellation)?;
    let mut store = IncrementalGraph::new();
    for (path, subgraph) in &prior.subgraphs {
        check(inputs.deadline, inputs.cancellation)?;
        store
            .try_upsert_subgraph(path.clone(), subgraph.clone())
            .map_err(|error| CliError::Cache(error.to_string()))?;
    }
    check(inputs.deadline, inputs.cancellation)?;
    if hydrated_paths != prior.file_paths {
        return fresh_scope(inputs);
    }

    let changed = changed_paths(inputs.files, inputs.changed_paths);
    let deleted = deleted_paths(prior, inputs.files, inputs.deleted_paths);
    if !transition_is_complete(prior, inputs.files, &changed, &deleted) {
        return fresh_scope(inputs);
    }

    let mut tracked = store.into_tracked(token(prior.candidate_id));
    let mut batch_by_path = BTreeMap::new();
    for facts in inputs
        .files
        .iter()
        .filter(|facts| changed.contains(&facts.file))
    {
        check(inputs.deadline, inputs.cancellation)?;
        batch_by_path.insert(facts.file.as_str(), FileChange::Upsert(facts));
    }
    for path in &deleted {
        check(inputs.deadline, inputs.cancellation)?;
        batch_by_path.insert(path.as_str(), FileChange::Remove(path));
    }
    let batch: Vec<_> = batch_by_path.into_values().collect();
    check(inputs.deadline, inputs.cancellation)?;
    let delta = tracked
        .apply_batch_with_delta(&batch, token(inputs.candidate_id))
        .map_err(index_error)?;
    check(inputs.deadline, inputs.cancellation)?;

    let file_subgraphs = collect_subgraphs(
        inputs.files,
        |path| tracked.subgraph(path),
        inputs.deadline,
        inputs.cancellation,
    )?;
    let graph = tracked.graph();
    check(inputs.deadline, inputs.cancellation)?;
    Ok(ResolvedCandidate {
        graph,
        file_subgraphs,
        scope_delta: Some(delta),
    })
}

fn fresh_scope(inputs: ResolveCandidateInputs<'_>) -> Result<ResolvedCandidate> {
    check(inputs.deadline, inputs.cancellation)?;
    let mut store = IncrementalGraph::new();
    for facts in inputs.files {
        check(inputs.deadline, inputs.cancellation)?;
        store.upsert(facts);
    }
    check(inputs.deadline, inputs.cancellation)?;
    let file_subgraphs = collect_subgraphs(
        inputs.files,
        |path| store.subgraph(path),
        inputs.deadline,
        inputs.cancellation,
    )?;
    let graph = store.graph();
    check(inputs.deadline, inputs.cancellation)?;
    Ok(ResolvedCandidate {
        graph,
        file_subgraphs,
        scope_delta: None,
    })
}

fn validate_current_files(
    files: &[FileFacts],
    deadline: &Deadline,
    cancellation: &dyn Cancellation,
) -> Result<()> {
    for pair in files.windows(2) {
        check(deadline, cancellation)?;
        if pair[0].file >= pair[1].file {
            return Err(CliError::Index(
                "current file facts must be strictly sorted and unique by path".into(),
            ));
        }
    }
    for facts in files {
        check(deadline, cancellation)?;
        validate_file_facts(std::slice::from_ref(facts)).map_err(index_error)?;
        if !code2graph::Language::ALL
            .iter()
            .any(|language| language.as_str() == facts.lang)
        {
            return Err(CliError::Index(format!(
                "file `{}` has an unknown language `{}`",
                facts.file, facts.lang
            )));
        }
        let invalid_symbol_owner = facts.symbols.iter().any(|symbol| {
            symbol.file != facts.file
                || symbol
                    .id
                    .language()
                    .is_some_and(|language| language != facts.lang)
                || symbol
                    .id
                    .local_file()
                    .is_some_and(|file| file != facts.file)
        });
        let invalid_binding_owner = facts.bindings.iter().any(|binding| match &binding.target {
            code2graph::BindingTarget::Def(id) => {
                !facts.symbols.iter().any(|symbol| &symbol.id == id)
            }
            _ => false,
        });
        if invalid_symbol_owner
            || invalid_binding_owner
            || facts
                .references
                .iter()
                .any(|reference| reference.occ.file != facts.file)
            || facts.ffi_exports.iter().any(|export| {
                !facts
                    .symbols
                    .iter()
                    .any(|symbol| symbol.id == export.symbol)
            })
        {
            return Err(CliError::Index(format!(
                "file `{}` contains facts owned by another path",
                facts.file
            )));
        }
    }
    check(deadline, cancellation)?;
    Ok(())
}

fn changed_paths(files: &[FileFacts], explicit: Option<&BTreeSet<String>>) -> BTreeSet<String> {
    explicit
        .cloned()
        .unwrap_or_else(|| files.iter().map(|facts| facts.file.clone()).collect())
}

fn deleted_paths(
    prior: &PriorScopeState,
    files: &[FileFacts],
    explicit: Option<&BTreeSet<String>>,
) -> BTreeSet<String> {
    explicit.cloned().unwrap_or_else(|| {
        let current: BTreeSet<_> = files.iter().map(|facts| facts.file.as_str()).collect();
        prior
            .file_paths
            .iter()
            .filter(|path| !current.contains(path.as_str()))
            .cloned()
            .collect()
    })
}

fn transition_is_complete(
    prior: &PriorScopeState,
    files: &[FileFacts],
    changed: &BTreeSet<String>,
    deleted: &BTreeSet<String>,
) -> bool {
    let current: BTreeSet<_> = files.iter().map(|facts| facts.file.as_str()).collect();
    if !changed.iter().all(|path| current.contains(path.as_str()))
        || !deleted.iter().all(|path| prior.file_paths.contains(path))
        || deleted.iter().any(|path| current.contains(path.as_str()))
        || !changed.is_disjoint(deleted)
    {
        return false;
    }

    let mut transitioned = prior.file_paths.clone();
    transitioned.retain(|path| !deleted.contains(path));
    transitioned.extend(changed.iter().cloned());
    transitioned
        == current
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>()
}

fn collect_subgraphs<'a>(
    files: &[FileFacts],
    mut get: impl FnMut(&str) -> Option<&'a FileSubgraph>,
    deadline: &Deadline,
    cancellation: &dyn Cancellation,
) -> Result<BTreeMap<String, Option<FileSubgraph>>> {
    let mut subgraphs = BTreeMap::new();
    for facts in files {
        check(deadline, cancellation)?;
        let Some(subgraph) = get(&facts.file) else {
            return Err(CliError::Index(format!(
                "scope resolver did not retain subgraph for `{}`",
                facts.file
            )));
        };
        subgraphs.insert(facts.file.clone(), Some(subgraph.clone()));
    }
    Ok(subgraphs)
}

fn empty_subgraphs(files: &[FileFacts]) -> BTreeMap<String, Option<FileSubgraph>> {
    files
        .iter()
        .map(|facts| (facts.file.clone(), None))
        .collect()
}

fn token(candidate_id: CandidateId) -> ScopeSnapshotToken {
    ScopeSnapshotToken::new(*candidate_id.as_bytes())
}

fn check(deadline: &Deadline, cancellation: &dyn Cancellation) -> Result<()> {
    deadline.check(cancellation)
}

fn index_error(error: code2graph::CodegraphError) -> CliError {
    CliError::Index(error.to_string())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::NeverCancelled;

    fn facts(path: &str) -> FileFacts {
        FileFacts {
            file: path.into(),
            lang: "rust".into(),
            symbols: Vec::new(),
            references: Vec::new(),
            scopes: Vec::new(),
            bindings: Vec::new(),
            ffi_exports: Vec::new(),
        }
    }

    fn candidate(byte: u8) -> CandidateId {
        CandidateId::from_bytes([byte; 32])
    }

    fn resolve<'a>(
        tier: ResolverCacheTier,
        files: &'a [FileFacts],
        prior_scope: Option<&'a PriorScopeState>,
        changed_paths: Option<&'a BTreeSet<String>>,
        deadline: &'a Deadline,
        cancellation: &'a dyn Cancellation,
    ) -> Result<ResolvedCandidate> {
        resolve_candidate(ResolveCandidateInputs {
            tier,
            files,
            candidate_id: candidate(2),
            prior_scope,
            changed_paths,
            deleted_paths: None,
            deadline,
            cancellation,
        })
    }

    #[test]
    fn every_fresh_tier_matches_its_direct_complete_resolver() {
        let files = vec![facts("a.rs")];
        let deadline = Deadline::new(None);
        for (tier, direct) in [
            (ResolverCacheTier::Name, SymbolTableResolver.resolve(&files)),
            (
                ResolverCacheTier::Scope,
                code2graph::ScopeGraphResolver.resolve(&files),
            ),
            (
                ResolverCacheTier::Dense,
                LayeredResolver::default_dense().resolve(&files),
            ),
        ] {
            let resolved = resolve(tier, &files, None, None, &deadline, &NeverCancelled)
                .expect("fresh resolution");
            assert_eq!(
                format!("{:?}", resolved.graph),
                format!("{:?}", direct.unwrap())
            );
            assert_eq!(resolved.file_subgraphs.len(), 1);
            if tier == ResolverCacheTier::Scope {
                assert!(resolved.file_subgraphs.values().all(Option::is_some));
            } else {
                assert!(resolved.file_subgraphs.values().all(Option::is_none));
            }
            assert!(resolved.scope_delta.is_none());
        }
    }

    #[test]
    fn complete_scope_restore_returns_lineage_and_every_subgraph() {
        let files = vec![facts("a.rs")];
        let deadline = Deadline::new(None);
        let fresh = resolve(
            ResolverCacheTier::Scope,
            &files,
            None,
            None,
            &deadline,
            &NeverCancelled,
        )
        .expect("fresh scope");
        let prior = PriorScopeState {
            candidate_id: candidate(1),
            file_paths: BTreeSet::from(["a.rs".into()]),
            subgraphs: fresh
                .file_subgraphs
                .into_iter()
                .map(|(path, subgraph)| (path, subgraph.expect("scope subgraph")))
                .collect(),
        };
        let unchanged = BTreeSet::new();
        let restored = resolve(
            ResolverCacheTier::Scope,
            &files,
            Some(&prior),
            Some(&unchanged),
            &deadline,
            &NeverCancelled,
        )
        .expect("restored scope");
        assert!(restored.scope_delta.is_some());
        assert!(restored.file_subgraphs.values().all(Option::is_some));
    }

    #[test]
    fn changed_definition_relinks_an_unchanged_caller_like_a_fresh_scope_graph() {
        let previous = vec![
            code2graph::extract_path("caller.rs", "fn caller() { helper(); }")
                .expect("caller facts"),
            code2graph::extract_path("helper.rs", "fn helper() {} ").expect("helper facts"),
        ];
        let current = vec![
            previous[0].clone(),
            code2graph::extract_path("helper.rs", "fn replacement() {} ")
                .expect("replacement facts"),
        ];
        let deadline = Deadline::new(None);
        let initial = resolve(
            ResolverCacheTier::Scope,
            &previous,
            None,
            None,
            &deadline,
            &NeverCancelled,
        )
        .expect("initial scope");
        let prior = PriorScopeState {
            candidate_id: candidate(1),
            file_paths: previous.iter().map(|facts| facts.file.clone()).collect(),
            subgraphs: initial
                .file_subgraphs
                .into_iter()
                .map(|(path, subgraph)| (path, subgraph.expect("scope subgraph")))
                .collect(),
        };
        let changed = BTreeSet::from(["helper.rs".into()]);
        let restored = resolve(
            ResolverCacheTier::Scope,
            &current,
            Some(&prior),
            Some(&changed),
            &deadline,
            &NeverCancelled,
        )
        .expect("incremental scope");
        let direct = code2graph::ScopeGraphResolver
            .resolve(&current)
            .expect("direct scope");
        assert_eq!(format!("{:?}", restored.graph), format!("{:?}", direct));
        assert!(restored.scope_delta.is_some());
    }

    #[test]
    fn corrupt_scope_state_and_deadline_and_cancellation_are_typed() {
        struct Cancelled;
        impl Cancellation for Cancelled {
            fn is_cancelled(&self) -> bool {
                true
            }
        }

        let files = vec![facts("a.rs")];
        let deadline = Deadline::new(None);
        let fresh = resolve(
            ResolverCacheTier::Scope,
            &files,
            None,
            None,
            &deadline,
            &NeverCancelled,
        )
        .expect("fresh scope");
        let prior = PriorScopeState {
            candidate_id: candidate(1),
            file_paths: BTreeSet::from(["wrong.rs".into()]),
            subgraphs: BTreeMap::from([(
                "wrong.rs".into(),
                fresh.file_subgraphs["a.rs"]
                    .clone()
                    .expect("scope subgraph"),
            )]),
        };
        let changed = BTreeSet::from(["a.rs".into()]);
        let deleted = BTreeSet::from(["wrong.rs".into()]);
        let corrupted = resolve_candidate(ResolveCandidateInputs {
            tier: ResolverCacheTier::Scope,
            files: &files,
            candidate_id: candidate(2),
            prior_scope: Some(&prior),
            changed_paths: Some(&changed),
            deleted_paths: Some(&deleted),
            deadline: &deadline,
            cancellation: &NeverCancelled,
        });
        assert!(matches!(corrupted, Err(CliError::Cache(_))));

        let foreign_row = PriorScopeState {
            candidate_id: candidate(1),
            file_paths: BTreeSet::new(),
            subgraphs: BTreeMap::from([(
                "a.rs".into(),
                fresh.file_subgraphs["a.rs"]
                    .clone()
                    .expect("scope subgraph"),
            )]),
        };
        assert!(matches!(
            resolve(
                ResolverCacheTier::Scope,
                &files,
                Some(&foreign_row),
                Some(&changed),
                &deadline,
                &NeverCancelled,
            ),
            Err(CliError::Cache(_))
        ));

        let timeout = Deadline::new(Some(Duration::ZERO));
        assert!(matches!(
            resolve(
                ResolverCacheTier::Name,
                &files,
                None,
                None,
                &timeout,
                &NeverCancelled
            ),
            Err(CliError::Timeout)
        ));
        assert!(matches!(
            resolve(
                ResolverCacheTier::Name,
                &files,
                None,
                None,
                &deadline,
                &Cancelled
            ),
            Err(CliError::Cancelled)
        ));
    }

    #[test]
    fn missing_scope_unit_and_incomplete_change_hints_fall_back_fresh() {
        let deadline = Deadline::new(None);
        let files = vec![facts("a.rs")];
        let missing = PriorScopeState {
            candidate_id: candidate(1),
            file_paths: BTreeSet::from(["a.rs".into()]),
            subgraphs: BTreeMap::new(),
        };
        let unchanged = BTreeSet::new();
        let resolved = resolve(
            ResolverCacheTier::Scope,
            &files,
            Some(&missing),
            Some(&unchanged),
            &deadline,
            &NeverCancelled,
        )
        .expect("missing unit is a cache miss");
        assert!(resolved.scope_delta.is_none());
        assert!(resolved.file_subgraphs.values().all(Option::is_some));

        let initial = resolve(
            ResolverCacheTier::Scope,
            &files,
            None,
            None,
            &deadline,
            &NeverCancelled,
        )
        .expect("initial scope");
        let prior = PriorScopeState {
            candidate_id: candidate(1),
            file_paths: BTreeSet::from(["a.rs".into()]),
            subgraphs: initial
                .file_subgraphs
                .into_iter()
                .map(|(path, subgraph)| (path, subgraph.expect("scope subgraph")))
                .collect(),
        };
        let expanded = vec![facts("a.rs"), facts("b.rs")];
        let incomplete = resolve(
            ResolverCacheTier::Scope,
            &expanded,
            Some(&prior),
            Some(&unchanged),
            &deadline,
            &NeverCancelled,
        )
        .expect("incomplete hints safely rebuild");
        assert!(incomplete.scope_delta.is_none());
        assert_eq!(incomplete.file_subgraphs.len(), 2);
    }

    #[test]
    fn deleted_paths_are_derived_and_unchanged_callers_match_fresh() {
        let previous = vec![
            code2graph::extract_path("old.go", "package p\nfunc helper() {}")
                .expect("provider facts"),
            code2graph::extract_path("stay.go", "package p\nfunc caller() { helper() }")
                .expect("caller facts"),
        ];
        let current = vec![previous[1].clone()];
        let deadline = Deadline::new(None);
        let initial = resolve(
            ResolverCacheTier::Scope,
            &previous,
            None,
            None,
            &deadline,
            &NeverCancelled,
        )
        .expect("initial scope");
        let prior = PriorScopeState {
            candidate_id: candidate(1),
            file_paths: previous.iter().map(|facts| facts.file.clone()).collect(),
            subgraphs: initial
                .file_subgraphs
                .into_iter()
                .map(|(path, subgraph)| (path, subgraph.expect("scope subgraph")))
                .collect(),
        };
        let unchanged = BTreeSet::new();
        let incremental = resolve(
            ResolverCacheTier::Scope,
            &current,
            Some(&prior),
            Some(&unchanged),
            &deadline,
            &NeverCancelled,
        )
        .expect("derived deletion");
        let direct = code2graph::ScopeGraphResolver
            .resolve(&current)
            .expect("direct scope");
        assert_eq!(format!("{:?}", incremental.graph), format!("{:?}", direct));
        assert_eq!(
            incremental
                .file_subgraphs
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["stay.go"]
        );
        let delta = incremental.scope_delta.expect("incremental delta");
        assert!(!delta.removed_symbols.is_empty());
        assert!(!delta.removed_edges.is_empty());
    }

    #[test]
    fn incremental_ambiguity_matches_fresh_and_delta_uses_candidate_tokens() {
        let previous = vec![
            code2graph::extract_path("caller.go", "package p\nfunc caller() { helper() }")
                .expect("caller facts"),
            code2graph::extract_path("one.go", "package p\nfunc helper() {}")
                .expect("first helper"),
        ];
        let current = vec![
            previous[0].clone(),
            previous[1].clone(),
            code2graph::extract_path("two.go", "package p\nfunc helper() {}")
                .expect("second helper"),
        ];
        let deadline = Deadline::new(None);
        let initial = resolve_candidate(ResolveCandidateInputs {
            tier: ResolverCacheTier::Scope,
            files: &previous,
            candidate_id: candidate(7),
            prior_scope: None,
            changed_paths: None,
            deleted_paths: None,
            deadline: &deadline,
            cancellation: &NeverCancelled,
        })
        .expect("initial scope");
        let prior = PriorScopeState {
            candidate_id: candidate(7),
            file_paths: previous.iter().map(|facts| facts.file.clone()).collect(),
            subgraphs: initial
                .file_subgraphs
                .into_iter()
                .map(|(path, subgraph)| (path, subgraph.expect("scope subgraph")))
                .collect(),
        };
        let changed = BTreeSet::from(["two.go".into()]);
        let incremental = resolve_candidate(ResolveCandidateInputs {
            tier: ResolverCacheTier::Scope,
            files: &current,
            candidate_id: candidate(9),
            prior_scope: Some(&prior),
            changed_paths: Some(&changed),
            deleted_paths: Some(&BTreeSet::new()),
            deadline: &deadline,
            cancellation: &NeverCancelled,
        })
        .expect("incremental ambiguity");
        let direct = code2graph::ScopeGraphResolver
            .resolve(&current)
            .expect("direct scope");
        assert_eq!(format!("{:?}", incremental.graph), format!("{:?}", direct));
        let delta = incremental.scope_delta.expect("incremental delta");
        assert_eq!(delta.base_snapshot.as_bytes(), candidate(7).as_bytes());
        assert_eq!(delta.snapshot.as_bytes(), candidate(9).as_bytes());
        assert!(!delta.removed_edges.is_empty());
    }

    #[test]
    fn rejects_unsorted_duplicate_unknown_language_and_cross_owned_facts() {
        let deadline = Deadline::new(None);
        for files in [
            vec![facts("b.rs"), facts("a.rs")],
            vec![facts("a.rs"), facts("a.rs")],
        ] {
            assert!(matches!(
                resolve(
                    ResolverCacheTier::Name,
                    &files,
                    None,
                    None,
                    &deadline,
                    &NeverCancelled,
                ),
                Err(CliError::Index(_))
            ));
        }

        let mut unknown = facts("a.rs");
        unknown.lang = "unknown".into();
        assert!(matches!(
            resolve(
                ResolverCacheTier::Name,
                &[unknown],
                None,
                None,
                &deadline,
                &NeverCancelled,
            ),
            Err(CliError::Index(_))
        ));

        let mut cross_owned =
            code2graph::extract_path("owner.rs", "fn owned() {}").expect("owned facts");
        cross_owned.file = "other.rs".into();
        assert!(matches!(
            resolve(
                ResolverCacheTier::Name,
                &[cross_owned],
                None,
                None,
                &deadline,
                &NeverCancelled,
            ),
            Err(CliError::Index(_))
        ));
    }
}
