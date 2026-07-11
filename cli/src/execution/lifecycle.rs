// SPDX-License-Identifier: Apache-2.0

use code2graph::CodeGraph;

use crate::cache::{
    CacheCompleteness, CacheError, CacheLocation, CacheStore, CandidateSnapshot, LoadedSnapshot,
    ResolverCacheTier,
};
use crate::commands::{
    DefinitionCommandRequest, ImpactCommandRequest, QueryCommandContext, RelationCommandRequest,
    RelationDirection, SymbolsCommandRequest, execute_definition, execute_impact,
    execute_relations, execute_symbols,
};
use crate::refresh::{
    PrepareCandidateInputs, PreparedRefreshCandidate, prepare_and_publish,
    prepare_refresh_candidate,
};
use crate::request::{CliRequest, CommandRequest};
use crate::result::{
    CacheDisposition, Freshness, IndexOutput, OutputEnvelope, PlanDecisionCountsOutput,
    ProjectOutput, StatusOutput, success_status,
};
use crate::{CliError, Deadline, Result, select_project};

use super::cache_policy::{frozen_missing, latest_active, refresh_prior};
use super::context::ExecutionContext;

/// Result of an executable command. Graph loading is public so future query
/// commands can share the same selection policy without duplicating lifecycle.
pub enum CommandOutput {
    Index(OutputEnvelope<IndexOutput>),
    Status(OutputEnvelope<StatusOutput>),
    Symbols(OutputEnvelope<Vec<crate::SymbolOutput>>),
    Def(OutputEnvelope<Vec<crate::SymbolOutput>>),
    Callers(OutputEnvelope<Vec<crate::RelationOutput>>),
    Callees(OutputEnvelope<Vec<crate::RelationOutput>>),
    Usages(OutputEnvelope<Vec<crate::RelationOutput>>),
    Impact(OutputEnvelope<Vec<crate::ImpactOutput>>),
    LoadedGraph(LoadedGraph),
}

/// A graph selected from cache or prepared in memory under the command policy.
pub struct LoadedGraph {
    pub selection: crate::ProjectSelection,
    pub snapshot: LoadedSnapshot,
    pub graph: CodeGraph,
    pub project: ProjectOutput,
}

#[derive(Clone, Copy, Default)]
struct ExecutionRefreshOptions {
    force: bool,
    trust_mtime: bool,
}

struct ExecutionRefreshInputs<'a> {
    request: &'a CliRequest,
    selection: &'a crate::ProjectSelection,
    options: ExecutionRefreshOptions,
    prior: Option<&'a LoadedSnapshot>,
    prepared_at_ns: u64,
    deadline: &'a Deadline,
    context: &'a ExecutionContext<'a>,
}

impl<'a> ExecutionRefreshInputs<'a> {
    fn candidate_inputs(&self) -> PrepareCandidateInputs<'a> {
        PrepareCandidateInputs {
            selection: self.selection,
            limits: &self.request.global.limits,
            include_hidden: self.request.global.include_hidden,
            force: self.options.force,
            trust_mtime: self.options.trust_mtime,
            tier: self.request.global.tier,
            prior: self.prior,
            prepared_at_ns: self.prepared_at_ns,
            deadline: self.deadline,
            cancellation: self.context.cancellation,
        }
    }
}

/// Executes the implemented top-level commands. Selection starts only after a
/// command-wide deadline and cancellation check have been established.
pub fn execute(request: CliRequest, context: &ExecutionContext<'_>) -> Result<CommandOutput> {
    let result_limit = request.global.limits.result_limit;
    let min_confidence = request.global.effective_min_confidence();
    match request.command.clone() {
        CommandRequest::Index { .. } => execute_index(request, context),
        CommandRequest::Status => execute_status(request, context),
        CommandRequest::Symbols {
            text,
            file,
            kind,
            case_sensitive,
        } => execute_symbols_query(
            request,
            context,
            SymbolsCommandRequest {
                text: &text,
                file: file.as_deref(),
                kind,
                case_sensitive,
                result_limit,
            },
        ),
        CommandRequest::Def {
            selector,
            file,
            kind,
            require_unique,
        } => execute_definition_query(
            request,
            context,
            DefinitionCommandRequest {
                selector: &selector,
                file: file.as_deref(),
                kind,
                require_unique,
                result_limit,
            },
        ),
        CommandRequest::Callers {
            selector,
            file,
            kind,
            require_unique,
            role,
        } => execute_relations_query(
            request,
            context,
            RelationCommandRequest {
                selector: &selector,
                file: file.as_deref(),
                kind,
                require_unique,
                role: Some(role.unwrap_or(code2graph::RefRole::Call)),
                direction: RelationDirection::Incoming,
                result_limit,
                min_confidence,
            },
            CommandOutput::Callers,
        ),
        CommandRequest::Callees {
            selector,
            file,
            kind,
            require_unique,
            role,
        } => execute_relations_query(
            request,
            context,
            RelationCommandRequest {
                selector: &selector,
                file: file.as_deref(),
                kind,
                require_unique,
                role: Some(role.unwrap_or(code2graph::RefRole::Call)),
                direction: RelationDirection::Outgoing,
                result_limit,
                min_confidence,
            },
            CommandOutput::Callees,
        ),
        CommandRequest::Usages {
            selector,
            file,
            kind,
            require_unique,
            role,
        } => execute_relations_query(
            request,
            context,
            RelationCommandRequest {
                selector: &selector,
                file: file.as_deref(),
                kind,
                require_unique,
                role,
                direction: RelationDirection::Incoming,
                result_limit,
                min_confidence,
            },
            CommandOutput::Usages,
        ),
        CommandRequest::Impact {
            selector,
            file,
            kind,
            require_unique,
            role,
            depth,
        } => execute_impact_query(
            request,
            context,
            ImpactCommandRequest {
                selector: &selector,
                file: file.as_deref(),
                kind,
                require_unique,
                role: Some(role.unwrap_or(code2graph::RefRole::Call)),
                depth,
                max_nodes: result_limit,
                min_confidence,
            },
        ),
        command => Err(CliError::Unavailable {
            command: command.name().to_owned(),
        }),
    }
}

fn execute_symbols_query(
    request: CliRequest,
    execution: &ExecutionContext<'_>,
    command: SymbolsCommandRequest<'_>,
) -> Result<CommandOutput> {
    let loaded = load_query_graph(&request, execution)?;
    let deadline = Deadline::new(request.global.limits.timeout);
    deadline.check(execution.cancellation)?;
    let index = crate::build_graph_index(&loaded)?;
    let context = QueryCommandContext::new(
        &loaded,
        &index,
        &deadline,
        execution.cancellation,
        request.global.limits.max_file_bytes,
    )?;
    Ok(CommandOutput::Symbols(execute_symbols(&context, command)?))
}

fn execute_relations_query(
    request: CliRequest,
    execution: &ExecutionContext<'_>,
    command: RelationCommandRequest<'_>,
    output: fn(OutputEnvelope<Vec<crate::RelationOutput>>) -> CommandOutput,
) -> Result<CommandOutput> {
    let loaded = load_query_graph(&request, execution)?;
    let deadline = Deadline::new(request.global.limits.timeout);
    deadline.check(execution.cancellation)?;
    let index = crate::build_graph_index(&loaded)?;
    let context = QueryCommandContext::new(
        &loaded,
        &index,
        &deadline,
        execution.cancellation,
        request.global.limits.max_file_bytes,
    )?;
    Ok(output(execute_relations(&context, command)?))
}

fn execute_impact_query(
    request: CliRequest,
    execution: &ExecutionContext<'_>,
    command: ImpactCommandRequest<'_>,
) -> Result<CommandOutput> {
    let loaded = load_query_graph(&request, execution)?;
    let deadline = Deadline::new(request.global.limits.timeout);
    deadline.check(execution.cancellation)?;
    let index = crate::build_graph_index(&loaded)?;
    let context = QueryCommandContext::new(
        &loaded,
        &index,
        &deadline,
        execution.cancellation,
        request.global.limits.max_file_bytes,
    )?;
    Ok(CommandOutput::Impact(execute_impact(&context, command)?))
}

fn execute_definition_query(
    request: CliRequest,
    execution: &ExecutionContext<'_>,
    command: DefinitionCommandRequest<'_>,
) -> Result<CommandOutput> {
    let loaded = load_query_graph(&request, execution)?;
    let deadline = Deadline::new(request.global.limits.timeout);
    deadline.check(execution.cancellation)?;
    let index = crate::build_graph_index(&loaded)?;
    let context = QueryCommandContext::new(
        &loaded,
        &index,
        &deadline,
        execution.cancellation,
        request.global.limits.max_file_bytes,
    )?;
    Ok(CommandOutput::Def(execute_definition(&context, command)?))
}

fn deadline_before_selection(
    request: &CliRequest,
    context: &ExecutionContext<'_>,
) -> Result<Deadline> {
    let deadline = Deadline::new(request.global.limits.timeout);
    deadline.check(context.cancellation)?;
    Ok(deadline)
}

fn execute_index(request: CliRequest, context: &ExecutionContext<'_>) -> Result<CommandOutput> {
    let CommandRequest::Index {
        force, trust_mtime, ..
    } = &request.command
    else {
        return Err(CliError::Fatal(
            "index lifecycle received another command".into(),
        ));
    };
    let deadline = deadline_before_selection(&request, context)?;
    let selection = select_project(&request, &context.cwd)?;
    let prepared_at_ns = context.clock.unix_time_ns()?;

    if request.global.no_cache {
        let prepared = prepare(ExecutionRefreshInputs {
            request: &request,
            selection: &selection,
            options: ExecutionRefreshOptions {
                force: *force,
                trust_mtime: *trust_mtime,
            },
            prior: None,
            prepared_at_ns,
            deadline: &deadline,
            context,
        })?;
        enforce_partial(&prepared, request.global.allow_partial)?;
        let snapshot = loaded_from_candidate(prepared.snapshot.clone());
        return Ok(CommandOutput::Index(index_envelope(
            &selection,
            &snapshot,
            &prepared,
            request.global.tier,
            CacheDisposition::Disabled,
        )));
    }

    let location = cache_location(context, &selection)?;
    let store = CacheStore::open_writable(&location, &selection.canonical_root, &deadline)?;
    let tier = ResolverCacheTier::from(request.global.tier);
    let prior = refresh_prior(&store, tier, request.global.allow_partial, &deadline)?;
    let published = prepare_and_publish(
        &store,
        ExecutionRefreshInputs {
            request: &request,
            selection: &selection,
            options: ExecutionRefreshOptions {
                force: *force,
                trust_mtime: *trust_mtime,
            },
            prior: prior.as_ref(),
            prepared_at_ns,
            deadline: &deadline,
            context,
        }
        .candidate_inputs(),
        request.global.allow_partial,
    )?;
    let cache = refresh_cache_disposition(prior.as_ref(), &published.prepared);
    Ok(CommandOutput::Index(index_envelope(
        &selection,
        &published.loaded,
        &published.prepared,
        request.global.tier,
        cache,
    )))
}

fn execute_status(request: CliRequest, context: &ExecutionContext<'_>) -> Result<CommandOutput> {
    let deadline = deadline_before_selection(&request, context)?;
    let selection = select_project(&request, &context.cwd)?;
    let tier = ResolverCacheTier::from(request.global.tier);

    if request.global.frozen {
        let location = cache_location(context, &selection)?;
        let store = open_frozen(&location, &selection.canonical_root, &deadline)?;
        let snapshot = latest_active(&store, tier, request.global.allow_partial, &deadline)?
            .ok_or_else(frozen_missing)?;
        return Ok(CommandOutput::Status(status_envelope(
            &request,
            &selection,
            snapshot,
            Freshness::Frozen,
            CacheDisposition::Hit,
        )));
    }

    let prepared_at_ns = context.clock.unix_time_ns()?;
    if request.global.no_cache {
        let prepared = prepare(ExecutionRefreshInputs {
            request: &request,
            selection: &selection,
            options: ExecutionRefreshOptions::default(),
            prior: None,
            prepared_at_ns,
            deadline: &deadline,
            context,
        })?;
        enforce_partial(&prepared, request.global.allow_partial)?;
        return Ok(CommandOutput::Status(status_envelope(
            &request,
            &selection,
            loaded_from_candidate(prepared.snapshot),
            Freshness::Fresh,
            CacheDisposition::Disabled,
        )));
    }

    let location = cache_location(context, &selection)?;
    let store = CacheStore::open_writable(&location, &selection.canonical_root, &deadline)?;
    let prior = refresh_prior(&store, tier, request.global.allow_partial, &deadline)?;
    let refresh = prepare_and_publish(
        &store,
        ExecutionRefreshInputs {
            request: &request,
            selection: &selection,
            options: ExecutionRefreshOptions::default(),
            prior: prior.as_ref(),
            prepared_at_ns,
            deadline: &deadline,
            context,
        }
        .candidate_inputs(),
        request.global.allow_partial,
    );
    match refresh {
        Ok(published) => Ok(CommandOutput::Status(status_envelope(
            &request,
            &selection,
            published.loaded,
            Freshness::Fresh,
            refresh_cache_disposition(prior.as_ref(), &published.prepared),
        ))),
        Err(error) if request.global.allow_stale => {
            let snapshot = latest_active(&store, tier, request.global.allow_partial, &deadline)?
                .ok_or(error)?;
            Ok(CommandOutput::Status(status_envelope(
                &request,
                &selection,
                snapshot,
                Freshness::Stale,
                CacheDisposition::Hit,
            )))
        }
        Err(error) => Err(error),
    }
}

/// Loads a graph under the same frozen, no-cache, normal, and stale policy as
/// execution. It intentionally does not perform selector evaluation.
pub fn load_query_graph(
    request: &CliRequest,
    context: &ExecutionContext<'_>,
) -> Result<LoadedGraph> {
    let deadline = deadline_before_selection(request, context)?;
    let selection = select_project(request, &context.cwd)?;
    let tier = ResolverCacheTier::from(request.global.tier);
    if request.global.frozen {
        let location = cache_location(context, &selection)?;
        let store = open_frozen(&location, &selection.canonical_root, &deadline)?;
        let snapshot = latest_active(&store, tier, request.global.allow_partial, &deadline)?
            .ok_or_else(frozen_missing)?;
        return graph_from_snapshot(
            selection,
            snapshot,
            request.global.tier,
            Freshness::Frozen,
            CacheDisposition::Hit,
        );
    }
    let prepared_at_ns = context.clock.unix_time_ns()?;
    if request.global.no_cache {
        let prepared = prepare(ExecutionRefreshInputs {
            request,
            selection: &selection,
            options: ExecutionRefreshOptions::default(),
            prior: None,
            prepared_at_ns,
            deadline: &deadline,
            context,
        })?;
        enforce_partial(&prepared, request.global.allow_partial)?;
        return graph_from_snapshot(
            selection,
            loaded_from_candidate(prepared.snapshot),
            request.global.tier,
            Freshness::Fresh,
            CacheDisposition::Disabled,
        );
    }
    let location = cache_location(context, &selection)?;
    let store = CacheStore::open_writable(&location, &selection.canonical_root, &deadline)?;
    let prior = refresh_prior(&store, tier, request.global.allow_partial, &deadline)?;
    match prepare_and_publish(
        &store,
        ExecutionRefreshInputs {
            request,
            selection: &selection,
            options: ExecutionRefreshOptions::default(),
            prior: prior.as_ref(),
            prepared_at_ns,
            deadline: &deadline,
            context,
        }
        .candidate_inputs(),
        request.global.allow_partial,
    ) {
        Ok(published) => graph_from_snapshot(
            selection,
            published.loaded,
            request.global.tier,
            Freshness::Fresh,
            refresh_cache_disposition(prior.as_ref(), &published.prepared),
        ),
        Err(error) if request.global.allow_stale => {
            latest_active(&store, tier, request.global.allow_partial, &deadline)?
                .ok_or(error)
                .and_then(|snapshot| {
                    graph_from_snapshot(
                        selection,
                        snapshot,
                        request.global.tier,
                        Freshness::Stale,
                        CacheDisposition::Hit,
                    )
                })
        }
        Err(error) => Err(error),
    }
}

fn prepare(inputs: ExecutionRefreshInputs<'_>) -> Result<PreparedRefreshCandidate> {
    prepare_refresh_candidate(inputs.candidate_inputs())
}

fn refresh_cache_disposition(
    prior: Option<&LoadedSnapshot>,
    prepared: &PreparedRefreshCandidate,
) -> CacheDisposition {
    let current = &prepared.snapshot.compatibility;
    if prior.is_some_and(|prior| {
        prior.compatibility.id == current.id
            && prior.compatibility.language_fingerprint == current.language_fingerprint
            && prior.compatibility.package_fingerprint == current.package_fingerprint
    }) {
        CacheDisposition::Hit
    } else {
        CacheDisposition::Miss
    }
}

fn enforce_partial(prepared: &PreparedRefreshCandidate, allowed: bool) -> Result<()> {
    if prepared.snapshot.completeness == CacheCompleteness::Partial && !allowed {
        return Err(CliError::PartialNotAllowed);
    }
    Ok(())
}

fn open_frozen(
    location: &CacheLocation,
    root: &std::path::Path,
    deadline: &Deadline,
) -> Result<CacheStore> {
    match CacheStore::open_frozen(location, root, deadline) {
        Err(CacheError::Missing) => Err(frozen_missing()),
        result => result.map_err(Into::into),
    }
}

fn cache_location(
    context: &ExecutionContext<'_>,
    selection: &crate::ProjectSelection,
) -> Result<CacheLocation> {
    CacheLocation::for_project(context.cache_base.as_deref(), &selection.canonical_root)
        .ok_or_else(|| CliError::Cache("no operating-system cache directory is available".into()))
}

fn loaded_from_candidate(snapshot: CandidateSnapshot) -> LoadedSnapshot {
    LoadedSnapshot {
        candidate_id: snapshot.candidate_id,
        compatibility: snapshot.compatibility,
        input_digest: snapshot.input_digest,
        completeness: snapshot.completeness,
        omissions: snapshot.omissions,
        created_at_ns: snapshot.created_at_ns,
        inventory_file_count: snapshot.inventory_file_count,
        inventory_total_bytes: snapshot.inventory_total_bytes,
        files: snapshot.files,
        tier_graphs: snapshot.tier_graphs,
    }
}

fn index_envelope(
    selection: &crate::ProjectSelection,
    snapshot: &LoadedSnapshot,
    prepared: &PreparedRefreshCandidate,
    tier: crate::ResolverTier,
    cache: CacheDisposition,
) -> OutputEnvelope<IndexOutput> {
    let mut envelope = OutputEnvelope::new(
        success_status(snapshot.completeness, Freshness::Fresh),
        IndexOutput::from_loaded_snapshot(
            snapshot,
            tier,
            prepared.changed_paths.len(),
            prepared.deleted_paths.len(),
            prepared.ignored_omissions.len(),
            prepared.attempts,
            PlanDecisionCountsOutput::from(&prepared.plan),
        ),
    );
    envelope.project = Some(project_output(
        selection,
        snapshot,
        tier,
        Freshness::Fresh,
        cache,
    ));
    envelope
}

fn status_envelope(
    request: &CliRequest,
    selection: &crate::ProjectSelection,
    snapshot: LoadedSnapshot,
    freshness: Freshness,
    cache: CacheDisposition,
) -> OutputEnvelope<StatusOutput> {
    let project = project_output(selection, &snapshot, request.global.tier, freshness, cache);
    let mut envelope = OutputEnvelope::new(
        success_status(snapshot.completeness, freshness),
        StatusOutput::from_loaded_snapshot(project.clone(), &snapshot, &request.global.limits),
    );
    envelope.project = Some(project);
    envelope
}

fn graph_from_snapshot(
    selection: crate::ProjectSelection,
    snapshot: LoadedSnapshot,
    tier: crate::ResolverTier,
    freshness: Freshness,
    cache: CacheDisposition,
) -> Result<LoadedGraph> {
    let graph = snapshot
        .tier_graphs
        .iter()
        .find(|(stored, _)| *stored == ResolverCacheTier::from(tier))
        .map(|(_, graph)| graph.clone())
        .ok_or_else(|| {
            CliError::Cache("selected snapshot lacks the requested resolver tier graph".into())
        })?;
    let project = project_output(&selection, &snapshot, tier, freshness, cache);
    Ok(LoadedGraph {
        selection,
        snapshot,
        graph,
        project,
    })
}

fn project_output(
    selection: &crate::ProjectSelection,
    snapshot: &LoadedSnapshot,
    tier: crate::ResolverTier,
    freshness: Freshness,
    cache: CacheDisposition,
) -> ProjectOutput {
    ProjectOutput {
        root: selection.canonical_root.to_string_lossy().into_owned(),
        snapshot: snapshot.candidate_id.to_string(),
        tier,
        freshness,
        cache,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tempfile::{TempDir, tempdir};

    use super::*;
    use crate::{
        CacheCompletenessOutput, Cancellation, Clock, GlobalOptions, NeverCancelled, OutputStatus,
        ResolverTier,
    };

    struct FixedClock;
    impl Clock for FixedClock {
        fn unix_time_ns(&self) -> Result<u64> {
            Ok(7)
        }
    }

    struct Cancelled;
    impl Cancellation for Cancelled {
        fn is_cancelled(&self) -> bool {
            true
        }
    }

    struct PanicClock;
    impl Clock for PanicClock {
        fn unix_time_ns(&self) -> Result<u64> {
            panic!("frozen execution must not read the wall clock")
        }
    }

    struct CountingClock(AtomicUsize);
    impl Clock for CountingClock {
        fn unix_time_ns(&self) -> Result<u64> {
            Ok(self.0.fetch_add(1, Ordering::SeqCst) as u64 + 10)
        }
    }

    struct FailingClock;
    impl Clock for FailingClock {
        fn unix_time_ns(&self) -> Result<u64> {
            Err(CliError::Fatal("clock unavailable".into()))
        }
    }

    fn status(no_cache: bool) -> CliRequest {
        CliRequest {
            global: GlobalOptions {
                no_cache,
                ..GlobalOptions::default()
            },
            command: CommandRequest::Status,
        }
    }

    #[test]
    fn no_cache_status_never_creates_its_cache_base() {
        let project = tempdir().expect("project");
        let cache = project.path().join("cache-base");
        let cancellation = NeverCancelled;
        let clock = FixedClock;
        let context = ExecutionContext::new(
            PathBuf::from(project.path()),
            Some(cache.clone()),
            &cancellation,
            &clock,
        );
        let output = execute(status(true), &context).expect("status");
        assert!(matches!(output, CommandOutput::Status(_)));
        assert!(!cache.exists());
    }

    #[test]
    fn cancellation_stops_before_project_selection() {
        let missing = PathBuf::from("/definitely-not-a-project");
        let cancellation = Cancelled;
        let clock = FixedClock;
        let context = ExecutionContext::new(missing, None, &cancellation, &clock);
        assert!(matches!(
            execute(status(true), &context),
            Err(CliError::Cancelled)
        ));
    }

    fn fixture() -> (TempDir, PathBuf, PathBuf) {
        let temp = tempdir().expect("fixture");
        let root = temp.path().join("project");
        let cache = temp.path().join("cache");
        fs::create_dir(&root).expect("project");
        (temp, root, cache)
    }

    fn index_request(no_cache: bool) -> CliRequest {
        CliRequest {
            global: GlobalOptions {
                no_cache,
                ..GlobalOptions::default()
            },
            command: CommandRequest::Index {
                path: None,
                force: false,
                trust_mtime: false,
            },
        }
    }

    fn context<'a>(
        root: &Path,
        cache: &Path,
        cancellation: &'a dyn Cancellation,
        clock: &'a dyn Clock,
    ) -> ExecutionContext<'a> {
        ExecutionContext::new(
            root.to_path_buf(),
            Some(cache.to_path_buf()),
            cancellation,
            clock,
        )
    }

    #[test]
    fn normal_cache_reports_miss_then_hit_and_loads_the_requested_tier() {
        let (_temp, root, cache) = fixture();
        let cancellation = NeverCancelled;
        let clock = CountingClock(AtomicUsize::new(0));
        let context = context(&root, &cache, &cancellation, &clock);

        let first = execute(index_request(false), &context).expect("first index");
        let CommandOutput::Index(first) = first else {
            panic!("index output")
        };
        assert_eq!(first.status, OutputStatus::Ok);
        assert_eq!(
            first.results.completeness,
            CacheCompletenessOutput::Complete
        );
        assert_eq!(first.results.tier, ResolverTier::Scope);
        let project = first.project.expect("project");
        assert_eq!(project.cache, CacheDisposition::Miss);
        assert_eq!(project.freshness, Freshness::Fresh);
        assert_eq!(project.snapshot, first.results.snapshot);

        let second = execute(index_request(false), &context).expect("second index");
        let CommandOutput::Index(second) = second else {
            panic!("index output")
        };
        assert_eq!(
            second.project.expect("project").cache,
            CacheDisposition::Hit
        );

        let loaded = load_query_graph(&status(false), &context).expect("query graph");
        assert_eq!(loaded.project.cache, CacheDisposition::Hit);
        assert_eq!(loaded.project.tier, ResolverTier::Scope);
        assert_eq!(loaded.snapshot.tier_graphs.len(), 1);
        assert_eq!(loaded.snapshot.tier_graphs[0].0, ResolverCacheTier::Scope);
        assert_eq!(clock.0.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn incompatible_prior_is_reported_as_a_cache_miss() {
        let (_temp, root, cache) = fixture();
        let cancellation = NeverCancelled;
        let clock = FixedClock;
        let context = context(&root, &cache, &cancellation, &clock);
        execute(index_request(false), &context).expect("initial index");
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = 'changed-package'\nversion = '0.1.0'\n",
        )
        .expect("manifest");

        let CommandOutput::Index(refreshed) =
            execute(index_request(false), &context).expect("incompatible refresh")
        else {
            panic!("index output")
        };
        assert_eq!(
            refreshed.project.expect("project").cache,
            CacheDisposition::Miss
        );
    }

    #[test]
    fn no_cache_index_status_and_graph_never_resolve_a_cache_location() {
        let (_temp, root, cache) = fixture();
        let cancellation = NeverCancelled;
        let clock = FixedClock;
        let context = context(&root, &cache, &cancellation, &clock);

        let CommandOutput::Index(index) =
            execute(index_request(true), &context).expect("no-cache index")
        else {
            panic!("index output")
        };
        assert_eq!(
            index.project.expect("index project").cache,
            CacheDisposition::Disabled
        );
        let CommandOutput::Status(status) =
            execute(status(true), &context).expect("no-cache status")
        else {
            panic!("status output")
        };
        assert_eq!(status.results.project.cache, CacheDisposition::Disabled);
        let graph = load_query_graph(&status_request(true), &context).expect("no-cache graph");
        assert_eq!(graph.project.cache, CacheDisposition::Disabled);
        assert!(!cache.exists());
    }

    fn status_request(no_cache: bool) -> CliRequest {
        status(no_cache)
    }

    #[test]
    fn frozen_status_and_graph_use_only_the_cached_snapshot() {
        let (_temp, root, cache) = fixture();
        let cancellation = NeverCancelled;
        let clock = FixedClock;
        let writable = context(&root, &cache, &cancellation, &clock);
        let CommandOutput::Index(seed) =
            execute(index_request(false), &writable).expect("seed cache")
        else {
            panic!("index output")
        };
        let snapshot = seed.results.snapshot;
        fs::write(root.join("added-after-index.rs"), "fn added() {}\n").expect("new source");

        let panic_clock = PanicClock;
        let frozen_context = context(&root, &cache, &cancellation, &panic_clock);
        let mut request = status(false);
        request.global.frozen = true;
        let CommandOutput::Status(status) =
            execute(request.clone(), &frozen_context).expect("frozen status")
        else {
            panic!("status output")
        };
        assert_eq!(status.status, OutputStatus::Ok);
        assert_eq!(status.results.project.snapshot, snapshot);
        assert_eq!(status.results.project.freshness, Freshness::Frozen);
        assert_eq!(status.results.project.cache, CacheDisposition::Hit);
        assert_eq!(status.results.inventory.admitted_files, 0);

        let graph = load_query_graph(&request, &frozen_context).expect("frozen graph");
        assert_eq!(graph.project.snapshot, snapshot);
        assert_eq!(graph.project.freshness, Freshness::Frozen);
    }

    #[test]
    fn complete_is_preferred_over_partial_and_partial_requires_allowance() {
        let (_temp, root, cache) = fixture();
        let cancellation = NeverCancelled;
        let clock = FixedClock;
        let context = context(&root, &cache, &cancellation, &clock);
        let CommandOutput::Index(complete) =
            execute(index_request(false), &context).expect("complete seed")
        else {
            panic!("index output")
        };
        let complete_snapshot = complete.results.snapshot;
        fs::write(root.join("bounded.rs"), "fn bounded() {}\n").expect("source");

        let mut partial_request = index_request(false);
        partial_request.global.allow_partial = true;
        partial_request.global.limits.max_files = 0;
        let CommandOutput::Index(partial) =
            execute(partial_request, &context).expect("partial index")
        else {
            panic!("index output")
        };
        assert_eq!(partial.status, OutputStatus::Partial);
        assert_eq!(
            partial.results.completeness,
            CacheCompletenessOutput::Partial
        );

        let mut frozen = status(false);
        frozen.global.frozen = true;
        frozen.global.allow_partial = true;
        let CommandOutput::Status(selected) = execute(frozen, &context).expect("frozen selection")
        else {
            panic!("status output")
        };
        assert_eq!(selected.results.project.snapshot, complete_snapshot);
        assert_eq!(selected.status, OutputStatus::Ok);
    }

    #[test]
    fn partial_only_snapshot_is_hidden_without_allow_partial() {
        let (_temp, root, cache) = fixture();
        fs::write(root.join("bounded.rs"), "fn bounded() {}\n").expect("source");
        let cancellation = NeverCancelled;
        let clock = FixedClock;
        let context = context(&root, &cache, &cancellation, &clock);
        let mut index = index_request(false);
        index.global.allow_partial = true;
        index.global.limits.max_files = 0;
        execute(index, &context).expect("partial seed");

        let mut frozen = status(false);
        frozen.global.frozen = true;
        assert!(matches!(
            execute(frozen.clone(), &context),
            Err(CliError::FrozenSnapshotMissing)
        ));
        frozen.global.allow_partial = true;
        let CommandOutput::Status(output) = execute(frozen, &context).expect("allowed partial")
        else {
            panic!("status output")
        };
        assert_eq!(output.status, OutputStatus::Partial);
    }

    #[test]
    fn stale_fallback_occurs_only_when_explicitly_allowed() {
        let (_temp, root, cache) = fixture();
        let cancellation = NeverCancelled;
        let clock = FixedClock;
        let context = context(&root, &cache, &cancellation, &clock);
        execute(index_request(false), &context).expect("complete seed");
        fs::write(root.join("bounded.rs"), "fn bounded() {}\n").expect("source");

        let mut refresh = status(false);
        refresh.global.limits.max_files = 0;
        assert!(matches!(
            execute(refresh.clone(), &context),
            Err(CliError::PartialNotAllowed)
        ));
        refresh.global.allow_stale = true;
        let CommandOutput::Status(stale) =
            execute(refresh.clone(), &context).expect("stale status")
        else {
            panic!("status output")
        };
        assert_eq!(stale.status, OutputStatus::Stale);
        assert_eq!(stale.results.project.freshness, Freshness::Stale);
        assert_eq!(stale.results.project.cache, CacheDisposition::Hit);

        let graph = load_query_graph(&refresh, &context).expect("stale graph");
        assert_eq!(graph.project.freshness, Freshness::Stale);
    }

    #[test]
    fn tier_selection_never_substitutes_an_available_different_graph() {
        let (_temp, root, cache) = fixture();
        let cancellation = NeverCancelled;
        let clock = FixedClock;
        let context = context(&root, &cache, &cancellation, &clock);
        let mut name = index_request(false);
        name.global.tier = ResolverTier::Name;
        execute(name, &context).expect("name seed");

        let mut scope = status(false);
        scope.global.frozen = true;
        scope.global.tier = ResolverTier::Scope;
        assert!(matches!(
            load_query_graph(&scope, &context),
            Err(CliError::FrozenSnapshotMissing)
        ));
    }

    #[test]
    fn clock_failure_precedes_cache_location_side_effects() {
        let (_temp, root, cache) = fixture();
        let cancellation = NeverCancelled;
        let clock = FailingClock;
        let context = context(&root, &cache, &cancellation, &clock);
        assert!(matches!(
            execute(status(false), &context),
            Err(CliError::Fatal(message)) if message == "clock unavailable"
        ));
        assert!(matches!(
            load_query_graph(&status(false), &context),
            Err(CliError::Fatal(message)) if message == "clock unavailable"
        ));
        assert!(!cache.exists());
    }
}
