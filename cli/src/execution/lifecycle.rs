// SPDX-License-Identifier: Apache-2.0

use code2graph::{CodeGraph, Edge, EdgeKey, Symbol, SymbolId};
use code2graph_query::{EdgeFilter, GraphIndex, GraphPage, GraphRead};

use crate::cache::{
    ActiveSnapshotMetadata, CacheCompleteness, CacheError, CacheGraphRead, CacheLocation,
    CacheStore, CandidateSnapshot, LoadedSnapshot, ResolverCacheTier,
};
use crate::commands::{
    DefinitionCommandRequest, ImpactCommandRequest, ImportsCommandRequest,
    ModuleDepsCommandRequest, QueryCommandContext, ReferencesCommandRequest,
    RelationCommandRequest, RelationDirection, SymbolsCommandRequest, execute_definition,
    execute_impact, execute_imports, execute_module_deps, execute_references, execute_relations,
    execute_symbols,
};
use crate::inventory::{OmissionImpact, discover_sources_checked};
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
    Imports(OutputEnvelope<Vec<crate::RelationOutput>>),
    References(OutputEnvelope<Vec<crate::ReferenceOutput>>),
    ModuleDeps(OutputEnvelope<Vec<crate::ModuleDependencyOutput>>),
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

enum QueryGraph<'a, 'deadline> {
    InMemory(GraphIndex),
    Cached(CacheGraphRead<'a, 'deadline>),
}

impl GraphRead for QueryGraph<'_, '_> {
    type Error = CliError;

    fn symbol(&self, id: &SymbolId) -> std::result::Result<Option<Symbol>, Self::Error> {
        match self {
            Self::InMemory(graph) => GraphRead::symbol(graph, id).map_err(|never| match never {}),
            Self::Cached(graph) => graph.symbol(id).map_err(Into::into),
        }
    }
    fn contains_id(&self, id: &SymbolId) -> std::result::Result<bool, Self::Error> {
        match self {
            Self::InMemory(graph) => {
                GraphRead::contains_id(graph, id).map_err(|never| match never {})
            }
            Self::Cached(graph) => graph.contains_id(id).map_err(Into::into),
        }
    }
    fn symbols(
        &self,
        after: Option<&SymbolId>,
        limit: usize,
    ) -> std::result::Result<GraphPage<Symbol, SymbolId>, Self::Error> {
        match self {
            Self::InMemory(graph) => {
                GraphRead::symbols(graph, after, limit).map_err(|never| match never {})
            }
            Self::Cached(graph) => graph.symbols(after, limit).map_err(Into::into),
        }
    }
    fn symbols_named(
        &self,
        name: &str,
        after: Option<&SymbolId>,
        limit: usize,
    ) -> std::result::Result<GraphPage<Symbol, SymbolId>, Self::Error> {
        match self {
            Self::InMemory(graph) => {
                GraphRead::symbols_named(graph, name, after, limit).map_err(|never| match never {})
            }
            Self::Cached(graph) => graph.symbols_named(name, after, limit).map_err(Into::into),
        }
    }
    fn symbols_with_scip(
        &self,
        scip: &str,
        after: Option<&SymbolId>,
        limit: usize,
    ) -> std::result::Result<GraphPage<Symbol, SymbolId>, Self::Error> {
        match self {
            Self::InMemory(graph) => GraphRead::symbols_with_scip(graph, scip, after, limit)
                .map_err(|never| match never {}),
            Self::Cached(graph) => graph
                .symbols_with_scip(scip, after, limit)
                .map_err(Into::into),
        }
    }
    fn ids_with_scip(
        &self,
        scip: &str,
        after: Option<&SymbolId>,
        limit: usize,
    ) -> std::result::Result<GraphPage<SymbolId, SymbolId>, Self::Error> {
        match self {
            Self::InMemory(graph) => {
                GraphRead::ids_with_scip(graph, scip, after, limit).map_err(|never| match never {})
            }
            Self::Cached(graph) => graph.ids_with_scip(scip, after, limit).map_err(Into::into),
        }
    }
    fn symbols_in_file(
        &self,
        file: &str,
        after: Option<&SymbolId>,
        limit: usize,
    ) -> std::result::Result<GraphPage<Symbol, SymbolId>, Self::Error> {
        match self {
            Self::InMemory(graph) => GraphRead::symbols_in_file(graph, file, after, limit)
                .map_err(|never| match never {}),
            Self::Cached(graph) => graph
                .symbols_in_file(file, after, limit)
                .map_err(Into::into),
        }
    }
    fn symbol_at_byte(
        &self,
        file: &str,
        byte: usize,
    ) -> std::result::Result<Option<Symbol>, Self::Error> {
        match self {
            Self::InMemory(graph) => {
                GraphRead::symbol_at_byte(graph, file, byte).map_err(|never| match never {})
            }
            Self::Cached(graph) => graph.symbol_at_byte(file, byte).map_err(Into::into),
        }
    }
    fn edges(
        &self,
        filter: EdgeFilter,
        after: Option<&EdgeKey>,
        limit: usize,
    ) -> std::result::Result<GraphPage<Edge, EdgeKey>, Self::Error> {
        match self {
            Self::InMemory(graph) => {
                GraphRead::edges(graph, filter, after, limit).map_err(|never| match never {})
            }
            Self::Cached(graph) => graph.edges(filter, after, limit).map_err(Into::into),
        }
    }
    fn edges_in_file(
        &self,
        file: &str,
        filter: EdgeFilter,
        after: Option<&EdgeKey>,
        limit: usize,
    ) -> std::result::Result<GraphPage<Edge, EdgeKey>, Self::Error> {
        match self {
            Self::InMemory(graph) => GraphRead::edges_in_file(graph, file, filter, after, limit)
                .map_err(|never| match never {}),
            Self::Cached(graph) => graph
                .edges_in_file(file, filter, after, limit)
                .map_err(Into::into),
        }
    }
    fn incoming(
        &self,
        id: &SymbolId,
        filter: EdgeFilter,
        after: Option<&EdgeKey>,
        limit: usize,
    ) -> std::result::Result<GraphPage<Edge, EdgeKey>, Self::Error> {
        match self {
            Self::InMemory(graph) => {
                GraphRead::incoming(graph, id, filter, after, limit).map_err(|never| match never {})
            }
            Self::Cached(graph) => graph.incoming(id, filter, after, limit).map_err(Into::into),
        }
    }
    fn outgoing(
        &self,
        id: &SymbolId,
        filter: EdgeFilter,
        after: Option<&EdgeKey>,
        limit: usize,
    ) -> std::result::Result<GraphPage<Edge, EdgeKey>, Self::Error> {
        match self {
            Self::InMemory(graph) => {
                GraphRead::outgoing(graph, id, filter, after, limit).map_err(|never| match never {})
            }
            Self::Cached(graph) => graph.outgoing(id, filter, after, limit).map_err(Into::into),
        }
    }
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
        CommandRequest::Imports { file } => execute_imports_query(
            request,
            context,
            ImportsCommandRequest {
                file: &file,
                result_limit,
                min_confidence,
            },
        ),
        CommandRequest::References { file, name, role } => execute_references_query(
            request,
            context,
            ReferencesCommandRequest {
                file: &file,
                name: name.as_deref(),
                role,
                result_limit,
            },
        ),
        CommandRequest::ModuleDeps => execute_module_deps_query(
            request,
            context,
            ModuleDepsCommandRequest {
                result_limit,
                min_confidence,
            },
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
                role,
                depth,
                max_nodes: result_limit,
                min_confidence,
            },
        ),
    }
}

fn execute_imports_query(
    request: CliRequest,
    execution: &ExecutionContext<'_>,
    command: ImportsCommandRequest<'_>,
) -> Result<CommandOutput> {
    execute_query_backend(request, execution, |context| {
        execute_imports(context, command).map(CommandOutput::Imports)
    })
}

fn execute_references_query(
    request: CliRequest,
    execution: &ExecutionContext<'_>,
    command: ReferencesCommandRequest<'_>,
) -> Result<CommandOutput> {
    execute_query_backend(request, execution, |context| {
        execute_references(context, command).map(CommandOutput::References)
    })
}

fn execute_module_deps_query(
    request: CliRequest,
    execution: &ExecutionContext<'_>,
    command: ModuleDepsCommandRequest,
) -> Result<CommandOutput> {
    execute_query_backend(request, execution, |context| {
        execute_module_deps(context, command).map(CommandOutput::ModuleDeps)
    })
}

fn execute_symbols_query(
    request: CliRequest,
    execution: &ExecutionContext<'_>,
    command: SymbolsCommandRequest<'_>,
) -> Result<CommandOutput> {
    execute_query_backend(request, execution, |context| {
        execute_symbols(context, command).map(CommandOutput::Symbols)
    })
}

fn execute_relations_query(
    request: CliRequest,
    execution: &ExecutionContext<'_>,
    command: RelationCommandRequest<'_>,
    output: fn(OutputEnvelope<Vec<crate::RelationOutput>>) -> CommandOutput,
) -> Result<CommandOutput> {
    execute_query_backend(request, execution, |context| {
        execute_relations(context, command).map(output)
    })
}

fn execute_impact_query(
    request: CliRequest,
    execution: &ExecutionContext<'_>,
    command: ImpactCommandRequest<'_>,
) -> Result<CommandOutput> {
    execute_query_backend(request, execution, |context| {
        execute_impact(context, command).map(CommandOutput::Impact)
    })
}

fn execute_definition_query(
    request: CliRequest,
    execution: &ExecutionContext<'_>,
    command: DefinitionCommandRequest<'_>,
) -> Result<CommandOutput> {
    execute_query_backend(request, execution, |context| {
        execute_definition(context, command).map(CommandOutput::Def)
    })
}

fn execute_query_backend(
    request: CliRequest,
    execution: &ExecutionContext<'_>,
    run: impl FnOnce(&QueryCommandContext<'_, QueryGraph<'_, '_>>) -> Result<CommandOutput>,
) -> Result<CommandOutput> {
    let deadline = deadline_before_selection(&request, execution)?;
    let selection = select_project(&request, &execution.cwd)?;
    let tier = ResolverCacheTier::from(request.global.tier);
    if request.global.no_cache {
        let LoadedGraph {
            selection,
            snapshot,
            graph: resolved,
            project,
        } = load_query_graph(&request, execution)?;
        let loaded = LoadedGraph {
            selection,
            snapshot,
            graph: CodeGraph {
                symbols: Vec::new(),
                edges: Vec::new(),
            },
            project,
        };
        let graph = QueryGraph::InMemory(
            GraphIndex::from_graph(resolved).map_err(|error| CliError::Index(error.to_string()))?,
        );
        let context = QueryCommandContext::new(
            &loaded,
            &graph,
            &deadline,
            execution.cancellation,
            request.global.limits.max_file_bytes,
        )?;
        return run(&context);
    }

    let location = cache_location(execution, &selection)?;
    let store = if request.global.frozen {
        open_frozen(&location, &selection.canonical_root, &deadline)?
    } else {
        CacheStore::open_writable(&location, &selection.canonical_root, &deadline)?
    };
    let (metadata, freshness, cache) = if request.global.frozen {
        (
            active_metadata(&store, tier, request.global.allow_partial, &deadline)?
                .ok_or_else(frozen_missing)?,
            Freshness::Frozen,
            CacheDisposition::Hit,
        )
    } else {
        let prepared_at_ns = execution.clock.unix_time_ns()?;
        // Cached query execution never hydrates a whole prior snapshot. A refresh
        // runs only when no active metadata exists; source-changing operations
        // use the explicit index/status refresh path below.
        let prior: Option<LoadedSnapshot> = None;
        let active = active_metadata(&store, tier, request.global.allow_partial, &deadline)?;
        let current = match active.as_ref() {
            Some(metadata) => cached_sources_are_current(
                &store,
                metadata,
                &request,
                &selection,
                &deadline,
                execution.cancellation,
            )?,
            None => false,
        };
        match if current {
            Ok(None)
        } else {
            prepare_and_publish(
                &store,
                ExecutionRefreshInputs {
                    request: &request,
                    selection: &selection,
                    options: ExecutionRefreshOptions::default(),
                    prior: prior.as_ref(),
                    prepared_at_ns,
                    deadline: &deadline,
                    context: execution,
                }
                .candidate_inputs(),
                request.global.allow_partial,
            )
            .map(Some)
        } {
            Ok(Some(published)) => (
                active_metadata(&store, tier, request.global.allow_partial, &deadline)?
                    .ok_or_else(|| CliError::Cache("published snapshot is not active".into()))?,
                Freshness::Fresh,
                refresh_cache_disposition(prior.as_ref(), &published.prepared),
            ),
            Ok(None) => (
                active.expect("checked active metadata"),
                Freshness::Fresh,
                CacheDisposition::Hit,
            ),
            Err(error) if request.global.allow_stale => (
                active_metadata(&store, tier, request.global.allow_partial, &deadline)?
                    .ok_or(error)?,
                Freshness::Stale,
                CacheDisposition::Hit,
            ),
            Err(error) => return Err(error),
        }
    };
    let hashes = store.candidate_file_hashes(metadata.candidate_id, &deadline)?;
    let reference_facts = match &request.command {
        CommandRequest::References { file, .. } => {
            store.file_facts(metadata.candidate_id, file, &deadline)?
        }
        _ => None,
    };
    let loaded = loaded_from_metadata(selection, metadata, request.global.tier, freshness, cache);
    let graph =
        QueryGraph::Cached(store.graph_reader(loaded.snapshot.candidate_id, tier, &deadline)?);
    let context = QueryCommandContext::with_candidate_hashes(
        &loaded,
        &graph,
        &deadline,
        execution.cancellation,
        request.global.limits.max_file_bytes,
        hashes,
        reference_facts,
    )?;
    run(&context)
}

fn active_metadata(
    store: &CacheStore,
    tier: ResolverCacheTier,
    allow_partial: bool,
    deadline: &Deadline,
) -> Result<Option<ActiveSnapshotMetadata>> {
    let complete = store.active_metadata(tier, CacheCompleteness::Complete, deadline)?;
    if complete.is_some() || !allow_partial {
        return Ok(complete);
    }
    store
        .active_metadata(tier, CacheCompleteness::Partial, deadline)
        .map_err(Into::into)
}

fn cached_sources_are_current(
    store: &CacheStore,
    metadata: &ActiveSnapshotMetadata,
    request: &CliRequest,
    selection: &crate::ProjectSelection,
    deadline: &Deadline,
    cancellation: &dyn crate::Cancellation,
) -> Result<bool> {
    if metadata.completeness != CacheCompleteness::Complete {
        return Ok(false);
    }
    let discovery = discover_sources_checked(
        selection,
        &request.global.limits,
        request.global.include_hidden,
        deadline,
        cancellation,
    )?;
    if discovery
        .omitted
        .iter()
        .any(|omission| omission.impact == OmissionImpact::IncompleteSourceSet)
        || discovery.candidates.len() as u64 != metadata.inventory_file_count
    {
        return Ok(false);
    }
    let cached = store.candidate_file_metadata(metadata.candidate_id, deadline)?;
    if cached.len() != discovery.candidates.len() {
        return Ok(false);
    }
    Ok(discovery
        .candidates
        .iter()
        .zip(cached)
        .all(|(candidate, cached)| {
            candidate.path.as_str() == cached.path
                && candidate
                    .language
                    .is_some_and(|language| language.as_str() == cached.language)
                && candidate.size_bytes == cached.size_bytes
                && candidate.mtime == cached.mtime
        }))
}

fn loaded_from_metadata(
    selection: crate::ProjectSelection,
    metadata: ActiveSnapshotMetadata,
    tier: crate::ResolverTier,
    freshness: Freshness,
    cache: CacheDisposition,
) -> LoadedGraph {
    let snapshot = LoadedSnapshot {
        candidate_id: metadata.candidate_id,
        compatibility: metadata.compatibility,
        input_digest: metadata.input_digest,
        completeness: metadata.completeness,
        omissions: metadata.omissions,
        created_at_ns: metadata.created_at_ns,
        inventory_file_count: metadata.inventory_file_count,
        inventory_total_bytes: metadata.inventory_total_bytes,
        files: Vec::new(),
        tier_graphs: Vec::new(),
    };
    let project = project_output(&selection, &snapshot, tier, freshness, cache);
    LoadedGraph {
        selection,
        snapshot,
        graph: CodeGraph {
            symbols: Vec::new(),
            edges: Vec::new(),
        },
        project,
    }
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
        let metadata = active_metadata(&store, tier, request.global.allow_partial, &deadline)?
            .ok_or_else(frozen_missing)?;
        let loaded = loaded_from_metadata(
            selection.clone(),
            metadata,
            request.global.tier,
            Freshness::Frozen,
            CacheDisposition::Hit,
        );
        return Ok(CommandOutput::Status(status_envelope(
            &request,
            &selection,
            loaded.snapshot,
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
    if let Some(metadata) = active_metadata(&store, tier, request.global.allow_partial, &deadline)?
        && cached_sources_are_current(
            &store,
            &metadata,
            &request,
            &selection,
            &deadline,
            context.cancellation,
        )?
    {
        let loaded = loaded_from_metadata(
            selection.clone(),
            metadata,
            request.global.tier,
            Freshness::Fresh,
            CacheDisposition::Hit,
        );
        return Ok(CommandOutput::Status(status_envelope(
            &request,
            &selection,
            loaded.snapshot,
            Freshness::Fresh,
            CacheDisposition::Hit,
        )));
    }
    let prior: Option<LoadedSnapshot> = None;
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
        Ok(published) => {
            let metadata = active_metadata(&store, tier, request.global.allow_partial, &deadline)?
                .ok_or_else(|| CliError::Cache("published snapshot is not active".into()))?;
            let loaded = loaded_from_metadata(
                selection.clone(),
                metadata,
                request.global.tier,
                Freshness::Fresh,
                refresh_cache_disposition(prior.as_ref(), &published.prepared),
            );
            Ok(CommandOutput::Status(status_envelope(
                &request,
                &selection,
                loaded.snapshot,
                Freshness::Fresh,
                refresh_cache_disposition(prior.as_ref(), &published.prepared),
            )))
        }
        Err(error) if request.global.allow_stale => {
            let metadata = active_metadata(&store, tier, request.global.allow_partial, &deadline)?
                .ok_or(error)?;
            let loaded = loaded_from_metadata(
                selection.clone(),
                metadata,
                request.global.tier,
                Freshness::Stale,
                CacheDisposition::Hit,
            );
            Ok(CommandOutput::Status(status_envelope(
                &request,
                &selection,
                loaded.snapshot,
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
    mut snapshot: LoadedSnapshot,
    tier: crate::ResolverTier,
    freshness: Freshness,
    cache: CacheDisposition,
) -> Result<LoadedGraph> {
    let graph_index = snapshot
        .tier_graphs
        .iter()
        .position(|(stored, _)| *stored == ResolverCacheTier::from(tier))
        .ok_or_else(|| {
            CliError::Cache("selected snapshot lacks the requested resolver tier graph".into())
        })?;
    let graph = std::mem::replace(
        &mut snapshot.tier_graphs[graph_index].1,
        CodeGraph {
            symbols: Vec::new(),
            edges: Vec::new(),
        },
    );
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
        completeness: snapshot.completeness.into(),
        omitted_files: snapshot.omissions.len(),
        omissions: snapshot.omissions.iter().map(Into::into).collect(),
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
    fn frozen_cached_status_and_symbols_never_load_a_whole_graph() {
        let (_temp, root, cache) = fixture();
        let cancellation = NeverCancelled;
        let clock = FixedClock;
        let context = context(&root, &cache, &cancellation, &clock);
        execute(index_request(false), &context).expect("index");

        crate::cache::reset_whole_graph_loads();
        let mut frozen_status = status(false);
        frozen_status.global.frozen = true;
        execute(frozen_status, &context).expect("cached status");
        let frozen_symbols = CliRequest {
            global: GlobalOptions {
                frozen: true,
                ..GlobalOptions::default()
            },
            command: CommandRequest::Symbols {
                text: "run".into(),
                file: None,
                kind: None,
                case_sensitive: true,
            },
        };
        assert!(matches!(
            execute(frozen_symbols, &context),
            Err(CliError::NoMatch)
        ));
        assert_eq!(crate::cache::whole_graph_loads(), 0);
    }

    #[test]
    fn normal_cached_status_and_query_never_load_a_whole_graph() {
        let (_temp, root, cache) = fixture();
        let cancellation = NeverCancelled;
        let clock = FixedClock;
        let context = context(&root, &cache, &cancellation, &clock);
        execute(index_request(false), &context).expect("index");

        crate::cache::reset_whole_graph_loads();
        execute(status(false), &context).expect("cached status");
        let symbols = CliRequest {
            global: GlobalOptions::default(),
            command: CommandRequest::Symbols {
                text: "run".into(),
                file: None,
                kind: None,
                case_sensitive: true,
            },
        };
        let _ = execute(symbols, &context);
        assert_eq!(crate::cache::whole_graph_loads(), 0);
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
