// SPDX-License-Identifier: Apache-2.0

use code2graph::{CodeGraph, Edge, EdgeKey, Symbol, SymbolId};
use code2graph_query::{EdgeFilter, GraphIndex, GraphPage, GraphRead};

use crate::cache::{
    ActiveSnapshotMetadata, CacheCompleteness, CacheError, CacheGraphRead, CacheLocation,
    CacheStore, CompatibilityFingerprint, LanguageFeatureFingerprint, LoadedSnapshot,
    PackageFingerprint, ResolverCacheTier,
};
use crate::commands::{
    DefinitionCommandRequest, DiffImpactCommandRequest, ImpactCommandRequest,
    ImportsCommandRequest, ModuleDepsCommandRequest, QueryCommandContext, ReferencesCommandRequest,
    RelationCommandRequest, RelationDirection, SymbolsCommandRequest, execute_definition,
    execute_diff_impact, execute_impact, execute_imports, execute_module_deps, execute_references,
    execute_relations, execute_symbols,
};
use crate::inventory::{
    MaterializedCandidate, OmissionImpact, discover_sources_checked, materialize_candidate_checked,
};
use crate::package_assignment::assign_packages_checked;
use crate::refresh::{
    PrepareCandidateInputs, PreparedRefreshCandidate, apply_metadata_budgets, cache_omission,
    prepare_and_publish, prepare_refresh_candidate,
};
use crate::request::{CacheOp, CliRequest, CommandRequest};
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
    Cache(crate::CacheReport),
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

// The owned in-memory `GraphIndex` variant is larger than the borrowed cache
// read handle, but `QueryGraph` is only ever a single short-lived local per
// query (never held in bulk), so the size difference is immaterial here and
// boxing it would only add an indirection across every `GraphRead` method.
#[allow(clippy::large_enum_variant)]
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
        CommandRequest::DiffImpact { base, role, depth } => execute_diff_impact_query(
            request,
            context,
            DiffImpactCommandRequest {
                base,
                role,
                depth,
                max_nodes: result_limit,
                min_confidence,
            },
        ),
        CommandRequest::Cache { op } => execute_cache(op, request, context),
    }
}

/// Executes the cache-management operations. `path`/`status`/project `clear`
/// select the current project; `clear --all` operates on every cached project
/// without needing a project root.
fn execute_cache(
    op: CacheOp,
    request: CliRequest,
    context: &ExecutionContext<'_>,
) -> Result<CommandOutput> {
    let detail = match op {
        CacheOp::Path => {
            let selection = select_project(&request, &context.cwd)?;
            let location = cache_location(context, &selection)?;
            crate::CacheDetail::Path {
                cache_dir: location.directory.display().to_string(),
                database_path: location.database_path.display().to_string(),
                exists: location.database_path.exists(),
            }
        }
        CacheOp::Status { all: true } => {
            let projects_root = cache_projects_root(context)?;
            survey_projects(&projects_root)?
        }
        CacheOp::Status { all: false } => {
            let deadline = deadline_before_selection(&request, context)?;
            let selection = select_project(&request, &context.cwd)?;
            let location = cache_location(context, &selection)?;
            let exists = location.database_path.exists();
            let size_bytes = cache_size_bytes(&location.database_path);
            let snapshots = if exists {
                let store =
                    CacheStore::open_read_only(&location, &selection.canonical_root, &deadline)?;
                store
                    .snapshot_summaries(&deadline)?
                    .into_iter()
                    .map(|summary| crate::CacheSnapshotOutput {
                        tier: crate::ResolverTier::from(summary.tier).as_str().to_owned(),
                        active: summary.active,
                        symbols: summary.symbols,
                        edges: summary.edges,
                    })
                    .collect()
            } else {
                Vec::new()
            };
            let (schema_version, reclaimable_bytes) = database_health(&location.database_path);
            crate::CacheDetail::Status {
                cache_dir: location.directory.display().to_string(),
                database_path: location.database_path.display().to_string(),
                exists,
                size_bytes,
                reclaimable_bytes,
                schema_version,
                snapshots,
            }
        }
        CacheOp::Clear { all: false } => {
            let selection = select_project(&request, &context.cwd)?;
            let location = cache_location(context, &selection)?;
            let projects_root = cache_projects_root(context)?;
            let dir = &location.directory;
            let (removed, freed) = if dir.exists() {
                // Only ever remove a genuine `<base>/projects/<key>` directory.
                if dir.parent() != Some(projects_root.as_path()) {
                    return Err(CliError::Cache(
                        "refusing to remove a cache directory outside the cache root".into(),
                    ));
                }
                let freed = dir_size(dir);
                std::fs::remove_dir_all(dir).map_err(|error| {
                    CliError::Cache(format!("failed to remove cache directory: {error}"))
                })?;
                (1, freed)
            } else {
                (0, 0)
            };
            crate::CacheDetail::Clear {
                scope: crate::CacheClearScope::Project,
                removed_projects: removed,
                freed_bytes: freed,
            }
        }
        CacheOp::Clear { all: true } => {
            let projects_root = cache_projects_root(context)?;
            let (removed, freed) = clear_all_projects(&projects_root)?;
            crate::CacheDetail::Clear {
                scope: crate::CacheClearScope::All,
                removed_projects: removed,
                freed_bytes: freed,
            }
        }
        CacheOp::Rebuild => {
            // Discard first, then index: `--force` re-extracts but keeps the
            // database, so it cannot recover a cache whose file itself is the
            // problem. This is the "start over" path.
            let selection = select_project(&request, &context.cwd)?;
            let location = cache_location(context, &selection)?;
            let projects_root = cache_projects_root(context)?;
            let discarded = if location.directory.exists() {
                if location.directory.parent() != Some(projects_root.as_path()) {
                    return Err(CliError::Cache(
                        "refusing to remove a cache directory outside the cache root".into(),
                    ));
                }
                let freed = dir_size(&location.directory);
                std::fs::remove_dir_all(&location.directory).map_err(|error| {
                    CliError::Cache(format!("failed to remove cache directory: {error}"))
                })?;
                freed
            } else {
                0
            };
            let mut index = request.clone();
            index.command = CommandRequest::Index {
                path: None,
                force: false,
                trust_mtime: false,
            };
            let CommandOutput::Index(envelope) = execute_index(index, context)? else {
                return Err(CliError::Fatal("rebuild did not produce an index".into()));
            };
            crate::CacheDetail::Rebuild {
                discarded_bytes: discarded,
                indexed_files: envelope.results.inventory_file_count,
                size_bytes: dir_size(&location.directory),
            }
        }
        CacheOp::Prune => {
            let projects_root = cache_projects_root(context)?;
            prune_projects(&projects_root)?
        }
        CacheOp::Compact { all } => {
            let directories = if all {
                project_directories(&cache_projects_root(context)?)?
            } else {
                let selection = select_project(&request, &context.cwd)?;
                vec![cache_location(context, &selection)?.directory]
            };
            let mut compacted: u64 = 0;
            let mut freed: u64 = 0;
            for directory in directories {
                let database = directory.join(CACHE_DATABASE_NAME);
                if !database.is_file() {
                    continue;
                }
                let before = file_len(&database);
                if compact_database(&database) {
                    compacted += 1;
                    freed = freed.saturating_add(before.saturating_sub(file_len(&database)));
                }
            }
            crate::CacheDetail::Compact {
                compacted_projects: compacted,
                freed_bytes: freed,
            }
        }
    };
    Ok(CommandOutput::Cache(crate::CacheReport {
        status: crate::OutputStatus::Ok,
        detail,
    }))
}

/// How long a cache root goes between automatic prunes.
///
/// Long enough that the check costs one `stat` on essentially every command,
/// short enough that dead caches never accumulate for months. The work itself
/// only ever removes caches that can no longer serve a query.
const AUTO_PRUNE_INTERVAL_NS: u64 = 7 * 24 * 60 * 60 * 1_000_000_000;

/// Records when the cache root was last pruned. Its contents are the timestamp,
/// so the decision never depends on filesystem mtime granularity.
const AUTO_PRUNE_STAMP: &str = ".last-prune";

/// Set to `off` to disable the periodic automatic prune entirely.
const AUTO_PRUNE_ENV: &str = "CODE2GRAPH_AUTO_PRUNE";

/// Removes unusable caches at most once per [`AUTO_PRUNE_INTERVAL_NS`].
///
/// Called only from `index`, never from a query: indexing is already the
/// expensive, deliberate operation, and it is the one that grows the cache root.
/// When the interval has not elapsed the whole check is a single file read.
///
/// Best-effort throughout — a cache root that cannot be read or stamped leaves
/// indexing unaffected, because pruning is hygiene, not part of the result.
fn auto_prune(context: &ExecutionContext<'_>) {
    if std::env::var(AUTO_PRUNE_ENV).is_ok_and(|value| value.eq_ignore_ascii_case("off")) {
        return;
    }
    let Ok(projects_root) = cache_projects_root(context) else {
        return;
    };
    if !projects_root.is_dir() {
        return;
    }
    let Ok(now) = context.clock.unix_time_ns() else {
        return;
    };
    let stamp = projects_root.join(AUTO_PRUNE_STAMP);
    let last = std::fs::read_to_string(&stamp)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok());
    if last.is_some_and(|last| now.saturating_sub(last) < AUTO_PRUNE_INTERVAL_NS) {
        return;
    }
    // Stamp before pruning: a prune that fails halfway must not make every later
    // command retry the same scan.
    if std::fs::write(&stamp, now.to_string()).is_err() {
        return;
    }
    if let Ok(crate::CacheDetail::Prune {
        removed_orphaned,
        removed_outdated,
        freed_bytes,
        ..
    }) = prune_projects(&projects_root)
        && removed_orphaned + removed_outdated > 0
    {
        eprintln!(
            "[code2graph] pruned {removed_orphaned} orphaned and {removed_outdated} outdated cache(s), freed {freed_bytes} bytes"
        );
    }
}

/// File name of a project cache's SQLite database inside its cache directory.
const CACHE_DATABASE_NAME: &str = "cache.sqlite3";

/// Lists every project-cache directory under the shared cache root.
fn project_directories(projects_root: &std::path::Path) -> Result<Vec<std::path::PathBuf>> {
    if !projects_root.exists() {
        return Ok(Vec::new());
    }
    let entries = std::fs::read_dir(projects_root)
        .map_err(|error| CliError::Cache(format!("failed to read cache root: {error}")))?;
    let mut directories = Vec::new();
    for entry in entries {
        let entry = entry
            .map_err(|error| CliError::Cache(format!("failed to read cache entry: {error}")))?;
        let file_type = entry
            .file_type()
            .map_err(|error| CliError::Cache(format!("failed to inspect cache entry: {error}")))?;
        if file_type.is_dir() {
            directories.push(entry.path());
        }
    }
    directories.sort();
    Ok(directories)
}

/// Reads a cache database's layout version and its unreturned free space.
///
/// Both answer the question "is this cache healthy": a version below the current
/// one means the next command rebuilds it, and a large reclaimable figure means
/// the file is holding pages that `cache compact` gives back.
fn database_health(database: &std::path::Path) -> (Option<i64>, u64) {
    let Ok(connection) =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
    else {
        return (None, 0);
    };
    let version: Option<i64> = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .ok();
    let free: Option<i64> = connection
        .pragma_query_value(None, "freelist_count", |row| row.get(0))
        .ok();
    let page: Option<i64> = connection
        .pragma_query_value(None, "page_size", |row| row.get(0))
        .ok();
    let reclaimable = match (free, page) {
        (Some(free), Some(page)) if free > 0 && page > 0 => u64::try_from(free)
            .unwrap_or(0)
            .saturating_mul(u64::try_from(page).unwrap_or(0)),
        _ => 0,
    };
    (version, reclaimable)
}

/// Rewrites a cache database in place so fragmentation returns to the
/// filesystem. Best-effort: a locked or unreadable cache is skipped, never fatal.
fn compact_database(database: &std::path::Path) -> bool {
    let Ok(connection) = rusqlite::Connection::open(database) else {
        return false;
    };
    connection.execute_batch("VACUUM").is_ok()
}

/// Reports every cached project's footprint and whether it can still be used.
fn survey_projects(projects_root: &std::path::Path) -> Result<crate::CacheDetail> {
    let mut projects = Vec::new();
    let mut total_size: u64 = 0;
    let mut total_reclaimable: u64 = 0;
    for directory in project_directories(projects_root)? {
        let database = directory.join(CACHE_DATABASE_NAME);
        let size_bytes = dir_size(&directory);
        let (schema_version, reclaimable_bytes) = database_health(&database);
        let root = recorded_root(&database);
        let state = match schema_version {
            _ if !database.is_file() => crate::CacheProjectState::Orphaned,
            Some(version) if version < crate::cache::SCHEMA_VERSION => {
                crate::CacheProjectState::Outdated
            }
            Some(version) if version > crate::cache::SCHEMA_VERSION => {
                crate::CacheProjectState::Newer
            }
            Some(_) => match root.as_deref() {
                Some(root) if std::path::Path::new(root).is_dir() => {
                    crate::CacheProjectState::Current
                }
                _ => crate::CacheProjectState::Orphaned,
            },
            None => crate::CacheProjectState::Orphaned,
        };
        total_size = total_size.saturating_add(size_bytes);
        total_reclaimable = total_reclaimable.saturating_add(reclaimable_bytes);
        projects.push(crate::CacheProjectOutput {
            root,
            cache_dir: directory.display().to_string(),
            size_bytes,
            reclaimable_bytes,
            schema_version,
            state,
        });
    }
    // Largest first: the caches worth acting on are the ones at the top.
    projects.sort_by_key(|project| std::cmp::Reverse(project.size_bytes));
    Ok(crate::CacheDetail::StatusAll {
        cache_dir: projects_root.display().to_string(),
        projects,
        total_size_bytes: total_size,
        total_reclaimable_bytes: total_reclaimable,
    })
}

/// The project root a cache was built for, as recorded in its own metadata.
fn recorded_root(database: &std::path::Path) -> Option<String> {
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .ok()?;
    let bytes: Vec<u8> = connection
        .query_row("SELECT canonical_root FROM meta", [], |row| row.get(0))
        .ok()?;
    Some(native_path_from_bytes(&bytes)?.display().to_string())
}

/// Removes every project cache that can no longer serve a query, and reports
/// what it kept.
///
/// Two kinds are unusable. An ORPHANED cache names a project root that no longer
/// exists — a deleted checkout or, most often, a temporary directory — and
/// nothing will ever open it again. An OUTDATED cache was written by an older
/// schema, so the next command on that project discards and rebuilds it anyway.
/// Neither is recoverable state: everything in a cache is derived from source.
///
/// A cache stamped NEWER than this binary is kept untouched; it belongs to a
/// newer build that can still read it.
fn prune_projects(projects_root: &std::path::Path) -> Result<crate::CacheDetail> {
    let mut orphaned: u64 = 0;
    let mut outdated: u64 = 0;
    let mut kept: u64 = 0;
    let mut freed: u64 = 0;
    if !projects_root.exists() {
        return Ok(crate::CacheDetail::Prune {
            removed_orphaned: orphaned,
            removed_outdated: outdated,
            kept_projects: kept,
            freed_bytes: freed,
        });
    }
    let entries = std::fs::read_dir(projects_root)
        .map_err(|error| CliError::Cache(format!("failed to read cache root: {error}")))?;
    for entry in entries {
        let entry = entry
            .map_err(|error| CliError::Cache(format!("failed to read cache entry: {error}")))?;
        let file_type = entry
            .file_type()
            .map_err(|error| CliError::Cache(format!("failed to inspect cache entry: {error}")))?;
        if !file_type.is_dir() {
            continue;
        }
        let path = entry.path();
        let reason = prune_reason(&path);
        let Some(reason) = reason else {
            kept += 1;
            continue;
        };
        freed = freed.saturating_add(dir_size(&path));
        std::fs::remove_dir_all(&path).map_err(|error| {
            CliError::Cache(format!("failed to remove cache directory: {error}"))
        })?;
        match reason {
            PruneReason::Orphaned => orphaned += 1,
            PruneReason::Outdated => outdated += 1,
        }
    }
    Ok(crate::CacheDetail::Prune {
        removed_orphaned: orphaned,
        removed_outdated: outdated,
        kept_projects: kept,
        freed_bytes: freed,
    })
}

/// Inverse of the cache's native path encoding, for reading a recorded root back.
fn native_path_from_bytes(bytes: &[u8]) -> Option<std::path::PathBuf> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Some(std::path::PathBuf::from(std::ffi::OsStr::from_bytes(bytes)))
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        if bytes.len() % 2 != 0 {
            return None;
        }
        let wide: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        Some(std::path::PathBuf::from(std::ffi::OsString::from_wide(
            &wide,
        )))
    }
    #[cfg(not(any(unix, windows)))]
    {
        std::str::from_utf8(bytes)
            .ok()
            .map(std::path::PathBuf::from)
    }
}

enum PruneReason {
    Orphaned,
    Outdated,
}

/// Why one project-cache directory is unusable, or `None` to keep it.
///
/// A directory that cannot be inspected at all — missing database, unreadable
/// metadata — counts as orphaned: nothing can open it, so nothing loses state
/// when it goes.
fn prune_reason(directory: &std::path::Path) -> Option<PruneReason> {
    let database = directory.join("cache.sqlite3");
    if !database.is_file() {
        return Some(PruneReason::Orphaned);
    }
    let Ok(connection) = rusqlite::Connection::open_with_flags(
        &database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    ) else {
        return Some(PruneReason::Orphaned);
    };
    let version: Option<i64> = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .ok();
    match version {
        Some(version) if version < crate::cache::SCHEMA_VERSION => {
            return Some(PruneReason::Outdated);
        }
        None => return Some(PruneReason::Orphaned),
        Some(_) => {}
    }
    let root: Option<Vec<u8>> = connection
        .query_row("SELECT canonical_root FROM meta", [], |row| row.get(0))
        .ok();
    let Some(root) = root else {
        return Some(PruneReason::Orphaned);
    };
    let Some(root) = native_path_from_bytes(&root) else {
        return Some(PruneReason::Orphaned);
    };
    if root.is_dir() {
        None
    } else {
        Some(PruneReason::Orphaned)
    }
}

/// The `<base>/projects` directory shared by every project cache.
fn cache_projects_root(context: &ExecutionContext<'_>) -> Result<std::path::PathBuf> {
    CacheLocation::projects_root(context.cache_base.as_deref())
        .ok_or_else(|| CliError::Cache("no operating-system cache directory is available".into()))
}

/// Removes every immediate project-cache subdirectory of `projects_root`,
/// leaving `projects_root` itself in place. Non-directory and symlink entries
/// are skipped so removal can never escape the cache root.
fn clear_all_projects(projects_root: &std::path::Path) -> Result<(u64, u64)> {
    if !projects_root.exists() {
        return Ok((0, 0));
    }
    let entries = std::fs::read_dir(projects_root)
        .map_err(|error| CliError::Cache(format!("failed to read cache root: {error}")))?;
    let mut removed: u64 = 0;
    let mut freed: u64 = 0;
    for entry in entries {
        let entry = entry
            .map_err(|error| CliError::Cache(format!("failed to read cache entry: {error}")))?;
        let file_type = entry
            .file_type()
            .map_err(|error| CliError::Cache(format!("failed to inspect cache entry: {error}")))?;
        if !file_type.is_dir() {
            continue;
        }
        let path = entry.path();
        freed = freed.saturating_add(dir_size(&path));
        std::fs::remove_dir_all(&path).map_err(|error| {
            CliError::Cache(format!("failed to remove cache directory: {error}"))
        })?;
        removed += 1;
    }
    Ok((removed, freed))
}

/// Total on-disk size of the SQLite database plus its `-wal`/`-shm` sidecars.
fn cache_size_bytes(database_path: &std::path::Path) -> u64 {
    let mut total = file_len(database_path);
    for suffix in ["-wal", "-shm"] {
        let mut name = database_path.as_os_str().to_owned();
        name.push(suffix);
        total = total.saturating_add(file_len(std::path::Path::new(&name)));
    }
    total
}

fn file_len(path: &std::path::Path) -> u64 {
    std::fs::metadata(path)
        .map(|metadata| metadata.len())
        .unwrap_or(0)
}

/// Recursive on-disk size of a directory, following no symlinks.
fn dir_size(path: &std::path::Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(path) else {
        return 0;
    };
    let mut total: u64 = 0;
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            total = total.saturating_add(dir_size(&entry.path()));
        } else if file_type.is_file() {
            total =
                total.saturating_add(entry.metadata().map(|metadata| metadata.len()).unwrap_or(0));
        }
    }
    total
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

fn execute_diff_impact_query(
    request: CliRequest,
    execution: &ExecutionContext<'_>,
    command: DiffImpactCommandRequest,
) -> Result<CommandOutput> {
    execute_query_backend(request, execution, |context| {
        execute_diff_impact(context, command).map(CommandOutput::Impact)
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
                CurrencyCheck::Metadata,
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

/// How strictly a cached source set is checked against the working tree.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CurrencyCheck {
    /// Size and mtime only. Used by read-only commands, which never widen the
    /// guarantee an existing snapshot already carries.
    Metadata,
    /// Size, mtime, and a blake3 comparison of every source's bytes against the
    /// stored content hash. `index` is the explicit correctness command, so its
    /// reuse decision must match the content-hash standard a refresh applies.
    Content,
}

fn cached_sources_are_current(
    store: &CacheStore,
    metadata: &ActiveSnapshotMetadata,
    request: &CliRequest,
    selection: &crate::ProjectSelection,
    check_depth: CurrencyCheck,
    deadline: &Deadline,
    cancellation: &dyn crate::Cancellation,
) -> Result<bool> {
    let mut discovery = discover_sources_checked(
        selection,
        &request.global.limits,
        request.global.include_hidden,
        deadline,
        cancellation,
    )?;
    apply_metadata_budgets(&mut discovery, &request.global.limits);
    // A snapshot stays reusable only while the inputs that define cache
    // compatibility still hash the same. Source bytes are checked below; the
    // enabled language set and the package manifests are not sources at all, so
    // a snapshot built under a different manifest must never be served as a hit.
    let packages = assign_packages_checked(
        &selection.canonical_root,
        &discovery.candidates,
        request.global.limits.max_file_bytes,
        deadline,
        cancellation,
    )?;
    let language_fingerprint = LanguageFeatureFingerprint::current();
    let package_fingerprint = PackageFingerprint::from_selection(
        packages.manifest_fingerprint_records(),
        packages.assignment_fingerprint_records(),
    );
    if metadata.compatibility.id
        != CompatibilityFingerprint::new(language_fingerprint, package_fingerprint)
    {
        return Ok(false);
    }
    // A discovery-level omission that shrinks the source set (a metadata budget
    // or an oversized file) matters only when it DIFFERS from the one the
    // snapshot recorded. Treating any such omission as a refresh trigger means
    // a project holding one oversized vendored file can never reuse its cache:
    // every query and index re-extracts the whole tree.
    let current_omissions: Vec<_> = discovery
        .omitted
        .iter()
        .filter(|omission| omission.impact == OmissionImpact::IncompleteSourceSet)
        .map(cache_omission)
        .collect();
    // The reverse direction — a recorded omission that no longer applies —
    // needs no check here: the file reappears as a discovered source and the
    // inventory count below stops balancing.
    if current_omissions
        .iter()
        .any(|omission| !metadata.omissions.contains(omission))
    {
        return Ok(false);
    }
    // A PARTIAL snapshot (some files failed extraction — normal for any real
    // codebase with an unparseable file) is still a valid cache: those files
    // contribute no facts, so the graph is unchanged as long as the SOURCE SET
    // is unchanged. Serve it from cache instead of re-indexing on every query.
    // The expected source set is the successfully-cached files plus the recorded
    // extraction omissions; a mismatch (added/removed source) forces a refresh.
    let cached = store.candidate_file_metadata(metadata.candidate_id, deadline)?;
    let omission_paths: std::collections::HashSet<&str> = metadata
        .omissions
        .iter()
        .map(|omission| omission.path.as_str())
        .collect();
    // Only language-bearing candidates are real sources: discovery also lists
    // files it recognises but has no extractor for (`language == None`), which the
    // index neither extracts nor records as omissions. Comparing against those
    // would wrongly report every query as stale. The accounted set is therefore
    // the successfully-cached files plus the recorded extraction omissions.
    let sources: Vec<_> = discovery
        .candidates
        .iter()
        .filter(|candidate| candidate.language.is_some())
        .collect();
    // Only EXTRACTION omissions belong in this count. A discovery-level
    // omission (oversized file, metadata budget) never became a candidate, so
    // it is absent from `sources`; adding it here made the totals disagree by
    // exactly the number of such files, and any project holding one could never
    // reuse its cache. Extraction omissions are the recorded ones that discovery
    // still lists as sources.
    let source_paths: std::collections::HashSet<&str> = sources
        .iter()
        .map(|candidate| candidate.path.as_str())
        .collect();
    let extraction_omissions = omission_paths
        .iter()
        .filter(|path| source_paths.contains(*path))
        .count();
    if sources.len() as u64 != metadata.inventory_file_count + extraction_omissions as u64 {
        return Ok(false);
    }
    let cached_by_path: std::collections::HashMap<&str, _> = cached
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect();
    // Content verification reads the stored hashes once; a metadata-only check
    // never touches them, so read-only commands keep their single-query cost.
    let content_hashes = match check_depth {
        CurrencyCheck::Metadata => None,
        CurrencyCheck::Content => {
            Some(store.candidate_file_hashes(metadata.candidate_id, deadline)?)
        }
    };
    for candidate in sources {
        match cached_by_path.get(candidate.path.as_str()) {
            // A successfully-extracted file: it must be byte-for-byte unchanged.
            Some(cached) => {
                let unchanged = candidate
                    .language
                    .is_some_and(|language| language.as_str() == cached.language)
                    && candidate.size_bytes == cached.size_bytes
                    && candidate.mtime == cached.mtime;
                if !unchanged {
                    return Ok(false);
                }
                if let Some(hashes) = content_hashes.as_ref() {
                    deadline.check(cancellation)?;
                    let Some(expected) = hashes.get(candidate.path.as_str()) else {
                        return Ok(false);
                    };
                    let MaterializedCandidate::File(file) = materialize_candidate_checked(
                        candidate,
                        &request.global.limits,
                        deadline,
                        cancellation,
                    )?
                    else {
                        return Ok(false);
                    };
                    if blake3::hash(&file.bytes).as_bytes() != expected {
                        return Ok(false);
                    }
                }
            }
            // A file that failed extraction last time: its bytes are not tracked
            // (it contributed no facts), so accept it as still-omitted. An
            // explicit `index` re-checks whether it has since become parseable.
            None if omission_paths.contains(candidate.path.as_str()) => {}
            // A source the cache has never seen → refresh.
            None => return Ok(false),
        }
    }
    Ok(true)
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
        let snapshot: LoadedSnapshot = prepared.snapshot.clone().into();
        return Ok(CommandOutput::Index(index_envelope(
            &selection,
            &snapshot,
            &prepared,
            request.global.tier,
            CacheDisposition::Disabled,
            None,
        )));
    }

    let location = cache_location(context, &selection)?;
    let store = CacheStore::open_writable(&location, &selection.canonical_root, &deadline)?;
    // Placed before the reuse check so it covers both index paths: a project
    // whose sources never change would otherwise never sweep the cache root.
    auto_prune(context);
    let tier = ResolverCacheTier::from(request.global.tier);
    // An unchanged source set already has a published graph for this tier.
    // Re-resolving it rebuilds every cross-file edge to reproduce the snapshot
    // byte-for-byte, so reuse it instead. `--force` still refreshes, and
    // `--trust-mtime` relaxes the check to the same size/mtime standard it
    // relaxes extraction to.
    if !*force
        && let Some(metadata) =
            active_metadata(&store, tier, request.global.allow_partial, &deadline)?
        && cached_sources_are_current(
            &store,
            &metadata,
            &request,
            &selection,
            if *trust_mtime {
                CurrencyCheck::Metadata
            } else {
                CurrencyCheck::Content
            },
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
        return Ok(CommandOutput::Index(unchanged_index_envelope(
            &selection,
            &loaded.snapshot,
            request.global.tier,
            store.recovery_diagnostic(),
        )));
    }
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
        store.recovery_diagnostic(),
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
            prepared.snapshot.into(),
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
            CurrencyCheck::Metadata,
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
            prepared.snapshot.into(),
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
        )
        .map(|mut graph| {
            graph.project.cache_recovery = store.recovery_diagnostic();
            graph
        }),
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

fn index_envelope(
    selection: &crate::ProjectSelection,
    snapshot: &LoadedSnapshot,
    prepared: &PreparedRefreshCandidate,
    tier: crate::ResolverTier,
    cache: CacheDisposition,
    cache_recovery: Option<String>,
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
    let mut project = project_output(selection, snapshot, tier, Freshness::Fresh, cache);
    project.cache_recovery = cache_recovery;
    envelope.project = Some(project);
    envelope
}

/// Envelope for an `index` that reused an already-current snapshot. Every
/// refresh counter is zero because no file was hashed, extracted, or removed.
fn unchanged_index_envelope(
    selection: &crate::ProjectSelection,
    snapshot: &LoadedSnapshot,
    tier: crate::ResolverTier,
    cache_recovery: Option<String>,
) -> OutputEnvelope<IndexOutput> {
    let mut envelope = OutputEnvelope::new(
        success_status(snapshot.completeness, Freshness::Fresh),
        IndexOutput::from_loaded_snapshot(
            snapshot,
            tier,
            0,
            0,
            0,
            0,
            PlanDecisionCountsOutput::default(),
        ),
    );
    let mut project = project_output(
        selection,
        snapshot,
        tier,
        Freshness::Fresh,
        CacheDisposition::Hit,
    );
    project.cache_recovery = cache_recovery;
    envelope.project = Some(project);
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
    let (omissions, omissions_truncated) = crate::result::capped_omissions(&snapshot.omissions);
    ProjectOutput {
        root: selection.canonical_root.to_string_lossy().into_owned(),
        snapshot: snapshot.candidate_id.to_string(),
        tier,
        freshness,
        cache,
        completeness: snapshot.completeness.into(),
        omitted_files: snapshot.omissions.len(),
        omissions,
        omissions_truncated,
        // Only the paths that actually refreshed against a store can observe a
        // recovery; they fill this in from the store afterwards.
        cache_recovery: None,
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

    /// A cache whose stored facts stop satisfying their validation contract —
    /// what an upgrade that tightens or widens that contract produces — is
    /// silently discarded and rebuilt, which is otherwise indistinguishable from
    /// a cold cache. The rule that rejected it has to reach the operator.
    #[test]
    fn a_silently_discarded_cache_reports_why_in_the_index_output() {
        let (_temp, root, cache) = fixture();
        let cancellation = NeverCancelled;
        let clock = CountingClock(AtomicUsize::new(0));
        let context = context(&root, &cache, &cancellation, &clock);
        let deadline = Deadline::new(None);
        let canonical = fs::canonicalize(&root).expect("canonical root");
        let location =
            crate::cache::CacheLocation::for_project(Some(&cache), &canonical).expect("location");
        // The name tier keeps the seeded candidate free of per-file subgraphs;
        // the cache-recovery path under test is the same for every tier.
        let store = CacheStore::open_writable(&location, &canonical, &deadline).expect("store");
        store
            .publish_candidate(
                &crate::cache::single_file_candidate("src/a.rs", ResolverCacheTier::Name),
                &deadline,
            )
            .expect("seed a cache to invalidate");
        drop(store);

        // Rewrite the cached facts so they claim a different file. The blob
        // stays structurally valid, so only the context contract rejects it —
        // exactly how a contract change invalidates a previously good cache.
        let foreign = code2graph::FileFacts {
            file: "somewhere-else.rs".into(),
            lang: "rust".into(),
            symbols: Vec::new(),
            references: Vec::new(),
            scopes: Vec::new(),
            bindings: Vec::new(),
            ffi_exports: Vec::new(),
        };
        let blob = crate::cache::encode_file_facts(&foreign).expect("encode");
        let rewritten = rusqlite::Connection::open(&location.database_path)
            .expect("sqlite")
            .execute(
                "UPDATE candidate_files SET file_facts = ?1",
                rusqlite::params![blob],
            )
            .expect("rewrite cached facts");
        assert_eq!(rewritten, 1, "the seeded cache holds exactly one file");

        let mut request = index_request(false);
        request.global.tier = ResolverTier::Name;
        let CommandOutput::Index(output) = execute(request, &context).expect("index") else {
            panic!("index returned another command output");
        };
        let detail = output
            .project
            .expect("project")
            .cache_recovery
            .expect("a discarded cache must report why");
        assert!(
            detail.contains("somewhere-else.rs"),
            "the diagnostic must name the rejected facts, got {detail}"
        );
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

    /// Counts project-cache directories, ignoring the auto-prune stamp file.
    fn cache_dir_count(projects_root: &std::path::Path) -> usize {
        fs::read_dir(projects_root)
            .expect("projects")
            .filter(|entry| {
                entry
                    .as_ref()
                    .expect("entry")
                    .file_type()
                    .expect("file type")
                    .is_dir()
            })
            .count()
    }

    fn partial_index_request() -> CliRequest {
        let mut request = index_request(false);
        request.global.allow_partial = true;
        request
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
        // Two indexes and one query take a timestamp each; the two indexes also
        // consult the clock to decide whether the cache root is due a prune.
        assert_eq!(clock.0.load(Ordering::SeqCst), 5);
    }

    #[test]
    fn index_reuses_an_unchanged_snapshot_and_refreshes_after_an_edit() {
        let (_temp, root, cache) = fixture();
        let cancellation = NeverCancelled;
        let clock = FixedClock;
        let context = context(&root, &cache, &cancellation, &clock);
        fs::create_dir_all(root.join("src")).expect("src");
        fs::write(root.join("src/a.rs"), "pub fn helper() {}\n").expect("source");

        let CommandOutput::Index(first) =
            execute(partial_index_request(), &context).expect("first index")
        else {
            panic!("index output")
        };
        assert_eq!(
            first.project.expect("project").cache,
            CacheDisposition::Miss
        );

        // Nothing moved: the published graph is reused verbatim, so no file is
        // hashed for extraction, extracted, or removed, and no refresh attempt runs.
        let CommandOutput::Index(reused) =
            execute(partial_index_request(), &context).expect("reusing index")
        else {
            panic!("index output")
        };
        assert_eq!(
            reused.project.expect("project").cache,
            CacheDisposition::Hit
        );
        assert_eq!(reused.results.changed, 0);
        assert_eq!(reused.results.deleted, 0);
        assert_eq!(reused.results.attempts, 0);
        assert_eq!(
            reused.results.plan_decisions,
            PlanDecisionCountsOutput::default()
        );
        assert_eq!(reused.results.snapshot, first.results.snapshot);

        // A source set that moved must still refresh into a different snapshot.
        fs::write(root.join("src/b.rs"), "pub fn added() {}\n").expect("added source");
        let CommandOutput::Index(refreshed) =
            execute(partial_index_request(), &context).expect("refresh after a new source")
        else {
            panic!("index output")
        };
        assert_ne!(refreshed.results.snapshot, first.results.snapshot);
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

    fn cache_request(op: CacheOp) -> CliRequest {
        CliRequest {
            global: GlobalOptions::default(),
            command: CommandRequest::Cache { op },
        }
    }

    #[test]
    fn cache_path_reports_location_before_any_index() {
        let (_temp, root, cache) = fixture();
        let cancellation = NeverCancelled;
        let clock = FixedClock;
        let context = context(&root, &cache, &cancellation, &clock);
        let CommandOutput::Cache(report) =
            execute(cache_request(CacheOp::Path), &context).expect("cache path")
        else {
            panic!("cache output")
        };
        let crate::CacheDetail::Path {
            cache_dir,
            database_path,
            exists,
        } = report.detail
        else {
            panic!("path detail")
        };
        assert!(!exists);
        assert!(database_path.ends_with("cache.sqlite3"));
        assert!(cache_dir.starts_with(cache.to_str().expect("utf-8 cache path")));
    }

    #[test]
    fn cache_status_after_index_reports_size_and_snapshot_counts() {
        let (_temp, root, cache) = fixture();
        fs::write(
            root.join("a.rs"),
            "pub fn target() {}\npub fn caller() { target(); }\n",
        )
        .expect("source");
        let cancellation = NeverCancelled;
        let clock = FixedClock;
        let context = context(&root, &cache, &cancellation, &clock);
        // The unit-test harness does not run the extraction worker, so a project
        // with real sources indexes to a partial snapshot; allow it. This test
        // covers the cache-status plumbing (size + snapshot rows), not extraction
        // content — real symbol/edge counts are exercised end-to-end.
        let mut index = index_request(false);
        index.global.allow_partial = true;
        execute(index, &context).expect("index");

        let CommandOutput::Cache(report) =
            execute(cache_request(CacheOp::Status { all: false }), &context).expect("cache status")
        else {
            panic!("cache output")
        };
        let crate::CacheDetail::Status {
            exists,
            size_bytes,
            snapshots,
            ..
        } = report.detail
        else {
            panic!("status detail")
        };
        assert!(exists);
        assert!(size_bytes > 0);
        assert!(
            snapshots
                .iter()
                .any(|snapshot| snapshot.active && snapshot.tier == "scope"),
            "expected an active scope snapshot, got {snapshots:?}"
        );
    }

    #[test]
    fn cache_clear_removes_the_project_cache_and_reports_freed_bytes() {
        let (_temp, root, cache) = fixture();
        fs::write(root.join("a.rs"), "pub fn run() {}\n").expect("source");
        let cancellation = NeverCancelled;
        let clock = FixedClock;
        let context = context(&root, &cache, &cancellation, &clock);
        let mut index = index_request(false);
        index.global.allow_partial = true;
        execute(index, &context).expect("index");

        let CommandOutput::Cache(report) =
            execute(cache_request(CacheOp::Clear { all: false }), &context).expect("cache clear")
        else {
            panic!("cache output")
        };
        let crate::CacheDetail::Clear {
            scope,
            removed_projects,
            freed_bytes,
        } = report.detail
        else {
            panic!("clear detail")
        };
        assert_eq!(scope, crate::CacheClearScope::Project);
        assert_eq!(removed_projects, 1);
        assert!(freed_bytes > 0);

        let CommandOutput::Cache(after) =
            execute(cache_request(CacheOp::Path), &context).expect("cache path")
        else {
            panic!("cache output")
        };
        let crate::CacheDetail::Path { exists, .. } = after.detail else {
            panic!("path detail")
        };
        assert!(!exists);
    }

    #[test]
    fn cache_rebuild_discards_the_database_and_indexes_again() {
        let (_temp, root, cache) = fixture();
        let cancellation = NeverCancelled;
        let clock = FixedClock;
        let context = context(&root, &cache, &cancellation, &clock);
        fs::create_dir_all(root.join("src")).expect("src");
        fs::write(root.join("src/a.rs"), "pub fn run() {}\n").expect("source");
        let CommandOutput::Index(first) =
            execute(partial_index_request(), &context).expect("index")
        else {
            panic!("index output")
        };

        let mut rebuild = cache_request(CacheOp::Rebuild);
        rebuild.global.allow_partial = true;
        let CommandOutput::Cache(report) = execute(rebuild, &context).expect("rebuild") else {
            panic!("cache output")
        };
        let crate::CacheDetail::Rebuild {
            discarded_bytes,
            indexed_files,
            size_bytes,
        } = report.detail
        else {
            panic!("rebuild detail")
        };
        assert!(discarded_bytes > 0, "an existing cache was discarded");
        // The rebuild indexes the same source set the discarded cache held.
        assert_eq!(indexed_files, first.results.inventory_file_count);
        assert!(size_bytes > 0, "a fresh cache was written");
    }

    #[test]
    fn indexing_prunes_dead_caches_at_most_once_per_interval() {
        // A clock well past one interval, so the stamp can be aged backwards.
        struct LateClock;
        impl Clock for LateClock {
            fn unix_time_ns(&self) -> Result<u64> {
                Ok(AUTO_PRUNE_INTERVAL_NS * 3)
            }
        }

        let temp = tempdir().expect("fixture");
        let cache = temp.path().join("cache");
        let cancellation = NeverCancelled;
        let clock = LateClock;
        for name in ["live", "deleted"] {
            let root = temp.path().join(name);
            fs::create_dir(&root).expect("project");
            fs::write(root.join("a.rs"), "pub fn run() {}\n").expect("source");
            let context = context(&root, &cache, &cancellation, &clock);
            execute(partial_index_request(), &context).expect("index");
        }
        let projects_root = cache.join("projects");
        let caches = || cache_dir_count(&projects_root);
        assert_eq!(caches(), 2);
        // The first index of a fresh cache root already stamps it, so age the
        // stamp whenever the next index is expected to sweep.
        let age_stamp = || {
            fs::write(projects_root.join(AUTO_PRUNE_STAMP), "0").expect("age the stamp");
        };
        assert!(projects_root.join(AUTO_PRUNE_STAMP).is_file());
        fs::remove_dir_all(temp.path().join("deleted")).expect("remove project");

        // Indexing the surviving project sweeps the dead cache away.
        let live = context(&temp.path().join("live"), &cache, &cancellation, &clock);
        age_stamp();
        execute(partial_index_request(), &live).expect("index after deletion");
        assert_eq!(caches(), 1);

        // A second dead cache inside the same interval is left alone: the check
        // is a stamp read, not a scan.
        let other = temp.path().join("other");
        fs::create_dir(&other).expect("project");
        fs::write(other.join("a.rs"), "pub fn run() {}\n").expect("source");
        let context = context(&other, &cache, &cancellation, &clock);
        execute(partial_index_request(), &context).expect("index other");
        fs::remove_dir_all(&other).expect("remove other");
        execute(partial_index_request(), &live).expect("index within interval");
        assert_eq!(caches(), 2);

        // Once the interval has elapsed, the next index sweeps again.
        age_stamp();
        execute(partial_index_request(), &live).expect("index after interval");
        assert_eq!(caches(), 1);
    }

    #[test]
    fn cache_prune_removes_orphaned_and_outdated_caches_and_keeps_the_rest() {
        let temp = tempdir().expect("fixture");
        let cache = temp.path().join("cache");
        let cancellation = NeverCancelled;
        let clock = FixedClock;
        for name in ["live", "deleted", "stale"] {
            let root = temp.path().join(name);
            fs::create_dir(&root).expect("project");
            fs::write(root.join("a.rs"), "pub fn run() {}\n").expect("source");
            let context = context(&root, &cache, &cancellation, &clock);
            let mut index = index_request(false);
            index.global.allow_partial = true;
            execute(index, &context).expect("index");
        }
        let projects_root = cache.join("projects");
        assert_eq!(cache_dir_count(&projects_root), 3);

        // One project root disappears; one cache is left on an older schema.
        fs::remove_dir_all(temp.path().join("deleted")).expect("remove project");
        let stale_root =
            fs::canonicalize(temp.path().join(".").join("stale")).expect("canonical stale project");
        let stale_key =
            crate::cache::CacheLocation::for_project(Some(cache.as_path()), &stale_root)
                .expect("stale location");
        let connection =
            rusqlite::Connection::open(&stale_key.database_path).expect("open stale cache");
        connection
            .pragma_update(None, "user_version", crate::cache::SCHEMA_VERSION - 1)
            .expect("downgrade");
        drop(connection);

        let context = context(&temp.path().join("live"), &cache, &cancellation, &clock);
        let CommandOutput::Cache(report) =
            execute(cache_request(CacheOp::Prune), &context).expect("prune")
        else {
            panic!("cache output")
        };
        let crate::CacheDetail::Prune {
            removed_orphaned,
            removed_outdated,
            kept_projects,
            freed_bytes,
        } = report.detail
        else {
            panic!("prune detail")
        };
        assert_eq!(removed_orphaned, 1);
        assert_eq!(removed_outdated, 1);
        assert_eq!(kept_projects, 1);
        assert!(freed_bytes > 0);
        assert_eq!(cache_dir_count(&projects_root), 1);
    }

    #[test]
    fn cache_clear_all_removes_every_project_cache_under_the_injected_base() {
        let temp = tempdir().expect("fixture");
        let cache = temp.path().join("cache");
        let cancellation = NeverCancelled;
        let clock = FixedClock;
        for name in ["alpha", "beta"] {
            let root = temp.path().join(name);
            fs::create_dir(&root).expect("project");
            fs::write(root.join("a.rs"), "pub fn run() {}\n").expect("source");
            let context = context(&root, &cache, &cancellation, &clock);
            let mut index = index_request(false);
            index.global.allow_partial = true;
            execute(index, &context).expect("index");
        }
        let projects_root = cache.join("projects");
        assert_eq!(cache_dir_count(&projects_root), 2);

        // `clear --all` never selects a project, so a missing root is irrelevant.
        let missing = temp.path().join("no-project");
        let context = context(&missing, &cache, &cancellation, &clock);
        let CommandOutput::Cache(report) =
            execute(cache_request(CacheOp::Clear { all: true }), &context).expect("clear all")
        else {
            panic!("cache output")
        };
        let crate::CacheDetail::Clear {
            scope,
            removed_projects,
            freed_bytes,
        } = report.detail
        else {
            panic!("clear detail")
        };
        assert_eq!(scope, crate::CacheClearScope::All);
        assert_eq!(removed_projects, 2);
        assert!(freed_bytes > 0);
        assert_eq!(cache_dir_count(&projects_root), 0);
        assert!(projects_root.exists());
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
