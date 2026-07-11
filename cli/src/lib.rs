// SPDX-License-Identifier: Apache-2.0

//! Public contracts and argument parsing for the `code2graph` CLI.

pub mod args;
pub mod cache;
pub mod config;
pub mod deadline;
pub mod error;
pub mod execution;
pub mod exit;
pub mod inventory;
pub mod package_assignment;
pub mod project;
pub mod refresh;
pub mod request;
pub mod result;
pub mod selector;
pub mod worker;

pub use args::{ParseOutcome, parse_from};
pub use config::{
    DEFAULT_IMPACT_DEPTH, DEFAULT_LIMIT, DEFAULT_MAX_DEPTH, DEFAULT_MAX_FILE_BYTES,
    DEFAULT_MAX_FILES, DEFAULT_MAX_TOTAL_BYTES, GlobalOptions, ResolverTier, ResourceLimits,
};
pub use deadline::{Cancellation, Deadline, NeverCancelled};
pub use error::{CliError, Result};
pub use execution::{
    Clock, CommandOutput, ExecutionContext, LoadedGraph, SystemClock, execute, load_query_graph,
    render_human,
};
pub use exit::ExitCode;
pub use inventory::{
    FileClassification, InventoryCompleteness, InventoryFile, InventorySummary,
    MaterializedCandidate, MtimeHint, OmissionImpact, OmissionReason, OmittedFile, SourceCandidate,
    SourceDiscovery, SourceInventory, StableIdentity, StableIoErrorKind, build_inventory,
    discover_sources, discover_sources_checked, materialize_candidate,
    materialize_candidate_checked,
};
pub use package_assignment::{
    ManifestInput, ManifestOutcome, ManifestParserKind, PackageAssignmentSet, PackageDiagnostic,
    PackageDiagnosticKind, PackageSourcePath, SourcePackageAssignment, assign_packages,
    assign_packages_checked,
};
pub use project::{ProjectPath, ProjectSelection, SelectionProvenance, select_project};
pub use refresh::{
    ExtractionError, FactsExtractor, MAX_REFRESH_ATTEMPTS, PrepareCandidateInputs,
    PreparedRefreshCandidate, PriorFileRecord, PriorScopeState, ProcessFactsExtractor,
    RefreshDecision, RefreshEntry, RefreshInputs, RefreshPlan, ResolveCandidateInputs,
    ResolvedCandidate, prepare_refresh_candidate, prepare_refresh_candidate_with,
    resolve_candidate,
};
pub use request::{CliRequest, CommandRequest, Selector, SourcePosition};
pub use result::{
    CacheCompletenessOutput, CacheDisposition, CacheOmissionOutput, ConfidenceOutput,
    ErrorEnvelope, Freshness, ImpactOutput, IndexOutput, InventoryCompletenessOutput,
    InventoryOmissionReasonOutput, InventoryReasonCountOutput, InventorySummaryOutput,
    ModuleDependencyOutput, ModuleDependencyTargetOutput, OUTPUT_SCHEMA_VERSION, OccurrenceOutput,
    OutputEnvelope, OutputStatus, PlanDecisionCountsOutput, ProjectOutput, ProvenanceOutput,
    RefRoleOutput, ReferenceOutput, RelationOutput, SelectorOutput, StableIoErrorOutput,
    StatusOutput, SymbolKindOutput, SymbolOutput, TypeRefContextOutput, success_exit_code,
    success_status,
};
pub use selector::{
    SelectorContext, SelectorOptions, SelectorPurpose, SelectorRequest, SelectorResolution,
    SelectorSummary, build_graph_index, resolve_selector,
};
pub use worker::{
    WORKER_SENTINEL, WorkerFailure, extract_inventory_file, is_worker_invocation, run_worker,
};
