// SPDX-License-Identifier: Apache-2.0

//! Public contracts and argument parsing for the `code2graph` CLI.

pub mod args;
pub mod config;
pub mod deadline;
pub mod error;
pub mod exit;
pub mod inventory;
pub mod project;
pub mod request;
pub mod result;
pub mod worker;

pub use args::{ParseOutcome, parse_from};
pub use config::{
    DEFAULT_IMPACT_DEPTH, DEFAULT_LIMIT, DEFAULT_MAX_DEPTH, DEFAULT_MAX_FILE_BYTES,
    DEFAULT_MAX_FILES, DEFAULT_MAX_TOTAL_BYTES, GlobalOptions, ResolverTier, ResourceLimits,
};
pub use deadline::{Cancellation, Deadline, NeverCancelled};
pub use error::{CliError, Result};
pub use exit::ExitCode;
pub use inventory::{
    FileClassification, InventoryCompleteness, InventoryFile, InventorySummary, MtimeHint,
    OmissionReason, OmittedFile, SourceInventory, StableIoErrorKind, build_inventory,
};
pub use project::{ProjectPath, ProjectSelection, SelectionProvenance, select_project};
pub use request::{CliRequest, CommandRequest, Selector, SourcePosition};
pub use result::{
    CacheDisposition, ConfidenceOutput, ErrorEnvelope, Freshness, ImpactOutput,
    InventoryCompletenessOutput, InventoryOmissionReasonOutput, InventoryReasonCountOutput,
    InventorySummaryOutput, ModuleDependencyOutput, ModuleDependencyTargetOutput,
    OUTPUT_SCHEMA_VERSION, OccurrenceOutput, OutputEnvelope, OutputStatus, ProjectOutput,
    ProvenanceOutput, RefRoleOutput, ReferenceOutput, RelationOutput, SelectorOutput,
    StableIoErrorOutput, StatusOutput, SymbolKindOutput, SymbolOutput, TypeRefContextOutput,
};
pub use worker::{
    WORKER_SENTINEL, WorkerFailure, extract_inventory_file, is_worker_invocation, run_worker,
};
