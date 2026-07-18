// SPDX-License-Identifier: Apache-2.0

use code2graph::{Confidence, Provenance, RefRole, SymbolId, SymbolKind, TypeRefContext};
use serde::{Deserialize, Serialize};

use crate::cache::{CacheCompleteness, CacheOmission, LoadedSnapshot};
use crate::config::{ResolverTier, ResourceLimits};
use crate::exit::ExitCode;
use crate::inventory::{
    InventoryCompleteness, InventorySummary, OmissionReason, StableIoErrorKind,
};

/// The first version of the stable JSON output envelope.
pub const OUTPUT_SCHEMA_VERSION: u32 = 1;

/// Stable machine-visible command status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutputStatus {
    Ok,
    NoMatch,
    Ambiguous,
    Partial,
    Stale,
    Unsupported,
    Timeout,
    Error,
}

/// Freshness of the selected snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Freshness {
    Fresh,
    Frozen,
    Stale,
}

/// Stable cache snapshot completeness spelling in index and cached-status output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CacheCompletenessOutput {
    Complete,
    Partial,
}

impl From<CacheCompleteness> for CacheCompletenessOutput {
    fn from(value: CacheCompleteness) -> Self {
        match value {
            CacheCompleteness::Complete => Self::Complete,
            CacheCompleteness::Partial => Self::Partial,
        }
    }
}

/// Maps successful snapshot states to their machine-visible status. Stale wins
/// over completeness because it describes the authoritative freshness caveat.
pub const fn success_status(completeness: CacheCompleteness, freshness: Freshness) -> OutputStatus {
    match (completeness, freshness) {
        (_, Freshness::Stale) => OutputStatus::Stale,
        (CacheCompleteness::Partial, _) => OutputStatus::Partial,
        (CacheCompleteness::Complete, Freshness::Fresh | Freshness::Frozen) => OutputStatus::Ok,
    }
}

/// All successful index/query states, including partial and stale results, use
/// the stable success exit code.
pub const fn success_exit_code(
    _completeness: CacheCompleteness,
    _freshness: Freshness,
) -> ExitCode {
    ExitCode::Success
}

/// Cache participation for this invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CacheDisposition {
    Hit,
    Miss,
    Disabled,
}

/// Project metadata carried by successful machine envelopes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectOutput {
    pub root: String,
    pub snapshot: String,
    pub tier: ResolverTier,
    pub freshness: Freshness,
    pub cache: CacheDisposition,
    pub completeness: CacheCompletenessOutput,
    #[serde(rename = "omittedFiles")]
    pub omitted_files: usize,
    pub omissions: Vec<CacheOmissionOutput>,
}

/// Stable kebab-case spelling of [`SymbolKind`] in CLI output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SymbolKindOutput {
    Function,
    Method,
    Struct,
    Enum,
    Trait,
    Interface,
    Class,
    TypeAlias,
    Const,
    Static,
    Module,
    Impl,
    Table,
    View,
    Column,
    Resource,
    Other,
}

impl From<SymbolKind> for SymbolKindOutput {
    fn from(kind: SymbolKind) -> Self {
        match kind {
            SymbolKind::Function => Self::Function,
            SymbolKind::Method => Self::Method,
            SymbolKind::Struct => Self::Struct,
            SymbolKind::Enum => Self::Enum,
            SymbolKind::Trait => Self::Trait,
            SymbolKind::Interface => Self::Interface,
            SymbolKind::Class => Self::Class,
            SymbolKind::TypeAlias => Self::TypeAlias,
            SymbolKind::Const => Self::Const,
            SymbolKind::Static => Self::Static,
            SymbolKind::Module => Self::Module,
            SymbolKind::Impl => Self::Impl,
            SymbolKind::Table => Self::Table,
            SymbolKind::View => Self::View,
            SymbolKind::Column => Self::Column,
            SymbolKind::Resource => Self::Resource,
            SymbolKind::Other => Self::Other,
        }
    }
}

/// Stable kebab-case spelling of [`RefRole`] in CLI output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RefRoleOutput {
    Call,
    IsImplementation,
    Import,
    ModuleRef,
    TypeRef,
    Read,
    Write,
}

impl From<RefRole> for RefRoleOutput {
    fn from(role: RefRole) -> Self {
        match role {
            RefRole::Call => Self::Call,
            RefRole::IsImplementation => Self::IsImplementation,
            RefRole::Import => Self::Import,
            RefRole::ModuleRef => Self::ModuleRef,
            RefRole::TypeRef => Self::TypeRef,
            RefRole::Read => Self::Read,
            RefRole::Write => Self::Write,
        }
    }
}

/// Stable kebab-case confidence spelling in CLI output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfidenceOutput {
    Heuristic,
    NameOnly,
    Scoped,
    Exact,
}

impl From<Confidence> for ConfidenceOutput {
    fn from(confidence: Confidence) -> Self {
        match confidence {
            Confidence::Heuristic => Self::Heuristic,
            Confidence::NameOnly => Self::NameOnly,
            Confidence::Scoped => Self::Scoped,
            Confidence::Exact => Self::Exact,
        }
    }
}

/// Stable kebab-case provenance spelling in CLI output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProvenanceOutput {
    SymbolTable,
    ScopeGraph,
    FfiBridge,
    Conformance,
    LocalType,
    NormalizedName,
    External,
    CrossArtifact,
}

impl From<Provenance> for ProvenanceOutput {
    fn from(provenance: Provenance) -> Self {
        match provenance {
            Provenance::SymbolTable => Self::SymbolTable,
            Provenance::ScopeGraph => Self::ScopeGraph,
            Provenance::FfiBridge => Self::FfiBridge,
            Provenance::Conformance => Self::Conformance,
            Provenance::LocalType => Self::LocalType,
            Provenance::NormalizedName => Self::NormalizedName,
            Provenance::External => Self::External,
            Provenance::CrossArtifact => Self::CrossArtifact,
        }
    }
}

/// Stable kebab-case type-reference context spelling in raw-reference output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TypeRefContextOutput {
    ParameterType,
    ReturnType,
    Field,
    GenericArg,
    Attribute,
    Other,
}

impl From<TypeRefContext> for TypeRefContextOutput {
    fn from(context: TypeRefContext) -> Self {
        match context {
            TypeRefContext::ParameterType => Self::ParameterType,
            TypeRefContext::ReturnType => Self::ReturnType,
            TypeRefContext::Field => Self::Field,
            TypeRefContext::GenericArg => Self::GenericArg,
            TypeRefContext::Attribute => Self::Attribute,
            TypeRefContext::Other => Self::Other,
        }
    }
}

/// Owned definition data. `id` is always the lossless wire identity;
/// `id_display` is only a human/interoperability convenience.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolOutput {
    pub id: SymbolId,
    #[serde(rename = "idDisplay")]
    pub id_display: String,
    pub name: String,
    pub kind: SymbolKindOutput,
    pub file: String,
    pub line: u32,
    pub signature: String,
}

impl From<&code2graph::Symbol> for SymbolOutput {
    fn from(symbol: &code2graph::Symbol) -> Self {
        Self {
            id: symbol.id.clone(),
            id_display: symbol.id.to_scip_string(),
            name: symbol.name.clone(),
            kind: symbol.kind.into(),
            file: symbol.file.clone(),
            line: symbol.line,
            signature: symbol.signature.clone(),
        }
    }
}

/// A source occurrence. Lines are 1-based and columns are 0-based, matching
/// the core graph schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OccurrenceOutput {
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub byte: usize,
}

/// One resolved graph relation. Endpoint identities are always lossless.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelationOutput {
    pub from: SymbolId,
    pub to: SymbolId,
    pub role: RefRoleOutput,
    pub confidence: ConfidenceOutput,
    pub provenance: ProvenanceOutput,
    pub occurrence: OccurrenceOutput,
}

/// One bounded reverse-reachability row returned by `impact`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImpactOutput {
    /// The selected structural identity whose independent traversal produced this row.
    pub seed: SymbolId,
    pub symbol: SymbolId,
    pub parent: SymbolId,
    pub depth: u32,
    pub path_confidence: ConfidenceOutput,
    pub via: RelationOutput,
}

/// One raw extracted reference returned by `references`, including unresolved
/// references that therefore have no graph endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceOutput {
    pub name: String,
    pub role: RefRoleOutput,
    pub occurrence: OccurrenceOutput,
    #[serde(rename = "sourceModule", skip_serializing_if = "Option::is_none")]
    pub source_module: Option<String>,
    #[serde(rename = "fromPath", skip_serializing_if = "Option::is_none")]
    pub from_path: Option<String>,
    #[serde(rename = "importedName", skip_serializing_if = "Option::is_none")]
    pub imported_name: Option<String>,
    #[serde(rename = "isReexport", skip_serializing_if = "std::ops::Not::not")]
    pub is_reexport: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qualifier: Option<String>,
    #[serde(rename = "typeRefContext", skip_serializing_if = "Option::is_none")]
    pub type_ref_context: Option<TypeRefContextOutput>,
}

/// The target aggregation key for a resolved module dependency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ModuleDependencyTargetOutput {
    /// Resolved definitions aggregate at their normalized project-relative file.
    File { file: String },
    /// Endpoints without a definition retain their complete structural identity.
    External {
        id: SymbolId,
        #[serde(rename = "idDisplay")]
        id_display: String,
    },
}

/// A deterministic aggregation row returned by `module-deps`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleDependencyOutput {
    pub source_file: String,
    pub target: ModuleDependencyTargetOutput,
    pub role: RefRoleOutput,
    pub count: usize,
    pub evidence: Vec<RelationOutput>,
}

/// Stable inventory completeness spelling in status output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InventoryCompletenessOutput {
    Complete,
    Partial,
}

impl From<InventoryCompleteness> for InventoryCompletenessOutput {
    fn from(value: InventoryCompleteness) -> Self {
        match value {
            InventoryCompleteness::Complete => Self::Complete,
            InventoryCompleteness::Partial => Self::Partial,
        }
    }
}

/// A typed, stable inventory omission reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum InventoryOmissionReasonOutput {
    UnrecognizedExtension,
    FeatureDisabled { language: String },
    SymlinkFile,
    SymlinkDirectory,
    NotRegularFile,
    FileTooLarge { limit: usize },
    TotalBytesLimit { limit: usize },
    FileCountLimit { limit: usize },
    InvalidUtf8,
    ExtractionError,
    ChangedDuringRead,
    ReadError { error: StableIoErrorOutput },
}

impl From<&OmissionReason> for InventoryOmissionReasonOutput {
    fn from(value: &OmissionReason) -> Self {
        match value {
            OmissionReason::UnrecognizedExtension => Self::UnrecognizedExtension,
            OmissionReason::FeatureDisabled { language } => Self::FeatureDisabled {
                language: language.as_str().to_owned(),
            },
            OmissionReason::SymlinkFile => Self::SymlinkFile,
            OmissionReason::SymlinkDirectory => Self::SymlinkDirectory,
            OmissionReason::NotRegularFile => Self::NotRegularFile,
            OmissionReason::FileTooLarge { limit } => Self::FileTooLarge { limit: *limit },
            OmissionReason::TotalBytesLimit { limit } => Self::TotalBytesLimit { limit: *limit },
            OmissionReason::FileCountLimit { limit } => Self::FileCountLimit { limit: *limit },
            OmissionReason::InvalidUtf8 => Self::InvalidUtf8,
            OmissionReason::ExtractionError => Self::ExtractionError,
            OmissionReason::ChangedDuringRead => Self::ChangedDuringRead,
            OmissionReason::ReadError { kind } => Self::ReadError {
                error: (*kind).into(),
            },
        }
    }
}

/// Stable platform-neutral I/O error kind in inventory output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StableIoErrorOutput {
    NotFound,
    PermissionDenied,
    AlreadyExists,
    InvalidInput,
    InvalidData,
    TimedOut,
    Interrupted,
    UnexpectedEof,
    WouldBlock,
    WriteZero,
    Other,
}

impl From<StableIoErrorKind> for StableIoErrorOutput {
    fn from(value: StableIoErrorKind) -> Self {
        match value {
            StableIoErrorKind::NotFound => Self::NotFound,
            StableIoErrorKind::PermissionDenied => Self::PermissionDenied,
            StableIoErrorKind::AlreadyExists => Self::AlreadyExists,
            StableIoErrorKind::InvalidInput => Self::InvalidInput,
            StableIoErrorKind::InvalidData => Self::InvalidData,
            StableIoErrorKind::TimedOut => Self::TimedOut,
            StableIoErrorKind::Interrupted => Self::Interrupted,
            StableIoErrorKind::UnexpectedEof => Self::UnexpectedEof,
            StableIoErrorKind::WouldBlock => Self::WouldBlock,
            StableIoErrorKind::WriteZero => Self::WriteZero,
            StableIoErrorKind::Other => Self::Other,
        }
    }
}

/// One typed omission-reason count, in stable reason-tag order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventoryReasonCountOutput {
    pub reason: InventoryOmissionReasonOutput,
    pub count: usize,
}

/// Typed aggregate inventory status returned by `status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventorySummaryOutput {
    pub completeness: InventoryCompletenessOutput,
    pub admitted_files: usize,
    pub admitted_bytes: usize,
    pub omitted_files: usize,
    pub omission_reasons: Vec<InventoryReasonCountOutput>,
}

impl InventorySummaryOutput {
    pub fn new(completeness: InventoryCompleteness, summary: &InventorySummary) -> Self {
        Self {
            completeness: completeness.into(),
            admitted_files: summary.admitted_files,
            admitted_bytes: summary.admitted_bytes,
            omitted_files: summary.omitted_files,
            omission_reasons: summary
                .omission_reasons
                .iter()
                .map(|(reason, count)| InventoryReasonCountOutput {
                    reason: reason.into(),
                    count: *count,
                })
                .collect(),
        }
    }
}

/// One persisted cache omission. Its reason is cache data, not a live-walk
/// classification, and is therefore intentionally represented verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheOmissionOutput {
    pub path: String,
    pub reason: String,
    pub detail: String,
}

impl From<&CacheOmission> for CacheOmissionOutput {
    fn from(value: &CacheOmission) -> Self {
        Self {
            path: value.path.clone(),
            reason: value.reason.clone(),
            detail: value.detail.clone(),
        }
    }
}

/// Counts of decisions made by the refresh planner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PlanDecisionCountsOutput {
    pub need_hash: usize,
    pub reuse_facts: usize,
    pub extract: usize,
    pub remove: usize,
    pub omit: usize,
}

impl From<&crate::refresh::RefreshPlan> for PlanDecisionCountsOutput {
    fn from(plan: &crate::refresh::RefreshPlan) -> Self {
        let mut counts = Self::default();
        for entry in &plan.entries {
            match &entry.decision {
                crate::refresh::RefreshDecision::NeedHash => counts.need_hash += 1,
                crate::refresh::RefreshDecision::ReuseFacts => counts.reuse_facts += 1,
                crate::refresh::RefreshDecision::Extract => counts.extract += 1,
                crate::refresh::RefreshDecision::Remove => counts.remove += 1,
                crate::refresh::RefreshDecision::Omit { .. } => counts.omit += 1,
            }
        }
        counts
    }
}

/// Owned result returned by `index`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexOutput {
    pub candidate: String,
    pub snapshot: String,
    pub tier: ResolverTier,
    pub completeness: CacheCompletenessOutput,
    pub inventory_file_count: u64,
    pub inventory_total_bytes: u64,
    pub omissions: Vec<CacheOmissionOutput>,
    pub changed: usize,
    pub deleted: usize,
    pub ignored_omissions: usize,
    pub attempts: u8,
    pub plan_decisions: PlanDecisionCountsOutput,
}

impl IndexOutput {
    /// Creates an owned index contract from persisted snapshot metadata.
    pub fn from_loaded_snapshot(
        snapshot: &LoadedSnapshot,
        tier: ResolverTier,
        changed: usize,
        deleted: usize,
        ignored_omissions: usize,
        attempts: u8,
        plan_decisions: PlanDecisionCountsOutput,
    ) -> Self {
        Self {
            candidate: snapshot.candidate_id.to_string(),
            snapshot: snapshot.candidate_id.to_string(),
            tier,
            completeness: snapshot.completeness.into(),
            inventory_file_count: snapshot.inventory_file_count,
            inventory_total_bytes: snapshot.inventory_total_bytes,
            omissions: snapshot.omissions.iter().map(Into::into).collect(),
            changed,
            deleted,
            ignored_omissions,
            attempts,
            plan_decisions,
        }
    }
}

/// Cache/project and inventory information returned by `status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusOutput {
    pub project: ProjectOutput,
    pub inventory: InventorySummaryOutput,
    /// Persisted omissions available without claiming that the filesystem was scanned.
    pub cached_omissions: Vec<CacheOmissionOutput>,
    pub max_files: usize,
    pub max_file_bytes: usize,
    pub max_total_bytes: usize,
    pub max_depth: u32,
    pub result_limit: usize,
    pub impact_depth: u32,
    pub timeout_millis: Option<u64>,
}

impl StatusOutput {
    /// Builds status entirely from an already loaded snapshot. This deliberately
    /// reports cached omission metadata rather than implying a live inventory walk.
    pub fn from_loaded_snapshot(
        project: ProjectOutput,
        snapshot: &LoadedSnapshot,
        limits: &ResourceLimits,
    ) -> Self {
        Self {
            project,
            inventory: InventorySummaryOutput {
                completeness: match snapshot.completeness {
                    CacheCompleteness::Complete => InventoryCompletenessOutput::Complete,
                    CacheCompleteness::Partial => InventoryCompletenessOutput::Partial,
                },
                admitted_files: usize::try_from(snapshot.inventory_file_count)
                    .unwrap_or(usize::MAX),
                admitted_bytes: usize::try_from(snapshot.inventory_total_bytes)
                    .unwrap_or(usize::MAX),
                omitted_files: snapshot.omissions.len(),
                omission_reasons: Vec::new(),
            },
            cached_omissions: snapshot.omissions.iter().map(Into::into).collect(),
            max_files: limits.max_files,
            max_file_bytes: limits.max_file_bytes,
            max_total_bytes: limits.max_total_bytes,
            max_depth: limits.max_depth,
            result_limit: limits.result_limit,
            impact_depth: crate::config::DEFAULT_IMPACT_DEPTH,
            timeout_millis: limits
                .timeout
                .map(|value| value.as_millis().try_into().unwrap_or(u64::MAX)),
        }
    }
}

/// A lossless selector report, emitted before result limiting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectorOutput {
    pub matched: usize,
    pub ambiguous: bool,
    pub ids: Vec<SymbolId>,
    pub symbols: Vec<SymbolOutput>,
}

/// Versioned output shared by every command-specific owned result record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputEnvelope<T> {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub status: OutputStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project: Option<ProjectOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selector: Option<SelectorOutput>,
    pub returned: usize,
    pub total: usize,
    pub truncated: bool,
    pub results: T,
}

impl<T> OutputEnvelope<T> {
    pub const SCHEMA_VERSION: u32 = OUTPUT_SCHEMA_VERSION;

    pub fn new(status: OutputStatus, results: T) -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION,
            status,
            project: None,
            selector: None,
            returned: 0,
            total: 0,
            truncated: false,
            results,
        }
    }
}

/// Versioned JSON-only failure record for the thin executable boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorEnvelope {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub status: OutputStatus,
    pub error: String,
}

impl ErrorEnvelope {
    pub const SCHEMA_VERSION: u32 = OUTPUT_SCHEMA_VERSION;

    pub fn new(status: OutputStatus, error: impl Into<String>) -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION,
            status,
            error: error.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loaded_snapshot(completeness: CacheCompleteness) -> LoadedSnapshot {
        let language = crate::cache::LanguageFeatureFingerprint::current();
        let package = crate::cache::PackageFingerprint::from_normalized(["test"]);
        let compatibility = crate::cache::CompatibilityFingerprint::new(language, package);
        let digest =
            crate::cache::ProjectInputDigest::from_inputs([] as [(&str, &str, [u8; 32]); 0]);
        let omissions = vec![CacheOmission {
            path: "src/large.rs".into(),
            reason: "file-too-large".into(),
            detail: "limit=1024".into(),
        }];
        LoadedSnapshot {
            candidate_id: crate::cache::CandidateId::new(
                compatibility,
                digest,
                completeness,
                &omissions,
            ),
            compatibility: crate::cache::CompatibilityRecord {
                id: compatibility,
                language_fingerprint: language,
                package_fingerprint: package,
                created_at_ns: 1,
            },
            input_digest: digest,
            completeness,
            omissions,
            created_at_ns: 2,
            inventory_file_count: 3,
            inventory_total_bytes: 42,
            files: Vec::new(),
            tier_graphs: Vec::new(),
        }
    }

    #[test]
    fn symbol_output_keeps_lossless_identity_and_line() {
        let symbol = code2graph::Symbol {
            id: SymbolId::global("rust", vec![code2graph::Descriptor::Term("run".into())]),
            name: "run".into(),
            kind: SymbolKind::Function,
            visibility: code2graph::Visibility::Public,
            entry_points: Vec::new(),
            file: "src/lib.rs".into(),
            line: 7,
            span: code2graph::ByteSpan { start: 0, end: 8 },
            signature: "pub fn run()".into(),
        };
        let expected_display = symbol.id.to_scip_string();
        let output = SymbolOutput::from(&symbol);
        assert_eq!(output.id, symbol.id);
        assert_eq!(output.line, 7);
        let mut maximum_line = symbol.clone();
        maximum_line.line = u32::MAX;
        assert_eq!(SymbolOutput::from(&maximum_line).line, u32::MAX);
        let json = serde_json::to_value(output).unwrap();
        assert_eq!(json["idDisplay"], expected_display);
        assert_eq!(json["id"]["version"], 1);
    }

    #[test]
    fn envelope_uses_stable_schema_and_spelling() {
        let envelope = OutputEnvelope::new(OutputStatus::NoMatch, Vec::<String>::new());
        assert_eq!(
            serde_json::to_string(&envelope).unwrap(),
            r#"{"schemaVersion":1,"status":"no-match","returned":0,"total":0,"truncated":false,"results":[]}"#
        );
    }

    #[test]
    fn typed_values_use_documented_kebab_case() {
        assert_eq!(
            serde_json::to_string(&SymbolKindOutput::TypeAlias).unwrap(),
            r#""type-alias""#
        );
        assert_eq!(
            serde_json::to_string(&RefRoleOutput::IsImplementation).unwrap(),
            r#""is-implementation""#
        );
        assert_eq!(
            serde_json::to_string(&ConfidenceOutput::NameOnly).unwrap(),
            r#""name-only""#
        );
        assert_eq!(
            serde_json::to_string(&ProvenanceOutput::ScopeGraph).unwrap(),
            r#""scope-graph""#
        );
        assert_eq!(
            serde_json::to_string(&TypeRefContextOutput::GenericArg).unwrap(),
            r#""generic-arg""#
        );
        assert_eq!(
            serde_json::to_string(&ModuleDependencyTargetOutput::File {
                file: "src/lib.rs".into()
            })
            .unwrap(),
            r#"{"kind":"file","file":"src/lib.rs"}"#
        );
    }

    fn project_output_for_test(snapshot: &LoadedSnapshot, freshness: Freshness) -> ProjectOutput {
        ProjectOutput {
            root: "/project".into(),
            snapshot: "snapshot".into(),
            tier: ResolverTier::Scope,
            freshness,
            cache: CacheDisposition::Hit,
            completeness: snapshot.completeness.into(),
            omitted_files: snapshot.omissions.len(),
            omissions: snapshot.omissions.iter().map(Into::into).collect(),
        }
    }

    #[test]
    fn index_output_and_cached_status_are_owned_stable_contracts() {
        let snapshot = loaded_snapshot(CacheCompleteness::Partial);
        let index = IndexOutput::from_loaded_snapshot(
            &snapshot,
            ResolverTier::Scope,
            2,
            1,
            4,
            3,
            PlanDecisionCountsOutput {
                need_hash: 1,
                reuse_facts: 2,
                extract: 3,
                remove: 4,
                omit: 5,
            },
        );
        let value = serde_json::to_value(&index).unwrap();
        assert_eq!(value["tier"], "scope");
        assert_eq!(value["completeness"], "partial");
        assert_eq!(value["inventory_file_count"], 3);
        assert_eq!(value["omissions"][0]["reason"], "file-too-large");
        assert_eq!(value["plan_decisions"]["extract"], 3);

        let status = StatusOutput::from_loaded_snapshot(
            project_output_for_test(&snapshot, Freshness::Frozen),
            &snapshot,
            &ResourceLimits::default(),
        );
        assert_eq!(status.inventory.admitted_files, 3);
        assert_eq!(status.cached_omissions[0].path, "src/large.rs");
        assert!(status.inventory.omission_reasons.is_empty());
    }

    #[test]
    fn index_and_stale_partial_status_have_golden_json_contracts() {
        let index = IndexOutput {
            candidate: "candidate".into(),
            snapshot: "snapshot".into(),
            tier: ResolverTier::Scope,
            completeness: CacheCompletenessOutput::Partial,
            inventory_file_count: 3,
            inventory_total_bytes: 42,
            omissions: vec![CacheOmissionOutput {
                path: "src/large.rs".into(),
                reason: "file-too-large".into(),
                detail: "limit=1024".into(),
            }],
            changed: 2,
            deleted: 1,
            ignored_omissions: 4,
            attempts: 3,
            plan_decisions: PlanDecisionCountsOutput {
                need_hash: 1,
                reuse_facts: 2,
                extract: 3,
                remove: 4,
                omit: 5,
            },
        };
        assert_eq!(
            serde_json::to_value(&index).unwrap(),
            serde_json::json!({
                "candidate": "candidate",
                "snapshot": "snapshot",
                "tier": "scope",
                "completeness": "partial",
                "inventory_file_count": 3,
                "inventory_total_bytes": 42,
                "omissions": [{
                    "path": "src/large.rs", "reason": "file-too-large", "detail": "limit=1024"
                }],
                "changed": 2,
                "deleted": 1,
                "ignored_omissions": 4,
                "attempts": 3,
                "plan_decisions": {
                    "need_hash": 1, "reuse_facts": 2, "extract": 3, "remove": 4, "omit": 5
                }
            })
        );

        let snapshot = loaded_snapshot(CacheCompleteness::Partial);
        let status = StatusOutput::from_loaded_snapshot(
            project_output_for_test(&snapshot, Freshness::Stale),
            &snapshot,
            &ResourceLimits::default(),
        );
        assert_eq!(
            serde_json::to_value(&status).unwrap(),
            serde_json::json!({
                "project": {
                    "root": "/project", "snapshot": "snapshot", "tier": "scope",
                    "freshness": "stale", "cache": "hit", "completeness": "partial",
                    "omittedFiles": 1,
                    "omissions": [{
                        "path": "src/large.rs", "reason": "file-too-large", "detail": "limit=1024"
                    }]
                },
                "inventory": {
                    "completeness": "partial", "admitted_files": 3, "admitted_bytes": 42,
                    "omitted_files": 1, "omission_reasons": []
                },
                "cached_omissions": [{
                    "path": "src/large.rs", "reason": "file-too-large", "detail": "limit=1024"
                }],
                "max_files": 10000,
                "max_file_bytes": 1048576,
                "max_total_bytes": 268435456,
                "max_depth": 32,
                "result_limit": 50,
                "impact_depth": 2,
                "timeout_millis": null
            })
        );
    }

    #[test]
    fn project_metadata_json_is_complete_for_fresh_partial_stale_and_frozen() {
        let snapshot = loaded_snapshot(CacheCompleteness::Partial);
        for (freshness, spelling) in [
            (Freshness::Fresh, "fresh"),
            (Freshness::Stale, "stale"),
            (Freshness::Frozen, "frozen"),
        ] {
            assert_eq!(
                serde_json::to_value(project_output_for_test(&snapshot, freshness)).unwrap(),
                serde_json::json!({
                    "root": "/project", "snapshot": "snapshot", "tier": "scope",
                    "freshness": spelling, "cache": "hit", "completeness": "partial",
                    "omittedFiles": 1,
                    "omissions": [{
                        "path": "src/large.rs", "reason": "file-too-large", "detail": "limit=1024"
                    }]
                })
            );
        }
        let complete = ProjectOutput {
            root: "/project".into(),
            snapshot: "snapshot".into(),
            tier: ResolverTier::Scope,
            freshness: Freshness::Fresh,
            cache: CacheDisposition::Hit,
            completeness: CacheCompletenessOutput::Complete,
            omitted_files: 0,
            omissions: Vec::new(),
        };
        assert_eq!(
            serde_json::to_value(complete).unwrap(),
            serde_json::json!({
                "root": "/project", "snapshot": "snapshot", "tier": "scope", "freshness": "fresh",
                "cache": "hit", "completeness": "complete", "omittedFiles": 0, "omissions": []
            })
        );
    }

    #[test]
    fn success_status_matrix_preserves_success_exit_code() {
        for (completeness, freshness, expected) in [
            (
                CacheCompleteness::Complete,
                Freshness::Fresh,
                OutputStatus::Ok,
            ),
            (
                CacheCompleteness::Complete,
                Freshness::Frozen,
                OutputStatus::Ok,
            ),
            (
                CacheCompleteness::Partial,
                Freshness::Fresh,
                OutputStatus::Partial,
            ),
            (
                CacheCompleteness::Partial,
                Freshness::Frozen,
                OutputStatus::Partial,
            ),
            (
                CacheCompleteness::Complete,
                Freshness::Stale,
                OutputStatus::Stale,
            ),
            (
                CacheCompleteness::Partial,
                Freshness::Stale,
                OutputStatus::Stale,
            ),
        ] {
            assert_eq!(success_status(completeness, freshness), expected);
            assert_eq!(
                success_exit_code(completeness, freshness),
                ExitCode::Success
            );
        }
    }

    #[test]
    fn status_represents_every_freshness_and_cache_disposition_without_losing_completeness() {
        let snapshot = loaded_snapshot(CacheCompleteness::Partial);
        for freshness in [Freshness::Fresh, Freshness::Frozen, Freshness::Stale] {
            for cache in [
                CacheDisposition::Hit,
                CacheDisposition::Miss,
                CacheDisposition::Disabled,
            ] {
                let status = StatusOutput::from_loaded_snapshot(
                    ProjectOutput {
                        root: "/project".into(),
                        snapshot: "snapshot".into(),
                        tier: ResolverTier::Dense,
                        freshness,
                        cache,
                        completeness: snapshot.completeness.into(),
                        omitted_files: snapshot.omissions.len(),
                        omissions: snapshot.omissions.iter().map(Into::into).collect(),
                    },
                    &snapshot,
                    &ResourceLimits::default(),
                );
                let value = serde_json::to_value(status).unwrap();
                assert_eq!(
                    value["project"]["freshness"],
                    serde_json::to_value(freshness).unwrap()
                );
                assert_eq!(
                    value["project"]["cache"],
                    serde_json::to_value(cache).unwrap()
                );
                assert_eq!(value["inventory"]["completeness"], "partial");
                assert_eq!(value["cached_omissions"][0]["path"], "src/large.rs");
                assert_eq!(
                    success_status(CacheCompleteness::Partial, freshness),
                    if freshness == Freshness::Stale {
                        OutputStatus::Stale
                    } else {
                        OutputStatus::Partial
                    }
                );
            }
        }
    }

    #[test]
    fn inventory_summary_has_a_typed_stable_json_contract() {
        let summary = InventorySummary {
            admitted_files: 2,
            admitted_bytes: 17,
            omitted_files: 2,
            omission_reasons: vec![
                (OmissionReason::FileTooLarge { limit: 8 }, 1),
                (
                    OmissionReason::ReadError {
                        kind: StableIoErrorKind::PermissionDenied,
                    },
                    1,
                ),
            ],
        };
        let output = InventorySummaryOutput::new(InventoryCompleteness::Partial, &summary);
        assert_eq!(
            serde_json::to_string(&output).unwrap(),
            r#"{"completeness":"partial","admitted_files":2,"admitted_bytes":17,"omitted_files":2,"omission_reasons":[{"reason":{"kind":"file-too-large","limit":8},"count":1},{"reason":{"kind":"read-error","error":"permission-denied"},"count":1}]}"#
        );
    }
}
