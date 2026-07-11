// SPDX-License-Identifier: Apache-2.0

use code2graph::{Confidence, Provenance, RefRole, SymbolId, SymbolKind, TypeRefContext};
use serde::{Deserialize, Serialize};

use crate::config::ResolverTier;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
    NormalizedName,
    External,
}

impl From<Provenance> for ProvenanceOutput {
    fn from(provenance: Provenance) -> Self {
        match provenance {
            Provenance::SymbolTable => Self::SymbolTable,
            Provenance::ScopeGraph => Self::ScopeGraph,
            Provenance::FfiBridge => Self::FfiBridge,
            Provenance::Conformance => Self::Conformance,
            Provenance::NormalizedName => Self::NormalizedName,
            Provenance::External => Self::External,
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

/// Cache/project information returned by `status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusOutput {
    pub project: ProjectOutput,
    pub max_files: usize,
    pub max_file_bytes: usize,
    pub max_total_bytes: usize,
    pub max_depth: u32,
    pub result_limit: usize,
    pub impact_depth: u32,
    pub timeout_millis: Option<u64>,
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
}
