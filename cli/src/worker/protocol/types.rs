// SPDX-License-Identifier: Apache-2.0

//! Protocol data types and public wire contracts.

use code2graph::FileFacts;
pub const PROTOCOL_VERSION: u16 = 1;
pub const REQUEST_FRAME_MAX: usize = 16 * 1024 * 1024;
pub const RESPONSE_FRAME_MAX: usize = 64 * 1024 * 1024;
pub const MAX_DEPTH: usize = 64;
pub const MAX_STRING_BYTES: usize = 1024 * 1024;
pub const MAX_COLLECTION_ITEMS: usize = 1_000_000;
pub const MAX_ERROR_MESSAGE_BYTES: usize = 64 * 1024;

pub type RequestId = u64;

#[derive(Debug, thiserror::Error)]
pub enum WorkerProtocolError {
    #[error("worker frame is malformed: {0}")]
    Malformed(&'static str),
    /// The stream ended part-way through a frame. Unlike every other variant
    /// this is not evidence of a protocol defect: it is what a worker killed
    /// mid-write (a crash, the OOM killer, the deadline monitor) leaves behind,
    /// so clients classify it as worker death and let crash recovery respawn.
    #[error("worker frame is truncated: {0}")]
    Truncated(&'static str),
    #[error("worker frame exceeds its limit")]
    FrameTooLarge,
    #[error("worker protocol version {0} is unsupported")]
    Version(u16),
    #[error("worker message kind {0} is invalid")]
    Kind(u8),
    #[error("worker MessagePack decode failed: {0}")]
    Decode(zerompk::Error),
    #[error("worker MessagePack encode failed: {0}")]
    Encode(zerompk::Error),
    #[error("worker frame I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("worker facts are invalid: {0}")]
    Facts(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Stable numeric keys: version, kind, request ID, path, language, source,
/// custom query-binding rules.
pub struct WorkerRequest {
    pub version: u16,
    pub kind: u8,
    pub request_id: RequestId,
    pub path: String,
    pub language: u16,
    pub source: Vec<u8>,
    pub custom_rules: Vec<QueryBindingRuleWire>,
}

/// Wire form of a `code2graph::QueryBindingRule` sourced from `code2graph.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryBindingRuleWire {
    pub lang: String,
    pub construct: String,
    pub sql_arg: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Stable numeric keys: version, kind, request ID, facts, error.
pub struct WorkerResponse {
    pub version: u16,
    pub kind: u8,
    pub request_id: RequestId,
    pub facts: Option<FileFactsWire>,
    pub error: Option<WorkerErrorWire>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum WorkerErrorCode {
    Extraction = 1,
    InvalidRequest = 2,
    Internal = 3,
}

/// A protocol-only response classification. It intentionally keeps the worker
/// validation code out of the public `WorkerErrorCode` contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkerResponseErrorCode {
    Public(WorkerErrorCode),
    InvalidFacts,
}

pub(crate) const INVALID_FACTS_ERROR_CODE: u16 = 4;

impl WorkerResponseErrorCode {
    pub(super) fn from_wire(value: u16) -> Result<Self, WorkerProtocolError> {
        match value {
            1 => Ok(Self::Public(WorkerErrorCode::Extraction)),
            2 => Ok(Self::Public(WorkerErrorCode::InvalidRequest)),
            3 => Ok(Self::Public(WorkerErrorCode::Internal)),
            INVALID_FACTS_ERROR_CODE => Ok(Self::InvalidFacts),
            _ => Err(WorkerProtocolError::Facts(
                "unknown worker error code".into(),
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerErrorWire {
    pub code: u16,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerRemoteError {
    pub code: WorkerErrorCode,
    pub message: String,
}

pub type WorkerResponseResult = Result<FileFacts, WorkerRemoteError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileFactsWire {
    pub file: String,
    pub lang: String,
    pub symbols: Vec<SymbolWire>,
    pub references: Vec<ReferenceWire>,
    pub scopes: Vec<ScopeWire>,
    pub bindings: Vec<BindingWire>,
    pub ffi_exports: Vec<FfiExportWire>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolIdWireDto {
    pub version: u32,
    pub scip: String,
    pub lang: Option<String>,
    pub file: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolWire {
    pub id: SymbolIdWireDto,
    pub name: String,
    pub kind: u8,
    pub visibility: u8,
    pub entry_points: Vec<EntryPointWire>,
    pub file: String,
    pub line: u32,
    pub span_start: u64,
    pub span_end: u64,
    pub signature: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryPointWire {
    pub tag: u8,
    pub value: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OccurrenceWire {
    pub file: String,
    pub line: u32,
    pub col: u32,
    pub byte: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceWire {
    pub name: String,
    pub occ: OccurrenceWire,
    pub role: u8,
    pub source_module: Option<String>,
    pub from_path: Option<String>,
    pub imported_name: Option<String>,
    pub is_reexport: Option<bool>,
    pub qualifier: Option<String>,
    pub scope: Option<u64>,
    pub type_ref_ctx: Option<u8>,
    pub cross_artifact: Option<bool>,
    pub self_receiver: Option<bool>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeWire {
    pub parent: Option<u64>,
    pub start: u64,
    pub end: u64,
    pub kind: u8,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingWire {
    pub scope: u64,
    pub name: String,
    pub intro: u64,
    pub kind: u8,
    pub target_tag: u8,
    pub target_value: Option<String>,
    pub target_id: Option<SymbolIdWireDto>,
    pub type_name: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FfiExportWire {
    pub symbol: SymbolIdWireDto,
    pub abi: u8,
    pub export_name: String,
}
