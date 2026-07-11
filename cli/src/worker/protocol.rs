// SPDX-License-Identifier: Apache-2.0

//! Versioned worker envelopes and fixed-width fact DTOs.

use code2graph::{
    Binding, BindingKind, BindingTarget, ByteSpan, EntryPoint, FfiAbi, FfiExport, FileFacts,
    FileFactsValidationContext, Language, Occurrence, RefRole, Reference, Scope, ScopeKind, Symbol,
    SymbolId, SymbolIdWire, SymbolKind, TypeRefContext, Visibility,
    validate_file_facts_with_context,
};
use zerompk::{FromMessagePack, Read, ToMessagePack, Write};

use crate::{InventoryFile, ProjectPath};

pub const PROTOCOL_VERSION: u16 = 1;
pub const REQUEST_FRAME_MAX: usize = 16 * 1024 * 1024;
pub const RESPONSE_FRAME_MAX: usize = 64 * 1024 * 1024;
pub const MAX_DEPTH: usize = 64;
pub const MAX_STRING_BYTES: usize = 1024 * 1024;
pub const MAX_COLLECTION_ITEMS: usize = 1_000_000;

pub type RequestId = u64;

#[derive(Debug, thiserror::Error)]
pub enum WorkerProtocolError {
    #[error("worker frame is malformed: {0}")]
    Malformed(&'static str),
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
    #[error("worker facts are invalid: {0}")]
    Facts(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Fixed field order: version, kind, request ID, path, language, source.
pub struct WorkerRequest {
    pub version: u16,
    pub kind: u8,
    pub request_id: RequestId,
    pub path: String,
    pub language: u16,
    pub source: Vec<u8>,
}

impl ToMessagePack for WorkerRequest {
    fn write<W: Write>(&self, writer: &mut W) -> zerompk::Result<()> {
        writer.write_array_len(6)?;
        self.version.write(writer)?;
        self.kind.write(writer)?;
        self.request_id.write(writer)?;
        self.path.write(writer)?;
        self.language.write(writer)?;
        writer.write_binary(&self.source)
    }
}

impl<'a> FromMessagePack<'a> for WorkerRequest {
    fn read<R: Read<'a>>(reader: &mut R) -> zerompk::Result<Self> {
        reader.check_array_len(6)?;
        Ok(Self {
            version: u16::read(reader)?,
            kind: u8::read(reader)?,
            request_id: u64::read(reader)?,
            path: String::read(reader)?,
            language: u16::read(reader)?,
            source: reader.read_binary()?.into_owned(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, ToMessagePack, FromMessagePack)]
/// Fixed field order: version, kind, request ID, facts, error.
pub struct WorkerResponse {
    pub version: u16,
    pub kind: u8,
    pub request_id: RequestId,
    pub facts: Option<FileFactsWire>,
    pub error: Option<WorkerErrorWire>,
}

#[derive(Debug, Clone, PartialEq, Eq, ToMessagePack, FromMessagePack)]
pub struct WorkerErrorWire {
    pub code: u16,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, ToMessagePack, FromMessagePack)]
pub struct FileFactsWire {
    pub file: String,
    pub lang: String,
    pub symbols: Vec<SymbolWire>,
    pub references: Vec<ReferenceWire>,
    pub scopes: Vec<ScopeWire>,
    pub bindings: Vec<BindingWire>,
    pub ffi_exports: Vec<FfiExportWire>,
}
#[derive(Debug, Clone, PartialEq, Eq, ToMessagePack, FromMessagePack)]
pub struct SymbolIdWireDto {
    pub version: u32,
    pub scip: String,
    pub lang: Option<String>,
    pub file: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, ToMessagePack, FromMessagePack)]
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
#[derive(Debug, Clone, PartialEq, Eq, ToMessagePack, FromMessagePack)]
pub struct EntryPointWire {
    pub tag: u8,
    pub value: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, ToMessagePack, FromMessagePack)]
pub struct OccurrenceWire {
    pub file: String,
    pub line: u32,
    pub col: u32,
    pub byte: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, ToMessagePack, FromMessagePack)]
pub struct ReferenceWire {
    pub name: String,
    pub occ: OccurrenceWire,
    pub role: u8,
    pub source_module: Option<String>,
    pub from_path: Option<String>,
    pub qualifier: Option<String>,
    pub scope: Option<u64>,
    pub type_ref_ctx: Option<u8>,
}
#[derive(Debug, Clone, PartialEq, Eq, ToMessagePack, FromMessagePack)]
pub struct ScopeWire {
    pub parent: Option<u64>,
    pub start: u64,
    pub end: u64,
    pub kind: u8,
}
#[derive(Debug, Clone, PartialEq, Eq, ToMessagePack, FromMessagePack)]
pub struct BindingWire {
    pub scope: u64,
    pub name: String,
    pub intro: u64,
    pub kind: u8,
    pub target_tag: u8,
    pub target_value: Option<String>,
    pub target_id: Option<SymbolIdWireDto>,
}
#[derive(Debug, Clone, PartialEq, Eq, ToMessagePack, FromMessagePack)]
pub struct FfiExportWire {
    pub symbol: SymbolIdWireDto,
    pub abi: u8,
    pub export_name: String,
}

impl WorkerRequest {
    /// Build and validate a request from an admitted inventory file.
    pub fn from_inventory_file(
        request_id: RequestId,
        file: &InventoryFile,
    ) -> Result<Self, WorkerProtocolError> {
        validate_inventory_file(file)?;
        let request = Self {
            version: PROTOCOL_VERSION,
            kind: 1,
            request_id,
            path: file.path.as_str().to_owned(),
            language: language_to_tag(file.language),
            source: file.bytes.clone(),
        };
        validate_request_for_file(&request, file)?;
        Ok(request)
    }
}

/// Validate an extraction request before it reaches the extractor.
pub fn validate_request(request: &WorkerRequest) -> Result<Language, WorkerProtocolError> {
    if request.version != PROTOCOL_VERSION {
        return Err(WorkerProtocolError::Version(request.version));
    }
    if request.kind != 1 {
        return Err(WorkerProtocolError::Kind(request.kind));
    }
    if request.source.len() > REQUEST_FRAME_MAX {
        return Err(WorkerProtocolError::FrameTooLarge);
    }
    cap(&request.path)?;
    ProjectPath::new(std::path::Path::new(&request.path))
        .map_err(|_| WorkerProtocolError::Facts("invalid project-relative request path".into()))?;
    std::str::from_utf8(&request.source)
        .map_err(|_| WorkerProtocolError::Facts("request source is not UTF-8".into()))?;
    let language = language_from_tag(request.language)?;
    if Language::from_path(&request.path) != Some(language) {
        return Err(WorkerProtocolError::Facts(
            "request path extension does not match language".into(),
        ));
    }
    Ok(language)
}

/// Validate that a request is an exact projection of its trusted inventory file.
pub fn validate_request_for_file(
    request: &WorkerRequest,
    file: &InventoryFile,
) -> Result<Language, WorkerProtocolError> {
    validate_inventory_file(file)?;
    let language = validate_request(request)?;
    if request.path != file.path.as_str()
        || language != file.language
        || request.source != file.bytes
    {
        return Err(WorkerProtocolError::Facts(
            "request does not match inventory file".into(),
        ));
    }
    Ok(language)
}

fn validate_inventory_file(file: &InventoryFile) -> Result<(), WorkerProtocolError> {
    cap(file.path.as_str())?;
    if file.bytes.len() > REQUEST_FRAME_MAX {
        return Err(WorkerProtocolError::FrameTooLarge);
    }
    let bytes_text = std::str::from_utf8(&file.bytes)
        .map_err(|_| WorkerProtocolError::Facts("inventory bytes are not UTF-8".into()))?;
    if bytes_text != file.text {
        return Err(WorkerProtocolError::Facts(
            "inventory text does not match bytes".into(),
        ));
    }
    if Language::from_path(file.path.as_str()) != Some(file.language) {
        return Err(WorkerProtocolError::Facts(
            "inventory path extension does not match language".into(),
        ));
    }
    if blake3::hash(&file.bytes).to_hex().as_str() != file.blake3 {
        return Err(WorkerProtocolError::Facts(
            "inventory digest does not match bytes".into(),
        ));
    }
    Ok(())
}

/// Validate a response's identity and facts against the request that produced it.
pub fn validate_response_facts(
    response: &WorkerResponse,
    request: &WorkerRequest,
) -> Result<FileFacts, WorkerProtocolError> {
    let language = validate_request(request)?;
    if response.version != PROTOCOL_VERSION {
        return Err(WorkerProtocolError::Version(response.version));
    }
    if response.kind != 2 {
        return Err(WorkerProtocolError::Kind(response.kind));
    }
    if response.request_id != request.request_id {
        return Err(WorkerProtocolError::Malformed(
            "response request ID mismatch",
        ));
    }
    if response.error.is_some() {
        return Err(WorkerProtocolError::Malformed(
            "response carries an error instead of success facts",
        ));
    }
    let facts = response
        .facts
        .clone()
        .ok_or(WorkerProtocolError::Malformed("missing success facts"))?
        .try_into()?;
    validate_file_facts_with_context(
        &facts,
        FileFactsValidationContext {
            expected_file: &request.path,
            expected_language: language,
            source_len: request.source.len(),
        },
    )
    .map_err(|error| WorkerProtocolError::Facts(error.to_string()))?;
    Ok(facts)
}

/// Append-only language tags; never use a Rust enum ordinal on the wire.
pub const fn language_to_tag(language: Language) -> u16 {
    match language {
        Language::Rust => 0,
        Language::TypeScript => 1,
        Language::JavaScript => 2,
        Language::Python => 3,
        Language::Go => 4,
        Language::Shell => 5,
        Language::C => 6,
        Language::Cpp => 7,
        Language::Java => 8,
        Language::Ruby => 9,
        Language::Php => 10,
        Language::Swift => 11,
        Language::Kotlin => 12,
        Language::Solidity => 13,
        Language::Sql => 14,
        Language::Hcl => 15,
        Language::CSharp => 16,
        Language::Scala => 17,
        Language::Dart => 18,
        Language::Lua => 19,
        Language::Luau => 20,
        Language::Pascal => 21,
        Language::Svelte => 22,
    }
}

pub fn language_from_tag(tag: u16) -> Result<Language, WorkerProtocolError> {
    let all = [
        Language::Rust,
        Language::TypeScript,
        Language::JavaScript,
        Language::Python,
        Language::Go,
        Language::Shell,
        Language::C,
        Language::Cpp,
        Language::Java,
        Language::Ruby,
        Language::Php,
        Language::Swift,
        Language::Kotlin,
        Language::Solidity,
        Language::Sql,
        Language::Hcl,
        Language::CSharp,
        Language::Scala,
        Language::Dart,
        Language::Lua,
        Language::Luau,
        Language::Pascal,
        Language::Svelte,
    ];
    all.get(usize::from(tag))
        .copied()
        .ok_or_else(|| WorkerProtocolError::Facts("unknown language tag".into()))
}

fn usize_from(value: u64) -> Result<usize, WorkerProtocolError> {
    usize::try_from(value)
        .map_err(|_| WorkerProtocolError::Facts("coordinate exceeds platform usize".into()))
}
fn id_from(w: SymbolIdWireDto) -> Result<SymbolId, WorkerProtocolError> {
    cap(&w.scip)?;
    cap_option(&w.lang)?;
    cap_option(&w.file)?;
    SymbolId::try_from_wire(SymbolIdWire {
        version: w.version,
        scip: w.scip,
        lang: w.lang,
        file: w.file,
    })
    .map_err(|e| WorkerProtocolError::Facts(e.to_string()))
}
fn id_to(id: &SymbolId) -> SymbolIdWireDto {
    let w = id.to_wire();
    SymbolIdWireDto {
        version: w.version,
        scip: w.scip,
        lang: w.lang,
        file: w.file,
    }
}

impl From<&FileFacts> for FileFactsWire {
    fn from(f: &FileFacts) -> Self {
        Self {
            file: f.file.clone(),
            lang: f.lang.clone(),
            symbols: f.symbols.iter().map(SymbolWire::from).collect(),
            references: f.references.iter().map(ReferenceWire::from).collect(),
            scopes: f.scopes.iter().map(ScopeWire::from).collect(),
            bindings: f.bindings.iter().map(BindingWire::from).collect(),
            ffi_exports: f.ffi_exports.iter().map(FfiExportWire::from).collect(),
        }
    }
}
impl TryFrom<FileFactsWire> for FileFacts {
    type Error = WorkerProtocolError;
    fn try_from(f: FileFactsWire) -> Result<Self, Self::Error> {
        cap(&f.file)?;
        cap(&f.lang)?;
        cap_collection(f.symbols.len())?;
        cap_collection(f.references.len())?;
        cap_collection(f.scopes.len())?;
        cap_collection(f.bindings.len())?;
        cap_collection(f.ffi_exports.len())?;
        Ok(Self {
            file: f.file,
            lang: f.lang,
            symbols: f
                .symbols
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
            references: f
                .references
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
            scopes: f
                .scopes
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
            bindings: f
                .bindings
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
            ffi_exports: f
                .ffi_exports
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
        })
    }
}
fn cap(s: &str) -> Result<(), WorkerProtocolError> {
    if s.len() > MAX_STRING_BYTES {
        Err(WorkerProtocolError::Facts("string exceeds limit".into()))
    } else {
        Ok(())
    }
}

fn cap_option(value: &Option<String>) -> Result<(), WorkerProtocolError> {
    value.as_deref().map_or(Ok(()), cap)
}

fn cap_collection(length: usize) -> Result<(), WorkerProtocolError> {
    if length > MAX_COLLECTION_ITEMS {
        Err(WorkerProtocolError::Facts(
            "collection exceeds limit".into(),
        ))
    } else {
        Ok(())
    }
}
fn tag<T>(tag: u8, values: &[T]) -> Result<&T, WorkerProtocolError> {
    values
        .get(usize::from(tag))
        .ok_or_else(|| WorkerProtocolError::Facts("unknown enum tag".into()))
}

// These matches are deliberately exhaustive and append-only. Never derive a
// wire number from a Rust enum discriminant.
const fn symbol_kind_tag(value: SymbolKind) -> u8 {
    match value {
        SymbolKind::Function => 0,
        SymbolKind::Method => 1,
        SymbolKind::Struct => 2,
        SymbolKind::Enum => 3,
        SymbolKind::Trait => 4,
        SymbolKind::Interface => 5,
        SymbolKind::Class => 6,
        SymbolKind::TypeAlias => 7,
        SymbolKind::Const => 8,
        SymbolKind::Static => 9,
        SymbolKind::Module => 10,
        SymbolKind::Impl => 11,
        SymbolKind::Table => 12,
        SymbolKind::View => 13,
        SymbolKind::Column => 14,
        SymbolKind::Resource => 15,
        SymbolKind::Other => 16,
    }
}
const fn visibility_tag(value: Visibility) -> u8 {
    match value {
        Visibility::Public => 0,
        Visibility::Internal => 1,
        Visibility::Protected => 2,
        Visibility::Private => 3,
        Visibility::Unknown => 4,
    }
}
const fn ref_role_tag(value: RefRole) -> u8 {
    match value {
        RefRole::Call => 0,
        RefRole::IsImplementation => 1,
        RefRole::Import => 2,
        RefRole::ModuleRef => 3,
        RefRole::TypeRef => 4,
        RefRole::Read => 5,
        RefRole::Write => 6,
    }
}
const fn type_ref_context_tag(value: TypeRefContext) -> u8 {
    match value {
        TypeRefContext::ParameterType => 0,
        TypeRefContext::ReturnType => 1,
        TypeRefContext::Field => 2,
        TypeRefContext::GenericArg => 3,
        TypeRefContext::Attribute => 4,
        TypeRefContext::Other => 5,
    }
}
const fn scope_kind_tag(value: ScopeKind) -> u8 {
    match value {
        ScopeKind::Module => 0,
        ScopeKind::Function => 1,
        ScopeKind::Block => 2,
        ScopeKind::Type => 3,
        ScopeKind::Other => 4,
    }
}
const fn binding_kind_tag(value: BindingKind) -> u8 {
    match value {
        BindingKind::Local => 0,
        BindingKind::Param => 1,
        BindingKind::Import => 2,
        BindingKind::Definition => 3,
    }
}
const fn ffi_abi_tag(value: FfiAbi) -> u8 {
    match value {
        FfiAbi::C => 0,
        FfiAbi::Python => 1,
        FfiAbi::Wasm => 2,
        FfiAbi::NodeApi => 3,
        FfiAbi::Jni => 4,
    }
}

impl From<&Symbol> for SymbolWire {
    fn from(s: &Symbol) -> Self {
        Self {
            id: id_to(&s.id),
            name: s.name.clone(),
            kind: symbol_kind_tag(s.kind),
            visibility: visibility_tag(s.visibility),
            entry_points: s
                .entry_points
                .iter()
                .map(|e| match e {
                    EntryPoint::Main => EntryPointWire {
                        tag: 0,
                        value: None,
                    },
                    EntryPoint::HttpRoute(x) => EntryPointWire {
                        tag: 1,
                        value: Some(x.clone()),
                    },
                })
                .collect(),
            file: s.file.clone(),
            line: s.line,
            span_start: s.span.start as u64,
            span_end: s.span.end as u64,
            signature: s.signature.clone(),
        }
    }
}
impl TryFrom<SymbolWire> for Symbol {
    type Error = WorkerProtocolError;
    fn try_from(s: SymbolWire) -> Result<Self, Self::Error> {
        cap(&s.name)?;
        cap(&s.file)?;
        cap(&s.signature)?;
        cap_collection(s.entry_points.len())?;
        let kinds = [
            SymbolKind::Function,
            SymbolKind::Method,
            SymbolKind::Struct,
            SymbolKind::Enum,
            SymbolKind::Trait,
            SymbolKind::Interface,
            SymbolKind::Class,
            SymbolKind::TypeAlias,
            SymbolKind::Const,
            SymbolKind::Static,
            SymbolKind::Module,
            SymbolKind::Impl,
            SymbolKind::Table,
            SymbolKind::View,
            SymbolKind::Column,
            SymbolKind::Resource,
            SymbolKind::Other,
        ];
        let vis = [
            Visibility::Public,
            Visibility::Internal,
            Visibility::Protected,
            Visibility::Private,
            Visibility::Unknown,
        ];
        Ok(Self {
            id: id_from(s.id)?,
            name: s.name,
            kind: *tag(s.kind, &kinds)?,
            visibility: *tag(s.visibility, &vis)?,
            entry_points: s
                .entry_points
                .into_iter()
                .map(|x| match (x.tag, x.value) {
                    (0, None) => Ok(EntryPoint::Main),
                    (1, Some(v)) => {
                        cap(&v)?;
                        Ok(EntryPoint::HttpRoute(v))
                    }
                    _ => Err(WorkerProtocolError::Facts("invalid entry-point tag".into())),
                })
                .collect::<Result<_, _>>()?,
            file: s.file,
            line: s.line,
            span: ByteSpan {
                start: usize_from(s.span_start)?,
                end: usize_from(s.span_end)?,
            },
            signature: s.signature,
        })
    }
}
impl From<&Reference> for ReferenceWire {
    fn from(r: &Reference) -> Self {
        Self {
            name: r.name.clone(),
            occ: OccurrenceWire::from(&r.occ),
            role: ref_role_tag(r.role),
            source_module: r.source_module.clone(),
            from_path: r.from_path.clone(),
            qualifier: r.qualifier.clone(),
            scope: r.scope.map(|v| v as u64),
            type_ref_ctx: r.type_ref_ctx.map(type_ref_context_tag),
        }
    }
}
impl From<&Occurrence> for OccurrenceWire {
    fn from(o: &Occurrence) -> Self {
        Self {
            file: o.file.clone(),
            line: o.line,
            col: o.col,
            byte: o.byte as u64,
        }
    }
}
impl TryFrom<ReferenceWire> for Reference {
    type Error = WorkerProtocolError;
    fn try_from(r: ReferenceWire) -> Result<Self, Self::Error> {
        cap(&r.name)?;
        cap(&r.occ.file)?;
        cap_option(&r.source_module)?;
        cap_option(&r.from_path)?;
        cap_option(&r.qualifier)?;
        let roles = [
            RefRole::Call,
            RefRole::IsImplementation,
            RefRole::Import,
            RefRole::ModuleRef,
            RefRole::TypeRef,
            RefRole::Read,
            RefRole::Write,
        ];
        let ctx = [
            TypeRefContext::ParameterType,
            TypeRefContext::ReturnType,
            TypeRefContext::Field,
            TypeRefContext::GenericArg,
            TypeRefContext::Attribute,
            TypeRefContext::Other,
        ];
        Ok(Self {
            name: r.name,
            occ: Occurrence {
                file: r.occ.file,
                line: r.occ.line,
                col: r.occ.col,
                byte: usize_from(r.occ.byte)?,
            },
            role: *tag(r.role, &roles)?,
            source_module: r.source_module,
            from_path: r.from_path,
            qualifier: r.qualifier,
            scope: r.scope.map(usize_from).transpose()?,
            type_ref_ctx: r.type_ref_ctx.map(|v| tag(v, &ctx).copied()).transpose()?,
        })
    }
}
impl From<&Scope> for ScopeWire {
    fn from(s: &Scope) -> Self {
        Self {
            parent: s.parent.map(|x| x as u64),
            start: s.span.start as u64,
            end: s.span.end as u64,
            kind: scope_kind_tag(s.kind),
        }
    }
}
impl TryFrom<ScopeWire> for Scope {
    type Error = WorkerProtocolError;
    fn try_from(s: ScopeWire) -> Result<Self, Self::Error> {
        let kinds = [
            ScopeKind::Module,
            ScopeKind::Function,
            ScopeKind::Block,
            ScopeKind::Type,
            ScopeKind::Other,
        ];
        Ok(Self {
            parent: s.parent.map(usize_from).transpose()?,
            span: ByteSpan {
                start: usize_from(s.start)?,
                end: usize_from(s.end)?,
            },
            kind: *tag(s.kind, &kinds)?,
        })
    }
}
impl From<&Binding> for BindingWire {
    fn from(b: &Binding) -> Self {
        let (target_tag, target_value, target_id) = match &b.target {
            BindingTarget::Local => (0, None, None),
            BindingTarget::Import(x) => (1, Some(x.clone()), None),
            BindingTarget::Def(x) => (2, None, Some(id_to(x))),
        };
        Self {
            scope: b.scope as u64,
            name: b.name.clone(),
            intro: b.intro as u64,
            kind: binding_kind_tag(b.kind),
            target_tag,
            target_value,
            target_id,
        }
    }
}
impl TryFrom<BindingWire> for Binding {
    type Error = WorkerProtocolError;
    fn try_from(b: BindingWire) -> Result<Self, Self::Error> {
        cap(&b.name)?;
        cap_option(&b.target_value)?;
        let kinds = [
            BindingKind::Local,
            BindingKind::Param,
            BindingKind::Import,
            BindingKind::Definition,
        ];
        let target = match (b.target_tag, b.target_value, b.target_id) {
            (0, None, None) => BindingTarget::Local,
            (1, Some(x), None) => BindingTarget::Import(x),
            (2, None, Some(x)) => BindingTarget::Def(id_from(x)?),
            _ => return Err(WorkerProtocolError::Facts("invalid binding target".into())),
        };
        Ok(Self {
            scope: usize_from(b.scope)?,
            name: b.name,
            intro: usize_from(b.intro)?,
            kind: *tag(b.kind, &kinds)?,
            target,
        })
    }
}
impl From<&FfiExport> for FfiExportWire {
    fn from(e: &FfiExport) -> Self {
        Self {
            symbol: id_to(&e.symbol),
            abi: ffi_abi_tag(e.abi),
            export_name: e.export_name.clone(),
        }
    }
}
impl TryFrom<FfiExportWire> for FfiExport {
    type Error = WorkerProtocolError;
    fn try_from(e: FfiExportWire) -> Result<Self, Self::Error> {
        cap(&e.export_name)?;
        let abis = [
            FfiAbi::C,
            FfiAbi::Python,
            FfiAbi::Wasm,
            FfiAbi::NodeApi,
            FfiAbi::Jni,
        ];
        Ok(Self {
            symbol: id_from(e.symbol)?,
            abi: *tag(e.abi, &abis)?,
            export_name: e.export_name,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use code2graph::Descriptor;

    fn request() -> WorkerRequest {
        WorkerRequest {
            version: PROTOCOL_VERSION,
            kind: 1,
            request_id: 7,
            path: "src/a.rs".into(),
            language: 0,
            source: b"fn run() {}".to_vec(),
        }
    }

    fn facts() -> FileFacts {
        let id = SymbolId::global("rust", vec![Descriptor::Term("run".into())]);
        FileFacts {
            file: "src/a.rs".into(),
            lang: "rust".into(),
            symbols: vec![Symbol {
                id: id.clone(),
                name: "run".into(),
                kind: SymbolKind::Function,
                visibility: Visibility::Private,
                entry_points: vec![EntryPoint::Main, EntryPoint::HttpRoute("app.route".into())],
                file: "src/a.rs".into(),
                line: 1,
                span: ByteSpan { start: 0, end: 11 },
                signature: "fn run()".into(),
            }],
            references: vec![
                Reference {
                    name: "run".into(),
                    occ: Occurrence {
                        file: "src/a.rs".into(),
                        line: 1,
                        col: 3,
                        byte: 3,
                    },
                    role: RefRole::TypeRef,
                    source_module: None,
                    from_path: None,
                    qualifier: Some("crate::module".into()),
                    scope: Some(0),
                    type_ref_ctx: Some(TypeRefContext::ReturnType),
                },
                Reference {
                    name: "dependency".into(),
                    occ: Occurrence {
                        file: "src/a.rs".into(),
                        line: 1,
                        col: 0,
                        byte: 0,
                    },
                    role: RefRole::Import,
                    source_module: Some("codegraph . . . a/".into()),
                    from_path: Some("dependency::module".into()),
                    qualifier: None,
                    scope: None,
                    type_ref_ctx: None,
                },
            ],
            scopes: vec![Scope {
                parent: None,
                span: ByteSpan { start: 0, end: 11 },
                kind: ScopeKind::Module,
            }],
            bindings: vec![
                Binding {
                    scope: 0,
                    name: "run".into(),
                    intro: 0,
                    kind: BindingKind::Definition,
                    target: BindingTarget::Def(id.clone()),
                },
                Binding {
                    scope: 0,
                    name: "arg".into(),
                    intro: 1,
                    kind: BindingKind::Param,
                    target: BindingTarget::Local,
                },
                Binding {
                    scope: 0,
                    name: "dependency".into(),
                    intro: 2,
                    kind: BindingKind::Import,
                    target: BindingTarget::Import("dependency::module".into()),
                },
            ],
            ffi_exports: vec![FfiExport {
                symbol: id,
                abi: FfiAbi::C,
                export_name: "run".into(),
            }],
        }
    }

    #[test]
    fn fixed_dto_round_trips_every_file_facts_collection_and_nested_field() {
        let facts = facts();
        let wire = FileFactsWire::from(&facts);
        let restored: FileFacts = wire.clone().try_into().unwrap();
        assert_eq!(FileFactsWire::from(&restored), wire);
        assert_eq!(restored.symbols[0].id, facts.symbols[0].id);
    }

    #[test]
    fn response_validation_binds_facts_to_request_context() {
        let request = request();
        let response = WorkerResponse {
            version: PROTOCOL_VERSION,
            kind: 2,
            request_id: request.request_id,
            facts: Some(FileFactsWire::from(&facts())),
            error: None,
        };
        assert!(validate_response_facts(&response, &request).is_ok());

        let mut foreign = response.clone();
        foreign.facts.as_mut().unwrap().file = "src/b.rs".into();
        assert!(validate_response_facts(&foreign, &request).is_err());

        let mut wrong_language = response.clone();
        wrong_language.facts.as_mut().unwrap().lang = "python".into();
        assert!(validate_response_facts(&wrong_language, &request).is_err());

        let mut outside_source = response;
        outside_source.facts.as_mut().unwrap().symbols[0].span_end = 12;
        assert!(validate_response_facts(&outside_source, &request).is_err());
    }

    #[test]
    fn request_and_dto_caps_are_enforced() {
        let mut request = request();
        request.path = "x".repeat(MAX_STRING_BYTES + 1);
        assert!(validate_request(&request).is_err());

        let mut wire = FileFactsWire::from(&facts());
        wire.references[0].qualifier = Some("x".repeat(MAX_STRING_BYTES + 1));
        assert!(FileFacts::try_from(wire).is_err());
    }

    #[test]
    fn request_is_validated_against_the_admitted_inventory_file() {
        let bytes = b"fn run() {}".to_vec();
        let file = InventoryFile {
            path: ProjectPath::new(std::path::Path::new("src/a.rs")).unwrap(),
            language: Language::Rust,
            text: String::from_utf8(bytes.clone()).unwrap(),
            blake3: blake3::hash(&bytes).to_hex().to_string(),
            bytes,
            mtime: None,
        };
        let request = WorkerRequest::from_inventory_file(41, &file).unwrap();
        assert_eq!(
            validate_request_for_file(&request, &file).unwrap(),
            Language::Rust
        );

        let mut changed = request.clone();
        changed.source.push(b' ');
        assert!(validate_request_for_file(&changed, &file).is_err());
        let mut invalid_path = request.clone();
        invalid_path.path = "../a.rs".into();
        assert!(validate_request(&invalid_path).is_err());
        let mut invalid_utf8 = request.clone();
        invalid_utf8.source = vec![0xff];
        assert!(validate_request(&invalid_utf8).is_err());
        let mut mismatched_language = request;
        mismatched_language.language = language_to_tag(Language::Python);
        assert!(validate_request(&mismatched_language).is_err());
    }

    #[test]
    fn request_messagepack_schema_has_a_stable_numeric_golden() {
        let request = WorkerRequest {
            version: 1,
            kind: 1,
            request_id: 7,
            path: "a.rs".into(),
            language: 0,
            source: vec![0xff],
        };
        assert_eq!(
            zerompk::to_msgpack_vec(&request).unwrap(),
            [
                0x96, 0x01, 0x01, 0x07, 0xa4, b'a', b'.', b'r', b's', 0x00, 0xc4, 0x01, 0xff,
            ]
        );
    }

    #[test]
    fn numeric_enum_schema_is_exhaustive_and_stable() {
        for (expected, &language) in Language::ALL.iter().enumerate() {
            let expected = u16::try_from(expected).unwrap();
            assert_eq!(language_to_tag(language), expected);
            assert_eq!(language_from_tag(expected).unwrap(), language);
        }
        assert_eq!(
            [
                SymbolKind::Function,
                SymbolKind::Method,
                SymbolKind::Struct,
                SymbolKind::Enum,
                SymbolKind::Trait,
                SymbolKind::Interface,
                SymbolKind::Class,
                SymbolKind::TypeAlias,
                SymbolKind::Const,
                SymbolKind::Static,
                SymbolKind::Module,
                SymbolKind::Impl,
                SymbolKind::Table,
                SymbolKind::View,
                SymbolKind::Column,
                SymbolKind::Resource,
                SymbolKind::Other,
            ]
            .map(symbol_kind_tag),
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
        );
        assert_eq!(
            [
                RefRole::Call,
                RefRole::IsImplementation,
                RefRole::Import,
                RefRole::ModuleRef,
                RefRole::TypeRef,
                RefRole::Read,
                RefRole::Write,
            ]
            .map(ref_role_tag),
            [0, 1, 2, 3, 4, 5, 6]
        );
        assert_eq!(
            [
                Visibility::Public,
                Visibility::Internal,
                Visibility::Protected,
                Visibility::Private,
                Visibility::Unknown,
            ]
            .map(visibility_tag),
            [0, 1, 2, 3, 4]
        );
        assert_eq!(
            [
                TypeRefContext::ParameterType,
                TypeRefContext::ReturnType,
                TypeRefContext::Field,
                TypeRefContext::GenericArg,
                TypeRefContext::Attribute,
                TypeRefContext::Other,
            ]
            .map(type_ref_context_tag),
            [0, 1, 2, 3, 4, 5]
        );
        assert_eq!(
            [
                ScopeKind::Module,
                ScopeKind::Function,
                ScopeKind::Block,
                ScopeKind::Type,
                ScopeKind::Other,
            ]
            .map(scope_kind_tag),
            [0, 1, 2, 3, 4]
        );
        assert_eq!(
            [
                BindingKind::Local,
                BindingKind::Param,
                BindingKind::Import,
                BindingKind::Definition,
            ]
            .map(binding_kind_tag),
            [0, 1, 2, 3]
        );
        assert_eq!(
            [
                FfiAbi::C,
                FfiAbi::Python,
                FfiAbi::Wasm,
                FfiAbi::NodeApi,
                FfiAbi::Jni
            ]
            .map(ffi_abi_tag),
            [0, 1, 2, 3, 4]
        );
        let wire = FileFactsWire::from(&facts());
        assert_eq!(
            wire.symbols[0]
                .entry_points
                .iter()
                .map(|entry| entry.tag)
                .collect::<Vec<_>>(),
            [0, 1]
        );
        assert_eq!(
            wire.bindings
                .iter()
                .map(|binding| binding.target_tag)
                .collect::<Vec<_>>(),
            [2, 0, 1]
        );
    }

    #[test]
    fn unknown_and_inconsistent_dto_tags_are_rejected() {
        assert!(language_from_tag(u16::MAX).is_err());

        let mut symbol = FileFactsWire::from(&facts()).symbols.remove(0);
        symbol.kind = u8::MAX;
        assert!(Symbol::try_from(symbol).is_err());
        let mut symbol = FileFactsWire::from(&facts()).symbols.remove(0);
        symbol.visibility = u8::MAX;
        assert!(Symbol::try_from(symbol).is_err());
        let mut symbol = FileFactsWire::from(&facts()).symbols.remove(0);
        symbol.entry_points[0].tag = u8::MAX;
        assert!(Symbol::try_from(symbol).is_err());
        let mut symbol = FileFactsWire::from(&facts()).symbols.remove(0);
        symbol.id.version = u32::MAX;
        assert!(Symbol::try_from(symbol).is_err());

        let mut reference = FileFactsWire::from(&facts()).references.remove(0);
        reference.role = u8::MAX;
        assert!(Reference::try_from(reference).is_err());
        let mut reference = FileFactsWire::from(&facts()).references.remove(0);
        reference.type_ref_ctx = Some(u8::MAX);
        assert!(Reference::try_from(reference).is_err());

        let mut scope = FileFactsWire::from(&facts()).scopes.remove(0);
        scope.kind = u8::MAX;
        assert!(Scope::try_from(scope).is_err());

        let mut binding = FileFactsWire::from(&facts()).bindings.remove(0);
        binding.target_tag = u8::MAX;
        assert!(Binding::try_from(binding).is_err());
        let mut binding = FileFactsWire::from(&facts()).bindings.remove(0);
        binding.kind = u8::MAX;
        assert!(Binding::try_from(binding).is_err());

        let mut export = FileFactsWire::from(&facts()).ffi_exports.remove(0);
        export.abi = u8::MAX;
        assert!(FfiExport::try_from(export).is_err());
    }
}
