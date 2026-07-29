// SPDX-License-Identifier: Apache-2.0

//! Conversion between protocol DTOs and code2graph facts.

use super::tags::*;
use super::*;

use code2graph::{
    Binding, BindingKind, BindingTarget, ByteSpan, EntryPoint, FfiAbi, FfiExport, FileFacts,
    Occurrence, RefRole, Reference, Scope, ScopeKind, Symbol, SymbolId, SymbolIdWire, SymbolKind,
    TypeRefContext, Visibility,
};

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
pub(super) fn cap(s: &str) -> Result<(), WorkerProtocolError> {
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
            SymbolKind::Field,
            SymbolKind::Variant,
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
            imported_name: r.imported_name.clone(),
            is_reexport: Some(r.is_reexport),
            qualifier: r.qualifier.clone(),
            scope: r.scope.map(|v| v as u64),
            type_ref_ctx: r.type_ref_ctx.map(type_ref_context_tag),
            cross_artifact: Some(r.cross_artifact),
            self_receiver: Some(r.self_receiver),
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
        cap_option(&r.imported_name)?;
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
            imported_name: r.imported_name,
            is_reexport: r.is_reexport.unwrap_or(false),
            qualifier: r.qualifier,
            scope: r.scope.map(usize_from).transpose()?,
            type_ref_ctx: r.type_ref_ctx.map(|v| tag(v, &ctx).copied()).transpose()?,
            cross_artifact: r.cross_artifact.unwrap_or(false),
            self_receiver: r.self_receiver.unwrap_or(false),
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
            type_name: b.type_name.clone(),
        }
    }
}
impl TryFrom<BindingWire> for Binding {
    type Error = WorkerProtocolError;
    fn try_from(b: BindingWire) -> Result<Self, Self::Error> {
        cap(&b.name)?;
        cap_option(&b.target_value)?;
        cap_option(&b.type_name)?;
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
            type_name: b.type_name,
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
