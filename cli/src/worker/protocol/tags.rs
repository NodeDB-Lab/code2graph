// SPDX-License-Identifier: Apache-2.0

//! Stable append-only numeric tags for protocol enums.

use super::*;

use code2graph::{
    BindingKind, FfiAbi, Language, RefRole, ScopeKind, SymbolKind, TypeRefContext, Visibility,
};

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

pub(super) const fn symbol_kind_tag(value: SymbolKind) -> u8 {
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
        SymbolKind::Field => 17,
        SymbolKind::Variant => 18,
    }
}
pub(super) const fn visibility_tag(value: Visibility) -> u8 {
    match value {
        Visibility::Public => 0,
        Visibility::Internal => 1,
        Visibility::Protected => 2,
        Visibility::Private => 3,
        Visibility::Unknown => 4,
    }
}
pub(super) const fn ref_role_tag(value: RefRole) -> u8 {
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
pub(super) const fn type_ref_context_tag(value: TypeRefContext) -> u8 {
    match value {
        TypeRefContext::ParameterType => 0,
        TypeRefContext::ReturnType => 1,
        TypeRefContext::Field => 2,
        TypeRefContext::GenericArg => 3,
        TypeRefContext::Attribute => 4,
        TypeRefContext::Other => 5,
    }
}
pub(super) const fn scope_kind_tag(value: ScopeKind) -> u8 {
    match value {
        ScopeKind::Module => 0,
        ScopeKind::Function => 1,
        ScopeKind::Block => 2,
        ScopeKind::Type => 3,
        ScopeKind::Other => 4,
    }
}
pub(super) const fn binding_kind_tag(value: BindingKind) -> u8 {
    match value {
        BindingKind::Local => 0,
        BindingKind::Param => 1,
        BindingKind::Import => 2,
        BindingKind::Definition => 3,
    }
}
pub(super) const fn ffi_abi_tag(value: FfiAbi) -> u8 {
    match value {
        FfiAbi::C => 0,
        FfiAbi::Python => 1,
        FfiAbi::Wasm => 2,
        FfiAbi::NodeApi => 3,
        FfiAbi::Jni => 4,
    }
}
