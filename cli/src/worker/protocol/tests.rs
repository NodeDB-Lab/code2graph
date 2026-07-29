// SPDX-License-Identifier: Apache-2.0

//! Protocol regression tests.

use super::*;

use super::tags::{
    binding_kind_tag, ffi_abi_tag, ref_role_tag, scope_kind_tag, symbol_kind_tag,
    type_ref_context_tag, visibility_tag,
};
use crate::{InventoryFile, ProjectPath};
use code2graph::{
    Binding, BindingKind, BindingTarget, ByteSpan, EntryPoint, FfiAbi, FfiExport, FileFacts,
    Language, Occurrence, RefRole, Reference, Scope, ScopeKind, Symbol, SymbolId, SymbolKind,
    TypeRefContext, Visibility,
};

use code2graph::Descriptor;

fn request() -> WorkerRequest {
    WorkerRequest {
        version: PROTOCOL_VERSION,
        kind: 1,
        request_id: 7,
        path: "src/a.rs".into(),
        language: 0,
        source: b"fn run() {}".to_vec(),
        custom_rules: Vec::new(),
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
                imported_name: None,
                is_reexport: false,
                qualifier: Some("crate::module".into()),
                scope: Some(0),
                type_ref_ctx: Some(TypeRefContext::ReturnType),
                cross_artifact: false,
                self_receiver: false,
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
                imported_name: None,
                is_reexport: false,
                qualifier: None,
                scope: None,
                type_ref_ctx: None,
                cross_artifact: false,
                self_receiver: false,
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
                type_name: None,
            },
            Binding {
                scope: 0,
                name: "arg".into(),
                intro: 1,
                kind: BindingKind::Param,
                target: BindingTarget::Local,
                type_name: Some("Repo".into()),
            },
            Binding {
                scope: 0,
                name: "dependency".into(),
                intro: 2,
                kind: BindingKind::Import,
                target: BindingTarget::Import("dependency::module".into()),
                type_name: None,
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
fn manual_codecs_round_trip_nested_records_and_default_optional_fields() {
    let wire = FileFactsWire::from(&facts());
    let encoded = zerompk::to_msgpack_vec(&wire).unwrap();
    assert_eq!(
        zerompk::from_msgpack::<FileFactsWire>(&encoded).unwrap(),
        wire
    );

    let response_without_optional_payloads = [0x83, 0x00, 0x01, 0x01, 0x02, 0x02, 0x07];
    assert_eq!(
        zerompk::from_msgpack::<WorkerResponse>(&response_without_optional_payloads).unwrap(),
        WorkerResponse {
            version: 1,
            kind: 2,
            request_id: 7,
            facts: None,
            error: None
        }
    );
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
    assert!(matches!(
        validate_response_detailed(&foreign, &request),
        Err(DetailedWorkerResponseError::InvalidFacts { .. })
    ));

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
    let request = WorkerRequest::from_inventory_file(41, &file, &[]).unwrap();
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
        custom_rules: Vec::new(),
    };
    assert_eq!(
        zerompk::to_msgpack_vec(&request).unwrap(),
        [
            0x87, 0x00, 0x01, 0x01, 0x01, 0x02, 0x07, 0x03, 0xa4, b'a', b'.', b'r', b's', 0x04,
            0x00, 0x05, 0xc4, 0x01, 0xff, 0x06, 0x90,
        ]
    );
}

#[test]
fn request_round_trips_custom_rules() {
    let mut request = request();
    request.custom_rules = vec![
        QueryBindingRuleWire {
            lang: "rust".into(),
            construct: "mydb::sql".into(),
            sql_arg: 0,
        },
        QueryBindingRuleWire {
            lang: "python".into(),
            construct: "mydb.execute".into(),
            sql_arg: 1,
        },
    ];
    let encoded = zerompk::to_msgpack_vec(&request).unwrap();
    assert_eq!(
        zerompk::from_msgpack::<WorkerRequest>(&encoded).unwrap(),
        request
    );
}

#[test]
fn every_codec_emits_its_complete_map_in_ascending_numeric_key_order() {
    let response = WorkerResponse {
        version: 1,
        kind: 2,
        request_id: 7,
        facts: None,
        error: None,
    };
    assert_eq!(
        zerompk::to_msgpack_vec(&response).unwrap(),
        [0x85, 0, 1, 1, 2, 2, 7, 3, 0xc0, 4, 0xc0]
    );
    assert_eq!(
        zerompk::to_msgpack_vec(&ScopeWire {
            parent: None,
            start: 1,
            end: 2,
            kind: 3,
        })
        .unwrap(),
        [0x84, 0, 0xc0, 1, 1, 2, 2, 3, 3]
    );

    let wire = FileFactsWire::from(&facts());
    let encoded = zerompk::to_msgpack_vec(&wire).unwrap();
    assert_eq!(encoded[0], 0x87);
    assert_eq!(
        zerompk::from_msgpack::<FileFactsWire>(&encoded).unwrap(),
        wire
    );
}

#[test]
fn numeric_map_decode_is_order_independent_and_strict_about_required_keys() {
    let reordered = [
        0x86, 0x05, 0xc4, 0x01, 0xff, 0x04, 0x00, 0x03, 0xa4, b'a', b'.', b'r', b's', 0x02, 0x07,
        0x01, 0x01, 0x00, 0x01,
    ];
    assert_eq!(
        zerompk::from_msgpack::<WorkerRequest>(&reordered)
            .unwrap()
            .request_id,
        7
    );
    let with_unknown = [
        0x87, 0x00, 0x01, 0x01, 0x01, 0x02, 0x07, 0x03, 0xa4, b'a', b'.', b'r', b's', 0x04, 0x00,
        0x05, 0xc4, 0x01, 0xff, 0x63, 0xc0,
    ];
    assert!(zerompk::from_msgpack::<WorkerRequest>(&with_unknown).is_ok());
    let missing = [0x81, 0x00, 0x01];
    assert!(zerompk::from_msgpack::<WorkerRequest>(&missing).is_err());
    let duplicate = [
        0x87, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x02, 0x07, 0x03, 0xa4, b'a', b'.', b'r', b's',
        0x04, 0x00, 0x05, 0xc4, 0x01, 0xff,
    ];
    assert!(zerompk::from_msgpack::<WorkerRequest>(&duplicate).is_err());

    // Future unsigned keys are not restricted to the current u8 key range,
    // and their values may have any bounded MessagePack shape.
    let future_key_and_nested_value = [
        0x87, 0x00, 0x01, 0x01, 0x01, 0x02, 0x07, 0x03, 0xa4, b'a', b'.', b'r', b's', 0x04, 0x00,
        0x05, 0xc4, 0x01, 0xff, 0xcd, 0x01, 0x2c, 0x92, 0x81, 0xa1, b'x', 0xd4, 0x01, 0xff, 0xc0,
    ];
    assert!(zerompk::from_msgpack::<WorkerRequest>(&future_key_and_nested_value).is_ok());

    let duplicate_optional_nil = [0x86, 0, 1, 1, 2, 2, 7, 3, 0xc0, 3, 0xc0, 4, 0xc0];
    assert!(zerompk::from_msgpack::<WorkerResponse>(&duplicate_optional_nil).is_err());
    assert!(zerompk::from_msgpack::<WorkerErrorWire>(&[0x81, 0, 1]).is_err());
    assert!(zerompk::from_msgpack::<ScopeWire>(&[0x83, 0, 0xc0, 2, 2, 3, 3]).is_err());
}

#[test]
fn response_validation_enforces_xor_error_code_and_message_cap() {
    let request = request();
    let success = WorkerResponse {
        version: PROTOCOL_VERSION,
        kind: 2,
        request_id: request.request_id,
        facts: Some(FileFactsWire::from(&facts())),
        error: None,
    };
    assert!(matches!(validate_response(&success, &request), Ok(Ok(_))));

    let mut response = success.clone();
    response.facts = None;
    response.error = Some(WorkerErrorWire {
        code: WorkerErrorCode::Extraction as u16,
        message: "failed".into(),
    });
    assert!(matches!(validate_response(&response, &request), Ok(Err(_))));
    response.error.as_mut().unwrap().code = u16::MAX;
    assert!(validate_response(&response, &request).is_err());
    assert!(matches!(
        validate_response_detailed(&response, &request),
        Err(DetailedWorkerResponseError::Protocol(WorkerProtocolError::Facts(message)))
            if message == "unknown worker error code"
    ));
    response.error.as_mut().unwrap().code = WorkerErrorCode::Internal as u16;
    response.error.as_mut().unwrap().message = "x".repeat(MAX_ERROR_MESSAGE_BYTES + 1);
    assert!(validate_response(&response, &request).is_err());
    assert!(matches!(
        validate_response_detailed(&response, &request),
        Err(DetailedWorkerResponseError::Protocol(WorkerProtocolError::Facts(message)))
            if message == "worker error message exceeds limit"
    ));

    let mut both = success.clone();
    both.error = Some(WorkerErrorWire {
        code: 1,
        message: String::new(),
    });
    assert!(validate_response(&both, &request).is_err());
    let mut neither = success;
    neither.facts = None;
    assert!(validate_response(&neither, &request).is_err());
}

#[test]
fn invalid_wire_facts_are_protocol_failures() {
    let request = request();
    let mut wire = FileFactsWire::from(&facts());
    wire.symbols[0].kind = u8::MAX;
    let response = WorkerResponse {
        version: PROTOCOL_VERSION,
        kind: 2,
        request_id: request.request_id,
        facts: Some(wire),
        error: None,
    };

    assert!(matches!(
        validate_response_detailed(&response, &request),
        Err(DetailedWorkerResponseError::Protocol(WorkerProtocolError::Facts(message)))
            if message == "unknown enum tag"
    ));
}

#[test]
fn private_invalid_facts_wire_code_preserves_legacy_public_response_shape() {
    let request = request();
    let response = WorkerResponse {
        version: PROTOCOL_VERSION,
        kind: 2,
        request_id: request.request_id,
        facts: None,
        error: Some(WorkerErrorWire {
            code: INVALID_FACTS_ERROR_CODE,
            message: "context validation failed".into(),
        }),
    };
    assert!(matches!(
        validate_response(&response, &request),
        Ok(Err(WorkerRemoteError {
            code: WorkerErrorCode::Extraction,
            ..
        }))
    ));
    assert!(matches!(
        validate_response_detailed(&response, &request),
        Ok(DetailedWorkerResponse::InvalidFacts { .. })
    ));
    let _: WorkerErrorCode = WorkerErrorCode::Extraction;
    assert_eq!(WorkerErrorCode::Extraction as u16, 1);
    assert_eq!(WorkerErrorCode::InvalidRequest as u16, 2);
    assert_eq!(WorkerErrorCode::Internal as u16, 3);
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
            SymbolKind::Field,
            SymbolKind::Variant,
        ]
        .map(symbol_kind_tag),
        [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18
        ]
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
