// SPDX-License-Identifier: Apache-2.0

//! The trusted one-shot worker runtime.

use std::io::{Read, Write};

use code2graph::{
    BindingRules, Language, QueryBindingRule, extract_file_with_bindings, validate_file_facts,
};

use super::frame::{decode_request_frame, read_frame, reject_trailing_bytes, write_frame};
use super::protocol::{
    FileFactsWire, MAX_STRING_BYTES, PROTOCOL_VERSION, REQUEST_FRAME_MAX, RESPONSE_FRAME_MAX,
    WorkerErrorCode, WorkerErrorWire, WorkerProtocolError, WorkerResponse, validate_request,
};

/// Hidden sole argument which enters the worker runtime before CLI parsing.
pub const WORKER_SENTINEL: &str = "--code2graph-worker-v1";

/// True only for the exact hidden worker invocation.
pub fn is_worker_invocation(args: &[std::ffi::OsString]) -> bool {
    args.len() == 2 && args[1] == WORKER_SENTINEL
}

/// Processes exactly one request from `input` and writes exactly one response.
///
/// Malformed transport cannot be correlated safely and is returned to the caller as
/// an operational failure. Valid requests always receive either facts or a typed error.
pub fn run_worker<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
) -> Result<(), WorkerProtocolError> {
    let frame = read_frame(input, REQUEST_FRAME_MAX)?
        .ok_or(WorkerProtocolError::Malformed("missing request frame"))?;
    reject_trailing_bytes(input)?;
    let request = decode_request_frame(&frame)?;
    // Cross-artifact code→SQL edges are on by default: extraction applies the
    // built-in query-binding rules so embedded SQL in recognized constructs
    // (e.g. `sqlx::query("… FROM users")`) yields references to SQL entities.
    // Project-supplied custom rules (from `code2graph.toml`, wired through the
    // request) are layered on top of the defaults.
    let mut rules = BindingRules::with_defaults();
    for wire in &request.custom_rules {
        // A malformed/foreign advisory rule must never break extraction of an
        // otherwise-valid file: unknown lang tags and implausibly large strings
        // are skipped, not errored. (Bounds mirror the codebase's per-string cap
        // for wire data; genuine constructs are a few dozen bytes.)
        if wire.lang.len() > MAX_STRING_BYTES || wire.construct.len() > MAX_STRING_BYTES {
            continue;
        }
        if let Some(lang) = Language::from_tag(&wire.lang) {
            rules.register(QueryBindingRule {
                lang,
                construct: wire.construct.clone(),
                sql_arg: wire.sql_arg as usize,
            });
        }
    }
    let response = match validate_request(&request) {
        Ok(language) => match std::str::from_utf8(&request.source)
            .ok()
            .and_then(|source| {
                extract_file_with_bindings(language, source, &request.path, &rules).ok()
            })
            .filter(|facts| validate_file_facts(std::slice::from_ref(facts)).is_ok())
        {
            Some(facts) => WorkerResponse {
                version: PROTOCOL_VERSION,
                kind: 2,
                request_id: request.request_id,
                facts: Some(FileFactsWire::from(&facts)),
                error: None,
            },
            None => remote_error(&request, WorkerErrorCode::Extraction, "extraction failed"),
        },
        Err(_) => remote_error(&request, WorkerErrorCode::InvalidRequest, "invalid request"),
    };
    write_frame(output, &response, RESPONSE_FRAME_MAX)
}

fn remote_error(
    request: &super::protocol::WorkerRequest,
    code: WorkerErrorCode,
    message: &str,
) -> WorkerResponse {
    WorkerResponse {
        version: PROTOCOL_VERSION,
        kind: 2,
        request_id: request.request_id,
        facts: None,
        error: Some(WorkerErrorWire {
            code: code as u16,
            message: message.into(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::super::frame::{decode_response_frame, encode_frame};
    use super::super::protocol::{QueryBindingRuleWire, WorkerRequest, validate_response};
    use super::*;

    fn request(path: &str, source: &[u8]) -> WorkerRequest {
        WorkerRequest {
            version: PROTOCOL_VERSION,
            kind: 1,
            request_id: 4,
            path: path.into(),
            language: 0,
            source: source.into(),
            custom_rules: Vec::new(),
        }
    }

    #[test]
    fn runtime_extracts_a_valid_request() {
        let request = request("src/a.rs", b"fn run() {}");
        let mut input = std::io::Cursor::new(encode_frame(&request, REQUEST_FRAME_MAX).unwrap());
        let mut output = Vec::new();
        run_worker(&mut input, &mut output).unwrap();
        assert!(
            validate_response(&decode_response_frame(&output).unwrap(), &request)
                .unwrap()
                .is_ok()
        );
    }

    #[test]
    fn runtime_round_trip_accepts_qualified_and_renamed_reexports() {
        for source in [
            b"pub use inner::Thing as T;".as_slice(),
            b"pub use inner::deep;".as_slice(),
            b"pub use inner::deep::d;".as_slice(),
            b"pub use crate::inner::helper;".as_slice(),
        ] {
            let request = request("src/lib.rs", source);
            let mut input =
                std::io::Cursor::new(encode_frame(&request, REQUEST_FRAME_MAX).unwrap());
            let mut output = Vec::new();
            run_worker(&mut input, &mut output).unwrap();
            assert!(
                validate_response(&decode_response_frame(&output).unwrap(), &request)
                    .unwrap()
                    .is_ok(),
                "worker rejected {}",
                String::from_utf8_lossy(source)
            );
        }
    }

    #[test]
    fn runtime_applies_custom_query_binding_rules_from_the_request() {
        let mut req = request(
            "src/app.rs",
            b"pub fn f() { mydb::sql(\"SELECT id FROM users\"); }",
        );
        req.custom_rules = vec![QueryBindingRuleWire {
            lang: "rust".into(),
            construct: "mydb::sql".into(),
            sql_arg: 0,
        }];
        let mut input = std::io::Cursor::new(encode_frame(&req, REQUEST_FRAME_MAX).unwrap());
        let mut output = Vec::new();
        run_worker(&mut input, &mut output).unwrap();
        let response = decode_response_frame(&output).unwrap();
        let facts = response.facts.expect("valid request should produce facts");
        assert!(
            facts
                .references
                .iter()
                // role 4 == RefRole::TypeRef (see `ref_role_tag` in protocol.rs).
                .any(|r| r.name == "users" && r.role == 4 && r.cross_artifact == Some(true)),
            "expected a cross-artifact TypeRef reference named 'users' from the custom rule, got {:?}",
            facts.references
        );
    }

    #[test]
    fn runtime_returns_typed_error_for_invalid_request_and_utf8() {
        for request in [
            request("src/a.py", b"fn run() {}"),
            request("src/a.rs", &[0xff]),
        ] {
            let mut input =
                std::io::Cursor::new(encode_frame(&request, REQUEST_FRAME_MAX).unwrap());
            let mut output = Vec::new();
            run_worker(&mut input, &mut output).unwrap();
            let response = decode_response_frame(&output).unwrap();
            let remote = response.error.unwrap();
            assert_eq!(remote.code, WorkerErrorCode::InvalidRequest as u16);
            assert_eq!(remote.message, "invalid request");
        }
    }

    #[test]
    fn runtime_rejects_eof_malformed_trailing_and_second_frame() {
        assert!(run_worker(&mut std::io::Cursor::new(Vec::<u8>::new()), &mut Vec::new()).is_err());
        assert!(run_worker(&mut std::io::Cursor::new(vec![0, 0]), &mut Vec::new()).is_err());
        let frame = encode_frame(&request("src/a.rs", b"fn run() {}"), REQUEST_FRAME_MAX).unwrap();
        let mut trailing = frame.clone();
        trailing.push(0);
        assert!(run_worker(&mut std::io::Cursor::new(trailing), &mut Vec::new()).is_err());
        let mut second = frame.clone();
        second.extend_from_slice(&frame);
        assert!(run_worker(&mut std::io::Cursor::new(second), &mut Vec::new()).is_err());
    }
}
