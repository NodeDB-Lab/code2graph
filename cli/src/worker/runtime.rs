// SPDX-License-Identifier: Apache-2.0

//! The trusted one-shot worker runtime.

use std::io::{Read, Write};

use code2graph::{extract_file, validate_file_facts};

use super::frame::{decode_request_frame, read_frame, reject_trailing_bytes, write_frame};
use super::protocol::{
    FileFactsWire, PROTOCOL_VERSION, REQUEST_FRAME_MAX, RESPONSE_FRAME_MAX, WorkerErrorCode,
    WorkerErrorWire, WorkerProtocolError, WorkerResponse, validate_request,
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
    let response = match validate_request(&request) {
        Ok(language) => match std::str::from_utf8(&request.source)
            .ok()
            .and_then(|source| extract_file(language, source, &request.path).ok())
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
    use super::super::protocol::{WorkerRequest, validate_response};
    use super::*;

    fn request(path: &str, source: &[u8]) -> WorkerRequest {
        WorkerRequest {
            version: PROTOCOL_VERSION,
            kind: 1,
            request_id: 4,
            path: path.into(),
            language: 0,
            source: source.into(),
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
