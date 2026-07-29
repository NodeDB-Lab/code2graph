// SPDX-License-Identifier: Apache-2.0

//! Request and response validation.

use super::conversion::cap;
use super::*;

use code2graph::{
    FileFacts, FileFactsValidationContext, Language, QueryBindingRule,
    validate_file_facts_with_context,
};

use crate::{InventoryFile, ProjectPath};

impl WorkerRequest {
    /// Build and validate a request from an admitted inventory file, carrying
    /// `rules` (project-supplied custom query-binding rules, sourced from
    /// `code2graph.toml`) to the worker as wire DTOs.
    pub fn from_inventory_file(
        request_id: RequestId,
        file: &InventoryFile,
        rules: &[QueryBindingRule],
    ) -> Result<Self, WorkerProtocolError> {
        validate_inventory_file(file)?;
        let request = Self {
            version: PROTOCOL_VERSION,
            kind: 1,
            request_id,
            path: file.path.as_str().to_owned(),
            language: language_to_tag(file.language),
            source: file.bytes.clone(),
            custom_rules: rules
                .iter()
                .map(|rule| QueryBindingRuleWire {
                    lang: rule.lang.as_str().to_owned(),
                    construct: rule.construct.clone(),
                    sql_arg: rule.sql_arg as u64,
                })
                .collect(),
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

/// Crate-private response classification that retains protocol-only worker
/// validation failures for refresh recovery.
#[derive(Debug, Clone)]
pub(crate) enum DetailedWorkerResponse {
    Facts(FileFacts),
    Remote(WorkerRemoteError),
    InvalidFacts { message: String },
}

/// Internal response-validation distinction used by worker clients: only
/// decoded facts that fail their request context are safe to omit.
#[derive(Debug)]
pub(crate) enum DetailedWorkerResponseError {
    InvalidFacts { message: String },
    Protocol(WorkerProtocolError),
}

/// Validate response identity and its exactly-one-of facts/error payload.
///
/// Protocol-only invalid-facts responses retain their legacy public shape as an
/// extraction failure. Internal callers use `validate_response_detailed` to
/// distinguish them without inspecting an error message.
pub fn validate_response(
    response: &WorkerResponse,
    request: &WorkerRequest,
) -> Result<WorkerResponseResult, WorkerProtocolError> {
    match validate_response_detailed(response, request) {
        Ok(DetailedWorkerResponse::Facts(facts)) => Ok(Ok(facts)),
        Ok(DetailedWorkerResponse::Remote(error)) => Ok(Err(error)),
        Ok(DetailedWorkerResponse::InvalidFacts { message }) => Ok(Err(WorkerRemoteError {
            code: WorkerErrorCode::Extraction,
            message,
        })),
        Err(DetailedWorkerResponseError::InvalidFacts { message }) => {
            Err(WorkerProtocolError::Facts(message))
        }
        Err(DetailedWorkerResponseError::Protocol(error)) => Err(error),
    }
}

pub(crate) fn validate_response_detailed(
    response: &WorkerResponse,
    request: &WorkerRequest,
) -> Result<DetailedWorkerResponse, DetailedWorkerResponseError> {
    let language = validate_request(request).map_err(DetailedWorkerResponseError::Protocol)?;
    if response.version != PROTOCOL_VERSION {
        return Err(DetailedWorkerResponseError::Protocol(
            WorkerProtocolError::Version(response.version),
        ));
    }
    if response.kind != 2 {
        return Err(DetailedWorkerResponseError::Protocol(
            WorkerProtocolError::Kind(response.kind),
        ));
    }
    if response.request_id != request.request_id {
        return Err(DetailedWorkerResponseError::Protocol(
            WorkerProtocolError::Malformed("response request ID mismatch"),
        ));
    }
    match (&response.facts, &response.error) {
        (Some(facts), None) => {
            let facts: FileFacts = facts
                .clone()
                .try_into()
                .map_err(DetailedWorkerResponseError::Protocol)?;
            validate_file_facts_with_context(
                &facts,
                FileFactsValidationContext {
                    expected_file: &request.path,
                    expected_language: language,
                    source_len: request.source.len(),
                },
            )
            .map_err(|error| DetailedWorkerResponseError::InvalidFacts {
                message: error.to_string(),
            })?;
            Ok(DetailedWorkerResponse::Facts(facts))
        }
        (None, Some(error)) => {
            if error.message.len() > MAX_ERROR_MESSAGE_BYTES {
                return Err(DetailedWorkerResponseError::Protocol(
                    WorkerProtocolError::Facts("worker error message exceeds limit".into()),
                ));
            }
            match WorkerResponseErrorCode::from_wire(error.code)
                .map_err(DetailedWorkerResponseError::Protocol)?
            {
                WorkerResponseErrorCode::Public(code) => {
                    Ok(DetailedWorkerResponse::Remote(WorkerRemoteError {
                        code,
                        message: error.message.clone(),
                    }))
                }
                WorkerResponseErrorCode::InvalidFacts => Ok(DetailedWorkerResponse::InvalidFacts {
                    message: error.message.clone(),
                }),
            }
        }
        (Some(_), Some(_)) => Err(DetailedWorkerResponseError::Protocol(
            WorkerProtocolError::Malformed("response carries both facts and error"),
        )),
        (None, None) => Err(DetailedWorkerResponseError::Protocol(
            WorkerProtocolError::Malformed("response carries neither facts nor error"),
        )),
    }
}

/// Validate and require a successful response.
pub fn validate_response_facts(
    response: &WorkerResponse,
    request: &WorkerRequest,
) -> Result<FileFacts, WorkerProtocolError> {
    validate_response(response, request)?.map_err(|_| {
        WorkerProtocolError::Malformed("response carries an error instead of success facts")
    })
}
