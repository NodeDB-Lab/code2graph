// SPDX-License-Identifier: Apache-2.0

//! Isolated one-shot extraction worker protocol and process boundary.

mod frame;
mod platform;
mod process;
mod protocol;
mod runtime;

pub use process::{WorkerFailure, extract_inventory_file};
pub use protocol::{
    BindingWire, EntryPointWire, FfiExportWire, FileFactsWire, OccurrenceWire, PROTOCOL_VERSION,
    QueryBindingRuleWire, REQUEST_FRAME_MAX, RESPONSE_FRAME_MAX, ReferenceWire, RequestId,
    ScopeWire, SymbolIdWireDto, SymbolWire, WorkerErrorCode, WorkerErrorWire, WorkerProtocolError,
    WorkerRemoteError, WorkerRequest, WorkerResponse, language_from_tag, language_to_tag,
    validate_request, validate_request_for_file, validate_response, validate_response_facts,
};
pub use runtime::{WORKER_SENTINEL, is_worker_invocation, run_worker};
