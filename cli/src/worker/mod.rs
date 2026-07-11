// SPDX-License-Identifier: Apache-2.0

//! Bounded worker wire protocol (transport only; no process management).

mod frame;
mod protocol;

pub use frame::{decode_request_frame, decode_response_frame, encode_frame};
pub use protocol::{
    BindingWire, EntryPointWire, FfiExportWire, FileFactsWire, OccurrenceWire, PROTOCOL_VERSION,
    REQUEST_FRAME_MAX, RESPONSE_FRAME_MAX, ReferenceWire, RequestId, ScopeWire, SymbolIdWireDto,
    SymbolWire, WorkerErrorWire, WorkerProtocolError, WorkerRequest, WorkerResponse,
    language_from_tag, language_to_tag, validate_request, validate_request_for_file,
    validate_response_facts,
};
