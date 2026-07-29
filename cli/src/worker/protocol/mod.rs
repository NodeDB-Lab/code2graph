// SPDX-License-Identifier: Apache-2.0

//! Versioned worker envelopes and their bounded MessagePack protocol.

mod codec;
mod conversion;
mod tags;
#[cfg(test)]
mod tests;
mod types;
mod validation;

pub use tags::{language_from_tag, language_to_tag};
pub use types::*;
pub(crate) use validation::{
    DetailedWorkerResponse, DetailedWorkerResponseError, validate_response_detailed,
};
pub use validation::{
    validate_request, validate_request_for_file, validate_response, validate_response_facts,
};
