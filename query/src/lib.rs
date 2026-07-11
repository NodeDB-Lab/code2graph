// SPDX-License-Identifier: Apache-2.0

//! Query-side indexes and snapshot-delta application for `code2graph` facts.

pub mod error;
#[cfg(test)]
mod order;

pub use error::{QueryError, Result};
