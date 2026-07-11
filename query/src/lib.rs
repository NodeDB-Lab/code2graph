// SPDX-License-Identifier: Apache-2.0

//! Query-side indexes for `code2graph` facts.

pub mod error;
pub mod index;
mod order;

pub use error::{QueryError, Result};
pub use index::GraphIndex;
