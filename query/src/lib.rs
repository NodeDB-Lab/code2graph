// SPDX-License-Identifier: Apache-2.0

//! Query-side indexes for `code2graph` facts.

pub mod error;
pub mod impact;
pub mod index;
mod order;
mod read;
pub mod relation;

pub use error::{QueryError, Result};
pub use impact::{ImpactOptions, ImpactResult, ImpactStep, impact};
pub use index::{EdgeFilter, GraphIndex};
pub use read::{GraphPage, GraphRead};
