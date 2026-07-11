// SPDX-License-Identifier: Apache-2.0

//! Node.js / Bun bindings for code2graph.

mod api;
mod convert;
mod query;

pub use api::{build_graph, extract, language_of};
pub use query::GraphIndex;
