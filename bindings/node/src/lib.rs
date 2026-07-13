// SPDX-License-Identifier: Apache-2.0

//! Node.js / Bun bindings for code2graph.

mod api;
mod convert;
mod query;

pub use api::{QueryBindingRuleInput, build_graph, extract, extract_with_bindings, language_of};
pub use query::GraphIndex;
