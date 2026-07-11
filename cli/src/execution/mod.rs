// SPDX-License-Identifier: Apache-2.0

//! Command execution lifecycle and presentation wiring.

mod cache_policy;
mod context;
mod lifecycle;
mod output;

pub use context::{Clock, ExecutionContext, SystemClock};
pub use lifecycle::{CommandOutput, LoadedGraph, execute, load_query_graph};
pub use output::render_human;
