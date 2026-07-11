// SPDX-License-Identifier: Apache-2.0

//! Selector evaluation over a loaded structural graph.

mod position;
mod resolve;
mod types;

pub use resolve::{build_graph_index, resolve_selector};
pub use types::{
    SelectorContext, SelectorOptions, SelectorPurpose, SelectorRequest, SelectorResolution,
    SelectorSummary,
};
