// SPDX-License-Identifier: Apache-2.0

//! Resolution: link references to definitions, producing cross-file edges.
//!
//! A [`Resolver`] takes per-file [`FileFacts`] and returns a resolved
//! [`CodeGraph`]. The trait is the **tier seam**: every resolver emits the same
//! schema, tagging each edge with a [`Confidence`]. codegraph ships a fast,
//! broad [`SymbolTableResolver`] (Tier A — name/scope matching across all
//! languages); a precise stack-graphs resolver (Tier B) can slot in behind the
//! same trait per language without changing the output shape.
//!
//! [`Confidence`]: crate::graph::Confidence

use crate::graph::{CodeGraph, FileFacts};

pub mod symbol_table;

pub use symbol_table::SymbolTableResolver;

/// Links references to definitions. Pure: no I/O, deterministic.
pub trait Resolver {
    /// Resolve `files` into a graph of symbols and confidence-tagged edges.
    fn resolve(&self, files: &[FileFacts]) -> CodeGraph;
}
