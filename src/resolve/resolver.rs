// SPDX-License-Identifier: Apache-2.0

//! The [`Resolver`] trait — the tier seam every resolver implements.

use crate::{
    error::Result,
    graph::{CodeGraph, FileFacts},
};

/// Links references to definitions. Pure: no I/O, deterministic.
pub trait Resolver {
    /// Resolve facts into a graph of symbols and confidence-tagged edges.
    ///
    /// Every public resolution entry point validates the supplied facts before
    /// traversing scopes or deriving edges, returning a typed error for malformed
    /// untrusted input.
    fn resolve(&self, files: &[FileFacts]) -> Result<CodeGraph>;
}
