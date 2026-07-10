// SPDX-License-Identifier: Apache-2.0

//! SCIP-aligned symbol identity: descriptors and `SymbolId`.

pub mod descriptor;
pub mod id;
#[cfg(feature = "serde")]
mod serde_impl;

pub use descriptor::{Descriptor, MethodDisambiguator};
pub use id::{Package, SCHEME, SymbolId, SymbolParseError};
