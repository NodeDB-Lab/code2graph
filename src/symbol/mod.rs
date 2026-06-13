// SPDX-License-Identifier: Apache-2.0

//! SCIP-aligned symbol identity: descriptors and `SymbolId`.

pub mod descriptor;
pub mod id;

pub use descriptor::Descriptor;
pub use id::{Package, SymbolId, SCHEME};
