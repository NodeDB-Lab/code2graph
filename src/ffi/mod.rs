// SPDX-License-Identifier: Apache-2.0
//! Neutral per-ABI FFI registry: one self-contained spec file per `FfiAbi`.
//! Both the producer extractors (marker→ABI classification) and the bridge
//! resolver (consumer matrix) read from here, so adding an ABI is one spec file
//! plus one `SPECS` entry — never a growing match or an inline extractor block.
#[cfg(any(feature = "rust", feature = "c", feature = "cpp"))]
mod c;
#[cfg(any(feature = "rust", feature = "c", feature = "java"))]
mod jni;
#[cfg(any(feature = "rust", feature = "typescript"))]
mod node_api;
#[cfg(any(feature = "rust", feature = "python"))]
mod python;
mod spec;
#[cfg(any(feature = "rust", feature = "typescript"))]
mod wasm;

#[cfg(all(test, any(feature = "rust", feature = "c")))]
mod sync_tests;

#[cfg(feature = "c")]
pub(crate) use spec::c_name_export_abi;
pub(crate) use spec::consumers;
#[cfg(feature = "rust")]
pub(crate) use spec::rust_exports;
