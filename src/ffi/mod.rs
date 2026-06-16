// SPDX-License-Identifier: Apache-2.0
//! Neutral per-ABI FFI registry: one self-contained spec file per `FfiAbi`.
//! Both the producer extractors (marker→ABI classification) and the bridge
//! resolver (consumer matrix) read from here, so adding an ABI is one spec file
//! plus one `SPECS` entry — never a growing match or an inline extractor block.
mod c;
mod jni;
mod node_api;
mod python;
mod spec;
mod wasm;

pub(crate) use spec::{c_name_export_abi, consumers, rust_exports};
