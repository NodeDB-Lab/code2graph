// SPDX-License-Identifier: Apache-2.0

//! Optional package enrichment: stamp `Package` identity onto extracted facts.
//!
//! The dep-free [`enrich`] function and [`SymbolId::with_package`] are always
//! available. Manifest parsing (`from_manifest`) is behind the `manifest`
//! cargo feature and pulls `toml`/`serde`/`serde_json`.
//!
//! Entry point: `code2graph::package::enrich(&mut facts, &pkg)`.

pub mod enrich;
#[cfg(feature = "manifest")]
pub mod manifest;

pub use enrich::enrich;
#[cfg(feature = "manifest")]
pub use manifest::from_manifest;
