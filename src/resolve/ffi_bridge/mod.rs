// SPDX-License-Identifier: Apache-2.0

//! FFI-bridge resolver — links cross-language call sites to FFI exports.
//!
//! Some definitions are deliberately exposed across a runtime boundary: a Rust
//! `#[no_mangle]` function is callable from C under a stable linker name, and a
//! PyO3 `#[pyfunction]` is callable from Python. The extractor records each as a
//! neutral [`FfiExport`] fact (tagged with its [`FfiAbi`]); this resolver bridges
//! it to call sites in a language that **consumes that ABI**
//! ([`FfiAbi::consumers`]) — so a C call binds to a C-ABI export, a Python call
//! to a Python-ABI export, never crossed.
//!
//! It is the honest, deterministic subset of cross-language linking: the export
//! side is grounded in a real syntactic marker, and the bridge fires only across
//! a language boundary (a definition's own language never consumes its ABI, so
//! same-language use is an ordinary call, not an FFI crossing). The consumer side
//! is matched by name, so edges carry honest
//! confidence — [`Confidence::Scoped`] when the export is unique, otherwise
//! [`Confidence::NameOnly`] — and always [`Provenance::FfiBridge`], so a consumer
//! can treat boundary-crossing edges distinctly.
//!
//! Composability: this resolver emits **only** bridge edges. A consumer that
//! wants intra-language resolution too runs a tier resolver
//! ([`SymbolTableResolver`](crate::SymbolTableResolver) /
//! [`ScopeGraphResolver`](crate::ScopeGraphResolver)) and concatenates the edge
//! sets — every tier emits the same schema.
//!
//! [`Confidence::Scoped`]: crate::graph::Confidence::Scoped
//! [`Confidence::NameOnly`]: crate::graph::Confidence::NameOnly
//! [`Provenance::FfiBridge`]: crate::graph::Provenance::FfiBridge
//! [`FfiExport`]: crate::graph::FfiExport

mod resolver;

pub use resolver::FfiBridgeResolver;
