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

use std::collections::HashMap;

use crate::graph::types::{
    CodeGraph, Confidence, Edge, FfiAbi, FileFacts, Provenance, RefRole, Symbol,
};
use crate::symbol::SymbolId;

use super::Resolver;
use super::enclosing_symbol_index;

/// A cross-language FFI export plus the ABI it is exposed under (so the resolver
/// can bridge it only to call sites in a language that consumes that ABI).
struct ExportRec {
    symbol: SymbolId,
    abi: FfiAbi,
}

/// Links cross-language call sites to deterministic FFI exports
/// ([`Provenance::FfiBridge`]).
#[derive(Debug, Default, Clone, Copy)]
pub struct FfiBridgeResolver;

impl Resolver for FfiBridgeResolver {
    fn resolve(&self, files: &[FileFacts]) -> CodeGraph {
        let mut symbols: Vec<Symbol> = Vec::new();
        for f in files {
            symbols.extend(f.symbols.iter().cloned());
        }

        // export name → exports declared under it, each tagged with its language.
        let mut exports: HashMap<&str, Vec<ExportRec>> = HashMap::new();
        for f in files {
            for e in &f.ffi_exports {
                exports
                    .entry(e.export_name.as_str())
                    .or_default()
                    .push(ExportRec {
                        symbol: e.symbol.clone(),
                        abi: e.abi,
                    });
            }
        }
        if exports.is_empty() {
            return CodeGraph {
                symbols,
                edges: Vec::new(),
            };
        }

        // Per-file symbol index for caller attribution (span containment).
        let mut by_file: HashMap<&str, Vec<usize>> = HashMap::new();
        for (i, s) in symbols.iter().enumerate() {
            by_file.entry(s.file.as_str()).or_default().push(i);
        }

        let mut edges: Vec<Edge> = Vec::new();
        for f in files {
            let file_syms = by_file.get(f.file.as_str());
            for r in &f.references {
                // An FFI bridge is a *call* across the boundary.
                if r.role != RefRole::Call {
                    continue;
                }
                let Some(targets) = exports.get(r.name.as_str()) else {
                    continue;
                };
                // An FFI crossing: this call's language consumes the export's ABI
                // (which excludes same-language use — a definition's own language
                // is never in its ABI's consumer set).
                let cross: Vec<&ExportRec> = targets
                    .iter()
                    .filter(|e| e.abi.consumers().contains(&f.lang.as_str()))
                    .collect();
                if cross.is_empty() {
                    continue;
                }
                let Some(from_idx) =
                    file_syms.and_then(|idxs| enclosing_symbol_index(&symbols, idxs, r.occ.byte))
                else {
                    continue; // call site not inside any extracted symbol
                };
                // Honest confidence: unique export → Scoped, otherwise NameOnly.
                let confidence = if cross.len() == 1 {
                    Confidence::Scoped
                } else {
                    Confidence::NameOnly
                };
                for e in cross {
                    edges.push(Edge {
                        from: symbols[from_idx].id.clone(),
                        to: e.symbol.clone(),
                        role: RefRole::Call,
                        confidence,
                        provenance: Provenance::FfiBridge,
                        occ: r.occ.clone(),
                    });
                }
            }
        }

        CodeGraph { symbols, edges }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::{CExtractor, Extractor, PythonExtractor, RustExtractor};

    /// Rust `#[no_mangle]` export, called from C → one FfiBridge edge.
    #[test]
    fn bridges_rust_no_mangle_export_to_c_call() {
        let rust = RustExtractor
            .extract(
                "#[no_mangle]\npub extern \"C\" fn create_user() -> u32 { 0 }",
                "src/ffi.rs",
            )
            .unwrap();
        // Sanity: the export fact was recorded.
        assert_eq!(rust.ffi_exports.len(), 1, "expected one FFI export");
        assert_eq!(rust.ffi_exports[0].export_name, "create_user");

        let c = CExtractor
            .extract("void use_it(void) { create_user(); }", "src/app.c")
            .unwrap();

        let graph = FfiBridgeResolver.resolve(&[rust, c]);
        assert_eq!(graph.edges.len(), 1, "expected one FFI bridge edge");
        let e = &graph.edges[0];
        assert_eq!(e.provenance, Provenance::FfiBridge);
        assert_eq!(e.confidence, Confidence::Scoped);
        assert_eq!(e.role, RefRole::Call);
        assert!(
            e.from.to_scip_string().ends_with("use_it()."),
            "from was: {}",
            e.from.to_scip_string()
        );
        assert!(
            e.to.to_scip_string().ends_with("ffi/create_user()."),
            "to was: {}",
            e.to.to_scip_string()
        );
        assert_eq!(e.occ.file, "src/app.c");
    }

    /// `#[export_name = "..."]` overrides the bridged name.
    #[test]
    fn export_name_attribute_overrides_symbol_name() {
        let rust = RustExtractor
            .extract(
                "#[export_name = \"c_alloc\"]\npub extern \"C\" fn rust_alloc() -> u32 { 0 }",
                "src/ffi.rs",
            )
            .unwrap();
        assert_eq!(rust.ffi_exports[0].export_name, "c_alloc");

        // C calls the exported name, not the Rust name.
        let c = CExtractor
            .extract("void m(void) { c_alloc(); }", "src/app.c")
            .unwrap();
        let graph = FfiBridgeResolver.resolve(&[rust, c]);
        assert_eq!(graph.edges.len(), 1);
        assert!(
            graph.edges[0]
                .to
                .to_scip_string()
                .ends_with("rust_alloc().")
        );
    }

    /// A same-language call to the exported name is NOT an FFI crossing.
    #[test]
    fn same_language_call_is_not_bridged() {
        let lib = RustExtractor
            .extract(
                "#[no_mangle]\npub extern \"C\" fn create_user() -> u32 { 0 }",
                "src/ffi.rs",
            )
            .unwrap();
        let caller = RustExtractor
            .extract("pub fn run() { create_user(); }", "src/main.rs")
            .unwrap();
        let graph = FfiBridgeResolver.resolve(&[lib, caller]);
        assert!(
            graph.edges.is_empty(),
            "same-language use must not bridge, got {:?}",
            graph.edges.len()
        );
    }

    /// A plain `extern "C"` function with no stable-export attribute is not an export.
    #[test]
    fn extern_c_without_no_mangle_is_not_an_export() {
        let rust = RustExtractor
            .extract("pub extern \"C\" fn helper() -> u32 { 0 }", "src/ffi.rs")
            .unwrap();
        assert!(
            rust.ffi_exports.is_empty(),
            "extern \"C\" alone is mangled — not a stable export"
        );
    }

    /// Rust PyO3 `#[pyfunction]` export, called from Python → one FfiBridge edge.
    #[test]
    fn bridges_rust_pyfunction_export_to_python_call() {
        let rust = RustExtractor
            .extract(
                "#[pyfunction]\npub fn tokenize() -> u32 { 0 }",
                "src/ext.rs",
            )
            .unwrap();
        assert_eq!(rust.ffi_exports.len(), 1, "expected one FFI export");
        assert_eq!(rust.ffi_exports[0].abi, FfiAbi::Python);
        assert_eq!(rust.ffi_exports[0].export_name, "tokenize");

        let py = PythonExtractor
            .extract("def run():\n    tokenize()", "app.py")
            .unwrap();

        let graph = FfiBridgeResolver.resolve(&[rust, py]);
        assert_eq!(graph.edges.len(), 1, "expected one FFI bridge edge");
        let e = &graph.edges[0];
        assert_eq!(e.provenance, Provenance::FfiBridge);
        assert!(
            e.to.to_scip_string().ends_with("ext/tokenize()."),
            "to was: {}",
            e.to.to_scip_string()
        );
        assert_eq!(e.occ.file, "app.py");
    }

    /// `#[pyo3(name = "…")]` overrides the Python-side name.
    #[test]
    fn pyo3_name_attribute_overrides_export_name() {
        let rust = RustExtractor
            .extract(
                "#[pyfunction]\n#[pyo3(name = \"tok\")]\npub fn tokenize() -> u32 { 0 }",
                "src/ext.rs",
            )
            .unwrap();
        assert_eq!(rust.ffi_exports[0].export_name, "tok");

        let py = PythonExtractor
            .extract("def run():\n    tok()", "app.py")
            .unwrap();
        let graph = FfiBridgeResolver.resolve(&[rust, py]);
        assert_eq!(graph.edges.len(), 1);
        assert!(
            graph.edges[0]
                .to
                .to_scip_string()
                .ends_with("ext/tokenize().")
        );
    }

    /// ABI isolation: a C call must NOT bridge to a Python-only (PyO3) export of
    /// the same name, nor a Python call to a C-only export.
    #[test]
    fn abi_consumers_are_isolated() {
        let py_export = RustExtractor
            .extract("#[pyfunction]\npub fn shared() -> u32 { 0 }", "src/ext.rs")
            .unwrap();
        let c = CExtractor
            .extract("void run(void) { shared(); }", "app.c")
            .unwrap();
        assert!(
            FfiBridgeResolver.resolve(&[py_export, c]).edges.is_empty(),
            "C cannot consume a Python-only export"
        );

        let c_export = RustExtractor
            .extract(
                "#[no_mangle]\npub extern \"C\" fn shared() -> u32 { 0 }",
                "src/ffi.rs",
            )
            .unwrap();
        let py = PythonExtractor
            .extract("def run():\n    shared()", "app.py")
            .unwrap();
        assert!(
            FfiBridgeResolver.resolve(&[c_export, py]).edges.is_empty(),
            "Python cannot consume a C-only export"
        );
    }
}
