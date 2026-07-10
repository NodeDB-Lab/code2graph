// SPDX-License-Identifier: Apache-2.0

//! [`FfiBridgeResolver`] — see the [`ffi_bridge`](super) module docs for the
//! design rationale (honest cross-language linking via FFI exports).

use std::collections::HashMap;

use crate::graph::types::{
    CodeGraph, Confidence, Edge, FfiAbi, FileFacts, Provenance, RefRole, Symbol,
};
use crate::symbol::SymbolId;

use crate::resolve::Resolver;
use crate::resolve::{dedup_files_last_wins, enclosing_symbol_index};

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
    fn resolve(&self, files: &[FileFacts]) -> crate::Result<CodeGraph> {
        crate::validate_file_facts(files)?;
        let files = dedup_files_last_wins(files);
        // export name → exports declared under it, each tagged with its language.
        let mut symbols: Vec<Symbol> = Vec::new();
        let mut exports: HashMap<&str, Vec<ExportRec>> = HashMap::new();
        for f in files.iter().copied() {
            symbols.extend(f.symbols.iter().cloned());
            for e in &f.ffi_exports {
                // An export fact must identify exactly one symbol in its own
                // facts; otherwise it is malformed and cannot be bridged.
                if f.symbols.iter().filter(|s| s.id == e.symbol).count() != 1
                    || f.ffi_exports
                        .iter()
                        .filter(|other| other.symbol == e.symbol)
                        .count()
                        != 1
                {
                    continue;
                }
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
            return Ok(CodeGraph {
                symbols,
                edges: Vec::new(),
            });
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
                    .filter(|e| crate::ffi::consumers(e.abi).contains(&f.lang.as_str()))
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

        Ok(CodeGraph { symbols, edges })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::{
        CExtractor, Extractor, JavaExtractor, JavaScriptExtractor, PythonExtractor, RustExtractor,
    };

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

        let graph = FfiBridgeResolver.resolve(&[rust, c]).unwrap();
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
        let graph = FfiBridgeResolver.resolve(&[rust, c]).unwrap();
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
        let graph = FfiBridgeResolver.resolve(&[lib, caller]).unwrap();
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

        let graph = FfiBridgeResolver.resolve(&[rust, py]).unwrap();
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
        let graph = FfiBridgeResolver.resolve(&[rust, py]).unwrap();
        assert_eq!(graph.edges.len(), 1);
        assert!(
            graph.edges[0]
                .to
                .to_scip_string()
                .ends_with("ext/tokenize().")
        );
    }

    /// Rust `#[wasm_bindgen]` export, called from JavaScript → one FfiBridge edge.
    #[test]
    fn bridges_rust_wasm_bindgen_export_to_js_call() {
        let rust = RustExtractor
            .extract("#[wasm_bindgen]\npub fn greet() -> u32 { 0 }", "src/lib.rs")
            .unwrap();
        assert_eq!(rust.ffi_exports.len(), 1, "expected one FFI export");
        assert_eq!(rust.ffi_exports[0].abi, FfiAbi::Wasm);
        assert_eq!(rust.ffi_exports[0].export_name, "greet");

        let js = JavaScriptExtractor
            .extract("function run() { greet(); }", "app.js")
            .unwrap();
        let graph = FfiBridgeResolver.resolve(&[rust, js]).unwrap();
        assert_eq!(graph.edges.len(), 1, "expected one FFI bridge edge");
        let e = &graph.edges[0];
        assert_eq!(e.provenance, Provenance::FfiBridge);
        assert!(
            e.to.to_scip_string().ends_with("greet()."),
            "to was: {}",
            e.to.to_scip_string()
        );
        assert_eq!(e.occ.file, "app.js");
    }

    /// Rust `#[napi]` export, called from JavaScript → one FfiBridge edge.
    #[test]
    fn bridges_rust_napi_export_to_js_call() {
        let rust = RustExtractor
            .extract("#[napi]\npub fn compute() -> u32 { 0 }", "src/lib.rs")
            .unwrap();
        assert_eq!(rust.ffi_exports.len(), 1, "expected one FFI export");
        assert_eq!(rust.ffi_exports[0].abi, FfiAbi::NodeApi);
        assert_eq!(rust.ffi_exports[0].export_name, "compute");

        let js = JavaScriptExtractor
            .extract("function run() { compute(); }", "app.js")
            .unwrap();
        let graph = FfiBridgeResolver.resolve(&[rust, js]).unwrap();
        assert_eq!(graph.edges.len(), 1, "expected one FFI bridge edge");
        assert_eq!(graph.edges[0].provenance, Provenance::FfiBridge);
        assert!(
            graph.edges[0].to.to_scip_string().ends_with("compute()."),
            "to was: {}",
            graph.edges[0].to.to_scip_string()
        );
    }

    /// JNI: a Java `native` method bridges to its Rust `Java_*` implementation
    /// via the mangled name, tagged with the JNI ABI.
    #[test]
    fn bridges_java_native_method_to_rust_jni_impl() {
        let java = JavaExtractor
            .extract(
                "package com.example;\npublic class Foo {\n    public native int compute(int x);\n}\n",
                "Foo.java",
            )
            .unwrap();
        let rust = RustExtractor
            .extract(
                "#[no_mangle]\npub extern \"C\" fn Java_com_example_Foo_compute() -> u32 { 0 }",
                "src/jni.rs",
            )
            .unwrap();
        assert_eq!(rust.ffi_exports.len(), 1, "expected one FFI export");
        assert_eq!(
            rust.ffi_exports[0].abi,
            FfiAbi::Jni,
            "Java_-prefixed export must be classified JNI, not C"
        );
        assert_eq!(
            rust.ffi_exports[0].export_name,
            "Java_com_example_Foo_compute"
        );

        let graph = FfiBridgeResolver.resolve(&[java, rust]).unwrap();
        let bridges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.provenance == Provenance::FfiBridge)
            .collect();
        assert_eq!(bridges.len(), 1, "expected one JNI bridge edge");
        assert!(
            bridges[0]
                .to
                .to_scip_string()
                .contains("Java_com_example_Foo_compute"),
            "bridge target was {}",
            bridges[0].to.to_scip_string()
        );
    }

    /// JNI: a Java `native` method bridges to a C implementation too (the common
    /// NDK case), via the `Java_*` export the C extractor emits.
    #[test]
    fn bridges_java_native_method_to_c_jni_impl() {
        let java = JavaExtractor
            .extract(
                "package com.example;\npublic class Foo {\n    public native int compute(int x);\n}\n",
                "Foo.java",
            )
            .unwrap();
        let c = CExtractor
            .extract(
                "int Java_com_example_Foo_compute(void* env, void* obj, int x) { return x; }",
                "jni.c",
            )
            .unwrap();
        assert_eq!(c.ffi_exports.len(), 1, "C must export the Java_ function");
        assert_eq!(c.ffi_exports[0].abi, FfiAbi::Jni);

        let graph = FfiBridgeResolver.resolve(&[java, c]).unwrap();
        let bridges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.provenance == Provenance::FfiBridge)
            .collect();
        assert_eq!(
            bridges.len(),
            1,
            "expected one JNI bridge edge to the C impl"
        );
    }

    #[test]
    fn bridge_exports_must_belong_exactly_once_to_the_declaring_file() {
        let source = RustExtractor
            .extract(
                "#[no_mangle]\npub extern \"C\" fn shared() -> u32 { 0 }",
                "src/ffi.rs",
            )
            .unwrap();
        let caller = CExtractor
            .extract("void run(void) { shared(); }", "src/app.c")
            .unwrap();

        let mut fabricated = source.clone();
        fabricated.ffi_exports[0].symbol = SymbolId::global(
            "rust",
            vec![crate::symbol::Descriptor::Term("absent".into())],
        );

        let mut duplicate = source.clone();
        duplicate.ffi_exports.push(duplicate.ffi_exports[0].clone());

        let mut foreign = source.clone();
        foreign.ffi_exports[0].symbol = caller.symbols[0].id.clone();

        let malformed_exports = [
            ("fabricated", fabricated),
            ("duplicate", duplicate),
            ("foreign", foreign),
        ];
        let bridged: Vec<_> = malformed_exports
            .iter()
            .filter_map(|(name, exports)| {
                (!FfiBridgeResolver
                    .resolve(&[exports.clone(), caller.clone()])
                    .unwrap()
                    .edges
                    .is_empty())
                .then_some(*name)
            })
            .collect();

        assert!(
            bridged.is_empty(),
            "only an export identity occurring exactly once in its declaring facts may bridge; accepted {bridged:?}"
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
            FfiBridgeResolver
                .resolve(&[py_export, c])
                .unwrap()
                .edges
                .is_empty(),
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
            FfiBridgeResolver
                .resolve(&[c_export, py])
                .unwrap()
                .edges
                .is_empty(),
            "Python cannot consume a C-only export"
        );
    }
}
