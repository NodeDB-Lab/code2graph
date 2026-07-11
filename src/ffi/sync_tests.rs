// SPDX-License-Identifier: Apache-2.0
//! Anti-rot: every FFI marker/prefix in `SPECS` must be named in the matrix doc.
use super::spec::SPECS;

fn read_doc(rel: &str) -> String {
    let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"))
}

#[test]
fn ffi_markers_are_documented() {
    let doc = read_doc("docs/ffi-support-matrix.md");
    for spec in SPECS {
        #[cfg(feature = "rust")]
        for marker in spec.rust_attr_markers {
            assert!(
                doc.contains(marker),
                "FFI marker `{marker}` (abi {:?}) is missing from \
                 docs/ffi-support-matrix.md — document it there",
                spec.abi,
            );
        }
        #[cfg(any(feature = "rust", feature = "c"))]
        if let Some(prefix) = spec.name_prefix {
            assert!(
                doc.contains(prefix),
                "FFI name prefix `{prefix}` (abi {:?}) is missing from \
                 docs/ffi-support-matrix.md — document the `{prefix}*` rule there",
                spec.abi,
            );
        }
    }
}
