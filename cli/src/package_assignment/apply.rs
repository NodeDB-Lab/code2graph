// SPDX-License-Identifier: Apache-2.0

//! Per-file application of already-selected package coordinates.

use code2graph::FileFacts;

use super::PackageAssignmentSet;

impl PackageAssignmentSet {
    /// Applies the already-selected source package to one worker result.
    ///
    /// This is deliberately a per-`FileFacts` operation: every file can carry a
    /// different nearest manifest, so no whole-graph package assumption is made.
    /// Missing assignments and assignments with no package leave the facts
    /// unchanged. The core pass preserves local IDs and external path metadata.
    pub fn enrich_file_facts(&self, facts: &mut FileFacts) {
        if let Some(package) = self
            .assignments
            .iter()
            .find(|item| item.source_path.as_str() == facts.file)
            .and_then(|item| item.package.as_ref())
        {
            code2graph::package::enrich_file_facts(facts, package);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use code2graph::{
        ByteSpan, Descriptor, FileFacts, Package, Symbol, SymbolId, SymbolKind, Visibility,
    };

    use super::*;
    use crate::package_assignment::SourcePackageAssignment;
    use crate::project::ProjectPath;

    fn facts(id: SymbolId) -> FileFacts {
        FileFacts {
            file: "src/lib.rs".into(),
            lang: "rust".into(),
            symbols: vec![Symbol {
                id,
                name: "f".into(),
                kind: SymbolKind::Function,
                visibility: Visibility::Public,
                entry_points: vec![],
                file: "src/lib.rs".into(),
                line: 1,
                span: ByteSpan { start: 0, end: 1 },
                signature: String::new(),
            }],
            references: vec![],
            scopes: vec![],
            bindings: vec![],
            ffi_exports: vec![],
        }
    }

    #[test]
    fn applies_only_the_matching_file_assignment() {
        let package = Package {
            manager: "cargo".into(),
            name: "pkg".into(),
            version: "1".into(),
        };
        let mut selected = facts(SymbolId::global("rust", vec![Descriptor::Term("f".into())]));
        let mut unselected = facts(SymbolId::global("rust", vec![Descriptor::Term("g".into())]));
        unselected.file = "src/other.rs".into();
        let set = PackageAssignmentSet {
            manifests: vec![],
            assignments: vec![SourcePackageAssignment {
                source_path: ProjectPath::new(Path::new("src/lib.rs")).expect("path"),
                manifest_path: Some("Cargo.toml".into()),
                package: Some(package),
            }],
            diagnostics: vec![],
        };
        set.enrich_file_facts(&mut selected);
        set.enrich_file_facts(&mut unselected);
        assert!(
            selected.symbols[0]
                .id
                .to_scip_string()
                .contains("cargo pkg 1")
        );
        assert_eq!(
            unselected.symbols[0].id.to_scip_string(),
            "codegraph . . . g."
        );
    }
}
