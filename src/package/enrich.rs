// SPDX-License-Identifier: Apache-2.0

//! Dep-free enrichment pass: stamps a [`Package`] onto every [`SymbolId`]-bearing
//! field in a [`FileFacts`]. Always compiled (no feature gate).

use crate::graph::types::{BindingTarget, FileFacts};
use crate::symbol::{Package, SymbolId};

/// Stamp `package` onto every [`SymbolId`] carried by `facts`.
///
/// Affected fields:
/// - `facts.symbols[*].id`
/// - `facts.bindings[*].target` when the target is `BindingTarget::Def(_)`
/// - `facts.ffi_exports[*].symbol`
/// - `facts.references[*].source_module` when it is a parseable global SCIP ID
///
/// A reference's `source_module` is the rendered identity of the importing
/// file's module symbol, so it must track the same package rewrite as that
/// symbol. Local and non-SCIP source-module strings are preserved; `from_path`,
/// qualifiers, and all other external/import metadata are never package IDs and
/// are left unchanged. This per-file API is intentionally independent of any
/// project-wide graph: callers assign a package to each file, then invoke it
/// before resolution.
pub fn enrich_file_facts(facts: &mut FileFacts, package: &Package) {
    for sym in &mut facts.symbols {
        sym.id = sym.id.with_package(package.clone());
    }
    for binding in &mut facts.bindings {
        if let BindingTarget::Def(id) = &binding.target {
            binding.target = BindingTarget::Def(id.with_package(package.clone()));
        }
    }
    for export in &mut facts.ffi_exports {
        export.symbol = export.symbol.with_package(package.clone());
    }
    for reference in &mut facts.references {
        rewrite_source_module(&mut reference.source_module, package);
    }
}

fn rewrite_source_module(source_module: &mut Option<String>, package: &Package) {
    let Some(existing) = source_module else {
        return;
    };
    let Ok(id) = SymbolId::from_scip_string(existing) else {
        return;
    };
    if id.language().is_some() {
        *existing = id.with_package(package.clone()).to_scip_string();
    }
}

/// Backwards-compatible name for [`enrich_file_facts`].
pub fn enrich(facts: &mut FileFacts, package: &Package) {
    enrich_file_facts(facts, package);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::types::{
        Binding, BindingKind, BindingTarget, ByteSpan, FfiAbi, FfiExport, FileFacts, Occurrence,
        RefRole, Reference, Symbol, SymbolKind, Visibility,
    };
    use crate::symbol::{Descriptor, SymbolId};

    fn make_symbol(id: SymbolId) -> Symbol {
        Symbol {
            id,
            name: "foo".into(),
            kind: SymbolKind::Function,
            visibility: Visibility::Public,
            entry_points: Vec::new(),
            file: "src/lib.rs".into(),
            line: 1,
            span: ByteSpan { start: 0, end: 10 },
            signature: "fn foo()".into(),
        }
    }

    #[test]
    fn with_package_on_global_stamps_package() {
        let id = SymbolId::global("rust", vec![Descriptor::Term("foo".into())]);
        // Un-enriched: empty package fields render as '.'
        assert_eq!(id.to_scip_string(), "codegraph . . . foo.");

        let pkg = Package {
            manager: "cargo".into(),
            name: "mylib".into(),
            version: "1.0.0".into(),
        };
        let enriched = id.with_package(pkg);
        assert_eq!(
            enriched.to_scip_string(),
            "codegraph cargo mylib 1.0.0 foo."
        );
    }

    #[test]
    fn with_package_on_local_is_unchanged() {
        let id = SymbolId::local("src/main.rs", "x0");
        let pkg = Package {
            manager: "cargo".into(),
            name: "mylib".into(),
            version: "1.0.0".into(),
        };
        let after = id.with_package(pkg);
        assert_eq!(after.to_scip_string(), "local x0");
        assert_eq!(after, id);
    }

    #[test]
    fn enrich_restamps_symbols_bindings_ffi_exports() {
        let pkg = Package {
            manager: "cargo".into(),
            name: "mylib".into(),
            version: "1.0.0".into(),
        };
        let expected_scip = "codegraph cargo mylib 1.0.0 foo.";

        let sym_id = SymbolId::global("rust", vec![Descriptor::Term("foo".into())]);
        let export_id = SymbolId::global("rust", vec![Descriptor::Term("foo".into())]);
        let def_id = SymbolId::global("rust", vec![Descriptor::Term("foo".into())]);

        let mut facts = FileFacts {
            file: "src/lib.rs".into(),
            lang: "rust".into(),
            symbols: vec![make_symbol(sym_id.clone())],
            references: vec![
                Reference {
                    name: "dep".into(),
                    occ: Occurrence {
                        file: "src/lib.rs".into(),
                        line: 1,
                        col: 0,
                        byte: 0,
                    },
                    role: RefRole::Import,
                    source_module: Some(sym_id.to_scip_string()),
                    from_path: Some("external::dep".into()),
                    is_reexport: false,
                    imported_name: None,
                    qualifier: Some("external".into()),
                    scope: None,
                    type_ref_ctx: None,
                    cross_artifact: false,
                },
                Reference {
                    name: "local".into(),
                    occ: Occurrence {
                        file: "src/lib.rs".into(),
                        line: 1,
                        col: 1,
                        byte: 1,
                    },
                    role: RefRole::Import,
                    source_module: Some(SymbolId::local("src/lib.rs", "module").to_scip_string()),
                    from_path: Some("keep/me".into()),
                    is_reexport: false,
                    imported_name: None,
                    qualifier: None,
                    scope: None,
                    type_ref_ctx: None,
                    cross_artifact: false,
                },
                Reference {
                    name: "opaque".into(),
                    occ: Occurrence {
                        file: "src/lib.rs".into(),
                        line: 1,
                        col: 2,
                        byte: 2,
                    },
                    role: RefRole::Import,
                    source_module: Some("not a SCIP id".into()),
                    from_path: Some("still/external".into()),
                    is_reexport: false,
                    imported_name: None,
                    qualifier: None,
                    scope: None,
                    type_ref_ctx: None,
                    cross_artifact: false,
                },
            ],
            scopes: vec![],
            bindings: vec![
                Binding {
                    scope: 0,
                    name: "foo".into(),
                    intro: 0,
                    kind: BindingKind::Definition,
                    target: BindingTarget::Def(def_id),
                },
                // Non-Def binding — must remain untouched
                Binding {
                    scope: 0,
                    name: "bar".into(),
                    intro: 5,
                    kind: BindingKind::Local,
                    target: BindingTarget::Local,
                },
            ],
            ffi_exports: vec![FfiExport {
                symbol: export_id,
                abi: FfiAbi::C,
                export_name: "foo".into(),
            }],
        };

        enrich(&mut facts, &pkg);

        assert_eq!(facts.symbols[0].id.to_scip_string(), expected_scip);

        // Def binding re-stamped
        assert!(
            matches!(&facts.bindings[0].target, BindingTarget::Def(id) if id.to_scip_string() == expected_scip)
        );
        // Non-Def binding untouched
        assert_eq!(facts.bindings[1].target, BindingTarget::Local);

        assert_eq!(facts.ffi_exports[0].symbol.to_scip_string(), expected_scip);

        // The importing module's rendered global ID tracks its definition;
        // local/opaque IDs and external path metadata stay exactly as supplied.
        assert_eq!(
            facts.references[0].source_module.as_deref(),
            Some(expected_scip)
        );
        assert_eq!(
            facts.references[0].from_path.as_deref(),
            Some("external::dep")
        );
        assert_eq!(facts.references[0].qualifier.as_deref(), Some("external"));
        assert_eq!(
            facts.references[1].source_module.as_deref(),
            Some("local module")
        );
        assert_eq!(facts.references[1].from_path.as_deref(), Some("keep/me"));
        assert_eq!(
            facts.references[2].source_module.as_deref(),
            Some("not a SCIP id")
        );
        assert_eq!(
            facts.references[2].from_path.as_deref(),
            Some("still/external")
        );
    }

    #[test]
    fn per_file_enrichment_supports_mixed_packages_without_graph_context() {
        let global = SymbolId::global("rust", vec![Descriptor::Term("f".into())]);
        let local = SymbolId::local("src/a.rs", "local");
        let mut first = FileFacts {
            file: "src/a.rs".into(),
            lang: "rust".into(),
            symbols: vec![make_symbol(global.clone()), make_symbol(local.clone())],
            references: vec![],
            scopes: vec![],
            bindings: vec![],
            ffi_exports: vec![],
        };
        let mut second = FileFacts {
            file: "src/b.rs".into(),
            lang: "rust".into(),
            symbols: vec![make_symbol(global)],
            references: vec![],
            scopes: vec![],
            bindings: vec![],
            ffi_exports: vec![],
        };
        enrich_file_facts(
            &mut first,
            &Package {
                manager: "cargo".into(),
                name: "one".into(),
                version: "1".into(),
            },
        );
        enrich_file_facts(
            &mut second,
            &Package {
                manager: "npm".into(),
                name: "two".into(),
                version: "2".into(),
            },
        );
        assert!(first.symbols[0].id.to_scip_string().contains("cargo one 1"));
        assert!(second.symbols[0].id.to_scip_string().contains("npm two 2"));
        assert_eq!(first.symbols[1].id, local);
    }
}
