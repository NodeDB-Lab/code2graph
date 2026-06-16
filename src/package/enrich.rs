// SPDX-License-Identifier: Apache-2.0

//! Dep-free enrichment pass: stamps a [`Package`] onto every [`SymbolId`](crate::symbol::SymbolId)-bearing
//! field in a [`FileFacts`]. Always compiled (no feature gate).

use crate::graph::types::{BindingTarget, CodeGraph, FileFacts};
use crate::symbol::Package;

/// Stamp `package` onto every [`SymbolId`](crate::symbol::SymbolId) carried by `facts`.
///
/// Affected fields:
/// - `facts.symbols[*].id`
/// - `facts.bindings[*].target` when the target is `BindingTarget::Def(_)`
/// - `facts.ffi_exports[*].symbol`
///
/// References, scopes, and non-`Def` binding targets carry no `SymbolId` and
/// are left untouched.
pub fn enrich(facts: &mut FileFacts, package: &Package) {
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
}

/// Stamp `package` onto every [`SymbolId`](crate::symbol::SymbolId) carried by a
/// resolved [`CodeGraph`].
///
/// Unlike [`enrich`] (which operates on a single file's facts before
/// resolution), a `CodeGraph`'s edges reference symbols *by* their `SymbolId`,
/// so identity is matched by SCIP-string equality. This pass therefore rewrites
/// all three id-bearing slots consistently:
/// - `graph.symbols[*].id`
/// - `graph.edges[*].from`
/// - `graph.edges[*].to`
///
/// Both endpoints of every edge get the *same* package as the symbols they
/// point at, so string-equality matching is preserved (no edge is broken).
/// `Local` ids are left unchanged by [`SymbolId::with_package`](crate::symbol::SymbolId::with_package)
/// — locals have no cross-repo coordinate — which is correct.
pub fn enrich_codegraph(graph: &mut CodeGraph, package: &Package) {
    for sym in &mut graph.symbols {
        sym.id = sym.id.with_package(package.clone());
    }
    for edge in &mut graph.edges {
        edge.from = edge.from.with_package(package.clone());
        edge.to = edge.to.with_package(package.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::types::{
        Binding, BindingKind, BindingTarget, ByteSpan, FfiAbi, FfiExport, FileFacts, Symbol,
        SymbolKind, Visibility,
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
            symbols: vec![make_symbol(sym_id)],
            references: vec![],
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
    }

    #[test]
    fn enrich_codegraph_restamps_symbols_and_both_edge_endpoints() {
        use crate::graph::types::{CodeGraph, Confidence, Edge, Occurrence, Provenance, RefRole};

        let pkg = Package {
            manager: "cargo".into(),
            name: "demo".into(),
            version: "1.0.0".into(),
        };

        let from_id = SymbolId::global("rust", vec![Descriptor::Term("run".into())]);
        let to_id = SymbolId::global("rust", vec![Descriptor::Term("helper".into())]);
        // A Local id present as a symbol — must stay unchanged.
        let local_id = SymbolId::local("src/main.rs", "x0");

        let mut graph = CodeGraph {
            symbols: vec![
                make_symbol(from_id.clone()),
                make_symbol(to_id.clone()),
                make_symbol(local_id.clone()),
            ],
            edges: vec![Edge {
                from: from_id,
                to: to_id,
                role: RefRole::Call,
                confidence: Confidence::NameOnly,
                provenance: Provenance::SymbolTable,
                occ: Occurrence {
                    file: "src/main.rs".into(),
                    line: 1,
                    col: 0,
                    byte: 0,
                },
            }],
        };

        enrich_codegraph(&mut graph, &pkg);

        // (1) Every global symbol id now carries the package (no '.' placeholders).
        assert_eq!(
            graph.symbols[0].id.to_scip_string(),
            "codegraph cargo demo 1.0.0 run."
        );
        assert_eq!(
            graph.symbols[1].id.to_scip_string(),
            "codegraph cargo demo 1.0.0 helper."
        );

        // (3) The Local symbol id is unchanged.
        assert_eq!(graph.symbols[2].id.to_scip_string(), "local x0");
        assert_eq!(graph.symbols[2].id, local_id);

        // (2) Both edge endpoints were rewritten and stay consistent with the
        // enriched symbol ids (string-equality matching preserved).
        assert_eq!(
            graph.edges[0].from.to_scip_string(),
            "codegraph cargo demo 1.0.0 run."
        );
        assert_eq!(graph.edges[0].from, graph.symbols[0].id);
        assert_eq!(graph.edges[0].to, graph.symbols[1].id);

        // SCIP round-trip: the enriched id parses back to the same string.
        let scip = graph.edges[0].to.to_scip_string();
        let reparsed = SymbolId::from_scip_string(&scip).expect("should parse");
        assert_eq!(reparsed.to_scip_string(), scip);
    }
}
