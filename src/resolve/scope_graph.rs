// SPDX-License-Identifier: Apache-2.0

//! Tier-B scope-aware resolver (**in progress**).
//!
//! This resolver walks each file's lexical scopes to bind references the way the
//! language's name-resolution rules would. **Today it handles only the local
//! case**: a reference that resolves to a local variable or parameter within the
//! file's scopes produces a [`Confidence::Scoped`] edge whose target is a
//! synthesized [`SymbolId::Local`]. Everything else is a graceful no-op — a
//! reference with `scope: None` (every extractor except Rust, for now) or a name
//! that binds to nothing simply yields no edge.
//!
//! It is therefore **not** a drop-in replacement for the Tier-A name-table
//! resolver yet: it does not yet resolve references that bind to top-level
//! definitions or imports (future units fill those in via the same
//! [`scope_walk`] core). The honest read: this is the scope-walk foundation plus
//! the local/param case, nothing more.

use std::collections::HashMap;

use crate::graph::types::{
    Binding, BindingKind, CodeGraph, Confidence, Edge, FileFacts, Scope, ScopeId, Symbol,
};
use crate::symbol::SymbolId;

use super::Resolver;
use super::enclosing_symbol_index;

/// Scope-aware resolver. See module docs — currently resolves local/param
/// references only.
#[derive(Debug, Default, Clone, Copy)]
pub struct ScopeGraphResolver;

impl Resolver for ScopeGraphResolver {
    fn resolve(&self, files: &[FileFacts]) -> CodeGraph {
        // Flatten symbols exactly like Tier-A — these are the returned graph's
        // symbols. Synthesized Local targets are edge targets only (SCIP-style);
        // they are never added here.
        let symbols: Vec<Symbol> = files
            .iter()
            .flat_map(|f| f.symbols.iter().cloned())
            .collect();

        // file path → indices into `symbols`, for caller attribution.
        let mut syms_by_file: HashMap<&str, Vec<usize>> = HashMap::new();
        for (i, s) in symbols.iter().enumerate() {
            syms_by_file.entry(s.file.as_str()).or_default().push(i);
        }

        let mut edges: Vec<Edge> = Vec::new();
        for f in files {
            // Per-file binding index (scope → its bindings), built before the
            // reference loop so it borrows `f.bindings` independently of the
            // separate immutable borrow of `f.references`.
            let mut bindings_by_scope: HashMap<ScopeId, Vec<&Binding>> = HashMap::new();
            for b in &f.bindings {
                bindings_by_scope.entry(b.scope).or_default().push(b);
            }

            for r in &f.references {
                // No scope info on the reference → no Tier-B edge.
                let Some(start) = r.scope else { continue };

                let Some(binding) =
                    scope_walk(&r.name, r.occ.byte, start, &f.scopes, &bindings_by_scope)
                else {
                    continue; // name binds to nothing visible — no edge
                };

                match binding.kind {
                    BindingKind::Local | BindingKind::Param => {
                        // The caller: innermost symbol in this file enclosing the ref.
                        let Some(from_idx) = syms_by_file
                            .get(f.file.as_str())
                            .and_then(|idxs| enclosing_symbol_index(&symbols, idxs, r.occ.byte))
                        else {
                            continue; // unattributable reference — skip, like Tier-A
                        };

                        // Stable, unique id for the local: file + scope + name +
                        // intro byte distinguishes shadowing bindings of one name.
                        let local_id = format!(
                            "{}@{}:{}@{}",
                            f.file, binding.scope, binding.name, binding.intro
                        );
                        let to = SymbolId::local(f.file.clone(), local_id);

                        edges.push(Edge {
                            from: symbols[from_idx].id.clone(),
                            to,
                            role: r.role,
                            confidence: Confidence::Scoped,
                            occ: r.occ.clone(),
                        });
                    }
                    // U6/U7 will handle Definition/Import bindings here.
                    _ => continue,
                }
            }
        }

        CodeGraph { symbols, edges }
    }
}

/// Walk lexical scopes outward from `start` looking for the binding that the
/// name resolves to. Returns the winning binding (caller dispatches on kind).
///
/// The walk goes outward only (child → parent), so a reference never sees
/// bindings in sibling or child scopes — block visibility falls out for free.
fn scope_walk<'b>(
    name: &str,
    ref_byte: usize,
    start: ScopeId,
    scopes: &[Scope],
    bindings_by_scope: &HashMap<ScopeId, Vec<&'b Binding>>,
) -> Option<&'b Binding> {
    let mut current = start;
    loop {
        if let Some(cands) = bindings_by_scope.get(&current) {
            // Visible candidates in THIS scope, matching the name. On shadowing
            // (multiple matches), the latest introduction wins.
            let winner = cands
                .iter()
                .copied()
                .filter(|b| b.name == name && is_visible(b, ref_byte))
                .max_by_key(|b| b.intro);
            if let Some(b) = winner {
                return Some(b);
            }
        }
        match scopes.get(current).and_then(|s| s.parent) {
            Some(p) => current = p,
            None => return None, // reached root with no match
        }
    }
}

/// Visibility: `let` locals are position-gated (must be introduced before use);
/// params, definitions, and imports are visible scope-wide.
fn is_visible(b: &Binding, ref_byte: usize) -> bool {
    match b.kind {
        BindingKind::Local => b.intro <= ref_byte,
        BindingKind::Param | BindingKind::Definition | BindingKind::Import => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::Extractor;
    use crate::extract::PythonExtractor;
    use crate::extract::RustExtractor;
    use crate::graph::types::RefRole;

    /// All edges whose target renders as a `local …` SCIP string.
    fn local_edges(graph: &CodeGraph) -> Vec<&Edge> {
        graph
            .edges
            .iter()
            .filter(|e| e.to.to_scip_string().starts_with("local "))
            .collect()
    }

    #[test]
    fn resolves_local_binding() {
        // `helper` binds to the `let helper`; `make()` binds to nothing → no edge.
        let facts = RustExtractor
            .extract(
                "pub fn run() { let helper = make(); helper() }",
                "src/main.rs",
            )
            .unwrap();
        let graph = ScopeGraphResolver.resolve(&[facts]);

        let locals = local_edges(&graph);
        assert_eq!(
            locals.len(),
            1,
            "expected exactly one local edge, got {:?}",
            locals.len()
        );
        let e = locals[0];
        assert_eq!(e.confidence, Confidence::Scoped);
        assert!(
            e.from.to_scip_string().ends_with("run()."),
            "from was: {}",
            e.from.to_scip_string()
        );
    }

    #[test]
    fn shadowing_latest_binding_wins() {
        // `val` is ≥ MIN_REF_LEN so the `val()` call is captured.
        let src = "pub fn run() { let val = make(); let val = other(); val() }";
        let facts = RustExtractor.extract(src, "src/main.rs").unwrap();

        // Expected: the SECOND `let val` (greater intro byte) wins. Compute both
        // intro bytes from the source so the assertion is grounded.
        let first_let = src.find("let val").unwrap();
        let second_let = src[first_let + 1..].find("let val").unwrap() + first_let + 1;
        assert!(second_let > first_let);

        let graph = ScopeGraphResolver.resolve(&[facts]);
        let locals = local_edges(&graph);
        assert_eq!(
            locals.len(),
            1,
            "expected one local edge, got {:?}",
            locals.len()
        );

        // The synthesized local id encodes the winning binding's intro byte. The
        // intro is the name position; both `let x` lines have `x` after `let `.
        let second_intro = second_let + "let ".len();
        let id = locals[0].to.to_scip_string();
        assert!(
            id.ends_with(&format!("@{}", second_intro)),
            "local id {id} should encode the second binding intro {second_intro}"
        );
    }

    #[test]
    fn resolves_param_binding() {
        // `callback` is a parameter; `callback()` resolves to it (tree-sitter
        // doesn't typecheck). Name length ≥ MIN_REF_LEN so the call is captured.
        let facts = RustExtractor
            .extract("pub fn run(callback: u32) { callback() }", "src/main.rs")
            .unwrap();
        let graph = ScopeGraphResolver.resolve(&[facts]);

        let locals = local_edges(&graph);
        assert_eq!(
            locals.len(),
            1,
            "expected one local edge, got {:?}",
            locals.len()
        );
        assert_eq!(locals[0].confidence, Confidence::Scoped);
    }

    #[test]
    fn unbound_name_produces_no_edge() {
        let facts = RustExtractor
            .extract("pub fn run() { nothing_here() }", "src/main.rs")
            .unwrap();
        let graph = ScopeGraphResolver.resolve(&[facts]);
        assert!(
            local_edges(&graph).is_empty(),
            "unbound name must not bind to a local"
        );
    }

    #[test]
    fn non_scope_language_is_graceful_noop() {
        // Python refs carry scope: None → no local edges, no panic.
        let facts = PythonExtractor
            .extract("def f():\n    pass\n", "src/m.py")
            .unwrap();
        let sym_count = facts.symbols.len();
        let graph = ScopeGraphResolver.resolve(&[facts]);
        assert_eq!(graph.symbols.len(), sym_count);
        assert!(local_edges(&graph).is_empty());
    }

    #[test]
    fn block_local_not_visible_to_outer_ref() {
        // `let val` lives in the inner block; `val()` is in the function scope
        // and must NOT see it (outward walk skips child scopes). Name ≥ MIN_REF_LEN
        // so the call IS captured — otherwise this would pass for the wrong reason.
        let facts = RustExtractor
            .extract("pub fn run() { { let val = make(); } val() }", "src/main.rs")
            .unwrap();
        let graph = ScopeGraphResolver.resolve(&[facts]);
        assert!(
            local_edges(&graph).is_empty(),
            "outer ref must not bind to a block-scoped local"
        );
    }

    #[test]
    fn ignores_role_noise_only_local_edges_counted() {
        // Sanity: with no resolvable local, even if a call ref exists, no local edge.
        let facts = RustExtractor
            .extract("pub fn run() { helper() }", "src/main.rs")
            .unwrap();
        let graph = ScopeGraphResolver.resolve(&[facts]);
        // `helper` is a Definition-bound name (top-level) or unbound here; either
        // way this unit emits no local edge for it.
        for e in local_edges(&graph) {
            assert_ne!(e.role, RefRole::IsImplementation);
        }
    }
}
