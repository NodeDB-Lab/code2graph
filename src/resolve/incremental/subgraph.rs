// SPDX-License-Identifier: Apache-2.0

//! Per-file (intra-file) Tier-B resolution.
//!
//! [`build_subgraph`] performs ALL of a file's isolated resolution work — local
//! and parameter bindings, same-file definitions — and emits them as fully
//! resolved [`Edge`]s. Any reference whose resolution depends on *other* files
//! (path-qualified calls, imports) is deferred as a [`PendingRef`] for the
//! cross-file stitch phase. Nothing here looks at any file but its own: caller
//! attribution indexes only `f.symbols`, so the result is a true per-file
//! subgraph that a future incremental store can build and cache in isolation.

use std::collections::HashMap;

use crate::graph::types::{
    Binding, BindingKind, BindingTarget, Confidence, Edge, FileFacts, Occurrence, Provenance,
    RefRole, Scope, ScopeId, Symbol,
};
use crate::symbol::SymbolId;

use super::super::{enclosing_symbol_index, normalize_from_path};

/// Schema version for opaque [`FileSubgraph`] persistence blobs.
pub const FILE_SUBGRAPH_SCHEMA_VERSION: u32 = 1;

/// A cross-file reference whose resolution is deferred to the stitch phase.
/// Qualified calls, imports, and unqualified same-namespace cross-file calls
/// all reduce to "match `name` whose namespace chain ends with `segs`,
/// uniquely" — they differ only in `role` and `confidence`.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone)]
pub(crate) struct PendingRef {
    /// Caller (resolved intra-file).
    pub from: SymbolId,
    /// Leaf name to look up.
    pub name: String,
    /// Normalized qualifier / import-path segments.
    pub segs: Vec<String>,
    pub role: RefRole,
    pub occ: Occurrence,
    /// Confidence to stamp on the resolved edge. Explicit written paths
    /// (qualified calls, imports) are [`Confidence::Exact`]; an unqualified
    /// same-namespace cross-file match (e.g. a Go same-package call) is
    /// [`Confidence::Scoped`] — consistent with same-file Definition resolution.
    pub confidence: Confidence,
    /// True when `segs` came from an *explicit written qualifier* (`Recv.method()`
    /// / `mod::fn()`). Such refs match against the enclosing descriptor chain
    /// (namespaces *and* types) so a module/class qualifier resolves, not just a
    /// namespace one. All other pending refs (imports, same-namespace deferrals,
    /// cross-artifact `TypeRef`s) match on the namespace chain only.
    pub qualified: bool,
}

/// The resolution facts for ONE file, isolated from all other files.
///
/// A `FileSubgraph` is the per-file unit of incremental Tier-B resolution.
/// Its fields are intentionally `pub(crate)` — the type is `pub` so a consumer
/// can name it as a serialization/deserialization target (e.g. `serde_json::from_str::<FileSubgraph>(…)`),
/// but the internal fields remain crate-private so `PendingRef` (also crate-private)
/// does not leak into the public API and the blob stays opaque to callers.
///
/// To obtain a `FileSubgraph` for persistence, use [`IncrementalGraph::subgraph`];
/// to restore one, use [`IncrementalGraph::upsert_subgraph`].
///
/// [`IncrementalGraph::subgraph`]: super::store::IncrementalGraph::subgraph
/// [`IncrementalGraph::upsert_subgraph`]: super::store::IncrementalGraph::upsert_subgraph
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone)]
pub struct FileSubgraph {
    /// Persistence format version. Rejecting unknown versions prevents silently
    /// restoring facts under changed invariants.
    pub(crate) schema_version: u32,
    /// File key that owns this isolated subgraph.
    pub(crate) owner_file: String,
    /// This file's symbols (a clone of `f.symbols`).
    pub(crate) symbols: Vec<Symbol>,
    /// Fully-resolved local/param/same-file-definition edges.
    pub(crate) intra_edges: Vec<Edge>,
    /// Cross-file refs awaiting the global index.
    pub(crate) pending: Vec<PendingRef>,
}

/// Resolve everything in `f` that can be resolved without other files, deferring
/// cross-file references as [`PendingRef`]s. See module docs.
pub(crate) fn build_subgraph(f: &FileFacts) -> FileSubgraph {
    let symbols = f.symbols.clone();

    // All of this file's symbols index into `symbols` (every one belongs to
    // `f.file`), so caller attribution is per-file — no global flattened vec.
    let all_idxs: Vec<usize> = (0..symbols.len()).collect();

    // Per-file binding index (scope → its bindings), built before the reference
    // loop so it borrows `f.bindings` independently of `f.references`.
    let mut bindings_by_scope: HashMap<ScopeId, Vec<&Binding>> = HashMap::new();
    for b in &f.bindings {
        bindings_by_scope.entry(b.scope).or_default().push(b);
    }

    // Precompute normalized import-path segments once per unique from_path.
    // Many references in a file can resolve to the same import binding (e.g. an
    // imported name used 50 times); without this cache, `normalize_from_path`
    // would re-split and re-filter the same string on every such reference. The
    // cache borrows `from_path` strings and segment slices from `f.bindings`,
    // which lives for the whole function — lifetimes are fine.
    let mut import_segs_cache: HashMap<&str, Vec<&str>> = HashMap::new();
    for b in &f.bindings {
        if let BindingTarget::Import(fp) = &b.target {
            import_segs_cache
                .entry(fp.as_str())
                .or_insert_with(|| normalize_from_path(fp.as_str()));
        }
    }

    // This file's own namespace (the package, for Go), derived from any defined
    // symbol's `Namespace` descriptors. All of a file's symbols share it. Used
    // to defer unqualified, unbound references so the stitch phase can match a
    // same-namespace definition in another file (e.g. a Go same-package call
    // with no import). Empty when the file defines no namespaced symbol — then
    // we never defer (nothing to match against; Tier-B never fakes precision).
    let file_namespace: Vec<String> = symbols
        .iter()
        .find(|s| s.id.namespaces_iter().next().is_some())
        .map(|s| s.id.namespaces_iter().map(str::to_owned).collect())
        .unwrap_or_default();

    let mut intra_edges: Vec<Edge> = Vec::new();
    let mut pending: Vec<PendingRef> = Vec::new();

    for r in &f.references {
        // Caller attribution — needed by both the qualified and unqualified
        // paths. Indexes only this file's symbols (isolation).
        let Some(from_idx) = enclosing_symbol_index(&symbols, &all_idxs, r.occ.byte) else {
            continue; // unattributable reference — skip, like Tier-A
        };
        let from = symbols[from_idx].id.clone();

        // MODULE REFERENCE: a `mod x;` declaration or an intermediate module
        // segment of an import path names a MODULE itself. It resolves by unique
        // module name (v1: empty `segs` — an ambiguous module name yields no
        // edge, honestly). Module decls / use-paths are module-level, so this is
        // NOT gated on `r.scope`; it is deferred for the module-only stitch path.
        if r.role == RefRole::ModuleRef {
            pending.push(PendingRef {
                from,
                name: r.name.clone(),
                segs: Vec::new(),
                role: RefRole::ModuleRef,
                occ: r.occ.clone(),
                confidence: Confidence::Scoped,
                qualified: false,
            });
            continue;
        }

        // QUALIFIED CALL: explicit written path → unique global match against the
        // target's enclosing descriptor chain. Bypasses scope_walk entirely (this
        // is a path lookup, not lexical resolution). Deferred to the stitch phase
        // with `qualified: true`, so it matches the qualifier against BOTH
        // namespace AND type descriptors — `mod_a::process` (namespace qualifier)
        // and `Alpha.compute` / `Service.helper` (a module/class/object *type*
        // qualifier) both resolve. The qualifier names a *container*, never the
        // member, so matching drops the leaf descriptor and suffix-matches the rest.
        //
        // REMAINING LIMITATION: a type-qualified call resolves only when the
        // member is extracted as a top-level symbol under that type (true for
        // Ruby `module`/Kotlin `object` methods). Rust `Type::assoc_fn()` inside
        // an `impl` block is still not extracted as a top-level symbol, so it does
        // not resolve — an honest extraction gap, not a matching one. Precision is
        // never faked: stitch only emits an edge on a UNIQUE match.
        if let Some(qual) = &r.qualifier {
            let segs = normalize_from_path(qual);
            if !segs.is_empty() {
                pending.push(PendingRef {
                    from,
                    name: r.name.clone(),
                    segs: segs.into_iter().map(str::to_string).collect(),
                    role: r.role,
                    occ: r.occ.clone(),
                    confidence: Confidence::Exact,
                    qualified: true,
                });
            }
            continue; // qualified ref handled (deferred or honest no-op)
        }

        // UNQUALIFIED: lexical scope_walk path (needs r.scope). No scope info on
        // the reference → no Tier-B edge.
        let Some(start) = r.scope else { continue };

        let Some(binding) = scope_walk(&r.name, r.occ.byte, start, &f.scopes, &bindings_by_scope)
        else {
            // CROSS-ARTIFACT TYPE REFERENCE: a `TypeRef` that no in-file binding
            // satisfies may name a definition in a DIFFERENT artifact/namespace
            // entirely — e.g. a Rust field type `users: Repo<users>` naming a SQL
            // `users` table symbol that carries an EMPTY namespace. Scoping it to
            // THIS file's namespace (below) would never match such a target, so a
            // TypeRef instead defers with EMPTY segs: stitch matches it to the
            // globally UNIQUE symbol of that name across all artifacts/namespaces.
            // Precision is preserved by stitch's `unique_match` — zero or 2+
            // candidates yield no edge, so this never fakes precision; it only
            // adds recall where the name is globally unambiguous.
            if r.role == RefRole::TypeRef {
                pending.push(PendingRef {
                    from,
                    name: r.name.clone(),
                    segs: Vec::new(),
                    role: r.role,
                    occ: r.occ.clone(),
                    confidence: Confidence::Scoped,
                    qualified: false,
                });
                continue;
            }

            // Not bound anywhere visible in this file. It may be a same-namespace
            // definition in ANOTHER file (e.g. a Go same-package call with no
            // import). Defer it scoped to THIS file's namespace so stitch matches
            // only a sibling-file def of the same package — never cross-package,
            // and a no-op for languages whose files have distinct namespaces.
            // No namespace known (symbol-less file) → drop (don't fake precision).
            if !file_namespace.is_empty() {
                pending.push(PendingRef {
                    from,
                    name: r.name.clone(),
                    segs: file_namespace.clone(),
                    role: r.role,
                    occ: r.occ.clone(),
                    confidence: Confidence::Scoped,
                    qualified: false,
                });
            }
            continue;
        };

        match binding.kind {
            BindingKind::Local | BindingKind::Param => {
                // A name-use exactly at its own binding's introduction site is
                // the definition, not a reference — emit no self-edge. (In
                // Python, `base = helper()` both defines `base` and is its write
                // site; the write must not resolve to itself.)
                if binding.intro == r.occ.byte {
                    continue;
                }
                // Stable, unique id for the local: file + scope + name + intro
                // byte distinguishes shadowing bindings of one name.
                let local_id = format!(
                    "{}@{}:{}@{}",
                    f.file, binding.scope, binding.name, binding.intro
                );
                let to = SymbolId::local(f.file.clone(), local_id);

                intra_edges.push(Edge {
                    from,
                    to,
                    role: r.role,
                    confidence: Confidence::Exact,
                    provenance: Provenance::ScopeGraph,
                    occ: r.occ.clone(),
                });
            }
            BindingKind::Definition => {
                // Same-file definition: resolve to the bound symbol's identity,
                // precisely.
                if let BindingTarget::Def(target_id) = &binding.target {
                    // A definition never links to itself (same-file recursion) —
                    // parity with Tier-A, which skips `i == from_idx`.
                    if &from != target_id {
                        intra_edges.push(Edge {
                            from,
                            to: target_id.clone(),
                            role: r.role,
                            confidence: Confidence::Scoped,
                            provenance: Provenance::ScopeGraph,
                            occ: r.occ.clone(),
                        });
                    }
                }
                // (A Definition binding always carries Def(_); the `if let` is
                // defensive.)
            }
            BindingKind::Import => {
                if let BindingTarget::Import(from_path) = &binding.target {
                    let segs: &[&str] = import_segs_cache
                        .get(from_path.as_str())
                        .map(Vec::as_slice)
                        .unwrap_or(&[]);
                    if !segs.is_empty() {
                        // Among global symbols sharing the imported name, the
                        // stitch phase finds the UNIQUE one whose namespace chain
                        // ends with the import path segments.
                        pending.push(PendingRef {
                            from,
                            name: binding.name.clone(),
                            segs: segs.iter().copied().map(str::to_string).collect(),
                            role: r.role,
                            occ: r.occ.clone(),
                            confidence: Confidence::Exact,
                            qualified: false,
                        });
                    }
                    // Empty segs → drop (Tier-B never fakes precision; Tier-A
                    // still provides recall via fan-out for those).
                }
                // No from_path → no edge.
            }
        }
    }

    FileSubgraph {
        schema_version: FILE_SUBGRAPH_SCHEMA_VERSION,
        owner_file: f.file.clone(),
        symbols,
        intra_edges,
        pending,
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
    // Facts may come from deserialization at binding boundaries. A malformed
    // parent cycle must not turn resolution into an unbounded CPU loop.
    for _ in 0..scopes.len() {
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
    // More parent hops than scopes proves a cycle or malformed index chain.
    None
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
    use crate::extract::{Extractor, RustExtractor};

    /// All `TypeRef` pending refs `build_subgraph` defers for `f`.
    fn typeref_pendings(f: &FileFacts) -> Vec<PendingRef> {
        build_subgraph(f)
            .pending
            .into_iter()
            .filter(|p| p.role == RefRole::TypeRef)
            .collect()
    }

    /// A cross-artifact-style `TypeRef` — a field type whose definition lives in
    /// a DIFFERENT namespace and is unbound in this file — is deferred with EMPTY
    /// `segs`, so the stitch phase can match it by globally-unique name alone
    /// rather than by this file's namespace (which would never match a target in
    /// another artifact/namespace). This is the recall fix for cross_artifact.
    #[test]
    fn unbound_typeref_defers_with_empty_segs() {
        // `src/model.rs` → file namespace ["model"]. The field type `Users` has
        // no in-file binding (it is defined elsewhere), so it must defer empty.
        let consumer = RustExtractor
            .extract("pub struct Order { who: Users }", "src/model.rs")
            .unwrap();

        let users_pending: Vec<PendingRef> = typeref_pendings(&consumer)
            .into_iter()
            .filter(|p| p.name == "Users")
            .collect();

        assert_eq!(
            users_pending.len(),
            1,
            "expected exactly one deferred TypeRef for the unbound `Users`"
        );
        let p = &users_pending[0];
        assert!(
            p.segs.is_empty(),
            "cross-artifact TypeRef must defer with empty segs (match by unique \
             name across artifacts), got {:?}",
            p.segs
        );
        assert_eq!(
            p.confidence,
            Confidence::Scoped,
            "deferred TypeRef stays Scoped (never fakes Exact)"
        );
    }

    /// Precision contract: an empty-`segs` TypeRef matches the target only when
    /// it is GLOBALLY UNIQUE by name. With a single `Users` definition (in an
    /// empty-namespace `src/lib.rs`, a different namespace than the consumer)
    /// the unique-name match resolves to exactly one edge.
    #[test]
    fn cross_artifact_unique_typeref_resolves_one_edge() {
        use super::super::stitch::{GlobalIndex, stitch};

        // Target lives in an EMPTY namespace (src/lib.rs); consumer in ["model"].
        let provider = RustExtractor
            .extract("pub struct Users {}", "src/lib.rs")
            .unwrap();
        let consumer = RustExtractor
            .extract("pub struct Order { who: Users }", "src/model.rs")
            .unwrap();

        let provider_sub = build_subgraph(&provider);
        let consumer_sub = build_subgraph(&consumer);

        let mut index = GlobalIndex::new();
        index.insert_symbols(&provider_sub.owner_file, &provider_sub.symbols);

        let type_edges: Vec<Edge> = stitch(&consumer_sub.pending, &index)
            .into_iter()
            .filter(|e| e.role == RefRole::TypeRef && e.to.leaf_name() == Some("Users"))
            .collect();

        assert_eq!(
            type_edges.len(),
            1,
            "a globally-unique cross-namespace TypeRef must resolve to exactly \
             one ScopeGraph edge"
        );
        assert_eq!(type_edges[0].provenance, Provenance::ScopeGraph);
        assert_eq!(type_edges[0].confidence, Confidence::Scoped);
    }

    /// Precision contract (the other side): when TWO definitions share the name
    /// `Users`, the empty-`segs` match is ambiguous → stitch's `unique_match`
    /// emits NO edge. Empty segs widen recall but never fake precision.
    #[test]
    fn ambiguous_typeref_resolves_no_edge() {
        use super::super::stitch::{GlobalIndex, stitch};

        // Two distinct `Users` defs in different namespaces.
        let p1 = RustExtractor
            .extract("pub struct Users {}", "src/a.rs")
            .unwrap();
        let p2 = RustExtractor
            .extract("pub struct Users {}", "src/b.rs")
            .unwrap();
        let consumer = RustExtractor
            .extract("pub struct Order { who: Users }", "src/model.rs")
            .unwrap();

        let consumer_sub = build_subgraph(&consumer);

        let p1_sub = build_subgraph(&p1);
        let p2_sub = build_subgraph(&p2);
        let mut index = GlobalIndex::new();
        index.insert_symbols(&p1_sub.owner_file, &p1_sub.symbols);
        index.insert_symbols(&p2_sub.owner_file, &p2_sub.symbols);

        let type_edges = stitch(&consumer_sub.pending, &index)
            .into_iter()
            .filter(|e| e.role == RefRole::TypeRef && e.to.leaf_name() == Some("Users"))
            .count();

        assert_eq!(
            type_edges, 0,
            "two same-named definitions → ambiguous → no edge (precision preserved)"
        );
    }
}
