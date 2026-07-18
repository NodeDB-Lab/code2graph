// SPDX-License-Identifier: Apache-2.0

//! Regression guard for resolution quality.
//!
//! These assertions turn the harness into a non-regression gate: they encode the
//! *invariants* the tiers must uphold, not brittle exact rates. A drop in
//! Tier-A recall, a Tier-B false positive, or an erosion of the scope-tier's
//! precision advantage all fail the build here.

use code2graph::{FfiBridgeResolver, ScopeGraphResolver, SymbolTableResolver};
use code2graph_eval::corpus::{Case, load_corpus};
use code2graph_eval::runner::{corpus_total, corpus_total_tiered, per_language, score_case};
use std::path::Path;

fn corpus() -> Vec<Case> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus");
    load_corpus(&root)
        .expect("corpus loads")
        .into_iter()
        // `*_realrepo` cases are large real-world MEASUREMENT fixtures (scored by
        // the scorecard binary, see REAL-REPO-SCORECARD.md), not curated invariant
        // fixtures. Real code has macro/generic/line-divergence sites a build-free
        // resolver genuinely mis-resolves, so the perfect-precision / full-recall
        // invariants below hold only on the curated `*_oracle` + hand-built cases.
        // They are also gitignored, so this keeps the guard identical whether or
        // not a maintainer has regenerated them locally.
        .filter(|c| !c.lang.ends_with("_realrepo"))
        .collect()
}

/// Cases in a given language directory.
fn cases_in<'a>(cases: &'a [Case], lang: &str) -> Vec<&'a Case> {
    cases.iter().filter(|c| c.lang == lang).collect()
}

// ── C7: LayeredResolver density tests ────────────────────────────────────────

/// Tightening the confidence cutoff can only remove edges, never add them, so
/// recall is non-increasing as the threshold rises: Heuristic ≥ NameOnly ≥
/// Scoped ≥ Exact.
#[test]
fn layered_recall_is_monotonic_non_increasing() {
    let cases = corpus();
    let t = corpus_total_tiered(&cases);
    assert!(
        t.heuristic.recall() >= t.name_only.recall(),
        "recall@Heuristic ({:.4}) must be >= recall@NameOnly ({:.4})",
        t.heuristic.recall(),
        t.name_only.recall()
    );
    assert!(
        t.name_only.recall() >= t.scoped.recall(),
        "recall@NameOnly ({:.4}) must be >= recall@Scoped ({:.4})",
        t.name_only.recall(),
        t.scoped.recall()
    );
    assert!(
        t.scoped.recall() >= t.exact.recall(),
        "recall@Scoped ({:.4}) must be >= recall@Exact ({:.4})",
        t.scoped.recall(),
        t.exact.recall()
    );
}

/// The density thesis: `LayeredResolver` at the Heuristic (all-edges) cutoff
/// achieves recall at least as good as each individual resolver alone over the
/// same corpus. The union can only add edges, never remove them, so the layered
/// recall is an upper bound on any single layer's recall.
#[test]
fn layered_recall_at_heuristic_beats_each_single_tier() {
    let cases = corpus();
    let layered = corpus_total_tiered(&cases);
    let layered_recall = layered.heuristic.recall();

    let name_recall = corpus_total(&cases, &SymbolTableResolver).recall();
    let scope_recall = corpus_total(&cases, &ScopeGraphResolver).recall();
    let ffi_recall = corpus_total(&cases, &FfiBridgeResolver).recall();

    assert!(
        layered_recall >= name_recall,
        "LayeredResolver recall@Heuristic ({:.4}) must be >= SymbolTableResolver recall ({:.4})",
        layered_recall,
        name_recall
    );
    assert!(
        layered_recall >= scope_recall,
        "LayeredResolver recall@Heuristic ({:.4}) must be >= ScopeGraphResolver recall ({:.4})",
        layered_recall,
        scope_recall
    );
    assert!(
        layered_recall >= ffi_recall,
        "LayeredResolver recall@Heuristic ({:.4}) must be >= FfiBridgeResolver recall ({:.4})",
        layered_recall,
        ffi_recall
    );
}

/// Precision is non-decreasing as the cutoff tightens: the strict end (Exact)
/// is at least as precise as the dense end (Heuristic).
///
/// Made non-vacuous by first requiring the Exact tier to actually make claims:
/// `Scorecard::precision()` returns `1.0` for an empty claim set, so without this
/// precondition the monotonicity check passes for free whenever the Exact tier
/// emits nothing. The corpus does produce Exact edges today, so the precondition
/// holds; if it ever stops, this test should fail loudly rather than pass
/// vacuously. We then assert the strict end fakes nothing (zero false positives)
/// before checking the monotonicity itself.
#[test]
fn layered_precision_improves_toward_exact() {
    let cases = corpus();
    let t = corpus_total_tiered(&cases);

    assert!(
        t.exact.true_positives + t.exact.false_positives > 0,
        "corpus must produce Exact-tier edges for this precision invariant to be meaningful"
    );
    assert_eq!(
        t.exact.false_positives, 0,
        "Exact tier must never fake precision"
    );
    assert!(
        t.exact.precision() >= t.heuristic.precision(),
        "precision@Exact ({:.4}) must be >= precision@Heuristic ({:.4})",
        t.exact.precision(),
        t.heuristic.precision()
    );
}

#[test]
fn corpus_is_non_empty() {
    assert!(!corpus().is_empty(), "eval corpus must contain cases");
}

#[test]
fn tier_a_is_recall_first() {
    // Tier-A is the recall-first tier: within its lane (intra-language name
    // resolution) it must find every ground-truth edge. Two lanes are excluded:
    // the `ffi` lane is a different resolver's job (cross-runtime boundaries),
    // and the `*_oracle` lanes are scored location-only against a SCIP index
    // whose ground truth includes edges outside name resolution's lane (module
    // references, imports), so full name-resolution recall is not the invariant
    // there.
    let cases = corpus();
    let in_lane: Vec<Case> = cases
        .into_iter()
        .filter(|c| c.lang != "ffi" && !c.lang.ends_with("_oracle"))
        .collect();
    let total = corpus_total(&in_lane, &SymbolTableResolver);
    assert_eq!(
        total.recall(),
        1.0,
        "Tier-A must retain full recall in its lane (TP={}, FN={})",
        total.true_positives,
        total.false_negatives
    );
}

#[test]
fn ffi_bridge_recovers_what_name_resolution_cannot() {
    // The FFI corpus deliberately uses an `#[export_name]` mismatch: the call
    // name differs from the definition name, so name/scope resolution cannot
    // bridge it, but the FFI resolver follows the export marker.
    let cases = corpus();
    let ffi = cases_in(&cases, "ffi");
    assert!(!ffi.is_empty(), "expected ffi corpus cases");

    let mut ffi_tier = code2graph_eval::score::Scorecard::default();
    let mut name_tier = code2graph_eval::score::Scorecard::default();
    let mut scope_tier = code2graph_eval::score::Scorecard::default();
    for c in &ffi {
        ffi_tier.merge(&score_case(c, &FfiBridgeResolver));
        name_tier.merge(&score_case(c, &SymbolTableResolver));
        scope_tier.merge(&score_case(c, &ScopeGraphResolver));
    }
    assert_eq!(
        ffi_tier.recall(),
        1.0,
        "FFI bridge must resolve the boundary"
    );
    assert_eq!(ffi_tier.false_positives, 0, "FFI bridge must be precise");
    assert_eq!(
        name_tier.true_positives, 0,
        "name resolution must not recover the export-name-mismatched edge"
    );
    assert_eq!(
        scope_tier.true_positives, 0,
        "scope resolution must not either"
    );
}

#[test]
fn tier_b_never_fakes_precision() {
    // Tier-B's contract: it emits an edge only when it can resolve it precisely,
    // so it must have zero false positives across the corpus.
    let total = corpus_total(&corpus(), &ScopeGraphResolver);
    assert_eq!(
        total.false_positives, 0,
        "Tier-B must not emit false positives"
    );
    assert_eq!(total.precision(), 1.0, "Tier-B precision must be perfect");
}

#[test]
fn scope_tier_beats_name_tier_on_precision_where_it_resolves() {
    // The #1 thesis: in every language with scope extraction and genuine
    // ambiguity, the scope tier is strictly more precise than the name tier and
    // invents no edges. Asserted per scope-aware language so adding the next one
    // extends the guarantee automatically.
    let cases = corpus();
    let a = per_language(&cases, &SymbolTableResolver);
    let b = per_language(&cases, &ScopeGraphResolver);
    for lang in ["rust", "python", "typescript"] {
        let (Some(a_l), Some(b_l)) = (a.get(lang), b.get(lang)) else {
            panic!("corpus must include {lang} cases");
        };
        assert!(
            b_l.precision() > a_l.precision(),
            "Tier-B precision ({:.2}) must beat Tier-A ({:.2}) on {lang}",
            b_l.precision(),
            a_l.precision()
        );
        // And it does so without inventing edges: every Tier-B edge is correct.
        assert_eq!(
            b_l.false_positives, 0,
            "Tier-B emitted a false positive on {lang}"
        );
    }
}

#[test]
fn scip_oracle_clang_scope_tier_resolves_more_without_faking() {
    // C and C++ have no import system a build-free resolver can lean on for
    // cross-file calls (C's flat linker namespace / C++ ADL vs our path-based
    // identity; scip-clang only links cross-TU when a prototype unifies the
    // symbol, which we model as a same-file definition). So their honest,
    // measurable contribution against an external scip-clang oracle is
    // *intra-file*: the scope tier resolves strictly more edges than name-only
    // resolution — it scopes the in-function local/param reads Tier-A cannot —
    // while still inventing no edges (precision stays perfect on both tiers).
    let cases = corpus();
    let a = per_language(&cases, &SymbolTableResolver);
    let b = per_language(&cases, &ScopeGraphResolver);
    for lang in ["c_oracle", "cpp_oracle"] {
        let (Some(a_l), Some(b_l)) = (a.get(lang), b.get(lang)) else {
            panic!("corpus must include {lang} cases");
        };
        assert!(
            b_l.recall() > a_l.recall(),
            "Tier-B recall ({:.2}) must beat Tier-A ({:.2}) on {lang}",
            b_l.recall(),
            a_l.recall()
        );
        assert_eq!(
            b_l.false_positives, 0,
            "Tier-B emitted a false positive on {lang}"
        );
        assert_eq!(
            a_l.false_positives, 0,
            "Tier-A emitted a false positive on {lang}"
        );
    }
}

#[test]
fn scip_oracle_tier_b_beats_tier_a_on_ambiguous_calls() {
    // Same thesis as `scope_tier_beats_name_tier_on_precision_where_it_resolves`,
    // but locked against an EXTERNAL SCIP oracle instead of hand-authored golden
    // edges: on the oracle lanes that include an ambiguous-call case
    // ("rust_oracle", "py_oracle", "ts_oracle", "java_oracle", "kotlin_oracle",
    // "ruby_oracle"), Tier-B must be strictly more precise than Tier-A and invent
    // no edges. The ambiguity is cross-file: two packages/modules export the same
    // name (a `Service.helper()` for Java, a top-level `compute()` for Kotlin, a
    // module-qualified `Alpha.compute` for Ruby) and only one is referenced —
    // name-only resolution fans out to both, the scope tier follows the import
    // (Java/Kotlin) or the module qualifier (Ruby) to exactly one. "go_oracle" is
    // excluded — it has no ambiguous_call case, so name resolution never fans out.
    let cases = corpus();
    let a = per_language(&cases, &SymbolTableResolver);
    let b = per_language(&cases, &ScopeGraphResolver);
    for lang in [
        "rust_oracle",
        "py_oracle",
        "ts_oracle",
        "java_oracle",
        "kotlin_oracle",
        "ruby_oracle",
    ] {
        let (Some(a_l), Some(b_l)) = (a.get(lang), b.get(lang)) else {
            panic!("corpus must include {lang} cases");
        };
        assert!(
            b_l.precision() > a_l.precision(),
            "Tier-B precision ({:.2}) must beat Tier-A ({:.2}) on {lang}",
            b_l.precision(),
            a_l.precision()
        );
        assert_eq!(
            b_l.false_positives, 0,
            "Tier-B emitted a false positive on {lang}"
        );
    }
}
