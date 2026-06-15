// SPDX-License-Identifier: Apache-2.0

//! Regression guard for resolution quality.
//!
//! These assertions turn the harness into a non-regression gate: they encode the
//! *invariants* the tiers must uphold, not brittle exact rates. A drop in
//! Tier-A recall, a Tier-B false positive, or an erosion of the scope-tier's
//! precision advantage all fail the build here.

use code2graph::{FfiBridgeResolver, ScopeGraphResolver, SymbolTableResolver};
use code2graph_eval::corpus::{Case, load_corpus};
use code2graph_eval::runner::{corpus_total, per_language, score_case};
use std::path::Path;

fn corpus() -> Vec<Case> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus");
    load_corpus(&root).expect("corpus loads")
}

/// Cases in a given language directory.
fn cases_in<'a>(cases: &'a [Case], lang: &str) -> Vec<&'a Case> {
    cases.iter().filter(|c| c.lang == lang).collect()
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
fn scip_oracle_tier_b_beats_tier_a_on_ambiguous_calls() {
    // Same thesis as `scope_tier_beats_name_tier_on_precision_where_it_resolves`,
    // but locked against an EXTERNAL SCIP oracle instead of hand-authored golden
    // edges: on the oracle lanes that include an ambiguous-call case
    // ("rust_oracle", "py_oracle", "ts_oracle"), Tier-B must be strictly more
    // precise than Tier-A and invent no edges. "go_oracle" is excluded — it has
    // no ambiguous_call case, so name resolution never fans out there.
    let cases = corpus();
    let a = per_language(&cases, &SymbolTableResolver);
    let b = per_language(&cases, &ScopeGraphResolver);
    for lang in ["rust_oracle", "py_oracle", "ts_oracle"] {
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
