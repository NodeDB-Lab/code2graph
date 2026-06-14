// SPDX-License-Identifier: Apache-2.0

//! Regression guard for resolution quality.
//!
//! These assertions turn the harness into a non-regression gate: they encode the
//! *invariants* the tiers must uphold, not brittle exact rates. A drop in
//! Tier-A recall, a Tier-B false positive, or an erosion of the scope-tier's
//! precision advantage all fail the build here.

use codegraph::{FfiBridgeResolver, ScopeGraphResolver, SymbolTableResolver};
use codegraph_eval::corpus::{Case, load_corpus};
use codegraph_eval::runner::{corpus_total, per_language, score_case};
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
    // resolution) it must find every ground-truth edge. The `ffi` lane is a
    // different resolver's job (cross-runtime boundaries), so it is excluded.
    let cases = corpus();
    let in_lane: Vec<Case> = cases.into_iter().filter(|c| c.lang != "ffi").collect();
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

    let mut ffi_tier = codegraph_eval::score::Scorecard::default();
    let mut name_tier = codegraph_eval::score::Scorecard::default();
    let mut scope_tier = codegraph_eval::score::Scorecard::default();
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
    // The #1 thesis: on a language with scope extraction and genuine ambiguity
    // (rust), the scope tier is strictly more precise than the name tier.
    let cases = corpus();
    let a = per_language(&cases, &SymbolTableResolver);
    let b = per_language(&cases, &ScopeGraphResolver);
    let (Some(a_rust), Some(b_rust)) = (a.get("rust"), b.get("rust")) else {
        panic!("corpus must include rust cases");
    };
    assert!(
        b_rust.precision() > a_rust.precision(),
        "Tier-B precision ({:.2}) must beat Tier-A ({:.2}) on rust",
        b_rust.precision(),
        a_rust.precision()
    );
    // And it does so without inventing edges: every Tier-B rust edge is correct.
    assert_eq!(b_rust.false_positives, 0);
}
