// SPDX-License-Identifier: Apache-2.0

//! Prints a per-language, per-tier precision/recall scorecard for the corpus.
//!
//! ```text
//! cargo run -p code2graph-eval
//! ```

use code2graph::{FfiBridgeResolver, LayeredResolver, ScopeGraphResolver, SymbolTableResolver};
use code2graph_eval::corpus::load_corpus;
use code2graph_eval::diagnose::RecallDiagnosis;
use code2graph_eval::runner::{
    corpus_total, corpus_total_tiered, diagnose_case, per_language, per_language_tiered,
};
use code2graph_eval::score::{Scorecard, TieredScorecard};
use std::collections::BTreeMap;
use std::path::Path;
use std::process::ExitCode;

/// Tier label paired with its per-language and total scorecards.
struct TierReport {
    label: &'static str,
    per_lang: BTreeMap<String, Scorecard>,
    total: Scorecard,
}

fn main() -> ExitCode {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus");
    let cases = match load_corpus(&root) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("failed to load corpus at {}: {e}", root.display());
            return ExitCode::FAILURE;
        }
    };
    if cases.is_empty() {
        eprintln!("corpus is empty at {}", root.display());
        return ExitCode::FAILURE;
    }

    let tiers = [
        TierReport {
            label: "Tier-A (name)",
            per_lang: per_language(&cases, &SymbolTableResolver),
            total: corpus_total(&cases, &SymbolTableResolver),
        },
        TierReport {
            label: "Tier-B (scope)",
            per_lang: per_language(&cases, &ScopeGraphResolver),
            total: corpus_total(&cases, &ScopeGraphResolver),
        },
        // The CLI's actual default tier: scope-path resolution plus the additive
        // receiver-typed passes (Conformance + LocalTypedCall). Measured here so
        // their precise `Scoped` member edges are visible, unlike the
        // `ScopeGraphResolver`-only row above.
        TierReport {
            label: "Scoped+ (default)",
            per_lang: per_language(&cases, &LayeredResolver::default_scoped()),
            total: corpus_total(&cases, &LayeredResolver::default_scoped()),
        },
        TierReport {
            label: "FFI (bridge)",
            per_lang: per_language(&cases, &FfiBridgeResolver),
            total: corpus_total(&cases, &FfiBridgeResolver),
        },
    ];

    let langs: Vec<&String> = tiers[0].per_lang.keys().collect();
    println!(
        "code2graph eval — {} cases across {} languages\n",
        cases.len(),
        langs.len()
    );
    print_header(&tiers);
    for lang in &langs {
        let scores: Vec<&Scorecard> = tiers
            .iter()
            .map(|t| t.per_lang.get(*lang).expect("lang present in every tier"))
            .collect();
        print_row(lang, &scores);
    }
    print_divider(tiers.len());
    let totals: Vec<&Scorecard> = tiers.iter().map(|t| &t.total).collect();
    print_row("ALL", &totals);
    println!("\nP = precision, R = recall, F1 = harmonic mean (ref→def edges).");

    // ── Layered (dense) — recall@tier ────────────────────────────────────────
    let tiered_by_lang = per_language_tiered(&cases);
    let tiered_total = corpus_total_tiered(&cases);

    println!("\nLayered (dense) — recall@tier\n");
    print_tiered_header();
    for lang in &langs {
        if let Some(ts) = tiered_by_lang.get(*lang) {
            print_tiered_row(lang, ts);
        }
    }
    print_tiered_divider();
    print_tiered_row("ALL", &tiered_total);
    println!(
        "\nR@Heur = recall at Heuristic (all edges), R@Name = NameOnly+, \
         R@Scoped = Scoped+, R@Exact = Exact only, P@Exact = precision at Exact."
    );

    // ── Recall diagnosis — real-repo cases only, dense tier ──────────────────
    let mut diag_by_lang: BTreeMap<String, RecallDiagnosis> = BTreeMap::new();
    for case in &cases {
        if !case.lang.contains("realrepo") {
            continue;
        }
        if let Some(d) = diagnose_case(case) {
            diag_by_lang.entry(case.lang.clone()).or_default().merge(&d);
        }
    }
    print_recall_diagnosis(&diag_by_lang);

    // Opt-in: dump a sample of structural-def misses (with source lines) so the
    // missing definition KINDS can be inspected. `C2G_EVAL_SAMPLES=1 cargo run …`.
    if std::env::var_os("C2G_EVAL_SAMPLES").is_some() {
        print_structural_samples(&cases);
    }

    ExitCode::SUCCESS
}

/// Print up to 15 structural-def misses per real-repo language, each as the ref
/// source line and the def source line it points at.
fn print_structural_samples(cases: &[code2graph_eval::corpus::Case]) {
    println!("\nStructural-miss samples (def not extracted, not a local) — ref → def source\n");
    for case in cases {
        if !case.lang.contains("realrepo") {
            continue;
        }
        let samples = code2graph_eval::runner::structural_samples_for_case(case, 15);
        if samples.is_empty() {
            continue;
        }
        println!("── {} / {} ──", case.lang, case.name);
        for s in &samples {
            println!(
                "  {}:{}  {}\n    → {}:{}  {}",
                s.ref_file, s.ref_line, s.ref_source, s.def_file, s.def_line, s.def_source
            );
        }
    }
}

/// Print the per-language recall-gap cause breakdown for the real-repo cases.
///
/// Prints nothing beyond a short note when no real-repo cases are present (the
/// corpus wasn't generated) — never fails.
fn print_recall_diagnosis(by_lang: &BTreeMap<String, RecallDiagnosis>) {
    if by_lang.is_empty() {
        println!("\nRecall diagnosis — no real-repo cases present.");
        return;
    }

    println!("\nRecall diagnosis (dense tier, real-repo misses by cause)\n");
    print!("{:<16}", "language");
    println!(
        " │ {:>6} {:>7} {:>7} {:>7} {:>7}",
        "missed", "nearln", "nodef", "noref", "other"
    );
    print!("{:-<16}", "");
    println!("-┼{:-<40}", "");
    for (lang, d) in by_lang {
        print!("{:<16}", lang);
        println!(
            " │ {:>6} {:>7} {:>7} {:>7} {:>7}",
            d.missed,
            d.near_miss_line,
            d.def_not_extracted,
            d.ref_not_captured,
            d.resolved_to_other
        );
        println!(
            "  nodef split: in-function (local/param, out of scope) = {}, structural (real gap) = {}",
            d.def_in_function, d.def_structural,
        );
        println!(
            "  captured_unresolved = {} → by shape: self={} recv={} import={} bare={}",
            d.captured_unresolved,
            d.cu_self_receiver,
            d.cu_qualified_receiver,
            d.cu_imported,
            d.cu_bare_name,
        );
    }
    println!(
        "\nnearln = alignment (edge emitted, line off ≤2), nodef = def not extracted \
         (split into in-function locals vs structural misses), noref = ref not captured, \
         other = resolved elsewhere; captured_unresolved = pure resolution gap (the actionable bucket)."
    );
}

fn print_tiered_header() {
    print!("{:<12}", "language");
    print!(
        " │ {:>6} {:>6} {:>6} {:>6} {:>7}",
        "R@Heur", "R@Name", "R@Scpd", "R@Exct", "P@Exct"
    );
    println!();
    print_tiered_divider();
}

fn print_tiered_divider() {
    print!("{:-<12}", "");
    print!("-┼{:-<41}", "");
    println!();
}

fn print_tiered_row(label: &str, ts: &TieredScorecard) {
    print!("{:<12}", label);
    print!(
        " │ {:>6.2} {:>6.2} {:>6.2} {:>6.2} {:>7.2}",
        ts.heuristic.recall(),
        ts.name_only.recall(),
        ts.scoped.recall(),
        ts.exact.recall(),
        ts.exact.precision(),
    );
    println!();
}

fn print_header(tiers: &[TierReport]) {
    print!("{:<12}", "language");
    for t in tiers {
        print!(" │ {:^22}", t.label);
    }
    println!();
    print!("{:<12}", "");
    for _ in tiers {
        print!(" │ {:>6} {:>6} {:>6}", "P", "R", "F1");
    }
    println!();
    print_divider(tiers.len());
}

fn print_divider(n: usize) {
    print!("{:-<12}", "");
    for _ in 0..n {
        print!("-┼{:-<23}", "");
    }
    println!();
}

fn print_row(label: &str, scores: &[&Scorecard]) {
    print!("{:<12}", label);
    for sc in scores {
        print!(
            " │ {:>6.2} {:>6.2} {:>6.2}",
            sc.precision(),
            sc.recall(),
            sc.f1()
        );
    }
    println!();
}
