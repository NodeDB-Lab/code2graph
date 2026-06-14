// SPDX-License-Identifier: Apache-2.0

//! Prints a per-language, per-tier precision/recall scorecard for the corpus.
//!
//! ```text
//! cargo run -p codegraph-eval
//! ```

use codegraph::{FfiBridgeResolver, ScopeGraphResolver, SymbolTableResolver};
use codegraph_eval::corpus::load_corpus;
use codegraph_eval::runner::{corpus_total, per_language};
use codegraph_eval::score::Scorecard;
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
        TierReport {
            label: "FFI (bridge)",
            per_lang: per_language(&cases, &FfiBridgeResolver),
            total: corpus_total(&cases, &FfiBridgeResolver),
        },
    ];

    let langs: Vec<&String> = tiers[0].per_lang.keys().collect();
    println!(
        "codegraph eval — {} cases across {} languages\n",
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
    ExitCode::SUCCESS
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
