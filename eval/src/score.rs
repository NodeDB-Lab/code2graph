// SPDX-License-Identifier: Apache-2.0

//! Pure precision/recall scoring of resolved edges against ground truth.
//!
//! The evaluation unit is a **located ref→def edge**: a reference site (file +
//! line) bound to a definition site (file + line) under some [`RefRole`]. This
//! granularity is what exposes name-only fan-out — a single reference that
//! resolves to *N* same-named definitions counts as one true positive and
//! `N - 1` false positives, so an over-connecting resolver is penalised exactly
//! where it over-connects.
//!
//! The scorer is agnostic about where the *expected* set came from: hand-authored
//! golden fixtures today, a SCIP precision oracle (rust-analyzer / scip-java)
//! later. Both project into the same located-edge space.

use code2graph::{CodeGraph, RefRole};
use std::collections::HashSet;

/// A ground-truth ref→def edge, located by file + line at both ends.
///
/// Lines are 1-based, matching [`code2graph::Symbol::line`] and
/// [`code2graph::Occurrence::line`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExpectedEdge {
    /// File containing the reference (use) site.
    pub ref_file: String,
    /// 1-based line of the reference site.
    pub ref_line: u32,
    /// The relationship the edge expresses.
    pub role: RefRole,
    /// File containing the target definition.
    pub def_file: String,
    /// 1-based line of the target definition.
    pub def_line: u32,
}

/// The tallies and derived rates of one comparison.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Scorecard {
    /// Emitted edges that match an expected edge.
    pub true_positives: usize,
    /// Emitted edges with no matching expected edge (over-connection).
    pub false_positives: usize,
    /// Expected edges no emitted edge matched (under-connection).
    pub false_negatives: usize,
}

impl Scorecard {
    /// `TP / (TP + FP)`. An empty claim set (no edges emitted) scores `1.0`: a
    /// resolver that says nothing makes no *wrong* claim — its weakness is recall,
    /// not precision. This mirrors Tier-B's contract of never faking precision.
    pub fn precision(&self) -> f64 {
        let denom = self.true_positives + self.false_positives;
        if denom == 0 {
            1.0
        } else {
            self.true_positives as f64 / denom as f64
        }
    }

    /// `TP / (TP + FN)`. An empty ground-truth set scores `1.0`: there was
    /// nothing to find, so nothing was missed.
    pub fn recall(&self) -> f64 {
        let denom = self.true_positives + self.false_negatives;
        if denom == 0 {
            1.0
        } else {
            self.true_positives as f64 / denom as f64
        }
    }

    /// Harmonic mean of [`precision`](Self::precision) and
    /// [`recall`](Self::recall); `0.0` when both are zero.
    pub fn f1(&self) -> f64 {
        let (p, r) = (self.precision(), self.recall());
        if p + r == 0.0 {
            0.0
        } else {
            2.0 * p * r / (p + r)
        }
    }

    /// Fold another scorecard's tallies into this one (for per-language or
    /// whole-corpus aggregation).
    pub fn merge(&mut self, other: &Scorecard) {
        self.true_positives += other.true_positives;
        self.false_positives += other.false_positives;
        self.false_negatives += other.false_negatives;
    }
}

/// Project a resolved [`CodeGraph`] into the located-edge space and score it
/// against the expected set.
///
/// An emitted edge whose target [`code2graph::SymbolId`] has no matching symbol in
/// the graph (which should not happen for a well-formed graph) is skipped — it
/// cannot be located, so it is neither credited nor penalised.
pub fn score(graph: &CodeGraph, expected: &[ExpectedEdge]) -> Scorecard {
    // Locate every definition by its SCIP identity.
    let mut def_loc = std::collections::HashMap::new();
    for sym in &graph.symbols {
        def_loc.insert(sym.id.to_scip_string(), (sym.file.clone(), sym.line));
    }

    // Only score emitted edges whose role is actually asserted by this case.
    // Roles not mentioned in `expected` are invisible — neither TP nor FP —
    // so adding new role variants never breaks existing cases.
    let expected_roles: std::collections::HashSet<RefRole> =
        expected.iter().map(|e| e.role).collect();

    let emitted: HashSet<ExpectedEdge> = graph
        .edges
        .iter()
        .filter_map(|e| {
            if !expected_roles.contains(&e.role) {
                return None;
            }
            let (def_file, def_line) = def_loc.get(&e.to.to_scip_string())?;
            Some(ExpectedEdge {
                ref_file: e.occ.file.clone(),
                ref_line: e.occ.line,
                role: e.role,
                def_file: def_file.clone(),
                def_line: *def_line,
            })
        })
        .collect();

    let expected: HashSet<ExpectedEdge> = expected.iter().cloned().collect();

    let true_positives = emitted.intersection(&expected).count();
    Scorecard {
        true_positives,
        false_positives: emitted.len() - true_positives,
        false_negatives: expected.len() - true_positives,
    }
}

/// Score a resolved [`CodeGraph`] against SCIP-oracle location pairs.
///
/// Matching is location-only: an emitted edge is a true positive iff
/// `(ref_file, ref_line, def_file, def_line)` appears in the oracle set.
/// Role is ignored — SCIP occurrence roles don't map 1-to-1 onto
/// code2graph's [`RefRole`] taxonomy.
pub fn score_oracle(graph: &CodeGraph, oracle: &[(String, u32, String, u32)]) -> Scorecard {
    // Build def location map the same way `score` does.
    let mut def_loc = std::collections::HashMap::new();
    for sym in &graph.symbols {
        def_loc.insert(sym.id.to_scip_string(), (sym.file.clone(), sym.line));
    }

    let emitted: HashSet<(String, u32, String, u32)> = graph
        .edges
        .iter()
        .filter_map(|e| {
            let (def_file, def_line) = def_loc.get(&e.to.to_scip_string())?;
            Some((e.occ.file.clone(), e.occ.line, def_file.clone(), *def_line))
        })
        .collect();

    let expected: HashSet<(String, u32, String, u32)> = oracle.iter().cloned().collect();

    let true_positives = emitted.intersection(&expected).count();
    Scorecard {
        true_positives,
        false_positives: emitted.len() - true_positives,
        false_negatives: expected.len() - true_positives,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precision_recall_f1_basic() {
        let s = Scorecard {
            true_positives: 3,
            false_positives: 1,
            false_negatives: 1,
        };
        assert_eq!(s.precision(), 0.75);
        assert_eq!(s.recall(), 0.75);
        assert_eq!(s.f1(), 0.75);
    }

    #[test]
    fn empty_claim_is_perfectly_precise() {
        let s = Scorecard {
            true_positives: 0,
            false_positives: 0,
            false_negatives: 2,
        };
        assert_eq!(s.precision(), 1.0);
        assert_eq!(s.recall(), 0.0);
    }

    #[test]
    fn empty_ground_truth_is_full_recall() {
        let s = Scorecard::default();
        assert_eq!(s.precision(), 1.0);
        assert_eq!(s.recall(), 1.0);
    }

    #[test]
    fn merge_sums_tallies() {
        let mut a = Scorecard {
            true_positives: 1,
            false_positives: 2,
            false_negatives: 3,
        };
        a.merge(&Scorecard {
            true_positives: 4,
            false_positives: 5,
            false_negatives: 6,
        });
        assert_eq!(a.true_positives, 5);
        assert_eq!(a.false_positives, 7);
        assert_eq!(a.false_negatives, 9);
    }
}
