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

use code2graph::{CodeGraph, Provenance, RefRole};
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

/// Precision+recall of one resolver's graph at each confidence cutoff.
///
/// Each field is the scorecard of `graph.min_confidence(tier)`: tightening the
/// cutoff keeps fewer edges, so recall is non-increasing (`Heuristic` → `Exact`)
/// while precision rises (fewer false positives relative to true positives).
///
/// The `Heuristic` field represents **all** edges (no filtering), because
/// `Confidence::Heuristic` is the lowest variant and `min_confidence` keeps
/// every edge at or above it.
#[derive(Default)]
pub struct TieredScorecard {
    /// `graph.min_confidence(Confidence::Heuristic)` — all edges.
    pub heuristic: Scorecard,
    /// `graph.min_confidence(Confidence::NameOnly)` — drops `Heuristic` edges.
    pub name_only: Scorecard,
    /// `graph.min_confidence(Confidence::Scoped)` — drops `Heuristic` + `NameOnly`.
    pub scoped: Scorecard,
    /// `graph.min_confidence(Confidence::Exact)` — keeps only `Exact` edges.
    pub exact: Scorecard,
}

impl TieredScorecard {
    /// Fold another `TieredScorecard`'s tallies into this one (for per-language
    /// or whole-corpus aggregation).
    pub fn merge(&mut self, other: &TieredScorecard) {
        self.heuristic.merge(&other.heuristic);
        self.name_only.merge(&other.name_only);
        self.scoped.merge(&other.scoped);
        self.exact.merge(&other.exact);
    }
}

/// Project a resolved [`CodeGraph`] into the located-edge space and score it
/// against the expected set.
///
/// An emitted edge whose target [`code2graph::SymbolId`] has no matching symbol in
/// the graph is an over-connection and counts as a **false positive** — a resolver
/// claiming an intra-graph resolution to a definition that does not exist. The one
/// exception is a [`Provenance::External`] edge, which deliberately points outside
/// the corpus (a call into a dependency whose body isn't extracted); the oracle
/// can't enumerate external defs, so those are skipped — neither credited nor
/// penalised. Edges whose role isn't asserted by this case stay invisible.
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

    // Edges that pass the role filter but whose target can't be located: a
    // genuine over-connection unless they are honestly `External`.
    let mut unlocatable_fp = 0usize;

    let emitted: HashSet<ExpectedEdge> = graph
        .edges
        .iter()
        .filter_map(|e| {
            if !expected_roles.contains(&e.role) {
                return None;
            }
            let Some((def_file, def_line)) = def_loc.get(&e.to.to_scip_string()) else {
                if e.provenance != Provenance::External {
                    unlocatable_fp += 1;
                }
                return None;
            };
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
        false_positives: (emitted.len() - true_positives) + unlocatable_fp,
        false_negatives: expected.len() - true_positives,
    }
}

/// Recover the `(file, 1-based def line)` for an edge target that is a
/// synthesized local symbol, by parsing its SCIP string of the form
/// `local <file>@<scope>:<name>@<intro>` where `intro` is the 0-based byte
/// offset of the binding introduction, and converting that offset to a line
/// number using the file's source text.
///
/// Returns `None` if the string isn't in local form, the file has no source
/// entry, or the byte offset is out of range.
///
/// Assumption (noted here): the file basename and binding name contain no `@`
/// character. This holds for the corpus basenames and all valid identifiers.
pub(crate) fn local_def_loc(
    scip: &str,
    sources: &std::collections::HashMap<String, String>,
) -> Option<(String, u32)> {
    let rest = scip.strip_prefix("local ")?;
    // file is everything before the FIRST '@'
    let (file, after) = rest.split_once('@')?;
    // intro is the integer after the LAST '@'
    let intro: usize = after.rsplit_once('@')?.1.parse().ok()?;
    let src = sources.get(file)?;
    if intro > src.len() {
        return None;
    }
    let line = 1 + src.as_bytes()[..intro]
        .iter()
        .filter(|&&b| b == b'\n')
        .count() as u32;
    Some((file.to_string(), line))
}

/// Score a resolved [`CodeGraph`] against SCIP-oracle location pairs.
///
/// Matching is location-only: an emitted edge is a true positive iff
/// `(ref_file, ref_line, def_file, def_line)` appears in the oracle set.
/// Role is ignored — SCIP occurrence roles don't map 1-to-1 onto
/// code2graph's [`RefRole`] taxonomy.
///
/// `sources` maps each file basename to its full source text, used to
/// resolve the definition line of local-symbol targets (synthesized locals
/// carry a byte-offset rather than appearing in `graph.symbols`).
///
/// An emitted edge whose target is locatable by neither `graph.symbols` nor
/// [`local_def_loc`] counts as a **false positive** — an over-connection to a
/// definition that does not exist. The exception is a [`Provenance::External`]
/// edge, which honestly points outside the corpus the oracle can verify; those
/// are skipped (neither credited nor penalised).
pub fn score_oracle(
    graph: &CodeGraph,
    oracle: &[(String, u32, String, u32)],
    sources: &std::collections::HashMap<String, String>,
) -> Scorecard {
    // Build def location map the same way `score` does.
    let mut def_loc = std::collections::HashMap::new();
    for sym in &graph.symbols {
        def_loc.insert(sym.id.to_scip_string(), (sym.file.clone(), sym.line));
    }

    // Emitted edges whose target is locatable by neither path: an over-connection
    // unless honestly `External`.
    let mut unlocatable_fp = 0usize;

    let emitted: HashSet<(String, u32, String, u32)> = graph
        .edges
        .iter()
        .filter_map(|e| {
            let scip = e.to.to_scip_string();
            let Some((def_file, def_line)) = def_loc
                .get(&scip)
                .cloned()
                .or_else(|| local_def_loc(&scip, sources))
            else {
                if e.provenance != Provenance::External {
                    unlocatable_fp += 1;
                }
                return None;
            };
            Some((e.occ.file.clone(), e.occ.line, def_file, def_line))
        })
        .collect();

    let expected: HashSet<(String, u32, String, u32)> = oracle.iter().cloned().collect();

    let true_positives = emitted.intersection(&expected).count();
    Scorecard {
        true_positives,
        false_positives: (emitted.len() - true_positives) + unlocatable_fp,
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

    use code2graph::{Confidence, Descriptor, Edge, Occurrence, SymbolId};

    fn unlocatable_id(name: &str) -> SymbolId {
        SymbolId::global(
            "rust",
            vec![
                Descriptor::Namespace("pkg".into()),
                Descriptor::Term(name.into()),
            ],
        )
    }

    fn call_edge_to(to: SymbolId, provenance: Provenance) -> Edge {
        Edge {
            from: unlocatable_id("caller"),
            to,
            role: RefRole::Call,
            confidence: Confidence::NameOnly,
            provenance,
            occ: Occurrence {
                file: "main.rs".into(),
                line: 3,
                col: 0,
                byte: 0,
            },
        }
    }

    /// An edge to a target absent from `graph.symbols` is an over-connection: a
    /// `SymbolTable` (non-External) edge counts as a false positive, while an
    /// honest `External` edge to the same unlocatable target does not.
    #[test]
    fn unlocatable_non_external_target_is_a_false_positive() {
        // The graph has no symbols at all, so every edge target is unlocatable.
        let expected = [ExpectedEdge {
            ref_file: "main.rs".into(),
            ref_line: 3,
            role: RefRole::Call,
            def_file: "lib.rs".into(),
            def_line: 1,
        }];

        // (a) non-External target → counted as a false positive.
        let non_external = CodeGraph {
            symbols: vec![],
            edges: vec![call_edge_to(
                unlocatable_id("ghost"),
                Provenance::SymbolTable,
            )],
        };
        let s = score(&non_external, &expected);
        assert_eq!(s.true_positives, 0);
        assert_eq!(
            s.false_positives, 1,
            "junk intra-graph edge must be penalised"
        );

        // (b) External target → exempt, neither TP nor FP.
        let external = CodeGraph {
            symbols: vec![],
            edges: vec![call_edge_to(unlocatable_id("dep"), Provenance::External)],
        };
        let s = score(&external, &expected);
        assert_eq!(s.true_positives, 0);
        assert_eq!(
            s.false_positives, 0,
            "honest External edge must not be penalised"
        );
    }
}
