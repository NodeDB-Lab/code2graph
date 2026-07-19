// SPDX-License-Identifier: Apache-2.0

//! Explains *why* each oracle edge was missed, turning a bare recall number into
//! an actionable cause breakdown.
//!
//! [`score_oracle`](crate::score::score_oracle) reports recall as one number; on
//! real repos it is low (0.36–0.53), but the number alone can't say whether the
//! gap is an alignment artefact, an extraction hole, or a genuine resolution
//! failure. [`diagnose_recall`] assigns every false-negative (an oracle edge no
//! emitted edge matched) to exactly one cause bucket, checked in priority order,
//! so the buckets always sum to the total missed.
//!
//! The actionable bucket is `captured_unresolved`: the reference *was* captured
//! and the definition *was* extracted, yet no edge connects them — a pure
//! resolution gap no current resolver closes. Its `cu_*` sub-breakdown splits
//! those by the reference's syntactic shape, pointing at which resolution feature
//! (self-receiver typing, qualifier resolution, import following) would close it.
//!
//! **Honesty note — line granularity.** Matching is by `(file, line)` at both
//! ends, mirroring the oracle's own granularity. When several references share a
//! source line, the `cu_*` sub-classification looks at *all* references on that
//! line and picks the most-specific shape present; it cannot attribute the miss
//! to one specific reference. The `near_miss_line` bucket likewise treats any
//! emitted edge within [`TOL`] lines of both endpoints as the "same" edge shifted
//! by alignment — approximate, but it separates alignment drift from real gaps.

use crate::score::local_def_loc;
use code2graph::{CodeGraph, FileFacts, Reference, SymbolKind};
use std::collections::{HashMap, HashSet};

/// Line-proximity tolerance (in lines) for treating an emitted edge as the same
/// edge as a missed one, shifted by an alignment artefact rather than genuinely
/// different. Applied to both the reference and definition endpoints.
const TOL: u32 = 2;

/// A cause breakdown of the oracle edges a resolved graph failed to emit.
///
/// The five top-level buckets partition every false-negative — they sum to
/// [`missed`](Self::missed) — and are assigned in the priority order documented
/// on [`diagnose_recall`]. The `cu_*` fields are a sub-breakdown of
/// [`captured_unresolved`](Self::captured_unresolved) by reference shape and sum
/// to it.
#[derive(Debug, Default, Clone)]
pub struct RecallDiagnosis {
    /// Total false-negatives (equals the sum of the five buckets below).
    pub missed: usize,
    /// Emitted the edge but a line is off by `<= TOL` (alignment bug, not a
    /// resolution failure).
    pub near_miss_line: usize,
    /// No extracted symbol at/near the definition location.
    /// Equals `def_in_function + def_structural`.
    pub def_not_extracted: usize,
    /// `def_not_extracted` where the def location falls inside an extracted
    /// function/method body span — a local/parameter/nested definition that
    /// code2graph's structural graph deliberately does not model. The oracle
    /// counts references to these, so they depress recall without being a bug.
    pub def_in_function: usize,
    /// `def_not_extracted` where the def is NOT inside any function/method — a
    /// top-level or type-member definition code2graph arguably should emit but
    /// did not. This is the genuine extraction-gap signal.
    pub def_structural: usize,
    /// No captured reference at the reference location.
    pub ref_not_captured: usize,
    /// An edge exists from the reference location but to a genuinely different def.
    pub resolved_to_other: usize,
    /// Reference captured + definition extracted, yet no edge from that reference
    /// — a pure resolution gap (the actionable bucket).
    pub captured_unresolved: usize,
    /// `captured_unresolved` where a reference on the line has `self_receiver`.
    pub cu_self_receiver: usize,
    /// `captured_unresolved` where a reference on the line wrote a receiver
    /// var/type (`qualifier.is_some()`).
    pub cu_qualified_receiver: usize,
    /// `captured_unresolved` where a reference on the line carries import data
    /// (`source_module`/`imported_name`/`from_path`/`is_reexport`).
    pub cu_imported: usize,
    /// `captured_unresolved` for a plain unqualified name (none of the above).
    pub cu_bare_name: usize,
}

impl RecallDiagnosis {
    /// Fold another diagnosis's counters into this one (for per-language or
    /// whole-corpus aggregation), mirroring [`Scorecard::merge`].
    ///
    /// [`Scorecard::merge`]: crate::score::Scorecard::merge
    pub fn merge(&mut self, other: &RecallDiagnosis) {
        self.missed += other.missed;
        self.near_miss_line += other.near_miss_line;
        self.def_not_extracted += other.def_not_extracted;
        self.def_in_function += other.def_in_function;
        self.def_structural += other.def_structural;
        self.ref_not_captured += other.ref_not_captured;
        self.resolved_to_other += other.resolved_to_other;
        self.captured_unresolved += other.captured_unresolved;
        self.cu_self_receiver += other.cu_self_receiver;
        self.cu_qualified_receiver += other.cu_qualified_receiver;
        self.cu_imported += other.cu_imported;
        self.cu_bare_name += other.cu_bare_name;
    }
}

/// Bucket every missed oracle edge by cause.
///
/// The emitted-edge set is built exactly as
/// [`score_oracle`](crate::score::score_oracle) builds it: each edge's target is
/// located via `graph.symbols` (by SCIP identity) or, for a synthesized local, via
/// [`local_def_loc`]; unlocatable targets are skipped. `missed = oracle - emitted`.
///
/// Each missed `(ref_file, ref_line, def_file, def_line)` is assigned to the
/// **first** matching bucket in this order:
///
/// 1. `near_miss_line` — an emitted edge is within [`TOL`] lines of both endpoints.
/// 2. `def_not_extracted` — no extracted symbol within [`TOL`] lines of the def.
/// 3. `ref_not_captured` — no captured reference at the ref location.
/// 4. `resolved_to_other` — the ref resolved to some def, just not the oracle's.
/// 5. `captured_unresolved` — fallthrough; sub-classified by reference shape.
pub fn diagnose_recall(
    graph: &CodeGraph,
    files: &[FileFacts],
    oracle: &[(String, u32, String, u32)],
    sources: &HashMap<String, String>,
) -> RecallDiagnosis {
    // Locate every definition by its SCIP identity (same as `score_oracle`).
    let mut def_loc: HashMap<String, (String, u32)> = HashMap::new();
    for sym in &graph.symbols {
        def_loc.insert(sym.id.to_scip_string(), (sym.file.clone(), sym.line));
    }

    // Emitted located edges + a ref-location → resolved-def index. Built from the
    // same locate step `score_oracle` uses, so "emitted" means identical here.
    let mut emitted: HashSet<(String, u32, String, u32)> = HashSet::new();
    let mut emitted_by_ref: HashMap<(String, u32), Vec<(String, u32)>> = HashMap::new();
    for e in &graph.edges {
        let scip = e.to.to_scip_string();
        let Some((def_file, def_line)) = def_loc
            .get(&scip)
            .cloned()
            .or_else(|| local_def_loc(&scip, sources))
        else {
            continue;
        };
        emitted.insert((e.occ.file.clone(), e.occ.line, def_file.clone(), def_line));
        emitted_by_ref
            .entry((e.occ.file.clone(), e.occ.line))
            .or_default()
            .push((def_file, def_line));
    }

    // Every extracted symbol line per file, for near-def detection.
    let mut symbol_lines_by_file: HashMap<String, Vec<u32>> = HashMap::new();
    // Function/method body spans per file, for classifying a not-extracted def as
    // an in-body local (out of structural scope) vs a genuine structural miss.
    let mut fn_spans_by_file: HashMap<String, Vec<(usize, usize)>> = HashMap::new();
    for sym in &graph.symbols {
        symbol_lines_by_file
            .entry(sym.file.clone())
            .or_default()
            .push(sym.line);
        if matches!(sym.kind, SymbolKind::Function | SymbolKind::Method) {
            fn_spans_by_file
                .entry(sym.file.clone())
                .or_default()
                .push((sym.span.start, sym.span.end));
        }
    }

    // Every captured reference location, plus references grouped by location for
    // shape sub-classification.
    let mut ref_locs: HashSet<(String, u32)> = HashSet::new();
    let mut refs_at: HashMap<(String, u32), Vec<&Reference>> = HashMap::new();
    for f in files {
        for r in &f.references {
            ref_locs.insert((r.occ.file.clone(), r.occ.line));
            refs_at
                .entry((r.occ.file.clone(), r.occ.line))
                .or_default()
                .push(r);
        }
    }

    let expected: HashSet<(String, u32, String, u32)> = oracle.iter().cloned().collect();

    let mut d = RecallDiagnosis::default();
    for (rf, rl, df, dl) in &expected {
        if emitted.contains(&(rf.clone(), *rl, df.clone(), *dl)) {
            continue; // true positive — not missed.
        }
        d.missed += 1;

        // 1. near_miss_line: an emitted edge within TOL of both endpoints (same
        //    files). Covers both ref-line and def-line drift.
        let near_miss = emitted.iter().any(|(erf, erl, edf, edl)| {
            erf == rf && edf == df && erl.abs_diff(*rl) <= TOL && edl.abs_diff(*dl) <= TOL
        });
        if near_miss {
            d.near_miss_line += 1;
            continue;
        }

        // 2. def_not_extracted: no extracted symbol within TOL of the def line.
        let def_extracted = symbol_lines_by_file
            .get(df)
            .is_some_and(|lines| lines.iter().any(|l| l.abs_diff(*dl) <= TOL));
        if !def_extracted {
            d.def_not_extracted += 1;
            // Inside an extracted function/method body → a local/param/nested def
            // (out of structural scope); otherwise a genuine structural miss. If the
            // source is unavailable to map the line, count it as structural (surface
            // the uncertainty rather than hide a possible gap).
            let inside_fn = sources
                .get(df)
                .and_then(|src| line_start_byte(src, *dl))
                .zip(fn_spans_by_file.get(df))
                .is_some_and(|(byte, spans)| {
                    spans
                        .iter()
                        .any(|(start, end)| *start <= byte && byte < *end)
                });
            if inside_fn {
                d.def_in_function += 1;
            } else {
                d.def_structural += 1;
            }
            continue;
        }

        // 3. ref_not_captured: no reference captured at the ref location.
        if !ref_locs.contains(&(rf.clone(), *rl)) {
            d.ref_not_captured += 1;
            continue;
        }

        // 4. resolved_to_other: the ref resolved somewhere, just not the oracle's
        //    def (near-misses already excluded above).
        if emitted_by_ref.contains_key(&(rf.clone(), *rl)) {
            d.resolved_to_other += 1;
            continue;
        }

        // 5. captured_unresolved: ref captured + def extracted, no edge from it.
        //    Sub-classify by the most-specific shape among refs on the line.
        d.captured_unresolved += 1;
        let empty: Vec<&Reference> = Vec::new();
        let refs = refs_at.get(&(rf.clone(), *rl)).unwrap_or(&empty);
        if refs.iter().any(|r| r.self_receiver) {
            d.cu_self_receiver += 1;
        } else if refs.iter().any(|r| r.qualifier.is_some()) {
            d.cu_qualified_receiver += 1;
        } else if refs.iter().any(|r| {
            r.source_module.is_some()
                || r.imported_name.is_some()
                || r.from_path.is_some()
                || r.is_reexport
        }) {
            d.cu_imported += 1;
        } else {
            d.cu_bare_name += 1;
        }
    }
    d
}

/// Byte offset of the start of 1-based `line` in `src`, or `None` if the source
/// has fewer than `line` lines.
fn line_start_byte(src: &str, line: u32) -> Option<usize> {
    if line == 0 {
        return None;
    }
    if line == 1 {
        return Some(0);
    }
    let mut newlines = 0u32;
    for (index, byte) in src.bytes().enumerate() {
        if byte == b'\n' {
            newlines += 1;
            if newlines == line - 1 {
                return Some(index + 1);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use code2graph::{
        ByteSpan, Confidence, Descriptor, Edge, Occurrence, Provenance, RefRole, Symbol, SymbolId,
        SymbolKind, Visibility,
    };

    fn sym_id(name: &str) -> SymbolId {
        SymbolId::global(
            "rust",
            vec![
                Descriptor::Namespace("util".into()),
                Descriptor::Term(name.into()),
            ],
        )
    }

    fn def_symbol(id: SymbolId, file: &str, line: u32) -> Symbol {
        Symbol {
            id,
            name: "helper".into(),
            kind: SymbolKind::Function,
            visibility: Visibility::Public,
            entry_points: vec![],
            file: file.into(),
            line,
            span: ByteSpan { start: 0, end: 0 },
            signature: String::new(),
        }
    }

    fn bare_ref(file: &str, line: u32) -> Reference {
        Reference {
            name: "helper".into(),
            occ: Occurrence {
                file: file.into(),
                line,
                col: 0,
                byte: 0,
            },
            role: RefRole::Call,
            source_module: None,
            from_path: None,
            imported_name: None,
            is_reexport: false,
            qualifier: None,
            scope: None,
            type_ref_ctx: None,
            cross_artifact: false,
            self_receiver: false,
        }
    }

    fn facts_with(refs: Vec<Reference>) -> FileFacts {
        FileFacts {
            file: "main.rs".into(),
            lang: "rust".into(),
            symbols: vec![],
            references: refs,
            scopes: vec![],
            bindings: vec![],
            ffi_exports: vec![],
        }
    }

    /// A bare-name reference that was captured, with its definition extracted, but
    /// no edge connecting them → the actionable `captured_unresolved`/`cu_bare_name`.
    #[test]
    fn captured_but_unresolved_bare_name() {
        let graph = CodeGraph {
            symbols: vec![def_symbol(sym_id("helper"), "util.rs", 1)],
            edges: vec![], // nothing resolved
        };
        let files = vec![facts_with(vec![bare_ref("main.rs", 3)])];
        let oracle = vec![("main.rs".to_string(), 3, "util.rs".to_string(), 1)];
        let d = diagnose_recall(&graph, &files, &oracle, &HashMap::new());

        assert_eq!(d.missed, 1);
        assert_eq!(d.captured_unresolved, 1);
        assert_eq!(d.cu_bare_name, 1);
        assert_eq!(d.near_miss_line, 0);
        assert_eq!(d.def_not_extracted, 0);
        assert_eq!(d.ref_not_captured, 0);
        assert_eq!(d.resolved_to_other, 0);
    }

    /// The edge resolved, but its def line is off by 1 (within TOL) → `near_miss_line`,
    /// never a resolution bucket.
    #[test]
    fn def_line_off_by_one_is_near_miss() {
        let id = sym_id("helper");
        let graph = CodeGraph {
            symbols: vec![def_symbol(id.clone(), "util.rs", 1)],
            edges: vec![Edge {
                from: sym_id("caller"),
                to: id,
                role: RefRole::Call,
                confidence: Confidence::NameOnly,
                provenance: Provenance::SymbolTable,
                occ: Occurrence {
                    file: "main.rs".into(),
                    line: 3,
                    col: 0,
                    byte: 0,
                },
            }],
        };
        let files = vec![facts_with(vec![bare_ref("main.rs", 3)])];
        // Oracle says the def is at line 2; the graph emitted line 1.
        let oracle = vec![("main.rs".to_string(), 3, "util.rs".to_string(), 2)];
        let d = diagnose_recall(&graph, &files, &oracle, &HashMap::new());

        assert_eq!(d.missed, 1);
        assert_eq!(d.near_miss_line, 1);
        assert_eq!(d.captured_unresolved, 0);
        assert_eq!(d.resolved_to_other, 0);
    }

    /// A not-extracted def whose location falls inside an extracted function body
    /// is a local (out of structural scope), classified `def_in_function`, not the
    /// genuine-gap `def_structural`.
    #[test]
    fn not_extracted_def_inside_a_function_body_is_a_local() {
        let src = "fn outer() {\n  a();\n  b();\n  let helper = 1;\n  c();\n}\n";
        let mut sources = HashMap::new();
        sources.insert("util.rs".to_string(), src.to_string());
        let mut outer = def_symbol(sym_id("outer"), "util.rs", 1);
        outer.span = ByteSpan {
            start: 0,
            end: src.len(),
        };
        let graph = CodeGraph {
            symbols: vec![outer],
            edges: vec![],
        };
        let files = vec![facts_with(vec![])];
        // Oracle def is the `let helper` local on line 4 — no symbol extracted there.
        let oracle = vec![("main.rs".to_string(), 3, "util.rs".to_string(), 4)];
        let d = diagnose_recall(&graph, &files, &oracle, &sources);

        assert_eq!(d.missed, 1);
        assert_eq!(d.def_not_extracted, 1);
        assert_eq!(d.def_in_function, 1);
        assert_eq!(d.def_structural, 0);
    }
}
