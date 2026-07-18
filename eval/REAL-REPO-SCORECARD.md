<!-- SPDX-License-Identifier: Apache-2.0 -->

# Real-repository scorecard

The committed `eval/corpus/*_oracle/` cases are tiny hand-built fixtures (2–6
edges each). They prove *directional* theses — scope beats name on ambiguity,
Tier-B never fakes precision — but their P/R numbers (Tier-B often `1.00`) are
**not** a real-world accuracy measurement.

This scorecard measures code2graph's ref→def resolution against a full
[SCIP](https://github.com/sourcegraph/scip) index of a **real** codebase, scored
by the same `score_oracle` machinery. It is the honest, at-scale answer to "how
good is the conversion?" — deliberately unflattering where the micro-fixtures
flatter.

## Method

- **Subject:** [`dtolnay/anyhow`](https://github.com/dtolnay/anyhow) `1.0.104` —
  a real, widely-used Rust crate (~3,900 LOC across 13 `src/` files).
- **Oracle:** `rust-analyzer scip` (a type-aware, compiler-grade indexer) → an
  `index.scip`, converted to location-only `ref:line → def:line` pairs by the
  eval crate's `gen-oracle`.
- **Scope:** intra-`src/` edges only (both endpoints under `src/`) — **784
  ground-truth ref→def edges**. This measures resolution of the crate's own
  symbols; references into `std`/deps are external (code2graph does not claim to
  resolve them, and `score_oracle` ignores `External` edges).
- **Matching:** a true positive requires code2graph's `(ref_file, ref_line,
  def_file, def_line)` to equal the oracle's exactly (1-based, role-agnostic).
- **Reproduce:** `eval/scripts/gen-realrepo-oracle.sh` (needs `rust-analyzer` +
  network; writes a gitignored `eval/corpus/rust_realrepo/anyhow/` case), then
  `cargo run -p code2graph-eval` and read the `rust_realrepo` row.

## Result (anyhow 1.0.104, 784 oracle edges)

| Resolver | Precision | Recall | F1 |
|---|---|---|---|
| Tier-A (`SymbolTableResolver`, name) | 0.46 | 0.44 | 0.45 |
| Tier-B (`ScopeGraphResolver`, scope) | 0.52 | 0.36 | 0.43 |

Layered (dense), recall by minimum-confidence cutoff:

| R@Heuristic | R@Name | R@Scoped | R@Exact | P@Exact |
|---|---|---|---|---|
| 0.45 | 0.45 | 0.41 | 0.09 | 0.27 |

For contrast, the toy `rust_oracle` fixtures score Tier-B **P=1.00, R=0.90** —
the gap between that and the `0.52 / 0.36` here is exactly the illusion this
scorecard exists to dispel.

## Honest reading

- **This is a floor, not a ceiling, and it is measured — not claimed.** ~0.5
  precision / ~0.4 recall on a real crate is the number to improve against; the
  point of the exercise is that it is now a *number*.
- **Recall is understated by design.** The oracle is role-agnostic SCIP truth —
  every variable read/write, type-position use, macro-expanded site, and field
  access rust-analyzer records is ground truth. code2graph emits a deliberately
  narrower edge set, so a large slice of "misses" are occurrence kinds it never
  claims. Read recall as "fraction of type-aware truth recovered syntactically."
- **Precision is the actionable signal.** Line-exact, role-agnostic matching
  penalizes real divergences (a call attributed to a macro-expansion line vs the
  written line; name-only fan-out counting `N−1` extra edges). Tier-B's 0.52
  vs Tier-A's 0.46 confirms scope resolution helps, and the low `P@Exact` (0.27)
  shows how little of anyhow resolves to a single `Exact` target syntactically —
  a real crate leans heavily on macros, generics, and trait dispatch that a
  build-free resolver cannot pin. That is the honest ceiling of the approach.

## Extending

Add more real repos (per language) by extending `gen-realrepo-oracle.sh` with a
pinned `git` ref and its indexer (`scip-typescript` for TS/JS, `scip-python` for
Python, `rust-analyzer scip` for Rust). Each new `*_realrepo/<case>/` scores
automatically. Vendoring the repos is intentionally avoided — the script fetches
them, and only this scorecard's numbers are committed.
