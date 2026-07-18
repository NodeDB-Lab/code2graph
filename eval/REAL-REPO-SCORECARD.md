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

- **Subjects** (real, widely-used projects, pinned):
  - [`dtolnay/anyhow`](https://github.com/dtolnay/anyhow) `1.0.104` — Rust crate,
    ~3,900 LOC / 13 `src/` files. Oracle: `rust-analyzer scip`.
  - [`sindresorhus/ky`](https://github.com/sindresorhus/ky) — TypeScript HTTP
    client, ~4,000 LOC / 30 `source/` files. Oracle: `scip-typescript`.
  - [`pallets/click`](https://github.com/pallets/click) — Python CLI framework,
    ~12,500 LOC / 17 `src/click/` files. Oracle: `scip-python`.
- **Oracle:** a type-aware, compiler-grade SCIP indexer → an `index.scip`,
  converted to location-only `ref:line → def:line` pairs by the eval crate's
  `gen-oracle`.
- **Scope:** intra-source edges only (both endpoints under the project's source
  root). This measures resolution of the project's **own** symbols; references
  into `std`/deps are external (code2graph does not claim to resolve them, and
  `score_oracle` ignores `External` edges).
- **Matching:** a true positive requires code2graph's `(ref_file, ref_line,
  def_file, def_line)` to equal the oracle's exactly (1-based, role-agnostic).
- **Reproduce:** `eval/scripts/gen-realrepo-oracle.sh` (needs `rust-analyzer`,
  `npm`/`npx`, network; writes gitignored `eval/corpus/*_realrepo/` cases), then
  `cargo run -p code2graph-eval` and read the `rust_realrepo` / `ts_realrepo` rows.

## Results

| Project (oracle edges) | Resolver | Precision | Recall | F1 |
|---|---|---|---|---|
| **anyhow** — Rust (784) | Tier-A (name) | 0.46 | 0.44 | 0.45 |
| | Tier-B (scope) | 0.52 | 0.36 | 0.43 |
| **ky** — TypeScript (1995) | Tier-A (name) | 0.92 | 0.22 | 0.36 |
| | Tier-B (scope) | 0.79 | 0.44 | 0.56 |
| **click** — Python (6819) | Tier-A (name) | 0.33 | 0.19 | 0.24 |
| | Tier-B (scope) | 0.73 | 0.53 | 0.61 |

Layered (dense), recall by minimum-confidence cutoff:

| Project | R@Heuristic | R@Name | R@Scoped | R@Exact | P@Exact |
|---|---|---|---|---|---|
| anyhow (Rust) | 0.45 | 0.45 | 0.41 | 0.09 | 0.27 |
| ky (TypeScript) | 0.46 | 0.46 | 0.46 | 0.38 | 0.76 |
| click (Python) | 0.55 | 0.55 | 0.54 | 0.43 | 0.71 |

For contrast, the toy `*_oracle` fixtures score Tier-B **P=1.00** — the gap
between that and the `0.52` / `0.79` / `0.73` here is exactly the illusion this
scorecard exists to dispel. Two real signals emerge across the three:

- **Tier-B (scope) is consistently the more precise tier, and matters most where
  name fan-out is worst.** On Python, Tier-A precision collapses to `0.33` (many
  same-named methods), while Tier-B holds `0.73` — the single clearest
  demonstration that scope resolution earns its keep on real code.
- **The build-free ceiling is language-shaped.** `P@Exact` runs `0.27` (Rust) →
  `0.71` (Python) → `0.76` (TypeScript): a macro/generic/trait-heavy Rust crate
  resolves to a unique `Exact` target far less often than straighter-line Python
  or TypeScript. Same resolver, honestly different ceilings.

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
  written line; name-only fan-out counting `N−1` extra edges). Scope resolution
  helps where it can (ky Tier-B P 0.79), but the picture is language-dependent:
  anyhow's low `P@Exact` (0.27) shows how little of a macro/generic/trait-heavy
  Rust crate resolves to a single `Exact` target syntactically, whereas ky's
  0.76 shows a straighter-line TypeScript codebase largely does. The build-free
  ceiling is real and it is not the same height in every language.

## Extending

Add more real repos (per language) by extending `gen-realrepo-oracle.sh` with a
pinned `git` ref and its indexer (`scip-typescript` for TS/JS, `scip-python` for
Python, `rust-analyzer scip` for Rust). Each new `*_realrepo/<case>/` scores
automatically. Vendoring the repos is intentionally avoided — the script fetches
them, and only this scorecard's numbers are committed.
