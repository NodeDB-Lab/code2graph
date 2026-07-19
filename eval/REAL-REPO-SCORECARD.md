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
  `cargo run -p code2graph-eval` and read the `rust_realrepo` / `ts_realrepo` /
  `py_realrepo` rows — the **`Scoped+ (default)`** column is the CLI's default tier.

## Results

Three resolver views per project: `Tier-A (name)` (`SymbolTableResolver` alone,
recall-first), `Tier-B (scope)` (`ScopeGraphResolver` alone), and
**`Scoped+ (default)`** — the CLI's actual default, `LayeredResolver::default_scoped()`
= scope-path resolution plus the additive receiver-typed passes (conformance +
local-typed member resolution). `Scoped+` is the honest default-experience number.

| Project (oracle edges) | Resolver | Precision | Recall | F1 |
|---|---|---|---|---|
| **anyhow** — Rust (784) | Tier-A (name) | 0.42 | 0.62 | 0.51 |
| | Tier-B (scope) | 0.51 | 0.40 | 0.45 |
| | **Scoped+ (default)** | **0.53** | **0.42** | **0.47** |
| **ky** — TypeScript (1995) | Tier-A (name) | 0.29 | 0.28 | 0.29 |
| | Tier-B (scope) | 0.75 | 0.45 | 0.56 |
| | **Scoped+ (default)** | **0.75** | **0.45** | **0.57** |
| **click** — Python (6819) | Tier-A (name) | 0.35 | 0.20 | 0.26 |
| | Tier-B (scope) | 0.74 | 0.53 | 0.61 |
| | **Scoped+ (default)** | **0.74** | **0.53** | **0.62** |

Layered (dense), recall by minimum-confidence cutoff:

| Project | R@Heuristic | R@Name | R@Scoped | R@Exact | P@Exact |
|---|---|---|---|---|---|
| anyhow (Rust) | 0.63 | 0.63 | 0.46 | 0.09 | 0.27 |
| ky (TypeScript) | 0.52 | 0.52 | 0.50 | 0.38 | 0.76 |
| click (Python) | 0.55 | 0.55 | 0.54 | 0.42 | 0.70 |

For contrast, the toy `*_oracle` fixtures score Tier-B **P=1.00** — the gap
between that and the `0.51` / `0.75` / `0.74` here is exactly the illusion this
scorecard exists to dispel. Three real signals emerge across the three:

- **The composed default (`Scoped+`) beats scope-alone.** Adding the receiver-typed
  passes lifts anyhow from Tier-B `P 0.51 / R 0.40` to `P 0.53 / R 0.42`, and nudges
  ky and click up a point of F1 each — precise `Scoped` member edges that
  `ScopeGraphResolver` alone does not emit. Measuring only `Tier-B` understates the
  tier the CLI actually ships.
- **Name fan-out is a real precision cost, and it is confidence-tagged.** `Tier-A`
  precision runs `0.29` (ky) → `0.35` (click) → `0.42` (anyhow): common member names
  (`headers`, `json`, a same-named method) link to *every* same-named definition. This
  is `NameOnly` by contract — the scope tiers hold precision far higher (ky `Tier-B`
  `P 0.75`) exactly where name fan-out is worst. A consumer filters by `Confidence`
  to trade recall for precision.
- **The build-free ceiling is language-shaped.** `P@Exact` runs `0.27` (Rust) →
  `0.70` (Python) → `0.76` (TypeScript): a macro/generic/trait-heavy Rust crate
  resolves to a unique `Exact` target far less often than straighter-line Python
  or TypeScript. Same resolver, honestly different ceilings.

## Honest reading

- **This is a floor, not a ceiling, and it is measured — not claimed.** ~0.5
  precision / ~0.4 recall on a real crate is the number to improve against; the
  point of the exercise is that it is now a *number*.
- **Recall is understated, but less than before.** The oracle is role-agnostic
  SCIP truth — every variable read/write, type-position use, and macro-expanded
  site rust-analyzer records is ground truth. code2graph now models member-level
  definitions (struct fields, enum variants, interface/type properties,
  module-level constants) and captures member-access reads, so field/property
  access is no longer entirely unclaimed — this is the bulk of the recall lift on
  anyhow (`Tier-A R 0.44 → 0.62`). What remains deliberately unmodelled: local
  variables, parameters, and pure type-position uses. Read recall as "fraction of
  type-aware truth recovered syntactically."
- **Precision is the actionable signal.** Line-exact, role-agnostic matching
  penalizes real divergences (a call attributed to a macro-expansion line vs the
  written line; name-only fan-out counting `N−1` extra edges). Scope resolution
  helps where it can (ky `Tier-B`/`Scoped+` P 0.75), but the picture is
  language-dependent: anyhow's low `P@Exact` (0.27) shows how little of a
  macro/generic/trait-heavy Rust crate resolves to a single `Exact` target
  syntactically, whereas ky's 0.76 shows a straighter-line TypeScript codebase
  largely does. The build-free ceiling is real and it is not the same height in
  every language.

## Extending

Add more real repos (per language) by extending `gen-realrepo-oracle.sh` with a
pinned `git` ref and its indexer (`scip-typescript` for TS/JS, `scip-python` for
Python, `rust-analyzer scip` for Rust). Each new `*_realrepo/<case>/` scores
automatically. Vendoring the repos is intentionally avoided — the script fetches
them, and only this scorecard's numbers are committed.
