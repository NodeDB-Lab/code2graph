<div align="center">

# code2graph

<h3>Source files → structural facts.</h3>

<p>
A purpose-neutral, language-agnostic code-graph extraction library. It turns source code into
</br><strong>symbols</strong>, <strong>references</strong>, and <strong>cross-file edges</strong> (calls, imports, …) 
</br>as plain data — and stops there. 
</p>

<p>
  <a href="#install"><strong>Install</strong></a>
·
  <a href="#quickstart"><strong>Quickstart</strong></a>
·
  <a href="#languages"><strong>Languages</strong></a>
·
  <a href="#resolution-tiers"><strong>Resolution tiers</strong></a>
·
  <a href="CONTRIBUTING.md"><strong>Contributing</strong></a>
</p>

<p align="center">
  <a href="https://discord.gg/s54gDMVc7B">
    <img src="assets/discord-cta.svg" alt="Join the code2graph Discord" width="340">
  </a>
</p>
 
<p>
  <a href="https://crates.io/crates/code2graph"><img src="https://img.shields.io/crates/v/code2graph?logo=rust" alt="crates.io"></a>
  <a href="https://pypi.org/project/code2graph-rs/"><img src="https://img.shields.io/pypi/v/code2graph-rs?logo=pypi&logoColor=white&label=pypi" alt="PyPI"></a>
  <a href="https://www.npmjs.com/package/@nodedb-lab/code2graph"><img src="https://img.shields.io/npm/v/@nodedb-lab/code2graph?logo=npm" alt="npm"></a>
  <a href="https://docs.rs/code2graph"><img src="https://img.shields.io/docsrs/code2graph?logo=docsdotrs&logoColor=white" alt="docs.rs"></a>
  <a href="https://github.com/nodedb-lab/code2graph/actions/workflows/ci.yml"><img src="https://github.com/nodedb-lab/code2graph/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
</p>

<p>
  <img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="License: Apache-2.0">
  <img src="https://img.shields.io/badge/rustc-1.85%2B-orange" alt="MSRV 1.85">
  <img src="https://img.shields.io/badge/edition-2024-purple" alt="Edition 2024">
  <img src="https://img.shields.io/badge/status-pre--0.1-yellow" alt="Status: pre-0.1">
</p>

</div>

---

code2graph has **no storage opinion** and **no product opinion**. It does not embed, score, rank, persist, or judge. It's a focused primitive — like a tokenizer or a parser generator — that many different tools build on. Consumers decide what the facts mean:

- a memory/RAG tool maps symbols to embedded entries for retrieval;
- a codebase-quality analyzer applies precision-first policy to find drift and risk;
- a security scanner walks the edges for taint paths.

## Why a separate library

Turning code into a graph means, per language: a tree-sitter walk, node-kind normalization, qualified-name and namespace conventions, signature extraction, and cross-file reference resolution. Most tools that need a code graph re-implement this from scratch.

code2graph does it once, behind a neutral output and a stable identity scheme, so a consumer builds its own layer (retrieval, analysis, navigation) without redoing parsing. The wider ecosystem can share one substrate instead of many bespoke ones.

## When to use code2graph

**Use it when you're building a tool that needs to understand code structure — and you want to own the storage and policy decisions yourself.**

code2graph is a **low-level primitive**, not a finished product. If your tool needs symbols, a reference graph, and cross-file edges, you have two choices: re-implement per-language tree-sitter walks, SCIP-aligned identity, and cross-file resolution from scratch (and maintain all of it as grammars drift), or depend on code2graph and get neutral facts out of the box.

It exists so other tools don't each rebuild the same conversion layer.

**Storage- and database-agnostic by design.** code2graph hands you plain data — `{ symbols, references, edges }` — and stops. It never persists anything and has no opinion on _where_ the graph lives. Put it in a graph database, a vector store, SQLite, an in-memory index, or flat files — your call.

Most code-intelligence tools ship a baked-in storage engine and a fixed query model bolted to the parser; code2graph deliberately keeps them separate, so you're never fighting someone else's persistence or query opinion.

Reach for it when:

- you're building developer tooling: code search, RAG over code, refactoring, dependency or impact analysis, security scanning — and don't want to own the parsing layer;
- you need a code graph but want to **choose your own storage, index, and query engine**;
- you want honest, deterministic facts with an explicit `Confidence` on every edge. Not a black box that scores, ranks, or persists for you.

It's **not** for you if you want a turnkey, batteries-included code-intelligence product. Code2graph is the substrate _beneath_ that, not the product itself.

## Install

code2graph ships to three ecosystems from a single source — the Rust crate plus native bindings that emit the same neutral facts as language-native objects:

| Ecosystem  | Package                                                                          | Install                              |
| ---------- | -------------------------------------------------------------------------------- | ------------------------------------ |
| Rust       | [`code2graph`](https://crates.io/crates/code2graph)                              | `cargo add code2graph`               |
| Python     | [`code2graph-rs`](https://pypi.org/project/code2graph-rs/)                       | `pip install code2graph-rs`          |
| Node / Bun | [`@nodedb-lab/code2graph`](https://www.npmjs.com/package/@nodedb-lab/code2graph) | `npm install @nodedb-lab/code2graph` |

API reference: [docs.rs/code2graph](https://docs.rs/code2graph). Binding sources: [`bindings/python`](bindings/python) (PyO3 / maturin) and [`bindings/node`](bindings/node) (napi-rs).

## Quickstart

The pipeline is two pure, deterministic stages:

```text
source ──[extract]──▶ FileFacts (symbols + references) ──[resolve]──▶ CodeGraph (symbols + edges)
```

```rust
use code2graph::{extract_path, resolve::{Resolver, SymbolTableResolver}};

let a = extract_path("src/util.rs", "pub fn helper() {}")?;
let b = extract_path("src/main.rs", "pub fn run() { helper() }")?;

let graph = SymbolTableResolver.resolve(&[a, b])?; // run --calls--> helper
```

Language is inferred from the file extension — there's nothing to configure. Symbols carry a **byte span**, not source text; the consumer slices what it needs.

### Symbol identity wire format

`SymbolId::to_scip_string()` remains a standard, SCIP-parseable display/interoperability string. SCIP has no language or local-file coordinate, so serde-backed API payloads use the versioned lossless object form `{ "version": 1, "scip": "…", "lang": "…" }` for global IDs and `{ "version": 1, "scip": "local …", "file": "…" }` for local IDs. These coordinates are part of code2graph identity and must be retained when persisting or forwarding facts. Readers continue to accept the legacy SCIP-string form; it lacks those coordinates and therefore cannot preserve full identity.

## Scope

**In scope:**

- Multi-language symbol **definitions** (functions, types, traits/classes, consts, modules, …).
- **References** (call sites / usages) with `file:line:col`.
- **Cross-file edges** built by resolving references to definitions (`calls`, `imports`, `inherits`; richer reference kinds and data-flow later).
- A neutral `CodeGraph` value: `{ symbols, references, edges }`.

**Out of scope** (belongs in the consumer):

- Storage, indexing, embeddings, ranking, scoring.
- Recall-first heuristics, retrieval signals, ACLs.
- Document/Markdown ingestion. code2graph is **code**.

## Languages

Coverage spans systems, JVM, scripting, web (incl. embedded single-file components like Svelte, whose `<script>` blocks are extracted as real TS/JS), and declarative DSLs (SQL, HCL/Terraform) — at varying depth.

> **Full coverage, honestly:** [`docs/supported-languages.md`](docs/supported-languages.md) — the per-language matrix (extraction depth, what each emits, and the candidate / not-feasible / out-of-scope lists). Cross-language FFI boundaries: [`docs/ffi-support-matrix.md`](docs/ffi-support-matrix.md).
>
> The **canonical, always-current set** is the `Language` enum + extension dispatch in [`src/lang.rs`](src/lang.rs) — read that, never a list cached in prose. Each language is a Cargo feature (all on by default). Builds can select a smaller set with, for example, `default-features = false, features = ["rust"]`; check `Language::availability()` before extraction, because a disabled language returns `UnsupportedLanguage`. JavaScript shares the `typescript` feature, and `svelte` enables it transitively. Adding one follows a mechanical recipe — see [CONTRIBUTING.md](CONTRIBUTING.md#adding-a-language).

## Resolution tiers

Resolution is **pluggable behind the `Resolver` trait** — the tier seam. Every resolver emits the same `CodeGraph` schema, tagging each edge with a `Confidence` (how sure) and a `Provenance` (which analysis derived it). Consumers pick a tier without changing how they read the output.

| Tier  | Resolver              | Confidence         | Behaviour                                                                                                                                                                                                                                                          |
| ----- | --------------------- | ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **A** | `SymbolTableResolver` | `NameOnly`         | Fast, all languages, **recall-first**. An ambiguous name links to _all_ same-named definitions.                                                                                                                                                                    |
| **B** | `ScopeGraphResolver`  | `Scoped` / `Exact` | Scope-aware: resolves through lexical scopes, imports, and qualified paths. **Never fakes precision** — it emits an edge only when it can resolve one, so it has zero false positives.                                                                             |
| —     | `FfiBridgeResolver`   | —                  | Links cross-language boundaries (e.g. a `#[no_mangle]` Rust fn called from C, a PyO3 `#[pyfunction]` from Python, a `#[wasm_bindgen]`/`#[napi]` fn from JS/TS, a Java `native` method) by ABI name — even when the exported name differs from the definition name. |

Both tiers emit the same shape, so a consumer reads the output identically and chooses the tier by the confidence it needs. The scope-aware tier is implemented for a growing subset of languages; others fall back to the recall-first baseline. Identity rendering and the graph schema may still evolve before `0.1`.

## Measuring resolution quality

Resolution quality is **measured, not asserted**. The `code2graph-eval` crate scores ref→def **precision and recall per language and per resolver tier** against a corpus (`eval/corpus/`). The evaluation unit is a _located edge_ — a reference site bound to a definition site — so name-only fan-out is penalised exactly where it over-connects: a reference that links to _N_ same-named definitions scores one true positive and _N − 1_ false positives.

```bash
cargo run  -p code2graph-eval    # print the scorecard
cargo test -p code2graph-eval    # regression gate on the invariants
```

Ground truth comes from hand-authored golden fixtures **and** from external **SCIP oracles** — indexes produced by mature, type-aware indexers (rust-analyzer, scip-typescript, scip-java, …) — so the numbers quantify each tier's lane against an independent source of truth. The normal build and test loop pulls no SCIP/indexer dependencies; see `eval/ORACLE.md` for the maintainer-only regeneration workflow.

## Status

🚧 **Early, pre-`0.1`.** Extraction and the resolver tiers work end-to-end across the language set above. SCIP-aligned identity (`SymbolId` renders to a stable SCIP string, so cross-file matching is string equality) and the neutral fact schema are in place; both may still evolve before `0.1`.

## Used by

code2graph is designed as a neutral substrate for tools that apply their own policy and storage, including memory and retrieval systems, code-analysis tools, and security scanners.

Building something on code2graph? Open a [Discussion](https://github.com/nodedb-lab/code2graph/discussions) — and if it's useful to you, a ⭐ on the repo genuinely helps others find it.

## Contributing

Contributions are welcome — especially **new languages** and **resolution-quality improvements**. Start with [CONTRIBUTING.md](CONTRIBUTING.md): it covers the architecture and invariants, the language-adding recipe, what to do when a language has **no usable tree-sitter grammar**, the resolver tiers, and how to validate changes against the eval harness. By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
