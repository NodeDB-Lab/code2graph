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

**Storage- and database-agnostic by design.** Extraction returns `FileFacts` containing symbols and raw references; resolution returns a `CodeGraph` containing symbols and edges. code2graph never persists either and has no opinion on _where_ a consumer keeps them. Put consumer-owned data in a graph database, a vector store, SQLite, an in-memory index, or flat files — your call.

Most code-intelligence tools ship a baked-in storage engine and a fixed query model bolted to the parser; code2graph deliberately keeps them separate, so you're never fighting someone else's persistence or query opinion.

Reach for it when:

- you're building developer tooling: code search, RAG over code, refactoring, dependency or impact analysis, security scanning — and don't want to own the parsing layer;
- you need a code graph but want to **choose your own storage, index, and query engine**;
- you want honest, deterministic facts with an explicit `Confidence` on every edge. Not a black box that scores, ranks, or persists for you.

It's **not** for you if you want a turnkey, batteries-included code-intelligence product. Code2graph is the substrate _beneath_ that, not the product itself.

## Install

Choose the surface that owns the work you need:

| Surface | Package | Install |
| --- | --- | --- |
| Conversion primitive | [`code2graph`](https://crates.io/crates/code2graph) | `cargo add code2graph` |
| Optional in-memory query index | [`code2graph-query`](https://crates.io/crates/code2graph-query) | `cargo add code2graph-query` |
| Project-query CLI (`code2graph` binary) | [`code2graph-cli`](https://crates.io/crates/code2graph-cli) | `cargo install code2graph-cli` |
| Python binding | [`code2graph-rs`](https://pypi.org/project/code2graph-rs/) | `pip install code2graph-rs` |
| Node / Bun binding | [`@nodedb-lab/code2graph`](https://www.npmjs.com/package/@nodedb-lab/code2graph) | `npm install @nodedb-lab/code2graph` |

`code2graph-query` is optional and storage-free: it builds an owned in-memory index over a resolved graph, leaving persistence to its caller. A `CodeGraph` contains the extracted symbol definitions plus resolved edges; each edge records its source and target IDs, relationship role, confidence, provenance, and reference occurrence.

```rust
use code2graph::resolve::{Resolver, SymbolTableResolver};
use code2graph_query::GraphIndex;

let graph = SymbolTableResolver.resolve(&[a, b])?;
let index = GraphIndex::from_graph(graph)?; // owned by this process
let helpers = index.symbols_named("helper");
```

The CLI is a consumer application, not part of the core or query crates. It builds a local, consumer-owned cache for project commands; use `--no-cache` when a cache should not be read or written.

```sh
code2graph index .
code2graph symbols helper
code2graph callers helper
code2graph impact helper --depth 3
```

`cargo install code2graph-cli` builds the binary from source with Cargo. No prebuilt binary distribution is promised here.

### Managing the cache

The CLI keeps a per-project SQLite cache under the OS cache directory (on Linux, `$XDG_CACHE_HOME/code2graph` or `~/.cache/code2graph`; the equivalent on macOS/Windows), keyed by an opaque hash of the project's canonical root. The cache is incremental and self-bounding: re-indexing reuses unchanged work, and superseded snapshots are garbage-collected on publish so the database does not grow without limit. The `cache` subcommand inspects and manages it — all commands accept `--json`.

```sh
code2graph --root . cache path       # print this project's cache directory and database path
code2graph --root . cache status     # + on-disk size and a per-snapshot tier/edge/symbol breakdown
code2graph --root . cache clear      # delete this project's cache; reports bytes freed
code2graph cache clear --all         # delete every project's cache (no --root needed)
```

`cache clear` only ever removes directories under `<cache>/projects/`; it never touches your source tree. Deleting a project's cache simply forces a fresh index on the next command.

The Python and Node/Bun packages expose the conversion and query handles as native language objects; see [`bindings/python`](bindings/python) and [`bindings/node`](bindings/node) for their APIs. A public Pi host integration is available as [`@nodedb-lab/pi-code2graph`](bindings/pi); it composes the native binding for agent-host tools without changing the core library's storage-neutral contract. Other host integrations are described only as integrations, not as part of the core API.

API reference: [docs.rs/code2graph](https://docs.rs/code2graph).

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
- A neutral `FileFacts` value with symbols and raw references, and a resolved `CodeGraph` with symbols and edges.

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
| **B** | `ScopeGraphResolver`  | `Scoped` / `Exact` | Scope-aware: resolves through lexical scopes, imports, and qualified paths. It emits only syntactically supported resolutions and marks the resulting confidence; it is not type-checking.                                                                             |
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

## Release operation

Pushing an immutable `vX.Y.Z` (or `vX.Y.Z-alpha.N`, `-beta.N`, `-rc.N`) tag runs **Release Prepare**. It validates and tests the tag, builds each native package once, and retains the checksummed bundle for 14 days. It publishes nothing.

Distribute that exact bundle manually after Prepare succeeds. The manual workflow checks the successful Prepare run's tag, source SHA, workflow identity, manifest, checksums, and complete file set before any registry or GitHub publication:

```sh
gh workflow run release.yml -f tag=vX.Y.Z -f prepare_run_id=PREPARE_RUN_ID
```

The optional `distribution_ref` is only for a distribution-workflow/helper fix; the source and prepared artifacts remain bound to the tag. To retry a failed registry or GitHub stage, dispatch the same command and disable every completed toggle (`crates`, `pypi`, `npm`, `github`). Do not rerun Prepare for a distribution failure. If the bundle expires, rerun Prepare for the same immutable tag and use its new run ID. A package already present with different content fails closed.

## License

Apache-2.0. See [LICENSE](LICENSE).
