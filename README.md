# codegraph

**Source files → structural facts.** A purpose-neutral, language-agnostic code-graph
extraction library: it turns source code into **symbols**, **references**, and **cross-file
edges** (calls, imports, …) as plain data — and stops there.

codegraph has **no storage opinion** and **no product opinion**. It does not embed, score,
rank, persist, or judge. Consumers decide what the facts mean:

- a memory/RAG tool maps symbols to embedded entries for retrieval;
- a codebase-quality analyzer applies precision-first policy to find drift and risk;
- a security scanner walks the edges for taint paths.

## Why a separate library

Turning code into a graph means, per language: a tree-sitter walk, node-kind normalization,
qualified-name and namespace conventions, signature extraction, and cross-file reference
resolution — then maintaining all of it as grammars change. Most tools that need a code graph
re-implement this from scratch. codegraph does it once, behind a neutral output and a stable
identity scheme, so a consumer builds its own layer (retrieval, analysis, navigation) without
redoing parsing — and the wider ecosystem can share one substrate instead of many bespoke ones.

## Scope

In scope:

- Multi-language symbol **definitions** (functions, types, traits/classes, consts, modules, …).
- **References** (call sites / usages) with file:line:col.
- **Cross-file edges** built by resolving references to definitions (`calls`, `imports`,
  `inherits`; richer reference kinds and data-flow later).
- A neutral `CodeGraph` value: `{ symbols, references, edges }`. Symbols carry a **byte span**,
  not source text — the consumer slices what it needs.

Out of scope (belongs in the consumer):

- Storage, indexing, embeddings, ranking, scoring.
- Recall-first heuristics, retrieval signals, ACLs.
- Document/Markdown ingestion. codegraph is **code**.

## Status

🚧 **Early, pre-`0.1`.** Extractors for 14 languages work end-to-end, plus a baseline name/scope
resolver: `extract` source into per-file facts, then `resolve` them into a `CodeGraph` of symbols
and confidence-tagged edges (`calls`, `imports`, `inherits`). Symbol identity is SCIP-aligned — a
descriptor path rendering to a stable string, so cross-file matching is string equality.

The baseline resolver is **recall-first**: it matches by name and tags every edge `NameOnly`, so
an ambiguous name links to all same-named definitions. A precise, scope-aware resolver
(`ScopeGraphResolver`) now sits behind the same `Resolver` trait, emitting `Scoped`/`Exact` edges
by resolving references through lexical scopes, imports, and qualified paths instead of name
fan-out. Scope analysis is currently implemented for Rust, Python, and TypeScript/JavaScript; other
languages fall back to the recall-first baseline. Both resolvers emit the same schema, so a consumer picks the tier without
changing how it reads the output. Identity rendering and the graph schema may still evolve before
`0.1`.

Every edge also carries a `Provenance` tag — which analysis derived it (name table, scope graph,
or FFI bridge) — orthogonal to its `Confidence`. On top of the tiers, an `FfiBridgeResolver` links
cross-language boundaries deterministically: a Rust `#[no_mangle]`/`#[export_name]` function called
from C, or a PyO3 `#[pyfunction]` called from Python, resolves to one edge — matched ABI-to-consumer
and even when the exported name differs from the definition name, a boundary plain name resolution
cannot recover.

## Measuring resolution quality

Resolution quality is measured, not asserted. The `codegraph-eval` crate scores ref→def
**precision and recall per language and per resolver tier** against a corpus of golden fixtures
(`eval/corpus/`), where each case pairs source files with the ground-truth edges they should
resolve to. The evaluation unit is a located edge — a reference site bound to a definition site —
so name-only fan-out is penalised exactly where it over-connects: a reference that links to *N*
same-named definitions scores one true positive and *N − 1* false positives.

```text
cargo run -p codegraph-eval     # prints the scorecard
cargo test -p codegraph-eval    # regression gate on the invariants
```

The scorer is independent of where the ground truth comes from, so a SCIP precision oracle
(rust-analyzer / scip-java) can be plugged in alongside the hand-authored fixtures. The numbers
quantify each resolver's lane directly: the recall-first name tier finds everything but
over-connects on ambiguity, the scope-aware tier resolves a narrower set with no false positives,
and the FFI bridge recovers cross-language boundary edges the other two cannot.

## License

Apache-2.0
