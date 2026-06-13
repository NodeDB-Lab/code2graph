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
an ambiguous name links to all same-named definitions. A precise, scope-aware resolver (emitting
`Scoped`/`Exact` edges) is in progress behind the stable `Resolver` trait — a consumer picks the
tier and the output schema does not change. Identity rendering and the graph schema may still
evolve before `0.1`.

## License

Apache-2.0
