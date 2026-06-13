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

Cross-file symbol resolution across many languages is a large, slow-moving body of work
(tree-sitter queries per language, qualified-name conventions, call-graph linking). It is the
one substrate genuinely shared between otherwise-unrelated products. Extracting it once — with
a neutral output and tunable precision — lets each consumer optimize its own layer without
re-implementing parsing, and lets the wider ecosystem build on it.

## Scope

In scope:

- Multi-language symbol **definitions** (functions, types, traits/classes, consts, modules, …).
- **References** (call sites / usages) with file:line:col.
- **Cross-file edges** built by resolving references to definitions (`calls`, later `imports`,
  `inherits`, data-flow).
- A neutral `CodeGraph` value: `{ symbols, references, edges }`. Symbols carry a **byte span**,
  not source text — the consumer slices what it needs.

Out of scope (belongs in the consumer):

- Storage, indexing, embeddings, ranking, scoring.
- Recall-first heuristics, retrieval signals, ACLs.
- Document/Markdown ingestion. codegraph is **code**.

## Status

🚧 **Early.** The Rust extractor and the baseline name/scope resolver work end-to-end:
`extract` source into per-file facts, then `resolve` them into a `CodeGraph` of symbols and
confidence-tagged `calls` edges. Symbol identity is SCIP-aligned (a descriptor path rendering
to a stable string, so cross-file matching is string equality). The remaining languages and a
precise stack-graphs resolver are in progress behind stable traits. The graph schema may still
evolve before `0.1`.

## License

Apache-2.0
