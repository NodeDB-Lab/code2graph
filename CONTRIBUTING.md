# Contributing to code2graph

Thank you for your interest in contributing. code2graph is a **purpose-neutral, language-agnostic code-graph extraction library**. It turns source files into structural facts (symbols, references, cross-file edges) and stops there. This guide gets you oriented before you open a PR.

The single most common contribution is **adding a language** or **improving resolution quality**. Both are covered in detail below.

---

## Where to Start

- **[GitHub Discussions](https://github.com/nodedb-lab/code2graph/discussions)** — design proposals, architecture questions, "should code2graph support X?"
- **[GitHub Issues](https://github.com/nodedb-lab/code2graph/issues)** — bug reports and well-scoped feature requests

For a new language with a maintained grammar, you can usually just open a PR — the recipe below is mechanical. For anything that changes the **fact schema**, the **identity scheme**, or the **resolver trait**, open a Discussion first.

---

## What code2graph Is (and Isn't)

code2graph is a **focused primitive**, like a tokenizer or a parser generator. Consumers build retrieval, analysis, or navigation on top of its output; code2graph itself takes no position on what the facts mean.

The pipeline is two pure, deterministic stages:

```
source ──[extract]──▶ FileFacts (symbols + references) ──[resolve]──▶ CodeGraph (symbols + edges)
```

```rust
use code2graph::{extract_path, resolve::{Resolver, SymbolTableResolver}};

let a = extract_path("src/util.rs", "pub fn helper() {}")?;
let b = extract_path("src/main.rs", "pub fn run() { helper() }")?;
let graph = SymbolTableResolver.resolve(&[a, b]); // run --calls--> helper
```

### Core invariants — non-negotiable, enforced in review

These are bright lines, not style preferences. A PR that crosses one will be asked to change regardless of size:

- **No storage, no I/O in the library core.** Extractors and resolvers are pure and deterministic. No files, no network, no databases.
- **No source bodies.** A `Symbol` carries a `ByteSpan`, never the source text. The consumer slices what it needs.
- **Purpose-neutral.** No scoring, ranking, embeddings, recall-vs-precision policy, or ACLs baked in. That's the consumer's job.
- **Every edge carries a `Confidence` and a `Provenance`.** Be honest about resolution quality — never fake precision (see [Resolution tiers](#resolution-tiers)).
- **Extractors produce neutral facts; resolvers stay pure** and only connect/derive edges — they never invent facts the extractor didn't emit.
- **Module-root files are wiring only.** `mod.rs` / `lib.rs` contain _only_ module declarations and re-exports (`mod` / `pub mod` / `pub use` / `pub(crate) use`) plus the module doc comment — never trait/type/fn definitions, dispatch `match`es, helpers, or consts. Put logic in a named sibling submodule and re-export it.
- **Grammars are imported in exactly one place.** `src/grammar.rs` is the sole importer of every `tree_sitter_*` crate. Extractors call `crate::grammar::<lang>()`, never a grammar crate directly.

---

## Repository Layout

| Module               | Role                                                                                                                                                                                         |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/lang.rs`        | The `Language` enum + file-extension dispatch. **The canonical source of truth for language coverage.**                                                                                      |
| `src/grammar.rs`     | The grammar chokepoint — the only file that imports `tree_sitter_*` crates, gated per Cargo feature.                                                                                         |
| `src/extract/`       | Per-language extraction. `mod.rs` is wiring; `dispatch.rs` holds the `Extractor` trait + entry points; `support.rs` holds shared helpers; `<lang>.rs` is one tree-sitter walk → defs + refs. |
| `src/resolve/`       | The `Resolver` trait (the tier seam) + the resolvers that implement it. Read `mod.rs` for the current set.                                                                                   |
| `src/symbol/`        | SCIP-aligned identity: `Descriptor` + `SymbolId` rendering to a stable SCIP string. Cross-file match = string equality.                                                                      |
| `src/graph/types.rs` | The neutral fact schema: `Symbol`, `Reference`, `Edge`, `FileFacts`, `CodeGraph`, `SymbolKind`, `EdgeKind`, `Confidence`, `Provenance`, `ByteSpan`.                                          |
| `eval/`              | The measurement harness — scores ref→def precision/recall per language and per tier (see [Validation](#validation-prove-the-number)).                                                        |

---

## Development Setup

**Requirements:** Rust stable (see `rust-toolchain.toml` / `Cargo.toml` `rust-version`; MSRV is **1.85**, edition **2024**). No system dependencies — tree-sitter grammars build from source via `cc`.

```bash
git clone https://github.com/nodedb-lab/code2graph.git
cd code2graph

cargo test                                    # unit + doc tests
cargo test --workspace                        # includes the eval/ integration suite
cargo clippy --all-targets -- -D warnings     # lints — must be clean
cargo fmt --all                               # formatting
```

Every language is a Cargo feature, all enabled by default. To work on one in isolation:

```bash
cargo test --no-default-features --features rust    # just the Rust extractor
cargo test --features scala scala                   # run only the Scala tests
```

Every public-facing file starts with `// SPDX-License-Identifier: Apache-2.0`.

---

## Adding a Language

This is the most common contribution and it's mechanical once a grammar exists. The resolver is language-agnostic, so **cross-file edges work for free** once extraction emits correct facts.

> **First: is there a usable grammar?** code2graph pins `tree-sitter` to `>=0.24, <0.27`. A grammar crate must be compatible with that range. If no compatible grammar exists, read [When a language has no usable grammar](#when-a-language-has-no-usable-grammar) before writing any code.

### The recipe

Using a hypothetical language `Foo` with extension `.foo`:

**1. Add the grammar dependency and feature flag** (`Cargo.toml`):

```toml
[features]
# add to the default list so it's on by default
default = [ …, "foo" ]
foo = ["dep:tree-sitter-foo"]

[dependencies]
tree-sitter-foo = { version = "<x.y.z>", optional = true }
```

**2. Register the grammar** in the chokepoint (`src/grammar.rs`) — and add the ABI sanity-check arm at the bottom of the file:

```rust
#[cfg(feature = "foo")]
/// Returns the tree-sitter grammar for Foo.
pub fn foo() -> Language {
    tree_sitter_foo::LANGUAGE.into()
}
// …and in the abi_versions_are_compatible test:
#[cfg(feature = "foo")]
check("foo", super::foo());
```

**3. Register the language** (`src/lang.rs`): add the `Foo` enum variant, the `Language::Foo => "foo"` arm in `as_str()`, and the extension dispatch `"foo" => Some(Self::Foo)`.

**4. Write the extractor** (`src/extract/foo.rs`): a `struct FooExtractor` implementing the `Extractor` trait. One tree-sitter walk that collects:

- **definitions** → a `Symbol` with a SCIP `SymbolId` (namespace descriptors derived from the file path or the language's package/module convention), a `SymbolKind`, a `ByteSpan`, and a one-line signature;
- **references** (call sites, imports, type uses) → a `Reference` with a byte offset and, where the syntax has a receiver (`obj.method()`), the receiver captured as the reference's `qualifier` so the scope-aware resolver can disambiguate.

Reuse the shared helpers in `src/extract/support.rs` (`node_text`, `field_text`, `one_line_signature`, `collect_call_references`, `push_import_ref`, `push_ref`, `push_type_ref`, the scope/binding helpers, …) — don't reinvent them. The freshest extractor is usually the best template; pick one structurally similar to your language (class-based, module-based, etc.).

**5. Wire it up:**

- `src/extract/mod.rs` (wiring only): `#[cfg(feature = "foo")] pub mod foo;` and `#[cfg(feature = "foo")] pub use foo::FooExtractor;`
- `src/extract/dispatch.rs`: the `use super::FooExtractor;` and the `Language::Foo => FooExtractor.extract(source, file),` match arm.

**6. Add unit tests** in `foo.rs` (`#[cfg(test)] mod tests`): assert that definitions get the expected SCIP id strings and `SymbolKind`s, and that references (including qualifiers on member calls) are captured. Assert the _real_ rendered SCIP string — derive it from an existing extractor's tests.

### Tip: dump the real AST before you write the extractor

Published grammars frequently differ from the `node-types.json` in their GitHub repo. Don't guess node/field names — verify them against the **exact crate version** you depend on. The reliable way: wire up the grammar (steps 1–2), drop a throwaway `examples/` program that prints `tree.root_node().to_sexp()` for a few representative snippets, run it, read the real tree, then delete it. This catches surprises (separate signature/body nodes, field labels that point at punctuation, nested wrapper nodes) before they cost a review round-trip.

### Embedded / single-file-component languages

Some languages embed another language — a Svelte/Vue `<script>` block contains real JS/TS. Don't re-implement JS/TS parsing: parse the host document, locate the script's inner source node, run the existing extractor (`super::typescript::extract_ecmascript`), then remap every byte offset back into the host file with `support::shift_offsets`. The Svelte extractor is the reference implementation for this shape.

---

## When a Language Has No Usable Grammar

Not every language has a tree-sitter grammar you can depend on. **Surface this honestly — don't ship a fragile workaround.** Work through these in order:

1. **Search crates.io for a maintained binding.** Try the obvious name and common variants (`tree-sitter-<lang>`, `-<lang>-ng`, `-<lang>3`). Prefer the one with real download counts and recent releases.

2. **Check tree-sitter version compatibility — this is the usual blocker.** code2graph pins `tree-sitter` to `>=0.24, <0.27`. A grammar crate built against an old `tree-sitter` (e.g. `0.20`) exposes a _different_ `Language` type that **cannot** be passed to our parser, and its generated parser may have an ABI version outside our supported range. The `abi_versions_are_compatible` test in `src/grammar.rs` guards the ABI; a mismatched crate will fail it (or fail to link). If the only available grammar is stuck on an old tree-sitter, the language is **not feasible right now** — say so in the PR/issue.

3. **Do not bridge incompatible tree-sitter versions.** Adding an old `tree-sitter` as a side dependency and transmuting its `Language` into ours is a layout-dependent hack that breaks the moment either crate changes. It violates the project's durability bar and will be rejected. The same goes for any "make it link somehow" FFI trick.

4. **If a grammar source exists but isn't published compatibly,** vendoring/regenerating it is a real option — but it crosses the "grammars come from crates.io" line and adds generated C to maintain. **Open a Discussion first**; this is a project-level decision, not a drive-by PR.

5. **Otherwise, document and skip.** Note the blocker (which crates exist, what tree-sitter version they target) in an issue so the next person doesn't re-discover it. When a maintained, compatible grammar appears, the language becomes a normal recipe-follows contribution.

The honest "we can't support this yet, and here's exactly why" is a valuable contribution. A grammar shim that links by luck is not.

---

## Resolution Tiers

Resolution is **pluggable behind the `Resolver` trait** — the tier seam. Every resolver takes per-file `FileFacts` and emits the same `CodeGraph` schema, tagging each edge with a `Confidence` and a `Provenance`. Consumers pick a tier without changing how they read the output.

| Tier  | Resolver              | Confidence         | Behaviour                                                                                                                                                                                                         |
| ----- | --------------------- | ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **A** | `SymbolTableResolver` | `NameOnly`         | Fast, all languages, **recall-first**. Matches by name/scope. An ambiguous name fans out to _all_ same-named definitions.                                                                                         |
| **B** | `ScopeGraphResolver`  | `Scoped` / `Exact` | Scope-aware: resolves references through lexical scopes, imports, and qualified paths. **Emits an edge only when it can resolve precisely — never fakes precision** (zero false positives is the contract).       |
| —     | `FfiBridgeResolver`   | —                  | Links cross-language boundaries deterministically (e.g. a `#[no_mangle]` Rust fn called from C, a PyO3 `#[pyfunction]` from Python) by matching the exported ABI name, which plain name resolution can't recover. |

`Provenance` records _which analysis_ derived an edge (name table, scope graph, FFI bridge, …), orthogonal to `Confidence`.

**The decisive axis is resolution correctness.** The highest-value resolution contributions:

- **Extend scope-aware resolution to another language.** Tier B's quality depends on the extractor emitting the right facts — qualifiers on member calls, import bindings with their `from_path`, namespace descriptors. Improving an extractor's references often upgrades that language from Tier-A fan-out to Tier-B precision with no resolver change.
- **Improve the resolver itself** behind the trait. New resolution capabilities (e.g. type-qualified call resolution) slot in behind the seam and must hold the contract: _uniqueness gates precision_ — widen the candidate set only where you can still prove a unique match, so you never introduce a false positive.

When you touch resolution, prove it with the eval harness (below).

---

## Validation: Prove the Number

"Best at code→graph" must be a **number**, not a claim. The `eval/` crate scores ref→def **precision and recall per language and per tier**. The evaluation unit is a _located edge_ (a reference site bound to a definition site), so name-only fan-out is penalised exactly where it over-connects: a reference linking to _N_ same-named definitions scores one true positive and _N − 1_ false positives.

```bash
cargo run -p code2graph-eval      # print the scorecard
cargo test  -p code2graph-eval    # the regression gate on the invariants
```

The corpus has two kinds of ground truth, both under `eval/corpus/`:

- **Golden fixtures** — hand-authored `expected.edges`, for role-typed scoring.
- **SCIP oracles** — `<lang>_oracle/<case>/` directories scored location-only against an index produced by a mature, type-aware indexer (rust-analyzer, scip-typescript, scip-java, …). This is how Tier-B's precision thesis is locked against an _external_ source of truth. See `eval/ORACLE.md` for the (maintainer-only, off-by-default) oracle regeneration workflow — the normal build and test loop pulls no SCIP/indexer dependencies; it only ever reads committed artifacts.

**When you add a language**, add at least one corpus case. **When you improve resolution**, add a case that exercises the ambiguity you fixed, and confirm the regression gate locks the gain. The regression tests encode _invariants_ (Tier-A keeps full recall in its lane; Tier-B never emits a false positive; Tier-B beats Tier-A on precision where genuine ambiguity exists) — not brittle exact rates.

---

## Testing

- **Unit tests** — in the same file as the code under test, `#[cfg(test)] mod tests { use super::*; … }`. Can test private functions. This is where extractor tests live (expected SCIP strings, kinds, captured references).
- **Integration tests** — in `eval/tests/` (and any crate's `tests/`). Test the public API and end-to-end resolution behaviour.
- **Corpus cases** — the data-driven scoring fixtures under `eval/corpus/`. Adding a directory is automatically picked up by the harness; no plumbing changes.

A language PR should include unit tests for the extractor **and** at least one corpus case.

---

## Code Standards

Enforced in review — run all three green before opening a PR:

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test --workspace
```

- **No `.unwrap()` / `.expect()` / `panic!` in library code.** Return `Result`, propagate with `?`, use `if let`/`let … else`. (Test code may unwrap.)
- **No `Result<T, String>`** — use the crate's typed `CodegraphError`.
- **Module-root files (`mod.rs` / `lib.rs`) are wiring only** — declarations and re-exports, no logic. (See the core invariants.)
- **Reuse `support.rs` helpers** rather than re-implementing text extraction, signature building, scope/binding construction, or reference pushing.
- **Keep files and functions focused.** If a module is expected to grow, use a directory from the start. Prefer many small, single-purpose files.
- **Grammars only through `src/grammar.rs`.** No direct `tree_sitter_*` imports elsewhere.

---

## Commits and Pull Requests

**Commit format** — [Conventional Commits](https://www.conventionalcommits.org/), scoped by area:

```
feat(extract): add Scala extractor
fix(resolve): capture receiver as qualifier on qualified calls
test(eval): add ruby_oracle/ambiguous_call corpus fixture
docs(symbol): document SCIP descriptor rendering
```

Types: `feat`, `fix`, `perf`, `refactor`, `test`, `docs`, `chore`. Common scopes: `extract`, `resolve`, `symbol`, `graph`, `lang`, `grammar`, `eval`.

- **One logical change per commit.** Each commit must build standalone (no broken bisect) — e.g. an extractor fix lands before the resolver test that depends on it.
- **Keep PRs scoped.** A new language is one coherent PR; don't bundle unrelated changes.
- **Draft PRs are welcome** for directional feedback before a full implementation.
- **Don't include generated noise** — no `Cargo.lock` churn unrelated to your dependency, no formatter reflows of untouched files.

---

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By participating you are expected to uphold it. Report unacceptable behaviour through the channels listed there.

## License

code2graph is licensed under **Apache-2.0**. By contributing, you agree your contributions are licensed under the same terms. No CLA is required.
