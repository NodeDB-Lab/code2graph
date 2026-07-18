# Supported languages

What code2graph can turn into structural facts — what's supported today, at what depth, and what's
planned. One table; only languages we'll **never** support are kept out of it (see the end).

> **The canonical, always-current set is the `Language` enum + extension dispatch in
> [`src/lang.rs`](../src/lang.rs).** This page is hand-maintained; if it disagrees with the code, the
> code wins. "Supported" = **extraction depth** (what facts we emit), not merely "the file parses."

## Legend

**Resolution tiers** (both behind the `Resolver` trait — see [README](../README.md#resolution-tiers)):

- **Tier A** (`SymbolTableResolver`) — name-based, recall-first; the floor under **every
  _supported_ language** (the ⭐/🟢/🟣 rows). An ambiguous name links to all same-named definitions
  (`NameOnly`, or `Scoped` when globally unique). It only needs symbols + references, which every
  extractor emits — so 🟠 planned / 🔴 blocked languages get _nothing_ (no extractor → no facts → no
  resolution at all, Tier-A included) until an extractor is written.
- **Tier B** (`ScopeGraphResolver`) — scope-aware (lexical scopes, imports, qualified paths),
  `Scoped`/`Exact`, never fakes precision. Available where the extractor emits `scopes` + `bindings`.

**Status & depth** (one marker per language = the _highest_ tier it reaches, on top of Tier-A):

- ⭐ **supported · Tier-B, oracle-measured** — scope-aware resolution with ref→def precision/recall
  scored against an external SCIP oracle (rust-analyzer / scip-typescript / scip-java / …). The
  proven lane.
- 🟢 **supported · Tier-B** — scope-aware resolution (emits scopes + bindings); not yet oracle-measured.
- 🟣 **supported · cross-artifact** — declarative format with no scope-aware tier: Tier-A name
  matching **plus** cross-artifact stitching (definition symbols + cross-reference edges, so a Rust
  field stitches to a SQL table). No lexical scopes or read/write.
- 🟠 **planned** — a tree-sitter grammar is believed available; adding it is the mechanical recipe.
  _(Always confirm `tree-sitter >=0.24, <0.27` compatibility first — see CONTRIBUTING.)_
- 🔴 **blocked** — feasible in principle, but no usable/compatible grammar exists yet.

**Capabilities:** ✓ emitted · ⤴ via a shared extractor · — not emitted / n/a · _blank_ = not implemented yet (a gap to contribute).

**Entry-pts** = attack-surface markers (`main`, HTTP routes); see [Entry-points](#entry-points).
Cross-language **FFI** is a property of language _pairs_, so it lives in its own matrix —
[ffi-support-matrix.md](ffi-support-matrix.md).

## Languages

| Language        | Extensions                              | Status | Calls | Imports | Inherit | Type-ref | Read/Write | Entry-pts | Notes                                                                 |
| --------------- | --------------------------------------- | :----: | :---: | :-----: | :-----: | :------: | :--------: | :-------: | --------------------------------------------------------------------- |
| Rust            | `.rs`                                   |   ⭐   |   ✓   |    ✓    |    ✓    |    ✓     |     ✓      |     ✓     | traits → inherit; FFI producer                                        |
| TypeScript      | `.ts` `.tsx`                            |   ⭐   |   ✓   |    ✓    |    ✓    |    ✓     |     ✓      |           |                                                                       |
| JavaScript      | `.js` `.jsx` `.mjs` `.cjs`              |   🟢   |   ⤴   |    ⤴    |    ⤴    |    ⤴     |     ⤴      |           | via the TS engine; not separately oracle-scored                       |
| Python          | `.py` `.pyi`                            |   ⭐   |   ✓   |    ✓    |    ✓    |    ✓     |     ✓      |     ✓     |                                                                       |
| Go              | `.go`                                   |   ⭐   |   ✓   |    ✓    |    —    |    ✓     |     ✓      |     ✓     | structural interfaces → no class inheritance                          |
| Java            | `.java`                                 |   ⭐   |   ✓   |    ✓    |    ✓    |    ✓     |     ✓      |     ✓     |                                                                       |
| C               | `.c` `.h`                               |   ⭐   |   ✓   |    —    |    —    |    ✓     |     ✓      |     ✓     | no import graph                                                       |
| C++             | `.cc` `.cpp` `.cxx` `.hh` `.hpp` `.hxx` |   ⭐   |   ✓   |    —    |    ✓    |    ✓     |     ✓      |     ✓     |                                                                       |
| Kotlin          | `.kt` `.kts`                            |   ⭐   |   ✓   |    ✓    |    ✓    |    ✓     |     ✓      |     ✓     |                                                                       |
| Ruby            | `.rb`                                   |   ⭐   |   ✓   |    —    |    ✓    |    —     |     ✓      |           | no type-refs / import graph                                           |
| PHP             | `.php`                                  |   🟢   |   ✓   |    ✓    |    ✓    |    ✓     |     ✓      |           |                                                                       |
| Swift           | `.swift`                                |   🟢   |   ✓   |    ✓    |    ✓    |    ✓     |     ✓      |     ✓     |                                                                       |
| C#              | `.cs`                                   |   🟢   |   ✓   |    ✓    |    ✓    |    ✓     |     ✓      |     ✓     |                                                                       |
| Scala           | `.scala` `.sc`                          |   🟢   |   ✓   |    ✓    |    ✓    |    ✓     |     ✓      |     ✓     |                                                                       |
| Dart            | `.dart`                                 |   🟢   |   ✓   |    ✓    |    ✓    |    ✓     |     ✓      |           |                                                                       |
| Solidity        | `.sol`                                  |   🟢   |   ✓   |    ✓    |    ✓    |    ✓     |     ✓      |           |                                                                       |
| Lua             | `.lua`                                  |   🟢   |   ✓   |    ✓    |    —    |    —     |     ✓      |           |                                                                       |
| Luau            | `.luau`                                 |   🟢   |   ⤴   |    ⤴    |    —    |    —     |     ⤴      |           | via the Lua-family core                                               |
| Pascal / Delphi | `.pas` `.dpr` `.dpk` `.lpr`             |   🟢   |   ✓   |    ✓    |    ✓    |    ✓     |     ✓      |           |                                                                       |
| Shell           | `.sh` `.bash` `.zsh`                    |   🟢   |   ✓   |    —    |    —    |    —     |     ✓      |           |                                                                       |
| Svelte          | `.svelte`                               |   🟢   |   ⤴   |    ⤴    |    ⤴    |    ⤴     |     ⤴      |           | `<script>` blocks via the TS engine                                   |
| SQL             | `.sql`                                  |   🟣   |   —   |    —    |    —    |    ✓     |     —      |     —     | `Table`/`View`/`Column` symbols; `FROM`/`JOIN` refs                   |
| HCL / Terraform | `.tf` `.hcl` `.tfvars`                  |   🟣   |   —   |    —    |    —    |    ✓     |     —      |     —     | `Resource`/module symbols; resource refs                              |
| Elixir          | `.ex` `.exs`                            |   🟠   |       |         |         |          |            |           | tree-sitter-elixir; `def`/`defp` = clean visibility; macros = ceiling |
| Erlang          | `.erl` `.hrl`                           |   🟠   |       |         |         |          |            |           | tree-sitter-erlang (WhatsApp); `-export` = visibility                 |
| Gleam           | `.gleam`                                |   🟠   |       |         |         |          |            |           | BEAM family; tree-sitter-gleam                                        |
| Zig             | `.zig`                                  |   🟠   |       |         |         |          |            |           | tree-sitter-zig                                                       |
| Julia           | `.jl`                                   |   🟠   |       |         |         |          |            |           | tree-sitter-julia                                                     |
| R               | `.r` `.R`                               |   🟠   |       |         |         |          |            |           | tree-sitter-r                                                         |
| Haskell         | `.hs`                                   |   🟠   |       |         |         |          |            |           | tree-sitter-haskell                                                   |
| OCaml           | `.ml` `.mli`                            |   🟠   |       |         |         |          |            |           | tree-sitter-ocaml                                                     |
| Objective-C     | `.m` `.mm`                              |   🟠   |       |         |         |          |            |           | exposes C ABI; pairs with Swift                                       |
| Fortran         | `.f90` `.f`                             |   🟠   |       |         |         |          |            |           | tree-sitter-fortran                                                   |
| Groovy          | `.groovy` `.gradle`                     |   🟠   |       |         |         |          |            |           | tree-sitter-groovy                                                    |
| PowerShell      | `.ps1` `.psm1`                          |   🟠   |       |         |         |          |            |           | grammar exists — verify compat                                        |
| SystemVerilog   | `.sv` `.svh`                            |   🟠   |       |         |         |          |            |           | hardware; tree-sitter-verilog                                         |
| Astro           | `.astro`                                |   🟠   |       |         |         |          |            |           | SFC — embedded-script pattern (like Svelte)                           |
| Vue             | `.vue`                                  |   🔴   |       |         |         |          |            |           | SFC; no maintained grammar compatible with our pinned tree-sitter     |
| Liquid          | `.liquid`                               |   🔴   |       |         |         |          |            |           | no compatible grammar                                                 |
| F#              | `.fs` `.fsi`                            |   🔴   |       |         |         |          |            |           | grammar availability/compat to verify                                 |
| Salesforce Apex | `.cls` `.trigger`                       |   🔴   |       |         |         |          |            |           | grammar availability/compat to verify                                 |
| COBOL           | `.cob` `.cbl`                           |   🔴   |       |         |         |          |            |           | grammar maturity to verify                                            |

Supported = the ⭐/🟢/🟣 rows; 🟠 planned / 🔴 blocked are not a queue — anything with a compatible
grammar follows the same recipe. **Blank cells on supported rows are real gaps** — exactly where a
contribution lands.

## What every supported language gets

- **Symbols** with a SCIP-aligned `SymbolId`, `SymbolKind`, byte span, and a one-line signature.
- **Declared visibility** — `Public` / `Internal` / `Protected` / `Private` / `Unknown` — as a
  **neutral fact**. code2graph emits _all_ symbols regardless of visibility and tags each; it never
  filters to "public only" for you. `Unknown` is honest where the AST can't tell (Ruby's runtime
  visibility, dynamic conventions) — never guessed. Consumers apply their own public/private policy.
- **References** by role (`Call`, `Import`, `IsImplementation`, `TypeRef`, `Read`, `Write`), resolved
  with a `Confidence` (`Heuristic` < `NameOnly` < `Scoped` < `Exact`) and a `Provenance` (which
  analysis derived the edge).

## Entry-points

The **Entry-pts** column tracks a neutral `EntryPoint` fact — `Main`, or `HttpRoute("<marker>")`
carrying the raw framework marker as written (e.g. `app.get`, `GetMapping`) — detected from
unambiguous syntax only; the consumer decides what counts as attack surface. Per-language status is
the column above (✓ where a detector ships · blank = open contribution); the detector follows the
same marker-walk pattern as FFI-export detection.

**As of the current extractors:** `Main` ships for Rust, Python, Go, Java, C, C++, Kotlin, Swift,
C#, and Scala. `HttpRoute` ships only for Rust, Python, Go, and Java (framework marker walks). A
blank cell means neither ships yet — not that the language is out of scope.

## Honest limitations

- **Oracle coverage = the ⭐ rows.** Tier-B is _implemented_ more broadly (the 🟢 rows), but only the
  ⭐ set has its precision/recall measured against an external compiler-grade index. The rest are
  "expected-good, not proven."
- **The type-inference ceiling is real and we don't fake past it.** Pure syntax + scope can't fully
  resolve generics, dynamic dispatch, overloads, or macro/metaprogramming-generated code. Those
  references stay at lower `Confidence` or unresolved — by design.
- **🟠/🔴 reflect grammar availability at a glance, not a commitment.** Per CONTRIBUTING, a grammar
  must be compatible with `tree-sitter >=0.24, <0.27`; we never bridge incompatible versions.
- **No source bodies** — symbols carry a byte span; the consumer slices text from it.

## Never (out of scope — deliberately not in the table)

- **Pure markup / styling (HTML, CSS)** and **prose** — too little call/reference structure to graph.
- **Generic config / data (JSON, YAML, TOML)** as first-class code graphs. (We _do_ parse specific
  manifests — `Cargo.toml`, `package.json`, `pyproject.toml`, `go.mod` — for package-coordinate
  enrichment, but we don't model arbitrary config as a symbol graph.)
- **Binary / non-source artifacts.**

## Adding a language

The recipe is mechanical and the resolver is language-agnostic, so cross-file edges work for free
once extraction emits correct facts. See [CONTRIBUTING.md](../CONTRIBUTING.md#adding-a-language),
including the embedded-SFC pattern and what to do when no usable grammar exists.
