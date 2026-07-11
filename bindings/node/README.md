# code2graph — Node.js / Bun bindings

Node.js and Bun native-addon bindings to the [code2graph](https://github.com/nodedb-lab/code2graph) Rust library, built with [napi-rs](https://napi.rs). Given source files in any supported language, it produces symbols, references, and cross-file edges as plain JS objects — the same neutral facts as the Rust crate, with no storage opinion.

## Build

```sh
npm install
npm run build:debug   # debug build — emits platform .node + index.js + index.d.ts
npm run build         # release build
```

The `napi build` command (from `@napi-rs/cli`) compiles the Rust crate and writes three files into `bindings/node/`: the platform-native `.node` addon, `index.js` (the JS loader), and `index.d.ts` (TypeScript declarations). The build post-processes the generated declaration file from `types/index.d.ts` so query IDs, filters, and results retain their public semantics.

## Usage

napi-rs automatically converts Rust `snake_case` function names to JS `camelCase` (`build_graph` → `buildGraph`, `language_of` → `languageOf`). TypeScript types are generated as `index.d.ts`.

```js
import { extract, buildGraph, languageOf } from "@nodedb-lab/code2graph";

const facts = extract("src/lib.rs", "pub fn hello() {}");
const graph = buildGraph([facts], "name");
console.log(graph.edges);

console.log(languageOf("src/main.go")); // "go"
console.log(languageOf("unknown.xyz")); // null
```

The addon is a CommonJS package, so CJS `require("@nodedb-lab/code2graph")` works too — ESM `import` resolves via Node's interop.

The `tier` argument to `buildGraph` is `"name"` (default, Tier A — fast, recall-first, `NameOnly` confidence) or `"scope"` (Tier B — scope-graph path resolution, `Scoped`/`Exact` confidence).

## Identity wire format

`SymbolId` values in facts and graphs are lossless objects: global IDs contain `{ version: 1, scip, lang }` and local IDs contain `{ version: 1, scip, file }`. `scip` is the standard SCIP-compatible display string, while `lang` and `file` preserve code2graph identity coordinates that SCIP itself has no field for. Consumers persisting or forwarding facts must retain the full object. Input remains backward-compatible with the legacy string form, but a legacy string cannot preserve those coordinates.

## GraphIndex queries

`GraphIndex` accepts a resolved `CodeGraph` serde object whose symbol and edge IDs are lossless structural-ID objects, and exposes exact structural-ID lookup and deterministic graph queries. Node method names are camelCase; graph payload fields and returned objects retain their Rust serde snake_case names (`entry_points`, `path_confidence`, `occ`).

```js
const index = new GraphIndex(graph);
index.symbol(symbolId); // a locally defined symbol or null
index.symbolsNamed("run");
index.idsWithScip(symbolId.scip); // plural: SCIP display strings can collide
index.incoming(symbolId, 50, "Call", "Scoped", "ScopeGraph");
index.outgoing(symbolId, 50);
index.impact(symbolId, 3, 100, "Call", "Scoped", "ScopeGraph");
```

`symbol`, `incoming`, `outgoing`, and `impact` require a lossless ID object, never a bare SCIP string. A global ID is `{ version: 1, scip, lang }`; a local ID is `{ version: 1, scip, file }`. `idsWithScip` is deliberately plural because global IDs with different `lang` coordinates and local IDs with different `file` coordinates can render to the same SCIP string. Edges may also name endpoint-only IDs, which are traversable but return `null` from `symbol`.

`incoming`, `outgoing`, and `impact` apply every supplied exact filter: `role` is one of `Call`, `IsImplementation`, `Import`, `ModuleRef`, `TypeRef`, `Read`, or `Write`; `minConfidence` is `Heuristic`, `NameOnly`, `Scoped`, or `Exact`; `provenance` is `SymbolTable`, `ScopeGraph`, `FfiBridge`, `Conformance`, `NormalizedName`, or `External`. Omitted filters mean every role/provenance and a `Heuristic` minimum confidence. `limit` must be a positive `u32`; query output is structural-ID/edge-key deterministic. `impact` traverses incoming edges, excludes the seed, terminates cycles, and returns `{ steps, truncated }`. `truncated` is true only when the requested depth or node limit omitted a matching reachable ID; there is no `visited` field.

`npm test` runs both the loader hardening check and the executable GraphIndex fixture coverage.

The generated loader is post-processed by `npm run harden-loader` after every `napi build`; environment variables never select a module to execute during package import.
