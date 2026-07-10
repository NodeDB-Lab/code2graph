# code2graph — Node.js / Bun bindings

Node.js and Bun native-addon bindings to the [code2graph](https://github.com/nodedb-lab/code2graph) Rust library, built with [napi-rs](https://napi.rs). Given source files in any supported language, it produces symbols, references, and cross-file edges as plain JS objects — the same neutral facts as the Rust crate, with no storage opinion.

## Build

```sh
npm install
npm run build:debug   # debug build — emits platform .node + index.js + index.d.ts
npm run build         # release build
```

The `napi build` command (from `@napi-rs/cli`) compiles the Rust crate and writes three files into `bindings/node/`: the platform-native `.node` addon, `index.js` (the JS loader), and `index.d.ts` (TypeScript declarations).

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

The generated loader is post-processed by `npm run harden-loader` after every `napi build`; environment variables never select a module to execute during package import.
