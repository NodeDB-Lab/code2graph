# FFI support matrix

Which cross-language (cross-runtime) call boundaries code2graph bridges today — honestly, with what
is **not yet** covered.

> The canonical source is `FfiAbi` + `FfiAbi::consumers()` in [`src/graph/types.rs`](../src/graph/types.rs)
> and the export markers in the per-language extractors. This page is hand-maintained; if it
> disagrees with the code, the code wins.

## What an FFI bridge is

Most static graphs stop at the language boundary: a Rust function exposed to C, or a Rust `wasm`
function called from JavaScript, is a dead end. code2graph's `FfiBridgeResolver` links a call site in
one language to a definition in another, **deterministically**:

- The **export** side is grounded in a real syntactic marker (e.g. Rust `#[no_mangle]`), recorded as
  a neutral `FfiExport { symbol, abi, export_name }`.
- The **consumer** side is matched by the exported ABI name, and only in a language that actually
  consumes that ABI (`FfiAbi::consumers()`), so a C call never binds to a Python-only export.
- Same-language use is _not_ a bridge (that's an ordinary call).
- Every bridge edge carries `Provenance::FfiBridge` and an honest `Confidence`: `Scoped` when the
  export is unique, `NameOnly` when several share the name. Never dressed up as precise.

## The matrix

Read a cell as **the row language calling a function defined in the column language**. Columns are
only the _natively-compiled_ languages that can expose an ABI; managed/scripting languages appear as
callers (rows) only. Pairs that aren't a standard FFI boundary are left blank.

**Legend:** 🟢 bridged by code2graph today · 🟠 real FFI boundary, not bridged yet (the frontier) ·
blank = not a standard FFI pair · — same language (ordinary call, not FFI)

| Caller ↓ \ Callee → | Rust |  C  | C++ | Go  | Swift | Zig | Kotlin/N |
| ------------------- | :--: | :-: | :-: | :-: | :---: | :-: | :------: |
| **C**               |  🟢  |  —  | 🟠  | 🟠  |  🟠   | 🟠  |    🟠    |
| **C++**             |  🟢  | 🟠  |  —  | 🟠  |  🟠   | 🟠  |    🟠    |
| **Rust**            |  —   | 🟠  | 🟠  | 🟠  |  🟠   | 🟠  |    🟠    |
| **Go**              |  🟠  | 🟠  | 🟠  |  —  |       | 🟠  |          |
| **Swift**           |  🟠  | 🟠  | 🟠  |     |   —   | 🟠  |          |
| **Zig**             |  🟠  | 🟠  | 🟠  | 🟠  |  🟠   |  —  |          |
| **Python**          |  🟢  | 🟠  | 🟠  | 🟠  |       | 🟠  |          |
| **Ruby**            |  🟠  | 🟠  | 🟠  |     |       | 🟠  |          |
| **JavaScript / TS** |  🟢  | 🟠  | 🟠  | 🟠  |       | 🟠  |          |
| **Java**            |  🟢  | 🟢  | 🟠  | 🟠  |       | 🟠  |          |
| **Kotlin**          |  🟠  | 🟠  | 🟠  |     |  🟠   | 🟠  |    —     |
| **C#**              |  🟠  | 🟠  | 🟠  | 🟠  |       | 🟠  |          |

The 🟢 cells are exactly the bridges code2graph emits today; every 🟠 is a real, named mechanism we do
not emit yet (see [the frontier](#not-yet-covered-the-frontier)).

## How the bridges are grounded (markers)

Each FFI mechanism, named once so the matrix cells stay uncluttered. The export side is always
grounded in a real syntactic marker; the consumer side is matched by the exported name.

| Mechanism           | Direction                         | Export marker                                         | State |
| ------------------- | --------------------------------- | ----------------------------------------------------- | ----- |
| C ABI               | C / C++ → Rust                    | Rust `#[no_mangle]`, `#[export_name = "…"]`           | 🟢    |
| PyO3                | Python → Rust                     | `#[pyfunction]` (`#[pyo3(name = "…")]` renames)       | 🟢    |
| Wasm                | JS / TS → Rust                    | `#[wasm_bindgen]`                                     | 🟢    |
| Node-API            | JS / TS → Rust                    | `#[napi]`                                             | 🟢    |
| JNI                 | Java → Rust, C                    | `Java_*` name mangling                                | 🟢    |
| C ABI (import side) | Rust / C++ / Go / Swift / Zig → C | `extern "C"`, cgo `//export`, `@_cdecl`, Zig `export` | 🟠    |
| cgo                 | Go ↔ C                            | `//export`, `import "C"`                              | 🟠    |
| ctypes / cffi       | Python → C                        | (runtime handle, no export marker)                    | 🟠    |
| pybind11 / Cython   | Python → C++                      | binding-generator                                     | 🟠    |
| P/Invoke            | C# → native                       | `[DllImport]` / `[UnmanagedCallersOnly]`              | 🟠    |
| cinterop / `@CName` | Kotlin/Native ↔ C                 | Kotlin `@CName`                                       | 🟠    |
| Rustler NIF         | Elixir / Erlang → Rust            | `#[rustler::nif]`                                     | 🟠    |

Edge confidence for the 🟢 bridges: `Scoped` when the export is unique, `NameOnly` when several share
the name — always `Provenance::FfiBridge`, never dressed up as precise.

## Honest ceilings

- **Export side is Rust-centric.** Only Rust (all five ABIs) and C (JNI only) currently _produce_
  exports. "You consuming a native library" — the inverse direction — is largely not bridged yet
  (see below).
- **Call-only.** Bridges are for calls across the boundary, not shared structs/data layouts (that's
  the type-inference frontier).
- **Consumer matched by name.** No arity/signature check; ambiguity stays `NameOnly` so consumers
  can filter it.

## Not yet covered (the frontier)

These are real, common boundaries code2graph does **not** bridge today. Listed honestly so you know
the edges of the map; ranked roughly by how common the boundary is.

- **C / C++ as a first-class export side** — a C function is C-ABI callable by default, so
  `Rust extern "C" → C` and `C++ → C` (consuming a C library) should bridge but don't yet.
- **Go cgo** — `//export` / `import "C"`.
- **C# P/Invoke** — `[DllImport]` (import) and `[UnmanagedCallersOnly]` (export).
- **BEAM NIFs / Rustler** — Rust `#[rustler::nif]` ↔ Elixir/Erlang (pairs with adding those
  languages).
- **Swift `@_cdecl`, Kotlin/Native `@CName` / cinterop, pybind11 / Cython (C++→Python).**
- **Python `ctypes` / `cffi` and Go cgo as consumers** — these call through a library handle
  (`lib.foo()`, `C.foo()`), a different call shape than the bare-name match used today.
- **WebAssembly component model / WIT imports** (beyond `wasm-bindgen` exports).

The architecture extends cleanly: each new boundary is one `FfiAbi` variant + a marker recognised in
the relevant extractor + an entry in `consumers()`. The resolver itself is generic.

## See also

- [supported-languages.md](supported-languages.md) — per-language extraction depth.
- [CONTRIBUTING.md](../CONTRIBUTING.md) — how to add a language or an FFI boundary.
