# code2graph Python bindings

`code2graph-rs` exposes the Rust extractor and resolver as Python values. It returns neutral symbols, references, and edges; it performs no storage or policy work.

## Identity wire format

Facts and graphs encode `SymbolId` losslessly. Global identities use an object with `version: 1`, `scip`, and `lang`; local identities use `version: 1`, `scip`, and `file`. The `scip` value stays compatible with SCIP tooling, but SCIP has no language or local-file coordinate, so applications must retain the whole object when persisting or forwarding facts. Deserialization also accepts the legacy plain SCIP string for compatibility, though it cannot preserve those identity coordinates.
