# code2graph Python bindings

`code2graph-rs` exposes the Rust extractor and resolver as Python values. It returns neutral symbols, references, and edges; it performs no storage or policy work.

## Identity wire format

Facts and graphs encode `SymbolId` losslessly. Global identities use an object with `version: 1`, `scip`, and `lang`; local identities use `version: 1`, `scip`, and `file`. The `scip` value stays compatible with SCIP tooling, but SCIP has no language or local-file coordinate, so applications must retain the whole object when persisting or forwarding facts. Deserialization also accepts the legacy plain SCIP string for compatibility, though it cannot preserve those identity coordinates. `GraphIndex` deliberately rejects that lossy form for identity lookup and traversal.

## GraphIndex queries

`GraphIndex` accepts a resolved `CodeGraph` dictionary whose symbol and edge IDs are lossless structural-ID dictionaries. Python method names and serde payload fields use snake_case:

```python
index = GraphIndex(graph)
index.symbol(symbol_id)  # a locally defined symbol or None
index.symbols_named("run")
index.ids_with_scip(symbol_id["scip"])  # plural: SCIP display strings can collide
index.incoming(symbol_id, 50, "Call", "Scoped", "ScopeGraph")
index.outgoing(symbol_id, 50)
index.impact(symbol_id, 3, 100, "Call", "Scoped", "ScopeGraph")
```

Global IDs are `{ "version": 1, "scip": ..., "lang": ... }`; local IDs are `{ "version": 1, "scip": ..., "file": ... }`. `ids_with_scip` is plural because globals with different `lang` coordinates and locals with different `file` coordinates can have identical SCIP display strings. Edges may also contain endpoint-only IDs: they are traversable, but `symbol` returns `None` for them.

`incoming`, `outgoing`, and `impact` accept optional `role`, `min_confidence`, and `provenance` filters. Valid role values are `Call`, `IsImplementation`, `Import`, `ModuleRef`, `TypeRef`, `Read`, and `Write`; confidence values are `Heuristic`, `NameOnly`, `Scoped`, and `Exact`; provenance values are `SymbolTable`, `ScopeGraph`, `FfiBridge`, `Conformance`, `NormalizedName`, and `External`. All provided filters are conjoined. Omitted filters allow every role/provenance and use `Heuristic` as the confidence floor. `limit` must be a positive `u32`; output order is deterministic. `impact` follows incoming edges, excludes the seed, terminates cycles, and returns `{ "steps": ..., "truncated": ... }`. `truncated` is true only if a depth or node bound omitted a matching reachable ID; no `visited` field is returned.

After `maturin develop`, or after installing the wheel produced by `maturin build`, run `python -m unittest bindings/python/tests/test_query.py` from the repository root to exercise this surface.
