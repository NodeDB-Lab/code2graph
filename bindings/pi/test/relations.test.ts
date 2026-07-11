// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import test from "node:test";
import { edgesForSymbols, resolveSymbols, reverseImpact } from "../extensions/code2graph/relations.ts";
import { buildIndexes, type CodeGraph, type EdgeFact, type RefRole, type ScanResult, type SymbolFact, type SymbolId } from "../extensions/code2graph/types.ts";

const id = (scip: string): SymbolId => ({ version: 1, scip, lang: "Rust" });
const a = id("a"), b = id("b"), c = id("c");
const symbol = (value: SymbolId, name: string): SymbolFact => ({ id: value, name, kind: "Function", visibility: "Public", entry_points: [], file: `${name}.rs`, line: 1, span: { start: 0, end: 1 }, signature: `fn ${name}()` });
const first: EdgeFact = { from: a, to: b, role: "Call", confidence: "Exact", provenance: "ScopeGraph", occ: { file: "a.rs", line: 1, col: 1, byte: 1 } };
const parallel: EdgeFact = { ...first, occ: { file: "a.rs", line: 1, col: 2, byte: 2 } };
const graph: CodeGraph = { symbols: [symbol(a, "a"), symbol(b, "b"), symbol(c, "c")], edges: [first, parallel] };
const calls: Array<unknown[]> = [];
const queryIndex = {
  symbol: () => null,
  incoming: (_id: SymbolId, limit: number, role?: RefRole | null) => { calls.push(["incoming", limit, role]); return [parallel, first]; },
  outgoing: (_id: SymbolId, limit: number, role?: RefRole | null) => { calls.push(["outgoing", limit, role]); return [first]; },
  impact: (value: SymbolId, _depth: number, limit: number, role?: RefRole | null) => {
    calls.push(["impact", value, limit, role]);
    return { truncated: false, steps: value.scip === "b" ? [{ symbol: a, parent: b, depth: 1, path_confidence: "Exact" as const, via: first }] : [{ symbol: a, parent: c, depth: 1, path_confidence: "Exact" as const, via: first }] };
  },
};
const result = { root: ".", tier: "scope", files: [], graph, warnings: [], truncated: false, totalBytes: 0, cache: { hit: false, ageMs: 0 }, indexes: buildIndexes(graph), queryIndex } as unknown as ScanResult;

test("relations preserve native adjacency order, canonicalize every RefRole, and retain parallel evidence", () => {
  const target = resolveSymbols(result, "", JSON.stringify(b));
  const edges = edgesForSymbols(result, target, "callers", "cAlL");
  assert.deepEqual(edges, [parallel, first], "TypeScript must not replace native EdgeKey order");
  assert.deepEqual(calls[0], ["incoming", graph.edges.length, "Call"]);
  const roles: RefRole[] = ["Call", "IsImplementation", "Import", "ModuleRef", "TypeRef", "Read", "Write"];
  for (const role of roles) assert.doesNotThrow(() => edgesForSymbols(result, target, "callers", role.toLowerCase()));
  assert.throws(() => edgesForSymbols(result, target, "callers", "unknown"), /Call, IsImplementation, Import, ModuleRef, TypeRef, Read, Write/);
});

test("edge dedup retains every native EdgeKey identity field and excludes confidence", () => {
  const variants: EdgeFact[] = [
    first,
    { ...first, confidence: "Scoped" },
    { ...first, from: c },
    { ...first, to: c },
    { ...first, role: "Import" },
    { ...first, provenance: "External" },
    { ...first, occ: { ...first.occ, file: "other.rs" } },
    { ...first, occ: { ...first.occ, byte: 99 } },
  ];
  const dedupResult = { ...result, queryIndex: { ...queryIndex, incoming: () => variants } } as unknown as ScanResult;
  assert.equal(edgesForSymbols(dedupResult, [graph.symbols[1]], "callers").length, 7);
});

test("impact delegates traversal to native and reports a global multi-target limit honestly", () => {
  const impact = reverseImpact(result, [graph.symbols[1], graph.symbols[2]], "CALL", 2, 1);
  assert.equal(impact.rows.length, 1); assert.equal(impact.rows[0].symbol?.name, "a");
  assert.equal(impact.truncated, true, "an unqueried matched target is omitted by the shared limit");
  assert.deepEqual(calls.at(-1)?.slice(0, 1), ["impact"]);
});
