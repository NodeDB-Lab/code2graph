// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import test from "node:test";
import { edgesForSymbols, resolveSymbols } from "../extensions/code2graph/relations.ts";
import { buildIndexes, type CodeGraph, type ScanResult } from "../extensions/code2graph/types.ts";
const a = { version: 1, scip: "a", lang: "Rust" }, b = { version: 1, scip: "b", lang: "Rust" }; const graph: CodeGraph = { symbols: [{ id: a, name: "a", kind: "Function", file: "a.rs", line: 1 }, { id: b, name: "b", kind: "Function", file: "b.rs", line: 1 }], edges: [{ from: { ...a }, to: { ...b }, role: "Call", confidence: "Exact", provenance: "ScopeGraph" }] }; const result = { root: ".", tier: "scope", files: [], graph, warnings: [], truncated: false, totalBytes: 0, cache: { hit: false, ageMs: 0 }, indexes: buildIndexes(graph) } as ScanResult;
test("relations join independently allocated identity objects", () => { const target = resolveSymbols(result, "", JSON.stringify(b)); assert.equal(edgesForSymbols(result, target, "callers").length, 1); });
