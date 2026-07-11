// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { setNativeForTests, type Native } from "../extensions/code2graph/code2graph-node.ts";
import { clearCache, configureScanForTests, resetScanTestConfiguration, scan } from "../extensions/code2graph/scan-service.ts";
import type { CodeGraph, FileFacts, SymbolId } from "../extensions/code2graph/types.ts";

const id: SymbolId = { version: 1, scip: "codegraph . . . helper.", lang: "rust" };
const graph: CodeGraph = { symbols: [{ id, name: "helper", kind: "Function", visibility: "Public", entry_points: [], file: "sample.rs", line: 1, span: { start: 0, end: 1 }, signature: "fn helper()" }], edges: [] };
const facts: FileFacts[] = [{ file: "sample.rs", lang: "rust", symbols: graph.symbols, references: [], scopes: [], bindings: [], ffi_exports: [] }];

function fixtureNative(constructions: { value: number }): Native {
  return {
    extract: () => facts[0], buildGraph: () => graph, languageOf: file => file.endsWith(".rs") ? "rust" : null,
    GraphIndex: class {
      constructor(_graph: CodeGraph) { constructions.value++; }
      symbol() { return null; }
      incoming() { return []; }
      outgoing() { return []; }
      impact() { return { steps: [], truncated: false }; }
    },
  };
}
function runner(delayMs = 0) {
  return (_files: Array<{ file: string; source: string }>, _tier: "name" | "scope", signal: AbortSignal): Promise<{ facts: FileFacts[]; graph: CodeGraph }> => new Promise((resolve, reject) => {
    const abort = () => reject(new DOMException("cancelled", "AbortError"));
    if (signal.aborted) return abort();
    signal.addEventListener("abort", abort, { once: true });
    setTimeout(() => { signal.removeEventListener("abort", abort); resolve({ facts, graph }); }, delayMs);
  });
}
async function withFixture(run: (root: string, constructions: { value: number }) => Promise<void>) {
  const root = await mkdtemp(path.join(tmpdir(), "pi-code2graph-worker-"));
  const constructions = { value: 0 };
  await writeFile(path.join(root, "sample.rs"), "pub fn helper() {}\n");
  setNativeForTests(fixtureNative(constructions)); configureScanForTests({ workerRunner: runner() });
  try { await run(root, constructions); } finally { resetScanTestConfiguration(); clearCache(); setNativeForTests(); await rm(root, { recursive: true, force: true }); }
}

test("a new scan constructs exactly one native query handle", async () => withFixture(async (root, constructions) => {
  await scan(root, { refresh: true });
  assert.equal(constructions.value, 1);
}));

test("a cache hit reuses the exact native query handle", async () => withFixture(async (root, constructions) => {
  const first = await scan(root, { refresh: true });
  const hit = await scan(root);
  assert.equal(constructions.value, 1); assert.equal(hit.cache.hit, true); assert.strictEqual(hit.queryIndex, first.queryIndex);
}));

test("refresh and source changes replace the native query handle", async () => withFixture(async (root, constructions) => {
  const first = await scan(root, { refresh: true });
  const refreshed = await scan(root, { refresh: true });
  assert.equal(constructions.value, 2); assert.notStrictEqual(refreshed.queryIndex, first.queryIndex);
  await writeFile(path.join(root, "sample.rs"), "pub fn changed() {}\n");
  const changed = await scan(root);
  assert.equal(constructions.value, 3); assert.notStrictEqual(changed.queryIndex, refreshed.queryIndex);
}));

test("cancellation and timeout never publish a native query handle", async () => withFixture(async (root, constructions) => {
  configureScanForTests({ workerRunner: runner(100) });
  const controller = new AbortController(); const cancelled = scan(root, { refresh: true }, controller.signal); controller.abort();
  await assert.rejects(cancelled, { name: "AbortError" }); assert.equal(constructions.value, 0);
  configureScanForTests({ timeoutMs: 10, workerRunner: runner(100) });
  await assert.rejects(scan(root, { refresh: true }), { name: "AbortError" }); assert.equal(constructions.value, 0);
  await new Promise(resolve => setTimeout(resolve, 0));
  configureScanForTests({ timeoutMs: 1_000, workerRunner: runner() });
  await scan(root, { refresh: true }); assert.equal(constructions.value, 1);
}));
