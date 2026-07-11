// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { clearCache, configureScanForTests, resetScanTestConfiguration, scan, scanDebugState } from "../extensions/code2graph/scan-service.ts";

async function withFixture(run: (root: string) => Promise<void>) {
  const root = await mkdtemp(path.join(tmpdir(), "pi-code2graph-worker-"));
  await writeFile(path.join(root, "sample.rs"), "pub fn helper() {}\npub fn run() { helper(); }\n");
  try { await run(root); } finally { resetScanTestConfiguration(); clearCache(); await rm(root, { recursive: true, force: true }); }
}

test("scan uses a worker thread to extract a real graph", async () => withFixture(async root => {
  const before = scanDebugState().workerStarts;
  const result = await scan(root, { refresh: true });
  assert.equal(result.files.length, 1); assert(result.graph.symbols.length >= 2); assert.equal(scanDebugState().workerStarts, before + 1);
}));

test("one shared worker survives owner cancellation while another subscriber receives its result", async () => withFixture(async root => {
  configureScanForTests({ workerDelayMs: 80 }); const before = scanDebugState().workerStarts;
  const owner = new AbortController(); const first = scan(root, { refresh: true }, owner.signal); const second = scan(root, { refresh: true }); owner.abort();
  await assert.rejects(first, { name: "AbortError" }); const result = await second;
  assert.equal(result.files.length, 1); assert.equal(scanDebugState().workerStarts, before + 1); assert.equal(scanDebugState().pending, 0);
}));

test("all cancelled subscribers terminate the shared worker without caching its result", async () => withFixture(async root => {
  configureScanForTests({ workerDelayMs: 100 }); const a = new AbortController(), b = new AbortController(); const first = scan(root, { refresh: true }, a.signal); const second = scan(root, { refresh: true }, b.signal); a.abort(); b.abort();
  await assert.rejects(first, { name: "AbortError" }); await assert.rejects(second, { name: "AbortError" });
  await new Promise(resolve => setTimeout(resolve, 30)); assert.deepEqual(scanDebugState(), { pending: 0, active: 0, cache: 0, workerStarts: scanDebugState().workerStarts });
}));

test("timeout aborts a shared scan and owner cleanup permits a fresh scan", async () => withFixture(async root => {
  configureScanForTests({ timeoutMs: 20, workerDelayMs: 100 }); await assert.rejects(scan(root, { refresh: true }), { name: "AbortError" });
  await new Promise(resolve => setTimeout(resolve, 30)); assert.equal(scanDebugState().pending, 0); configureScanForTests({ timeoutMs: 1_000, workerDelayMs: 0 });
  const result = await scan(root, { refresh: true }); assert.equal(result.files.length, 1);
}));
