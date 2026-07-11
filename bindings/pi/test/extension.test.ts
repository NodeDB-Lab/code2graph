// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { scan } from "../extensions/code2graph/scan.ts";
import extension from "../extensions/code2graph/index.ts";
import { getNative } from "../extensions/code2graph/code2graph-node.ts";

test("extension registers every public tool and command against ExtensionAPI", async () => {
  const tools: any[] = []; const commands = new Map<string, any>();
  extension({ registerTool(tool: any) { tools.push(tool); }, registerCommand(name: string, command: any) { commands.set(name, command); } } as any);
  assert.deepEqual(tools.map(tool => tool.name).sort(), ["code2graph_callees", "code2graph_callers", "code2graph_impact", "code2graph_scan", "code2graph_symbol_search"]);
  assert(commands.has("code2graph"));
  const notices: any[] = []; await commands.get("code2graph").handler("status", { cwd: process.cwd(), ui: { notify(message: string, level: string) { notices.push({ message, level }); } } });
  assert.match(notices[0].message, /tools loaded/); assert.equal(notices[0].level, "info");
});
test("tool schemas expose exact identity and bounded traversal inputs", () => {
  const tools: any[] = []; extension({ registerTool(tool: any) { tools.push(tool); }, registerCommand() {} } as any);
  for (const tool of tools) { assert.equal(typeof tool.execute, "function"); assert.equal(typeof tool.description, "string"); }
  assert.match(String(tools.find(tool => tool.name === "code2graph_callers").description), /exact lossless symbolId/);
});
test("relation and impact tools accept an exact symbolId without a text query", async t => {
  try { getNative(); } catch { t.skip("requires a built or published native binding; scan lifecycle tests inject a test native module"); return; }
  const root = await mkdtemp(path.join(tmpdir(), "pi-code2graph-selector-"));
  try {
    await writeFile(path.join(root, "sample.rs"), "pub fn target() {}\npub fn caller() { target(); }\n");
    const graph = await scan(root, { refresh: true }); const id = graph.graph.symbols.find(symbol => symbol.name === "target")!.id;
    const tools: any[] = []; extension({ registerTool(tool: any) { tools.push(tool); }, registerCommand() {} } as any);
    const ctx = { cwd: root }; const signal = new AbortController().signal;
    for (const name of ["code2graph_callers", "code2graph_impact"]) {
      const result = await tools.find(tool => tool.name === name).execute("test", { symbolId: id, refresh: true }, signal, undefined, ctx);
      assert.equal(result.details.ambiguous, false);
    }
    await assert.rejects(() => tools.find(tool => tool.name === "code2graph_callers").execute("test", {}, signal, undefined, ctx), /Provide query or symbolId/);
  } finally { await rm(root, { recursive: true, force: true }); }
});
