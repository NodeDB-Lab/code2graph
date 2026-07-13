// SPDX-License-Identifier: Apache-2.0
import { parentPort } from "node:worker_threads";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const native = require("@nodedb-lab/code2graph");
parentPort.on("message", async ({ files, tier, delayMs = 0 }) => {
  try {
    if (delayMs > 0) await new Promise(resolve => setTimeout(resolve, delayMs));
    const facts = files.map(({ file, source }) => native.extractWithBindings(file, source));
    const graph = native.buildGraph(facts, tier);
    const ids = [...graph.symbols.map((symbol) => symbol.id), ...graph.edges.flatMap((edge) => [edge.from, edge.to])];
    if (!Array.isArray(graph.symbols) || !Array.isArray(graph.edges) || ids.some((id) => !id || typeof id !== "object" || !Number.isInteger(id.version) || typeof id.scip !== "string" || ((typeof id.lang === "string") === (typeof id.file === "string")))) throw new Error("Installed @nodedb-lab/code2graph does not provide the required lossless SymbolId wire format; install version 0.0.0-beta.7 or newer.");
    parentPort.postMessage({ facts, graph });
  } catch (error) {
    parentPort.postMessage({ error: error instanceof Error ? error.message : String(error) });
  }
});
