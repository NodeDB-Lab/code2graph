// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import test from "node:test";
import { canonicalId } from "../extensions/code2graph/types.ts";
import { validateNative } from "../extensions/code2graph/code2graph-node.ts";

const complete = { extract() { return {}; }, buildGraph() { return {}; }, languageOf() { return null; }, GraphIndex: class {} };
test("native adapter rejects incomplete payloads including GraphIndex", () => {
  assert.throws(() => validateNative({ extract() {} }), /extract, buildGraph, languageOf, and GraphIndex/);
  assert.throws(() => validateNative({ extract() { return {}; }, buildGraph() { return {}; }, languageOf() { return null; } }), /GraphIndex/);
  assert.doesNotThrow(() => validateNative(complete));
});
test("legacy string symbol identities are rejected at the Pi boundary", () => {
  assert.throws(() => canonicalId("scip codegraph . foo()."), /lossless JSON identity/);
  assert.throws(() => canonicalId(JSON.stringify({ version: 1, scip: "x", lang: "Rust", file: "x.rs" })), /lossless JSON identity/);
});
