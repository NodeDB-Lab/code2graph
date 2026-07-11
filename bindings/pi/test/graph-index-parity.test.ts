// SPDX-License-Identifier: Apache-2.0
/** Test-only oracle retained to prove Pi's native query contract, never shipped in extension code. */
import assert from "node:assert/strict";
import test from "node:test";
import { getNative } from "../extensions/code2graph/code2graph-node.ts";
import { canonicalId, type CodeGraph, type EdgeFact, type RefRole, type SymbolId } from "../extensions/code2graph/types.ts";

const id = (name: string, lang = "rust"): SymbolId => ({ version: 1, scip: `codegraph . . . ${name}.`, lang });
const endpoint: SymbolId = { version: 1, scip: "local remote", file: "vendor/api.rs" };
const a = id("a"), b = id("b"), c = id("c"), d = id("d"), sameScipOtherLanguage = id("a", "python");
const edge = (from: SymbolId, to: SymbolId, byte: number, role: RefRole = "Call"): EdgeFact => ({ from, to, role, confidence: "Exact", provenance: "ScopeGraph", occ: { file: "calls.rs", line: 1, col: byte, byte } });
const graph: CodeGraph = { symbols: [a, b, c, d, sameScipOtherLanguage].map((value, n) => ({ id: value, name: value.scip, kind: "Function", visibility: "Public", entry_points: [], file: `${n}.rs`, line: 1, span: { start: 0, end: 1 }, signature: `fn item_${n}()` })), edges: [edge(a, endpoint, 1), edge(a, endpoint, 2), edge(b, a, 3), edge(c, a, 4), edge(d, b, 5), edge(a, b, 6), edge(c, endpoint, 7, "Import")] };
function compareEdges(left: EdgeFact, right: EdgeFact) { return canonicalId(left.from).localeCompare(canonicalId(right.from)) || canonicalId(left.to).localeCompare(canonicalId(right.to)) || left.role.localeCompare(right.role) || left.occ.byte - right.occ.byte; }
function legacyIncoming(target: SymbolId, role?: string) { return graph.edges.filter(item => canonicalId(item.to) === canonicalId(target) && (!role || item.role === role)).sort(compareEdges); }
function legacyOutgoing(source: SymbolId, role?: string) { return graph.edges.filter(item => canonicalId(item.from) === canonicalId(source) && (!role || item.role === role)).sort(compareEdges); }
function legacyImpact(seed: SymbolId, maxDepth: number, limit: number, role?: string) {
  const seen = new Set([canonicalId(seed)]), rows: Array<[string, number]> = []; let frontier = [seed];
  for (let depth = 1; depth <= maxDepth && frontier.length && rows.length < limit; depth++) { const next: SymbolId[] = []; for (const current of frontier) for (const item of legacyIncoming(current, role)) if (!seen.has(canonicalId(item.from))) { seen.add(canonicalId(item.from)); next.push(item.from); rows.push([canonicalId(item.from), depth]); if (rows.length === limit) break; } frontier = next; }
  return rows;
}
test("native GraphIndex matches the test-only legacy oracle across structural identities and traversal bounds", t => {
  let NativeGraphIndex: ReturnType<typeof getNative>["GraphIndex"];
  try { NativeGraphIndex = getNative().GraphIndex; } catch { t.skip("requires a built or published native binding; lifecycle tests inject a test native module"); return; }
  const native = new NativeGraphIndex(graph);
  assert.equal(native.symbol(endpoint), null, "endpoint-only IDs remain traversable but are not definitions");
  assert.notEqual(canonicalId(a), canonicalId(sameScipOtherLanguage), "SCIP display collisions are not structural collisions");
  assert.deepEqual(native.incoming(endpoint, graph.edges.length, "Call", "Heuristic").map(item => item.occ.byte), legacyIncoming(endpoint, "Call").map(item => item.occ.byte));
  assert.deepEqual(native.outgoing(a, graph.edges.length, "Call", "Heuristic").map(item => canonicalId(item.to)), legacyOutgoing(a, "Call").map(item => canonicalId(item.to)));
  assert.deepEqual(native.impact(a, 3, graph.edges.length, "Call", "Heuristic").steps.map(item => [canonicalId(item.symbol), item.depth]), legacyImpact(a, 3, graph.edges.length, "Call"));
  assert.equal(native.impact(a, 1, graph.edges.length, "Call", "Heuristic").truncated, true, "depth bounds report omitted diamond descendants");
  assert.equal(native.impact(a, 3, 1, "Call", "Heuristic").truncated, true, "node bounds report omitted nodes");
});
