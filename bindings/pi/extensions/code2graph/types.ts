// SPDX-License-Identifier: Apache-2.0

export type Tier = "name" | "scope";
export type SymbolId = { version: number; scip: string; lang?: string; file?: string };
export type SymbolIdInput = SymbolId | string;

export interface Occurrence { file: string; line: number; col: number; byte: number }
export interface SymbolFact { id: SymbolId; name: string; kind: string; file: string; line: number; signature?: string; visibility?: string; span?: { start: number; end: number } }
export interface EdgeFact { from: SymbolId; to: SymbolId; role: string; confidence: string; provenance: string; occ?: Occurrence }
export interface FileFacts { file: string; lang: string; symbols: SymbolFact[]; references?: unknown[]; bindings?: unknown[]; ffi_exports?: unknown[]; scopes?: unknown[] }
export interface CodeGraph { symbols: SymbolFact[]; edges: EdgeFact[] }

export interface ScanIndexes {
  symbolByKey: Map<string, SymbolFact>;
  forward: Map<string, EdgeFact[]>;
  reverse: Map<string, EdgeFact[]>;
}
export interface ScanResult {
  root: string; tier: Tier; files: FileFacts[]; graph: CodeGraph; warnings: string[]; truncated: boolean;
  totalBytes: number; cache: { hit: boolean; ageMs: number }; indexes: ScanIndexes;
}

export function canonicalId(value: SymbolIdInput): string {
  const id = typeof value === "string" ? parseId(value) : value;
  if (!id || !Number.isInteger(id.version) || id.version < 0 || typeof id.scip !== "string") throw new TypeError("Invalid code2graph SymbolId");
  if ((id.lang === undefined) === (id.file === undefined)) throw new TypeError("SymbolId must be global (lang) or local (file)");
  return JSON.stringify(id.lang === undefined
    ? { version: id.version, scip: id.scip, file: id.file }
    : { version: id.version, scip: id.scip, lang: id.lang });
}
export function parseId(value: string): SymbolId {
  try { return JSON.parse(value) as SymbolId; } catch { throw new TypeError("symbolId must be the lossless JSON identity returned by code2graph"); }
}
export function displayId(value: SymbolId): string { return value.scip; }
export function buildIndexes(graph: CodeGraph): ScanIndexes {
  const symbolByKey = new Map<string, SymbolFact>(); const forward = new Map<string, EdgeFact[]>(); const reverse = new Map<string, EdgeFact[]>();
  for (const symbol of graph.symbols) symbolByKey.set(canonicalId(symbol.id), symbol);
  for (const edge of graph.edges) { const from = canonicalId(edge.from); const to = canonicalId(edge.to); (forward.get(from) ?? forward.set(from, []).get(from)!).push(edge); (reverse.get(to) ?? reverse.set(to, []).get(to)!).push(edge); }
  for (const list of [...forward.values(), ...reverse.values()]) list.sort((a, b) => canonicalId(a.from).localeCompare(canonicalId(b.from)) || canonicalId(a.to).localeCompare(canonicalId(b.to)) || a.role.localeCompare(b.role));
  return { symbolByKey, forward, reverse };
}
