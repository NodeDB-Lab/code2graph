// SPDX-License-Identifier: Apache-2.0

import { canonicalId, displayId, type EdgeFact, type RefRole, type ScanResult, type SymbolFact, type SymbolIdInput } from "./types.ts";

const ROLES: readonly RefRole[] = ["Call", "IsImplementation", "Import", "ModuleRef", "TypeRef", "Read", "Write"];
const ROLE_BY_NORMALIZED = new Map(ROLES.map(role => [role.toLowerCase(), role]));
function canonicalRole(role?: string): RefRole | undefined {
  if (role === undefined) return undefined;
  const canonical = ROLE_BY_NORMALIZED.get(role.trim().toLowerCase());
  if (!canonical) throw new TypeError(`role must be one of ${ROLES.join(", ")}`);
  return canonical;
}
function nativeLimit(result: ScanResult): number { return Math.max(1, Math.min(0xffff_ffff, result.graph.edges.length)); }
/** Mirrors native EdgeKey: confidence is an attribute, not edge identity. */
function edgeKey(edge: EdgeFact): string {
  return JSON.stringify([canonicalId(edge.from), canonicalId(edge.to), edge.role, edge.occ.file, edge.occ.byte, edge.provenance]);
}

export function matches(symbol: SymbolFact, query: string, kind?: string, file?: string): boolean { const q=query.trim().toLowerCase(); if(kind&&symbol.kind.toLowerCase()!==kind.toLowerCase())return false; if(file&&!symbol.file.toLowerCase().includes(file.toLowerCase()))return false; return !q||[symbol.name,displayId(symbol.id),symbol.signature,symbol.file].some(v=>v.toLowerCase().includes(q)); }
export function symbolPreview(symbol: SymbolFact) { return {id:symbol.id,idDisplay:displayId(symbol.id),name:symbol.name,kind:symbol.kind,file:symbol.file,line:symbol.line,signature:symbol.signature,visibility:symbol.visibility}; }
export function resolveSymbols(result: ScanResult, query: string, exactId?: SymbolIdInput): SymbolFact[] { if(exactId !== undefined && (typeof exactId !== "string" || exactId.trim())) { try { const one=result.indexes.symbolByKey.get(canonicalId(exactId)); return one?[one]:[]; } catch { throw new TypeError("symbolId must be the lossless identity from a previous code2graph result"); } } return result.graph.symbols.filter(s=>matches(s,query)); }
export function edgesForSymbols(result: ScanResult, symbols: SymbolFact[], direction: "callers"|"callees", role?: string): EdgeFact[] {
  const edges = new Map<string, EdgeFact>(), canonical = canonicalRole(role), limit = nativeLimit(result);
  for (const symbol of symbols) for (const edge of direction === "callers"
    ? result.queryIndex.incoming(symbol.id, limit, canonical, "Heuristic")
    : result.queryIndex.outgoing(symbol.id, limit, canonical, "Heuristic")) edges.set(edgeKey(edge), edge);
  // Each native adjacency response is already in EdgeKey order. Do not re-sort
  // with a lossy TypeScript approximation of SymbolId/RefRole native ordering.
  return [...edges.values()];
}
export function edgePreview(edge:EdgeFact,result:ScanResult,direction:"callers"|"callees"){const id=direction==="callers"?edge.from:edge.to;const symbol=result.indexes.symbolByKey.get(canonicalId(id));return{role:edge.role,confidence:edge.confidence,provenance:edge.provenance,occurrence:edge.occ,other:symbol?symbolPreview(symbol):null};}
export interface ReverseImpactRow { depth: number; via: EdgeFact; symbol: SymbolFact | null }
export interface ReverseImpactResult { rows: ReverseImpactRow[]; truncated: boolean }
/** Aggregate independently native-computed reverse-impact results; TypeScript never walks edges. */
export function reverseImpact(result: ScanResult, targets: SymbolFact[], role: string | undefined, maxDepth: number, limit: number): ReverseImpactResult {
  const canonical = canonicalRole(role), seen = new Set(targets.map(symbol => canonicalId(symbol.id))), rows: ReverseImpactRow[] = [];
  let truncated = false;
  for (let targetIndex = 0; targetIndex < targets.length; targetIndex++) {
    const remaining = limit - rows.length;
    if (remaining <= 0) return { rows, truncated: true };
    const impact = result.queryIndex.impact(targets[targetIndex].id, maxDepth, remaining, canonical, "Heuristic");
    truncated ||= impact.truncated;
    for (const step of impact.steps) {
      const key = canonicalId(step.symbol);
      if (seen.has(key)) continue;
      seen.add(key);
      rows.push({ depth: step.depth, via: step.via, symbol: result.indexes.symbolByKey.get(key) ?? null });
      if (rows.length === limit) break;
    }
    if (rows.length === limit && targetIndex + 1 < targets.length) return { rows, truncated: true };
  }
  return { rows, truncated };
}
