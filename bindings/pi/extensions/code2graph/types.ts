// SPDX-License-Identifier: Apache-2.0

import type { NativeGraphIndex } from "./code2graph-node.ts";

export type Tier = "name" | "scope";
export type GlobalSymbolId = { version: 1; scip: string; lang: string; file?: never };
export type LocalSymbolId = { version: 1; scip: string; file: string; lang?: never };
export type SymbolId = GlobalSymbolId | LocalSymbolId;
export type SymbolIdInput = SymbolId | string;
export type Confidence = "Heuristic" | "NameOnly" | "Scoped" | "Exact";
export type RefRole = "Call" | "IsImplementation" | "Import" | "ModuleRef" | "TypeRef" | "Read" | "Write";
export type Provenance = "SymbolTable" | "ScopeGraph" | "FfiBridge" | "Conformance" | "NormalizedName" | "External";

export interface Occurrence { file: string; line: number; col: number; byte: number }
export interface SymbolFact {
  id: SymbolId; name: string; kind: string; visibility: string; entry_points: unknown[];
  file: string; line: number; span: { start: number; end: number }; signature: string;
}
export interface EdgeFact { from: SymbolId; to: SymbolId; role: RefRole; confidence: Confidence; provenance: Provenance; occ: Occurrence }
export interface FileFacts {
  file: string; lang: string; symbols: SymbolFact[]; references: unknown[]; scopes: unknown[];
  bindings: unknown[]; ffi_exports: unknown[];
}
export interface CodeGraph { symbols: SymbolFact[]; edges: EdgeFact[] }

export interface ScanIndexes { symbolByKey: Map<string, SymbolFact> }
export interface ScanResult {
  root: string; tier: Tier; files: FileFacts[]; graph: CodeGraph; warnings: string[]; truncated: boolean;
  totalBytes: number; cache: { hit: boolean; ageMs: number }; indexes: ScanIndexes; queryIndex: NativeGraphIndex;
}

function validId(value: unknown): value is SymbolId {
  if (!value || typeof value !== "object") return false;
  const id = value as Partial<SymbolId>;
  return id.version === 1 && typeof id.scip === "string"
    && ((typeof id.lang === "string" && id.file === undefined) || (typeof id.file === "string" && id.lang === undefined));
}
export function canonicalId(value: SymbolIdInput): string {
  const id = typeof value === "string" ? parseId(value) : value;
  if (!validId(id)) throw new TypeError("SymbolId must be a version-1 global (lang) or local (file) identity");
  return JSON.stringify(id.lang === undefined
    ? { version: id.version, scip: id.scip, file: id.file }
    : { version: id.version, scip: id.scip, lang: id.lang });
}
export function parseId(value: string): SymbolId {
  try {
    const parsed: unknown = JSON.parse(value);
    if (!validId(parsed)) throw new TypeError();
    return parsed;
  } catch { throw new TypeError("symbolId must be the lossless JSON identity returned by code2graph"); }
}
export function displayId(value: SymbolId): string { return value.scip; }
export function buildIndexes(graph: CodeGraph): ScanIndexes {
  const symbolByKey = new Map<string, SymbolFact>();
  for (const symbol of graph.symbols) symbolByKey.set(canonicalId(symbol.id), symbol);
  return { symbolByKey };
}
