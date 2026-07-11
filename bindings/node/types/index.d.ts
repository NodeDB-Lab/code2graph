/* SPDX-License-Identifier: Apache-2.0 */

/** A lossless global structural ID. Its `lang` coordinate is part of identity. */
export interface GlobalSymbolId {
  version: 1
  scip: string
  lang: string
  file?: never
}

/** A lossless file-local structural ID. Its `file` coordinate is part of identity. */
export interface LocalSymbolId {
  version: 1
  scip: string
  file: string
  lang?: never
}

/** Never use a bare SCIP string as a lookup or traversal ID. */
export type SymbolId = GlobalSymbolId | LocalSymbolId
export type Confidence = 'Heuristic' | 'NameOnly' | 'Scoped' | 'Exact'
export type RefRole = 'Call' | 'IsImplementation' | 'Import' | 'ModuleRef' | 'TypeRef' | 'Read' | 'Write'
export type Provenance = 'SymbolTable' | 'ScopeGraph' | 'FfiBridge' | 'Conformance' | 'NormalizedName' | 'External'

export interface Occurrence {
  file: string
  line: number
  col: number
  byte: number
}

export interface Edge {
  from: SymbolId
  to: SymbolId
  role: RefRole
  confidence: Confidence
  provenance: Provenance
  occ: Occurrence
}

export interface Symbol {
  id: SymbolId
  name: string
  kind: string
  visibility: string
  entry_points: unknown[]
  file: string
  line: number
  span: { start: number; end: number }
  signature: string
}

export interface CodeGraph {
  symbols: Symbol[]
  edges: Edge[]
}

/** The native serde payload for extracted facts. Field names remain snake_case. */
export interface FileFacts {
  file: string
  lang: string
  symbols: Symbol[]
  references: unknown[]
  scopes: unknown[]
  bindings: unknown[]
  ffi_exports: unknown[]
}

export interface ImpactStep {
  symbol: SymbolId
  parent: SymbolId
  depth: number
  path_confidence: Confidence
  via: Edge
}

export interface ImpactResult {
  steps: ImpactStep[]
  /** True only when a depth or node bound omitted a matching reachable symbol. */
  truncated: boolean
}

/** An owned, storage-free index over a resolved graph. */
export declare class GraphIndex {
  /** Construct an index from a lossless `CodeGraph` serde object. */
  constructor(graph: CodeGraph)
  /** Return the exact locally-defined symbol for a lossless structural ID. */
  symbol(id: SymbolId): Symbol | null
  /** Return all locally-defined symbols with an exact bare name, in structural-ID order. */
  symbolsNamed(name: string): Symbol[]
  /** Return all structural IDs with a SCIP display string, including endpoint-only IDs. */
  idsWithScip(scip: string): SymbolId[]
  /** Return stable incoming edges after all supplied filters, then the positive `limit`. */
  incoming(id: SymbolId, limit: number, role?: RefRole | null, minConfidence?: Confidence | null, provenance?: Provenance | null): Edge[]
  /** Return stable outgoing edges after all supplied filters, then the positive `limit`. */
  outgoing(id: SymbolId, limit: number, role?: RefRole | null, minConfidence?: Confidence | null, provenance?: Provenance | null): Edge[]
  /** Return bounded reverse-reachability rows and whether a bound omitted a match. */
  impact(id: SymbolId, maxDepth: number, limit: number, role?: RefRole | null, minConfidence?: Confidence | null, provenance?: Provenance | null): ImpactResult
}

/** Resolve extracted facts into a code graph. */
export declare function buildGraph(files: FileFacts[], tier?: 'name' | 'scope' | null): CodeGraph
/** Extract symbols and references from a single source file. */
export declare function extract(file: string, source: string): FileFacts
/** Return the canonical language tag for a file path, or `null` if unrecognized. */
export declare function languageOf(path: string): string | null
