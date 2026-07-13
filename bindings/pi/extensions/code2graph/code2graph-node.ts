// SPDX-License-Identifier: Apache-2.0

import { createRequire } from "node:module";
import { arch, platform } from "node:process";
import type { CodeGraph, Confidence, EdgeFact, FileFacts, Provenance, RefRole, SymbolFact, SymbolId, Tier } from "./types.ts";

const require = createRequire(import.meta.url);
export interface NativeImpactStep { symbol: SymbolId; parent: SymbolId; depth: number; path_confidence: Confidence; via: EdgeFact }
export interface NativeImpactResult { steps: NativeImpactStep[]; truncated: boolean }
export interface NativeGraphIndex {
  symbol(id: SymbolId): SymbolFact | null;
  incoming(id: SymbolId, limit: number, role?: RefRole | null, minConfidence?: Confidence | null, provenance?: Provenance | null): EdgeFact[];
  outgoing(id: SymbolId, limit: number, role?: RefRole | null, minConfidence?: Confidence | null, provenance?: Provenance | null): EdgeFact[];
  impact(id: SymbolId, maxDepth: number, limit: number, role?: RefRole | null, minConfidence?: Confidence | null, provenance?: Provenance | null): NativeImpactResult;
}
export interface Native {
  extract(file: string, source: string): FileFacts;
  extractWithBindings(file: string, source: string, customRules?: { lang: string; construct: string; sqlArg: number }[]): FileFacts;
  buildGraph(files: FileFacts[], tier?: Tier | null): CodeGraph;
  languageOf(file: string): string | null;
  GraphIndex: new (graph: CodeGraph) => NativeGraphIndex;
}

let injectedNative: Native | undefined;

export function validateNative(value: unknown): Native {
  const native = value as Partial<Native>;
  if (typeof native?.extract !== "function" || typeof native.extractWithBindings !== "function" || typeof native.buildGraph !== "function" || typeof native.languageOf !== "function" || typeof native.GraphIndex !== "function") throw new TypeError("package did not expose extract, extractWithBindings, buildGraph, languageOf, and GraphIndex");
  return native as Native;
}

function load(): Native {
  try {
    return validateNative(require("@nodedb-lab/code2graph"));
  } catch (cause) {
    const detail = cause instanceof Error ? ` ${cause.message}` : "";
    throw new Error(`Unable to load @nodedb-lab/code2graph for ${platform}/${arch}. Install supported optional native dependencies with \`npm install @nodedb-lab/pi-code2graph\` (or reinstall without --omit=optional). Supported targets: linux x64/arm64 glibc, linux x64 musl, macOS x64/arm64, Windows x64.${detail}`, { cause: cause instanceof Error ? cause : undefined });
  }
}

/** Load the validated production binding on first actual native use. */
export function getNative(): Native { return injectedNative ?? load(); }

/** Test-only injection that avoids loading an unpublished native package. */
export function setNativeForTests(native?: Native): void { injectedNative = native; }
