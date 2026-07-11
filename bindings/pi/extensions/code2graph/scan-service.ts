// SPDX-License-Identifier: Apache-2.0

import { existsSync, realpathSync } from "node:fs";
import { readdir, readFile, stat } from "node:fs/promises";
import { createHash } from "node:crypto";
import { Worker } from "node:worker_threads";
import path from "node:path";
import ignore from "ignore";
import { getNative } from "./code2graph-node.ts";
import { buildIndexes, type CodeGraph, type FileFacts, type ScanResult, type Tier } from "./types.ts";

const DEFAULT_MAX_FILES = 300, HARD_MAX_FILES = 1000, MAX_FILE_BYTES = 1_000_000, MAX_TOTAL_BYTES = 25_000_000, MAX_DEPTH = 32, MAX_WARNINGS = 20, MAX_CACHE_BYTES = 100_000_000, MAX_CONCURRENT = 2; let maxMs = 30_000, workerDelayForTests = 0;
const DENY = new Set([".git", ".hg", ".svn", "node_modules", "target", "dist", "build", "coverage", ".next", ".nuxt", ".svelte-kit", ".venv", "venv", "__pycache__"]);
type Cached = { result: ScanResult; fingerprint: string; at: number; bytes: number };
type Operation = { controller: AbortController; promise: Promise<ScanResult>; subscribers: number; settled: boolean; timer: ReturnType<typeof setTimeout> };
const cache = new Map<string, Cached>();
const pending = new Map<string, Operation>();
let active = 0, workerStarts = 0;
export interface ScanParams { root?: string; tier?: Tier; maxFiles?: number; includeHidden?: boolean; refresh?: boolean }
const abortError = () => new DOMException("Code graph scan cancelled", "AbortError");
function stopped(signal?: AbortSignal) { if (signal?.aborted) throw abortError(); }
function rootOf(cwd: string, requested?: string) { const root = path.resolve(cwd, requested?.trim() || "."); if (!existsSync(root)) throw new Error(`Path does not exist: ${root}`); return realpathSync(root); }
function rel(root: string, file: string) { return path.relative(root, file).split(path.sep).join("/"); }
async function rules(root: string) { const result = ignore(); for (const name of [".gitignore", ".ignore"]) try { result.add(await readFile(path.join(root, name), "utf8")); } catch {} return result; }
export async function collectSources(root: string, hidden: boolean, max: number, signal?: AbortSignal, supports: (file: string) => boolean = file => Boolean(getNative().languageOf(file))) {
  const ig = await rules(root), out: Array<{ file: string; source: string }> = [], warnings: string[] = []; let bytes = 0, truncated = false;
  async function walk(dir: string, depth: number): Promise<void> {
    stopped(signal); if (depth > MAX_DEPTH) { warnings.push(`Skipped deep directory ${rel(root, dir)}`); return; }
    let entries; try { entries = await readdir(dir, { withFileTypes: true }); } catch (e) { if (warnings.length < MAX_WARNINGS) warnings.push(`Cannot read ${rel(root, dir)}: ${String(e)}`); return; }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      stopped(signal); const full = path.join(dir, entry.name), relative = rel(root, full);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) { if (!DENY.has(entry.name) && (hidden || !entry.name.startsWith(".")) && !ig.ignores(`${relative}/`)) await walk(full, depth + 1); continue; }
      if (!entry.isFile() || (!hidden && entry.name.startsWith(".")) || ig.ignores(relative) || !supports(relative)) continue;
      if (out.length >= max) { truncated = true; return; }
      try { const size = (await stat(full)).size; if (size > MAX_FILE_BYTES || bytes + size > MAX_TOTAL_BYTES) { if (warnings.length < MAX_WARNINGS) warnings.push(`Skipped ${relative}: source budget exceeded`); continue; } const source = await readFile(full, "utf8"); bytes += Buffer.byteLength(source); out.push({ file: relative, source }); } catch (e) { if (warnings.length < MAX_WARNINGS) warnings.push(`Skipped ${relative}: ${String(e)}`); }
    }
  }
  await walk(root, 0); return { out, warnings, bytes, truncated };
}
type WorkerResult = { facts: FileFacts[]; graph: CodeGraph };
type WorkerRunner = (files: Array<{ file: string; source: string }>, tier: Tier, signal: AbortSignal) => Promise<WorkerResult>;
let workerRunner: WorkerRunner;
function worker(files: Array<{ file: string; source: string }>, tier: Tier, signal: AbortSignal): Promise<WorkerResult> {
  return new Promise((resolve, reject) => {
    workerStarts++;
    const w = new Worker(new URL("./scan-worker.mjs", import.meta.url)); let done = false;
    const finish = (fn: (value: any) => void, value: any) => { if (done) return; done = true; signal.removeEventListener("abort", cancel); void w.terminate(); fn(value); };
    const cancel = () => finish(reject, abortError());
    w.once("message", m => m.error ? finish(reject, new Error(m.error)) : finish(resolve, m)); w.once("error", e => finish(reject, e)); signal.addEventListener("abort", cancel, { once: true }); w.postMessage({ files, tier, delayMs: workerDelayForTests });
  });
}
workerRunner = worker;
function lruSet(key: string, item: Cached) { cache.delete(key); cache.set(key, item); let total = [...cache.values()].reduce((n, x) => n + x.bytes, 0); while (total > MAX_CACHE_BYTES && cache.size) { const old = cache.entries().next().value as [string, Cached]; cache.delete(old[0]); total -= old[1].bytes; } }
function subscribe(operation: Operation, signal?: AbortSignal): Promise<ScanResult> {
  stopped(signal); operation.subscribers++;
  return new Promise((resolve, reject) => {
    let done = false;
    const leave = () => { if (done) return; done = true; signal?.removeEventListener("abort", abort); operation.subscribers--; if (!operation.settled && operation.subscribers === 0) operation.controller.abort(); };
    const abort = () => { leave(); reject(abortError()); };
    signal?.addEventListener("abort", abort, { once: true });
    operation.promise.then(value => { leave(); resolve(value); }, error => { leave(); reject(error); });
  });
}
function createOperation(key: string, root: string, tier: Tier, maxFiles: number, hidden: boolean, refresh: boolean): Operation {
  const controller = new AbortController(); let operation!: Operation;
  const promise = (async () => {
    const collected = await collectSources(root, hidden, maxFiles, controller.signal);
    const fingerprint = createHash("sha256").update(JSON.stringify({ files: collected.out, hidden })).digest("hex");
    const hit = cache.get(key);
    if (!refresh && hit?.fingerprint === fingerprint) { cache.delete(key); cache.set(key, hit); return { ...hit.result, cache: { hit: true, ageMs: Date.now() - hit.at } }; }
    if (active >= MAX_CONCURRENT) throw new Error("Too many concurrent code graph scans; retry after an active scan completes");
    active++;
    try {
      const native = await workerRunner(collected.out, tier, controller.signal); stopped(controller.signal);
      const result: ScanResult = { root, tier, files: native.facts, graph: native.graph, warnings: collected.warnings, truncated: collected.truncated, totalBytes: collected.bytes, cache: { hit: false, ageMs: 0 }, indexes: buildIndexes(native.graph), queryIndex: new (getNative().GraphIndex)(native.graph) };
      if (!controller.signal.aborted && operation.subscribers > 0) lruSet(key, { result, fingerprint, at: Date.now(), bytes: collected.bytes });
      return result;
    } finally { active--; }
  })();
  operation = { controller, promise, subscribers: 0, settled: false, timer: setTimeout(() => controller.abort(), maxMs) };
  promise.finally(() => { operation.settled = true; clearTimeout(operation.timer); if (pending.get(key) === operation) pending.delete(key); }).catch(() => {});
  return operation;
}
export async function scan(cwd: string, params: ScanParams = {}, signal?: AbortSignal): Promise<ScanResult> {
  stopped(signal); const root = rootOf(cwd, params.root), tier = params.tier ?? "scope", maxFiles = Math.max(1, Math.min(HARD_MAX_FILES, Math.floor(params.maxFiles ?? DEFAULT_MAX_FILES))), hidden = params.includeHidden === true, key = JSON.stringify({ root, tier, maxFiles, hidden });
  let operation = pending.get(key); if (!operation) { operation = createOperation(key, root, tier, maxFiles, hidden, params.refresh === true); pending.set(key, operation); }
  return subscribe(operation, signal);
}
export function summarize(result: ScanResult) { return { root: result.root, tier: result.tier, files: result.files.length, symbols: result.graph.symbols.length, edges: result.graph.edges.length, totalBytes: result.totalBytes, warnings: { count: result.warnings.length, samples: result.warnings.slice(0, 5) }, truncated: result.truncated, cache: result.cache }; }
export function clearCache() { cache.clear(); }
export function scanDebugState() { return { pending: pending.size, active, cache: cache.size, workerStarts }; }
/** Test-only controls; not exported from the extension entry point. */
export function configureScanForTests(options: { timeoutMs?: number; workerDelayMs?: number; workerRunner?: WorkerRunner }) { if (options.timeoutMs !== undefined) maxMs = options.timeoutMs; if (options.workerDelayMs !== undefined) workerDelayForTests = options.workerDelayMs; if (options.workerRunner !== undefined) workerRunner = options.workerRunner; }
export function resetScanTestConfiguration() { maxMs = 30_000; workerDelayForTests = 0; workerRunner = worker; }
