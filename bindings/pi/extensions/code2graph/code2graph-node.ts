// SPDX-License-Identifier: Apache-2.0

import { createRequire } from "node:module";
import { arch, platform } from "node:process";
import type { CodeGraph, FileFacts, Tier } from "./types.ts";

const require = createRequire(import.meta.url);
type Native = { extract(file: string, source: string): FileFacts; buildGraph(files: FileFacts[], tier?: Tier | null): CodeGraph; languageOf(file: string): string | null };
export function validateNative(value: unknown): Native {
  const native = value as Partial<Native>;
  if (typeof native?.extract !== "function" || typeof native.buildGraph !== "function" || typeof native.languageOf !== "function") throw new TypeError("package did not expose extract, buildGraph, and languageOf");
  return native as Native;
}

function load(): Native {
  try {
    const value = require("@nodedb-lab/code2graph");
    return validateNative(value);
  } catch (cause) {
    const detail = cause instanceof Error ? ` ${cause.message}` : "";
    throw new Error(`Unable to load @nodedb-lab/code2graph for ${platform}/${arch}. Install supported optional native dependencies with \`npm install @nodedb-lab/pi-code2graph\` (or reinstall without --omit=optional). Supported targets: linux x64/arm64 glibc, linux x64 musl, macOS x64/arm64, Windows x64.${detail}`, { cause: cause instanceof Error ? cause : undefined });
  }
}
export const code2graph = load();
