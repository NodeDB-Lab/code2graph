// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";
test("npm package allowlist ships only Pi runtime resources", () => {
  const out = execFileSync("npm", ["pack", "--dry-run", "--json"], {
    encoding: "utf8",
  });
  const pack = JSON.parse(out)[0];
  const files = pack.files.map((f) => f.path);
  for (const required of [
    "extensions/code2graph/index.ts",
    "extensions/code2graph/scan-service.ts",
    "extensions/code2graph/scan-worker.mjs",
    "media/code2graph-preview.webp",
    "media/code2graph-preview.zen",
    "README.md",
    "LICENSE",
  ])
    assert(files.includes(required), required);
  assert.equal(
    readFileSync("LICENSE", "utf8").trimStart().startsWith("Apache License"),
    true,
  );
  assert.equal(
    readFileSync("media/code2graph-preview.zen", "utf8").includes(
      "code2graph for Pi",
    ),
    true,
  );
  assert(
    !files.some(
      (f) =>
        f.startsWith("test/") ||
        f.includes("node_modules") ||
        f.endsWith(".node") ||
        f.includes(".pi/") ||
        f.includes(".git"),
    ),
  );
  const manifest = JSON.parse(
    execFileSync("npm", ["pkg", "get", "dependencies.@nodedb-lab/code2graph"], {
      encoding: "utf8",
    }),
  );
  assert.match(manifest, /^\^?0\.0\.0-beta\.(\d+)$/);
  const beta = Number(manifest.match(/beta\.(\d+)$/)?.[1]);
  assert(beta >= 7, `requires lossless SymbolId support, got ${manifest}`);
  assert(!String(manifest).match(/file:|link:|workspace:|\//));
});
