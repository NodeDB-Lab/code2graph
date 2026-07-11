// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { collectSources } from "../extensions/code2graph/scan-service.ts";

async function fixture(files: Record<string, string>) {
  const root = await mkdtemp(path.join(tmpdir(), "pi-code2graph-"));
  await Promise.all(Object.entries(files).map(async ([name, content]) => {
    const target = path.join(root, name); await import("node:fs/promises").then(({ mkdir }) => mkdir(path.dirname(target), { recursive: true }));
    await writeFile(target, content);
  }));
  return root;
}
const supported = (file: string) => file.endsWith(".rs") || file.endsWith(".ts");
async function withFixture(files: Record<string, string>, run: (root: string) => Promise<void>) { const root = await fixture(files); try { await run(root); } finally { await rm(root, { recursive: true, force: true }); } }

test("scan traversal honors ignore rules, hidden paths, and deterministic ordering", async () => withFixture({
  ".gitignore": "ignored.rs\n!ignored-keep.rs\n", "z.rs": "z", "a.ts": "a", "ignored.rs": "x", "ignored-keep.rs": "y", ".hidden.rs": "h", "node_modules/no.rs": "n",
}, async root => {
  const visible = await collectSources(root, false, 20, undefined, supported);
  assert.deepEqual(visible.out.map(x => x.file), ["a.ts", "ignored-keep.rs", "z.rs"]);
  const hidden = await collectSources(root, true, 20, undefined, supported);
  assert(hidden.out.some(x => x.file === ".hidden.rs")); assert(!hidden.out.some(x => x.file.includes("node_modules")));
}));

test("scan limits distinguish an over-limit tree and stop before extra source reads", async () => withFixture({ "a.rs": "a", "b.rs": "b" }, async root => {
  const one = await collectSources(root, false, 1, undefined, supported);
  assert.equal(one.out.length, 1); assert.equal(one.truncated, true);
  const all = await collectSources(root, false, 2, undefined, supported);
  assert.equal(all.out.length, 2); assert.equal(all.truncated, false);
}));

test("scan cancellation prevents traversal completion", async () => withFixture({ "a.rs": "a" }, async root => {
  const controller = new AbortController(); controller.abort();
  await assert.rejects(() => collectSources(root, false, 10, controller.signal, supported), { name: "AbortError" });
}));

test("scan ignores symlink loops and never escapes its selected root", async () => withFixture({ "a.rs": "a" }, async root => {
  await symlink(root, path.join(root, "loop"));
  const result = await collectSources(root, false, 10, undefined, supported);
  assert.deepEqual(result.out.map(x => x.file), ["a.rs"]);
}));

test("content changes, add-remove-rename, same-size edits, and ignore changes produce distinct discovery fingerprints", async () => withFixture({ "a.rs": "one" }, async root => {
  const fingerprint = async () => JSON.stringify((await collectSources(root, false, 20, undefined, supported)).out);
  const initial = await fingerprint(); await writeFile(path.join(root, "a.rs"), "two"); assert.notEqual(await fingerprint(), initial);
  await writeFile(path.join(root, "b.rs"), "b"); const added = await fingerprint(); assert(added.includes("b.rs"));
  await import("node:fs/promises").then(({ rename }) => rename(path.join(root, "b.rs"), path.join(root, "c.rs"))); assert((await fingerprint()).includes("c.rs"));
  await writeFile(path.join(root, ".gitignore"), "c.rs\n"); assert(!(await fingerprint()).includes("c.rs"));
}));
