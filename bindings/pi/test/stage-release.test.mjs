// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import {
  chmodSync,
  cpSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { gzipSync } from "node:zlib";
import {
  assertNormalizedArtifactsEqual,
  assertReleaseVersion,
  compareTarballs,
  stampPackage,
  tarballEntries,
  verifyStagedPackage,
} from "../scripts/stage-release.mjs";

const root = path.resolve(import.meta.dirname, "..");

function comparisonDirectories() {
  const stage = mkdtempSync(path.join(tmpdir(), "pi-release-compare-"));
  const left = path.join(stage, "left");
  const right = path.join(stage, "right");
  mkdirSync(left);
  mkdirSync(right);
  return { left, right };
}

function writeTarball(file, entries) {
  const blocks = [];
  for (const entry of entries) {
    const content = Buffer.from(entry.content ?? "");
    const header = Buffer.alloc(512);
    header.write(entry.name, 0, 100, "utf8");
    header.write(`${(entry.mode ?? 0o644).toString(8).padStart(7, "0")}\0`, 100, 8, "ascii");
    header.write("0000000\0", 108, 8, "ascii");
    header.write("0000000\0", 116, 8, "ascii");
    header.write(`${content.length.toString(8).padStart(11, "0")}\0`, 124, 12, "ascii");
    header.write("00000000000\0", 136, 12, "ascii");
    header.fill(0x20, 148, 156);
    header[156] = (entry.type ?? "0").charCodeAt(0);
    header.write("ustar\0", 257, 6, "ascii");
    header.write("00", 263, 2, "ascii");
    const checksum = header.reduce((sum, byte) => sum + byte, 0);
    header.write(`${checksum.toString(8).padStart(6, "0")}\0 `, 148, 8, "ascii");
    blocks.push(header, content, Buffer.alloc((512 - (content.length % 512)) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  writeFileSync(file, gzipSync(Buffer.concat(blocks)));
}

test("release versions accept stable and supported prereleases", () => {
  for (const version of ["0.1.1", "12.0.0-alpha.0", "0.0.0-beta.8", "1.2.3-rc.10"]) {
    assert.equal(assertReleaseVersion(version), version);
  }
});

test("release versions reject prefixes, injections, and unsupported prereleases", () => {
  for (const version of ["", "v0.1.1", "0.1.1\nnext", "0.1.1;rm -rf /", "0.1", "01.1.1", "1.2.3-preview.1", "1.2.3-beta.01", "1.2.3+build.1"]) {
    assert.throws(() => assertReleaseVersion(version));
  }
});

test("stamping a staged manifest leaves its source manifest untouched", () => {
  const stage = mkdtempSync(path.join(tmpdir(), "pi-release-stamp-"));
  const source = path.join(root, "package.json");
  const staged = path.join(stage, "package.json");
  cpSync(source, staged);
  const original = readFileSync(source, "utf8");
  stampPackage(staged, "0.1.1", "0.0.0-beta.8");
  const manifest = JSON.parse(readFileSync(staged, "utf8"));
  assert.equal(manifest.version, "0.1.1");
  assert.equal(manifest.dependencies["@nodedb-lab/code2graph"], "0.0.0-beta.8");
  assert.equal(readFileSync(source, "utf8"), original);
});

test("stamping rejects an unexpected package or missing core dependency", () => {
  const stage = mkdtempSync(path.join(tmpdir(), "pi-release-stamp-invalid-"));
  const manifest = path.join(stage, "package.json");
  writeFileSync(manifest, '{"name":"wrong","dependencies":{"@nodedb-lab/code2graph":"1.0.0"}}');
  assert.throws(() => stampPackage(manifest, "1.0.0", "1.0.0"), /unexpected Pi package name/);
  writeFileSync(manifest, '{"name":"@nodedb-lab/pi-code2graph","dependencies":{}}');
  assert.throws(() => stampPackage(manifest, "1.0.0", "1.0.0"), /must depend/);
});

test("staged manifest and lockfile require exact names and core resolution", () => {
  const stage = mkdtempSync(path.join(tmpdir(), "pi-release-verify-"));
  const manifestPath = path.join(stage, "package.json");
  const lockPath = path.join(stage, "package-lock.json");
  const manifest = {
    name: "@nodedb-lab/pi-code2graph",
    version: "1.2.3",
    dependencies: { "@nodedb-lab/code2graph": "4.5.6" },
  };
  const lock = {
    name: manifest.name,
    version: manifest.version,
    packages: {
      "": manifest,
      "node_modules/@nodedb-lab/code2graph": { version: "4.5.6" },
    },
  };
  writeFileSync(manifestPath, JSON.stringify(manifest));
  writeFileSync(lockPath, JSON.stringify(lock));
  assert.doesNotThrow(() => verifyStagedPackage(manifestPath, lockPath, "1.2.3", "4.5.6"));
  lock.packages["node_modules/@nodedb-lab/code2graph"].version = "4.5.5";
  writeFileSync(lockPath, JSON.stringify(lock));
  assert.throws(() => verifyStagedPackage(manifestPath, lockPath, "1.2.3", "4.5.6"), /resolve the exact core version/);
  manifest.name = "wrong";
  writeFileSync(manifestPath, JSON.stringify(manifest));
  assert.throws(() => verifyStagedPackage(manifestPath, lockPath, "1.2.3", "4.5.6"), /unexpected Pi package name/);
});

test("normalized artifact comparison accepts equal trees", () => {
  const { left, right } = comparisonDirectories();
  writeFileSync(path.join(left, "package.json"), '{"name":"x"}\n');
  writeFileSync(path.join(right, "package.json"), '{"name":"x"}\n');
  assert.doesNotThrow(() => assertNormalizedArtifactsEqual(left, right));
});

test("normalized artifact comparison detects changed, missing, and extra files", () => {
  const changed = comparisonDirectories();
  writeFileSync(path.join(changed.left, "package.json"), '{"version":"1.0.0"}\n');
  writeFileSync(path.join(changed.right, "package.json"), '{"version":"1.0.1"}\n');
  assert.throws(() => assertNormalizedArtifactsEqual(changed.left, changed.right));

  const missing = comparisonDirectories();
  writeFileSync(path.join(missing.left, "required.js"), "export {};\n");
  assert.throws(() => assertNormalizedArtifactsEqual(missing.left, missing.right));
  assert.throws(() => assertNormalizedArtifactsEqual(missing.right, missing.left));
});

test("tarball comparison normalizes entry order and detects missing files", () => {
  const stage = mkdtempSync(path.join(tmpdir(), "pi-release-tar-compare-"));
  const expected = path.join(stage, "expected.tgz");
  const equal = path.join(stage, "equal.tgz");
  const missing = path.join(stage, "missing.tgz");
  const entries = [
    { name: "package/package.json", content: '{"name":"x"}\n' },
    { name: "package/index.js", content: "export {};\n", mode: 0o755 },
  ];
  writeTarball(expected, entries);
  writeTarball(equal, [...entries].reverse());
  writeTarball(missing, entries.slice(0, 1));
  assert.doesNotThrow(() => compareTarballs(expected, equal));
  assert.throws(() => compareTarballs(expected, missing), /contents differ/);
});

test("tarball reader rejects traversal and links without extracting", () => {
  const stage = mkdtempSync(path.join(tmpdir(), "pi-release-tar-"));
  const traversal = path.join(stage, "traversal.tgz");
  writeTarball(traversal, [{ name: "package/../../outside", content: "bad" }]);
  assert.throws(() => tarballEntries(traversal), /unsafe archive path/);

  const symlink = path.join(stage, "symlink.tgz");
  writeTarball(symlink, [{ name: "package/link", type: "2" }]);
  assert.throws(() => tarballEntries(symlink), /links are not permitted/);
});

test("normalized artifact comparison rejects symlinks and detects mode changes", () => {
  const linked = comparisonDirectories();
  writeFileSync(path.join(linked.left, "target"), "safe\n");
  writeFileSync(path.join(linked.right, "target"), "safe\n");
  symlinkSync("target", path.join(linked.right, "link"));
  assert.throws(() => assertNormalizedArtifactsEqual(linked.left, linked.right), /links are not permitted/);

  const modes = comparisonDirectories();
  writeFileSync(path.join(modes.left, "run.js"), "export {};\n", { mode: 0o644 });
  writeFileSync(path.join(modes.right, "run.js"), "export {};\n", { mode: 0o644 });
  chmodSync(path.join(modes.right, "run.js"), 0o755);
  assert.throws(() => assertNormalizedArtifactsEqual(modes.left, modes.right));
});
