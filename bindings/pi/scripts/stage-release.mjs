// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";
import {
  lstatSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";

export const PACKAGE_NAME = "@nodedb-lab/pi-code2graph";
export const CORE_NAME = "@nodedb-lab/code2graph";
const SEMVER = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)-(?:alpha|beta|rc)\.(?:0|[1-9]\d*)$|^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/;

export function assertReleaseVersion(value, label = "version") {
  if (typeof value !== "string" || /[\r\n]/.test(value) || !SEMVER.test(value)) {
    throw new Error(`${label} must be X.Y.Z or X.Y.Z-(alpha|beta|rc).N`);
  }
  return value;
}

export function stampPackage(packagePath, piVersion, coreVersion) {
  assertReleaseVersion(piVersion, "pi_version");
  assertReleaseVersion(coreVersion, "core_version");
  const manifest = JSON.parse(readFileSync(packagePath, "utf8"));
  assert.equal(manifest.name, PACKAGE_NAME, "unexpected Pi package name");
  assert.ok(manifest.dependencies && typeof manifest.dependencies === "object", "Pi package must have dependencies");
  assert.ok(Object.hasOwn(manifest.dependencies, CORE_NAME), `Pi package must depend on ${CORE_NAME}`);
  manifest.version = piVersion;
  manifest.dependencies[CORE_NAME] = coreVersion;
  writeFileSync(packagePath, `${JSON.stringify(manifest, null, 2)}\n`);
}

export function verifyStagedPackage(packagePath, lockPath, piVersion, coreVersion) {
  assertReleaseVersion(piVersion, "pi_version");
  assertReleaseVersion(coreVersion, "core_version");
  const manifest = JSON.parse(readFileSync(packagePath, "utf8"));
  const lock = JSON.parse(readFileSync(lockPath, "utf8"));
  assert.equal(manifest.name, PACKAGE_NAME, "unexpected Pi package name");
  assert.equal(manifest.version, piVersion, "unexpected Pi package version");
  assert.equal(manifest.dependencies?.[CORE_NAME], coreVersion, "Pi manifest must use the exact core version");
  assert.equal(lock.name, PACKAGE_NAME, "unexpected lockfile package name");
  assert.equal(lock.version, piVersion, "unexpected lockfile package version");
  assert.equal(lock.packages?.[""]?.dependencies?.[CORE_NAME], coreVersion, "lockfile root must use the exact core version");
  assert.equal(lock.packages?.[`node_modules/${CORE_NAME}`]?.version, coreVersion, "lockfile must resolve the exact core version");
}

function contentHash(content) {
  return createHash("sha256").update(content).digest("hex");
}

function safeArchivePath(value) {
  assert.ok(value && !/[\0-\x1f\x7f\\]/.test(value) && !value.startsWith("/"), `unsafe archive path: ${JSON.stringify(value)}`);
  const parts = value.split("/").filter((part, index, all) => part !== "" || index !== all.length - 1);
  assert.ok(parts.length > 0 && parts.every((part) => part !== "" && part !== "." && part !== ".."), `unsafe archive path: ${JSON.stringify(value)}`);
  return parts.join("/");
}

function parseTarNumber(field, label) {
  if (field.length > 0 && (field[0] & 0x80) !== 0) {
    const copy = Buffer.from(field);
    copy[0] &= 0x7f;
    const value = Number(BigInt(`0x${copy.toString("hex") || "0"}`));
    assert.ok(Number.isSafeInteger(value), `${label} is too large`);
    return value;
  }
  const text = field.toString("ascii").replace(/\0.*$/, "").trim();
  assert.match(text || "0", /^[0-7]+$/, `invalid ${label}`);
  return Number.parseInt(text || "0", 8);
}

function tarString(field) {
  const end = field.indexOf(0);
  return field.subarray(0, end === -1 ? field.length : end).toString("utf8");
}

function parsePax(content) {
  const values = new Map();
  let offset = 0;
  while (offset < content.length) {
    const space = content.indexOf(0x20, offset);
    assert.ok(space > offset, "invalid PAX record length");
    const length = Number.parseInt(content.subarray(offset, space).toString("ascii"), 10);
    assert.ok(Number.isSafeInteger(length) && length > 0 && offset + length <= content.length, "invalid PAX record size");
    const record = content.subarray(space + 1, offset + length - 1).toString("utf8");
    assert.equal(content[offset + length - 1], 0x0a, "invalid PAX record terminator");
    const equals = record.indexOf("=");
    assert.ok(equals > 0, "invalid PAX record");
    values.set(record.slice(0, equals), record.slice(equals + 1));
    offset += length;
  }
  return values;
}

export function tarballEntries(tarball) {
  const archive = gunzipSync(readFileSync(tarball));
  const entries = new Map();
  let offset = 0;
  let nextPax;
  while (offset + 512 <= archive.length) {
    const header = archive.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    const storedChecksum = parseTarNumber(header.subarray(148, 156), "tar checksum");
    const checksumHeader = Buffer.from(header);
    checksumHeader.fill(0x20, 148, 156);
    const actualChecksum = checksumHeader.reduce((sum, byte) => sum + byte, 0);
    assert.equal(actualChecksum, storedChecksum, "invalid tar header checksum");
    const size = parseTarNumber(header.subarray(124, 136), "tar entry size");
    const dataStart = offset + 512;
    const dataEnd = dataStart + size;
    assert.ok(dataEnd <= archive.length, "truncated tar entry");
    const content = archive.subarray(dataStart, dataEnd);
    const type = String.fromCharCode(header[156] || 0x30);
    const rawName = tarString(header.subarray(0, 100));
    const prefix = tarString(header.subarray(345, 500));
    const headerName = prefix ? `${prefix}/${rawName}` : rawName;
    if (type === "x") {
      nextPax = parsePax(content);
      for (const key of nextPax.keys()) {
        assert.equal(key, "path", `unsupported PAX attribute: ${key}`);
      }
    } else if (type === "g") {
      throw new Error("global PAX headers are not permitted in npm release tarballs");
    } else {
      const name = safeArchivePath(nextPax?.get("path") ?? headerName);
      nextPax = undefined;
      assert.ok(name === "package" || name.startsWith("package/"), `archive entry is outside package/: ${name}`);
      assert.ok(!entries.has(name), `duplicate archive entry: ${name}`);
      const mode = parseTarNumber(header.subarray(100, 108), "tar entry mode") & 0o7777;
      assert.equal(mode & 0o7000, 0, `privileged mode is not permitted: ${name}`);
      if (type === "0") {
        entries.set(name, { type: "file", mode, hash: contentHash(content), content });
      } else if (type === "5") {
        assert.equal(size, 0, `directory entry has content: ${name}`);
        entries.set(name, { type: "directory", mode, hash: null, content: null });
      } else if (type === "1" || type === "2") {
        throw new Error(`links are not permitted in npm release tarballs: ${name}`);
      } else {
        throw new Error(`unsupported tar entry type ${JSON.stringify(type)}: ${name}`);
      }
    }
    offset = dataStart + Math.ceil(size / 512) * 512;
  }
  assert.ok(entries.size > 0, "tarball is empty");
  return entries;
}

export function normalizedDirectoryEntries(directory) {
  const entries = new Map();
  function visit(current, prefix = "") {
    for (const name of readdirSync(current).sort()) {
      const file = path.join(current, name);
      const relative = path.posix.join(prefix, name);
      const stat = lstatSync(file);
      assert.ok(!stat.isSymbolicLink(), `links are not permitted: ${relative}`);
      const mode = stat.mode & 0o7777;
      assert.equal(mode & 0o7000, 0, `privileged mode is not permitted: ${relative}`);
      if (stat.isDirectory()) {
        entries.set(relative, { type: "directory", mode, hash: null });
        visit(file, relative);
      } else {
        assert.ok(stat.isFile(), `unsupported file type: ${relative}`);
        entries.set(relative, { type: "file", mode, hash: contentHash(readFileSync(file)) });
      }
    }
  }
  visit(directory);
  return entries;
}

function comparableEntries(entries) {
  return [...entries]
    .map(([name, entry]) => [name, { type: entry.type, mode: entry.mode, hash: entry.hash }])
    .sort(([left], [right]) => left.localeCompare(right));
}

export function assertNormalizedArtifactsEqual(expected, actual) {
  assert.deepEqual(comparableEntries(normalizedDirectoryEntries(actual)), comparableEntries(normalizedDirectoryEntries(expected)), "published tarball contents differ from tested tarball");
}

export function inspectTarball(tarball, expectedName, expectedVersion, expectedCoreVersion) {
  const entries = tarballEntries(tarball);
  const packageJson = entries.get("package/package.json");
  assert.equal(packageJson?.type, "file", `${tarball}: missing package.json`);
  const manifest = JSON.parse(packageJson.content.toString("utf8"));
  assert.equal(manifest.name, expectedName, `${tarball}: package name`);
  assert.equal(manifest.version, expectedVersion, `${tarball}: package version`);
  if (expectedCoreVersion !== undefined) {
    assert.equal(manifest.dependencies?.[CORE_NAME], expectedCoreVersion, `${tarball}: exact core dependency`);
  }
}

export function compareTarballs(expectedTarball, actualTarball) {
  assert.deepEqual(comparableEntries(tarballEntries(actualTarball)), comparableEntries(tarballEntries(expectedTarball)), "published tarball contents differ from tested tarball");
}

function usage() {
  throw new Error("usage: stage-release.mjs validate|stamp|verify|inspect|compare ...");
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [command, ...args] = process.argv.slice(2);
  try {
    switch (command) {
      case "validate":
        if (args.length < 1 || args.length > 2) usage();
        assertReleaseVersion(args[0], args[1] || "version");
        break;
      case "stamp":
        if (args.length !== 3) usage();
        stampPackage(...args);
        break;
      case "verify":
        if (args.length !== 4) usage();
        verifyStagedPackage(...args);
        break;
      case "inspect":
        if (args.length < 3 || args.length > 4) usage();
        inspectTarball(...args);
        break;
      case "compare":
        if (args.length !== 2) usage();
        compareTarballs(...args);
        break;
      default:
        usage();
    }
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  }
}
