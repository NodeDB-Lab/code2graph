// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const repo = path.resolve(root, "..", "..");
function run(command, args, cwd) { return execFileSync(command, args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }); }
async function rpcScan(packageDir, fixture, configDir) {
  return await new Promise((resolve, reject) => {
    const child = spawn("pi", ["--mode", "rpc", "--no-session", "--no-extensions", "--approve", "-e", packageDir], { cwd: fixture, env: { ...process.env, PI_CODING_AGENT_DIR: configDir, PI_OFFLINE: "1" }, stdio: ["pipe", "pipe", "pipe"] });
    let output = "", error = ""; const timer = setTimeout(() => { child.kill("SIGKILL"); reject(new Error(`Pi package smoke timed out: ${output}\n${error}`)); }, 20_000);
    child.stdout.on("data", chunk => { output += chunk; if (output.includes('"command":"prompt"') && output.includes('"success":true')) { clearTimeout(timer); child.kill(); resolve(output); } });
    child.stderr.on("data", chunk => { error += chunk; }); child.on("error", reject); child.stdin.write(`${JSON.stringify({ id: "scan", type: "prompt", message: "/code2graph scan ." })}\n`);
  });
}

test("packed package loads through Pi and scans a fixture without consumer tsx", { timeout: 60_000 }, async () => {
  if (!process.env.CODE2GRAPH_CORE_TARBALL && !existsSync(path.join(repo, "bindings", "node", "code2graph-node.linux-x64-gnu.node"))) return test.skip("native addon is built by CI before this smoke");
  const stage = await mkdtemp(path.join(tmpdir(), "pi-code2graph-pack-"));
  try {
    const coreDir = path.join(stage, "core"), packageDir = path.join(stage, "package"), fixture = path.join(stage, "fixture"), config = path.join(stage, "pi-config");
    await mkdir(coreDir, { recursive: true }); await mkdir(packageDir, { recursive: true }); await mkdir(fixture, { recursive: true }); await mkdir(config, { recursive: true });
    const suppliedCore = process.env.CODE2GRAPH_CORE_TARBALL;
    if (suppliedCore) { await writeFile(path.join(coreDir, "core-path"), suppliedCore); } else run("npm", ["pack", "--pack-destination", coreDir], path.join(repo, "bindings", "node"));
    const suppliedPackage = process.env.CODE2GRAPH_PI_TARBALL;
    if (!suppliedPackage) run("npm", ["pack", "--pack-destination", stage], root);
    const tarball = suppliedPackage || path.join(stage, run("node", ["-e", "const fs=require('fs');console.log(fs.readdirSync('.').find(x=>x.startsWith('nodedb-lab-pi-code2graph-')&&x.endsWith('.tgz')))"], stage).trim());
    run("tar", ["-xzf", tarball, "-C", packageDir, "--strip-components=1"], stage);
    const core = suppliedCore || path.join(coreDir, run("node", ["-e", "const fs=require('fs');console.log(fs.readdirSync('.').find(x=>x.endsWith('.tgz')))"], coreDir).trim());
    const platform = process.env.CODE2GRAPH_CORE_PLATFORM_TARBALL;
    const packages = platform ? [core, platform] : [core];
    run("npm", ["install", "--omit=dev", "--package-lock=false", ...packages], packageDir);
    await writeFile(path.join(fixture, "tiny.rs"), "pub fn answer() -> u32 { 42 }\n");
    const output = await rpcScan(packageDir, fixture, config);
    assert.match(output, /"success":true/);
  } finally { await rm(stage, { recursive: true, force: true }); }
});
