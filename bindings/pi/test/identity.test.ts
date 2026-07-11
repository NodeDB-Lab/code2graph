// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import test from "node:test";
import { canonicalId } from "../extensions/code2graph/types.ts";
test("canonical IDs preserve every global and local coordinate",()=>{const a={version:1,scip:"scip x",lang:"Rust"},b={version:1,scip:"scip x",lang:"Python"},c={version:1,scip:"scip x",file:"a.rs"},d={version:1,scip:"scip x",file:"b.rs"};assert.notEqual(canonicalId(a),canonicalId(b));assert.notEqual(canonicalId(c),canonicalId(d));assert.equal(canonicalId(a),canonicalId(JSON.stringify(a)));});
