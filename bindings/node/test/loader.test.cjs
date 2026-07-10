// SPDX-License-Identifier: Apache-2.0

const assert = require('node:assert/strict')
const { mkdtempSync, readFileSync, rmSync, writeFileSync } = require('node:fs')
const { tmpdir } = require('node:os')
const { join } = require('node:path')
const { spawnSync } = require('node:child_process')

const directory = mkdtempSync(join(tmpdir(), 'code2graph-loader-'))
const marker = join(directory, 'executed')
const payload = join(directory, 'payload.cjs')
writeFileSync(payload, `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'executed')`)

try {
  const result = spawnSync(process.execPath, ['-e', "require('./index.js')"], {
    cwd: join(__dirname, '..'),
    env: { ...process.env, NAPI_RS_NATIVE_LIBRARY_PATH: payload },
  })
  assert.equal(result.status, 0, result.stderr.toString())
  let executed = false
  try {
    readFileSync(marker)
    executed = true
  } catch (error) {
    if (error.code !== 'ENOENT') throw error
  }
  assert.equal(executed, false, 'environment-selected code must not execute')
} finally {
  rmSync(directory, { recursive: true, force: true })
}
