// SPDX-License-Identifier: Apache-2.0

/**
 * napi-rs regenerates index.js. Apply the package's loader policy after every
 * generation instead of maintaining an untracked hand edit of generated code.
 */
const { readFileSync, writeFileSync } = require('node:fs')
const { resolve } = require('node:path')

const loader = resolve(__dirname, '..', 'index.js')
const source = readFileSync(loader, 'utf8')
const unsafe = `  if (process.env.NAPI_RS_NATIVE_LIBRARY_PATH) {
    try {
      return require(process.env.NAPI_RS_NATIVE_LIBRARY_PATH);
    } catch (err) {
      loadErrors.push(err)
    }
  } else if (process.platform === 'android') {`
const safe = `  // Environment variables must not select executable modules. Keep this
  // restriction after every napi-rs regeneration.
  if (process.platform === 'android') {`

if (source.includes(safe)) process.exit(0)
if (!source.includes(unsafe)) {
  throw new Error('napi-rs loader template changed; review harden-loader.cjs')
}
writeFileSync(loader, source.replace(unsafe, safe))
