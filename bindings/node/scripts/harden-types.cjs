// SPDX-License-Identifier: Apache-2.0

const { copyFileSync } = require('node:fs')
const { join } = require('node:path')

copyFileSync(join(__dirname, '..', 'types', 'index.d.ts'), join(__dirname, '..', 'index.d.ts'))
