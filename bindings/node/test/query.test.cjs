// SPDX-License-Identifier: Apache-2.0

const assert = require('node:assert/strict')
const { GraphIndex } = require('..')

const globalId = (lang, name) => ({
  version: 1,
  scip: `codegraph . . . ${name}.`,
  lang,
})

const localId = (file, id) => ({ version: 1, scip: `local ${id}`, file })

const symbol = (id, name, file) => ({
  id,
  name,
  kind: 'Function',
  visibility: 'Public',
  entry_points: [],
  file,
  line: 1,
  span: { start: 0, end: 1 },
  signature: `fn ${name}()`,
})

const edge = (from, to, byte, role = 'Call', confidence = 'Exact', provenance = 'ScopeGraph') => ({
  from,
  to,
  role,
  confidence,
  provenance,
  occ: { file: 'src/calls.rs', line: 1, col: byte, byte },
})

function fixture(reverseEdges = false) {
  const rustShared = globalId('rust', 'shared')
  const pythonShared = globalId('python', 'shared')
  const endpoint = localId('vendor/a.rs', 'remote')
  const sameDisplayEndpoint = localId('vendor/b.rs', 'remote')
  const callerA = globalId('rust', 'caller_a')
  const callerB = globalId('rust', 'caller_b')
  const callerC = globalId('rust', 'caller_c')
  const ignored = globalId('rust', 'ignored')
  const weak = globalId('rust', 'weak')
  const edges = [
    edge(callerA, endpoint, 10),
    edge(callerC, endpoint, 20),
    edge(callerB, callerA, 30),
    edge(callerA, callerB, 40),
    edge(ignored, endpoint, 50, 'Import'),
    edge(weak, endpoint, 60, 'Call', 'NameOnly', 'SymbolTable'),
    edge(endpoint, sameDisplayEndpoint, 70),
  ]
  return {
    ids: { rustShared, pythonShared, endpoint, sameDisplayEndpoint, callerA, callerB, callerC },
    graph: {
      symbols: [
        symbol(rustShared, 'shared', 'src/shared.rs'),
        symbol(pythonShared, 'shared', 'src/shared.py'),
      ],
      edges: reverseEdges ? [...edges].reverse() : edges,
    },
  }
}

{
  const { ids, graph } = fixture()
  const index = new GraphIndex(graph)

  assert.deepEqual(index.symbol(ids.rustShared).id, ids.rustShared)
  assert.deepEqual(index.symbol(ids.pythonShared).id, ids.pythonShared)
  assert.equal(index.symbol(globalId('go', 'shared')), null, 'a matching SCIP display is not identity')
  assert.equal(index.symbol(ids.endpoint), null, 'endpoint-only IDs are not definitions')
  assert.deepEqual(index.symbolsNamed('shared').map((item) => item.id), [ids.pythonShared, ids.rustShared])
  assert.deepEqual(index.idsWithScip(ids.rustShared.scip), [ids.pythonShared, ids.rustShared])
  assert.deepEqual(index.idsWithScip(ids.endpoint.scip), [ids.endpoint, ids.sameDisplayEndpoint])

  assert.deepEqual(index.incoming(ids.endpoint, 10).map((item) => item.from), [
    ids.callerA,
    ids.callerC,
    globalId('rust', 'ignored'),
    globalId('rust', 'weak'),
  ])
  assert.deepEqual(index.outgoing(ids.endpoint, 10).map((item) => item.to), [ids.sameDisplayEndpoint])
  assert.deepEqual(
    index.incoming(ids.endpoint, 10, 'Call', 'Exact', 'ScopeGraph').map((item) => item.from),
    [ids.callerA, ids.callerC],
  )
  assert.deepEqual(
    index.incoming(ids.endpoint, 10, 'Import', 'Exact', 'ScopeGraph').map((item) => item.from),
    [globalId('rust', 'ignored')],
  )

  const fullImpact = index.impact(ids.endpoint, 10, 10, 'Call', 'Exact', 'ScopeGraph')
  assert.equal(fullImpact.truncated, false)
  assert.equal(Object.prototype.hasOwnProperty.call(fullImpact, 'visited'), false)
  assert.deepEqual(fullImpact.steps.map((step) => [step.symbol, step.depth]), [
    [ids.callerA, 1],
    [ids.callerC, 1],
    [ids.callerB, 2],
  ])
  assert.deepEqual(fullImpact.steps[2].parent, ids.callerA)

  const depthBound = index.impact(ids.endpoint, 1, 10, 'Call', 'Exact', 'ScopeGraph')
  assert.equal(depthBound.truncated, true)
  assert.deepEqual(depthBound.steps.map((step) => step.symbol), [ids.callerA, ids.callerC])

  const nodeBound = index.impact(ids.endpoint, 10, 1, 'Call', 'Exact', 'ScopeGraph')
  assert.equal(nodeBound.truncated, true)
  assert.deepEqual(nodeBound.steps.map((step) => step.symbol), [ids.callerA])

  assert.throws(
    () => new GraphIndex({ symbols: [{ id: ids.rustShared.scip }], edges: [] }),
    /graph symbols.id must be a lossless SymbolId serde object/,
  )
  assert.throws(() => index.symbol(ids.rustShared.scip), /lossless SymbolId serde object/)
  assert.throws(() => index.incoming({ version: 1, scip: ids.rustShared.scip }, 1), /SymbolId wire requires lang/)
  assert.throws(() => index.incoming(ids.endpoint, 0), /limit must be a positive u32/)
  assert.throws(() => index.impact(ids.endpoint, 1, 0), /limit must be a positive u32/)
  assert.throws(() => index.incoming(ids.endpoint, 1, 'call'), /invalid role/)
  assert.throws(() => index.incoming(ids.endpoint, 1, undefined, 'exact'), /invalid min_confidence/)
  assert.throws(() => index.incoming(ids.endpoint, 1, undefined, undefined, 'scope_graph'), /invalid provenance/)
}

{
  const first = fixture(false)
  const second = fixture(true)
  const left = new GraphIndex(first.graph)
  const right = new GraphIndex(second.graph)
  assert.deepEqual(
    left.incoming(first.ids.endpoint, 10, 'Call', 'Exact', 'ScopeGraph'),
    right.incoming(second.ids.endpoint, 10, 'Call', 'Exact', 'ScopeGraph'),
  )
  assert.deepEqual(
    left.impact(first.ids.endpoint, 10, 10, 'Call', 'Exact', 'ScopeGraph'),
    right.impact(second.ids.endpoint, 10, 10, 'Call', 'Exact', 'ScopeGraph'),
  )
}
