/* eslint-disable @typescript-eslint/explicit-function-return-type */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'

const read = (path) => readFileSync(new URL(`../../${path}`, import.meta.url), 'utf8')

test('default endpoint fallback includes AmazonQ CLI after IDE endpoints', () => {
  const source = read('src/main/proxy/kiroApi.ts')
  const start = source.indexOf('function getSortedEndpoints')
  const end = source.indexOf('function getAbortError', start)
  const body = source.slice(start, end)

  assert.notEqual(start, -1)
  assert.notEqual(end, -1)
  assert.match(body, /if \(!preferredEndpoint\) return KIRO_ENDPOINTS/)
  assert.doesNotMatch(body, /if \(!preferredEndpoint\) return KIRO_ENDPOINTS\.filter\(ep => ep\.name !== 'AmazonQCLI'\)/)
})

test('endpoint failures are persisted with error messages', () => {
  const source = read('src/main/proxy/kiroApi.ts')

  assert.match(source, /function formatEndpointError/)
  assert.match(source, /console\.error\(`\[KiroAPI\] Endpoint \$\{endpoint\.name\} failed:`[\s\S]*formatEndpointError\(error\)/)
})

test('request log export includes error text for failed rows', () => {
  const source = read('src/renderer/src/components/proxy/ProxyLogsDialog.tsx')
  const start = source.indexOf('const handleExport = () =>')
  const end = source.indexOf('const successCount', start)
  const body = source.slice(start, end)

  assert.notEqual(start, -1)
  assert.notEqual(end, -1)
  assert.match(body, /log\.error/)
})
