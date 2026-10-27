import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  applyBackgroundAccountUpdate,
  preserveNewerAccountCredentials
} from '../src/shared/accountCredentials.ts'
import { isUsageSyncDue, selectionChanged } from '../src/shared/usageSync.ts'
import { readFileSync } from 'node:fs'
import ts from 'typescript'

test('official usage survives a stale renderer save and serialized restart', () => {
  const account = {
    nickname: 'Before',
    credentials: { accessToken: 'access', refreshToken: 'refresh', expiresAt: 9000 },
    usage: { current: 100, limit: 5000, lastUpdated: 100 },
    subscription: { title: 'Pro Max' }
  }
  const updated = applyBackgroundAccountUpdate(
    account,
    {
      id: 'a',
      usage: { current: 3500, limit: 5000 },
      status: 'active'
    },
    200
  )
  const saved = { accounts: { a: updated } }
  const stale = { accounts: { a: { ...account, nickname: 'User edit' } } }
  const restarted = JSON.parse(JSON.stringify(preserveNewerAccountCredentials(stale, saved)))
  assert.equal(restarted.accounts.a.usage.current, 3500)
  assert.equal(restarted.accounts.a.usage.percentUsed, 0.7)
  assert.equal(restarted.accounts.a.nickname, 'User edit')
  assert.equal(restarted.accounts.a.credentials.accessToken, 'access')
  assert.deepEqual(preserveNewerAccountCredentials({ accounts: {} }, saved).accounts, {})
})

test('monthly reset can decrease usage while an older snapshot cannot roll it back', () => {
  const account = { usage: { current: 5000, limit: 5000, lastUpdated: 100 } }
  const reset = applyBackgroundAccountUpdate(
    account,
    { id: 'a', usage: { current: 0, limit: 5000 } },
    200
  )
  assert.equal(reset.usage.current, 0)
  assert.equal(reset.usage.percentUsed, 0)
  assert.equal(
    preserveNewerAccountCredentials({ accounts: { a: account } }, { accounts: { a: reset } })
      .accounts.a.usage?.current,
    0
  )
})

test('usage-only and token-only results preserve unrelated state', () => {
  const account = {
    credentials: { accessToken: 'old', refreshToken: 'keep', expiresAt: 10 },
    usage: { current: 42, limit: 1000, lastUpdated: 5 },
    subscription: { title: 'Student' }
  }
  const updated = applyBackgroundAccountUpdate(
    account,
    { id: 'a', accessToken: 'new', expiresIn: 3600 },
    100
  )
  assert.equal(updated.credentials.refreshToken, 'keep')
  assert.equal(updated.credentials.expiresAt, 3600100)
  assert.deepEqual(updated.usage, account.usage)
  assert.deepEqual(updated.subscription, account.subscription)
})

test('main usage polling respects switches, interval and renderer completion deadline', () => {
  const settings = { autoRefreshEnabled: true, autoRefreshSyncInfo: true, autoRefreshInterval: 5 }
  assert.equal(isUsageSyncDue(settings, 1000, 300999), false)
  assert.equal(isUsageSyncDue(settings, 1000, 301000), true)
  assert.equal(isUsageSyncDue(settings, 301000, 301001), false)
  assert.equal(isUsageSyncDue({ ...settings, autoRefreshEnabled: false }, 0, 999999), false)
  assert.equal(isUsageSyncDue({ ...settings, autoRefreshSyncInfo: false }, 0, 999999), false)
})

test('production background handler persists without a renderer and ignores deleted accounts', () => {
  const source = readFileSync(new URL('../src/main/index.ts', import.meta.url), 'utf8')
  const ast = ts.createSourceFile('main.ts', source, ts.ScriptTarget.Latest, true)
  const handler = ast.statements.find(
    (node) => ts.isFunctionDeclaration(node) && node.name?.text === 'publishBackgroundRefreshResult'
  )
  assert.ok(handler)
  const compiled = ts.transpileModule(handler.getText(ast), {
    compilerOptions: { target: ts.ScriptTarget.ES2022 }
  }).outputText
  let disk = { accounts: { a: { usage: { current: 1, limit: 5000 } } } }
  const runtime = new Function(
    'store',
    'mainWindow',
    'applyBackgroundAccountUpdate',
    'let lastSavedData;\n' +
      compiled +
      '\nreturn { publishBackgroundRefreshResult, snapshot: () => lastSavedData }'
  )(
    {
      get: () => disk,
      set: (_key: string, value: typeof disk) => {
        disk = value
      }
    },
    undefined,
    applyBackgroundAccountUpdate
  )
  runtime.publishBackgroundRefreshResult({
    id: 'a',
    success: true,
    data: { usage: { current: 3500, limit: 5000 } }
  })
  assert.equal(disk.accounts.a.usage.current, 3500)
  assert.deepEqual(runtime.snapshot(), disk)
  runtime.publishBackgroundRefreshResult({
    id: 'deleted',
    success: true,
    data: { accessToken: 'unused' }
  })
  assert.deepEqual(Object.keys(disk.accounts), ['a'])
  runtime.publishBackgroundRefreshResult({ id: 'a', success: false, error: 'network failure' })
  assert.equal(disk.accounts.a.usage.current, 3500)
})

test('real proxy quota failover selects the next account and emits the new selection', async () => {
  // Exercise the production selection method without starting sockets or loading native clients.
  const source = readFileSync(new URL('../src/main/proxy/proxyServer.ts', import.meta.url), 'utf8')
  const start = source.indexOf('  private async getAvailableAccount(')
  assert.ok(start >= 0)
  const bodyStart = source.indexOf('{', start)
  let depth = 1,
    end = bodyStart + 1
  for (; depth && end < source.length; end++) {
    if (source[end] === '{') depth++
    if (source[end] === '}') depth--
  }
  const method = source
    .slice(start, end)
    .replace('  private async getAvailableAccount', 'async function select')
  const compiled = ts.transpileModule(method, {
    compilerOptions: { target: ts.ScriptTarget.ES2022 }
  }).outputText
  const select = new Function(compiled + '\nreturn select')()
  const old = { id: 'old' },
    next = { id: 'next' }
  const disk = { selectedAccountIds: ['old'], port: 8992 }
  const context = {
    config: {
      enableMultiAccount: false,
      selectedAccountIds: ['old'],
      autoSwitchOnQuotaExhausted: true
    },
    accountPool: {
      getAccount: () => old,
      isQuotaExhausted: () => true,
      getNextAvailableAccount: () => next
    },
    syncKProxyDeviceId: () => {},
    isTokenExpiringSoon: () => false,
    getAllowedAccountIds: () => null,
    throwIfAborted: () => {},
    events: { onAccountUpdate: (account: unknown) => account }
  }
  const mainSource = readFileSync(new URL('../src/main/index.ts', import.meta.url), 'utf8')
  const ast = ts.createSourceFile('main.ts', mainSource, ts.ScriptTarget.Latest, true)
  let callback: ts.Expression | undefined
  function find(node: ts.Node): void {
    if (!callback && ts.isPropertyAssignment(node) && node.name.getText(ast) === 'onAccountUpdate')
      callback = node.initializer
    ts.forEachChild(node, find)
  }
  find(ast)
  assert.ok(callback)
  const callbackJs = ts.transpileModule('const handle = ' + callback.getText(ast), {
    compilerOptions: { target: ts.ScriptTarget.ES2022 }
  }).outputText
  context.events.onAccountUpdate = new Function(
    'proxyServer',
    'store',
    'persistAccountCredentialUpdate',
    'mainWindow',
    'selectionChanged',
    callbackJs + '\nreturn handle'
  )(
    { getConfig: () => context.config },
    { get: () => disk, set: (_key: string, value: typeof disk) => Object.assign(disk, value) },
    () => {},
    undefined,
    selectionChanged
  )
  assert.equal(await select.call(context), next)
  assert.deepEqual(JSON.parse(JSON.stringify(disk)), { selectedAccountIds: ['next'], port: 8992 })
  context.events.onAccountUpdate(old) // An unrelated token refresh must not switch back.
  assert.deepEqual(disk.selectedAccountIds, ['next'])
})
