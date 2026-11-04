/**
 * kiro-cli auth_kv 写入层单元测试
 *
 * 运行方式（node v26 原生 TS type-stripping，不需要先编译）：
 *   cd Kiro-account-manager
 *   node --disable-warning=MODULE_TYPELESS_PACKAGE_JSON --test test/cli-switch/*.test.ts
 *
 * 覆盖点（对应上游 issue #125 与 “切号目标对 CLI 不生效”）：
 *   - macOS/Windows/Linux 的 kiro-cli data.sqlite3 路径
 *   - social / IdC 判定（大小写、authMethod 兜底）
 *   - IdC token / device-registration / social token 的必填字段
 *   - start_url 从 clientSecret JWT 的 initiateLoginUri 推导
 *   - client_secret_expires_at 从 JWT expirationTimestamp 推导
 *   - 写入 auth_kv 的竞争 key 清理与 round-trip
 */

import assert from 'node:assert/strict'
import * as fs from 'node:fs/promises'
import * as os from 'node:os'
import * as path from 'node:path'
import { test } from 'node:test'

import {
  applyKiroCliAuth,
  buildKiroCliAuthRecords,
  clientSecretExpiresAtFromClientSecret,
  KIRO_CLI_DEVICE_REGISTRATION_KEY,
  KIRO_CLI_IDC_TOKEN_KEY,
  KIRO_CLI_SCOPES,
  KIRO_CLI_SOCIAL_TOKEN_KEY,
  KIRO_DEFAULT_START_URL,
  normalizeStartUrl,
  resolveCliStartUrl,
  resolveKiroCliAuthMethod,
  resolveKiroCliPaths,
  shouldSyncTrackedKiroCliAuth,
  startUrlFromClientSecret,
  writeKiroCliAuthRecords
} from '../../src/main/kiroCliAuth.ts'

const HOME = '/Users/testuser'

function base64url(value: string): string {
  return Buffer.from(value, 'utf-8').toString('base64url')
}

/** 造一个 shape 与 AWS SSO OIDC client secret 相同的假 JWT（不含真实凭证） */
function fakeClientSecret(serialized: Record<string, unknown>): string {
  const header = base64url(JSON.stringify({ alg: 'none', typ: 'JWT' }))
  const payload = base64url(JSON.stringify({ serialized: JSON.stringify(serialized) }))
  return `${header}.${payload}.signature`
}

const IDC_CLIENT_SECRET = fakeClientSecret({
  initiateLoginUri: 'https://d-example123.awsapps.com/start/',
  expirationTimestamp: 1794717438.0378888
})

function idcInput(overrides: Record<string, unknown> = {}): Parameters<typeof buildKiroCliAuthRecords>[0] {
  return {
    accessToken: 'access-token',
    refreshToken: 'refresh-token',
    expiresAtIso: '2026-11-04T03:00:00.000Z',
    region: 'us-east-1',
    provider: 'Enterprise',
    authMethod: 'IdC',
    clientId: 'client-id',
    clientSecret: IDC_CLIENT_SECRET,
    ...overrides
  }
}

// ============ 路径解析 ============

test('macOS: kiro-cli 数据库在 ~/Library/Application Support/kiro-cli', () => {
  const paths = resolveKiroCliPaths({ platform: 'darwin', home: HOME })
  assert.equal(paths.dataDir, path.join(HOME, 'Library', 'Application Support', 'kiro-cli'))
  assert.equal(paths.dbPath, path.join(HOME, 'Library', 'Application Support', 'kiro-cli', 'data.sqlite3'))
  // 旧的错误路径仅用于提示，不用于写入
  assert.equal(paths.legacyDbPath, path.join(HOME, '.local', 'share', 'kiro-cli', 'data.sqlite3'))
})

test('Linux: 优先 XDG_DATA_HOME，缺省 ~/.local/share', () => {
  const withXdg = resolveKiroCliPaths({
    platform: 'linux',
    home: HOME,
    env: { XDG_DATA_HOME: '/tmp/xdg-data' }
  })
  assert.equal(withXdg.dbPath, path.join('/tmp/xdg-data', 'kiro-cli', 'data.sqlite3'))

  const fallback = resolveKiroCliPaths({ platform: 'linux', home: HOME, env: {} })
  assert.equal(fallback.dbPath, path.join(HOME, '.local', 'share', 'kiro-cli', 'data.sqlite3'))
})

test('Windows: 使用 %LOCALAPPDATA%/kiro-cli', () => {
  const paths = resolveKiroCliPaths({
    platform: 'win32',
    home: HOME,
    env: { LOCALAPPDATA: '/tmp/LocalAppData' }
  })
  assert.equal(paths.dbPath, path.join('/tmp/LocalAppData', 'kiro-cli', 'data.sqlite3'))

  const fallback = resolveKiroCliPaths({ platform: 'win32', home: HOME, env: {} })
  assert.equal(
    fallback.dbPath,
    path.join(HOME, 'AppData', 'Local', 'kiro-cli', 'data.sqlite3')
  )
})

// ============ social / IdC 判定 ============

test('IdC 账号判定（BuilderId / Enterprise）', () => {
  assert.equal(resolveKiroCliAuthMethod({ provider: 'BuilderId', authMethod: 'IdC' }).isSocial, false)
  assert.equal(resolveKiroCliAuthMethod({ provider: 'Enterprise', authMethod: 'IdC' }).isSocial, false)
})

test('social 判定不区分大小写，并归一化为 CLI 序列化用的小写 provider', () => {
  assert.deepEqual(resolveKiroCliAuthMethod({ provider: 'google' }), {
    isSocial: true,
    providerForCli: 'google',
    oauthFlow: 'Pkce'
  })
  assert.equal(resolveKiroCliAuthMethod({ provider: 'GitHub' }).providerForCli, 'github')
  assert.equal(resolveKiroCliAuthMethod({ provider: 'Github' }).providerForCli, 'github')
  // 只有 authMethod、没有 provider 的导入路径也要识别为 social
  assert.equal(resolveKiroCliAuthMethod({ authMethod: 'social' }).isSocial, true)
})

// ============ start_url / client_secret 过期时间推导 ============

test('start_url 从 clientSecret JWT 的 initiateLoginUri 推导并去掉末尾 /', () => {
  assert.equal(startUrlFromClientSecret(IDC_CLIENT_SECRET), 'https://d-example123.awsapps.com/start')
  assert.equal(startUrlFromClientSecret('not-a-jwt'), undefined)
  assert.equal(startUrlFromClientSecret(undefined), undefined)
  assert.equal(normalizeStartUrl('https://view.awsapps.com/start///'), 'https://view.awsapps.com/start')
})

test('start_url 优先级：显式传入 > clientSecret 推导 > BuilderId 默认', () => {
  assert.equal(
    resolveCliStartUrl({ startUrl: 'https://custom.awsapps.com/start', clientSecret: IDC_CLIENT_SECRET }),
    'https://custom.awsapps.com/start'
  )
  assert.equal(
    resolveCliStartUrl({ clientSecret: IDC_CLIENT_SECRET }),
    'https://d-example123.awsapps.com/start'
  )
  assert.equal(resolveCliStartUrl({}), KIRO_DEFAULT_START_URL)
})

test('client_secret_expires_at 从 clientSecret JWT 的 expirationTimestamp 推导（秒级 Z 格式）', () => {
  const expected = new Date(1794717438.0378888 * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z')
  assert.equal(clientSecretExpiresAtFromClientSecret(IDC_CLIENT_SECRET), expected)
  assert.equal(clientSecretExpiresAtFromClientSecret('not-a-jwt'), undefined)
})

// ============ IdC 记录字段 ============

test('IdC token 记录包含 kiro-cli 必填字段（issue #125: oauth_flow 缺失会直接退出）', () => {
  const records = buildKiroCliAuthRecords(idcInput())
  assert.equal(records.tokenKey, KIRO_CLI_IDC_TOKEN_KEY)
  assert.equal(records.isSocial, false)
  const token = JSON.parse(records.tokenValue) as Record<string, unknown>

  assert.equal(token.access_token, 'access-token')
  assert.equal(token.refresh_token, 'refresh-token')
  assert.equal(token.expires_at, '2026-11-04T03:00:00.000Z')
  assert.equal(token.region, 'us-east-1')
  assert.equal(token.oauth_flow, 'Pkce')
  assert.equal(token.start_url, 'https://d-example123.awsapps.com/start')
  assert.deepEqual(token.scopes, KIRO_CLI_SCOPES)
  // 真实 kiro-cli IdC 记录不含 profile_arn；占位符 ARN 会触发 403，必须省略
  assert.equal('profile_arn' in token, false)

  // 不写 telemetry_generation（CLI 自愈；缺失不会触发 missing field）
  assert.equal('telemetry_generation' in token, false)
})

test('IdC device-registration 记录包含全部必填字段', () => {
  const records = buildKiroCliAuthRecords(idcInput())
  assert.equal(records.registrationKey, KIRO_CLI_DEVICE_REGISTRATION_KEY)
  const registration = JSON.parse(records.registrationValue as string) as Record<string, unknown>

  assert.equal(registration.client_id, 'client-id')
  assert.equal(registration.client_secret, IDC_CLIENT_SECRET)
  assert.equal(registration.region, 'us-east-1')
  assert.equal(registration.oauth_flow, 'Pkce')
  assert.deepEqual(registration.scopes, KIRO_CLI_SCOPES)
  const expectedExpiry = new Date(1794717438.0378888 * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z')
  assert.equal(registration.client_secret_expires_at, expectedExpiry)
  assert.equal(records.removeRegistration, false)
})

test('IdC 缺少 clientId/clientSecret 时只写 token，不写 registration', () => {
  const records = buildKiroCliAuthRecords(idcInput({ clientId: undefined, clientSecret: undefined }))
  assert.equal(records.registrationKey, undefined)
  assert.equal('client_id' in (JSON.parse(records.tokenValue) as Record<string, unknown>), false)
  // 没有 clientSecret 时 start_url 回落到 BuilderId 默认值
  assert.equal(
    (JSON.parse(records.tokenValue) as Record<string, unknown>).start_url,
    KIRO_DEFAULT_START_URL
  )
})

test('竞争 key 清理：删除 social / codewhisperer / external-idp，保留当前 key', () => {
  const idc = buildKiroCliAuthRecords(idcInput())
  assert.ok(idc.staleKeys.includes(KIRO_CLI_SOCIAL_TOKEN_KEY))
  assert.ok(idc.staleKeys.includes('codewhisperer:odic:token'))
  assert.ok(idc.staleKeys.includes('kirocli:external-idp:token'))
  assert.ok(!idc.staleKeys.includes(KIRO_CLI_IDC_TOKEN_KEY))

  const social = buildKiroCliAuthRecords(
    idcInput({ provider: 'google', authMethod: 'social', profileArn: 'arn:aws:codewhisperer:us-east-1:1:profile/X' })
  )
  assert.ok(social.staleKeys.includes(KIRO_CLI_IDC_TOKEN_KEY))
  assert.ok(!social.staleKeys.includes(KIRO_CLI_SOCIAL_TOKEN_KEY))
  assert.equal(social.removeRegistration, true)
})

// ============ App 主动 refresh 时的 CLI 同步判定 ============

test('只有目标含 cli 且刷新账号 == 最近切到 CLI 的账号时才同步 kiro-cli', () => {
  assert.equal(
    shouldSyncTrackedKiroCliAuth({ switchTarget: 'both', trackedAccountId: 'acc-1', accountId: 'acc-1' }),
    true
  )
  assert.equal(
    shouldSyncTrackedKiroCliAuth({ switchTarget: 'cli', trackedAccountId: 'acc-1', accountId: 'acc-1' }),
    true
  )
  // 目标不含 CLI 时不动 CLI 数据库
  assert.equal(
    shouldSyncTrackedKiroCliAuth({ switchTarget: 'ide', trackedAccountId: 'acc-1', accountId: 'acc-1' }),
    false
  )
  assert.equal(
    shouldSyncTrackedKiroCliAuth({ switchTarget: undefined, trackedAccountId: 'acc-1', accountId: 'acc-1' }),
    false
  )
  // 刷新的是其它账号时不动 CLI
  assert.equal(
    shouldSyncTrackedKiroCliAuth({ switchTarget: 'both', trackedAccountId: 'acc-1', accountId: 'acc-2' }),
    false
  )
  // 还没有成功切过 CLI
  assert.equal(
    shouldSyncTrackedKiroCliAuth({ switchTarget: 'both', trackedAccountId: null, accountId: 'acc-1' }),
    false
  )
  assert.equal(
    shouldSyncTrackedKiroCliAuth({ switchTarget: 'both', trackedAccountId: 'acc-1', accountId: undefined }),
    false
  )
})

// ============ social 记录字段 ============

test('social token 记录包含 provider / profile_arn，并清除 IdC registration', () => {
  const records = buildKiroCliAuthRecords(
    idcInput({
      provider: 'google',
      authMethod: 'social',
      profileArn: 'arn:aws:codewhisperer:us-east-1:699475941385:profile/EHGA3GRVQMUK'
    })
  )
  assert.equal(records.tokenKey, KIRO_CLI_SOCIAL_TOKEN_KEY)
  const token = JSON.parse(records.tokenValue) as Record<string, unknown>
  assert.equal(token.provider, 'google')
  assert.equal(token.profile_arn, 'arn:aws:codewhisperer:us-east-1:699475941385:profile/EHGA3GRVQMUK')
  assert.equal(token.access_token, 'access-token')
  assert.equal(token.refresh_token, 'refresh-token')
  assert.equal(records.removeRegistration, true)
})

test('social 缺少 profileArn 时报错（CLI 会把无 profile ARN 的 social token 视为无效）', () => {
  assert.throws(
    () => buildKiroCliAuthRecords(idcInput({ provider: 'Github', authMethod: 'social', profileArn: undefined })),
    /profileArn/
  )
})

// ============ SQLite 写入 ============

async function withTempDir(fn: (dir: string) => Promise<void>): Promise<void> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'kiro-cli-auth-test-'))
  try {
    await fn(dir)
  } finally {
    await fs.rm(dir, { recursive: true, force: true })
  }
}

async function readAuthKv(dbPath: string): Promise<Map<string, string>> {
  const { DatabaseSync } = await import('node:sqlite')
  const db = new DatabaseSync(dbPath)
  try {
    const rows = db.prepare('SELECT key, value FROM auth_kv').all() as Array<{ key: string; value: string }>
    return new Map(rows.map((row) => [row.key, row.value]))
  } finally {
    db.close()
  }
}

test('写入 auth_kv：upsert 记录并删除竞争 key', async () => {
  await withTempDir(async (dir) => {
    const dbPath = path.join(dir, 'data.sqlite3')
    // 预置旧账号的竞争 key
    await writeKiroCliAuthRecords(dbPath, {
      isSocial: false,
      providerForCli: 'BuilderId',
      tokenKey: KIRO_CLI_SOCIAL_TOKEN_KEY,
      tokenValue: JSON.stringify({ access_token: 'old-social' }),
      staleKeys: [],
      removeRegistration: false
    })

    const records = buildKiroCliAuthRecords(idcInput())
    await writeKiroCliAuthRecords(dbPath, records)

    const rows = await readAuthKv(dbPath)
    assert.equal(rows.get(KIRO_CLI_IDC_TOKEN_KEY), records.tokenValue)
    assert.equal(rows.get(KIRO_CLI_DEVICE_REGISTRATION_KEY), records.registrationValue)
    assert.equal(rows.has(KIRO_CLI_SOCIAL_TOKEN_KEY), false)
    const token = JSON.parse(rows.get(KIRO_CLI_IDC_TOKEN_KEY) as string) as Record<string, unknown>
    assert.equal(token.oauth_flow, 'Pkce')
  })
})

test('applyKiroCliAuth: kiro-cli 未初始化时给出可读错误，而不是静默写坏路径', async () => {
  await withTempDir(async (dir) => {
    const records = buildKiroCliAuthRecords(idcInput())
    await assert.rejects(
      () => applyKiroCliAuth(records, { platform: 'darwin', home: dir }),
      /未找到 Kiro CLI 数据库.*kiro-cli login/
    )
  })
})

test('applyKiroCliAuth: 显式 dbPath 时允许创建并写入（测试/迁移场景）', async () => {
  await withTempDir(async (dir) => {
    const dbPath = path.join(dir, 'nested', 'data.sqlite3')
    const records = buildKiroCliAuthRecords(idcInput())
    const result = await applyKiroCliAuth(records, { dbPath })
    assert.equal(result.dbPath, dbPath)
    const rows = await readAuthKv(dbPath)
    assert.ok(rows.has(KIRO_CLI_IDC_TOKEN_KEY))
  })
})
