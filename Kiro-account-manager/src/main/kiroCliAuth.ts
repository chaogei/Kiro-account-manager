// Kiro CLI 凭证写入层
//
// Kiro CLI (>= 2.x) 把登录凭证存到 data.sqlite3 的 auth_kv 表（不是 IDE 的
// ~/.aws/sso/cache/kiro-auth-token.json），而且对 JSON schema 有严格要求：
// 缺字段时 CLI 会直接报 `missing field ...` 并退出（见上游 issue #125）。
//
// 本模块与 main/index.ts 解耦（只依赖 Node 内置模块），方便单元测试：
//   resolveKiroCliDbPath       — 按平台解析 auth_kv 数据库路径
//   resolveKiroCliAuthMethod   — social(Google/Github) vs IdC 判定
//   buildKiroCliAuthRecords    — 生成 kiro-cli 兼容的 auth_kv 记录
//   writeKiroCliAuthRecords    — 写入 SQLite（node:sqlite 优先，sqlite3 CLI 兜底）
//
// 记录格式参考：
//   - 本机 kiro-cli 2.36 实际写入的 auth_kv 记录（BuilderIdToken struct）
//   - /Users/admin/bin/kiro-ide-auth-to-cli.py（IDE → CLI 同步脚本）
//   - 上游未合并 PR #121（chaogei/Kiro-account-manager）

import * as os from 'os'
import * as path from 'path'
import * as fs from 'fs/promises'
import { execFileSync } from 'child_process'

// kiro-cli auth_kv key 常量
export const KIRO_CLI_IDC_TOKEN_KEY = 'kirocli:odic:token'
export const KIRO_CLI_SOCIAL_TOKEN_KEY = 'kirocli:social:token'
export const KIRO_CLI_DEVICE_REGISTRATION_KEY = 'kirocli:odic:device-registration'

/** 与 kiro-cli device-registration / token 里的 scopes 保持一致 */
export const KIRO_CLI_SCOPES = [
  'codewhisperer:completions',
  'codewhisperer:analysis',
  'codewhisperer:conversations'
]

/** BuilderId 的默认 SSO start URL（Enterprise 由 clientSecret 里的 initiateLoginUri 推导） */
export const KIRO_DEFAULT_START_URL = 'https://view.awsapps.com/start'

/**
 * OAuth flow 标记。
 *
 * IDE 写入 CLI 的 client registration 来自 Kiro IDE 的 IdC 登录（clientType=PUBLIC，
 * enabledGrants=AUTH_CODE + REFRESH_TOKEN），对应的 flow 是 Pkce；CLI 自身的
 * `kiro-cli login` 用 DeviceCode。两者都是 CLI 支持的枚举值（2.36 二进制里
 * `DeviceCode`/`Pkce` 都存在），这里与 IDE registration 的真实来源保持一致。
 */
export const KIRO_CLI_OAUTH_FLOW = 'Pkce'

/** Kiro IDE 客户端注册有效期（与 kiroAuthSync 中 90 天保持一致） */
const CLIENT_REGISTRATION_LIFETIME_MS = 90 * 24 * 3600 * 1000

export type KiroCliPlatform = 'darwin' | 'win32' | 'linux' | string

export interface KiroCliPathOptions {
  platform?: KiroCliPlatform
  home?: string
  env?: Record<string, string | undefined>
}

export interface KiroCliPaths {
  /** kiro-cli 的 data dir（macOS: ~/Library/Application Support/kiro-cli） */
  dataDir: string
  /** auth_kv 所在的 data.sqlite3 */
  dbPath: string
  /** macOS 上旧版本 App 误写过的 ~/.local/share 路径（仅用于报错提示，不写入） */
  legacyDbPath?: string
}

/**
 * 解析 kiro-cli 的 data dir / data.sqlite3 路径。
 *
 * kiro-cli (Rust `dirs` crate)：
 *   - macOS:   dirs::data_dir()    = $HOME/Library/Application Support
 *   - Windows: dirs::data_local_dir() = %LOCALAPPDATA%
 *   - Linux:   dirs::data_dir()    = $XDG_DATA_HOME（缺省 ~/.local/share）
 *
 * 历史 bug：App 在所有非 Windows 平台都写 ~/.local/share/kiro-cli，macOS 上
 * kiro-cli 根本不读这个路径，所以切号对 CLI “不生效”。
 */
export function resolveKiroCliPaths(options: KiroCliPathOptions = {}): KiroCliPaths {
  const platform = options.platform ?? process.platform
  const home = options.home ?? os.homedir()
  const env = options.env ?? process.env

  if (platform === 'darwin') {
    const dataDir = path.join(home, 'Library', 'Application Support', 'kiro-cli')
    return {
      dataDir,
      dbPath: path.join(dataDir, 'data.sqlite3'),
      legacyDbPath: path.join(home, '.local', 'share', 'kiro-cli', 'data.sqlite3')
    }
  }

  if (platform === 'win32') {
    // kiro-cli 的 Windows 目录是 %LOCALAPPDATA%\kiro-cli（官方 Windows 构建里
    // paths.rs 的 "kiro-cli" 字面量与 "data.sqlite3" 相邻；NTFS 大小写不敏感，
    // 旧参考脚本用的 "Kiro-Cli" 也能命中同一目录，这里与 CLI 自身保持一致）。
    const localAppData = env.LOCALAPPDATA || path.join(home, 'AppData', 'Local')
    const dataDir = path.join(localAppData, 'kiro-cli')
    return { dataDir, dbPath: path.join(dataDir, 'data.sqlite3') }
  }

  const dataHome = env.XDG_DATA_HOME || path.join(home, '.local', 'share')
  const dataDir = path.join(dataHome, 'kiro-cli')
  return { dataDir, dbPath: path.join(dataDir, 'data.sqlite3') }
}

export interface KiroCliAuthMethodInput {
  provider?: string
  authMethod?: string
}

export interface KiroCliAuthMethod {
  isSocial: boolean
  /**
   * kiro-cli SocialToken 序列化枚举值：小写 `google` / `github`。
   *
   * 写成 `Google` / `Github` 也能登录（CLI 会打印
   * `unknown variant `Github`, expected `google` or `github`` 的 serde warning），
   * 但 CLI 自己写出的记录用的小写，因此这里统一小写，避免任何严格解析路径告警。
   */
  providerForCli: string
  /** 传给 kiro-cli token record 的 oauth_flow 值 */
  oauthFlow: string
}

/**
 * 判定账号类型。
 *
 * 不能只用严格等号：Gmail/Google 账号的 provider 可能是 "google" 小写，
 * 某些导入路径只有 authMethod="social"。误判会把 social 账号写进 odic key，
 * 导致 IDE 正常、CLI “Not logged in”。
 */
export function resolveKiroCliAuthMethod(input: KiroCliAuthMethodInput): KiroCliAuthMethod {
  const providerRaw = (input.provider || '').trim()
  const providerNorm = providerRaw.toLowerCase()
  const authMethodNorm = (input.authMethod || '').trim().toLowerCase()

  const isSocial = authMethodNorm === 'social' || providerNorm === 'google' || providerNorm === 'github'
  if (isSocial) {
    return {
      isSocial: true,
      providerForCli: providerNorm === 'github' ? 'github' : 'google',
      oauthFlow: KIRO_CLI_OAUTH_FLOW
    }
  }
  return {
    isSocial: false,
    providerForCli: providerRaw,
    oauthFlow: KIRO_CLI_OAUTH_FLOW
  }
}

/** 去掉 start URL 末尾的 "/"（与 kiro-ide-auth-to-cli.py、CLI 实际记录一致） */
export function normalizeStartUrl(value: string): string {
  return value.trim().replace(/\/+$/, '')
}

/**
 * 从 IDE device registration 的 clientSecret（AWS SSO OIDC client secret，JWT 格式）
 * 里解析 initiateLoginUri，作为 Enterprise 的 start URL。
 *
 * 与 kiro-ide-auth-to-cli.py 的 start_url_from_client_secret 等价。
 */
export function startUrlFromClientSecret(clientSecret: string | undefined): string | undefined {
  if (!clientSecret) return undefined
  const parts = clientSecret.split('.')
  if (parts.length < 2) return undefined
  try {
    let payload = parts[1].replace(/-/g, '+').replace(/_/g, '/')
    while (payload.length % 4) payload += '='
    const claims = JSON.parse(Buffer.from(payload, 'base64').toString('utf-8')) as {
      serialized?: unknown
    }
    if (typeof claims.serialized !== 'string') return undefined
    const registration = JSON.parse(claims.serialized) as { initiateLoginUri?: unknown }
    if (typeof registration.initiateLoginUri === 'string' && registration.initiateLoginUri) {
      return normalizeStartUrl(registration.initiateLoginUri)
    }
    return undefined
  } catch {
    return undefined
  }
}

/**
 * 从 IDE device registration 的 clientSecret（AWS SSO OIDC client secret，JWT 格式）
 * 里解析 registration 的真实过期时间（serialized.expirationTimestamp，Unix 秒）。
 *
 * 优先使用它而不是“now + 90 天”：两者可能差 2~3 个月，写错会让 kiro-cli
 * 在真实过期后仍以为 registration 有效（或提前失效），触发 invalid_client。
 */
export function clientSecretExpiresAtFromClientSecret(
  clientSecret: string | undefined
): string | undefined {
  if (!clientSecret) return undefined
  const parts = clientSecret.split('.')
  if (parts.length < 2) return undefined
  try {
    let payload = parts[1].replace(/-/g, '+').replace(/_/g, '/')
    while (payload.length % 4) payload += '='
    const claims = JSON.parse(Buffer.from(payload, 'base64').toString('utf-8')) as {
      serialized?: unknown
    }
    if (typeof claims.serialized !== 'string') return undefined
    const registration = JSON.parse(claims.serialized) as { expirationTimestamp?: unknown }
    const timestamp = registration.expirationTimestamp
    if (typeof timestamp === 'number' && Number.isFinite(timestamp) && timestamp > 0) {
      // AWS 返回的是带小数的 Unix 秒；kiro-cli 记录用秒级 RFC3339
      return new Date(timestamp * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z')
    }
    return undefined
  } catch {
    return undefined
  }
}

/**
 * 决定写进 kiro-cli token 的 start_url：
 *   1. 调用方显式传入的 startUrl（账号 store 里的 SSO Start URL）
 *   2. clientSecret 里的 initiateLoginUri（Enterprise）
 *   3. BuilderId 默认 https://view.awsapps.com/start
 */
export function resolveCliStartUrl(input: {
  startUrl?: string
  clientSecret?: string
}): string {
  if (input.startUrl && input.startUrl.trim()) return normalizeStartUrl(input.startUrl)
  const fromRegistration = startUrlFromClientSecret(input.clientSecret)
  if (fromRegistration) return fromRegistration
  return KIRO_DEFAULT_START_URL
}

export interface KiroCliAuthInput {
  accessToken: string
  refreshToken: string
  /** token 真实过期时间（RFC3339 / ISO 字符串） */
  expiresAtIso: string
  region?: string
  provider?: string
  authMethod?: string
  startUrl?: string
  clientId?: string
  clientSecret?: string
  /** social token 必填：Kiro 固定的 social profile ARN */
  profileArn?: string
  scopes?: string[]
  /** 可选：IDE token 里已有的 client_secret 过期时间 */
  clientSecretExpiresAtIso?: string
  /** 测试注入的“当前时间”；生产不传 */
  nowMs?: number
}

export interface KiroCliAuthRecords {
  isSocial: boolean
  providerForCli: string
  tokenKey: string
  tokenValue: string
  registrationKey?: string
  registrationValue?: string
  /** 需要删除的竞争性 key，避免 kiro-cli 优先读到旧账号 */
  staleKeys: string[]
  /** social 账号需要清掉旧的 odic device registration */
  removeRegistration: boolean
}

function rfc3339(value: string): string {
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) {
    throw new Error(`无效的时间字符串: ${value}`)
  }
  return parsed.toISOString()
}

/**
 * 生成与 kiro-cli 兼容的 auth_kv 记录。
 *
 * IdC token（BuilderIdToken，kiro-cli 2.36 的 8 个字段里除可选
 * telemetry_generation 外全部写入）：
 *   { access_token, expires_at, refresh_token, region, start_url, oauth_flow, scopes }
 * device-registration：
 *   { client_id, client_secret, client_secret_expires_at, region, oauth_flow, scopes }
 * social token（kirocli:social:token）：
 *   { access_token, expires_at, refresh_token, provider, profile_arn, region }
 */
export function buildKiroCliAuthRecords(input: KiroCliAuthInput): KiroCliAuthRecords {
  if (!input.accessToken) throw new Error('accessToken 不能为空')
  if (!input.refreshToken) throw new Error('refreshToken 不能为空')
  if (!input.expiresAtIso) throw new Error('expiresAtIso 不能为空')

  const region = input.region || 'us-east-1'
  const { isSocial, providerForCli, oauthFlow } = resolveKiroCliAuthMethod({
    provider: input.provider,
    authMethod: input.authMethod
  })
  const expiresAt = rfc3339(input.expiresAtIso)
  const scopes = input.scopes && input.scopes.length > 0 ? input.scopes : KIRO_CLI_SCOPES

  const staleKeys = [
    KIRO_CLI_IDC_TOKEN_KEY,
    KIRO_CLI_SOCIAL_TOKEN_KEY,
    'codewhisperer:odic:token',
    'kirocli:external-idp:token'
  ]

  if (isSocial) {
    if (!input.profileArn) {
      throw new Error('social 账号缺少 profileArn，kiro-cli 会判定 token 无效')
    }
    const tokenData = {
      access_token: input.accessToken,
      expires_at: expiresAt,
      refresh_token: input.refreshToken,
      provider: providerForCli,
      profile_arn: input.profileArn,
      region
    }
    return {
      isSocial: true,
      providerForCli,
      tokenKey: KIRO_CLI_SOCIAL_TOKEN_KEY,
      tokenValue: JSON.stringify(tokenData),
      staleKeys: staleKeys.filter((key) => key !== KIRO_CLI_SOCIAL_TOKEN_KEY),
      removeRegistration: true
    }
  }

  const startUrl = resolveCliStartUrl({
    startUrl: input.startUrl,
    clientSecret: input.clientSecret
  })

  const tokenData = {
    access_token: input.accessToken,
    expires_at: expiresAt,
    refresh_token: input.refreshToken,
    region,
    start_url: startUrl,
    oauth_flow: oauthFlow,
    scopes
  }

  let registrationKey: string | undefined
  let registrationValue: string | undefined
  if (input.clientId && input.clientSecret) {
    const clientExpiresAt = input.clientSecretExpiresAtIso
      ? rfc3339(input.clientSecretExpiresAtIso)
      : clientSecretExpiresAtFromClientSecret(input.clientSecret) ??
        new Date((input.nowMs ?? Date.now()) + CLIENT_REGISTRATION_LIFETIME_MS).toISOString()
    registrationKey = KIRO_CLI_DEVICE_REGISTRATION_KEY
    registrationValue = JSON.stringify({
      client_id: input.clientId,
      client_secret: input.clientSecret,
      client_secret_expires_at: clientExpiresAt,
      region,
      oauth_flow: oauthFlow,
      scopes
    })
  }

  return {
    isSocial: false,
    providerForCli,
    tokenKey: KIRO_CLI_IDC_TOKEN_KEY,
    tokenValue: JSON.stringify(tokenData),
    registrationKey,
    registrationValue,
    staleKeys: staleKeys.filter((key) => key !== KIRO_CLI_IDC_TOKEN_KEY),
    removeRegistration: false
  }
}

function sqlQuote(value: string): string {
  return value.replace(/'/g, "''")
}

async function writeWithNodeSqlite(dbPath: string, records: KiroCliAuthRecords): Promise<void> {
  const { DatabaseSync } = (await import('node:sqlite')) as unknown as {
    DatabaseSync: new (path: string) => {
      exec: (sql: string) => void
      prepare: (sql: string) => { run: (...params: unknown[]) => void }
      close: () => void
    }
  }
  const db = new DatabaseSync(dbPath)
  try {
    db.exec('PRAGMA busy_timeout = 5000;')
    db.exec('CREATE TABLE IF NOT EXISTS auth_kv (key TEXT PRIMARY KEY, value TEXT);')
    const upsert = db.prepare('INSERT OR REPLACE INTO auth_kv (key, value) VALUES (?, ?)')
    upsert.run(records.tokenKey, records.tokenValue)
    if (records.registrationKey && records.registrationValue) {
      upsert.run(records.registrationKey, records.registrationValue)
    }
    const del = db.prepare('DELETE FROM auth_kv WHERE key = ?')
    for (const key of records.staleKeys) del.run(key)
    if (records.removeRegistration) del.run(KIRO_CLI_DEVICE_REGISTRATION_KEY)
  } finally {
    db.close()
  }
}

function writeWithSqlite3Cli(dbPath: string, records: KiroCliAuthRecords): void {
  const sqlite3Bin = process.platform === 'win32' ? 'sqlite3.exe' : 'sqlite3'
  const statements: string[] = [
    'CREATE TABLE IF NOT EXISTS auth_kv (key TEXT PRIMARY KEY, value TEXT);',
    `INSERT OR REPLACE INTO auth_kv (key, value) VALUES ('${sqlQuote(records.tokenKey)}', '${sqlQuote(records.tokenValue)}');`
  ]
  if (records.registrationKey && records.registrationValue) {
    statements.push(
      `INSERT OR REPLACE INTO auth_kv (key, value) VALUES ('${sqlQuote(records.registrationKey)}', '${sqlQuote(records.registrationValue)}');`
    )
  }
  for (const key of records.staleKeys) {
    statements.push(`DELETE FROM auth_kv WHERE key = '${sqlQuote(key)}';`)
  }
  if (records.removeRegistration) {
    statements.push(`DELETE FROM auth_kv WHERE key = '${sqlQuote(KIRO_CLI_DEVICE_REGISTRATION_KEY)}';`)
  }
  execFileSync(sqlite3Bin, [dbPath], {
    input: statements.join('\n'),
    timeout: 10000,
    encoding: 'utf-8'
  })
}

/**
 * 写入 auth_kv。优先用 Electron/Node 内置的 node:sqlite（参数化 SQL，无需外部
 * 命令行工具；Electron 38 / Node 22.21 已可用），不可用时回退到 sqlite3 CLI。
 */
export async function writeKiroCliAuthRecords(
  dbPath: string,
  records: KiroCliAuthRecords
): Promise<void> {
  await fs.mkdir(path.dirname(dbPath), { recursive: true })
  let nodeSqliteError: unknown
  try {
    await writeWithNodeSqlite(dbPath, records)
    return
  } catch (error) {
    nodeSqliteError = error
    console.warn('[KiroCLI] node:sqlite 写入失败，回退 sqlite3 CLI:', error)
  }
  try {
    writeWithSqlite3Cli(dbPath, records)
  } catch (sqlite3Error) {
    // 不要透传 sqlite3 的 stderr/message：失败 SQL 里含 token JSON，可能被日志/UI 回显。
    const exitCode = (sqlite3Error as { status?: number | null }).status
    console.warn('[KiroCLI] sqlite3 CLI 写入失败（详细错误已省略，避免泄漏凭证内容）')
    console.warn('[KiroCLI] node:sqlite 不可用原因:', (nodeSqliteError as Error)?.name ?? 'unknown')
    throw new Error(
      `写入 Kiro CLI 数据库失败（${dbPath}）：sqlite3 命令执行失败` +
        `${typeof exitCode === 'number' ? `（exit ${exitCode}）` : ''}，且 node:sqlite 不可用。` +
        '请确认数据库未被 kiro-cli 占用后重试。'
    )
  }
}

export interface ApplyKiroCliAuthOptions extends KiroCliPathOptions {
  /** 测试注入：显式指定 db 路径，跳过存在性检查 */
  dbPath?: string
}

/**
 * 解析路径 + 校验 CLI 数据库已初始化 + 写入记录。
 *
 * 如果 kiro-cli 从未登录过（data.sqlite3 不存在），不主动创建库：CLI 的
 * migrations 记录与 auth_kv 表结构由 CLI 自己建，伪造一个空库可能让 kiro-cli
 * 启动时 migration 失败。此时返回可读错误，提示先运行一次 `kiro-cli login`。
 */
export async function applyKiroCliAuth(
  records: KiroCliAuthRecords,
  options: ApplyKiroCliAuthOptions = {}
): Promise<{ dbPath: string }> {
  const paths = resolveKiroCliPaths(options)
  const dbPath = options.dbPath ?? paths.dbPath
  if (!options.dbPath) {
    let dbExists = false
    try {
      await fs.access(dbPath)
      dbExists = true
    } catch {
      dbExists = false
    }
    if (!dbExists) {
      // macOS 上旧版本 App 曾把数据写到 ~/.local/share/kiro-cli（CLI 不读取），这里仅做提示。
      let legacyHint = ''
      if (paths.legacyDbPath) {
        try {
          await fs.access(paths.legacyDbPath)
          legacyHint = ` 注意：检测到旧版本误写的数据库 ${paths.legacyDbPath}，kiro-cli 不会读取它，可自行删除。`
        } catch {
          /* no legacy db */
        }
      }
      throw new Error(
        `未找到 Kiro CLI 数据库：${dbPath}。请先运行一次 kiro-cli login 完成初始化，再重试切号。${legacyHint}`
      )
    }
  }
  await writeKiroCliAuthRecords(dbPath, records)
  return { dbPath }
}
