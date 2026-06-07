// Kiro IDE Auth Token 同步层
//
// Kiro IDE 桌面端把 token 持久化在 ~/.aws/sso/cache/kiro-auth-token.json，
// 并对该文件做 fs.watchFile 监听 + 内部 refresh loop。
//
// 反代和 IDE 必须以这个文件作为 single source of truth，否则会出现：
//   反代 store 里 refreshToken_v2，磁盘里 refreshToken_v1（已被服务端轮换作废）
//   → IDE 一小时后用 v1 调 OIDC → 401 → logoutAndForget()
//
// 本模块提供：
//   writeKiroAuthTokenFile  — 以 Kiro IDE 兼容格式写入 token 文件（+ IdC 客户端注册）
//   readKiroAuthTokenFile   — 读取当前磁盘 token
//   parseAccessTokenClaims  — 解 accessToken 的 JWT 拿到 sub/email，用于反向匹配账号
//   watchKiroAuthTokenFile  — 监听文件变化（IDE 自己 refresh 时用于反向同步到反代 store）

import * as fs from 'fs/promises'
import * as fsSync from 'fs'
import * as path from 'path'
import * as os from 'os'
import * as crypto from 'crypto'

export const KIRO_SSO_CACHE_DIR = path.join(os.homedir(), '.aws', 'sso', 'cache')
export const KIRO_AUTH_TOKEN_PATH = path.join(KIRO_SSO_CACHE_DIR, 'kiro-auth-token.json')

const KIRO_DEFAULT_START_URL = 'https://view.awsapps.com/start'
const KIRO_OIDC_SCOPES = [
  'codewhisperer:completions',
  'codewhisperer:analysis',
  'codewhisperer:conversations',
  'codewhisperer:transformations',
  'codewhisperer:taskassist'
]

// =============== profileArn 决策中心 ===============
//
// 占位符 ARN：Kiro IDE 源码 FixedProfileArns 里给 BuilderId 硬编码的值。
// Kiro IDE 内部逻辑依赖该字段存在，移除会导致 IDE 功能异常。
export const KIRO_BUILDER_ID_PLACEHOLDER_ARN = 'arn:aws:codewhisperer:us-east-1:638616132270:profile/AAAACCCCXXXX'
// Social 登录（Github/Google）共用的 Kiro 后端固定 profileArn
export const KIRO_SOCIAL_PROFILE_ARN = 'arn:aws:codewhisperer:us-east-1:699475941385:profile/EHGA3GRVQMUK'

// Enterprise 备用 profileArn（自动获取失败时使用，区域动态替换）
const ENTERPRISE_FALLBACK_PROFILE_ID = 'VNECVYCYYAWN'
const ENTERPRISE_FALLBACK_ACCOUNT_ID = '610548660232'
export function getEnterpriseFallbackArn(region?: string): string {
  const r = region?.startsWith('eu-') ? 'eu-central-1' : 'us-east-1'
  return `arn:aws:codewhisperer:${r}:${ENTERPRISE_FALLBACK_ACCOUNT_ID}:profile/${ENTERPRISE_FALLBACK_PROFILE_ID}`
}

const PLACEHOLDER_PROFILE_ARNS = new Set<string>([KIRO_BUILDER_ID_PLACEHOLDER_ARN])

/** 检查给定 ARN 是不是已知占位符（旧版反代 / Kiro IDE 自身可能写入的脏数据） */
export function isPlaceholderProfileArn(arn: string | undefined | null): boolean {
  if (!arn) return false
  return PLACEHOLDER_PROFILE_ARNS.has(arn)
}

/**
 * 写入 token 文件前对 profileArn 的"应该写啥"做统一决策。
 *
 * 规则（优先级）：
 *   1. 调用方显式给出 profileArn 且非已知占位符 → 直接用
 *   2. social/Github/Google → 用固定 Kiro Social profileArn
 *   3. BuilderId / 其它 → 使用 Kiro IDE 官方占位符 ARN（IDE 内部逻辑依赖此字段存在）
 */
export function resolveProfileArnForWrite(input: {
  profileArn?: string
  authMethod?: string
  provider?: string
  region?: string
}): string | undefined {
  if (input.profileArn && !isPlaceholderProfileArn(input.profileArn)) {
    return input.profileArn
  }
  if (input.authMethod === 'social' || input.provider === 'Github' || input.provider === 'Google') {
    return KIRO_SOCIAL_PROFILE_ARN
  }
  // Enterprise 不能用 BuilderId 占位符（IDE 调接口会 Invalid token）
  if (input.provider === 'Enterprise' || input.authMethod === 'external_idp') {
    return getEnterpriseFallbackArn(input.region)
  }
  return KIRO_BUILDER_ID_PLACEHOLDER_ARN
}

export interface KiroAuthTokenFile {
  accessToken: string
  refreshToken: string
  expiresAt: string
  authMethod?: 'IdC' | 'social' | string
  provider?: string
  region?: string
  clientIdHash?: string
  profileArn?: string
}

export interface WriteKiroAuthTokenInput {
  accessToken: string
  refreshToken: string
  /** ISO 字符串。建议用 OIDC 返回的真实 expiresIn 算 */
  expiresAtIso: string
  authMethod: 'IdC' | 'social'
  provider: string
  region?: string
  startUrl?: string
  /** IdC 必填：会一起写客户端注册文件 */
  clientId?: string
  clientSecret?: string
  profileArn?: string
}

export interface WriteKiroAuthTokenResult {
  tokenPath: string
  clientRegPath?: string
}

function computeClientIdHash(startUrl?: string): string {
  return crypto
    .createHash('sha1')
    .update(JSON.stringify({ startUrl: startUrl || KIRO_DEFAULT_START_URL }))
    .digest('hex')
}

/**
 * 以与 Kiro IDE 完全兼容的格式写入 ~/.aws/sso/cache/kiro-auth-token.json
 * - mode 0o600：与 IDE 保持一致（writeTokenToDisk 用 0o600 即 384）
 * - social 与 IdC 字段顺序对齐 Kiro IDE 序列化结果，便于人工 diff
 * - IdC 同时写客户端注册文件 {clientIdHash}.json
 */
export async function writeKiroAuthTokenFile(
  input: WriteKiroAuthTokenInput
): Promise<WriteKiroAuthTokenResult> {
  await fs.mkdir(KIRO_SSO_CACHE_DIR, { recursive: true })

  const clientIdHash = computeClientIdHash(input.startUrl)

  const tokenData: Record<string, unknown> =
    input.authMethod === 'social'
      ? {
          accessToken: input.accessToken,
          refreshToken: input.refreshToken,
          profileArn: input.profileArn,
          expiresAt: input.expiresAtIso,
          authMethod: input.authMethod,
          provider: input.provider
        }
      : {
          accessToken: input.accessToken,
          refreshToken: input.refreshToken,
          expiresAt: input.expiresAtIso,
          clientIdHash,
          authMethod: input.authMethod,
          provider: input.provider,
          region: input.region || 'us-east-1',
          profileArn: input.profileArn
        }

  await fs.writeFile(KIRO_AUTH_TOKEN_PATH, JSON.stringify(tokenData, null, 2), {
    mode: 0o600
  })
  // Windows 上 chmod 对 0o600 是 no-op 但不抛错；Linux/macOS 上保证权限正确
  try {
    await fs.chmod(KIRO_AUTH_TOKEN_PATH, 0o600)
  } catch {
    /* ignore */
  }

  let clientRegPath: string | undefined
  if (input.authMethod !== 'social' && input.clientId && input.clientSecret) {
    clientRegPath = path.join(KIRO_SSO_CACHE_DIR, `${clientIdHash}.json`)
    // IDE 客户端注册有效期 90 天（Kiro IDE 原版做法），格式为去掉 Z 的 ISO 字符串
    const clientExpiresAt = new Date(Date.now() + 90 * 24 * 3600 * 1000).toISOString().replace('Z', '')
    const clientData = {
      clientId: input.clientId,
      clientSecret: input.clientSecret,
      expiresAt: clientExpiresAt,
      scopes: KIRO_OIDC_SCOPES
    }
    await fs.writeFile(clientRegPath, JSON.stringify(clientData, null, 2), { mode: 0o600 })
    try {
      await fs.chmod(clientRegPath, 0o600)
    } catch {
      /* ignore */
    }
  }

  return { tokenPath: KIRO_AUTH_TOKEN_PATH, clientRegPath }
}

export async function readKiroAuthTokenFile(): Promise<KiroAuthTokenFile | null> {
  try {
    const content = await fs.readFile(KIRO_AUTH_TOKEN_PATH, 'utf-8')
    const parsed = JSON.parse(content) as KiroAuthTokenFile
    if (!parsed.accessToken || !parsed.refreshToken) return null
    return parsed
  } catch {
    return null
  }
}

/**
 * 解 accessToken 的 JWT 第二段（payload）拿 sub / email / aud / preferred_username。
 * - 如果不是 JWT 格式返回 null
 * - 不验证签名（只用于反向匹配账号）
 */
export interface AccessTokenClaims {
  sub?: string
  email?: string
  aud?: string
  preferredUsername?: string
}

export function parseAccessTokenClaims(accessToken: string): AccessTokenClaims | null {
  if (!accessToken) return null
  const parts = accessToken.split('.')
  if (parts.length < 2) return null
  try {
    let b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/')
    while (b64.length % 4) b64 += '='
    const json = Buffer.from(b64, 'base64').toString('utf-8')
    const claims = JSON.parse(json) as Record<string, unknown>
    const audRaw = claims.aud
    const aud = typeof audRaw === 'string' ? audRaw : Array.isArray(audRaw) && typeof audRaw[0] === 'string' ? (audRaw[0] as string) : undefined
    return {
      sub: typeof claims.sub === 'string' ? (claims.sub as string) : undefined,
      email: typeof claims.email === 'string' ? (claims.email as string) : undefined,
      aud,
      preferredUsername:
        typeof claims['preferred_username'] === 'string'
          ? (claims['preferred_username'] as string)
          : undefined
    }
  } catch {
    return null
  }
}

/**
 * 监听 Kiro IDE 的 token 文件变化。
 * - 使用 fs.watchFile（polling）以保证跨平台一致性
 * - 内部做内容防抖（同一对 accessToken+refreshToken 不重复触发）
 * - 返回 dispose 函数
 */
export type WatchCallback = (token: KiroAuthTokenFile) => void | Promise<void>

export function watchKiroAuthTokenFile(onChange: WatchCallback, intervalMs = 2000): () => void {
  let debounceTimer: NodeJS.Timeout | null = null
  let lastSeenSig = ''
  let disposed = false

  const tick = async (): Promise<void> => {
    if (disposed) return
    try {
      const token = await readKiroAuthTokenFile()
      if (!token) return
      const sig = `${token.accessToken}|${token.refreshToken}`
      if (sig === lastSeenSig) return
      lastSeenSig = sig
      await onChange(token)
    } catch (e) {
      // 静默：watcher 不应该 throw 影响主进程
      console.warn('[kiroAuthSync] watcher tick failed:', e)
    }
  }

  const listener = (): void => {
    if (debounceTimer) clearTimeout(debounceTimer)
    debounceTimer = setTimeout(() => {
      debounceTimer = null
      void tick()
    }, 600)
  }

  // 先做一次基线读，避免启动后第一次"虚假变更"
  void readKiroAuthTokenFile().then((t) => {
    if (t) lastSeenSig = `${t.accessToken}|${t.refreshToken}`
  })

  fsSync.watchFile(KIRO_AUTH_TOKEN_PATH, { interval: intervalMs }, listener)

  return () => {
    disposed = true
    if (debounceTimer) clearTimeout(debounceTimer)
    fsSync.unwatchFile(KIRO_AUTH_TOKEN_PATH, listener)
  }
}
