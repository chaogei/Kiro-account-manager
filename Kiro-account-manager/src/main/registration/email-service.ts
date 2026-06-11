import * as tls from 'tls'
import { fetch as undiciFetch, type RequestInit as UndiciRequestInit } from 'undici'
import type { SessionClient } from 'tlsclientwrapper'
import { getSystemProxy, safeCreateProxyAgent } from '../proxy/systemProxy'
import { randomEmailPrefix } from './names'
import { waitProtonOtp } from './proton-mail-window'

function getRegistrationProxyUrl(): string | undefined {
  return process.env.HTTPS_PROXY || process.env.https_proxy || process.env.HTTP_PROXY || process.env.http_proxy || getSystemProxy() || undefined
}

async function proxyFetch(url: string, options?: RequestInit): Promise<Response> {
  const agent = safeCreateProxyAgent(getRegistrationProxyUrl())
  if (agent) {
    return await undiciFetch(url, { ...options, dispatcher: agent } as UndiciRequestInit) as unknown as Response
  }
  return await fetch(url, options)
}

// ============ 验证码提取 ============

const OTP_PATTERN = /\b(\d{6})\b/g

export function extractCode(body: string): string {
  const matches = body.match(OTP_PATTERN)
  if (!matches || matches.length === 0) return ''
  return matches[matches.length - 1]
}

// ============ TempEmailService 接口 ============

export interface TempEmailService {
  create(): Promise<string>
  /** signal：注册被取消时中断轮询（停止/暂停后立即退出，而非等满 timeout） */
  waitForCode(timeoutSec: number, intervalSec: number, signal?: AbortSignal): Promise<string>
  getAddress(): string
}

/** 可被 AbortSignal 中断的 sleep：停止注册时立刻 reject，不再傻等 */
function abortableSleep(ms: number, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted) return Promise.reject(new Error('注册已取消'))
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort)
      resolve()
    }, ms)
    const onAbort = (): void => {
      clearTimeout(timer)
      reject(new Error('注册已取消'))
    }
    signal?.addEventListener('abort', onAbort, { once: true })
  })
}

// ============ MoEmail 临时邮箱 ============

export class MoEmailService implements TempEmailService {
  private baseURL: string
  private apiKey: string
  private address = ''

  constructor(baseURL: string, apiKey: string) {
    this.baseURL = MoEmailService.normalizeBaseURL(baseURL)
    this.apiKey = apiKey
  }

  /**
   * 归一化用户输入的 baseURL：
   *   - 去除首尾空白与末尾斜杠
   *   - 缺少 protocol 时补 `https://`
   *   - 校验协议仅允许 http / https，否则抛清晰错误
   * 用于规避 fetch 因协议不合法抛出
   * "Invalid URL protocol: the URL must start with `http:` or `https:`."
   */
  private static normalizeBaseURL(raw: string): string {
    const trimmed = (raw || '').trim().replace(/\/+$/, '')
    if (!trimmed) throw new Error('MoEmail BaseURL 未配置')
    const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`
    let u: URL
    try {
      u = new URL(withScheme)
    } catch {
      throw new Error(`MoEmail BaseURL 格式无效: ${raw}`)
    }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') {
      throw new Error(`MoEmail BaseURL 协议不支持 (仅支持 http/https): ${u.protocol}`)
    }
    return withScheme
  }

  async create(): Promise<string> {
    const url = `${this.baseURL}/api/mail/create`
    const headers: Record<string, string> = { 'Content-Type': 'application/json' }
    if (this.apiKey) headers['Authorization'] = `Bearer ${this.apiKey}`

    const resp = await proxyFetch(url, { method: 'POST', headers, signal: AbortSignal.timeout(30000) })
    const data = (await resp.json()) as Record<string, unknown>

    const addr =
      (data.address as string) ||
      (data.email as string) ||
      ((data.data as Record<string, unknown>)?.address as string) ||
      ((data.data as Record<string, unknown>)?.email as string) ||
      ''

    if (!addr) {
      console.log('[MoEmail] 创建邮箱失败:', JSON.stringify(data))
      return ''
    }
    this.address = addr
    return addr
  }

  async waitForCode(timeoutSec: number, intervalSec: number, signal?: AbortSignal): Promise<string> {
    if (!this.address) throw new Error('邮箱地址为空')

    const maxRetries = Math.floor(timeoutSec / intervalSec)
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      if (signal?.aborted) throw new Error('注册已取消')
      await abortableSleep(intervalSec * 1000, signal)
      try {
        const code = await this.fetchCode()
        if (code) return code
      } catch (err) {
        if (attempt % 5 === 0) console.log(`[MoEmail] [${attempt}/${maxRetries}] 查询失败:`, err)
      }
      if (attempt % 5 === 0) console.log(`[MoEmail] [${attempt}/${maxRetries}] 暂无验证码...`)
    }
    throw new Error(`等待验证码超时 (${timeoutSec}s)`)
  }

  getAddress(): string {
    return this.address
  }

  private async fetchCode(): Promise<string> {
    const url = `${this.baseURL}/api/mail/messages?address=${this.address}`
    const headers: Record<string, string> = {}
    if (this.apiKey) headers['Authorization'] = `Bearer ${this.apiKey}`

    const resp = await proxyFetch(url, { headers, signal: AbortSignal.timeout(15000) })
    const raw = await resp.json()

    let messages: Array<Record<string, unknown>> = []
    if (Array.isArray(raw)) {
      messages = raw as Array<Record<string, unknown>>
    } else if (typeof raw === 'object' && raw !== null) {
      const wrapper = raw as Record<string, unknown>
      if (Array.isArray(wrapper.data)) {
        messages = wrapper.data as Array<Record<string, unknown>>
      }
    }

    for (const msg of messages) {
      const text = (msg.text as string) || (msg.body as string) || (msg.html as string) || ''
      if (text) {
        const code = extractCode(text)
        if (code) return code
      }
    }
    return ''
  }
}

// ============ TempMail.Plus + 自建域名 ============

export class TempMailPlusService implements TempEmailService {
  private static readonly BASE_URL = 'https://tempmail.plus/api'

  private readonly tmEmail: string   // tempmail.plus 用户名（不含 @mailto.plus）
  private readonly epin: string
  /** 支持多域名（用户填多行/逗号/空格分隔），每次 create 随机挑一个，降低单域名被风控关联 */
  private readonly domains: string[]
  private domain = ''
  private address = ''

  constructor(tmEmail: string, epin: string, domain: string) {
    this.tmEmail = tmEmail
    this.epin = epin
    this.domains = domain
      .split(/[\s,;]+/)
      .map((d) => d.trim().replace(/^@/, ''))
      .filter(Boolean)
    if (this.domains.length === 0) {
      throw new Error('TempMail.Plus 自建域名为空')
    }
  }

  private get headers(): Record<string, string> {
    return {
      'accept': 'application/json, text/javascript, */*; q=0.01',
      'accept-language': 'zh-CN,zh;q=0.9,en;q=0.8',
      'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36',
      'x-requested-with': 'XMLHttpRequest',
      'Referer': 'https://tempmail.plus/zh/',
      'cookie': `email=${encodeURIComponent(this.fullEmail)}`
    }
  }

  async create(): Promise<string> {
    const prefix = randomEmailPrefix()
    this.domain = this.domains[Math.floor(Math.random() * this.domains.length)]
    this.address = `${prefix}@${this.domain}`
    if (this.domains.length > 1) {
      console.log(`[TempMailPlus] 生成邮箱: ${this.address}  (域名池 ${this.domains.length} 个)`)
    } else {
      console.log(`[TempMailPlus] 生成邮箱: ${this.address}`)
    }
    return this.address
  }

  getAddress(): string {
    return this.address
  }

  async waitForCode(timeoutSec: number, intervalSec: number, signal?: AbortSignal): Promise<string> {
    if (!this.address) throw new Error('邮箱地址为空')
    const maxRetries = Math.floor(timeoutSec / intervalSec)
    const checkedIds = new Set<number>()

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      if (signal?.aborted) throw new Error('注册已取消')
      await abortableSleep(intervalSec * 1000, signal)
      try {
        const mails = await this.fetchMailList()
        if (attempt === 1 || attempt % 5 === 0) {
          console.log(`[TempMailPlus] [${attempt}/${maxRetries}] 邮件数: ${mails.length}`)
        }
        for (const mail of mails) {
          const mailId = mail.mail_id as number
          if (checkedIds.has(mailId)) continue
          checkedIds.add(mailId)

          const detail = await this.fetchMailDetail(mailId)
          if (!detail) continue

          // 验证收件人匹配
          const toField = String(detail.to || '').toLowerCase()
          if (!toField.includes(this.address.toLowerCase())) {
            console.log(`[TempMailPlus] 收件人不匹配: ${toField} (期望包含: ${this.address})`)
            continue
          }

          // 提取验证码
          const code = this.extractOTP(detail)
          if (code) {
            console.log(`[TempMailPlus] 验证码: ${code}`)
            await this.deleteMail(mailId)
            return code
          } else {
            console.log(`[TempMailPlus] 邮件 ${mailId} 未提取到验证码`)
          }
        }
      } catch (err) {
        console.log(`[TempMailPlus] [${attempt}/${maxRetries}] 查询失败:`, err)
      }
      if (attempt % 5 === 0) console.log(`[TempMailPlus] [${attempt}/${maxRetries}] 暂无验证码...`)
    }
    throw new Error(`等待验证码超时 (${timeoutSec}s)`)
  }

  private get fullEmail(): string {
    return `${this.tmEmail}@mailto.plus`
  }

  private async fetchMailList(): Promise<Array<Record<string, unknown>>> {
    const url = `${TempMailPlusService.BASE_URL}/mails?email=${encodeURIComponent(this.fullEmail)}&first_id=0&epin=${encodeURIComponent(this.epin)}`
    const resp = await proxyFetch(url, { headers: this.headers, signal: AbortSignal.timeout(15000) })
    const data = (await resp.json()) as Record<string, unknown>
    if (!data.result) return []
    return (data.mail_list as Array<Record<string, unknown>>) || []
  }

  private async fetchMailDetail(mailId: number): Promise<Record<string, unknown> | null> {
    const url = `${TempMailPlusService.BASE_URL}/mails/${mailId}?email=${encodeURIComponent(this.fullEmail)}&epin=${encodeURIComponent(this.epin)}`
    const resp = await proxyFetch(url, { headers: this.headers, signal: AbortSignal.timeout(15000) })
    const data = (await resp.json()) as Record<string, unknown>
    return data.result ? data : null
  }

  private async deleteMail(mailId: number): Promise<void> {
    const url = `${TempMailPlusService.BASE_URL}/mails/${mailId}`
    const headers = { ...this.headers, 'content-type': 'application/x-www-form-urlencoded; charset=UTF-8' }
    const body = `email=${encodeURIComponent(this.fullEmail)}&epin=${encodeURIComponent(this.epin)}`
    try {
      await proxyFetch(url, { method: 'DELETE', headers, body, signal: AbortSignal.timeout(10000) })
      console.log(`[TempMailPlus] 已删除邮件: ${mailId}`)
    } catch (err) {
      console.log(`[TempMailPlus] 删除邮件失败:`, err)
    }
  }

  private extractOTP(detail: Record<string, unknown>): string {
    // 从主题提取
    const subject = String(detail.subject || '')
    const subjectMatch = subject.match(/(\d{6})/)
    if (subjectMatch) return subjectMatch[1]
    // 从正文提取
    const text = String(detail.text || '')
    const code = extractCode(text)
    if (code) return code
    // 从 HTML 提取
    const html = String(detail.html || '')
    return extractCode(html)
  }
}

// ============ GPTmail (mail.chatgpt.org.uk) — 域名邮箱取码 ============

/**
 * GPTmail（mail.chatgpt.org.uk）取码源，**同时支持两种玩法**：
 *
 * 玩法 A：私有域名直收（推荐，无需 CF）
 *   1) 用户把自己域名 MX 直接解析到 GPTmail（在 GPTmail 站点添加私有/公开域名后会给 MX 指令）
 *   2) 注册时生成 `prefix@用户域名` —— 这个地址本身就是 GPTmail 上的 inbox，
 *      所有发到它的邮件 GPTmail 直接收到
 *   3) 用同一个地址 GET 页面拿 token，轮询取码
 *   inboxEmail 留空表示走这个模式。
 *
 * 玩法 B：CF Email Routing 转发
 *   1) 用户在 GPTmail 上拥有一个固定接收邮箱（如公共域名池里的 abc@msn-mail-free-9224.dynv6.net）
 *   2) 用户在自己域名 Cloudflare 配 catch-all：*@example.com → abc@msn-mail-free-9224.dynv6.net
 *   3) 注册时生成 `prefix@example.com`，CF 转发到接收邮箱
 *   4) 用接收邮箱的 token 轮询，从邮件里软匹配本次注册地址（CF 转发的邮件 to 字段会是接收邮箱）
 *   inboxEmail 填了表示走这个模式。
 *
 * GPTmail 协议要点（基于官方前端 + 抓包）：
 *  - 直接 GET `https://mail.chatgpt.org.uk/<email>` 页面，从 HTML 解析 `window.__BROWSER_AUTH.token`
 *    （服务端 SSR 嵌入，这是浏览器拿初始 token 的"零成本"路径，比 POST /api/inbox-token 更不易被反爬）
 *  - GET /api/emails?email=<inbox> (header x-inbox-token)
 *      -> {success, data:{emails:[{id, email_address, from_address, subject, content, html_content}]}, auth:{token,...}}
 *  - DELETE /api/emails/clear?email=<inbox> (header x-inbox-token)
 *  - 每次响应都会刷新 token（含 sid+email+exp），本类自动滚动保存
 *  - Cloudflare 后端通过 TLS 指纹 + sec-ch-* + Referer 校验"是否真实 Chrome"，
 *    所以本类必须通过 tlsclientwrapper SessionClient 发请求
 */
export class GptMailService implements TempEmailService {
  private static readonly DEFAULT_BASE_URL = 'https://mail.chatgpt.org.uk'
  // 与 sessionOpts 的 tlsClientIdentifier='chrome_146' 及 SessionClient 默认 UA 保持一致，
  // 否则 sec-ch-ua / UA / JA3 三者版本对不上，容易被 Cloudflare 风控识破。
  private static readonly CHROME_MAJOR = 146
  private static readonly UA = `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${GptMailService.CHROME_MAJOR}.0.0.0 Safari/537.36`
  private static readonly SEC_CH_UA = `"Google Chrome";v="${GptMailService.CHROME_MAJOR}", "Chromium";v="${GptMailService.CHROME_MAJOR}", "Not)A;Brand";v="24"`

  private readonly baseURL: string
  /**
   * 固定接收邮箱（CF 转发目标）。
   * - 玩法 A（私有域名直收）：留空 —— 本次注册地址本身就是 inbox
   * - 玩法 B（CF 转发）：填了，所有 prefix@domain 都转发到这个邮箱
   */
  private readonly fixedInboxEmail: string
  /** 用户自己的域名池（玩法 A：MX 已解析到 GPTmail；玩法 B：CF 配了 catch-all）*/
  private readonly domains: string[]
  /** 可选的固定前缀；留空则用 randomEmailPrefix() 生成 */
  private readonly fixedPrefix: string
  /**
   * 可选：私有域名密码。
   * 在 GPTmail 站点添加「私有域名」时会设一个密码，所有该域名下的 inbox 查看邮件前必须 unlock。
   * 留空 = 公共域名或公开域名（不需密码）。
   */
  private readonly privatePassword: string
  /**
   * 取当前 TLS SessionClient 的 getter（伪装 Chrome JA3 指纹）。
   * GPTmail 后端通过 TLS 握手指纹校验"是否真实浏览器"，
   * Node 默认 TLS / undici 会被识破返回 401 "Browser session required"，
   * 所以必须用 Registrar 已经初始化好的 SessionClient 发请求。
   *
   * 关键：这里**不能缓存 SessionClient 实例**。Registrar 在注册过程中（Portal/WorkflowInit
   * 重试、网络抖动、可恢复 TLS 错误）会 rebuildTlsClient() —— 销毁旧 session 再建新的。
   * 若缓存旧引用，邮箱创建后到取码之间一旦发生 rebuild，旧 session 已 destroyed，
   * 后续每次轮询都会抛 "SessionClient has been destroyed" 直到超时。
   * 因此每次请求都通过 getter 读取 Registrar 的**最新** session。
   */
  private readonly getSession: () => SessionClient | null

  /** 本次注册使用的"用户侧"邮箱地址（prefix@用户域名）—— 注册站点看到的就是它 */
  private address = ''
  /** 实际查询邮件用的 GPTmail inbox 地址（玩法 A = address；玩法 B = fixedInboxEmail）*/
  private inboxEmail = ''
  /** 当前滚动 token：每次响应若带回 auth.token 则替换 */
  private token = ''
  /**
   * create() 时已存在于 inbox 的邮件 ID 基线。
   * CF 转发模式下多个并发注册共享同一 inbox，绝不能用全量 clear（会删掉别的任务待取的验证码）；
   * 改为记录基线 ID，轮询时跳过这些旧邮件，做到无副作用、并发安全。
   */
  private baselineIds = new Set<string>()

  constructor(opts: {
    baseURL?: string
    inboxEmail?: string
    domain: string
    prefix?: string
    privatePassword?: string
    /** 取当前 SessionClient 的 getter（不缓存，规避 rebuildTlsClient 后引用失效） */
    getSession: () => SessionClient | null
  }) {
    if (typeof opts.getSession !== 'function') {
      throw new Error('GPTmail 必须传入 getSession（用于每次取最新 TLS SessionClient 绕过 401 校验）')
    }
    this.getSession = opts.getSession
    this.baseURL = GptMailService.normalizeBaseURL(opts.baseURL || GptMailService.DEFAULT_BASE_URL)
    this.fixedInboxEmail = (opts.inboxEmail || '').trim()
    if (this.fixedInboxEmail && !this.fixedInboxEmail.includes('@')) {
      throw new Error('GPTmail 接收邮箱格式无效（应为 xxx@yyy.zzz，或留空走私有域名直收）')
    }
    this.domains = (opts.domain || '')
      .split(/[\s,;]+/)
      .map((d) => d.trim().replace(/^@/, ''))
      .filter(Boolean)
    if (this.domains.length === 0) {
      throw new Error('GPTmail 自建域名池为空（私有模式: MX 已解析到 GPTmail 的域名；CF 模式: CF 配了 catch-all 的域名）')
    }
    this.fixedPrefix = (opts.prefix || '').trim().toLowerCase().replace(/[^a-z0-9._-]/g, '')
    this.privatePassword = (opts.privatePassword || '').trim()
  }

  private static normalizeBaseURL(raw: string): string {
    const trimmed = (raw || '').trim().replace(/\/+$/, '')
    if (!trimmed) return 'https://mail.chatgpt.org.uk'
    const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`
    let u: URL
    try {
      u = new URL(withScheme)
    } catch {
      throw new Error(`GPTmail BaseURL 格式无效: ${raw}`)
    }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') {
      throw new Error(`GPTmail BaseURL 协议不支持 (仅支持 http/https): ${u.protocol}`)
    }
    return withScheme
  }

  /**
   * 从页面 HTML 中提取 `window.__BROWSER_AUTH = {...}` 的 JSON 文本。
   * 用括号配平扫描（识别字符串与转义），从第一个 `{` 开始找到与之匹配的 `}`，
   * 支持对象内含嵌套 {} —— 比非贪婪正则健壮。
   */
  private static extractBrowserAuthJson(html: string): string | null {
    const anchor = html.indexOf('__BROWSER_AUTH')
    if (anchor < 0) return null
    const start = html.indexOf('{', anchor)
    if (start < 0) return null
    let depth = 0
    let inStr = false
    let quote = ''
    let escaped = false
    for (let i = start; i < html.length; i++) {
      const ch = html[i]
      if (inStr) {
        if (escaped) escaped = false
        else if (ch === '\\') escaped = true
        else if (ch === quote) inStr = false
        continue
      }
      if (ch === '"' || ch === '\'') {
        inStr = true
        quote = ch
      } else if (ch === '{') {
        depth++
      } else if (ch === '}') {
        depth--
        if (depth === 0) return html.slice(start, i + 1)
      }
    }
    return null
  }

  /**
   * 通用请求：经过 tlsclientwrapper（伪装 Chrome JA3 指纹）调用 GPTmail API。
   *
   * 关键：GPTmail 通过 TLS 指纹 + Referer/Origin/sec-ch-* 校验"是否真实 Chrome"，
   * 用 Node 默认 TLS / undici 会被识破返回 401 {"error":"Browser session required"}。
   * 此方法走 Registrar 的 SessionClient（伪装 chrome_146 JA3）并补全浏览器 headers，
   * 才能通过 Cloudflare 反爬。
   *
   * 自动注入 x-inbox-token，并从响应里滚动更新 token。
   */
  private async request<T = Record<string, unknown>>(
    path: string,
    init: { method?: 'GET' | 'POST' | 'DELETE'; body?: string; withToken?: boolean; headers?: Record<string, string>; _retried?: boolean } = {}
  ): Promise<T> {
    const url = `${this.baseURL}${path}`
    const origin = new URL(this.baseURL).origin
    // Referer 跟官方抓包对齐：`https://mail.chatgpt.org.uk/<inboxEmail>`（不带 /zh/）
    const referer = `${origin}/${this.inboxEmail || ''}`
    const method: 'GET' | 'POST' | 'DELETE' = init.method ?? 'GET'

    const headers: Record<string, string> = {
      'accept': 'application/json, text/plain, */*',
      'accept-language': 'zh-CN,zh;q=0.9,en;q=0.8',
      'user-agent': GptMailService.UA,
      'origin': origin,
      'referer': referer,
      'sec-ch-ua': GptMailService.SEC_CH_UA,
      'sec-ch-ua-mobile': '?0',
      'sec-ch-ua-platform': '"Windows"',
      'sec-fetch-dest': 'empty',
      'sec-fetch-mode': 'cors',
      'sec-fetch-site': 'same-origin',
      ...(init.headers || {})
    }
    if (init.body && !headers['content-type'] && !headers['Content-Type']) {
      headers['content-type'] = 'application/json'
    }
    if ((init.withToken ?? true) && this.token) {
      headers['x-inbox-token'] = this.token
    }

    // 走 tlsclientwrapper（伪装 Chrome 146 JA3 + 由 Registrar 的 sessionOpts 注入 UA/代理）
    const session = this.getSession()
    if (!session) throw new Error('GPTmail TLS SessionClient 不可用（可能正在重建，稍后重试）')
    let raw: { status: number; body: string }
    if (method === 'POST') {
      raw = await session.post(url, init.body ?? '', { headers })
    } else if (method === 'DELETE') {
      raw = await session.delete(url, { headers })
    } else {
      raw = await session.get(url, { headers })
    }

    let data: unknown
    try { data = JSON.parse(raw.body) } catch { data = raw.body }

    // 401/403 且带 token：可能是滚动 token 过期 —— 重新从页面拿一次 token 后重试一次。
    // （若是 TLS 指纹被识破的 "Browser session required"，重取也无害，最多再失败一次按原错误抛出）
    if ((raw.status === 401 || raw.status === 403) && !init._retried && (init.withToken ?? true) && path !== '') {
      try {
        await this.fetchInitialTokenFromPage()
        return await this.request<T>(path, { ...init, _retried: true })
      } catch { /* 重取失败则按原错误抛出 */ }
    }

    if (raw.status < 200 || raw.status >= 300) {
      const snippet = typeof data === 'string' ? data.slice(0, 200) : JSON.stringify(data).slice(0, 200)
      throw new Error(`GPTmail ${path} HTTP ${raw.status}: ${snippet}`)
    }

    if (data && typeof data === 'object') {
      const obj = data as Record<string, unknown>
      const auth = obj.auth as Record<string, unknown> | undefined
      const newToken = auth?.token
      if (typeof newToken === 'string' && newToken) {
        this.token = newToken
      }
    }
    return data as T
  }

  async create(): Promise<string> {
    // step 1: 生成「prefix@用户自建域名」作为注册站点提交的邮箱
    const domain = this.domains[Math.floor(Math.random() * this.domains.length)]
    const prefix = this.fixedPrefix || randomEmailPrefix()
    this.address = `${prefix}@${domain}`

    // step 2: 决定查询 GPTmail 时用哪个 inbox 邮箱
    //   玩法 A（私有域名直收）：inboxEmail = address —— 注册地址本身就是 inbox（MX 已解析到 GPTmail）
    //   玩法 B（CF 转发）：     inboxEmail = fixedInboxEmail —— 所有邮件转发到这个固定 inbox
    this.inboxEmail = this.fixedInboxEmail || this.address

    // step 3: GET 收件箱页面 https://mail.chatgpt.org.uk/<inboxEmail>，从 HTML 里解析
    //   服务端 SSR 嵌入的 window.__BROWSER_AUTH（含初始 token）。
    //   比 POST /api/inbox-token 更不容易触发反爬（那个 POST 端点会回 401 "Browser session required"）。
    await this.fetchInitialTokenFromPage()
    if (!this.token) {
      throw new Error('GPTmail 从页面 HTML 解析 __BROWSER_AUTH.token 失败')
    }

    // step 4: 私有域名密码解锁（如果设了密码）—— 私有域名 inbox 在未 unlock 前查 emails 会返回 403
    if (this.privatePassword) {
      await this.unlockPrivateInbox()
    }

    // step 5: 记录 inbox 现有邮件 ID 作为基线，轮询时跳过这些旧邮件，避免历史验证码污染。
    //   不再做全量 clear —— CF 转发模式下多个并发注册共享同一 inbox，
    //   全量删除会误删别的任务待取的验证码。基线方案无副作用、并发安全。
    try {
      const existing = await this.fetchMails()
      for (const mail of existing) {
        const id = String(mail.id ?? '')
        if (id) this.baselineIds.add(id)
      }
      if (this.baselineIds.size > 0) {
        console.log(`[GPTmail] inbox 基线邮件数: ${this.baselineIds.size}（轮询时将跳过）`)
      }
    } catch { /* 基线获取失败不影响后续轮询 */ }

    const mode = this.fixedInboxEmail
      ? `CF 转发 → ${this.inboxEmail}`
      : this.privatePassword ? '私有域名直收（已解锁）' : '私有域名直收（MX→GPTmail）'
    if (this.domains.length > 1) {
      console.log(`[GPTmail] 注册邮箱: ${this.address}  (域名池 ${this.domains.length} 个，模式: ${mode})`)
    } else {
      console.log(`[GPTmail] 注册邮箱: ${this.address}  (模式: ${mode})`)
    }
    return this.address
  }

  /**
   * 通过 GET 页面 HTML 解析 window.__BROWSER_AUTH 初始 token。
   * GPTmail 服务端会在 SSR 时把 `{token,email,expires_at}` 渲染到 HTML 的内联 script 里，
   * 这是浏览器拿到 token 的"零成本"路径，不会触发 /api/inbox-token 的反爬保护。
   */
  private async fetchInitialTokenFromPage(): Promise<void> {
    const origin = new URL(this.baseURL).origin
    const pageUrl = `${origin}/${this.inboxEmail}`

    const pageHeaders: Record<string, string> = {
      'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
      'accept-language': 'zh-CN,zh;q=0.9,en;q=0.8',
      'user-agent': GptMailService.UA,
      'sec-ch-ua': GptMailService.SEC_CH_UA,
      'sec-ch-ua-mobile': '?0',
      'sec-ch-ua-platform': '"Windows"',
      'sec-fetch-dest': 'document',
      'sec-fetch-mode': 'navigate',
      'sec-fetch-site': 'none',
      'sec-fetch-user': '?1',
      'upgrade-insecure-requests': '1'
    }

    const session = this.getSession()
    if (!session) throw new Error('GPTmail TLS SessionClient 不可用（可能正在重建，稍后重试）')
    const raw = await session.get(pageUrl, { headers: pageHeaders })
    if (raw.status < 200 || raw.status >= 300) {
      throw new Error(`GPTmail GET ${pageUrl} HTTP ${raw.status}: ${raw.body.slice(0, 200)}`)
    }

    // 解析 window.__BROWSER_AUTH = { ... }；用括号配平扫描而非非贪婪正则，
    // 避免对象出现嵌套 {} 时被 `\{[\s\S]*?\}` 提前截断导致 JSON 解析失败。
    const jsonText = GptMailService.extractBrowserAuthJson(raw.body)
    if (!jsonText) {
      throw new Error('GPTmail 页面里未找到 window.__BROWSER_AUTH（服务器结构可能已变）')
    }
    let auth: Record<string, unknown>
    try {
      auth = JSON.parse(jsonText)
    } catch (err) {
      throw new Error(`GPTmail __BROWSER_AUTH JSON 解析失败: ${err instanceof Error ? err.message : err}`)
    }
    const token = typeof auth.token === 'string' ? auth.token : ''
    if (!token) {
      throw new Error(`GPTmail __BROWSER_AUTH 缺 token 字段: ${JSON.stringify(auth).slice(0, 200)}`)
    }
    this.token = token
    console.log(`[GPTmail] 已从页面拿到初始 token（email=${auth.email}, exp=${auth.expires_at}）`)
  }

  /**
   * 私有域名密码解锁。
   * GPTmail 私有域名 inbox 在未 unlock 前调用 /api/emails 会返回 403 "private domain password required"。
   * 必须先 POST /api/private-domains/unlock {email, password} 拿到 unlock 后的 token，再轮询邮件。
   */
  private async unlockPrivateInbox(): Promise<void> {
    const lang = 'zh-CN' // 与 official frontend 默认一致
    const resp = await this.request<Record<string, unknown>>(
      `/api/private-domains/unlock?lang=${encodeURIComponent(lang)}`,
      {
        method: 'POST',
        body: JSON.stringify({ email: this.inboxEmail, password: this.privatePassword })
      }
    )
    if (!resp.success) {
      const err = (resp.error as string) || JSON.stringify(resp).slice(0, 200)
      throw new Error(`GPTmail 私有域名解锁失败: ${err}（密码错误？域名未设为私有？）`)
    }
    console.log(`[GPTmail] 私有域名 inbox 解锁成功: ${this.inboxEmail}`)
    // token 已被 request() 内部从 auth.token 自动滚动更新
  }

  getAddress(): string {
    return this.address
  }

  async waitForCode(timeoutSec: number, intervalSec: number, signal?: AbortSignal): Promise<string> {
    if (!this.address) throw new Error('GPTmail 注册邮箱为空，需先调用 create()')
    if (!this.inboxEmail) throw new Error('GPTmail inbox 邮箱为空，需先调用 create()')
    if (!this.token) throw new Error('GPTmail token 为空，需先调用 create()')

    const maxRetries = Math.max(1, Math.floor(timeoutSec / intervalSec))
    // 用 create() 时记录的基线 ID 初始化：跳过注册前就存在于 inbox 的旧邮件
    const checkedIds = new Set<string>(this.baselineIds)
    const userLocal = this.address.toLowerCase().split('@')[0]
    // 私有域名直收模式下，inbox = address，所有邮件 to 必然是 address，严格匹配即可
    const isPrivateDirect = !this.fixedInboxEmail

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      if (signal?.aborted) throw new Error('注册已取消')
      await abortableSleep(intervalSec * 1000, signal)
      try {
        const mails = await this.fetchMails()
        if (attempt === 1 || attempt % 5 === 0) {
          console.log(`[GPTmail] [${attempt}/${maxRetries}] 收件箱(${this.inboxEmail}) 邮件数: ${mails.length}`)
        }
        for (const mail of mails) {
          const id = String(mail.id ?? '')
          if (!id || checkedIds.has(id)) continue
          checkedIds.add(id)

          const subject = String(mail.subject ?? '')
          const content = String(mail.content ?? '')
          const html = String(mail.html_content ?? mail.html ?? '')

          if (isPrivateDirect) {
            // 私有直收：inbox=address，email_address 必然匹配
            const to = String(mail.email_address ?? '').toLowerCase()
            if (to && to !== this.address.toLowerCase()) {
              continue
            }
          } else {
            // CF 转发：email_address=inbox，需要从 subject/body 软匹配本次注册地址，
            //         避免拿到同一 inbox 其他注册的旧验证码
            const blob = `${subject}\n${content}\n${html}`.toLowerCase()
            const matches = blob.includes(this.address.toLowerCase()) || blob.includes(userLocal)
            if (!matches) {
              // 注意：subject/body 可能不含注册地址（部分服务只发"您的验证码"无邮箱回显），
              //       此时若 inbox 里恰好只有这一封新邮件也可能是本次的 —— 但我们保守跳过避免误用
              continue
            }
          }

          const code = this.extractOTP(mail)
          if (code) {
            console.log(`[GPTmail] 提取到验证码: ${code} (from=${mail.from_address ?? ''}, subject=${subject.slice(0, 60)})`)
            // 不再全量 clear inbox：CF 转发模式下多任务共享同一 inbox，
            // 清空会误删别的任务待取的验证码。本次邮件已记入 checkedIds，
            // 后续实例靠 create() 重新捕获基线跳过，已足够避免重复取码。
            return code
          }
        }
      } catch (err) {
        if (attempt % 5 === 0) {
          console.log(`[GPTmail] [${attempt}/${maxRetries}] 查询失败:`, err instanceof Error ? err.message : err)
        }
      }
      if (attempt % 5 === 0) console.log(`[GPTmail] [${attempt}/${maxRetries}] 暂无验证码...`)
    }
    throw new Error(`GPTmail 等待验证码超时 (${timeoutSec}s)`)
  }

  private async fetchMails(): Promise<Array<Record<string, unknown>>> {
    const url = `/api/emails?email=${encodeURIComponent(this.inboxEmail)}`
    const resp = await this.request<Record<string, unknown>>(url)
    if (!resp.success) return []
    const data = resp.data as Record<string, unknown> | undefined
    const arr = data?.emails
    return Array.isArray(arr) ? (arr as Array<Record<string, unknown>>) : []
  }

  private extractOTP(mail: Record<string, unknown>): string {
    // 1) 主题里直接含 6 位数字（"Your code is 123456" 类）
    const subject = String(mail.subject ?? '')
    const subjMatch = subject.match(/(\d{6})/)
    if (subjMatch) return subjMatch[1]

    // 2) 正文（content 是纯文本字段，HAR 里 AWS 验证码就在这里）
    const content = String(mail.content ?? '')
    const c1 = extractCode(content)
    if (c1) return c1

    // 3) HTML 兜底
    const html = String(mail.html_content ?? mail.html ?? '')
    return extractCode(html)
  }
}

// ============ Outlook IMAP ============

export interface OutlookAccount {
  email: string
  password: string
  clientId: string
  refreshToken: string
}

/** 按 ---- 拆分；多出的连字符(N-4)归还前一字段（refreshToken 等 base64url 可能以 '-' 结尾） */
function splitByDashes(line: string): string[] {
  const parts: string[] = []
  const re = /-{4,}/g
  let last = 0
  let m: RegExpExecArray | null
  while ((m = re.exec(line)) !== null) {
    parts.push(line.slice(last, m.index) + '-'.repeat(m[0].length - 4))
    last = m.index + m[0].length
  }
  parts.push(line.slice(last))
  return parts
}

export function parseOutlookLines(data: string): OutlookAccount[] {
  const accounts: OutlookAccount[] = []
  data = data.trim()
  if (!data) return accounts

  const lines = data.split('\n')
  const parseEntry = (entry: string): void => {
    entry = entry.trim()
    if (!entry) return
    const parts = splitByDashes(entry)
    if (parts.length === 4) {
      accounts.push({
        email: parts[0].trim(),
        password: parts[1].trim(),
        clientId: parts[2].trim(),
        refreshToken: parts[3].trim()
      })
    }
  }

  if (lines.length === 1) {
    for (const part of data.split(/\s+/)) parseEntry(part)
  } else {
    for (const line of lines) parseEntry(line)
  }
  return accounts
}

export async function refreshOutlookToken(acc: OutlookAccount): Promise<string> {
  const form = new URLSearchParams({
    client_id: acc.clientId,
    refresh_token: acc.refreshToken,
    grant_type: 'refresh_token',
    scope: 'https://outlook.office.com/IMAP.AccessAsUser.All offline_access'
  })

  const resp = await proxyFetch(
    'https://login.microsoftonline.com/consumers/oauth2/v2.0/token',
    { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: form.toString() }
  )
  const data = (await resp.json()) as Record<string, unknown>
  if (resp.status !== 200) throw new Error(`刷新失败 ${resp.status}: ${JSON.stringify(data).slice(0, 300)}`)
  const token = data.access_token as string
  if (!token) throw new Error('响应中无 access_token')
  return token
}

function buildXOAuth2(email: string, accessToken: string): string {
  const auth = `user=${email}\x01auth=Bearer ${accessToken}\x01\x01`
  return Buffer.from(auth).toString('base64')
}

class IMAPClient {
  private socket: tls.TLSSocket | null = null
  private buffer = ''
  private tag = 0

  async connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      const socket = tls.connect(993, 'outlook.office365.com', { servername: 'outlook.office365.com' })
      const timer = setTimeout(() => {
        socket.destroy()
        reject(new Error('连接超时'))
      }, 15000)

      socket.once('error', (err) => { clearTimeout(timer); reject(err) })
      socket.once('secureConnect', () => {
        clearTimeout(timer)
        this.socket = socket
        this.readLine().then(() => resolve()).catch(reject)
      })
    })
  }

  private readLine(timeoutMs = 30000): Promise<string> {
    return new Promise((resolve, reject) => {
      if (!this.socket) return reject(new Error('未连接'))

      let settled = false
      const timer = setTimeout(() => {
        if (settled) return
        settled = true
        this.socket?.removeListener('data', onData)
        this.socket?.removeListener('error', onError)
        reject(new Error('IMAP readLine 超时'))
      }, timeoutMs)

      const done = (line: string): void => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        this.socket?.removeListener('data', onData)
        this.socket?.removeListener('error', onError)
        resolve(line)
      }

      const onError = (err: Error): void => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        this.socket?.removeListener('data', onData)
        reject(err)
      }

      const check = (): boolean => {
        const idx = this.buffer.indexOf('\r\n')
        if (idx >= 0) {
          const line = this.buffer.slice(0, idx)
          this.buffer = this.buffer.slice(idx + 2)
          done(line)
          return true
        }
        return false
      }
      if (check()) return

      const onData = (chunk: Buffer): void => {
        this.buffer += chunk.toString()
        check()
      }
      this.socket.on('data', onData)
      this.socket.once('error', onError)
    })
  }

  private async sendCommand(cmd: string): Promise<string> {
    if (!this.socket) throw new Error('未连接')
    this.tag++
    const tagStr = `A${String(this.tag).padStart(3, '0')}`
    this.socket.write(`${tagStr} ${cmd}\r\n`)
    return tagStr
  }

  private async readUntilTag(tag: string): Promise<{ lines: string[]; result: string }> {
    const lines: string[] = []
    while (true) {
      const line = await this.readLine()
      if (line.startsWith(`${tag} `)) return { lines, result: line }
      lines.push(line)
    }
  }

  async authenticate(email: string, accessToken: string): Promise<void> {
    const xoauth2 = buildXOAuth2(email, accessToken)
    const tag = await this.sendCommand(`AUTHENTICATE XOAUTH2 ${xoauth2}`)
    const { result } = await this.readUntilTag(tag)
    if (!result.includes('OK')) throw new Error(`认证失败: ${result}`)
    console.log('[IMAP] 认证成功')
    await sleep(800)
  }

  async selectInbox(): Promise<number> {
    for (let retry = 0; retry < 3; retry++) {
      const tag = await this.sendCommand('SELECT INBOX')
      const { lines, result } = await this.readUntilTag(tag)
      if (result.includes('OK')) {
        for (const line of lines) {
          const m = line.match(/\*\s+(\d+)\s+EXISTS/)
          if (m) return parseInt(m[1], 10)
        }
        return 0
      }
      if (retry < 2) {
        console.log(`[IMAP] SELECT INBOX 失败 (${result}), 重试 ${retry + 1}/3...`)
        await sleep((1 + retry) * 1000)
      }
    }
    throw new Error('SELECT INBOX 重试耗尽')
  }

  async fetchLatestBody(seq: number): Promise<string> {
    if (seq <= 0) throw new Error('无效的邮件序号')
    const tag = await this.sendCommand(`FETCH ${seq} (BODY.PEEK[TEXT])`)
    const { lines, result } = await this.readUntilTag(tag)
    if (!result.includes('OK')) throw new Error(`FETCH TEXT 失败: ${result}`)

    const rawLines: string[] = []
    let inBody = false
    for (const line of lines) {
      if (line.includes('FETCH')) { inBody = true; continue }
      if (line === ')') continue
      if (inBody) rawLines.push(line)
    }
    const raw = rawLines.join('\n')

    // 尝试解码 MIME base64
    const parts = raw.split('------=_Part_')
    let decoded = ''
    for (const part of parts) {
      if (part.includes('base64')) {
        const idx = part.indexOf('base64')
        const content = part.slice(idx + 6)
        const b64 = content.replace(/[\s]/g, '')
        try {
          decoded += Buffer.from(b64, 'base64').toString() + ' '
        } catch { /* ignore */ }
      }
    }
    if (decoded) return decoded

    // 整体 base64 解码
    const cleaned = raw.replace(/[\s]/g, '')
    try {
      return Buffer.from(cleaned, 'base64').toString()
    } catch {
      return raw
    }
  }

  close(): void {
    if (this.socket) {
      try { this.socket.write('A999 LOGOUT\r\n') } catch { /* ignore */ }
      this.socket.destroy()
      this.socket = null
    }
  }
}

export async function getInboxCount(acc: OutlookAccount): Promise<number> {
  const accessToken = await refreshOutlookToken(acc)
  const client = new IMAPClient()
  try {
    await client.connect()
    await client.authenticate(acc.email, accessToken)
    return await client.selectInbox()
  } finally {
    client.close()
  }
}

export async function waitForOTP(
  acc: OutlookAccount,
  beforeCount: number,
  timeout: number,
  interval: number,
  signal?: AbortSignal
): Promise<string> {
  console.log(`[Outlook IMAP] 等待验证码, 邮箱=${acc.email}, 发送前邮件数=${beforeCount}`)
  let accessToken = await refreshOutlookToken(acc)
  const maxRetries = Math.floor(timeout / interval)

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    if (signal?.aborted) throw new Error('注册已取消')
    let client: IMAPClient | null = null
    try {
      client = new IMAPClient()
      await client.connect()
      await client.authenticate(acc.email, accessToken)
      const total = await client.selectInbox()

      if (total <= beforeCount) {
        if (attempt % 5 === 0) console.log(`[Outlook IMAP] [${attempt}/${maxRetries}] 暂无新邮件 (当前${total}封)...`)
        await abortableSleep(interval * 1000, signal)
        continue
      }

      for (let i = total; i > beforeCount; i--) {
        try {
          const body = await client.fetchLatestBody(i)
          const code = extractCode(body)
          if (code) {
            console.log(`[Outlook IMAP] 获取到验证码: ${code}`)
            return code
          }
        } catch { /* continue */ }
      }

      if (attempt % 5 === 0) console.log(`[Outlook IMAP] [${attempt}/${maxRetries}] 新邮件中未找到验证码...`)
    } catch (err) {
      if (attempt % 5 === 0) console.log(`[Outlook IMAP] 连接失败:`, err)
      try { accessToken = await refreshOutlookToken(acc) } catch { /* ignore */ }
    } finally {
      client?.close()
    }
    await abortableSleep(interval * 1000, signal)
  }
  throw new Error(`等待验证码超时 (${timeout}s)`)
}

// ============ Proton 邮箱（webview 借壳官方网页，轻量读 DOM 取码） ============

/**
 * Proton 点号别名取码源：用一个 Proton 母邮箱（如 evanbartellchae@protonmail.com），
 * 前端用 dotVariants 生成点号变体（evanbar.tellcha.e@protonmail.com）作为每个账号的注册邮箱，
 * 所有变体都进同一个 Proton 收件箱。读码经由主进程的隐藏 Proton 窗口（见 proton-mail-window.ts），
 * 官方网页负责登录与 PGP 解密，本类只接收前端生成好的具体地址并等待取码。
 */
export class ProtonWebviewService implements TempEmailService {
  /** 本次注册使用的具体邮箱地址（母邮箱或其点号变体，由前端生成传入） */
  private readonly address: string
  /** 日志回调：传入 registrar.this.log 时，取码日志会推送到注册页面日志面板；缺省回退 console */
  private readonly log: (msg: string) => void

  constructor(presetAddress: string, log?: (msg: string) => void) {
    this.address = (presetAddress || '').trim()
    if (!this.address) {
      throw new Error('Proton 邮箱地址为空')
    }
    this.log = log || ((m) => console.log(m))
  }

  async create(): Promise<string> {
    this.log(`[Proton] 使用邮箱: ${this.address}`)
    return this.address
  }

  getAddress(): string {
    return this.address
  }

  async waitForCode(timeoutSec: number, intervalSec: number, signal?: AbortSignal): Promise<string> {
    return waitProtonOtp(this.address, {
      timeoutSec,
      intervalSec,
      signal,
      log: this.log
    })
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms))
}
