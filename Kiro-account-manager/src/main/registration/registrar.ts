import { ModuleClient, SessionClient } from 'tlsclientwrapper'
import { fetch as undiciFetch, ProxyAgent, type RequestInit as UndiciRequestInit } from 'undici'
import { RegistrationConfig } from './config'
import { BrowserIdentity, randomIdentity } from './browser-identity'
import { FingerprintContext, newFPContext, resetPerfTiming, generateFingerprint } from './fingerprint'
import { encryptPassword } from './jwe'
import { refreshAppJSConfig } from './xxtea'
import {
  DEFAULT_UA, DEFAULT_SEC_UA,
  visitorId, awsccc, ubidGen, newUUID, gmtDate,
  extractParam, splitAfter, saveCookies,
  getNestedMap, getNestedStringMap
} from './http-utils'
import {
  TempEmailService, MoEmailService, TempMailPlusService,
  parseOutlookLines, getInboxCount, waitForOTP
} from './email-service'
import { getSystemProxy } from '../proxy/systemProxy'

export type LogFn = (message: string) => void

export interface RegistrationResult {
  status: 'success' | 'failed'
  email: string
  password?: string
  error?: string
  clientId?: string
  clientSecret?: string
  refreshToken?: string
  accessToken?: string
  region?: string
  provider?: string
  verify?: Record<string, unknown>
}

type StepFn = () => Promise<void>

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms))
}

export class Registrar {
  private cfg: RegistrationConfig
  private session: SessionClient | null = null
  private moduleClient: ModuleClient | null = null
  private cookies = new Map<string, string>()
  private identity: BrowserIdentity
  private fpCtx: FingerprintContext
  private vid: string

  private email = ''
  private emailSvc: TempEmailService | null = null
  private clientId = ''
  private clientSecret = ''
  private deviceCode = ''
  private userCode = ''
  private workflowHandle = ''
  private workflowId = ''
  private workflowState = ''
  private ubid = ''
  private regCode = ''
  private signState = ''
  private authCode = ''
  private ssoState = ''
  private wdcCSRFToken = ''
  private ssoToken = ''
  private outlookMailCount = 0

  private log: LogFn
  private abortController = new AbortController()

  constructor(cfg: RegistrationConfig, log?: LogFn) {
    this.cfg = cfg
    this.identity = randomIdentity()
    this.fpCtx = newFPContext(this.identity)
    this.vid = visitorId()
    this.log = log || ((msg) => console.log(msg))
  }

  /** 中止当前注册流程 */
  abort(): void {
    this.abortController.abort()
  }

  private checkAborted(): void {
    if (this.abortController.signal.aborted) throw new Error('注册已取消')
  }

  /** TLS SessionClient 选项 */
  private get sessionOpts() {
    const proxyUrl = process.env.HTTPS_PROXY || process.env.https_proxy || process.env.HTTP_PROXY || process.env.http_proxy || getSystemProxy() || undefined
    return {
      tlsClientIdentifier: 'chrome_144' as const,
      timeoutSeconds: 60,
      followRedirects: true,
      insecureSkipVerify: true,
      proxyUrl
    }
  }

  /** 初始化 TLS 客户端 */
  private async initTlsClient(): Promise<void> {
    // 确保 tls-client 共享库在临时目录可用（打包后 resources/ 有预置 dll）
    this.ensureTlsLibInTmpDir()
    // 不传 customLibraryPath，让 tlsclientwrapper 自动从 tmpdir 找 dll
    this.moduleClient = new ModuleClient()
    await this.moduleClient.open()
    this.log('[TLS] open() completed, pool stats: ' + JSON.stringify(this.moduleClient.getPoolStats()))
    this.session = new SessionClient(this.moduleClient, this.sessionOpts)
  }

  /** 确保 tls-client 共享库在临时目录可用 */
  private ensureTlsLibInTmpDir(): void {
    const os = require('os')
    const path = require('path')
    const fs = require('fs')
    const platform = os.platform()
    const arch = os.arch()
    let filename = 'tls-client-xgo-1.14.0-'
    if (platform === 'win32') {
      filename += (arch.includes('64') ? 'windows-amd64' : 'windows-386') + '.dll'
    } else if (platform === 'darwin') {
      filename += (arch === 'arm64' ? 'darwin-arm64' : 'darwin-amd64') + '.dylib'
    } else {
      filename += (arch === 'arm64' ? 'linux-arm64' : 'linux-amd64') + '.so'
    }
    const tmpPath = path.join(os.tmpdir(), filename)
    // 已存在则跳过
    if (fs.existsSync(tmpPath)) {
      this.log('[TLS] Library already exists in tmpdir: ' + tmpPath)
      return
    }
    // 从 resources/ 复制到临时目录（打包后 process.resourcesPath 指向 resources/）
    const resourcePath = path.join(process.resourcesPath || '', filename)
    if (fs.existsSync(resourcePath)) {
      this.log('[TLS] Copying library from resources to tmpdir: ' + resourcePath + ' -> ' + tmpPath)
      fs.copyFileSync(resourcePath, tmpPath)
      return
    }
    this.log('[TLS] Library not found in resources, will download from GitHub. Searched: ' + resourcePath)
  }

  private async rebuildTlsClient(): Promise<void> {
    try { await this.session?.destroySession() } catch { /* ignore */ }
    this.session = null
    if (this.moduleClient) {
      try { await this.moduleClient.terminate() } catch { /* ignore */ }
      this.moduleClient = null
    }
    await this.initTlsClient()
  }

  /**
   * 用 undici 直接 fetch 静态资源（如 AWS signin app.js），绕过 tls-client。
   * 原因：tls-client 的 dll 是进程级单例，失败请求会污染其全局状态，
   * 导致后续重建 SessionClient 后仍报 "no tls client for modification check"。
   * 静态资源不需要 TLS 指纹伪装，直接用 Node/undici fetch 即可。
   */
  private async fetchAppJS(url: string, init?: RequestInit): Promise<Response> {
    const proxyUrl = process.env.HTTPS_PROXY || process.env.https_proxy
      || process.env.HTTP_PROXY || process.env.http_proxy
      || getSystemProxy() || undefined
    if (proxyUrl) {
      const agent = new ProxyAgent({ uri: proxyUrl, requestTls: { rejectUnauthorized: false } })
      const resp = await undiciFetch(url, { ...(init as UndiciRequestInit), dispatcher: agent })
      return resp as unknown as Response
    }
    return await fetch(url, init)
  }

  private isRecoverableTlsClientError(err: unknown): boolean {
    if (!(err instanceof Error)) return false
    return err.message.includes('EOF')
      || err.message.includes('no tls client for modification check')
      || err.message.includes('failed to modify existing client')
  }

  /** 清理 TLS 客户端资源 */
  private async cleanup(): Promise<void> {
    if (this.session) {
      try { await this.session.destroySession() } catch { /* ignore */ }
      this.session = null
    }
    if (this.moduleClient) {
      try {
        await this.moduleClient.terminate()
      } catch (err: unknown) {
        // piscina 线程池终止时可能有排队任务被中止，属于预期行为
        const msg = err instanceof Error ? err.message : String(err)
        if (!msg.includes('aborted') && !msg.includes('terminated')) {
          console.error('Error during ModuleClient termination:', err)
        }
      }
      this.moduleClient = null
    }
  }

  /** 公共销毁方法，供外部调用释放资源 */
  async destroy(): Promise<void> {
    await this.cleanup()
  }

  // ============ HTTP 工具方法 ============

  private cookieString(): string {
    return Array.from(this.cookies.entries()).map(([k, v]) => `${k}=${v}`).join('; ')
  }

  private buildHeaders(referer: string, origin: string): Record<string, string> {
    const h: Record<string, string> = {
      'Accept': 'application/json, text/plain, */*',
      'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
      'Accept-Encoding': 'gzip, deflate, br',
      'Content-Type': 'application/json',
      'User-Agent': DEFAULT_UA,
      'sec-ch-ua': DEFAULT_SEC_UA,
      'sec-ch-ua-mobile': '?0',
      'sec-ch-ua-platform': '"Windows"',
      'sec-fetch-dest': 'empty',
      'sec-fetch-mode': 'cors',
      'sec-fetch-site': 'same-origin'
    }
    if (referer) h['Referer'] = referer
    if (origin) h['Origin'] = origin
    if (this.cookies.size > 0) h['Cookie'] = this.cookieString()
    return h
  }

  private buildProfileHeaders(referer: string): Record<string, string> {
    const h: Record<string, string> = {
      'Accept': '*/*',
      'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
      'Content-Type': 'application/json;charset=UTF-8',
      'User-Agent': DEFAULT_UA,
      'Origin': this.cfg.profileBase,
      'Referer': referer,
      'sec-ch-ua': DEFAULT_SEC_UA,
      'sec-ch-ua-mobile': '?0',
      'sec-ch-ua-platform': '"Windows"',
      'sec-fetch-dest': 'empty',
      'sec-fetch-mode': 'cors',
      'sec-fetch-site': 'same-origin',
      'priority': 'u=1, i'
    }
    const keys = ['awsccc', 'aws-user-profile-ubid', 'i18next']
    if (this.cookies.has('awsd2c-token')) keys.push('awsd2c-token', 'awsd2c-token-c')
    const parts = keys.filter((k) => this.cookies.has(k)).map((k) => `${k}=${this.cookies.get(k)}`)
    if (parts.length) h['Cookie'] = parts.join('; ')
    return h
  }

  private async doGet(url: string, headers: Record<string, string>): Promise<{ body: string; status: number; headers: Record<string, string | string[]> }> {
    if (!this.session) throw new Error('TLS 客户端未初始化')
    try {
      const resp = await this.session.get(url, { headers })
      return { body: resp.body || '', status: resp.status, headers: (resp.headers || {}) as Record<string, string | string[]> }
    } catch (err: unknown) {
      if (this.isRecoverableTlsClientError(err)) {
        this.log('[TLS] Recoverable GET error, rebuilding TLS client: ' + (err instanceof Error ? err.message : String(err)))
        await this.rebuildTlsClient()
        const resp = await this.session!.get(url, { headers })
        return { body: resp.body || '', status: resp.status, headers: (resp.headers || {}) as Record<string, string | string[]> }
      }
      throw err
    }
  }

  private async doPost(url: string, payload: unknown, headers: Record<string, string>): Promise<{ body: string; status: number; headers: Record<string, string | string[]> }> {
    if (!this.session) throw new Error('TLS 客户端未初始化')
    const body = JSON.stringify(payload)
    try {
      const resp = await this.session.post(url, body, { headers })
      return { body: resp.body || '', status: resp.status, headers: (resp.headers || {}) as Record<string, string | string[]> }
    } catch (err: unknown) {
      if (this.isRecoverableTlsClientError(err)) {
        this.log('[TLS] Recoverable POST error, rebuilding TLS client: ' + (err instanceof Error ? err.message : String(err)))
        await this.rebuildTlsClient()
        const resp = await this.session!.post(url, body, { headers })
        return { body: resp.body || '', status: resp.status, headers: (resp.headers || {}) as Record<string, string | string[]> }
      }
      throw err
    }
  }

  private parseBody(body: string): Record<string, unknown> {
    try { return JSON.parse(body) } catch { return {} }
  }

  private async fetchD2CToken(origin: string, referer: string): Promise<void> {
    const headers: Record<string, string> = {
      'Accept': '*/*', 'Content-Type': 'application/json',
      'User-Agent': DEFAULT_UA, 'Origin': origin, 'Referer': referer,
      'sec-ch-ua': DEFAULT_SEC_UA, 'sec-ch-ua-mobile': '?0',
      'sec-ch-ua-platform': '"Windows"', 'sec-fetch-dest': 'empty',
      'sec-fetch-mode': 'cors', 'sec-fetch-site': 'cross-site', 'priority': 'u=1, i'
    }
    const parts: string[] = []
    if (this.cookies.has('awsccc')) parts.push('awsccc=' + this.cookies.get('awsccc'))
    if (this.cookies.has('awsd2c-token')) {
      const old = this.cookies.get('awsd2c-token')!
      parts.push('awsd2c-token=' + old, 'awsd2c-token-c=' + old)
    }
    if (parts.length) headers['Cookie'] = parts.join('; ')

    const payload: Record<string, string> = {}
    if (this.cookies.has('awsd2c-token')) payload.token = this.cookies.get('awsd2c-token')!

    const resp = await this.doPost('https://vs.aws.amazon.com/token', payload, headers)
    saveCookies(this.cookies, resp.headers as Record<string, string | string[] | undefined>)
    const data = this.parseBody(resp.body)
    const tok = data.token as string
    if (tok) {
      this.cookies.set('awsd2c-token', tok)
      this.cookies.set('awsd2c-token-c', tok)
      // 从 JWT 中提取 visitor ID
      const jwtParts = tok.split('.')
      if (jwtParts.length >= 2) {
        try {
          const decoded = JSON.parse(Buffer.from(jwtParts[1], 'base64url').toString())
          if (decoded.vid) this.vid = decoded.vid
        } catch { /* ignore */ }
      }
    }
  }

  // ============ 指纹生成 ============

  private genFP(pageType: string, eventType: string, emailLen: number, emailAddr: string): string {
    return this.genFPWithTime(pageType, eventType, 0, emailLen, emailAddr)
  }

  private genFPWithTime(pageType: string, eventType: string, timeOnPage: number, emailLen: number, emailAddr: string): string {
    const did = this.cfg.directoryId
    let loc = '', ref = ''

    switch (pageType) {
      case 'signin':
        loc = `${this.cfg.signinBase}/platform/${did}/login?workflowStateHandle=${this.workflowHandle}`
        break
      case 'signup':
        loc = `${this.cfg.signinBase}/platform/${did}/signup?workflowStateHandle=${this.workflowHandle}`
        break
      default: // profile
        if (eventType === 'PageSubmit') {
          loc = `${this.cfg.profileBase}/?workflowID=${this.workflowId}#/signup/enter-email`
        } else {
          loc = `${this.cfg.profileBase}/?workflowID=${this.workflowId}#/signup/start`
        }
        if (!this.workflowId) loc = this.cfg.profileBase + '/'
    }

    if (pageType === 'profile') {
      ref = `${this.cfg.signinBase}/platform/${did}/signup?workflowStateHandle=${this.workflowHandle}`
    } else {
      ref = this.cfg.viewBase + '/'
    }

    return generateFingerprint(this.identity, loc, ref, this.fpCtx, pageType, eventType, timeOnPage, emailLen, emailAddr)
  }

  // ============ 注册步骤 ============

  private async step1OIDC(): Promise<void> {
    this.log('[1] OIDC 注册')
    const payload = {
      clientName: 'Amazon Q Developer for command line',
      clientType: 'public',
      scopes: ['codewhisperer:completions', 'codewhisperer:analysis', 'codewhisperer:conversations', 'codewhisperer:transformations', 'codewhisperer:taskassist']
    }
    const headers = { 'Content-Type': 'application/json' }

    let resp: { body: string; status: number; headers: Record<string, string | string[]> } | null = null
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        resp = await this.doPost(this.cfg.oidcBase + '/client/register', payload, headers)
        if (resp.status === 200) break
      } catch (err: unknown) {
        if (attempt < 2) {
          this.log(`[1] OIDC 重试 (${attempt + 1}/3)...`)
          await sleep(2000 * (attempt + 1))
          await this.rebuildTlsClient()
          continue
        }
        throw err
      }
    }
    if (!resp) throw new Error('OIDC 注册失败: 所有重试均失败')
    const data = this.parseBody(resp.body)
    this.clientId = (data.clientId as string) || ''
    this.clientSecret = (data.clientSecret as string) || ''
    if (!this.clientId) throw new Error(`OIDC 注册失败: ${resp.body.slice(0, 200)}`)
  }

  private async step2Device(): Promise<void> {
    this.log('[2] 设备授权')
    const resp = await this.doPost(this.cfg.oidcBase + '/device_authorization', {
      clientId: this.clientId, clientSecret: this.clientSecret,
      startUrl: this.cfg.startURL
    }, { 'Content-Type': 'application/json' })
    const data = this.parseBody(resp.body)
    this.deviceCode = (data.deviceCode as string) || ''
    this.userCode = (data.userCode as string) || ''
    this.log(`user_code=${this.userCode}`)
  }

  private async step3Email(): Promise<void> {
    if (this.cfg.manualMode) return // 手动模式在外部设置

    if (this.cfg.useOutlook && this.cfg.outlookData) {
      this.log('[3] 使用 Outlook 邮箱')
      const accounts = parseOutlookLines(this.cfg.outlookData)
      if (accounts.length === 0) throw new Error('无可用的 Outlook 账号')
      const acc = accounts[Math.floor(Math.random() * accounts.length)]
      this.email = acc.email
      this.log(`email=${this.email}`)
      return
    }

    if (this.cfg.useTempMailPlus) {
      this.log('[3] 使用自建域名邮箱 (TempMail.Plus)')
      if (!this.cfg.tempMailPlusEmail || !this.cfg.tempMailPlusEpin || !this.cfg.tempMailPlusDomain) {
        throw new Error('TempMail.Plus 配置不完整')
      }
      this.emailSvc = new TempMailPlusService(
        this.cfg.tempMailPlusEmail, this.cfg.tempMailPlusEpin, this.cfg.tempMailPlusDomain
      )
      this.email = await this.emailSvc.create()
      if (!this.email) throw new Error('生成邮箱地址失败')
      this.log(`email=${this.email}`)
      return
    }

    this.log('[3] 创建临时邮箱')
    if (!this.cfg.moEmailBaseURL) throw new Error('MoEmail 未配置')
    this.emailSvc = new MoEmailService(this.cfg.moEmailBaseURL, this.cfg.moEmailAPIKey)
    this.email = await this.emailSvc.create()
    if (!this.email) throw new Error('创建临时邮箱失败')
    this.log(`email=${this.email}`)
  }

  private async step4Portal(): Promise<void> {
    this.log('[4] Portal 初始化')
    this.cookies.set('awsccc', awsccc())
    const redirect = `${this.cfg.viewBase}/start/#/device?user_code=${this.userCode}`
    const url = `${this.cfg.portalBase}/login?directory_id=view&redirect_url=${redirect}`

    const h: Record<string, string> = {
      'Accept': 'application/json, text/plain, */*',
      'Content-Type': 'application/json',
      'Origin': this.cfg.viewBase,
      'Referer': this.cfg.viewBase + '/',
      'User-Agent': DEFAULT_UA
    }
    const resp = await this.doGet(url, h)
    saveCookies(this.cookies, resp.headers as Record<string, string | string[] | undefined>)
    const data = this.parseBody(resp.body)

    const rurl = (data.redirectUrl as string) || ''
    if (rurl.includes('workflowStateHandle=')) {
      this.workflowHandle = splitAfter(rurl, 'workflowStateHandle=')
    }
    if (data.csrfToken) this.cookies.set('loginCsrfToken', data.csrfToken as string)
    if (!this.workflowHandle) throw new Error('Portal 未返回 workflow handle')

    const loginURL = `${this.cfg.signinBase}/platform/${this.cfg.directoryId}/login?workflowStateHandle=${this.workflowHandle}`
    await this.fetchD2CToken(this.cfg.signinBase, loginURL)
  }

  private async step5WorkflowInit(): Promise<void> {
    this.log('[5] 工作流初始化')
    const api = `${this.cfg.signinBase}/platform/${this.cfg.directoryId}/api/execute`
    const ref = `${this.cfg.signinBase}/platform/${this.cfg.directoryId}/login?workflowStateHandle=${this.workflowHandle}`

    let fp = this.genFP('signin', 'first_load', 0, '')
    let rid = newUUID()
    let h = this.buildHeaders(ref, this.cfg.signinBase)
    h['x-amzn-requestid'] = rid; h['x-amz-date'] = gmtDate(); h['priority'] = 'u=1, i'

    let resp = await this.doPost(api, {
      stepId: '', workflowStateHandle: this.workflowHandle,
      inputs: [{ input_type: 'FingerPrintRequestInput', fingerPrint: fp }],
      requestId: rid
    }, h)
    saveCookies(this.cookies, resp.headers as Record<string, string | string[] | undefined>)
    let data = this.parseBody(resp.body)
    if (data.workflowStateHandle) this.workflowHandle = data.workflowStateHandle as string

    if (data.stepId === 'start') {
      fp = this.genFP('signin', 'PageLoad', 0, '')
      rid = newUUID()
      h = this.buildHeaders(ref, this.cfg.signinBase)
      h['x-amzn-requestid'] = rid; h['x-amz-date'] = gmtDate(); h['priority'] = 'u=1, i'

      resp = await this.doPost(api, {
        stepId: 'start', workflowStateHandle: this.workflowHandle,
        inputs: [{ input_type: 'FingerPrintRequestInput', fingerPrint: fp }],
        requestId: rid
      }, h)
      saveCookies(this.cookies, resp.headers as Record<string, string | string[] | undefined>)
      data = this.parseBody(resp.body)
      if (data.workflowStateHandle) this.workflowHandle = data.workflowStateHandle as string
    }
  }

  private async step6SubmitEmail(): Promise<'signup' | 'login'> {
    this.log(`[6] 提交邮箱 ${this.email}`)
    const api = `${this.cfg.signinBase}/platform/${this.cfg.directoryId}/api/execute`
    const ref = `${this.cfg.signinBase}/platform/${this.cfg.directoryId}/login?workflowStateHandle=${this.workflowHandle}`
    const fp = this.genFP('signin', 'PageSubmit', this.email.length, this.email)
    const rid = newUUID()
    const h = this.buildHeaders(ref, this.cfg.signinBase)
    h['x-amzn-requestid'] = rid; h['x-amz-date'] = gmtDate(); h['priority'] = 'u=1, i'

    const resp = await this.doPost(api, {
      stepId: 'get-identity-user', workflowStateHandle: this.workflowHandle,
      actionId: 'SUBMIT',
      inputs: [
        { input_type: 'UserRequestInput', username: this.email },
        { input_type: 'ApplicationTypeRequestInput', applicationType: 'SSO_INDIVIDUAL_ID' },
        {
          input_type: 'UserEventRequestInput', directoryId: this.cfg.directoryId,
          userName: this.email,
          userEvents: [{ input_type: 'UserEvent', eventType: 'PAGE_SUBMIT', pageName: 'IDENTIFICATION', timeSpentOnPage: 5000 }]
        },
        { input_type: 'FingerPrintRequestInput', fingerPrint: fp }
      ],
      visitorId: this.vid, requestId: rid
    }, h)
    saveCookies(this.cookies, resp.headers as Record<string, string | string[] | undefined>)
    const data = this.parseBody(resp.body)
    if (data.workflowStateHandle) this.workflowHandle = data.workflowStateHandle as string

    if (resp.status === 400) return 'signup'
    if (resp.status === 200) return 'login'
    throw new Error(`提交邮箱失败: ${resp.status} - ${resp.body.slice(0, 200)}`)
  }

  private async step7Signup(): Promise<void> {
    this.log('[7] 注册 (SIGNUP)')
    const api = `${this.cfg.signinBase}/platform/${this.cfg.directoryId}/api/execute`
    const ref = `${this.cfg.signinBase}/platform/${this.cfg.directoryId}/login?workflowStateHandle=${this.workflowHandle}`
    const fp = this.genFP('signup', 'PageSubmit', 0, '')
    const rid = newUUID()
    const h = this.buildHeaders(ref, this.cfg.signinBase)
    h['x-amzn-requestid'] = rid; h['x-amz-date'] = gmtDate(); h['priority'] = 'u=1, i'

    const resp = await this.doPost(api, {
      stepId: 'get-identity-user', workflowStateHandle: this.workflowHandle,
      actionId: 'SIGNUP',
      inputs: [
        { input_type: 'UserRequestInput', username: this.email },
        { input_type: 'FingerPrintRequestInput', fingerPrint: fp }
      ],
      visitorId: this.vid, requestId: rid
    }, h)
    saveCookies(this.cookies, resp.headers as Record<string, string | string[] | undefined>)
    const data = this.parseBody(resp.body)
    const redir = data.redirect as Record<string, unknown> | undefined
    const rurl = redir?.url as string
    if (rurl?.includes('workflowStateHandle=')) {
      this.workflowHandle = splitAfter(rurl, 'workflowStateHandle=')
    }
  }

  private async step7_5SignupInit(): Promise<void> {
    this.log('[7.5] Signup API 初始化')
    const api = `${this.cfg.signinBase}/platform/${this.cfg.directoryId}/signup/api/execute`
    const ref = `${this.cfg.signinBase}/platform/${this.cfg.directoryId}/signup?workflowStateHandle=${this.workflowHandle}`

    let fp = this.genFP('signup', 'first_load', 0, '')
    let rid = newUUID()
    let h = this.buildHeaders(ref, this.cfg.signinBase)
    h['x-amzn-requestid'] = rid; h['x-amz-date'] = gmtDate(); h['priority'] = 'u=1, i'

    let resp = await this.doPost(api, {
      stepId: '', workflowStateHandle: this.workflowHandle,
      inputs: [
        { input_type: 'UserRequestInput', username: this.email },
        { input_type: 'FingerPrintRequestInput', fingerPrint: fp }
      ],
      visitorId: this.vid, requestId: rid
    }, h)
    saveCookies(this.cookies, resp.headers as Record<string, string | string[] | undefined>)
    let data = this.parseBody(resp.body)
    if (data.workflowStateHandle) this.workflowHandle = data.workflowStateHandle as string
    if (data.stepId !== 'start') throw new Error(`Signup init 返回意外 stepId: ${data.stepId}, resp status: ${resp.status}, body: ${resp.body.substring(0, 200)}`)

    fp = this.genFP('signup', 'PageLoad', 0, '')
    rid = newUUID()
    h = this.buildHeaders(ref, this.cfg.signinBase)
    h['x-amzn-requestid'] = rid; h['x-amz-date'] = gmtDate(); h['priority'] = 'u=1, i'

    resp = await this.doPost(api, {
      stepId: 'start', workflowStateHandle: this.workflowHandle,
      inputs: [
        { input_type: 'UserRequestInput', username: this.email },
        { input_type: 'FingerPrintRequestInput', fingerPrint: fp }
      ],
      visitorId: this.vid, requestId: rid
    }, h)
    saveCookies(this.cookies, resp.headers as Record<string, string | string[] | undefined>)
    data = this.parseBody(resp.body)
    if (data.workflowStateHandle) this.workflowHandle = data.workflowStateHandle as string
    const redir = data.redirect as Record<string, unknown> | undefined
    const rurl = redir?.url as string
    if (rurl?.includes('workflowID=')) {
      let wid = splitAfter(rurl, 'workflowID=')
      const hashIdx = wid.indexOf('#')
      if (hashIdx >= 0) wid = wid.slice(0, hashIdx)
      this.workflowId = wid
    }
    if (!this.workflowId) throw new Error('Signup init 未返回 workflowID')
  }

  private async step7_8ProfileInit(): Promise<void> {
    this.log('[7.8] Profile 页面初始化')
    this.ubid = ubidGen()
    this.cookies.set('aws-user-profile-ubid', this.ubid)
    this.cookies.set('i18next', 'zh-CN')
    if (!this.cookies.has('awsccc')) this.cookies.set('awsccc', awsccc())

    const url = `${this.cfg.profileBase}/?workflowID=${this.workflowId}`
    const resp = await this.doGet(url, {
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'User-Agent': DEFAULT_UA,
      'sec-fetch-dest': 'document', 'sec-fetch-mode': 'navigate'
    })
    saveCookies(this.cookies, resp.headers as Record<string, string | string[] | undefined>)
    resetPerfTiming(this.fpCtx)
    await this.fetchD2CToken(this.cfg.profileBase, url)
  }

  private async step8ProfileStart(): Promise<void> {
    this.log('[8] Profile 启动')
    const ref = `${this.cfg.profileBase}/?workflowID=${this.workflowId}`
    const fp = this.genFP('profile', 'PageLoad', 0, '')

    const resp = await this.doPost(this.cfg.profileBase + '/api/start', {
      workflowID: this.workflowId,
      browserData: {
        attributes: {
          fingerprint: fp,
          eventTimestamp: new Date().toISOString().replace(/\.\d{3}Z$/, '.000Z'),
          timeSpentOnPage: '38', eventType: 'PageLoad',
          ubid: this.ubid, visitorId: this.vid
        },
        cookies: {}
      }
    }, this.buildProfileHeaders(ref))
    const data = this.parseBody(resp.body)
    this.workflowState = (data.workflowState as string) || ''
    if (!this.workflowState) throw new Error(`Profile start 未返回 workflowState: ${resp.body.slice(0, 200)}`)
  }

  private async step9SendOTP(): Promise<void> {
    this.log('[9] 发送验证码')

    if (this.cfg.useOutlook && this.cfg.outlookData) {
      const accounts = parseOutlookLines(this.cfg.outlookData)
      const acc = accounts.find((a) => a.email === this.email)
      if (acc) {
        try {
          this.outlookMailCount = await getInboxCount(acc)
          this.log(`发送前邮件数: ${this.outlookMailCount}`)
        } catch (err) {
          this.log(`获取邮件数量失败: ${err}, 默认为0`)
        }
      }
    }

    const ref = `${this.cfg.profileBase}/?workflowID=${this.workflowId}`
    const timeOnPage = 5000 + Math.floor(Math.random() * 3001)
    const fp = this.genFPWithTime('profile', 'PageSubmit', timeOnPage, this.email.length, this.email)
    const tsp = String(timeOnPage)

    const payload = {
      workflowState: this.workflowState,
      email: this.email,
      browserData: {
        attributes: {
          fingerprint: fp,
          eventTimestamp: new Date().toISOString().replace(/\.\d{3}Z$/, '.000Z'),
          timeSpentOnPage: tsp, pageName: 'EMAIL_COLLECTION',
          eventType: 'PageSubmit', ubid: this.ubid, visitorId: this.vid
        },
        cookies: {}
      }
    }

    const resp = await this.doPost(this.cfg.profileBase + '/api/send-otp', payload, this.buildProfileHeaders(ref))
    if (resp.status !== 200) throw new Error(`send-otp 失败 (${resp.status}), body: ${resp.body.substring(0, 300)}`)
    this.log('验证码已发送')
  }

  private async step10GetOTP(): Promise<string> {
    if (this.cfg.manualMode) throw new Error('手动模式需外部提供验证码')

    this.log('[10] 等待验证码')
    if (this.cfg.useOutlook && this.cfg.outlookData) {
      const accounts = parseOutlookLines(this.cfg.outlookData)
      const acc = accounts.find((a) => a.email === this.email)
      if (!acc) throw new Error('未找到对应 Outlook 账号')
      return await waitForOTP(acc, this.outlookMailCount, 120, 5)
    }
    if (!this.emailSvc) throw new Error('邮箱服务未初始化')
    return await this.emailSvc.waitForCode(120, 3)
  }

  private async step11CreateIdentity(otp: string): Promise<void> {
    this.log('[11] 创建身份')
    const ref = `${this.cfg.profileBase}/?workflowID=${this.workflowId}`
    const fp = this.genFP('profile', 'EmailVerification', 0, '')

    const resp = await this.doPost(this.cfg.profileBase + '/api/create-identity', {
      workflowState: this.workflowState,
      userData: { email: this.email, fullName: this.cfg.fullName },
      otpCode: otp,
      browserData: {
        attributes: {
          fingerprint: fp,
          eventTimestamp: new Date().toISOString().replace(/\.\d{3}Z$/, '.000Z'),
          timeSpentOnPage: '45000', pageName: 'EMAIL_VERIFICATION',
          eventType: 'EmailVerification', ubid: this.ubid, visitorId: this.vid
        },
        cookies: {}
      }
    }, this.buildProfileHeaders(ref))
    const data = this.parseBody(resp.body)
    this.regCode = (data.registrationCode as string) || ''
    this.signState = (data.signInState as string) || ''
    if (!this.regCode) throw new Error(`create-identity 未返回 registrationCode: ${resp.body.slice(0, 200)}`)
  }

  private async step12SetPassword(): Promise<void> {
    this.log('[12] 设置密码')
    const api = `${this.cfg.signinBase}/platform/${this.cfg.directoryId}/signup/api/execute`
    const ref = `${this.cfg.signinBase}/platform/${this.cfg.directoryId}/signup?registrationCode=${this.regCode}&state=${this.signState}`
    let fp = this.genFP('signup', 'PageSubmit', 0, '')

    // 12a: 获取加密公钥
    let rid = newUUID()
    let h = this.buildHeaders(ref, this.cfg.signinBase)
    h['x-amzn-requestid'] = rid; h['x-amz-date'] = gmtDate(); h['priority'] = 'u=1, i'

    let resp = await this.doPost(api, {
      stepId: '', state: this.signState,
      inputs: [
        { input_type: 'UserRegistrationRequestInput', registrationCode: this.regCode, state: this.signState },
        { input_type: 'FingerPrintRequestInput', fingerPrint: fp }
      ],
      requestId: rid
    }, h)
    saveCookies(this.cookies, resp.headers as Record<string, string | string[] | undefined>)
    let data = this.parseBody(resp.body)
    this.workflowHandle = (data.workflowStateHandle as string) || ''

    const encCtx = getNestedMap(data as Record<string, unknown>, 'workflowResponseData', 'encryptionContextResponse')
    const pubKeyMap = encCtx ? getNestedStringMap(encCtx, 'publicKey') : null
    if (!pubKeyMap?.n) throw new Error(`未获取到加密公钥: ${resp.body.slice(0, 200)}`)

    const issuer = (encCtx?.issuer as string) || 'signin'
    const audience = (encCtx?.audience as string) || 'AWSPasswordService'
    const region = (encCtx?.region as string) || 'us-east-1'

    const encrypted = encryptPassword(this.cfg.password, pubKeyMap, issuer, audience, region)

    // 12b: 提交密码
    fp = this.genFP('signup', 'PageSubmit', 0, '')
    rid = newUUID()
    h = this.buildHeaders(ref, this.cfg.signinBase)
    h['x-amzn-requestid'] = rid; h['x-amz-date'] = gmtDate(); h['priority'] = 'u=1, i'

    resp = await this.doPost(api, {
      stepId: 'get-new-password-for-password-creation',
      workflowStateHandle: this.workflowHandle, actionId: 'SUBMIT',
      inputs: [
        { input_type: 'PasswordRequestInput', password: encrypted, successfullyEncrypted: 'SUCCESSFUL' },
        { input_type: 'UserRequestInput', username: this.email },
        { input_type: 'FingerPrintRequestInput', fingerPrint: fp }
      ],
      visitorId: this.vid, requestId: rid
    }, h)
    saveCookies(this.cookies, resp.headers as Record<string, string | string[] | undefined>)
    data = this.parseBody(resp.body)

    const redir = data.redirect as Record<string, unknown> | undefined
    const rurl = redir?.url as string
    if (!rurl) throw new Error(`密码设置未返回 redirect: ${resp.body.slice(0, 200)}`)

    const wh = extractParam(rurl, 'workflowStateHandle')
    const st = extractParam(rurl, 'state')
    const rh = extractParam(rurl, 'workflowResultHandle')
    await this.completeSignup(wh, st, rh)
  }

  private async completeSignup(wh: string, state: string, rh: string): Promise<void> {
    this.log('[12.5] 完成注册工作流')
    const api = `${this.cfg.signinBase}/platform/${this.cfg.directoryId}/api/execute`
    const ref = `${this.cfg.signinBase}/platform/${this.cfg.directoryId}/login?workflowStateHandle=${wh}&state=${state}&workflowResultHandle=${rh}`
    const fp = this.genFP('signin', 'PageLoad', 0, '')
    const rid = newUUID()
    const h = this.buildHeaders(ref, this.cfg.signinBase)
    h['x-amzn-requestid'] = rid; h['x-amz-date'] = gmtDate(); h['priority'] = 'u=1, i'

    const resp = await this.doPost(api, {
      stepId: '', workflowStateHandle: wh,
      workflowResultHandle: rh, state,
      inputs: [
        { input_type: 'UserRequestInput', username: this.email },
        { input_type: 'FingerPrintRequestInput', fingerPrint: fp }
      ],
      visitorId: this.vid, requestId: rid
    }, h)
    saveCookies(this.cookies, resp.headers as Record<string, string | string[] | undefined>)
    const data = this.parseBody(resp.body)
    if (data.stepId !== 'end-of-workflow-success') throw new Error(`完成工作流失败: ${data.stepId}`)

    const redir = data.redirect as Record<string, unknown> | undefined
    const rurl = redir?.url as string
    if (rurl) {
      this.authCode = extractParam(rurl, 'workflowResultHandle')
      this.ssoState = extractParam(rurl, 'state')
      this.wdcCSRFToken = extractParam(rurl, 'wdc_csrf_token')
    }
  }

  // ============ SSO 授权 (Step12.8-13) ============

  private async step12_8SSOWorkflow(): Promise<void> {
    this.log('[12.8] SSO 工作流')
    const redirectURL = encodeURIComponent(this.cfg.viewBase + '/start/#/')
    const loginURL = `${this.cfg.portalBase}/login?directory_id=view&redirect_url=${redirectURL}`

    const h: Record<string, string> = {
      'Accept': '*/*', 'User-Agent': DEFAULT_UA,
      'Origin': this.cfg.viewBase, 'Referer': this.cfg.viewBase + '/',
      'sec-ch-ua': DEFAULT_SEC_UA, 'sec-ch-ua-mobile': '?0',
      'sec-ch-ua-platform': '"Windows"', 'sec-fetch-dest': 'empty',
      'sec-fetch-mode': 'cors', 'sec-fetch-site': 'cross-site', 'priority': 'u=1, i'
    }
    if (this.cookies.has('awsccc')) h['Cookie'] = 'awsccc=' + this.cookies.get('awsccc')

    const resp = await this.doGet(loginURL, h)
    saveCookies(this.cookies, resp.headers as Record<string, string | string[] | undefined>)
    const data = this.parseBody(resp.body)
    if (data.csrfToken) this.cookies.set('loginCsrfToken', data.csrfToken as string)

    const rurl = (data.redirectUrl as string) || ''
    let wh = ''
    if (rurl.includes('workflowStateHandle=')) {
      wh = splitAfter(rurl, 'workflowStateHandle=')
    }
    if (!wh) throw new Error('SSO 无法获取 workflowStateHandle')

    await this.completeSSOWorkflow(wh)
  }

  private async completeSSOWorkflow(wh: string): Promise<void> {
    const api = `${this.cfg.signinBase}/platform/${this.cfg.directoryId}/api/execute`
    const ref = `${this.cfg.signinBase}/platform/${this.cfg.directoryId}/login?workflowStateHandle=${wh}`
    let fp = this.genFP('signin', 'PageLoad', 0, '')
    let rid = newUUID()
    let h = this.buildHeaders(ref, this.cfg.signinBase)
    h['x-amzn-requestid'] = rid; h['x-amz-date'] = gmtDate(); h['priority'] = 'u=1, i'

    let resp = await this.doPost(api, {
      stepId: '', workflowStateHandle: wh,
      inputs: [{ input_type: 'FingerPrintRequestInput', fingerPrint: fp }],
      requestId: rid
    }, h)
    saveCookies(this.cookies, resp.headers as Record<string, string | string[] | undefined>)
    let data = this.parseBody(resp.body)
    let newWH = (data.workflowStateHandle as string) || wh

    if (data.stepId === 'start') {
      fp = this.genFP('signin', 'PageLoad', 0, '')
      rid = newUUID()
      h = this.buildHeaders(ref, this.cfg.signinBase)
      h['x-amzn-requestid'] = rid; h['x-amz-date'] = gmtDate(); h['priority'] = 'u=1, i'

      resp = await this.doPost(api, {
        stepId: 'start', workflowStateHandle: newWH,
        inputs: [{ input_type: 'FingerPrintRequestInput', fingerPrint: fp }],
        requestId: rid
      }, h)
      saveCookies(this.cookies, resp.headers as Record<string, string | string[] | undefined>)
      data = this.parseBody(resp.body)
    }

    if (data.stepId === 'end-of-workflow-success') {
      const redir = data.redirect as Record<string, unknown> | undefined
      const rurl = redir?.url as string
      if (rurl) {
        this.authCode = extractParam(rurl, 'workflowResultHandle')
        this.ssoState = extractParam(rurl, 'state')
        this.wdcCSRFToken = extractParam(rurl, 'wdc_csrf_token')
      }
    }

    // 访问 start 页面
    const params = new URLSearchParams()
    if (this.ssoState) params.set('state', this.ssoState)
    params.set('workflowResultHandle', this.authCode)
    if (this.wdcCSRFToken) params.set('wdc_csrf_token', this.wdcCSRFToken)
    const startURL = this.cfg.viewBase + '/start/?' + params.toString()

    const cookieParts: string[] = []
    if (this.cookies.has('loginCsrfToken')) cookieParts.push('loginCsrfToken=' + this.cookies.get('loginCsrfToken'))
    if (this.cookies.has('awsccc')) cookieParts.push('awsccc=' + this.cookies.get('awsccc'))

    await this.doGet(startURL, {
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'User-Agent': DEFAULT_UA,
      'Referer': this.cfg.signinBase + '/',
      'sec-fetch-dest': 'document', 'sec-fetch-mode': 'navigate',
      ...(cookieParts.length ? { Cookie: cookieParts.join('; ') } : {})
    })
  }

  private async step13SSOToken(): Promise<Record<string, unknown>> {
    this.log('[13] 获取 SSO Token')
    const csrf = this.cookies.get('loginCsrfToken')
    if (!csrf) throw new Error('缺少 loginCsrfToken')

    const h: Record<string, string> = {
      'Accept': 'application/json, text/plain, */*',
      'Content-Type': 'application/x-www-form-urlencoded',
      'User-Agent': DEFAULT_UA, 'Origin': this.cfg.viewBase,
      'Referer': this.cfg.viewBase + '/',
      'x-amz-sso-csrf-token': csrf,
      'sec-ch-ua': DEFAULT_SEC_UA, 'sec-ch-ua-mobile': '?0',
      'sec-ch-ua-platform': '"Windows"', 'sec-fetch-dest': 'empty',
      'sec-fetch-mode': 'cors', 'sec-fetch-site': 'cross-site', 'priority': 'u=1, i'
    }
    const formData = `authCode=${encodeURIComponent(this.authCode)}&state=${encodeURIComponent(this.ssoState)}&orgId=view`

    // 使用新客户端轮询 SSO Token
    const ssoSession = new SessionClient(this.moduleClient!, this.sessionOpts)

    try {
      for (let retry = 0; retry < 5; retry++) {
        const resp = await ssoSession.post(this.cfg.portalBase + '/auth/sso-token', formData, { headers: h })
        const data = JSON.parse(resp.body || '{}')

        if (data.token) {
          this.ssoToken = data.token
          break
        }
        const errMsg = (data.errorMessage || '') as string
        if (errMsg.toLowerCase().includes('not authorized')) {
          await sleep(3000)
          continue
        }
        throw new Error(`SSO Token 失败: ${resp.body?.slice(0, 200)}`)
      }
    } finally {
      try { await ssoSession.destroySession() } catch { /* ignore */ }
    }

    if (!this.ssoToken) throw new Error('SSO Token 重试 5 次仍失败')

    // Accept device + Associate token
    let resp = await this.doPost(this.cfg.oidcBase + '/device_authorization/accept_user_code', {
      userCode: this.userCode, userSessionId: this.ssoToken
    }, { 'Content-Type': 'application/json' })
    const dcData = this.parseBody(resp.body)
    const dc = dcData.deviceContext

    await this.doPost(this.cfg.oidcBase + '/device_authorization/associate_token', {
      deviceContext: dc, userSessionId: this.ssoToken
    }, { 'Content-Type': 'application/json' })

    // 轮询 token
    for (let i = 0; i < 30; i++) {
      resp = await this.doPost(this.cfg.oidcBase + '/token', {
        clientId: this.clientId, clientSecret: this.clientSecret,
        deviceCode: this.deviceCode,
        grantType: 'urn:ietf:params:oauth:grant-type:device_code'
      }, { 'Content-Type': 'application/json' })

      if (resp.status === 200) return this.parseBody(resp.body)
      await sleep(2000)
    }
    throw new Error('Token 轮询超时')
  }

  // ============ 验活 ============

  private async verifyAlive(awsToken: Record<string, unknown>): Promise<Record<string, unknown>> {
    this.log('[验活] 刷新 Token + 查用量')
    const refreshToken = (awsToken.refreshToken as string) || ''

    const resp = await this.doPost('https://oidc.us-east-1.amazonaws.com/token', {
      clientId: this.clientId, clientSecret: this.clientSecret,
      refreshToken, grantType: 'refresh_token'
    }, { 'Content-Type': 'application/json' })

    if (resp.status !== 200) {
      this.log(`Token 刷新失败: ${resp.status}`)
      return { alive: false, error: `refresh failed: ${resp.status}` }
    }

    const tok = this.parseBody(resp.body)
    const access = (tok.accessToken as string) || ''

    const usageUA = 'aws-sdk-js/1.0.18 ua/2.1 os/windows lang/js md/nodejs#20.16.0 api/codewhispererstreaming#1.0.18 m/E KiroIDE-0.6.18'

    for (const baseURL of ['https://q.us-east-1.amazonaws.com/getUsageLimits', 'https://q.eu-central-1.amazonaws.com/getUsageLimits']) {
      const usageURL = baseURL + '?origin=AI_EDITOR&resourceType=AGENTIC_REQUEST&isEmailRequired=true'
      const usageResp = await this.doGet(usageURL, {
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + access,
        'User-Agent': usageUA
      })

      if (usageResp.status === 403 && usageResp.body.toLowerCase().includes('suspended')) {
        return { alive: false, suspended: true, error: 'suspended' }
      }
      if (usageResp.status === 200) {
        return this.parseUsage(usageResp.body)
      }
    }
    return { alive: false, error: 'usage query failed' }
  }

  private parseUsage(body: string): Record<string, unknown> {
    const usage = this.parseBody(body)
    const userInfo = (usage.userInfo as Record<string, unknown>) || {}
    const emailAddr = (userInfo.email as string) || ''
    const subInfo = (usage.subscriptionInfo as Record<string, unknown>) || {}
    let sub = (subInfo.subscriptionTitle as string) || 'Free'

    let totalLimit = 0, totalUsed = 0
    const breakdown = usage.usageBreakdownList as Array<Record<string, unknown>> | undefined
    if (breakdown) {
      for (const item of breakdown) {
        const rt = item.resourceType as string
        const dn = item.displayName as string
        if (rt === 'CREDIT' || dn === 'Credits') {
          totalLimit = (item.usageLimitWithPrecision as number) || (item.usageLimit as number) || 0
          totalUsed = (item.currentUsageWithPrecision as number) || (item.currentUsage as number) || 0

          const ft = item.freeTrialInfo as Record<string, unknown> | undefined
          if (ft?.freeTrialStatus === 'ACTIVE') {
            totalLimit += (ft.usageLimitWithPrecision as number) || 0
            totalUsed += (ft.currentUsageWithPrecision as number) || 0
          }
          break
        }
      }
    }

    this.log(`验活成功! 邮箱=${emailAddr} 订阅=${sub} Credit=${totalUsed}/${totalLimit}`)
    return { alive: true, email: emailAddr, subscription: sub, credit_used: totalUsed, credit_limit: totalLimit }
  }

  // ============ 主流程 ============

  /** 执行完整注册流程（自动模式） */
  async run(): Promise<RegistrationResult> {
    try {
      await this.initTlsClient()
      await refreshAppJSConfig((url, init) => this.fetchAppJS(url, init))
      await this.rebuildTlsClient()

      const initSteps: Array<{ name: string; fn: StepFn }> = [
        { name: 'OIDC', fn: () => this.step1OIDC() },
        { name: 'Device', fn: () => this.step2Device() },
        { name: 'Email', fn: () => this.step3Email() },
        { name: 'Portal', fn: () => this.step4Portal() },
        { name: 'WorkflowInit', fn: () => this.step5WorkflowInit() }
      ]
      for (const s of initSteps) {
        this.checkAborted()
        try { await s.fn() } catch (err) {
          return { status: 'failed', email: this.email, error: `[${s.name}] ${(err as Error).message}` }
        }
      }

      this.checkAborted()
      const emailStatus = await this.step6SubmitEmail()

      if (emailStatus === 'signup') {
        const signupSteps: Array<{ name: string; fn: StepFn }> = [
          { name: 'Signup', fn: () => this.step7Signup() },
          { name: 'SignupInit', fn: () => this.step7_5SignupInit() },
          { name: 'ProfileInit', fn: () => this.step7_8ProfileInit() },
          { name: 'ProfileStart', fn: () => this.step8ProfileStart() },
          { name: 'SendOTP', fn: () => this.step9SendOTP() }
        ]
        for (const s of signupSteps) {
          this.checkAborted()
          try { await s.fn() } catch (err) {
            return { status: 'failed', email: this.email, error: `[${s.name}] ${(err as Error).message}` }
          }
        }

        this.checkAborted()
        let otp: string
        try { otp = await this.step10GetOTP() } catch (err) {
          return { status: 'failed', email: this.email, error: `[GetOTP] ${(err as Error).message}` }
        }

        for (const s of [
          { name: 'CreateIdentity', fn: () => this.step11CreateIdentity(otp) },
          { name: 'SetPassword', fn: () => this.step12SetPassword() }
        ] as Array<{ name: string; fn: StepFn }>) {
          this.checkAborted()
          try { await s.fn() } catch (err) {
            return { status: 'failed', email: this.email, error: `[${s.name}] ${(err as Error).message}` }
          }
        }
      } else {
        return { status: 'failed', email: this.email, error: '该邮箱已注册过' }
      }

      this.checkAborted()
      try { await this.step12_8SSOWorkflow() } catch (err) {
        return { status: 'failed', email: this.email, error: `[SSOWorkflow] ${(err as Error).message}` }
      }

      await sleep(2000)

      this.checkAborted()
      let awsToken: Record<string, unknown>
      try { awsToken = await this.step13SSOToken() } catch (err) {
        return { status: 'failed', email: this.email, error: `[SSOToken] ${(err as Error).message}` }
      }

      const verify = await this.verifyAlive(awsToken)
      if (verify.suspended) {
        return { status: 'failed', email: this.email, error: 'suspended' }
      }

      return {
        status: 'success',
        email: this.email,
        password: this.cfg.password,
        clientId: this.clientId,
        clientSecret: this.clientSecret,
        refreshToken: (awsToken.refreshToken as string) || '',
        accessToken: (awsToken.accessToken as string) || '',
        region: 'us-east-1',
        provider: 'BuilderId',
        verify
      }
    } finally {
      await this.cleanup()
    }
  }

  /** 手动模式注册 - Step1-2 自动，Step3 等待外部设置邮箱，Step4-9 自动，Step10 等待外部 OTP */
  async runManualPhase1(): Promise<{ success: boolean; error?: string }> {
    try {
      await this.initTlsClient()
      await refreshAppJSConfig((url, init) => this.fetchAppJS(url, init))
      await this.rebuildTlsClient()

      await this.step1OIDC()
      await this.step2Device()
      return { success: true }
    } catch (err) {
      return { success: false, error: (err as Error).message }
    }
  }

  /** 手动模式 - 设置邮箱后继续注册流程到发送 OTP */
  async runManualPhase2(email: string, fullName?: string): Promise<{ success: boolean; error?: string }> {
    this.email = email
    if (fullName) this.cfg.fullName = fullName

    try {
      await this.step4Portal()
      await this.step5WorkflowInit()

      const status = await this.step6SubmitEmail()
      if (status !== 'signup') return { success: false, error: '该邮箱已注册过' }

      await this.step7Signup()
      await this.step7_5SignupInit()
      await this.step7_8ProfileInit()
      await this.step8ProfileStart()
      await this.step9SendOTP()
      return { success: true }
    } catch (err) {
      return { success: false, error: (err as Error).message }
    }
  }

  /** 手动模式 - 输入 OTP 后完成注册 */
  async runManualPhase3(otp: string): Promise<RegistrationResult> {
    try {
      await this.step11CreateIdentity(otp)
      await this.step12SetPassword()
      await this.step12_8SSOWorkflow()
      await sleep(2000)

      const awsToken = await this.step13SSOToken()
      const verify = await this.verifyAlive(awsToken)
      if (verify.suspended) {
        return { status: 'failed', email: this.email, error: 'suspended' }
      }

      return {
        status: 'success',
        email: this.email,
        password: this.cfg.password,
        clientId: this.clientId,
        clientSecret: this.clientSecret,
        refreshToken: (awsToken.refreshToken as string) || '',
        accessToken: (awsToken.accessToken as string) || '',
        region: 'us-east-1',
        provider: 'BuilderId',
        verify
      }
    } catch (err) {
      return { status: 'failed', email: this.email, error: (err as Error).message }
    } finally {
      await this.cleanup()
    }
  }
}
