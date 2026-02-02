// Kiro Proxy HTTP/HTTPS 服务器
import http from 'http'
import https from 'https'
import fs from 'fs'
import { v4 as uuidv4 } from 'uuid'
import type {
  OpenAIChatRequest,
  ClaudeRequest,
  ProxyConfig,
  ProxyStats,
  ProxyAccount,
  TokenRefreshCallback
} from './types'
import { AccountPool } from './accountPool'
import { callKiroApiStream, callKiroApi, fetchKiroModels, type KiroModel } from './kiroApi'
import { proxyLogger } from './logger'
import { getKProxyService, generateDeviceId } from '../kproxy'
import {
  openaiToKiro,
  claudeToKiro,
  kiroToOpenaiResponse,
  kiroToClaudeResponse,
  createOpenaiStreamChunk,
  createClaudeStreamEvent
} from './translator'

export interface ProxyServerEvents {
  onRequest?: (info: { path: string; method: string; accountId?: string }) => void
  onResponse?: (info: { path: string; model?: string; status: number; tokens?: number; inputTokens?: number; outputTokens?: number; credits?: number; error?: string }) => void
  onError?: (error: Error) => void
  onConfigChanged?: (config: ProxyConfig) => void  // API Key 用量更新时触发
  onStatusChange?: (running: boolean, port: number) => void
  onTokenRefresh?: TokenRefreshCallback
  onAccountUpdate?: (account: ProxyAccount) => void
  onCreditsUpdate?: (totalCredits: number) => void
  onTokensUpdate?: (inputTokens: number, outputTokens: number) => void
  onRequestStatsUpdate?: (totalRequests: number, successRequests: number, failedRequests: number) => void
}

export class ProxyServer {
  private server: http.Server | https.Server | null = null
  private accountPool: AccountPool
  private config: ProxyConfig
  private stats: ProxyStats
  private sessionStats: { totalRequests: number; successRequests: number; failedRequests: number; startTime: number }
  private events: ProxyServerEvents
  private refreshingTokens: Set<string> = new Set() // 防止并发刷新
  private isHttps: boolean = false

  constructor(config: Partial<ProxyConfig> = {}, events: ProxyServerEvents = {}) {
    this.config = {
      enabled: false,
      port: 5580,
      host: '127.0.0.1',
      enableMultiAccount: true,
      selectedAccountIds: [],
      logRequests: true,
      maxConcurrent: 10,
      maxRetries: 3,
      retryDelayMs: 1000,
      tokenRefreshBeforeExpiry: 300, // 5分钟提前刷新
      autoStart: false, // 是否自动启动
      ...config
    }
    this.accountPool = new AccountPool()
    this.stats = {
      totalRequests: 0,
      successRequests: 0,
      failedRequests: 0,
      totalTokens: 0,
      totalCredits: 0,
      inputTokens: 0,
      outputTokens: 0,
      startTime: Date.now(),
      accountStats: new Map(),
      endpointStats: new Map(),
      modelStats: new Map(),
      recentRequests: []
    }
    this.sessionStats = {
      totalRequests: 0,
      successRequests: 0,
      failedRequests: 0,
      startTime: 0
    }
    this.events = events
  }

  // 启动服务器
  async start(): Promise<void> {
    if (this.server) {
      console.log('[ProxyServer] Server already running')
      return
    }

    return new Promise((resolve, reject) => {
      const requestHandler = (req: http.IncomingMessage, res: http.ServerResponse) => 
        this.handleRequest(req, res)

      // 检查是否启用 TLS
      if (this.config.tls?.enabled) {
        try {
          const tlsOptions = this.getTlsOptions()
          this.server = https.createServer(tlsOptions, requestHandler)
          this.isHttps = true
        } catch (error) {
          reject(new Error(`TLS configuration error: ${(error as Error).message}`))
          return
        }
      } else {
        this.server = http.createServer(requestHandler)
        this.isHttps = false
      }

      this.server.on('error', (error: NodeJS.ErrnoException) => {
        if (error.code === 'EADDRINUSE') {
          console.error(`[ProxyServer] Port ${this.config.port} is already in use`)
          reject(new Error(`Port ${this.config.port} is already in use`))
        } else {
          console.error('[ProxyServer] Server error:', error)
          reject(error)
        }
        this.events.onError?.(error)
      })

      // 服务器关闭时尝试自动重启
      this.server.on('close', () => {
        if (this.config.autoStart && this.config.enabled) {
          console.log('[ProxyServer] Server closed unexpectedly, attempting restart in 3s...')
          setTimeout(() => {
            if (this.config.autoStart && !this.isRunning()) {
              console.log('[ProxyServer] Auto-restarting...')
              this.start().catch(err => {
                console.error('[ProxyServer] Auto-restart failed:', err)
              })
            }
          }, 3000)
        }
      })

      const protocol = this.isHttps ? 'https' : 'http'
      this.server.listen(this.config.port, this.config.host, () => {
        proxyLogger.info('ProxyServer', `Started on ${protocol}://${this.config.host}:${this.config.port}`)
        this.stats.startTime = Date.now()
        // 重置会话统计
        this.sessionStats = {
          totalRequests: 0,
          successRequests: 0,
          failedRequests: 0,
          startTime: Date.now()
        }
        this.events.onStatusChange?.(true, this.config.port)
        resolve()
      })
    })
  }

  // 获取 TLS 配置选项
  private getTlsOptions(): https.ServerOptions {
    const tls = this.config.tls!
    
    let cert: string
    let key: string

    // 优先使用直接提供的 PEM 内容
    if (tls.cert && tls.key) {
      cert = tls.cert
      key = tls.key
    } else if (tls.certPath && tls.keyPath) {
      // 从文件读取
      cert = fs.readFileSync(tls.certPath, 'utf8')
      key = fs.readFileSync(tls.keyPath, 'utf8')
    } else {
      throw new Error('TLS enabled but no certificate/key provided')
    }

    return { cert, key }
  }

  // 停止服务器
  async stop(): Promise<void> {
    if (!this.server) {
      return
    }

    return new Promise((resolve) => {
      this.server!.close(() => {
        proxyLogger.info('ProxyServer', 'Stopped')
        this.server = null
        this.events.onStatusChange?.(false, this.config.port)
        resolve()
      })
    })
  }

  // 更新配置
  updateConfig(config: Partial<ProxyConfig>): void {
    this.config = { ...this.config, ...config }
  }

  // 获取配置
  getConfig(): ProxyConfig {
    return { ...this.config }
  }

  // 获取统计信息
  getStats(): ProxyStats {
    // 返回可序列化的统计信息（Map 对象在 IPC 中无法正确序列化）
    return {
      totalRequests: this.stats.totalRequests,
      successRequests: this.stats.successRequests,
      failedRequests: this.stats.failedRequests,
      totalTokens: this.stats.totalTokens,
      totalCredits: this.stats.totalCredits,
      inputTokens: this.stats.inputTokens,
      outputTokens: this.stats.outputTokens,
      startTime: this.stats.startTime,
      accountStats: this.stats.accountStats,
      endpointStats: this.stats.endpointStats,
      modelStats: this.stats.modelStats,
      recentRequests: this.stats.recentRequests
    }
  }

  // 获取账号池
  getAccountPool(): AccountPool {
    return this.accountPool
  }

  // 设置初始累计 credits（用于从持久化存储恢复）
  setTotalCredits(credits: number): void {
    this.stats.totalCredits = credits
  }

  // 重置累计 credits
  resetTotalCredits(): void {
    this.stats.totalCredits = 0
    this.events.onCreditsUpdate?.(0)
  }

  // 设置初始累计 tokens（用于从持久化存储恢复）
  setTotalTokens(inputTokens: number, outputTokens: number): void {
    this.stats.inputTokens = inputTokens
    this.stats.outputTokens = outputTokens
    this.stats.totalTokens = inputTokens + outputTokens
  }

  // 重置累计 tokens
  resetTotalTokens(): void {
    this.stats.inputTokens = 0
    this.stats.outputTokens = 0
    this.stats.totalTokens = 0
  }

  // 设置请求统计（用于从持久化存储恢复）
  setRequestStats(totalRequests: number, successRequests: number, failedRequests: number): void {
    this.stats.totalRequests = totalRequests
    this.stats.successRequests = successRequests
    this.stats.failedRequests = failedRequests
  }

  // 重置请求统计
  resetRequestStats(): void {
    this.stats.totalRequests = 0
    this.stats.successRequests = 0
    this.stats.failedRequests = 0
    this.notifyRequestStatsUpdate()
  }

  // 通知请求统计更新
  private notifyRequestStatsUpdate(): void {
    this.events.onRequestStatsUpdate?.(
      this.stats.totalRequests,
      this.stats.successRequests,
      this.stats.failedRequests
    )
  }

  // 记录请求成功
  private recordRequestSuccess(): void {
    this.stats.successRequests++
    this.sessionStats.successRequests++
    this.notifyRequestStatsUpdate()
  }

  // 记录请求失败
  private recordRequestFailed(): void {
    this.stats.failedRequests++
    this.sessionStats.failedRequests++
    this.notifyRequestStatsUpdate()
  }

  // 记录新请求
  private recordNewRequest(): void {
    this.stats.totalRequests++
    this.sessionStats.totalRequests++
    this.notifyRequestStatsUpdate()
  }

  // 获取会话统计（当前服务运行期间的统计）
  getSessionStats(): { totalRequests: number; successRequests: number; failedRequests: number; startTime: number } {
    return { ...this.sessionStats }
  }

  // 是否运行中
  isRunning(): boolean {
    return this.server !== null
  }

  // 清除模型缓存，强制下次请求重新获取
  clearModelCache(): void {
    this.modelCache = null
    console.log('[ProxyServer] Model cache cleared')
  }

  // 获取可用模型列表
  async getAvailableModels(): Promise<{ models: Array<{ id: string; name: string; description: string; inputTypes?: string[]; maxInputTokens?: number | null; maxOutputTokens?: number | null; rateMultiplier?: number; rateUnit?: string }>; fromCache: boolean }> {
    const now = Date.now()
    
    // 检查缓存
    if (this.modelCache && (now - this.modelCache.timestamp) < this.MODEL_CACHE_TTL) {
      return {
        models: this.modelCache.models.map(m => ({
          id: m.modelId,
          name: m.modelName,
          description: m.description,
          inputTypes: m.supportedInputTypes,
          maxInputTokens: m.tokenLimits?.maxInputTokens,
          maxOutputTokens: m.tokenLimits?.maxOutputTokens,
          rateMultiplier: m.rateMultiplier,
          rateUnit: m.rateUnit
        })),
        fromCache: true
      }
    }

    // 获取一个可用账号来请求模型列表
    const account = this.accountPool.getNextAccount()
    if (!account) {
      return { models: [], fromCache: false }
    }

    try {
      const kiroModels = await fetchKiroModels(account)
      if (kiroModels.length > 0) {
        this.modelCache = { models: kiroModels, timestamp: now }
      }
      return {
        models: kiroModels.map(m => ({
          id: m.modelId,
          name: m.modelName,
          description: m.description,
          inputTypes: m.supportedInputTypes,
          maxInputTokens: m.tokenLimits?.maxInputTokens,
          maxOutputTokens: m.tokenLimits?.maxOutputTokens,
          rateMultiplier: m.rateMultiplier,
          rateUnit: m.rateUnit
        })),
        fromCache: false
      }
    } catch (error) {
      console.error('[ProxyServer] Failed to fetch models:', error)
      return { models: [], fromCache: false }
    }
  }

  // 检查 Token 是否需要刷新
  private isTokenExpiringSoon(account: ProxyAccount): boolean {
    if (!account.expiresAt) return false
    const refreshBeforeMs = (this.config.tokenRefreshBeforeExpiry || 300) * 1000
    return Date.now() + refreshBeforeMs >= account.expiresAt
  }

  // 刷新 Token
  private async refreshToken(account: ProxyAccount): Promise<boolean> {
    if (!this.events.onTokenRefresh) {
      console.warn('[ProxyServer] No token refresh callback configured')
      return false
    }

    // 防止并发刷新
    if (this.refreshingTokens.has(account.id)) {
      console.log(`[ProxyServer] Token refresh already in progress for ${account.email || account.id}`)
      // 等待刷新完成
      await new Promise(resolve => setTimeout(resolve, 1000))
      return !this.isTokenExpiringSoon(this.accountPool.getAccount(account.id) || account)
    }

    this.refreshingTokens.add(account.id)
    console.log(`[ProxyServer] Refreshing token for ${account.email || account.id}`)

    try {
      const result = await this.events.onTokenRefresh(account)
      if (result.success && result.accessToken) {
        // 更新账号池中的 Token
        this.accountPool.updateAccount(account.id, {
          accessToken: result.accessToken,
          refreshToken: result.refreshToken || account.refreshToken,
          expiresAt: result.expiresAt
        })
        // 通知外部更新
        this.events.onAccountUpdate?.({
          ...account,
          accessToken: result.accessToken,
          refreshToken: result.refreshToken || account.refreshToken,
          expiresAt: result.expiresAt
        })
        console.log(`[ProxyServer] Token refreshed for ${account.email || account.id}`)
        return true
      } else {
        console.error(`[ProxyServer] Token refresh failed for ${account.email || account.id}: ${result.error}`)
        this.accountPool.markNeedsRefresh(account.id)
        return false
      }
    } catch (error) {
      console.error(`[ProxyServer] Token refresh error for ${account.email || account.id}:`, error)
      this.accountPool.markNeedsRefresh(account.id)
      return false
    } finally {
      this.refreshingTokens.delete(account.id)
    }
  }

  // 获取可用账号（包含 Token 刷新检查）
  private async getAvailableAccount(): Promise<ProxyAccount | null> {
    let account: ProxyAccount | null
    
    // 检查是否启用多账号轮询
    if (this.config.enableMultiAccount) {
      account = this.accountPool.getNextAccount()
    } else {
      // 禁用多账号轮询时，优先使用指定的账号
      if (this.config.selectedAccountIds && this.config.selectedAccountIds.length > 0) {
        // 使用指定的第一个账号
        account = this.accountPool.getAccount(this.config.selectedAccountIds[0])
        if (!account) {
          console.log(`[ProxyServer] Selected account ${this.config.selectedAccountIds[0]} not found, using first available`)
          const allAccounts = this.accountPool.getAllAccounts()
          account = allAccounts.length > 0 ? allAccounts[0] : null
        }
      } else {
        // 没有指定账号，使用第一个可用账号
        const allAccounts = this.accountPool.getAllAccounts()
        account = allAccounts.length > 0 ? allAccounts[0] : null
      }
    }
    
    if (!account) return null

    // 自动切换 K-Proxy 设备 ID（如果 K-Proxy 服务可用）
    this.syncKProxyDeviceId(account)

    // 检查是否需要刷新 Token
    if (this.isTokenExpiringSoon(account)) {
      const refreshed = await this.refreshToken(account)
      if (!refreshed) {
        // 刷新失败，如果启用多账号才尝试获取下一个账号
        if (this.config.enableMultiAccount) {
          return this.accountPool.getNextAccount()
        }
        return null
      }
      // 返回更新后的账号
      return this.accountPool.getAccount(account.id)
    }

    return account
  }

  // 同步 K-Proxy 设备 ID（根据账号自动切换）
  private syncKProxyDeviceId(account: ProxyAccount): void {
    const kproxyService = getKProxyService()
    if (!kproxyService || !kproxyService.isRunning()) {
      return // K-Proxy 未初始化或未运行
    }

    // 尝试切换到账号绑定的设备 ID
    const switched = kproxyService.switchToAccount(account.id)
    
    if (!switched) {
      // 账号没有绑定设备 ID，自动生成并绑定
      const newDeviceId = generateDeviceId()
      kproxyService.addDeviceIdMapping({
        accountId: account.id,
        deviceId: newDeviceId,
        description: account.email || `Account ${account.id.substring(0, 8)}`,
        createdAt: Date.now()
      })
      kproxyService.setDeviceId(newDeviceId)
      proxyLogger.info('ProxyServer', `Auto-generated device ID for account ${account.email || account.id.substring(0, 8)}`)
    } else {
      proxyLogger.debug('ProxyServer', `Switched to device ID for account ${account.email || account.id.substring(0, 8)}`)
    }
  }

  // 带重试的 API 调用
  private async callWithRetry<T>(
    account: ProxyAccount,
    apiCall: (acc: ProxyAccount, endpointIndex: number) => Promise<T>,
    _path: string // 用于日志
  ): Promise<{ result: T; account: ProxyAccount }> {
    const maxRetries = this.config.maxRetries || 3
    const retryDelay = this.config.retryDelayMs || 1000
    let lastError: Error | null = null
    let currentAccount = account
    let endpointIndex = 0

    for (let attempt = 0; attempt < maxRetries; attempt++) {
      try {
        const result = await apiCall(currentAccount, endpointIndex)
        return { result, account: currentAccount }
      } catch (error) {
        lastError = error as Error
        const errMsg = lastError.message || ''

        console.log(`[ProxyServer] API call failed (attempt ${attempt + 1}/${maxRetries}): ${errMsg}`)

        // 401/403: 尝试刷新 Token
        if (errMsg.includes('401') || errMsg.includes('403') || errMsg.includes('Auth')) {
          console.log('[ProxyServer] Auth error, attempting token refresh')
          const refreshed = await this.refreshToken(currentAccount)
          if (refreshed) {
            currentAccount = this.accountPool.getAccount(currentAccount.id) || currentAccount
            continue
          }
          // 刷新失败，只在启用多账号时切换账号
          if (this.config.enableMultiAccount) {
            const nextAccount = this.accountPool.getNextAccount()
            if (nextAccount && nextAccount.id !== currentAccount.id) {
              currentAccount = nextAccount
              continue
            }
          }
        }

        // 402/429: 额度耗尽，切换端点或账号
        if (errMsg.includes('402') || errMsg.includes('429') || errMsg.includes('quota') || errMsg.includes('ThrottlingException') || errMsg.includes('reached the limit')) {
          console.log('[ProxyServer] Quota/throttle error, switching endpoint or account')
          this.accountPool.recordError(currentAccount.id, true)
          endpointIndex = (endpointIndex + 1) % 2 // 切换端点
          if (endpointIndex === 0) {
            // 已尝试所有端点，检查是否需要切换账号
            if (this.config.enableMultiAccount) {
              // 多账号模式：切换到下一个账号
              const nextAccount = this.accountPool.getNextAccount()
              if (nextAccount && nextAccount.id !== currentAccount.id) {
                currentAccount = nextAccount
              }
            } else if (this.config.autoSwitchOnQuotaExhausted) {
              // 单账号模式 + 启用自动切换：切换到下一个可用账号
              const nextAccount = this.accountPool.getNextAvailableAccount(currentAccount.id)
              if (nextAccount && nextAccount.id !== currentAccount.id) {
                console.log(`[ProxyServer] Auto-switching from ${currentAccount.id} to ${nextAccount.id} due to quota exhausted`)
                currentAccount = nextAccount
                // 更新配置中的选定账号
                this.config.selectedAccountIds = [nextAccount.id]
                this.events.onAccountUpdate?.(nextAccount)
              }
            }
          }
          continue
        }

        // 5xx: 重试
        if (errMsg.includes('500') || errMsg.includes('502') || errMsg.includes('503') || errMsg.includes('504')) {
          console.log('[ProxyServer] Server error, retrying')
          await new Promise(resolve => setTimeout(resolve, retryDelay * (attempt + 1)))
          continue
        }

        // 其他错误，不重试
        break
      }
    }

    throw lastError || new Error('Unknown error')
  }

  // 验证 API Key 并返回匹配的 Key（用于统计）
  private validateApiKey(req: http.IncomingMessage): { valid: boolean; apiKey?: import('./types').ApiKey; reason?: string } {
    // 如果没有配置任何 API Key，则跳过验证
    const hasApiKeys = this.config.apiKeys && this.config.apiKeys.length > 0
    const hasLegacyKey = !!this.config.apiKey
    if (!hasApiKeys && !hasLegacyKey) return { valid: true }

    // 从 Authorization 头或 X-Api-Key 头获取 API Key
    const authHeader = req.headers['authorization'] || ''
    const apiKeyHeader = (req.headers['x-api-key'] as string) || ''

    let providedKey = ''
    // Bearer token 格式
    if (authHeader.startsWith('Bearer ')) {
      providedKey = authHeader.slice(7)
    }
    // 直接 API Key 格式
    if (!providedKey && apiKeyHeader) {
      providedKey = apiKeyHeader
    }

    if (!providedKey) return { valid: false }

    // 检查多 API Key
    if (hasApiKeys) {
      const matchedKey = this.config.apiKeys!.find(k => k.enabled && k.key === providedKey)
      if (matchedKey) {
        // 检查额度限制
        if (matchedKey.creditsLimit && matchedKey.usage.totalCredits >= matchedKey.creditsLimit) {
          return { valid: false, reason: 'Credits limit exceeded' }
        }
        return { valid: true, apiKey: matchedKey }
      }
    }

    // 兼容旧的单 API Key
    if (hasLegacyKey && providedKey === this.config.apiKey) {
      return { valid: true }
    }

    return { valid: false }
  }

  // 记录 API Key 用量
  recordApiKeyUsage(apiKeyId: string, credits: number, inputTokens: number, outputTokens: number, model?: string, path?: string): void {
    if (!this.config.apiKeys) return
    const apiKey = this.config.apiKeys.find(k => k.id === apiKeyId)
    if (!apiKey) return

    const today = new Date().toISOString().split('T')[0]
    const now = Date.now()
    
    // 更新总计
    apiKey.usage.totalRequests++
    apiKey.usage.totalCredits += credits
    apiKey.usage.totalInputTokens += inputTokens
    apiKey.usage.totalOutputTokens += outputTokens
    apiKey.lastUsedAt = now

    // 更新日统计
    if (!apiKey.usage.daily[today]) {
      apiKey.usage.daily[today] = { requests: 0, credits: 0, inputTokens: 0, outputTokens: 0 }
    }
    apiKey.usage.daily[today].requests++
    apiKey.usage.daily[today].credits += credits
    apiKey.usage.daily[today].inputTokens += inputTokens
    apiKey.usage.daily[today].outputTokens += outputTokens

    // 更新模型统计
    if (model) {
      if (!apiKey.usage.byModel) {
        apiKey.usage.byModel = {}
      }
      if (!apiKey.usage.byModel[model]) {
        apiKey.usage.byModel[model] = { requests: 0, credits: 0, inputTokens: 0, outputTokens: 0 }
      }
      apiKey.usage.byModel[model].requests++
      apiKey.usage.byModel[model].credits += credits
      apiKey.usage.byModel[model].inputTokens += inputTokens
      apiKey.usage.byModel[model].outputTokens += outputTokens
    }

    // 添加用量历史记录（保留最近 100 条）
    if (!apiKey.usageHistory) {
      apiKey.usageHistory = []
    }
    apiKey.usageHistory.unshift({
      timestamp: now,
      model: model || 'unknown',
      inputTokens,
      outputTokens,
      credits,
      path: path || 'unknown'
    })
    if (apiKey.usageHistory.length > 100) {
      apiKey.usageHistory = apiKey.usageHistory.slice(0, 100)
    }

    // 触发配置保存事件
    this.events.onConfigChanged?.(this.config)
  }

  // 应用模型映射
  private applyModelMapping(requestedModel: string, apiKeyId?: string): string {
    const mappings = this.config.modelMappings
    if (!mappings || mappings.length === 0) return requestedModel

    // 按优先级排序（数字越小优先级越高）
    const sortedMappings = [...mappings].sort((a, b) => a.priority - b.priority)

    for (const rule of sortedMappings) {
      // 检查规则是否启用
      if (!rule.enabled) continue

      // 检查是否适用于当前 API Key
      if (rule.apiKeyIds && rule.apiKeyIds.length > 0 && apiKeyId) {
        if (!rule.apiKeyIds.includes(apiKeyId)) continue
      }

      // 检查源模型是否匹配（支持通配符 *）
      const sourcePattern = rule.sourceModel.replace(/\*/g, '.*')
      const regex = new RegExp(`^${sourcePattern}$`, 'i')
      if (!regex.test(requestedModel)) continue

      // 匹配成功，根据类型选择目标模型
      const validTargets = rule.targetModels.filter(t => t.trim())
      if (validTargets.length === 0) continue

      let targetModel: string

      if (rule.type === 'loadbalance' && validTargets.length > 1) {
        // 负载均衡：根据权重随机选择
        const weights = rule.weights || validTargets.map(() => 1)
        const totalWeight = weights.reduce((a, b) => a + b, 0)
        let random = Math.random() * totalWeight
        let selectedIndex = 0
        for (let i = 0; i < weights.length; i++) {
          random -= weights[i]
          if (random <= 0) {
            selectedIndex = i
            break
          }
        }
        targetModel = validTargets[selectedIndex]
      } else {
        // replace 或 alias：直接使用第一个目标
        targetModel = validTargets[0]
      }

      proxyLogger.info('ProxyServer', `Model mapping applied: ${requestedModel} -> ${targetModel} (rule: ${rule.name}, type: ${rule.type})`)
      return targetModel
    }

    return requestedModel
  }

  // 处理请求
  private async handleRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const path = req.url || '/'
    const method = req.method || 'GET'

    // CORS 预检
    if (method === 'OPTIONS') {
      this.setCorsHeaders(res)
      res.writeHead(204)
      res.end()
      return
    }

    this.setCorsHeaders(res)

    // API Key 验证（健康检查端点除外）
    if (path !== '/health' && path !== '/') {
      const authResult = this.validateApiKey(req)
      if (!authResult.valid) {
        const errorMsg = authResult.reason || 'Invalid or missing API key'
        const statusCode = authResult.reason === 'Credits limit exceeded' ? 429 : 401
        this.sendError(res, statusCode, errorMsg)
        return
      }
      // 将匹配的 API Key 存储到请求对象中，用于后续统计
      ;(req as unknown as { matchedApiKey?: import('./types').ApiKey }).matchedApiKey = authResult.apiKey
    }

    // 记录请求
    if (this.config.logRequests) {
      proxyLogger.info('ProxyServer', `${method} ${path}`)
    }

    try {
      // 路由（移除查询参数）
      const pathWithoutQuery = path.split('?')[0]
      
      if (pathWithoutQuery === '/v1/models' || pathWithoutQuery === '/models') {
        await this.handleModels(res)
      } else if (pathWithoutQuery === '/v1/chat/completions' || pathWithoutQuery === '/chat/completions') {
        await this.handleOpenAIChat(req, res)
      } else if (pathWithoutQuery === '/v1/messages' || pathWithoutQuery === '/messages' || pathWithoutQuery === '/anthropic/v1/messages') {
        await this.handleClaudeMessages(req, res)
      } else if (pathWithoutQuery === '/v1/messages/count_tokens' || pathWithoutQuery === '/messages/count_tokens') {
        // Claude Code token 计数端点 - 返回模拟响应
        this.handleCountTokens(req, res)
      } else if (pathWithoutQuery === '/api/event_logging/batch') {
        // Claude Code 遥测端点 - 直接返回 200 OK
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ status: 'ok' }))
      } else if (pathWithoutQuery === '/health' || pathWithoutQuery === '/') {
        this.handleHealth(res)
      } else if (pathWithoutQuery.startsWith('/admin/')) {
        // 管理 API 端点
        await this.handleAdminApi(req, res, pathWithoutQuery)
      } else {
        // 记录未知路径以便调试
        console.log(`[ProxyServer] Unknown path: ${path} (method: ${method})`)
        this.sendError(res, 404, `Not Found: ${pathWithoutQuery}`)
      }
    } catch (error) {
      console.error('[ProxyServer] Request error:', error)
      this.sendError(res, 500, (error as Error).message)
      this.events.onError?.(error as Error)
    }
  }

  // 管理 API 端点
  private async handleAdminApi(req: http.IncomingMessage, res: http.ServerResponse, path: string): Promise<void> {
    const method = req.method || 'GET'

    // 管理 API 需要 API Key 验证
    const authResult = this.validateApiKey(req)
    if (!authResult.valid) {
      this.sendError(res, 401, 'Admin API requires authentication')
      return
    }

    if (path === '/admin/stats' && method === 'GET') {
      // 获取详细统计
      this.handleAdminStats(res)
    } else if (path === '/admin/accounts' && method === 'GET') {
      // 获取账号列表
      this.handleAdminAccounts(res)
    } else if (path === '/admin/config' && method === 'GET') {
      // 获取配置
      this.handleAdminConfig(res)
    } else if (path === '/admin/config' && method === 'POST') {
      // 更新配置
      const body = await this.readBody(req)
      const newConfig = JSON.parse(body)
      this.updateConfig(newConfig)
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ success: true, config: this.getConfig() }))
    } else if (path === '/admin/logs' && method === 'GET') {
      // 获取最近日志
      this.handleAdminLogs(res)
    } else {
      this.sendError(res, 404, 'Admin endpoint not found')
    }
  }

  // 管理 API - 详细统计
  private handleAdminStats(res: http.ServerResponse): void {
    const stats = this.getStats()
    const accountStats: Record<string, unknown> = {}
    stats.accountStats.forEach((v, k) => { accountStats[k] = v })

    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({
      totalRequests: stats.totalRequests,
      successRequests: stats.successRequests,
      failedRequests: stats.failedRequests,
      totalTokens: stats.totalTokens,
      inputTokens: stats.inputTokens,
      outputTokens: stats.outputTokens,
      uptime: Date.now() - stats.startTime,
      startTime: stats.startTime,
      accountStats,
      recentRequests: stats.recentRequests.slice(-50)
    }))
  }

  // 管理 API - 账号列表
  private handleAdminAccounts(res: http.ServerResponse): void {
    const accounts = this.accountPool.getAllAccounts().map(acc => ({
      id: acc.id,
      email: acc.email,
      isAvailable: acc.isAvailable !== false,
      lastUsed: acc.lastUsed,
      requestCount: acc.requestCount || 0,
      errorCount: acc.errorCount || 0,
      expiresAt: acc.expiresAt,
      authMethod: acc.authMethod
    }))

    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({
      total: accounts.length,
      available: accounts.filter(a => a.isAvailable).length,
      accounts
    }))
  }

  // 管理 API - 配置
  private handleAdminConfig(res: http.ServerResponse): void {
    const config = this.getConfig()
    // 隐藏敏感信息
    const safeConfig = {
      ...config,
      apiKey: config.apiKey ? '***' : undefined,
      tls: config.tls ? { enabled: config.tls.enabled } : undefined
    }

    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify(safeConfig))
  }

  // 管理 API - 日志
  private handleAdminLogs(res: http.ServerResponse): void {
    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({
      recentRequests: this.stats.recentRequests.slice(-100)
    }))
  }

  // 设置 CORS 头
  private setCorsHeaders(res: http.ServerResponse): void {
    res.setHeader('Access-Control-Allow-Origin', '*')
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Api-Key, anthropic-version, anthropic-beta, x-api-key, x-stainless-os, x-stainless-lang, x-stainless-package-version, x-stainless-runtime, x-stainless-runtime-version, x-stainless-arch')
    res.setHeader('Access-Control-Expose-Headers', 'x-request-id, x-ratelimit-limit-requests, x-ratelimit-limit-tokens, x-ratelimit-remaining-requests, x-ratelimit-remaining-tokens, x-ratelimit-reset-requests, x-ratelimit-reset-tokens')
  }

  // 健康检查
  private handleHealth(res: http.ServerResponse): void {
    const stats = this.getStats()
    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({
      status: 'ok',
      version: '1.0.0',
      accounts: this.accountPool.size,
      availableAccounts: this.accountPool.availableCount,
      stats: {
        totalRequests: stats.totalRequests,
        successRequests: stats.successRequests,
        failedRequests: stats.failedRequests,
        totalTokens: stats.totalTokens,
        uptime: Date.now() - stats.startTime
      }
    }))
  }

  // Claude Code token 计数（模拟响应）
  private async handleCountTokens(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    try {
      const body = await this.readBody(req)
      const request = JSON.parse(body)
      // 简单估算 token 数量（每4个字符约1个token）
      let totalChars = 0
      if (request.messages) {
        for (const msg of request.messages) {
          if (typeof msg.content === 'string') {
            totalChars += msg.content.length
          } else if (Array.isArray(msg.content)) {
            for (const part of msg.content) {
              if (part.type === 'text' && part.text) {
                totalChars += part.text.length
              }
            }
          }
        }
      }
      if (request.system) {
        totalChars += typeof request.system === 'string' ? request.system.length : JSON.stringify(request.system).length
      }
      const estimatedTokens = Math.ceil(totalChars / 4)
      
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ input_tokens: estimatedTokens }))
    } catch (error) {
      this.sendError(res, 400, 'Invalid request body')
    }
  }

  // 模型列表缓存
  private modelCache: { models: KiroModel[]; timestamp: number } | null = null
  private readonly MODEL_CACHE_TTL = 5 * 60 * 1000 // 5 分钟缓存

  // 模型列表
  private async handleModels(res: http.ServerResponse): Promise<void> {
    const now = Date.now()
    
    // Kiro 官方模型（与 UI 保持一致）
    const kiroOfficialModels = [
      { id: 'auto', object: 'model', created: now, owned_by: 'kiro-api', description: 'Auto select best model' },
      { id: 'claude-sonnet-4.5', object: 'model', created: now, owned_by: 'kiro-api', description: 'The latest Claude Sonnet model' },
      { id: 'claude-sonnet-4', object: 'model', created: now, owned_by: 'kiro-api', description: 'Hybrid reasoning and coding' },
      { id: 'claude-haiku-4.5', object: 'model', created: now, owned_by: 'kiro-api', description: 'The latest Claude Haiku model' },
      { id: 'claude-opus-4.5', object: 'model', created: now, owned_by: 'kiro-api', description: 'The most powerful model' }
    ]

    // 预设模型（GPT 兼容别名）
    const presetModels = [
      { id: 'gpt-4o', object: 'model', created: now, owned_by: 'kiro-proxy' },
      { id: 'gpt-4', object: 'model', created: now, owned_by: 'kiro-proxy' },
      { id: 'gpt-4-turbo', object: 'model', created: now, owned_by: 'kiro-proxy' },
      { id: 'gpt-3.5-turbo', object: 'model', created: now, owned_by: 'kiro-proxy' }
    ]

    // 尝试从 Kiro API 获取动态模型
    let kiroModels: KiroModel[] = []
    
    // 检查缓存
    if (this.modelCache && (now - this.modelCache.timestamp) < this.MODEL_CACHE_TTL) {
      kiroModels = this.modelCache.models
    } else {
      // 获取一个可用账号来请求模型列表
      const account = this.accountPool.getNextAccount()
      if (account) {
        try {
          kiroModels = await fetchKiroModels(account)
          if (kiroModels.length > 0) {
            this.modelCache = { models: kiroModels, timestamp: now }
            proxyLogger.info('ProxyServer', `Fetched ${kiroModels.length} models from Kiro API`)
          }
        } catch (error) {
          console.error('[ProxyServer] Failed to fetch Kiro models:', error)
        }
      }
    }

    // 转换 Kiro 模型为 OpenAI 格式（保持原始 modelId）
    const dynamicModels = kiroModels.map(m => ({
      id: m.modelId,
      object: 'model' as const,
      created: now,
      owned_by: 'kiro-api',
      description: m.description,
      model_name: m.modelName
    }))

    // 合并模型列表，去重
    const modelIds = new Set<string>()
    const allModels: Array<{ id: string; object: string; created: number; owned_by: string; description?: string; model_name?: string }> = []
    
    // 1. 先添加 Kiro 官方模型（与 UI 保持一致）
    for (const m of kiroOfficialModels) {
      if (!modelIds.has(m.id)) {
        modelIds.add(m.id)
        allModels.push(m)
      }
    }
    
    // 2. 添加动态模型（从 API 获取的，可能有额外模型）
    for (const m of dynamicModels) {
      if (!modelIds.has(m.id)) {
        modelIds.add(m.id)
        allModels.push(m)
      }
    }
    
    // 3. 添加 GPT 兼容别名
    for (const m of presetModels) {
      if (!modelIds.has(m.id)) {
        modelIds.add(m.id)
        allModels.push(m)
      }
    }

    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ object: 'list', data: allModels }))
  }

  // 处理 OpenAI Chat Completions 请求
  private async handleOpenAIChat(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const body = await this.readBody(req)
    const request: OpenAIChatRequest = JSON.parse(body)
    const matchedApiKey = (req as unknown as { matchedApiKey?: import('./types').ApiKey }).matchedApiKey

    // 应用模型映射
    request.model = this.applyModelMapping(request.model, matchedApiKey?.id)

    // 检查是否为该模型默认启用思考模式
    const modelThinkingEnabled = this.config.modelThinkingMode?.[request.model]
    const thinkingEnabled = modelThinkingEnabled || (req.headers['anthropic-beta'] as string || '').toLowerCase().includes('thinking')

    this.recordNewRequest()
    this.events.onRequest?.({ path: '/v1/chat/completions', method: 'POST' })

    // 获取账号（包含 Token 刷新检查）
    const account = await this.getAvailableAccount()
    if (!account) {
      this.recordRequestFailed()
      this.sendError(res, 503, 'No available accounts')
      this.events.onResponse?.({ path: '/v1/chat/completions', model: request.model, status: 503, error: 'No available accounts' })
      this.recordRequest({ path: '/v1/chat/completions', model: request.model, success: false, error: 'No available accounts' })
      return
    }

    this.events.onRequest?.({ path: '/v1/chat/completions', method: 'POST', accountId: account.id })
    const startTime = Date.now()

    try {
      // 如果启用了禁用工具调用，移除 tools 参数
      const processedRequest = this.config.disableTools
        ? { ...request, tools: undefined, tool_choice: undefined }
        : request

      // 转换为 Kiro 格式
      let kiroPayload = openaiToKiro(processedRequest, account.profileArn)

      // 如果启用了 thinking 模式，注入系统提示
      if (thinkingEnabled) {
        const thinkingPrompt = `<thinking_mode>enabled</thinking_mode>\n<max_thinking_length>200000</max_thinking_length>\n\n`
        const currentMessage = kiroPayload.conversationState?.currentMessage?.userInputMessage
        if (currentMessage && typeof currentMessage.content === 'string') {
          currentMessage.content = thinkingPrompt + currentMessage.content
        }
        proxyLogger.info('ProxyServer', 'Thinking mode enabled for request')
      }

      // 记录请求详情到日志
      if (this.config.logRequests) {
        const userInput = kiroPayload.conversationState.currentMessage?.userInputMessage
        const contentLength = typeof userInput?.content === 'string' ? userInput.content.length : 0
        const toolsCount = userInput?.userInputMessageContext?.tools?.length || 0
        const historyLength = kiroPayload.conversationState.history?.length || 0
        const hasImages = (userInput?.images?.length || 0) > 0
        
        proxyLogger.info('ProxyServer', `OpenAI API: ${request.model}`, {
          model: request.model,
          stream: request.stream,
          contentLength,
          toolsCount,
          historyLength,
          hasImages,
          accountId: account.id
        })
      }

      if (request.stream) {
        // 流式响应（流式不使用重试机制，错误由流处理）
        await this.handleOpenAIStream(res, account, kiroPayload, request.model, startTime, 0, undefined, false, matchedApiKey)
      } else {
        // 非流式响应（带重试机制）
        const { result, account: usedAccount } = await this.callWithRetry(
          account,
          async (acc) => callKiroApi(acc, openaiToKiro(processedRequest, acc.profileArn)),
          '/v1/chat/completions'
        )
        const response = kiroToOpenaiResponse(result.content, result.toolUses, result.usage, request.model)

        this.recordRequestSuccess()
        this.stats.totalTokens += result.usage.inputTokens + result.usage.outputTokens
        this.stats.inputTokens += result.usage.inputTokens
        this.stats.outputTokens += result.usage.outputTokens
        this.accountPool.recordSuccess(usedAccount.id, result.usage.inputTokens + result.usage.outputTokens)

        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify(response))
        this.events.onResponse?.({ path: '/v1/chat/completions', model: request.model, status: 200, tokens: result.usage.inputTokens + result.usage.outputTokens, inputTokens: result.usage.inputTokens, outputTokens: result.usage.outputTokens })
        this.recordRequest({ path: '/v1/chat/completions', model: request.model, accountId: usedAccount.id, inputTokens: result.usage.inputTokens, outputTokens: result.usage.outputTokens, responseTime: Date.now() - startTime, success: true })
        // 记录 API Key 用量
        if (matchedApiKey) {
          this.recordApiKeyUsage(matchedApiKey.id, result.usage.credits || 0, result.usage.inputTokens, result.usage.outputTokens, request.model, '/v1/chat/completions')
        }
      }
    } catch (error) {
      this.handleApiError(res, account, error as Error, '/v1/chat/completions', request.model, startTime)
    }
  }

  // 处理 OpenAI 流式响应
  private async handleOpenAIStream(
    res: http.ServerResponse,
    account: { id: string; accessToken: string; profileArn?: string },
    kiroPayload: ReturnType<typeof openaiToKiro>,
    model: string,
    startTime: number,
    currentRound: number = 0,
    streamId?: string,
    headersSent: boolean = false,
    matchedApiKey?: import('./types').ApiKey
  ): Promise<void> {
    if (!headersSent) {
      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive'
      })
    }

    const id = streamId || `chatcmpl-${uuidv4()}`
    let toolCallIndex = 0
    const pendingToolCalls: Map<string, { index: number; name: string; arguments: string }> = new Map()
    let collectedContent = ''
    let hasLoggedThinkingFormat = false
    // 用于检测普通响应中的 <thinking> 标签
    let textBuffer = ''
    let inThinkingBlock = false

    // 发送初始 chunk（仅首轮）
    if (currentRound === 0) {
      const initialChunk = createOpenaiStreamChunk(id, model, { role: 'assistant' })
      res.write(`data: ${JSON.stringify(initialChunk)}\n\n`)
    }

    // 处理文本输出，检测并转换 <thinking> 标签
    const processText = (text: string, forceFlush = false) => {
      const format = this.config.thinkingOutputFormat || 'reasoning_content'
      textBuffer += text
      
      while (true) {
        if (!inThinkingBlock) {
          // 查找 <thinking> 开始标签
          const thinkingStart = textBuffer.indexOf('<thinking>')
          if (thinkingStart !== -1) {
            // 输出 thinking 标签之前的内容
            if (thinkingStart > 0) {
              const beforeThinking = textBuffer.substring(0, thinkingStart)
              collectedContent += beforeThinking
              const chunk = createOpenaiStreamChunk(id, model, { content: beforeThinking })
              res.write(`data: ${JSON.stringify(chunk)}\n\n`)
            }
            textBuffer = textBuffer.substring(thinkingStart + 10) // 移除 <thinking>
            inThinkingBlock = true
            if (!hasLoggedThinkingFormat) {
              proxyLogger.info('ProxyServer', `Detected <thinking> tag, output format: ${format}`)
              hasLoggedThinkingFormat = true
            }
          } else if (forceFlush || textBuffer.length > 50) {
            // 没有找到标签，安全输出（保留可能的部分标签，需要足够长以检测 </thinking>）
            const safeLength = forceFlush ? textBuffer.length : Math.max(0, textBuffer.length - 15)
            if (safeLength > 0) {
              const safeText = textBuffer.substring(0, safeLength)
              collectedContent += safeText
              const chunk = createOpenaiStreamChunk(id, model, { content: safeText })
              res.write(`data: ${JSON.stringify(chunk)}\n\n`)
              textBuffer = textBuffer.substring(safeLength)
            }
            break
          } else {
            break
          }
        } else {
          // 在 thinking 块内，查找 </thinking> 结束标签
          const thinkingEnd = textBuffer.indexOf('</thinking>')
          if (thinkingEnd !== -1) {
            // 输出 thinking 内容
            const thinkingContent = textBuffer.substring(0, thinkingEnd)
            if (thinkingContent) {
              if (format === 'thinking') {
                const chunk = createOpenaiStreamChunk(id, model, { content: `<thinking>${thinkingContent}</thinking>` })
                res.write(`data: ${JSON.stringify(chunk)}\n\n`)
              } else if (format === 'think') {
                const chunk = createOpenaiStreamChunk(id, model, { content: `<think>${thinkingContent}</think>` })
                res.write(`data: ${JSON.stringify(chunk)}\n\n`)
              } else {
                const chunk = createOpenaiStreamChunk(id, model, { reasoning_content: thinkingContent })
                res.write(`data: ${JSON.stringify(chunk)}\n\n`)
              }
            }
            textBuffer = textBuffer.substring(thinkingEnd + 11) // 移除 </thinking>
            inThinkingBlock = false
          } else if (forceFlush) {
            // 强制刷新：输出剩余内容（未闭合的 thinking 块）
            if (textBuffer) {
              if (format === 'thinking') {
                const chunk = createOpenaiStreamChunk(id, model, { content: `<thinking>${textBuffer}</thinking>` })
                res.write(`data: ${JSON.stringify(chunk)}\n\n`)
              } else if (format === 'think') {
                const chunk = createOpenaiStreamChunk(id, model, { content: `<think>${textBuffer}</think>` })
                res.write(`data: ${JSON.stringify(chunk)}\n\n`)
              } else {
                const chunk = createOpenaiStreamChunk(id, model, { reasoning_content: textBuffer })
                res.write(`data: ${JSON.stringify(chunk)}\n\n`)
              }
              textBuffer = ''
            }
            break
          } else {
            break
          }
        }
      }
    }

    return new Promise((resolve) => {
      callKiroApiStream(
        account as any,
        kiroPayload,
        (text, toolUse, isThinking) => {
          if (text) {
            if (isThinking) {
              // reasoningContentEvent 的思考内容
              const format = this.config.thinkingOutputFormat || 'reasoning_content'
              if (!hasLoggedThinkingFormat) {
                proxyLogger.info('ProxyServer', `Thinking output format (reasoningContentEvent): ${format}`)
                hasLoggedThinkingFormat = true
              }
              if (format === 'thinking') {
                const chunk = createOpenaiStreamChunk(id, model, { content: `<thinking>${text}</thinking>` })
                res.write(`data: ${JSON.stringify(chunk)}\n\n`)
              } else if (format === 'think') {
                const chunk = createOpenaiStreamChunk(id, model, { content: `<think>${text}</think>` })
                res.write(`data: ${JSON.stringify(chunk)}\n\n`)
              } else {
                const chunk = createOpenaiStreamChunk(id, model, { reasoning_content: text })
                res.write(`data: ${JSON.stringify(chunk)}\n\n`)
              }
            } else {
              // 普通文本，检测 <thinking> 标签
              processText(text)
            }
          }
          if (toolUse) {
            const idx = toolCallIndex++
            pendingToolCalls.set(toolUse.toolUseId, {
              index: idx,
              name: toolUse.name,
              arguments: JSON.stringify(toolUse.input)
            })
            // 发送 tool_call chunk
            const toolChunk = createOpenaiStreamChunk(id, model, {
              tool_calls: [{
                index: idx,
                id: toolUse.toolUseId,
                type: 'function',
                function: {
                  name: toolUse.name,
                  arguments: JSON.stringify(toolUse.input)
                }
              }]
            })
            res.write(`data: ${JSON.stringify(toolChunk)}\n\n`)
          }
        },
        async (usage) => {
          // 刷新缓冲区中剩余的内容
          processText('', true)
          
          this.recordRequestSuccess()
          this.stats.totalTokens += usage.inputTokens + usage.outputTokens
          this.stats.inputTokens += usage.inputTokens
          this.stats.outputTokens += usage.outputTokens
          this.stats.totalCredits += usage.credits || 0
          this.events.onCreditsUpdate?.(this.stats.totalCredits)
          this.events.onTokensUpdate?.(this.stats.inputTokens, this.stats.outputTokens)
          this.accountPool.recordSuccess(account.id, usage.inputTokens + usage.outputTokens)
          this.events.onResponse?.({ path: '/v1/chat/completions', model, status: 200, tokens: usage.inputTokens + usage.outputTokens, inputTokens: usage.inputTokens, outputTokens: usage.outputTokens, credits: usage.credits })
          this.recordRequest({ path: '/v1/chat/completions', model, accountId: account.id, inputTokens: usage.inputTokens, outputTokens: usage.outputTokens, credits: usage.credits, responseTime: Date.now() - startTime, success: true })
          // 记录 API Key 用量
          if (matchedApiKey) {
            this.recordApiKeyUsage(matchedApiKey.id, usage.credits || 0, usage.inputTokens, usage.outputTokens, model, '/v1/chat/completions')
          }

          // 检查是否需要自动继续
          const maxRounds = this.config.autoContinueRounds || 0
          const hasToolCalls = pendingToolCalls.size > 0
          const shouldContinue = hasToolCalls && maxRounds > 0 && currentRound < maxRounds

          if (shouldContinue) {
            console.log(`[ProxyServer] Auto-continue round ${currentRound + 1}/${maxRounds}`)
            
            // 构造继续请求：添加 assistant 响应、工具结果和继续消息
            const toolResults = Array.from(pendingToolCalls.entries()).map(([toolId]) => ({
              toolUseId: toolId,
              content: [{ text: 'Done. Continue with the next step.' }]
            }))

            // 获取原始消息的 modelId 和 origin
            const originalMsg = kiroPayload.conversationState?.currentMessage?.userInputMessage
            const modelId = originalMsg?.modelId || 'anthropic.claude-sonnet-4-20250514-v1:0'
            const origin = originalMsg?.origin || 'CHAT'

            // 构造新的 Kiro payload
            const continuePayload = {
              ...kiroPayload,
              conversationState: {
                ...kiroPayload.conversationState,
                currentMessage: {
                  userInputMessage: {
                    content: 'Continue.',
                    userInputMessageContext: {},
                    modelId,
                    origin
                  }
                },
                history: [
                  ...(kiroPayload.conversationState?.history || []),
                  // 添加 assistant 响应
                  {
                    assistantResponseMessage: {
                      content: collectedContent || 'I will continue with the task.',
                      ...(pendingToolCalls.size > 0 ? {
                        toolUses: Array.from(pendingToolCalls.entries()).map(([toolId, toolData]) => ({
                          toolUseId: toolId,
                          name: toolData.name,
                          input: JSON.parse(toolData.arguments)
                        }))
                      } : {})
                    }
                  },
                  // 添加工具结果（作为 user 消息）
                  ...(toolResults.length > 0 ? [{
                    userInputMessage: {
                      content: 'Tool results provided.',
                      modelId,
                      origin,
                      userInputMessageContext: {
                        toolResults
                      }
                    }
                  }] : [])
                ]
              }
            } as typeof kiroPayload

            // 递归调用继续流式输出
            try {
              await this.handleOpenAIStream(res, account, continuePayload, model, startTime, currentRound + 1, id, true)
            } catch (error) {
              console.error('[ProxyServer] Auto-continue error:', error)
            }
            resolve()
          } else {
            // 发送结束 chunk（包含完整 usage 信息）
            const finishReason = hasToolCalls ? 'tool_calls' : 'stop'
            const usageInfo: {
              prompt_tokens: number
              completion_tokens: number
              total_tokens: number
              prompt_tokens_details?: { cached_tokens?: number }
              completion_tokens_details?: { reasoning_tokens?: number }
            } = {
              prompt_tokens: usage.inputTokens,
              completion_tokens: usage.outputTokens,
              total_tokens: usage.inputTokens + usage.outputTokens
            }
            // 添加 cache tokens 详情
            if (usage.cacheReadTokens && usage.cacheReadTokens > 0) {
              usageInfo.prompt_tokens_details = { cached_tokens: usage.cacheReadTokens }
            }
            // 添加 reasoning tokens 详情
            if (usage.reasoningTokens && usage.reasoningTokens > 0) {
              usageInfo.completion_tokens_details = { reasoning_tokens: usage.reasoningTokens }
            }
            const finalChunk = createOpenaiStreamChunk(id, model, {}, finishReason, usageInfo)
            res.write(`data: ${JSON.stringify(finalChunk)}\n\n`)
            res.write('data: [DONE]\n\n')
            res.end()
            resolve()
          }
        },
        (error) => {
          console.error('[ProxyServer] Stream error:', error)
          res.write(`data: ${JSON.stringify({ error: { message: error.message } })}\n\n`)
          res.end()

          this.recordRequestFailed()
          const isQuotaError = error.message.includes('429') || error.message.includes('quota')
          this.accountPool.recordError(account.id, isQuotaError)
          this.events.onResponse?.({ path: '/v1/chat/completions', model, status: 500, error: error.message })
          this.recordRequest({ path: '/v1/chat/completions', model, accountId: account.id, responseTime: Date.now() - startTime, success: false, error: error.message })
          resolve()
        }
      )
    })
  }

  // 处理 Claude Messages 请求
  private async handleClaudeMessages(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const body = await this.readBody(req)
    const request: ClaudeRequest = JSON.parse(body)
    const matchedApiKey = (req as unknown as { matchedApiKey?: import('./types').ApiKey }).matchedApiKey

    // 应用模型映射
    request.model = this.applyModelMapping(request.model, matchedApiKey?.id)

    // 检查是否为该模型默认启用思考模式
    const modelThinkingEnabled = this.config.modelThinkingMode?.[request.model]
    const thinkingEnabled = modelThinkingEnabled || (req.headers['anthropic-beta'] as string || '').toLowerCase().includes('thinking')

    this.recordNewRequest()
    this.events.onRequest?.({ path: '/v1/messages', method: 'POST' })

    // 获取账号（包含 Token 刷新检查）
    const account = await this.getAvailableAccount()
    if (!account) {
      this.recordRequestFailed()
      this.sendError(res, 503, 'No available accounts')
      this.events.onResponse?.({ path: '/v1/messages', model: request.model, status: 503, error: 'No available accounts' })
      this.recordRequest({ path: '/v1/messages', model: request.model, success: false, error: 'No available accounts' })
      return
    }

    this.events.onRequest?.({ path: '/v1/messages', method: 'POST', accountId: account.id })
    const startTime = Date.now()

    try {
      // 转换为 Kiro 格式
      let kiroPayload = claudeToKiro(request, account.profileArn)

      // 如果启用了 thinking 模式，注入系统提示
      if (thinkingEnabled) {
        const thinkingPrompt = `<thinking_mode>enabled</thinking_mode>\n<max_thinking_length>200000</max_thinking_length>\n\n`
        const currentMessage = kiroPayload.conversationState?.currentMessage?.userInputMessage
        if (currentMessage && typeof currentMessage.content === 'string') {
          currentMessage.content = thinkingPrompt + currentMessage.content
        }
        proxyLogger.info('ProxyServer', 'Thinking mode enabled for Claude request')
      }

      // 记录请求详情到日志
      if (this.config.logRequests) {
        const userInput = kiroPayload.conversationState.currentMessage?.userInputMessage
        const contentLength = typeof userInput?.content === 'string' ? userInput.content.length : 0
        const toolsCount = userInput?.userInputMessageContext?.tools?.length || 0
        const historyLength = kiroPayload.conversationState.history?.length || 0
        const hasImages = (userInput?.images?.length || 0) > 0
        
        proxyLogger.info('ProxyServer', `Claude API: ${request.model}`, {
          model: request.model,
          stream: request.stream,
          contentLength,
          toolsCount,
          historyLength,
          hasImages,
          accountId: account.id.substring(0, 8) + '...'
        })
      }

      if (request.stream) {
        // 流式响应（流式不使用重试机制，错误由流处理）
        await this.handleClaudeStream(res, account, kiroPayload, request.model, startTime, 0, undefined, false, 0, matchedApiKey)
      } else {
        // 非流式响应（带重试机制）
        const { result, account: usedAccount } = await this.callWithRetry(
          account,
          async (acc) => callKiroApi(acc, claudeToKiro(request, acc.profileArn)),
          '/v1/messages'
        )
        const response = kiroToClaudeResponse(result.content, result.toolUses, result.usage, request.model)

        this.recordRequestSuccess()
        this.stats.totalTokens += result.usage.inputTokens + result.usage.outputTokens
        this.stats.inputTokens += result.usage.inputTokens
        this.stats.outputTokens += result.usage.outputTokens
        this.accountPool.recordSuccess(usedAccount.id, result.usage.inputTokens + result.usage.outputTokens)

        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify(response))
        this.events.onResponse?.({ path: '/v1/messages', model: request.model, status: 200, tokens: result.usage.inputTokens + result.usage.outputTokens, inputTokens: result.usage.inputTokens, outputTokens: result.usage.outputTokens })
        this.recordRequest({ path: '/v1/messages', model: request.model, accountId: usedAccount.id, inputTokens: result.usage.inputTokens, outputTokens: result.usage.outputTokens, responseTime: Date.now() - startTime, success: true })
      }
    } catch (error) {
      this.handleApiError(res, account, error as Error, '/v1/messages', request.model, startTime)
    }
  }

  // 处理 Claude 流式响应
  private async handleClaudeStream(
    res: http.ServerResponse,
    account: { id: string; accessToken: string; profileArn?: string },
    kiroPayload: ReturnType<typeof claudeToKiro>,
    model: string,
    startTime: number,
    currentRound: number = 0,
    msgId?: string,
    headersSent: boolean = false,
    contentBlockIndex: number = 0,
    matchedApiKey?: import('./types').ApiKey
  ): Promise<void> {
    if (!headersSent) {
      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive'
      })
    }

    const id = msgId || `msg_${uuidv4()}`
    let currentBlockIndex = contentBlockIndex
    let hasStartedTextBlock = false
    let collectedContent = ''
    const pendingToolCalls: Map<string, { name: string; input: Record<string, unknown> }> = new Map()
    let hasLoggedThinkingFormat = false
    // 用于检测普通响应中的 <thinking> 标签
    let textBuffer = ''
    let inThinkingBlock = false

    // 估算输入 tokens（基于 payload 大小）
    const estimatedInputTokens = Math.max(1, Math.round(JSON.stringify(kiroPayload).length / 3))

    // 处理文本输出，检测并转换 <thinking> 标签
    const processClaudeText = (text: string, forceFlush = false) => {
      const format = this.config.thinkingOutputFormat || 'reasoning_content'
      textBuffer += text
      
      while (true) {
        if (!inThinkingBlock) {
          // 查找 <thinking> 开始标签
          const thinkingStart = textBuffer.indexOf('<thinking>')
          if (thinkingStart !== -1) {
            // 输出 thinking 标签之前的内容
            if (thinkingStart > 0) {
              const beforeThinking = textBuffer.substring(0, thinkingStart)
              collectedContent += beforeThinking
              if (!hasStartedTextBlock) {
                const blockStart = createClaudeStreamEvent('content_block_start', {
                  index: currentBlockIndex,
                  content_block: { type: 'text', text: '' }
                })
                res.write(`event: content_block_start\ndata: ${JSON.stringify(blockStart)}\n\n`)
                hasStartedTextBlock = true
              }
              const delta = createClaudeStreamEvent('content_block_delta', {
                index: currentBlockIndex,
                delta: { type: 'text_delta', text: beforeThinking }
              })
              res.write(`event: content_block_delta\ndata: ${JSON.stringify(delta)}\n\n`)
            }
            textBuffer = textBuffer.substring(thinkingStart + 10) // 移除 <thinking>
            inThinkingBlock = true
            if (!hasLoggedThinkingFormat) {
              proxyLogger.info('ProxyServer', `[Claude] Detected <thinking> tag, output format: ${format}`)
              hasLoggedThinkingFormat = true
            }
          } else if (forceFlush || textBuffer.length > 50) {
            // 没有找到标签，安全输出
            const safeLength = forceFlush ? textBuffer.length : Math.max(0, textBuffer.length - 15)
            if (safeLength > 0) {
              const safeText = textBuffer.substring(0, safeLength)
              collectedContent += safeText
              if (!hasStartedTextBlock) {
                const blockStart = createClaudeStreamEvent('content_block_start', {
                  index: currentBlockIndex,
                  content_block: { type: 'text', text: '' }
                })
                res.write(`event: content_block_start\ndata: ${JSON.stringify(blockStart)}\n\n`)
                hasStartedTextBlock = true
              }
              const delta = createClaudeStreamEvent('content_block_delta', {
                index: currentBlockIndex,
                delta: { type: 'text_delta', text: safeText }
              })
              res.write(`event: content_block_delta\ndata: ${JSON.stringify(delta)}\n\n`)
              textBuffer = textBuffer.substring(safeLength)
            }
            break
          } else {
            break
          }
        } else {
          // 在 thinking 块内，查找 </thinking> 结束标签
          const thinkingEnd = textBuffer.indexOf('</thinking>')
          if (thinkingEnd !== -1) {
            // 输出 thinking 内容
            const thinkingContent = textBuffer.substring(0, thinkingEnd)
            if (thinkingContent) {
              if (!hasStartedTextBlock) {
                const blockStart = createClaudeStreamEvent('content_block_start', {
                  index: currentBlockIndex,
                  content_block: { type: 'text', text: '' }
                })
                res.write(`event: content_block_start\ndata: ${JSON.stringify(blockStart)}\n\n`)
                hasStartedTextBlock = true
              }
              if (format === 'thinking') {
                const delta = createClaudeStreamEvent('content_block_delta', {
                  index: currentBlockIndex,
                  delta: { type: 'text_delta', text: `<thinking>${thinkingContent}</thinking>` }
                })
                res.write(`event: content_block_delta\ndata: ${JSON.stringify(delta)}\n\n`)
              } else if (format === 'think') {
                const delta = createClaudeStreamEvent('content_block_delta', {
                  index: currentBlockIndex,
                  delta: { type: 'text_delta', text: `<think>${thinkingContent}</think>` }
                })
                res.write(`event: content_block_delta\ndata: ${JSON.stringify(delta)}\n\n`)
              }
              // reasoning_content 格式：过滤掉 thinking 内容（大多数客户端不支持此字段）
            }
            textBuffer = textBuffer.substring(thinkingEnd + 11) // 移除 </thinking>
            inThinkingBlock = false
          } else if (forceFlush && textBuffer) {
            // 强制刷新：输出剩余内容
            if (format === 'thinking' || format === 'think') {
              if (!hasStartedTextBlock) {
                const blockStart = createClaudeStreamEvent('content_block_start', {
                  index: currentBlockIndex,
                  content_block: { type: 'text', text: '' }
                })
                res.write(`event: content_block_start\ndata: ${JSON.stringify(blockStart)}\n\n`)
                hasStartedTextBlock = true
              }
              const tag = format === 'thinking' ? 'thinking' : 'think'
              const delta = createClaudeStreamEvent('content_block_delta', {
                index: currentBlockIndex,
                delta: { type: 'text_delta', text: `<${tag}>${textBuffer}</${tag}>` }
              })
              res.write(`event: content_block_delta\ndata: ${JSON.stringify(delta)}\n\n`)
            }
            // reasoning_content 格式：过滤掉 thinking 内容
            textBuffer = ''
            break
          } else {
            break
          }
        }
      }
    }
    
    // 发送 message_start（仅首轮）
    if (currentRound === 0) {
      const messageStart = createClaudeStreamEvent('message_start', {
        message: {
          id,
          type: 'message',
          role: 'assistant',
          content: [],
          model,
          stop_reason: null,
          stop_sequence: null,
          usage: { input_tokens: estimatedInputTokens, output_tokens: 0 }
        }
      })
      res.write(`event: message_start\ndata: ${JSON.stringify(messageStart)}\n\n`)
    }

    return new Promise((resolve) => {
      callKiroApiStream(
        account as any,
        kiroPayload,
        (text, toolUse, isThinking) => {
          if (text) {
            if (isThinking) {
              // reasoningContentEvent 的思考内容
              const format = this.config.thinkingOutputFormat || 'reasoning_content'
              if (!hasLoggedThinkingFormat) {
                proxyLogger.info('ProxyServer', `[Claude] Thinking output format (reasoningContentEvent): ${format}`)
                hasLoggedThinkingFormat = true
              }
              // reasoning_content 格式：过滤掉思考内容（大多数客户端不支持）
              if (format === 'thinking' || format === 'think') {
                if (!hasStartedTextBlock) {
                  const blockStart = createClaudeStreamEvent('content_block_start', {
                    index: currentBlockIndex,
                    content_block: { type: 'text', text: '' }
                  })
                  res.write(`event: content_block_start\ndata: ${JSON.stringify(blockStart)}\n\n`)
                  hasStartedTextBlock = true
                }
                const tag = format === 'thinking' ? 'thinking' : 'think'
                const delta = createClaudeStreamEvent('content_block_delta', {
                  index: currentBlockIndex,
                  delta: { type: 'text_delta', text: `<${tag}>${text}</${tag}>` }
                })
                res.write(`event: content_block_delta\ndata: ${JSON.stringify(delta)}\n\n`)
              }
            } else {
              // 普通文本，检测 <thinking> 标签
              processClaudeText(text)
            }
          }
          if (toolUse) {
            // 结束之前的文本块
            if (hasStartedTextBlock) {
              const blockStop = createClaudeStreamEvent('content_block_stop', { index: currentBlockIndex })
              res.write(`event: content_block_stop\ndata: ${JSON.stringify(blockStop)}\n\n`)
              currentBlockIndex++
              hasStartedTextBlock = false
            }
            // 记录工具调用
            pendingToolCalls.set(toolUse.toolUseId, { name: toolUse.name, input: toolUse.input })
            // 开始工具块
            const toolBlockStart = createClaudeStreamEvent('content_block_start', {
              index: currentBlockIndex,
              content_block: { type: 'tool_use', id: toolUse.toolUseId, name: toolUse.name, input: {} }
            })
            res.write(`event: content_block_start\ndata: ${JSON.stringify(toolBlockStart)}\n\n`)
            // 发送工具输入
            const toolDelta = createClaudeStreamEvent('content_block_delta', {
              index: currentBlockIndex,
              delta: { type: 'input_json_delta', partial_json: JSON.stringify(toolUse.input) } as any
            })
            res.write(`event: content_block_delta\ndata: ${JSON.stringify(toolDelta)}\n\n`)
            // 结束工具块
            const toolBlockStop = createClaudeStreamEvent('content_block_stop', { index: currentBlockIndex })
            res.write(`event: content_block_stop\ndata: ${JSON.stringify(toolBlockStop)}\n\n`)
            currentBlockIndex++
          }
        },
        async (usage) => {
          // 刷新缓冲区中剩余的内容
          processClaudeText('', true)
          
          // 结束最后的文本块
          if (hasStartedTextBlock) {
            const blockStop = createClaudeStreamEvent('content_block_stop', { index: currentBlockIndex })
            res.write(`event: content_block_stop\ndata: ${JSON.stringify(blockStop)}\n\n`)
            currentBlockIndex++
          }

          this.recordRequestSuccess()
          this.stats.totalTokens += usage.inputTokens + usage.outputTokens
          this.stats.inputTokens += usage.inputTokens
          this.stats.outputTokens += usage.outputTokens
          this.stats.totalCredits += usage.credits || 0
          this.events.onCreditsUpdate?.(this.stats.totalCredits)
          this.events.onTokensUpdate?.(this.stats.inputTokens, this.stats.outputTokens)
          this.accountPool.recordSuccess(account.id, usage.inputTokens + usage.outputTokens)
          this.events.onResponse?.({ path: '/v1/messages', model, status: 200, tokens: usage.inputTokens + usage.outputTokens, inputTokens: usage.inputTokens, outputTokens: usage.outputTokens, credits: usage.credits })
          this.recordRequest({ path: '/v1/messages', model, accountId: account.id, inputTokens: usage.inputTokens, outputTokens: usage.outputTokens, credits: usage.credits, responseTime: Date.now() - startTime, success: true })
          // 记录 API Key 用量
          if (matchedApiKey) {
            this.recordApiKeyUsage(matchedApiKey.id, usage.credits || 0, usage.inputTokens, usage.outputTokens, model, '/v1/messages')
          }

          // 检查是否需要自动继续
          const maxRounds = this.config.autoContinueRounds || 0
          const hasToolCalls = pendingToolCalls.size > 0
          const shouldContinue = hasToolCalls && maxRounds > 0 && currentRound < maxRounds

          if (shouldContinue) {
            console.log(`[ProxyServer] Claude auto-continue round ${currentRound + 1}/${maxRounds}`)
            
            // 构造继续请求
            const toolResults = Array.from(pendingToolCalls.entries()).map(([toolId]) => ({
              toolUseId: toolId,
              content: [{ text: 'Done. Continue with the next step.' }],
              status: 'success' as const
            }))

            const originalMsg = kiroPayload.conversationState?.currentMessage?.userInputMessage
            const modelId = originalMsg?.modelId || 'anthropic.claude-sonnet-4-20250514-v1:0'
            const origin = originalMsg?.origin || 'CHAT'

            const continuePayload = {
              ...kiroPayload,
              conversationState: {
                ...kiroPayload.conversationState,
                currentMessage: {
                  userInputMessage: {
                    content: 'Continue.',
                    userInputMessageContext: {
                      toolResults
                    },
                    modelId,
                    origin
                  }
                },
                history: [
                  ...(kiroPayload.conversationState?.history || []),
                  {
                    assistantResponseMessage: {
                      content: collectedContent || 'I will continue with the task.',
                      ...(pendingToolCalls.size > 0 ? {
                        toolUses: Array.from(pendingToolCalls.entries()).map(([toolId, toolData]) => ({
                          toolUseId: toolId,
                          name: toolData.name,
                          input: toolData.input
                        }))
                      } : {})
                    }
                  }
                ]
              }
            } as typeof kiroPayload

            try {
              await this.handleClaudeStream(res, account, continuePayload, model, startTime, currentRound + 1, id, true, currentBlockIndex, matchedApiKey)
            } catch (error) {
              console.error('[ProxyServer] Claude auto-continue error:', error)
            }
            resolve()
          } else {
            // 发送 message_delta（包含完整 usage 信息）
            const stopReason = hasToolCalls ? 'tool_use' : 'end_turn'
            const messageDelta = createClaudeStreamEvent('message_delta', {
              delta: { stop_reason: stopReason, stop_sequence: null } as any,
              usage: { input_tokens: usage.inputTokens, output_tokens: usage.outputTokens }
            })
            res.write(`event: message_delta\ndata: ${JSON.stringify(messageDelta)}\n\n`)
            // 发送 message_stop
            const messageStop = createClaudeStreamEvent('message_stop')
            res.write(`event: message_stop\ndata: ${JSON.stringify(messageStop)}\n\n`)
            res.end()
            resolve()
          }
        },
        (error) => {
          console.error('[ProxyServer] Stream error:', error)
          const errorEvent = createClaudeStreamEvent('error', {
            error: { type: 'api_error', message: error.message }
          })
          res.write(`event: error\ndata: ${JSON.stringify(errorEvent)}\n\n`)
          res.end()

          this.recordRequestFailed()
          const isQuotaError = error.message.includes('429') || error.message.includes('quota')
          this.accountPool.recordError(account.id, isQuotaError)
          this.events.onResponse?.({ path: '/v1/messages', model, status: 500, error: error.message })
          this.recordRequest({ path: '/v1/messages', model, accountId: account.id, responseTime: Date.now() - startTime, success: false, error: error.message })
          resolve()
        }
      )
    })
  }

  // 处理 API 错误
  private handleApiError(res: http.ServerResponse, account: { id: string }, error: Error, path: string, model?: string, startTime?: number): void {
    this.recordRequestFailed()
    const isQuotaError = error.message.includes('429') || error.message.includes('quota')
    const isAuthError = error.message.includes('401') || error.message.includes('403') || error.message.includes('Auth')

    this.accountPool.recordError(account.id, isQuotaError)

    let statusCode = 500
    if (isQuotaError) statusCode = 429
    if (isAuthError) statusCode = 401

    this.sendError(res, statusCode, error.message)
    this.events.onResponse?.({ path, status: statusCode, error: error.message })
    this.recordRequest({ path, model, accountId: account.id, responseTime: startTime ? Date.now() - startTime : 0, success: false, error: error.message })
  }

  // 读取请求体
  private readBody(req: http.IncomingMessage): Promise<string> {
    return new Promise((resolve, reject) => {
      let body = ''
      req.on('data', chunk => body += chunk)
      req.on('end', () => resolve(body))
      req.on('error', reject)
    })
  }

  // 发送错误响应
  private sendError(res: http.ServerResponse, status: number, message: string): void {
    res.writeHead(status, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ error: { message, type: 'error', code: status } }))
  }

  // 记录请求到 recentRequests
  private recordRequest(log: {
    path: string
    model?: string
    accountId?: string
    inputTokens?: number
    outputTokens?: number
    credits?: number
    responseTime?: number
    success: boolean
    error?: string
  }): void {
    this.stats.recentRequests.push({
      timestamp: Date.now(),
      path: log.path,
      model: log.model || 'unknown',
      accountId: log.accountId || 'unknown',
      inputTokens: log.inputTokens || 0,
      outputTokens: log.outputTokens || 0,
      credits: log.credits,
      responseTime: log.responseTime || 0,
      success: log.success,
      error: log.error
    })
    // 只保留最近 100 条
    if (this.stats.recentRequests.length > 100) {
      this.stats.recentRequests = this.stats.recentRequests.slice(-100)
    }
  }
}
