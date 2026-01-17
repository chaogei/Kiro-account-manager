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
  onResponse?: (info: { path: string; status: number; tokens?: number; error?: string }) => void
  onError?: (error: Error) => void
  onStatusChange?: (running: boolean, port: number) => void
  onTokenRefresh?: TokenRefreshCallback
  onAccountUpdate?: (account: ProxyAccount) => void
}

export class ProxyServer {
  private server: http.Server | https.Server | null = null
  private accountPool: AccountPool
  private config: ProxyConfig
  private stats: ProxyStats
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
      inputTokens: 0,
      outputTokens: 0,
      startTime: Date.now(),
      accountStats: new Map(),
      endpointStats: new Map(),
      modelStats: new Map(),
      recentRequests: []
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
        console.log(`[ProxyServer] Started on ${protocol}://${this.config.host}:${this.config.port}`)
        this.stats.startTime = Date.now()
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
        console.log('[ProxyServer] Stopped')
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
    return { ...this.stats }
  }

  // 获取账号池
  getAccountPool(): AccountPool {
    return this.accountPool
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
    const account = this.accountPool.getNextAccount()
    if (!account) return null

    // 检查是否需要刷新 Token
    if (this.isTokenExpiringSoon(account)) {
      const refreshed = await this.refreshToken(account)
      if (!refreshed) {
        // 刷新失败，尝试获取下一个账号
        return this.accountPool.getNextAccount()
      }
      // 返回更新后的账号
      return this.accountPool.getAccount(account.id)
    }

    return account
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
          // 刷新失败，切换账号
          const nextAccount = this.accountPool.getNextAccount()
          if (nextAccount && nextAccount.id !== currentAccount.id) {
            currentAccount = nextAccount
            continue
          }
        }

        // 429: 切换端点或账号
        if (errMsg.includes('429') || errMsg.includes('quota') || errMsg.includes('ThrottlingException')) {
          console.log('[ProxyServer] Quota/throttle error, switching endpoint or account')
          this.accountPool.recordError(currentAccount.id, true)
          endpointIndex = (endpointIndex + 1) % 2 // 切换端点
          if (endpointIndex === 0) {
            // 已尝试所有端点，切换账号
            const nextAccount = this.accountPool.getNextAccount()
            if (nextAccount && nextAccount.id !== currentAccount.id) {
              currentAccount = nextAccount
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

  // 验证 API Key
  private validateApiKey(req: http.IncomingMessage): boolean {
    // 如果没有配置 API Key，则跳过验证
    if (!this.config.apiKey) return true

    // 从 Authorization 头或 X-Api-Key 头获取 API Key
    const authHeader = req.headers['authorization'] || ''
    const apiKeyHeader = req.headers['x-api-key'] || ''

    // Bearer token 格式
    if (authHeader.startsWith('Bearer ')) {
      const token = authHeader.slice(7)
      if (token === this.config.apiKey) return true
    }

    // 直接 API Key 格式
    if (apiKeyHeader === this.config.apiKey) return true

    return false
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
    if (path !== '/health' && path !== '/' && !this.validateApiKey(req)) {
      this.sendError(res, 401, 'Invalid or missing API key')
      return
    }

    // 记录请求
    if (this.config.logRequests) {
      console.log(`[ProxyServer] ${method} ${path}`)
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
    if (!this.validateApiKey(req)) {
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
    
    // 预设模型（兼容 OpenAI 格式）
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
            console.log(`[ProxyServer] Fetched ${kiroModels.length} models from Kiro API`)
          }
        } catch (error) {
          console.error('[ProxyServer] Failed to fetch Kiro models:', error)
        }
      }
    }

    // 转换 Kiro 模型为 OpenAI 格式
    const dynamicModels = kiroModels.map(m => ({
      id: m.modelId.replace(/\./g, '-'), // claude-sonnet-4.5 -> claude-sonnet-4-5
      object: 'model' as const,
      created: now,
      owned_by: 'kiro-api',
      description: m.description,
      model_name: m.modelName
    }))

    // 合并模型列表（动态 + 预设），去重
    const modelIds = new Set<string>()
    const allModels: Array<{ id: string; object: string; created: number; owned_by: string; description?: string; model_name?: string }> = []
    
    // 先添加动态模型
    for (const m of dynamicModels) {
      if (!modelIds.has(m.id)) {
        modelIds.add(m.id)
        allModels.push(m)
      }
    }
    
    // 再添加预设模型
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

    this.stats.totalRequests++
    this.events.onRequest?.({ path: '/v1/chat/completions', method: 'POST' })

    // 获取账号（包含 Token 刷新检查）
    const account = await this.getAvailableAccount()
    if (!account) {
      this.stats.failedRequests++
      this.sendError(res, 503, 'No available accounts')
      this.events.onResponse?.({ path: '/v1/chat/completions', status: 503, error: 'No available accounts' })
      this.recordRequest({ path: '/v1/chat/completions', model: request.model, success: false, error: 'No available accounts' })
      return
    }

    this.events.onRequest?.({ path: '/v1/chat/completions', method: 'POST', accountId: account.id })
    const startTime = Date.now()

    try {
      // 转换为 Kiro 格式
      const kiroPayload = openaiToKiro(request, account.profileArn)

      if (request.stream) {
        // 流式响应（流式不使用重试机制，错误由流处理）
        await this.handleOpenAIStream(res, account, kiroPayload, request.model, startTime)
      } else {
        // 非流式响应（带重试机制）
        const { result, account: usedAccount } = await this.callWithRetry(
          account,
          async (acc) => callKiroApi(acc, openaiToKiro(request, acc.profileArn)),
          '/v1/chat/completions'
        )
        const response = kiroToOpenaiResponse(result.content, result.toolUses, result.usage, request.model)

        this.stats.successRequests++
        this.stats.totalTokens += result.usage.inputTokens + result.usage.outputTokens
        this.accountPool.recordSuccess(usedAccount.id, result.usage.inputTokens + result.usage.outputTokens)

        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify(response))
        this.events.onResponse?.({ path: '/v1/chat/completions', status: 200, tokens: result.usage.inputTokens + result.usage.outputTokens })
        this.recordRequest({ path: '/v1/chat/completions', model: request.model, accountId: usedAccount.id, inputTokens: result.usage.inputTokens, outputTokens: result.usage.outputTokens, responseTime: Date.now() - startTime, success: true })
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
    startTime: number
  ): Promise<void> {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive'
    })

    const streamId = `chatcmpl-${uuidv4()}`
    let toolCallIndex = 0
    const pendingToolCalls: Map<string, { index: number; name: string; arguments: string }> = new Map()

    // 发送初始 chunk
    const initialChunk = createOpenaiStreamChunk(streamId, model, { role: 'assistant' })
    res.write(`data: ${JSON.stringify(initialChunk)}\n\n`)

    return new Promise((resolve) => {
      callKiroApiStream(
        account as any,
        kiroPayload,
        (text, toolUse) => {
          if (text) {
            const chunk = createOpenaiStreamChunk(streamId, model, { content: text })
            res.write(`data: ${JSON.stringify(chunk)}\n\n`)
          }
          if (toolUse) {
            const idx = toolCallIndex++
            pendingToolCalls.set(toolUse.toolUseId, {
              index: idx,
              name: toolUse.name,
              arguments: JSON.stringify(toolUse.input)
            })
            // 发送 tool_call chunk
            const toolChunk = createOpenaiStreamChunk(streamId, model, {
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
        (usage) => {
          // 发送结束 chunk
          const finishReason = pendingToolCalls.size > 0 ? 'tool_calls' : 'stop'
          const finalChunk = createOpenaiStreamChunk(streamId, model, {}, finishReason)
          res.write(`data: ${JSON.stringify(finalChunk)}\n\n`)
          res.write('data: [DONE]\n\n')
          res.end()

          this.stats.successRequests++
          this.stats.totalTokens += usage.inputTokens + usage.outputTokens
          this.accountPool.recordSuccess(account.id, usage.inputTokens + usage.outputTokens)
          this.events.onResponse?.({ path: '/v1/chat/completions', status: 200, tokens: usage.inputTokens + usage.outputTokens })
          this.recordRequest({ path: '/v1/chat/completions', model, accountId: account.id, inputTokens: usage.inputTokens, outputTokens: usage.outputTokens, responseTime: Date.now() - startTime, success: true })
          resolve()
        },
        (error) => {
          console.error('[ProxyServer] Stream error:', error)
          res.write(`data: ${JSON.stringify({ error: { message: error.message } })}\n\n`)
          res.end()

          this.stats.failedRequests++
          const isQuotaError = error.message.includes('429') || error.message.includes('quota')
          this.accountPool.recordError(account.id, isQuotaError)
          this.events.onResponse?.({ path: '/v1/chat/completions', status: 500, error: error.message })
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

    this.stats.totalRequests++
    this.events.onRequest?.({ path: '/v1/messages', method: 'POST' })

    // 获取账号（包含 Token 刷新检查）
    const account = await this.getAvailableAccount()
    if (!account) {
      this.stats.failedRequests++
      this.sendError(res, 503, 'No available accounts')
      this.events.onResponse?.({ path: '/v1/messages', status: 503, error: 'No available accounts' })
      this.recordRequest({ path: '/v1/messages', model: request.model, success: false, error: 'No available accounts' })
      return
    }

    this.events.onRequest?.({ path: '/v1/messages', method: 'POST', accountId: account.id })
    const startTime = Date.now()

    try {
      // 转换为 Kiro 格式
      const kiroPayload = claudeToKiro(request, account.profileArn)

      if (request.stream) {
        // 流式响应（流式不使用重试机制，错误由流处理）
        await this.handleClaudeStream(res, account, kiroPayload, request.model, startTime)
      } else {
        // 非流式响应（带重试机制）
        const { result, account: usedAccount } = await this.callWithRetry(
          account,
          async (acc) => callKiroApi(acc, claudeToKiro(request, acc.profileArn)),
          '/v1/messages'
        )
        const response = kiroToClaudeResponse(result.content, result.toolUses, result.usage, request.model)

        this.stats.successRequests++
        this.stats.totalTokens += result.usage.inputTokens + result.usage.outputTokens
        this.accountPool.recordSuccess(usedAccount.id, result.usage.inputTokens + result.usage.outputTokens)

        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify(response))
        this.events.onResponse?.({ path: '/v1/messages', status: 200, tokens: result.usage.inputTokens + result.usage.outputTokens })
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
    startTime: number
  ): Promise<void> {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive'
    })

    const messageId = `msg_${uuidv4()}`
    let contentBlockIndex = 0
    let hasStartedTextBlock = false

    // 发送 message_start
    const messageStart = createClaudeStreamEvent('message_start', {
      message: {
        id: messageId,
        type: 'message',
        role: 'assistant',
        content: [],
        model,
        stop_reason: null,
        stop_sequence: null,
        usage: { input_tokens: 0, output_tokens: 0 }
      }
    })
    res.write(`event: message_start\ndata: ${JSON.stringify(messageStart)}\n\n`)

    return new Promise((resolve) => {
      callKiroApiStream(
        account as any,
        kiroPayload,
        (text, toolUse) => {
          if (text) {
            if (!hasStartedTextBlock) {
              // 开始文本块
              const blockStart = createClaudeStreamEvent('content_block_start', {
                index: contentBlockIndex,
                content_block: { type: 'text', text: '' }
              })
              res.write(`event: content_block_start\ndata: ${JSON.stringify(blockStart)}\n\n`)
              hasStartedTextBlock = true
            }
            // 发送文本 delta
            const delta = createClaudeStreamEvent('content_block_delta', {
              index: contentBlockIndex,
              delta: { type: 'text_delta', text }
            })
            res.write(`event: content_block_delta\ndata: ${JSON.stringify(delta)}\n\n`)
          }
          if (toolUse) {
            // 结束之前的文本块
            if (hasStartedTextBlock) {
              const blockStop = createClaudeStreamEvent('content_block_stop', { index: contentBlockIndex })
              res.write(`event: content_block_stop\ndata: ${JSON.stringify(blockStop)}\n\n`)
              contentBlockIndex++
              hasStartedTextBlock = false
            }
            // 开始工具块
            const toolBlockStart = createClaudeStreamEvent('content_block_start', {
              index: contentBlockIndex,
              content_block: { type: 'tool_use', id: toolUse.toolUseId, name: toolUse.name, input: {} }
            })
            res.write(`event: content_block_start\ndata: ${JSON.stringify(toolBlockStart)}\n\n`)
            // 发送工具输入
            const toolDelta = createClaudeStreamEvent('content_block_delta', {
              index: contentBlockIndex,
              delta: { type: 'input_json_delta', partial_json: JSON.stringify(toolUse.input) } as any
            })
            res.write(`event: content_block_delta\ndata: ${JSON.stringify(toolDelta)}\n\n`)
            // 结束工具块
            const toolBlockStop = createClaudeStreamEvent('content_block_stop', { index: contentBlockIndex })
            res.write(`event: content_block_stop\ndata: ${JSON.stringify(toolBlockStop)}\n\n`)
            contentBlockIndex++
          }
        },
        (usage) => {
          // 结束最后的文本块
          if (hasStartedTextBlock) {
            const blockStop = createClaudeStreamEvent('content_block_stop', { index: contentBlockIndex })
            res.write(`event: content_block_stop\ndata: ${JSON.stringify(blockStop)}\n\n`)
          }
          // 发送 message_delta
          const messageDelta = createClaudeStreamEvent('message_delta', {
            delta: { stop_reason: 'end_turn', stop_sequence: null } as any,
            usage: { output_tokens: usage.outputTokens }
          })
          res.write(`event: message_delta\ndata: ${JSON.stringify(messageDelta)}\n\n`)
          // 发送 message_stop
          const messageStop = createClaudeStreamEvent('message_stop')
          res.write(`event: message_stop\ndata: ${JSON.stringify(messageStop)}\n\n`)
          res.end()

          this.stats.successRequests++
          this.stats.totalTokens += usage.inputTokens + usage.outputTokens
          this.accountPool.recordSuccess(account.id, usage.inputTokens + usage.outputTokens)
          this.events.onResponse?.({ path: '/v1/messages', status: 200, tokens: usage.inputTokens + usage.outputTokens })
          this.recordRequest({ path: '/v1/messages', model, accountId: account.id, inputTokens: usage.inputTokens, outputTokens: usage.outputTokens, responseTime: Date.now() - startTime, success: true })
          resolve()
        },
        (error) => {
          console.error('[ProxyServer] Stream error:', error)
          const errorEvent = createClaudeStreamEvent('error', {
            error: { type: 'api_error', message: error.message }
          })
          res.write(`event: error\ndata: ${JSON.stringify(errorEvent)}\n\n`)
          res.end()

          this.stats.failedRequests++
          const isQuotaError = error.message.includes('429') || error.message.includes('quota')
          this.accountPool.recordError(account.id, isQuotaError)
          this.events.onResponse?.({ path: '/v1/messages', status: 500, error: error.message })
          this.recordRequest({ path: '/v1/messages', model, accountId: account.id, responseTime: Date.now() - startTime, success: false, error: error.message })
          resolve()
        }
      )
    })
  }

  // 处理 API 错误
  private handleApiError(res: http.ServerResponse, account: { id: string }, error: Error, path: string, model?: string, startTime?: number): void {
    this.stats.failedRequests++
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
