// Kiro Proxy HTTP/HTTPS 服务器
import http from 'http'
import https from 'https'
import fs from 'fs'
import { v4 as uuidv4 } from 'uuid'
import type { Socket } from 'net'
import type {
  OpenAIChatRequest,
  OpenAIMessage,
  OpenAIResponsesRequest,
  ClaudeRequest,
  ClaudeContentBlock,
  ClaudeCacheControl,
  ProxyConfig,
  ProxyStats,
  ProxyAccount,
  TokenRefreshCallback
} from './types'
import { AccountPool, ErrorType, classifyError } from './accountPool'
import { callKiroApiStream, callKiroApi, fetchKiroModels, setModelContextWindow, type KiroModel } from './kiroApi'
import { proxyLogger } from './logger'
import { getKProxyService, generateDeviceId } from '../kproxy'
import {
  openaiToKiro,
  claudeToKiro,
  kiroToOpenaiResponse,
  kiroToClaudeResponse,
  createOpenaiStreamChunk,
  createClaudeStreamEvent,
  responsesToOpenAIChat,
  openAIChatToResponsesResponse
} from './translator'
import { ToolNameRegistry } from './toolNameRegistry'
import { promptCacheTracker } from './promptCacheTracker'


export interface ProxyServerEvents {
  onRequest?: (info: { path: string; method: string; accountId?: string }) => void
  onResponse?: (info: { path: string; model?: string; status: number; tokens?: number; inputTokens?: number; outputTokens?: number; cacheReadTokens?: number; cacheWriteTokens?: number; reasoningTokens?: number; credits?: number; responseTime?: number; error?: string }) => void
  onError?: (error: Error) => void
  onConfigChanged?: (config: ProxyConfig) => void  // API Key 用量更新时触发
  onStatusChange?: (running: boolean, port: number) => void
  onTokenRefresh?: TokenRefreshCallback
  onAccountUpdate?: (account: ProxyAccount) => void
  // 账号被 Kiro 后端长期封禁（如 TEMPORARILY_SUSPENDED / AccountSuspendedException）
  // 不同于临时 token 失效，需人工解封
  onAccountSuspended?: (info: { accountId: string; email?: string; reason: string; message: string }) => void
  onCreditsUpdate?: (totalCredits: number) => void
  onTokensUpdate?: (inputTokens: number, outputTokens: number) => void
  onRequestStatsUpdate?: (totalRequests: number, successRequests: number, failedRequests: number) => void
  onPoolEmpty?: () => Promise<void> // 账号池为空时触发（冷启动懒加载）
}

type ModelModality = 'text' | 'audio' | 'image' | 'video' | 'pdf'

type ClientModel = {
  id: string
  object: 'model'
  created: number
  owned_by: string
  name: string
  description: string
  model_name?: string
  family: string
  release_date: string
  attachment: boolean
  reasoning: boolean
  temperature: boolean
  tool_call: boolean
  interleaved: boolean | { field: 'reasoning_content' }
  cost: { input: number; output: number; cache_read: number; cache_write: number }
  limit: { context: number; input?: number; output: number }
  modalities: { input: ModelModality[]; output: ModelModality[] }
  capabilities: {
    temperature: boolean
    reasoning: boolean
    attachment: boolean
    toolcall: boolean
    input: Record<ModelModality, boolean>
    output: Record<ModelModality, boolean>
    interleaved: boolean | { field: 'reasoning_content' }
  }
  context_length: number
  max_tokens: number
  max_input_tokens?: number
  max_output_tokens: number
  inputTypes?: string[]
  rateMultiplier?: number
  rateUnit?: string
  supportsThinking?: boolean
  thinkingEfforts?: string[]
  supportsPromptCaching?: boolean
  modelProvider?: string
  permission: unknown[]
  root: string
  parent: null
}

function modelDisplayName(id: string, modelName?: string): string {
  if (modelName?.trim()) return modelName
  return id
    .split('-')
    .filter(Boolean)
    .map(part => part === 'gpt' ? 'GPT' : part === 'ai' ? 'AI' : part[0]?.toUpperCase() + part.slice(1))
    .join(' ')
}

function modelFamily(id: string): string {
  const lower = id.toLowerCase()
  if (lower.includes('opus')) return 'claude-opus'
  if (lower.includes('sonnet')) return 'claude-sonnet'
  if (lower.includes('haiku')) return 'claude-haiku'
  if (lower.includes('gpt-4o')) return 'gpt-4o'
  if (lower.includes('gpt-4')) return 'gpt-4'
  if (lower.includes('gpt-3.5')) return 'gpt-3.5'
  if (lower.includes('glm')) return 'glm'
  if (lower === 'auto') return 'auto'
  return lower.split(/[.-]/).slice(0, 2).join('-') || lower
}

function modelOutputLimit(id: string, output?: number | null): number {
  if (typeof output === 'number' && output > 0) return output
  const lower = id.toLowerCase()
  if (lower.includes('haiku') || lower.includes('gpt-3.5')) return 8192
  return 32000
}

function modelInputModalities(inputTypes?: string[]): ModelModality[] {
  const values = new Set<ModelModality>(['text'])
  for (const item of inputTypes ?? []) {
    const lower = item.toLowerCase()
    if (lower.includes('image')) values.add('image')
    if (lower.includes('pdf') || lower.includes('document') || lower.includes('file')) values.add('pdf')
    if (lower.includes('audio')) values.add('audio')
    if (lower.includes('video')) values.add('video')
  }
  return Array.from(values)
}

function modelCapabilityMap(modalities: ModelModality[]): Record<ModelModality, boolean> {
  return {
    text: modalities.includes('text'),
    audio: modalities.includes('audio'),
    image: modalities.includes('image'),
    video: modalities.includes('video'),
    pdf: modalities.includes('pdf')
  }
}

function extractThinkingEfforts(schema?: Record<string, unknown> | null): string[] | undefined {
  if (!schema) return undefined
  const props = schema.properties as Record<string, unknown> | undefined
  if (!props?.thinking) return undefined
  const thinking = props.thinking as Record<string, unknown>
  const thinkingProps = thinking.properties as Record<string, unknown> | undefined
  const typeField = thinkingProps?.type as Record<string, unknown> | undefined
  const enumValues = typeField?.enum as string[] | undefined
  if (enumValues?.includes('adaptive') || enumValues?.includes('disabled')) {
    const effortField = (props.output_config as Record<string, unknown> | undefined)?.properties as Record<string, unknown> | undefined
    const effortEnum = (effortField?.effort as Record<string, unknown> | undefined)?.enum as string[] | undefined
    return effortEnum || undefined
  }
  return undefined
}

function buildClientModel(input: {
  id: string
  created: number
  ownedBy: string
  description?: string
  modelName?: string
  supportedInputTypes?: string[]
  maxInputTokens?: number | null
  maxOutputTokens?: number | null
  rateMultiplier?: number
  rateUnit?: string
  promptCaching?: { supportsPromptCaching: boolean; maximumCacheCheckpointsPerRequest?: number | null; minimumTokensPerCacheCheckpoint?: number | null } | null
  additionalModelRequestFieldsSchema?: Record<string, unknown> | null
  modelProvider?: string | null
}): ClientModel {
  const name = modelDisplayName(input.id, input.modelName)
  const inputModalities = modelInputModalities(input.supportedInputTypes)
  const outputModalities: ModelModality[] = ['text']
  const output = modelOutputLimit(input.id, input.maxOutputTokens)
  const context = typeof input.maxInputTokens === 'number' && input.maxInputTokens > 0 ? input.maxInputTokens : 200000
  const reasoning = false
  const interleaved = false

  return {
    id: input.id,
    object: 'model',
    created: input.created,
    owned_by: input.ownedBy,
    name,
    description: input.description || name,
    model_name: input.modelName || name,
    family: modelFamily(input.id),
    release_date: '',
    attachment: inputModalities.some(item => item !== 'text'),
    reasoning,
    temperature: true,
    tool_call: true,
    interleaved,
    cost: { input: 0, output: 0, cache_read: 0, cache_write: 0 },
    limit: {
      context,
      ...(typeof input.maxInputTokens === 'number' && input.maxInputTokens > 0 ? { input: input.maxInputTokens } : {}),
      output
    },
    modalities: { input: inputModalities, output: outputModalities },
    capabilities: {
      temperature: true,
      reasoning,
      attachment: inputModalities.some(item => item !== 'text'),
      toolcall: true,
      input: modelCapabilityMap(inputModalities),
      output: modelCapabilityMap(outputModalities),
      interleaved
    },
    context_length: context,
    max_tokens: output,
    ...(typeof input.maxInputTokens === 'number' && input.maxInputTokens > 0 ? { max_input_tokens: input.maxInputTokens } : {}),
    max_output_tokens: output,
    inputTypes: input.supportedInputTypes,
    rateMultiplier: input.rateMultiplier,
    rateUnit: input.rateUnit,
    supportsThinking: !!(input.additionalModelRequestFieldsSchema?.properties as Record<string, unknown> | undefined)?.thinking,
    thinkingEfforts: extractThinkingEfforts(input.additionalModelRequestFieldsSchema),
    supportsPromptCaching: input.promptCaching?.supportsPromptCaching || false,
    modelProvider: input.modelProvider || undefined,
    permission: [],
    root: input.id,
    parent: null
  }
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
  private isStopping: boolean = false
  private activeRequests: Set<AbortController> = new Set()
  private sockets: Set<Socket> = new Set()

  /**
   * 从请求中提取 session hint，用于稳定 conversationId
   * 优先级 1：显式稳定 ID（header）
   * 优先级 2：请求体中的会话相关字段（body）
   * 优先级 3：返回 undefined（由 kiroApi 用 history fingerprint 兜底）
   */
  static extractSessionHint(req: http.IncomingMessage, body: unknown): string | undefined {
    const b = (body && typeof body === 'object' ? body : {}) as Record<string, unknown>
    const h = req.headers
    // 优先级 1：显式稳定 header
    const headerHint =
      (h['x-claude-code-session-id'] as string) ||
      (h['x-opencode-session'] as string) ||
      (h['x-session-affinity'] as string) ||
      (h['x-conversation-id'] as string)
    if (headerHint) return headerHint

    // 优先级 2：body 中可靠的会话字段
    const bodyHint =
      (b.prompt_cache_key as string) ||
      (b.promptCacheKey as string) ||
      (b.conversation_id as string) ||
      (b.conversationId as string) ||
      (b.thread_id as string) ||
      (b.threadId as string) ||
      (b.session_id as string) ||
      (b.sessionId as string)
    if (bodyHint) return bodyHint

    // 优先级 2.5：metadata 中的 session/conversation
    const metadata = b.metadata as Record<string, unknown> | undefined
    if (metadata) {
      const metaHint =
        (metadata.session_id as string) ||
        (metadata.conversation_id as string)
      if (metaHint) return metaHint
    }

    // 优先级 3：无显式 ID，返回 undefined（kiroApi 用 history fingerprint 兜底）
    return undefined
  }

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
      clientDrivenToolExecution: true,
      ...config
    }
    this.accountPool = new AccountPool()
    this.accountPool.setStrategy(this.config.accountSelectionStrategy || 'round-robin')
    this.stats = {
      totalRequests: 0,
      successRequests: 0,
      failedRequests: 0,
      totalTokens: 0,
      totalCredits: 0,
      inputTokens: 0,
      outputTokens: 0,
      cacheReadTokens: 0,
      cacheWriteTokens: 0,
      reasoningTokens: 0,
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
      this.isStopping = false
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

      this.server.on('connection', (socket: Socket) => {
        this.sockets.add(socket)
        socket.on('close', () => this.sockets.delete(socket))
      })

      // 服务器关闭时尝试自动重启
      this.server.on('close', () => {
        if (!this.isStopping && this.config.autoStart && this.config.enabled) {
          console.log('[ProxyServer] Server closed unexpectedly, attempting restart in 3s...')
          setTimeout(() => {
            if (!this.isStopping && this.config.autoStart && !this.isRunning()) {
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

    this.isStopping = true

    return new Promise((resolve) => {
      this.server!.close(() => {
        proxyLogger.info('ProxyServer', 'Stopped')
        this.server = null
        this.isStopping = false
        this.activeRequests.clear()
        this.sockets.clear()
        this.events.onStatusChange?.(false, this.config.port)
        resolve()
      })
      this.activeRequests.forEach(controller => controller.abort(new Error('Proxy server stopped')))
      this.sockets.forEach(socket => socket.destroy())
    })
  }

  // 更新配置
  updateConfig(config: Partial<ProxyConfig>): void {
    this.config = { ...this.config, ...config }
    // 同步账号选择策略到 accountPool
    if (config.accountSelectionStrategy !== undefined) {
      this.accountPool.setStrategy(this.config.accountSelectionStrategy || 'round-robin')
    }
  }

  // 获取配置
  getConfig(): ProxyConfig {
    return { ...this.config }
  }

  private validateCacheControl(cacheControl?: ClaudeCacheControl): void {
    if (!cacheControl) return
    if (cacheControl.type !== 'ephemeral') {
      throw new Error(`Unsupported cache_control type: ${cacheControl.type}`)
    }
  }


  private validateClaudeContentBlocks(blocks: ClaudeContentBlock[]): void {
    blocks.forEach(block => {
      this.validateCacheControl(block.cache_control)
      if (Array.isArray(block.content)) {
        this.validateClaudeContentBlocks(block.content)
      }
    })
  }

  private validateOpenAICacheControls(request: OpenAIChatRequest): void {
    request.messages.forEach(message => {
      this.validateCacheControl(message.cache_control)
      if (Array.isArray(message.content)) {
        message.content.forEach(part => this.validateCacheControl(part.cache_control))
      }
    })
    request.tools?.forEach(tool => this.validateCacheControl(tool.cache_control))
  }

  private validateClaudeCacheControls(request: ClaudeRequest): void {
    if (Array.isArray(request.system)) {
      request.system.forEach(block => this.validateCacheControl(block.cache_control))
    }
    request.messages.forEach(message => {
      this.validateCacheControl(message.cache_control)
      if (Array.isArray(message.content)) {
        this.validateClaudeContentBlocks(message.content)
      }
    })
    request.tools?.forEach(tool => this.validateCacheControl(tool.cache_control))
  }

  private async downloadImageDataUrl(url: string, signal?: AbortSignal): Promise<string> {
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), 15000)
    const abort = () => controller.abort(this.getAbortError(signal))
    try {
      if (signal?.aborted) throw this.getAbortError(signal)
      signal?.addEventListener('abort', abort, { once: true })
      const agent = (() => {
        const envProxy = process.env.HTTPS_PROXY || process.env.https_proxy || process.env.HTTP_PROXY || process.env.http_proxy
        if (envProxy) {
          const { ProxyAgent } = require('undici')
          return new ProxyAgent({ uri: envProxy, requestTls: { rejectUnauthorized: false } })
        }
        const { getSystemProxy } = require('./systemProxy')
        const systemProxy = getSystemProxy()
        if (systemProxy) {
          const { ProxyAgent } = require('undici')
          return new ProxyAgent({ uri: systemProxy, requestTls: { rejectUnauthorized: false } })
        }
        return undefined
      })()
      const { fetch: undiciFetch } = require('undici')
      const response = agent
        ? await undiciFetch(url, { signal: controller.signal, dispatcher: agent }) as unknown as globalThis.Response
        : await fetch(url, { signal: controller.signal })
      if (!response.ok) {
        throw new Error(`Failed to download image: HTTP ${response.status}`)
      }
      const contentType = response.headers.get('content-type')?.split(';')[0]?.toLowerCase()
      if (!contentType || !['image/jpeg', 'image/png', 'image/gif', 'image/webp'].includes(contentType)) {
        throw new Error(`Unsupported image content-type: ${contentType || 'unknown'}`)
      }
      const arrayBuffer = await response.arrayBuffer()
      if (arrayBuffer.byteLength > 10 * 1024 * 1024) {
        throw new Error('Image exceeds 10MB limit')
      }
      return `data:${contentType};base64,${Buffer.from(arrayBuffer).toString('base64')}`
    } finally {
      clearTimeout(timeout)
      signal?.removeEventListener('abort', abort)
    }
  }

  private async resolveOpenAIHttpImages(request: OpenAIChatRequest, signal?: AbortSignal): Promise<OpenAIChatRequest> {
    await Promise.all(request.messages.map(async message => {
      if (!Array.isArray(message.content)) return
      await Promise.all(message.content.map(async part => {
        if (part.type !== 'image_url' || !part.image_url?.url.startsWith('http')) return
        part.image_url.url = await this.downloadImageDataUrl(part.image_url.url, signal)
      }))
    }))
    return request
  }

  private async resolveClaudeHttpImages(request: ClaudeRequest, signal?: AbortSignal): Promise<ClaudeRequest> {
    await Promise.all(request.messages.map(async message => {
      if (!Array.isArray(message.content)) return
      await Promise.all(message.content.map(async block => {
        if (block.type !== 'image' || block.source?.type !== 'url') return
        const dataUrl = await this.downloadImageDataUrl(block.source.url, signal)
        const match = dataUrl.match(/^data:([^;]+);base64,(.+)$/)
        if (!match) {
          throw new Error('Downloaded image produced invalid data URL')
        }
        block.source = { type: 'base64', media_type: match[1], data: match[2] }
      }))
    }))
    return request
  }

  private prepareOpenAIRequest(request: OpenAIChatRequest): OpenAIChatRequest {
    this.validateOpenAICacheControls(request)

    if (this.config.disableTools || request.tool_choice === 'none') {
      return { ...request, tools: undefined, tool_choice: undefined }
    }

    if (request.tool_choice && typeof request.tool_choice === 'object' && request.tool_choice.type === 'function' && !request.tool_choice.function?.name) {
      throw new Error('tool_choice function requires a tool name')
    }

    if (request.tool_choice && typeof request.tool_choice === 'object' && request.tool_choice.function?.name) {
      const selectedToolName = request.tool_choice.function.name
      if (!request.tools?.some(tool => tool.function.name === selectedToolName)) {
        throw new Error(`tool_choice references unknown tool: ${selectedToolName}`)
      }
      return {
        ...request,
        tools: request.tools?.filter(tool => tool.function.name === selectedToolName)
      }
    }

    return request
  }

  private prepareClaudeRequest(request: ClaudeRequest): ClaudeRequest {
    this.validateClaudeCacheControls(request)

    if (this.config.disableTools || request.tool_choice?.type === 'none') {
      return { ...request, tools: undefined, tool_choice: undefined }
    }

    if (request.tool_choice?.type === 'tool' && !request.tool_choice.name) {
      throw new Error('tool_choice tool requires a tool name')
    }

    if (request.tool_choice?.name) {
      const selectedToolName = request.tool_choice.name
      if (!request.tools?.some(tool => tool.name === selectedToolName)) {
        throw new Error(`tool_choice references unknown tool: ${selectedToolName}`)
      }
      return {
        ...request,
        tools: request.tools?.filter(tool => tool.name === selectedToolName)
      }
    }

    return request
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
      cacheReadTokens: this.stats.cacheReadTokens,
      cacheWriteTokens: this.stats.cacheWriteTokens,
      reasoningTokens: this.stats.reasoningTokens,
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

  private getAbortError(signal?: AbortSignal): Error {
    if (signal?.reason instanceof Error) return signal.reason
    if (signal?.reason) return new Error(String(signal.reason))
    return new Error('Request aborted')
  }

  private isAbortError(error: unknown, signal?: AbortSignal): boolean {
    return signal?.aborted === true
      || (error instanceof Error && (error.message.includes('Client disconnected') || error.message.includes('Proxy server stopped')))
  }

  private throwIfAborted(signal?: AbortSignal): void {
    if (signal?.aborted) throw this.getAbortError(signal)
  }

  private throwIfResponseClosed(res: http.ServerResponse, signal?: AbortSignal): void {
    this.throwIfAborted(signal)
    if (res.writableEnded || res.destroyed) throw new Error('Client disconnected')
  }

  private isResponseClosed(res: http.ServerResponse): boolean {
    return res.writableEnded || res.destroyed
  }

  // 检测错误消息中是否包含账号被长期封禁的特征
  // 返回 { reason, message } 表示需要标记 suspended；返回 null 表示非封禁错误
  // 覆盖：
  //   - Kiro 后端 HTTP 403 + body: { reason: "TEMPORARILY_SUSPENDED", message: "..." }
  //   - CodeWhisperer AccountSuspendedException
  //   - 423 Locked
  private detectSuspendedError(errMsg: string): { reason: string; message: string } | null {
    if (!errMsg) return null

    // 1) 显式 reason: "TEMPORARILY_SUSPENDED" (Kiro 风控)
    const reasonMatch = errMsg.match(/"reason"\s*:\s*"(TEMPORARILY_SUSPENDED|ACCOUNT_SUSPENDED|PERMANENTLY_SUSPENDED)"/i)
    if (reasonMatch) {
      // 尝试提取 message 字段
      const msgMatch = errMsg.match(/"message"\s*:\s*"([^"]+)"/)
      return { reason: reasonMatch[1].toUpperCase(), message: msgMatch?.[1] || errMsg }
    }

    // 2) 文本特征 "temporarily suspended" / "user id is ... suspended"
    if (/User\s+ID\s+is\s+(temporarily\s+)?suspended/i.test(errMsg) || /temporarily\s+suspended/i.test(errMsg)) {
      const msgMatch = errMsg.match(/"message"\s*:\s*"([^"]+)"/)
      return { reason: 'TEMPORARILY_SUSPENDED', message: msgMatch?.[1] || errMsg }
    }

    // 3) AccountSuspendedException (CodeWhisperer)
    if (errMsg.includes('AccountSuspendedException') || errMsg.includes('Account suspended')) {
      const msgMatch = errMsg.match(/"message"\s*:\s*"([^"]+)"/)
      return { reason: 'AccountSuspendedException', message: msgMatch?.[1] || errMsg }
    }

    // 4) HTTP 423 Locked
    if (/\b423\b/.test(errMsg) && /locked|suspended/i.test(errMsg)) {
      return { reason: 'ACCOUNT_LOCKED', message: errMsg }
    }

    return null
  }

  private waitForRetry(ms: number, signal?: AbortSignal): Promise<void> {
    this.throwIfAborted(signal)
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        signal?.removeEventListener('abort', abort)
        resolve()
      }, ms)
      const abort = () => {
        clearTimeout(timeout)
        reject(this.getAbortError(signal))
      }
      signal?.addEventListener('abort', abort, { once: true })
    })
  }

  private async abortable<T>(promise: Promise<T>, signal?: AbortSignal): Promise<T> {
    this.throwIfAborted(signal)
    if (!signal) return promise
    return await Promise.race([
      promise,
      new Promise<T>((_, reject) => {
        const abort = () => reject(this.getAbortError(signal))
        signal.addEventListener('abort', abort, { once: true })
        promise.then(
          () => signal.removeEventListener('abort', abort),
          () => signal.removeEventListener('abort', abort)
        )
      })
    ])
  }

  // 清除模型缓存，强制下次请求重新获取
  clearModelCache(): void {
    this.modelCache = null
    console.log('[ProxyServer] Model cache cleared')
  }

  // 获取可用模型列表
  private static mapKiroModelToApi(m: KiroModel) {
    return {
      id: m.modelId,
      name: m.modelName,
      description: m.description,
      inputTypes: m.supportedInputTypes,
      maxInputTokens: m.tokenLimits?.maxInputTokens,
      maxOutputTokens: m.tokenLimits?.maxOutputTokens,
      rateMultiplier: m.rateMultiplier,
      rateUnit: m.rateUnit,
      supportsThinking: !!(m.additionalModelRequestFieldsSchema?.properties as Record<string, unknown> | undefined)?.thinking,
      thinkingEfforts: extractThinkingEfforts(m.additionalModelRequestFieldsSchema),
      supportsPromptCaching: m.promptCaching?.supportsPromptCaching || false,
      modelProvider: m.modelProvider || undefined
    }
  }

  async getAvailableModels(signal?: AbortSignal): Promise<{ models: ReturnType<typeof ProxyServer.mapKiroModelToApi>[]; fromCache: boolean }> {
    const now = Date.now()
    
    let kiroModels: KiroModel[]
    let fromCache = false

    if (this.modelCache && (now - this.modelCache.timestamp) < this.MODEL_CACHE_TTL) {
      kiroModels = this.modelCache.models
      fromCache = true
    } else {
      this.throwIfAborted(signal)
      const account = await this.getAvailableAccount(signal)
      this.throwIfAborted(signal)
      if (!account) {
        return { models: [], fromCache: false }
      }

      try {
        kiroModels = await fetchKiroModels(account, signal)
        if (kiroModels.length > 0) {
          this.modelCache = { models: kiroModels, timestamp: now }
          // 同步到 kiroApi 的 ctx cache, 供 token 裁剪逻辑使用
          for (const m of kiroModels) {
            if (m.tokenLimits?.maxInputTokens) {
              setModelContextWindow(m.modelId, m.tokenLimits.maxInputTokens)
            }
          }
        }
      } catch (error) {
        if (this.isAbortError(error, signal)) throw error
        console.error('[ProxyServer] Failed to fetch models:', error)
        return { models: [], fromCache: false }
      }
    }

    // 合并隐藏模型（与 /v1/models 端点一致）
    const modelIds = new Set(kiroModels.map(m => m.modelId))
    const hiddenModels: KiroModel[] = [
      { modelId: 'claude-3.7-sonnet', modelName: 'Claude 3.7 Sonnet', description: 'Claude 3.7 Sonnet (hidden)', supportedInputTypes: ['TEXT', 'IMAGE'], tokenLimits: { maxInputTokens: 200000, maxOutputTokens: 64000 } } as KiroModel,
      { modelId: 'simple-task', modelName: 'Simple Task', description: 'Kiro fast model (routes to Haiku)', supportedInputTypes: ['TEXT'], tokenLimits: { maxInputTokens: 200000, maxOutputTokens: 4096 } } as KiroModel,
      { modelId: 'CLAUDE_SONNET_4_20250514_V1_0', modelName: 'Claude Sonnet 4 (CW)', description: 'CodeWhisperer internal ID', supportedInputTypes: ['TEXT', 'IMAGE'], tokenLimits: { maxInputTokens: 200000, maxOutputTokens: 64000 } } as KiroModel,
      { modelId: 'CLAUDE_HAIKU_4_5_20251001_V1_0', modelName: 'Claude Haiku 4.5 (CW)', description: 'CodeWhisperer internal ID', supportedInputTypes: ['TEXT', 'IMAGE'], tokenLimits: { maxInputTokens: 200000, maxOutputTokens: 64000 } } as KiroModel,
      { modelId: 'CLAUDE_3_7_SONNET_20250219_V1_0', modelName: 'Claude 3.7 Sonnet (CW)', description: 'CodeWhisperer internal ID', supportedInputTypes: ['TEXT', 'IMAGE'], tokenLimits: { maxInputTokens: 200000, maxOutputTokens: 64000 } } as KiroModel
    ]
    const merged = [...kiroModels, ...hiddenModels.filter(m => !modelIds.has(m.modelId))]

    return { models: merged.map(ProxyServer.mapKiroModelToApi), fromCache }
  }

  // 检查 Token 是否需要刷新
  private isTokenExpiringSoon(account: ProxyAccount): boolean {
    if (!account.expiresAt) return false
    const refreshBeforeMs = (this.config.tokenRefreshBeforeExpiry || 300) * 1000
    return Date.now() + refreshBeforeMs >= account.expiresAt
  }

  // 刷新 Token
  private async refreshToken(account: ProxyAccount, signal?: AbortSignal): Promise<boolean> {
    this.throwIfAborted(signal)
    if (!this.events.onTokenRefresh) {
      console.warn('[ProxyServer] No token refresh callback configured')
      return false
    }

    // 防止并发刷新
    if (this.refreshingTokens.has(account.id)) {
      console.log(`[ProxyServer] Token refresh already in progress for ${account.email || account.id}`)
      // 等待刷新完成
      await this.waitForRetry(1000, signal)
      return !this.isTokenExpiringSoon(this.accountPool.getAccount(account.id) || account)
    }

    this.refreshingTokens.add(account.id)
    console.log(`[ProxyServer] Refreshing token for ${account.email || account.id}`)

    try {
      // 随机延迟 0-3 秒，避免多账号同时刷新被识别为批量操作
      const jitter = Math.floor(Math.random() * 3000)
      if (jitter > 0) await this.waitForRetry(jitter, signal)
      
      const result = await this.abortable(this.events.onTokenRefresh(account), signal)
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
      if (this.isAbortError(error, signal)) throw error
      console.error(`[ProxyServer] Token refresh error for ${account.email || account.id}:`, error)
      this.accountPool.markNeedsRefresh(account.id)
      return false
    } finally {
      this.refreshingTokens.delete(account.id)
    }
  }

  // 获取可用账号（包含 Token 刷新检查）
  private async getAvailableAccount(signal?: AbortSignal): Promise<ProxyAccount | null> {
    this.throwIfAborted(signal)
    // 如果 pool 为空，触发懒加载回调尝试同步账号（冷启动场景）
    if (this.accountPool.size === 0 && this.events.onPoolEmpty) {
      console.log('[ProxyServer] Account pool empty, triggering lazy sync...')
      await this.abortable(this.events.onPoolEmpty(), signal)
    }
    this.throwIfAborted(signal)

    let account: ProxyAccount | null
    
    // 检查是否启用多账号轮询
    if (this.config.enableMultiAccount) {
      account = this.accountPool.getNextAccount()
      if (!account) {
        const status = this.accountPool.getQuotaStatus()
        if (status.exhausted > 0 && status.available === 0) {
          console.log(`[ProxyServer] All accounts quota exhausted (${status.exhausted}/${status.total}), no available accounts`)
        }
      }
    } else {
      // 禁用多账号轮询时，优先使用指定的账号
      if (this.config.selectedAccountIds && this.config.selectedAccountIds.length > 0) {
        // 使用指定的第一个账号
        account = this.accountPool.getAccount(this.config.selectedAccountIds[0])
        // 检查指定账号是否配额耗尽，若是则尝试自动切换
        if (account && this.accountPool.isQuotaExhausted(account) && this.config.autoSwitchOnQuotaExhausted) {
          const nextAccount = this.accountPool.getNextAvailableAccount(account.id)
          if (nextAccount) {
            console.log(`[ProxyServer] Selected account ${account.email || account.id} quota exhausted, auto-switching to ${nextAccount.email || nextAccount.id}`)
            this.config.selectedAccountIds = [nextAccount.id]
            this.events.onAccountUpdate?.(nextAccount)
            account = nextAccount
          }
        }
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
      const refreshed = await this.refreshToken(account, signal)
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
    _path: string,
    signal?: AbortSignal
  ): Promise<{ result: T; account: ProxyAccount }> {
    const maxRetries = this.config.maxRetries || 3
    const retryDelay = this.config.retryDelayMs || 1000
    let lastError: Error | null = null
    let currentAccount = account
    let endpointIndex = 0

    for (let attempt = 0; attempt < maxRetries; attempt++) {
      this.throwIfAborted(signal)
      try {
        const result = await apiCall(currentAccount, endpointIndex)
        return { result, account: currentAccount }
      } catch (error) {
        if (this.isAbortError(error, signal)) throw error
        lastError = error as Error
        const errMsg = lastError.message || ''

        console.log(`[ProxyServer] API call failed (attempt ${attempt + 1}/${maxRetries}): ${errMsg}`)

        // 优先检测账号被长期封禁（不是 token 问题，刷新也没用）
        // 特征：HTTP 403 + reason: "TEMPORARILY_SUSPENDED" 或 AccountSuspendedException / 423
        const suspendInfo = this.detectSuspendedError(errMsg)
        if (suspendInfo) {
          const newlyMarked = this.accountPool.markSuspended(currentAccount.id, suspendInfo.reason, suspendInfo.message)
          if (newlyMarked) {
            this.events.onAccountSuspended?.({
              accountId: currentAccount.id,
              email: currentAccount.email,
              reason: suspendInfo.reason,
              message: suspendInfo.message
            })
          }
          console.warn(`[ProxyServer] Account ${currentAccount.email || currentAccount.id} suspended (${suspendInfo.reason}), switching to next available account`)
          // 切到下个可用账号（跳过被 suspended 的）
          if (this.config.enableMultiAccount || this.config.autoSwitchOnQuotaExhausted) {
            const nextAccount = this.config.enableMultiAccount
              ? this.accountPool.getNextAccount()
              : this.accountPool.getNextAvailableAccount(currentAccount.id)
            if (nextAccount && nextAccount.id !== currentAccount.id) {
              currentAccount = nextAccount
              if (!this.config.enableMultiAccount) {
                this.config.selectedAccountIds = [nextAccount.id]
                this.events.onAccountUpdate?.(nextAccount)
              }
              continue
            }
          }
          // 无可切换的账号 → 直接抛出错误给客户端
          break
        }

        // 401/403: 尝试刷新 Token
        if (errMsg.includes('401') || errMsg.includes('403') || errMsg.includes('Auth')) {
          console.log('[ProxyServer] Auth error, attempting token refresh')
          const refreshed = await this.refreshToken(currentAccount, signal)
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
        if (errMsg.includes('402') || errMsg.includes('429') || errMsg.includes('quota') || errMsg.includes('ThrottlingException') || errMsg.includes('reached the limit') || errMsg.includes('ServiceQuotaExceededException') || errMsg.includes('limit exceeded') || errMsg.includes('rate limit')) {
          console.log('[ProxyServer] Quota/throttle error, switching endpoint or account')
          this.accountPool.recordError(currentAccount.id, ErrorType.RECOVERABLE, 429)
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
          await this.waitForRetry(retryDelay * (attempt + 1), signal)
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
    const controller = new AbortController()
    const abortRequest = () => {
      if (!this.isStopping && res.writableEnded) return
      if (!controller.signal.aborted) {
        controller.abort(new Error(this.isStopping ? 'Proxy server stopped' : 'Client disconnected'))
      }
    }
    this.activeRequests.add(controller)
    req.on('aborted', abortRequest)
    res.on('close', abortRequest)

    // CORS 预检
    if (method === 'OPTIONS') {
      this.setCorsHeaders(res)
      res.writeHead(204)
      res.end()
      req.off('aborted', abortRequest)
      res.off('close', abortRequest)
      this.activeRequests.delete(controller)
      return
    }

    try {
      this.setCorsHeaders(res)

      // API Key 验证（健康检查端点除外）
      if (path !== '/health' && path !== '/') {
        const authResult = this.validateApiKey(req)
        if (!authResult.valid) {
          const errorMsg = authResult.reason || 'Invalid or missing API key'
          const statusCode = authResult.reason === 'Credits limit exceeded' ? 429 : 401
          this.sendError(res, statusCode, errorMsg, this.isAnthropicPath(path) ? 'anthropic' : 'openai')
          return
        }
        // 将匹配的 API Key 存储到请求对象中，用于后续统计
        ;(req as unknown as { matchedApiKey?: import('./types').ApiKey }).matchedApiKey = authResult.apiKey
      }

      // 记录请求
      if (this.config.logRequests) {
        proxyLogger.info('ProxyServer', `${method} ${path}`)
      }

      // 路由（移除查询参数）
      const pathWithoutQuery = path.split('?')[0]
      
      if (pathWithoutQuery === '/v1/models' || pathWithoutQuery === '/models') {
        await this.handleModels(res, controller.signal)
      } else if (pathWithoutQuery === '/v1/chat/completions' || pathWithoutQuery === '/chat/completions') {
        await this.handleOpenAIChat(req, res, controller.signal)
      } else if (pathWithoutQuery === '/v1/responses' || pathWithoutQuery === '/responses') {
        await this.handleOpenAIResponses(req, res, controller.signal)
      } else if (pathWithoutQuery === '/v1/messages' || pathWithoutQuery === '/messages' || pathWithoutQuery === '/anthropic/v1/messages') {
        await this.handleClaudeMessages(req, res, controller.signal)
      } else if (pathWithoutQuery === '/v1/messages/count_tokens' || pathWithoutQuery === '/messages/count_tokens') {
        // Claude Code token 计数端点 - 返回模拟响应
        await this.handleCountTokens(req, res, controller.signal)
      } else if (pathWithoutQuery === '/api/event_logging/batch') {
        // Claude Code 遥测端点 - 直接返回 200 OK
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ status: 'ok' }))
      } else if (pathWithoutQuery.startsWith('/v1beta/models/')) {
        // Gemini v1beta 兼容路由
        await this.handleGeminiRequest(req, res, pathWithoutQuery, controller.signal)
      } else if (pathWithoutQuery === '/v1beta/models') {
        // Gemini 模型列表
        await this.handleGeminiModels(res, controller.signal)
      } else if (pathWithoutQuery === '/health' || pathWithoutQuery === '/') {
        this.handleHealth(res)
      } else if (pathWithoutQuery.startsWith('/admin/')) {
        // 管理 API 端点
        await this.handleAdminApi(req, res, pathWithoutQuery, controller.signal)
      } else {
        // 记录未知路径以便调试
        console.log(`[ProxyServer] Unknown path: ${path} (method: ${method})`)
        this.sendError(res, 404, `Not Found: ${pathWithoutQuery}`)
      }
    } catch (error) {
      if (this.isAbortError(error, controller.signal)) {
        proxyLogger.info('ProxyServer', `Request aborted: ${method} ${path}`)
        return
      }
      console.error('[ProxyServer] Request error:', error)
      this.sendError(res, 500, (error as Error).message, this.isAnthropicPath(path) ? 'anthropic' : 'openai')
      this.events.onError?.(error as Error)
    } finally {
      req.off('aborted', abortRequest)
      res.off('close', abortRequest)
      this.activeRequests.delete(controller)
    }
  }

  // 管理 API 端点
  private async handleAdminApi(req: http.IncomingMessage, res: http.ServerResponse, path: string, signal?: AbortSignal): Promise<void> {
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
      const body = await this.readBody(req, signal)
      const newConfig = JSON.parse(body)
      this.updateConfig(newConfig)
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ success: true, config: this.getConfig() }))
    } else if (path === '/admin/logs' && method === 'GET') {
      // 获取最近日志
      this.handleAdminLogs(res)
    } else if (path === '/admin/cache/clear' && method === 'POST') {
      // 清除内存缓存（conversationId 映射、模型缓存、prompt cache）
      const { clearAllCaches } = require('./kiroApi')
      const cleared = clearAllCaches()
      const promptCacheCleared = promptCacheTracker.clear()
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ success: true, cleared: { ...cleared, promptCache: promptCacheCleared } }))
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

  private isAnthropicPath(path: string): boolean {
    const pathWithoutQuery = path.split('?')[0]
    return pathWithoutQuery === '/v1/messages'
      || pathWithoutQuery === '/messages'
      || pathWithoutQuery === '/anthropic/v1/messages'
      || pathWithoutQuery === '/v1/messages/count_tokens'
      || pathWithoutQuery === '/messages/count_tokens'
  }

  private getAnthropicErrorType(status: number): string {
    if (status === 400) return 'invalid_request_error'
    if (status === 401) return 'authentication_error'
    if (status === 403) return 'permission_error'
    if (status === 404) return 'not_found_error'
    if (status === 429) return 'rate_limit_error'
    return 'api_error'
  }

  private buildClaudeUsage(
    usage: { inputTokens: number; outputTokens: number; cacheWriteTokens?: number; cacheReadTokens?: number },
    simulatedCache?: { cacheCreationInputTokens: number; cacheReadInputTokens: number }
  ): { input_tokens?: number; output_tokens: number; cache_creation_input_tokens?: number; cache_read_input_tokens?: number } {
    // 优先使用 Kiro 后端返回的真实 cache tokens，否则用模拟器的值
    const cacheWrite = usage.cacheWriteTokens || simulatedCache?.cacheCreationInputTokens || 0
    const cacheRead = usage.cacheReadTokens || simulatedCache?.cacheReadInputTokens || 0
    // Kiro 的 inputTokens 是全量（含缓存），Anthropic API 规范中 input_tokens 不含缓存部分
    // 需要扣除 cache tokens 避免客户端双重计费
    const adjustedInput = Math.max(0, usage.inputTokens - cacheWrite - cacheRead)
    return {
      input_tokens: adjustedInput,
      output_tokens: usage.outputTokens,
      ...(cacheWrite ? { cache_creation_input_tokens: cacheWrite } : {}),
      ...(cacheRead ? { cache_read_input_tokens: cacheRead } : {})
    }
  }

  private estimateTokenCount(value: unknown): number {
    if (value === null || value === undefined) return 0
    if (typeof value === 'string') return Math.ceil(value.length / 4)
    if (typeof value === 'number' || typeof value === 'boolean') return 1
    if (Array.isArray(value)) {
      return value.reduce<number>((total, item) => total + this.estimateTokenCount(item), 0)
    }
    if (typeof value !== 'object') return 0
    const record = value as Record<string, unknown>
    if (record.type === 'text' || record.type === 'input_text' || record.type === 'output_text') return this.estimateTokenCount(record.text) + 4
    if (record.type === 'thinking') return this.estimateTokenCount(record.thinking) + this.estimateTokenCount(record.signature) + 4
    if (record.type === 'redacted_thinking') return 8
    if (record.type === 'image' || record.type === 'input_image') return 170
    if (record.type === 'document' || record.type === 'input_file') return this.estimateTokenCount(record.title) + this.estimateTokenCount(record.name) + this.estimateTokenCount(record.filename) + this.estimateTokenCount(record.source) + this.estimateTokenCount(record.file_data) + 120
    if (record.type === 'tool_use') return this.estimateTokenCount(record.name) + this.estimateTokenCount(record.input) + 12
    if (record.type === 'tool_result') return this.estimateTokenCount(record.content) + 8
    if (typeof record.role === 'string' && 'content' in record) return this.estimateTokenCount(record.content) + 4
    if (typeof record.name === 'string' && 'input_schema' in record) return this.estimateTokenCount(record.name) + this.estimateTokenCount(record.description) + this.estimateTokenCount(record.input_schema) + 32
    return Object.entries(record).reduce<number>((total, [key, item]) => key === 'cache_control' ? total : total + this.estimateTokenCount(item), 0)
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
  private async handleCountTokens(req: http.IncomingMessage, res: http.ServerResponse, signal?: AbortSignal): Promise<void> {
    try {
      this.throwIfAborted(signal)
      const body = await this.readBody(req, signal)
      this.throwIfAborted(signal)
      const request = JSON.parse(body) as Partial<ClaudeRequest>
      if (!Array.isArray(request.messages)) {
        throw new Error('count_tokens requires messages')
      }
      const estimatedTokens = Math.max(1, this.estimateTokenCount(request.system) + this.estimateTokenCount(request.messages) + this.estimateTokenCount(request.tools))
      
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ input_tokens: estimatedTokens }))
    } catch (error) {
      if (this.isAbortError(error, signal)) return
      this.sendError(res, 400, error instanceof Error ? error.message : 'Invalid request body', 'anthropic')
    }
  }

  // Gemini v1beta 模型列表
  private async handleGeminiModels(res: http.ServerResponse, signal?: AbortSignal): Promise<void> {
    const result = await this.getAvailableModels(signal)
    const geminiModels = result.models.map(m => ({
      name: `models/${m.id}`,
      version: '001',
      displayName: m.name || m.id,
      description: m.description || '',
      inputTokenLimit: m.maxInputTokens || 200000,
      outputTokenLimit: m.maxOutputTokens || 64000,
      supportedGenerationMethods: ['generateContent', 'streamGenerateContent']
    }))
    this.throwIfResponseClosed(res, signal)
    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ models: geminiModels }))
  }

  // Gemini v1beta generateContent / streamGenerateContent
  private async handleGeminiRequest(req: http.IncomingMessage, res: http.ServerResponse, path: string, signal?: AbortSignal): Promise<void> {
    const body = await this.readBody(req, signal)
    this.throwIfAborted(signal)
    const geminiReq = JSON.parse(body)
    const matchedApiKey = (req as unknown as { matchedApiKey?: import('./types').ApiKey }).matchedApiKey

    // 解析路径: /v1beta/models/{model}:{method}
    const match = path.match(/\/v1beta\/models\/([^:]+):(\w+)/)
    if (!match) {
      this.sendError(res, 400, 'Invalid Gemini endpoint path')
      return
    }
    const [, modelId, method] = match
    const isStream = method === 'streamGenerateContent'

    // 将 Gemini 请求转为 OpenAI 格式
    const messages: OpenAIMessage[] = []
    if (geminiReq.systemInstruction?.parts) {
      const sysText = geminiReq.systemInstruction.parts.map((p: { text?: string }) => p.text || '').join('\n')
      if (sysText) messages.push({ role: 'system', content: sysText })
    }
    for (const content of geminiReq.contents || []) {
      const role = content.role === 'model' ? 'assistant' : 'user'
      const text = (content.parts || []).map((p: { text?: string }) => p.text || '').join('')
      if (text) messages.push({ role: role as 'user' | 'assistant', content: text })
    }
    if (messages.length === 0) {
      messages.push({ role: 'user', content: 'Hello' })
    }

    const openaiRequest: OpenAIChatRequest = {
      model: this.applyModelMapping(modelId, matchedApiKey?.id),
      messages,
      stream: isStream,
      temperature: geminiReq.generationConfig?.temperature,
      top_p: geminiReq.generationConfig?.topP,
      max_tokens: geminiReq.generationConfig?.maxOutputTokens
    }

    // 复用 OpenAI 流程
    const startTime = Date.now()
    this.recordNewRequest()
    this.throwIfAborted(signal)
    const account = await this.getAvailableAccount(signal)
    this.throwIfAborted(signal)
    if (!account) {
      this.sendError(res, 503, 'No available accounts')
      return
    }

    try {
      const toolNameRegistry = new ToolNameRegistry()
      const kiroPayload = openaiToKiro(openaiRequest, account.profileArn, toolNameRegistry)

      if (isStream) {
        // SSE 流式
        res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'Connection': 'keep-alive' })
        return new Promise<void>((resolve) => {
          callKiroApiStream(
            account as ProxyAccount,
            kiroPayload,
            (text) => {
              if (signal?.aborted || this.isResponseClosed(res)) return
              if (text) {
                const chunk = { candidates: [{ content: { parts: [{ text }], role: 'model' }, finishReason: null }] }
                res.write(`data: ${JSON.stringify(chunk)}\n\n`)
              }
            },
            (usage) => {
              if (signal?.aborted || this.isResponseClosed(res)) {
                resolve()
                return
              }
              const finalChunk = { candidates: [{ content: { parts: [{ text: '' }], role: 'model' }, finishReason: 'STOP' }], usageMetadata: { promptTokenCount: usage.inputTokens, candidatesTokenCount: usage.outputTokens, totalTokenCount: usage.inputTokens + usage.outputTokens } }
              res.write(`data: ${JSON.stringify(finalChunk)}\n\n`)
              res.end()
              this.recordRequestSuccess()
              this.stats.totalTokens += usage.inputTokens + usage.outputTokens
              this.stats.inputTokens += usage.inputTokens
              this.stats.outputTokens += usage.outputTokens
              this.stats.totalCredits += usage.credits || 0
              this.accountPool.recordSuccess(account.id, usage.inputTokens + usage.outputTokens)
              resolve()
            },
            (error) => {
              if (this.isAbortError(error, signal) || this.isResponseClosed(res)) {
                resolve()
                return
              }
              res.write(`data: ${JSON.stringify({ error: { message: error.message } })}\n\n`)
              res.end()
              this.recordRequestFailed()
              resolve()
            },
            signal,
            this.config.preferredEndpoint
          ).catch(error => {
            if (!this.isAbortError(error, signal) && !this.isResponseClosed(res)) {
              res.write(`data: ${JSON.stringify({ error: { message: error.message } })}\n\n`)
              res.end()
              this.recordRequestFailed()
            }
            resolve()
          })
        })
      } else {
        // 非流式
        const result = await callKiroApi(account as ProxyAccount, kiroPayload, signal)
        this.throwIfResponseClosed(res, signal)
        this.recordRequestSuccess()
        this.stats.totalTokens += result.usage.inputTokens + result.usage.outputTokens
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({
          candidates: [{ content: { parts: [{ text: result.content }], role: 'model' }, finishReason: 'STOP' }],
          usageMetadata: { promptTokenCount: result.usage.inputTokens, candidatesTokenCount: result.usage.outputTokens, totalTokenCount: result.usage.inputTokens + result.usage.outputTokens }
        }))
      }
    } catch (error) {
      this.handleApiError(res, account, error as Error, '/v1beta', modelId, startTime, signal)
    }
  }

  // 模型列表缓存
  private modelCache: { models: KiroModel[]; timestamp: number } | null = null
  private readonly MODEL_CACHE_TTL = 5 * 60 * 1000 // 5 分钟缓存

  // 模型列表
  private async handleModels(res: http.ServerResponse, signal?: AbortSignal): Promise<void> {
    const now = Date.now()
    
    // Kiro 官方模型（与 UI 保持一致）
    const kiroOfficialModels = [
      buildClientModel({ id: 'auto', created: now, ownedBy: 'kiro-api', description: 'Auto select best model' }),
      buildClientModel({ id: 'claude-sonnet-4.5', created: now, ownedBy: 'kiro-api', description: 'The latest Claude Sonnet model' }),
      buildClientModel({ id: 'claude-sonnet-4', created: now, ownedBy: 'kiro-api', description: 'Hybrid reasoning and coding' }),
      buildClientModel({ id: 'claude-haiku-4.5', created: now, ownedBy: 'kiro-api', description: 'The latest Claude Haiku model' }),
      buildClientModel({ id: 'claude-opus-4.5', created: now, ownedBy: 'kiro-api', description: 'The most powerful model' })
    ]

    // 隐藏模型（未在官方 ListAvailableModels 中返回，但后端可能支持）
    const hiddenModels = [
      buildClientModel({ id: 'claude-3.7-sonnet', created: now, ownedBy: 'kiro-api', description: 'Claude 3.7 Sonnet (hidden)', modelName: 'Claude 3.7 Sonnet', supportedInputTypes: ['TEXT', 'IMAGE'], maxInputTokens: 200000, maxOutputTokens: 64000 }),
      buildClientModel({ id: 'simple-task', created: now, ownedBy: 'kiro-api', description: 'Kiro fast model for intent classification and lightweight tasks (routes to Haiku)', modelName: 'Simple Task', supportedInputTypes: ['TEXT'], maxInputTokens: 200000, maxOutputTokens: 4096 }),
      buildClientModel({ id: 'CLAUDE_SONNET_4_20250514_V1_0', created: now, ownedBy: 'kiro-api', description: 'Claude Sonnet 4 (CodeWhisperer internal ID)', modelName: 'Claude Sonnet 4 (CW)', supportedInputTypes: ['TEXT', 'IMAGE'], maxInputTokens: 200000, maxOutputTokens: 64000 }),
      buildClientModel({ id: 'CLAUDE_HAIKU_4_5_20251001_V1_0', created: now, ownedBy: 'kiro-api', description: 'Claude Haiku 4.5 (CodeWhisperer internal ID)', modelName: 'Claude Haiku 4.5 (CW)', supportedInputTypes: ['TEXT', 'IMAGE'], maxInputTokens: 200000, maxOutputTokens: 64000 }),
      buildClientModel({ id: 'CLAUDE_3_7_SONNET_20250219_V1_0', created: now, ownedBy: 'kiro-api', description: 'Claude 3.7 Sonnet (CodeWhisperer internal ID)', modelName: 'Claude 3.7 Sonnet (CW)', supportedInputTypes: ['TEXT', 'IMAGE'], maxInputTokens: 200000, maxOutputTokens: 64000 })
    ]

    // 预设模型（GPT 兼容别名）
    const presetModels = [
      buildClientModel({ id: 'gpt-4o', created: now, ownedBy: 'kiro-proxy', description: 'GPT-compatible alias for Kiro' }),
      buildClientModel({ id: 'gpt-4', created: now, ownedBy: 'kiro-proxy', description: 'GPT-compatible alias for Kiro' }),
      buildClientModel({ id: 'gpt-4-turbo', created: now, ownedBy: 'kiro-proxy', description: 'GPT-compatible alias for Kiro' }),
      buildClientModel({ id: 'gpt-3.5-turbo', created: now, ownedBy: 'kiro-proxy', description: 'GPT-compatible alias for Kiro' })
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
          kiroModels = await fetchKiroModels(account, signal)
          if (kiroModels.length > 0) {
            this.modelCache = { models: kiroModels, timestamp: now }
            // 同步到 kiroApi 的 ctx cache, 供 token 裁剪逻辑使用
            for (const m of kiroModels) {
              if (m.tokenLimits?.maxInputTokens) {
                setModelContextWindow(m.modelId, m.tokenLimits.maxInputTokens)
              }
            }
            proxyLogger.info('ProxyServer', `Fetched ${kiroModels.length} models from Kiro API`)
          }
        } catch (error) {
          if (this.isAbortError(error, signal)) throw error
          console.error('[ProxyServer] Failed to fetch Kiro models:', error)
        }
      }
    }

    // 转换 Kiro 模型为 OpenAI 格式（保持原始 modelId）
    const dynamicModels = kiroModels.map(m => buildClientModel({
      id: m.modelId,
      created: now,
      ownedBy: 'kiro-api',
      description: m.description,
      modelName: m.modelName,
      supportedInputTypes: m.supportedInputTypes,
      maxInputTokens: m.tokenLimits?.maxInputTokens,
      maxOutputTokens: m.tokenLimits?.maxOutputTokens,
      rateMultiplier: m.rateMultiplier,
      rateUnit: m.rateUnit,
      promptCaching: m.promptCaching,
      additionalModelRequestFieldsSchema: m.additionalModelRequestFieldsSchema,
      modelProvider: m.modelProvider
    }))

    // 合并模型列表，去重
    const modelIds = new Set<string>()
    const allModels: ClientModel[] = []
    
    // 1. 优先添加动态模型（从 API 获取的，包含真实 token limit / input types）
    for (const m of dynamicModels) {
      if (!modelIds.has(m.id)) {
        modelIds.add(m.id)
        allModels.push(m)
      }
    }
    
    // 2. 添加隐藏模型（未在官方 ListAvailableModels 中返回，但后端可能支持）
    for (const m of hiddenModels) {
      if (!modelIds.has(m.id)) {
        modelIds.add(m.id)
        allModels.push(m)
      }
    }
    
    // 3. 动态模型缺失时才添加静态兜底
    if (dynamicModels.length === 0) {
      for (const m of [...kiroOfficialModels, ...presetModels]) {
        if (!modelIds.has(m.id)) {
          modelIds.add(m.id)
          allModels.push(m)
        }
      }
    }

    this.throwIfResponseClosed(res, signal)
    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ object: 'list', data: allModels }))
  }

  // 处理 OpenAI Chat Completions 请求
  private async handleOpenAIChat(req: http.IncomingMessage, res: http.ServerResponse, signal?: AbortSignal): Promise<void> {
    const body = await this.readBody(req, signal)
    this.throwIfAborted(signal)
    const request: OpenAIChatRequest = JSON.parse(body)
    const matchedApiKey = (req as unknown as { matchedApiKey?: import('./types').ApiKey }).matchedApiKey

    // 提取 session hint（用于稳定 conversationId），拼入 API Key hash 隔离不同用户
    if (!request.conversation_id) {
      const hint = ProxyServer.extractSessionHint(req, request)
      if (hint) {
        const keyPrefix = matchedApiKey?.id?.slice(0, 8) || 'default'
        request.conversation_id = `${keyPrefix}:${hint}`
      }
    }

    // 应用模型映射
    request.model = this.applyModelMapping(request.model, matchedApiKey?.id)

    const startTime = Date.now()

    this.recordNewRequest()
    this.events.onRequest?.({ path: '/v1/chat/completions', method: 'POST' })

    let processedRequest: OpenAIChatRequest
    try {
      processedRequest = await this.resolveOpenAIHttpImages(this.prepareOpenAIRequest(request), signal)
    } catch (error) {
      if (this.isAbortError(error, signal)) return
      this.recordRequestFailed()
      const message = error instanceof Error ? error.message : 'Invalid request'
      this.sendError(res, 400, message)
      this.events.onResponse?.({ path: '/v1/chat/completions', model: request.model, status: 400, error: message })
      this.recordRequest({ path: '/v1/chat/completions', model: request.model, responseTime: Date.now() - startTime, success: false, error: message })
      return
    }

    // 获取账号（包含 Token 刷新检查）
    this.throwIfAborted(signal)
    const account = await this.getAvailableAccount(signal)
    this.throwIfAborted(signal)
    if (!account) {
      this.recordRequestFailed()
      const quotaStatus = this.accountPool.getQuotaStatus()
      const errorMsg = quotaStatus.exhausted > 0 && quotaStatus.available === 0
        ? `All accounts quota exhausted (${quotaStatus.exhausted}/${quotaStatus.total} exhausted, ${quotaStatus.cooldown} in cooldown)`
        : 'No available accounts'
      this.sendError(res, 503, errorMsg)
      this.events.onResponse?.({ path: '/v1/chat/completions', model: request.model, status: 503, error: errorMsg })
      this.recordRequest({ path: '/v1/chat/completions', model: request.model, success: false, error: errorMsg })
      return
    }

    this.events.onRequest?.({ path: '/v1/chat/completions', method: 'POST', accountId: account.id })

    try {
      const toolNameRegistry = new ToolNameRegistry()

      // 转换为 Kiro 格式
      const kiroPayload = openaiToKiro(processedRequest, account.profileArn, toolNameRegistry)

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
        await this.handleOpenAIStream(res, account, kiroPayload, request.model, startTime, 0, undefined, false, matchedApiKey, toolNameRegistry, signal)
      } else {
        // 非流式响应（带重试机制）
        const { result, account: usedAccount } = await this.callWithRetry(
          account,
          async (acc) => {
            const retryPayload = openaiToKiro(processedRequest, acc.profileArn, toolNameRegistry)
            return callKiroApi(acc, retryPayload, signal)
          },
          '/v1/chat/completions',
          signal
        )
        const response = kiroToOpenaiResponse(result.content, result.toolUses, result.usage, request.model, toolNameRegistry, result.reasoningContent)

        this.throwIfResponseClosed(res, signal)
        this.recordRequestSuccess()
        this.stats.totalTokens += result.usage.inputTokens + result.usage.outputTokens
        this.stats.inputTokens += result.usage.inputTokens
        this.stats.outputTokens += result.usage.outputTokens
        this.accountPool.recordSuccess(usedAccount.id, result.usage.inputTokens + result.usage.outputTokens)

        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify(response))
        const respTime = Date.now() - startTime
        this.events.onResponse?.({ path: '/v1/chat/completions', model: request.model, status: 200, tokens: result.usage.inputTokens + result.usage.outputTokens, inputTokens: result.usage.inputTokens, outputTokens: result.usage.outputTokens, cacheReadTokens: result.usage.cacheReadTokens, reasoningTokens: result.usage.reasoningTokens, credits: result.usage.credits, responseTime: respTime })
        this.recordRequest({ path: '/v1/chat/completions', model: request.model, accountId: usedAccount.id, inputTokens: result.usage.inputTokens, outputTokens: result.usage.outputTokens, credits: result.usage.credits, responseTime: respTime, success: true })
        // 记录 API Key 用量
        if (matchedApiKey) {
          this.recordApiKeyUsage(matchedApiKey.id, result.usage.credits || 0, result.usage.inputTokens, result.usage.outputTokens, request.model, '/v1/chat/completions')
        }
      }
    } catch (error) {
      this.handleApiError(res, account, error as Error, '/v1/chat/completions', request.model, startTime, signal)
    }
  }

  private async handleOpenAIResponses(req: http.IncomingMessage, res: http.ServerResponse, signal?: AbortSignal): Promise<void> {
    const body = await this.readBody(req, signal)
    this.throwIfAborted(signal)
    const matchedApiKey = (req as unknown as { matchedApiKey?: import('./types').ApiKey }).matchedApiKey
    const startTime = Date.now()

    this.recordNewRequest()
    this.events.onRequest?.({ path: '/v1/responses', method: 'POST' })

    let responseRequest: OpenAIResponsesRequest
    let chatRequest: OpenAIChatRequest
    let processedRequest: OpenAIChatRequest
    try {
      responseRequest = JSON.parse(body)
      chatRequest = responsesToOpenAIChat(responseRequest)
      chatRequest.model = this.applyModelMapping(chatRequest.model, matchedApiKey?.id)
      processedRequest = await this.resolveOpenAIHttpImages(this.prepareOpenAIRequest(chatRequest), signal)
    } catch (error) {
      if (this.isAbortError(error, signal)) return
      this.recordRequestFailed()
      const message = error instanceof Error ? error.message : 'Invalid request'
      this.sendError(res, 400, message)
      this.events.onResponse?.({ path: '/v1/responses', status: 400, error: message })
      this.recordRequest({ path: '/v1/responses', responseTime: Date.now() - startTime, success: false, error: message })
      return
    }

    this.throwIfAborted(signal)
    const account = await this.getAvailableAccount(signal)
    this.throwIfAborted(signal)
    if (!account) {
      this.recordRequestFailed()
      const quotaStatus = this.accountPool.getQuotaStatus()
      const errorMsg = quotaStatus.exhausted > 0 && quotaStatus.available === 0
        ? `All accounts quota exhausted (${quotaStatus.exhausted}/${quotaStatus.total} exhausted, ${quotaStatus.cooldown} in cooldown)`
        : 'No available accounts'
      this.sendError(res, 503, errorMsg)
      this.events.onResponse?.({ path: '/v1/responses', model: chatRequest.model, status: 503, error: errorMsg })
      this.recordRequest({ path: '/v1/responses', model: chatRequest.model, success: false, error: 'No available accounts' })
      return
    }

    this.events.onRequest?.({ path: '/v1/responses', method: 'POST', accountId: account.id })

    try {
      const toolNameRegistry = new ToolNameRegistry()
      if (processedRequest.stream) {
        res.writeHead(200, {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          'Connection': 'keep-alive'
        })
        const responseId = `resp_${uuidv4()}`
        res.write(`event: response.created\ndata: ${JSON.stringify({ type: 'response.created', response: { id: responseId, object: 'response', created_at: Math.floor(Date.now() / 1000), model: chatRequest.model, output: [] } })}\n\n`)
        const { result, account: usedAccount } = await this.callWithRetry(
          account,
          async (acc) => {
            const retryPayload = openaiToKiro(processedRequest, acc.profileArn, toolNameRegistry)
            return callKiroApi(acc, retryPayload, signal)
          },
          '/v1/responses',
          signal
        )
        const chatResponse = kiroToOpenaiResponse(result.content, result.toolUses, result.usage, chatRequest.model, toolNameRegistry, result.reasoningContent)
        this.throwIfResponseClosed(res, signal)
        const response = openAIChatToResponsesResponse(chatResponse, responseRequest.previous_response_id)
        const streamedResponse = { ...response, id: responseId }
        streamedResponse.output.forEach((item, outputIndex) => {
          this.throwIfResponseClosed(res, signal)
          res.write(`event: response.output_item.added\ndata: ${JSON.stringify({ type: 'response.output_item.added', output_index: outputIndex, item })}\n\n`)
          if (item.type === 'message') {
            item.content.forEach((part, contentIndex) => {
              this.throwIfResponseClosed(res, signal)
              res.write(`event: response.content_part.added\ndata: ${JSON.stringify({ type: 'response.content_part.added', item_id: item.id, output_index: outputIndex, content_index: contentIndex, part: { type: part.type, text: '' } })}\n\n`)
              if (part.text) {
                res.write(`event: response.output_text.delta\ndata: ${JSON.stringify({ type: 'response.output_text.delta', item_id: item.id, output_index: outputIndex, content_index: contentIndex, delta: part.text })}\n\n`)
              }
              res.write(`event: response.output_text.done\ndata: ${JSON.stringify({ type: 'response.output_text.done', item_id: item.id, output_index: outputIndex, content_index: contentIndex, text: part.text })}\n\n`)
              res.write(`event: response.content_part.done\ndata: ${JSON.stringify({ type: 'response.content_part.done', item_id: item.id, output_index: outputIndex, content_index: contentIndex, part })}\n\n`)
            })
          } else {
            if (item.arguments) {
              res.write(`event: response.function_call_arguments.delta\ndata: ${JSON.stringify({ type: 'response.function_call_arguments.delta', item_id: item.id, output_index: outputIndex, delta: item.arguments })}\n\n`)
            }
            res.write(`event: response.function_call_arguments.done\ndata: ${JSON.stringify({ type: 'response.function_call_arguments.done', item_id: item.id, output_index: outputIndex, arguments: item.arguments })}\n\n`)
          }
          this.throwIfResponseClosed(res, signal)
          res.write(`event: response.output_item.done\ndata: ${JSON.stringify({ type: 'response.output_item.done', output_index: outputIndex, item })}\n\n`)
        })
        this.throwIfResponseClosed(res, signal)
        res.write(`event: response.completed\ndata: ${JSON.stringify({ type: 'response.completed', response: streamedResponse })}\n\n`)
        res.end()
        this.recordRequestSuccess()
        this.stats.totalTokens += result.usage.inputTokens + result.usage.outputTokens
        this.stats.inputTokens += result.usage.inputTokens
        this.stats.outputTokens += result.usage.outputTokens
        this.accountPool.recordSuccess(usedAccount.id, result.usage.inputTokens + result.usage.outputTokens)
        const respTime = Date.now() - startTime
        this.events.onResponse?.({ path: '/v1/responses', model: chatRequest.model, status: 200, tokens: result.usage.inputTokens + result.usage.outputTokens, inputTokens: result.usage.inputTokens, outputTokens: result.usage.outputTokens, cacheReadTokens: result.usage.cacheReadTokens, reasoningTokens: result.usage.reasoningTokens, credits: result.usage.credits, responseTime: respTime })
        this.recordRequest({ path: '/v1/responses', model: chatRequest.model, accountId: usedAccount.id, inputTokens: result.usage.inputTokens, outputTokens: result.usage.outputTokens, credits: result.usage.credits, responseTime: respTime, success: true })
        if (matchedApiKey) {
          this.recordApiKeyUsage(matchedApiKey.id, result.usage.credits || 0, result.usage.inputTokens, result.usage.outputTokens, chatRequest.model, '/v1/responses')
        }
        return
      }

      const { result, account: usedAccount } = await this.callWithRetry(
        account,
        async (acc) => {
          const retryPayload = openaiToKiro(processedRequest, acc.profileArn, toolNameRegistry)
          return callKiroApi(acc, retryPayload, signal)
        },
        '/v1/responses',
        signal
      )
      const chatResponse = kiroToOpenaiResponse(result.content, result.toolUses, result.usage, chatRequest.model, toolNameRegistry, result.reasoningContent)
      this.throwIfResponseClosed(res, signal)
      const response = openAIChatToResponsesResponse(chatResponse, responseRequest.previous_response_id)

      this.recordRequestSuccess()
      this.stats.totalTokens += result.usage.inputTokens + result.usage.outputTokens
      this.stats.inputTokens += result.usage.inputTokens
      this.stats.outputTokens += result.usage.outputTokens
      this.accountPool.recordSuccess(usedAccount.id, result.usage.inputTokens + result.usage.outputTokens)

      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify(response))
      const respTime = Date.now() - startTime
      this.events.onResponse?.({ path: '/v1/responses', model: chatRequest.model, status: 200, tokens: result.usage.inputTokens + result.usage.outputTokens, inputTokens: result.usage.inputTokens, outputTokens: result.usage.outputTokens, cacheReadTokens: result.usage.cacheReadTokens, reasoningTokens: result.usage.reasoningTokens, credits: result.usage.credits, responseTime: respTime })
      this.recordRequest({ path: '/v1/responses', model: chatRequest.model, accountId: usedAccount.id, inputTokens: result.usage.inputTokens, outputTokens: result.usage.outputTokens, credits: result.usage.credits, responseTime: respTime, success: true })
      if (matchedApiKey) {
        this.recordApiKeyUsage(matchedApiKey.id, result.usage.credits || 0, result.usage.inputTokens, result.usage.outputTokens, chatRequest.model, '/v1/responses')
      }
    } catch (error) {
      this.handleApiError(res, account, error as Error, '/v1/responses', chatRequest.model, startTime, signal)
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
    matchedApiKey?: import('./types').ApiKey,
    toolNameRegistry: ToolNameRegistry = new ToolNameRegistry(),
    signal?: AbortSignal
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
    // 发送初始 chunk（仅首轮）
    if (currentRound === 0) {
      const initialChunk = createOpenaiStreamChunk(id, model, { role: 'assistant' })
      res.write(`data: ${JSON.stringify(initialChunk)}\n\n`)
    }

    return new Promise((resolve) => {
      callKiroApiStream(
        account as any,
        kiroPayload,
        (text, toolUse, isThinking) => {
          if (signal?.aborted || this.isResponseClosed(res)) return
          if (text && text.trim()) {
            if (isThinking) {
              // 原生 thinking 内容 → 输出为 reasoning_content
              const chunk = createOpenaiStreamChunk(id, model, { reasoning_content: text })
              res.write(`data: ${JSON.stringify(chunk)}\n\n`)
            } else {
              // 普通文本内容
              collectedContent += text
              const chunk = createOpenaiStreamChunk(id, model, { content: text })
              res.write(`data: ${JSON.stringify(chunk)}\n\n`)
            }
          }
          if (toolUse) {
            const idx = toolCallIndex++
            const restoredToolUse = toolNameRegistry.restoreToolUse(toolUse)
            pendingToolCalls.set(toolUse.toolUseId, {
              index: idx,
              name: toolUse.name,
              arguments: JSON.stringify(toolUse.input)
            })
            const toolChunk = createOpenaiStreamChunk(id, model, {
              tool_calls: [{
                index: idx,
                id: toolUse.toolUseId,
                type: 'function',
                function: {
                  name: restoredToolUse.name,
                  arguments: JSON.stringify(toolUse.input)
                }
              }]
            })
            res.write(`data: ${JSON.stringify(toolChunk)}\n\n`)
          }
        },
        async (usage) => {
          if (signal?.aborted || this.isResponseClosed(res)) {
            resolve()
            return
          }
          
          this.recordRequestSuccess()
          this.stats.totalTokens += usage.inputTokens + usage.outputTokens
          this.stats.inputTokens += usage.inputTokens
          this.stats.outputTokens += usage.outputTokens
          this.stats.cacheReadTokens += usage.cacheReadTokens || 0
          this.stats.cacheWriteTokens += usage.cacheWriteTokens || 0
          this.stats.reasoningTokens += usage.reasoningTokens || 0
          this.stats.totalCredits += usage.credits || 0
          this.events.onCreditsUpdate?.(this.stats.totalCredits)
          this.events.onTokensUpdate?.(this.stats.inputTokens, this.stats.outputTokens)
          this.accountPool.recordSuccess(account.id, usage.inputTokens + usage.outputTokens)
          const oaiRespTime = Date.now() - startTime
          this.events.onResponse?.({ path: '/v1/chat/completions', model, status: 200, tokens: usage.inputTokens + usage.outputTokens, inputTokens: usage.inputTokens, outputTokens: usage.outputTokens, cacheReadTokens: usage.cacheReadTokens, reasoningTokens: usage.reasoningTokens, credits: usage.credits, responseTime: oaiRespTime })
          this.recordRequest({ path: '/v1/chat/completions', model, accountId: account.id, inputTokens: usage.inputTokens, outputTokens: usage.outputTokens, credits: usage.credits, responseTime: oaiRespTime, success: true })
          // 记录 API Key 用量
          if (matchedApiKey) {
            this.recordApiKeyUsage(matchedApiKey.id, usage.credits || 0, usage.inputTokens, usage.outputTokens, model, '/v1/chat/completions')
          }

          // 发送结束 chunk（包含完整 usage 信息）
          const hasToolCalls = pendingToolCalls.size > 0
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
        },
        (error) => {
          if (this.isAbortError(error, signal) || this.isResponseClosed(res)) {
            resolve()
            return
          }
          console.error('[ProxyServer] Stream error:', error)
          res.write(`data: ${JSON.stringify({ error: { message: error.message } })}\n\n`)
          res.end()

          this.recordRequestFailed()
          const errStatusCode = error.message.match(/(\d{3})/)?.[1]
          this.accountPool.recordError(account.id, errStatusCode ? classifyError(parseInt(errStatusCode)) : ErrorType.RECOVERABLE, errStatusCode ? parseInt(errStatusCode) : undefined)
          this.events.onResponse?.({ path: '/v1/chat/completions', model, status: 500, error: error.message })
          this.recordRequest({ path: '/v1/chat/completions', model, accountId: account.id, responseTime: Date.now() - startTime, success: false, error: error.message })
          resolve()
        },
        signal,
        this.config.preferredEndpoint
      ).catch(error => {
        if (!this.isAbortError(error, signal) && !this.isResponseClosed(res)) {
          res.write(`data: ${JSON.stringify({ error: { message: error.message } })}\n\n`)
          res.end()
          this.recordRequestFailed()
        }
        resolve()
      })
    })
  }

  // 处理 Claude Messages 请求
  private async handleClaudeMessages(req: http.IncomingMessage, res: http.ServerResponse, signal?: AbortSignal): Promise<void> {
    const body = await this.readBody(req, signal)
    this.throwIfAborted(signal)
    const request: ClaudeRequest = JSON.parse(body)
    const matchedApiKey = (req as unknown as { matchedApiKey?: import('./types').ApiKey }).matchedApiKey

    // 提取 session hint（用于稳定 conversationId），拼入 API Key hash 隔离不同用户
    if (!request.conversation_id) {
      const hint = ProxyServer.extractSessionHint(req, request)
      if (hint) {
        const keyPrefix = matchedApiKey?.id?.slice(0, 8) || 'default'
        request.conversation_id = `${keyPrefix}:${hint}`
      }
    }

    // 应用模型映射
    request.model = this.applyModelMapping(request.model, matchedApiKey?.id)

    const startTime = Date.now()

    this.recordNewRequest()
    this.events.onRequest?.({ path: '/v1/messages', method: 'POST' })

    let processedRequest: ClaudeRequest
    try {
      processedRequest = await this.resolveClaudeHttpImages(this.prepareClaudeRequest(request), signal)
    } catch (error) {
      if (this.isAbortError(error, signal)) return
      this.recordRequestFailed()
      const message = error instanceof Error ? error.message : 'Invalid request'
      this.sendError(res, 400, message, 'anthropic')
      this.events.onResponse?.({ path: '/v1/messages', model: request.model, status: 400, error: message })
      this.recordRequest({ path: '/v1/messages', model: request.model, responseTime: Date.now() - startTime, success: false, error: message })
      return
    }

    // 获取账号（包含 Token 刷新检查）
    this.throwIfAborted(signal)
    const account = await this.getAvailableAccount(signal)
    this.throwIfAborted(signal)
    if (!account) {
      this.recordRequestFailed()
      const quotaStatus = this.accountPool.getQuotaStatus()
      const errorMsg = quotaStatus.exhausted > 0 && quotaStatus.available === 0
        ? `All accounts quota exhausted (${quotaStatus.exhausted}/${quotaStatus.total} exhausted, ${quotaStatus.cooldown} in cooldown)`
        : 'No available accounts'
      this.sendError(res, 503, errorMsg, 'anthropic')
      this.events.onResponse?.({ path: '/v1/messages', model: request.model, status: 503, error: errorMsg })
      this.recordRequest({ path: '/v1/messages', model: request.model, success: false, error: errorMsg })
      return
    }

    this.events.onRequest?.({ path: '/v1/messages', method: 'POST', accountId: account.id })

    try {
      const toolNameRegistry = new ToolNameRegistry()

      const kiroPayload = claudeToKiro(processedRequest, account.profileArn, toolNameRegistry)

      // 构建 prompt cache profile（用于模拟缓存 usage）
      const estimatedInputTokens = Math.max(1, Math.round(JSON.stringify(kiroPayload).length * 0.3))
      const cacheProfile = promptCacheTracker.buildClaudeProfile(
        processedRequest.system,
        processedRequest.messages,
        processedRequest.tools,
        estimatedInputTokens,
        processedRequest.model
      )
      const cacheUsage = promptCacheTracker.compute(account.id, cacheProfile)

      if (cacheProfile) {
        proxyLogger.info('ProxyServer', `Prompt cache: ${cacheProfile.breakpoints.length} breakpoints, creation=${cacheUsage.cacheCreationInputTokens}, read=${cacheUsage.cacheReadInputTokens}`)
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
        await this.handleClaudeStream(res, account, kiroPayload, request.model, startTime, 0, undefined, false, 0, matchedApiKey, toolNameRegistry, signal,
          cacheProfile ? { ...cacheUsage, cacheProfile, accountId: account.id } : undefined)
      } else {
        // 非流式响应（带重试机制）
        const { result, account: usedAccount } = await this.callWithRetry(
          account,
          async (acc) => {
            const retryPayload = claudeToKiro(processedRequest, acc.profileArn, toolNameRegistry)
            return callKiroApi(acc, retryPayload, signal)
          },
          '/v1/messages',
          signal
        )
        const response = kiroToClaudeResponse(result.content, result.toolUses, result.usage, request.model, toolNameRegistry, result.reasoningContent)

        // 用缓存模拟的 usage 覆盖（如果有 cache profile）
        if (cacheProfile && cacheUsage) {
          if (cacheUsage.cacheCreationInputTokens > 0) response.usage.cache_creation_input_tokens = cacheUsage.cacheCreationInputTokens
          if (cacheUsage.cacheReadInputTokens > 0) response.usage.cache_read_input_tokens = cacheUsage.cacheReadInputTokens
          promptCacheTracker.update(usedAccount.id, cacheProfile)
        }

        this.throwIfResponseClosed(res, signal)
        this.recordRequestSuccess()
        this.stats.totalTokens += result.usage.inputTokens + result.usage.outputTokens
        this.stats.inputTokens += result.usage.inputTokens
        this.stats.outputTokens += result.usage.outputTokens
        this.accountPool.recordSuccess(usedAccount.id, result.usage.inputTokens + result.usage.outputTokens)

        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify(response))
        const respTime = Date.now() - startTime
        this.events.onResponse?.({ path: '/v1/messages', model: request.model, status: 200, tokens: result.usage.inputTokens + result.usage.outputTokens, inputTokens: result.usage.inputTokens, outputTokens: result.usage.outputTokens, cacheReadTokens: result.usage.cacheReadTokens, reasoningTokens: result.usage.reasoningTokens, credits: result.usage.credits, responseTime: respTime })
        this.recordRequest({ path: '/v1/messages', model: request.model, accountId: usedAccount.id, inputTokens: result.usage.inputTokens, outputTokens: result.usage.outputTokens, credits: result.usage.credits, responseTime: respTime, success: true })
      }
    } catch (error) {
      this.handleApiError(res, account, error as Error, '/v1/messages', request.model, startTime, signal)
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
    matchedApiKey?: import('./types').ApiKey,
    toolNameRegistry: ToolNameRegistry = new ToolNameRegistry(),
    signal?: AbortSignal,
    simulatedCacheUsage?: { cacheCreationInputTokens: number; cacheReadInputTokens: number; cacheProfile?: unknown; accountId?: string }
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
    let hasStartedThinkingBlock = false
    let pendingThinkingSignature: string | undefined
    let collectedContent = ''
    const pendingToolCalls: Map<string, { name: string; input: Record<string, unknown> }> = new Map()

    const flushThinkingSignature = () => {
      if (!pendingThinkingSignature) return
      const signatureDelta = createClaudeStreamEvent('content_block_delta', {
        index: currentBlockIndex,
        delta: { type: 'signature_delta', signature: pendingThinkingSignature }
      })
      res.write(`event: content_block_delta\ndata: ${JSON.stringify(signatureDelta)}\n\n`)
      pendingThinkingSignature = undefined
    }

    // 估算输入 tokens（基于 payload 大小）
    const estimatedInputTokens = Math.max(1, Math.round(JSON.stringify(kiroPayload).length / 3))
    
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
        (text, toolUse, isThinking, reasoningSignature, redactedContent) => {
          if (signal?.aborted || this.isResponseClosed(res)) return
          // 优先处理 redacted_thinking（加密的 thinking 块，需单独 content_block）
          if (redactedContent) {
            if (hasStartedTextBlock) {
              const blockStop = createClaudeStreamEvent('content_block_stop', { index: currentBlockIndex })
              res.write(`event: content_block_stop\ndata: ${JSON.stringify(blockStop)}\n\n`)
              currentBlockIndex++
              hasStartedTextBlock = false
            }
            if (hasStartedThinkingBlock) {
              flushThinkingSignature()
              const blockStop = createClaudeStreamEvent('content_block_stop', { index: currentBlockIndex })
              res.write(`event: content_block_stop\ndata: ${JSON.stringify(blockStop)}\n\n`)
              currentBlockIndex++
              hasStartedThinkingBlock = false
            }
            const blockStart = createClaudeStreamEvent('content_block_start', {
              index: currentBlockIndex,
              content_block: { type: 'redacted_thinking', data: redactedContent }
            })
            res.write(`event: content_block_start\ndata: ${JSON.stringify(blockStart)}\n\n`)
            const blockStop = createClaudeStreamEvent('content_block_stop', { index: currentBlockIndex })
            res.write(`event: content_block_stop\ndata: ${JSON.stringify(blockStop)}\n\n`)
            currentBlockIndex++
            return
          }
          if (text && text.trim()) {
            if (isThinking) {
              // 原生 thinking 内容 → 输出为 Anthropic thinking block
              if (hasStartedTextBlock) {
                const blockStop = createClaudeStreamEvent('content_block_stop', { index: currentBlockIndex })
                res.write(`event: content_block_stop\ndata: ${JSON.stringify(blockStop)}\n\n`)
                currentBlockIndex++
                hasStartedTextBlock = false
              }
              if (!hasStartedThinkingBlock) {
                const blockStart = createClaudeStreamEvent('content_block_start', {
                  index: currentBlockIndex,
                  content_block: { type: 'thinking', thinking: '' }
                })
                res.write(`event: content_block_start\ndata: ${JSON.stringify(blockStart)}\n\n`)
                hasStartedThinkingBlock = true
              }
              const delta = createClaudeStreamEvent('content_block_delta', {
                index: currentBlockIndex,
                delta: { type: 'thinking_delta', thinking: text }
              })
              res.write(`event: content_block_delta\ndata: ${JSON.stringify(delta)}\n\n`)
              if (reasoningSignature) {
                pendingThinkingSignature = reasoningSignature
              }
            } else {
              // 普通文本内容
              if (hasStartedThinkingBlock) {
                flushThinkingSignature()
                const blockStop = createClaudeStreamEvent('content_block_stop', { index: currentBlockIndex })
                res.write(`event: content_block_stop\ndata: ${JSON.stringify(blockStop)}\n\n`)
                currentBlockIndex++
                hasStartedThinkingBlock = false
              }
              collectedContent += text
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
                delta: { type: 'text_delta', text }
              })
              res.write(`event: content_block_delta\ndata: ${JSON.stringify(delta)}\n\n`)
            }
          } else if (isThinking && reasoningSignature) {
            if (!hasStartedThinkingBlock) {
              const blockStart = createClaudeStreamEvent('content_block_start', {
                index: currentBlockIndex,
                content_block: { type: 'thinking', thinking: '' }
              })
              res.write(`event: content_block_start\ndata: ${JSON.stringify(blockStart)}\n\n`)
              hasStartedThinkingBlock = true
            }
            pendingThinkingSignature = reasoningSignature
          }
          if (toolUse) {
            const restoredToolUse = toolNameRegistry.restoreToolUse(toolUse)
            if (hasStartedThinkingBlock) {
              flushThinkingSignature()
              const blockStop = createClaudeStreamEvent('content_block_stop', { index: currentBlockIndex })
              res.write(`event: content_block_stop\ndata: ${JSON.stringify(blockStop)}\n\n`)
              currentBlockIndex++
              hasStartedThinkingBlock = false
            }
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
              content_block: { type: 'tool_use', id: toolUse.toolUseId, name: restoredToolUse.name, input: {} }
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
          if (signal?.aborted || this.isResponseClosed(res)) {
            resolve()
            return
          }
          if (hasStartedThinkingBlock) {
            flushThinkingSignature()
            const blockStop = createClaudeStreamEvent('content_block_stop', { index: currentBlockIndex })
            res.write(`event: content_block_stop\ndata: ${JSON.stringify(blockStop)}\n\n`)
            currentBlockIndex++
            hasStartedThinkingBlock = false
          }

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
          this.stats.cacheReadTokens += usage.cacheReadTokens || simulatedCacheUsage?.cacheReadInputTokens || 0
          this.stats.cacheWriteTokens += usage.cacheWriteTokens || simulatedCacheUsage?.cacheCreationInputTokens || 0
          this.stats.reasoningTokens += usage.reasoningTokens || 0
          const respTime = Date.now() - startTime
          this.events.onResponse?.({ path: '/v1/messages', model, status: 200, tokens: usage.inputTokens + usage.outputTokens, inputTokens: usage.inputTokens, outputTokens: usage.outputTokens, cacheReadTokens: usage.cacheReadTokens || simulatedCacheUsage?.cacheReadInputTokens, reasoningTokens: usage.reasoningTokens, credits: usage.credits, responseTime: respTime })
          this.recordRequest({ path: '/v1/messages', model, accountId: account.id, inputTokens: usage.inputTokens, outputTokens: usage.outputTokens, credits: usage.credits, responseTime: respTime, success: true })
          // 记录 API Key 用量
          if (matchedApiKey) {
            this.recordApiKeyUsage(matchedApiKey.id, usage.credits || 0, usage.inputTokens, usage.outputTokens, model, '/v1/messages')
          }

          // 成功后更新 prompt cache tracker
          if (simulatedCacheUsage?.cacheProfile && simulatedCacheUsage?.accountId) {
            promptCacheTracker.update(simulatedCacheUsage.accountId, simulatedCacheUsage.cacheProfile as any)
          }
          // 发送 message_delta（包含完整 usage 信息）
          const hasToolCalls = pendingToolCalls.size > 0
          const stopReason = hasToolCalls ? 'tool_use' : 'end_turn'
          const messageDelta = createClaudeStreamEvent('message_delta', {
            delta: { stop_reason: stopReason, stop_sequence: null } as any,
            usage: this.buildClaudeUsage(usage, simulatedCacheUsage)
          })
          res.write(`event: message_delta\ndata: ${JSON.stringify(messageDelta)}\n\n`)
          // 发送 message_stop
          const messageStop = createClaudeStreamEvent('message_stop')
          res.write(`event: message_stop\ndata: ${JSON.stringify(messageStop)}\n\n`)
          res.end()
          resolve()
        },
        (error) => {
          if (this.isAbortError(error, signal) || this.isResponseClosed(res)) {
            resolve()
            return
          }
          console.error('[ProxyServer] Stream error:', error)
          const errorEvent = createClaudeStreamEvent('error', {
            error: { type: 'api_error', message: error.message }
          })
          res.write(`event: error\ndata: ${JSON.stringify(errorEvent)}\n\n`)
          res.end()

          this.recordRequestFailed()
          const errStatusCode2 = error.message.match(/(\d{3})/)?.[1]
          this.accountPool.recordError(account.id, errStatusCode2 ? classifyError(parseInt(errStatusCode2)) : ErrorType.RECOVERABLE, errStatusCode2 ? parseInt(errStatusCode2) : undefined)
          this.events.onResponse?.({ path: '/v1/messages', model, status: 500, error: error.message })
          this.recordRequest({ path: '/v1/messages', model, accountId: account.id, responseTime: Date.now() - startTime, success: false, error: error.message })
          resolve()
        },
        signal,
        this.config.preferredEndpoint
      ).catch(error => {
        if (!this.isAbortError(error, signal) && !this.isResponseClosed(res)) {
          const errorEvent = createClaudeStreamEvent('error', {
            error: { type: 'api_error', message: error.message }
          })
          res.write(`event: error\ndata: ${JSON.stringify(errorEvent)}\n\n`)
          res.end()
          this.recordRequestFailed()
        }
        resolve()
      })
    })
  }

  // 处理 API 错误
  private handleApiError(res: http.ServerResponse, account: { id: string }, error: Error, path: string, model?: string, startTime?: number, signal?: AbortSignal): void {
    if (this.isAbortError(error, signal) || this.isResponseClosed(res)) return
    this.recordRequestFailed()
    const errCode = error.message.match(/(\d{3})/)?.[1]
    const parsedCode = errCode ? parseInt(errCode) : 500
    const errorType = classifyError(parsedCode)
    const isAuthError = error.message.includes('401') || error.message.includes('403') || error.message.includes('Auth')

    this.accountPool.recordError(account.id, errorType, parsedCode)

    let statusCode = parsedCode
    if (isAuthError) statusCode = 401

    if (res.headersSent) {
      if (!this.isResponseClosed(res)) {
        if (path === '/v1/responses' || path === '/responses') {
          res.write(`event: response.failed\ndata: ${JSON.stringify({ type: 'response.failed', error: { type: 'api_error', message: error.message } })}\n\n`)
        }
        res.end()
      }
      this.events.onResponse?.({ path, status: statusCode, error: error.message })
      this.recordRequest({ path, model, accountId: account.id, responseTime: startTime ? Date.now() - startTime : 0, success: false, error: error.message })
      return
    }

    this.sendError(res, statusCode, error.message, this.isAnthropicPath(path) ? 'anthropic' : 'openai')
    this.events.onResponse?.({ path, status: statusCode, error: error.message })
    this.recordRequest({ path, model, accountId: account.id, responseTime: startTime ? Date.now() - startTime : 0, success: false, error: error.message })
  }

  // 读取请求体
  private readBody(req: http.IncomingMessage, signal?: AbortSignal): Promise<string> {
    return new Promise((resolve, reject) => {
      let body = ''
      const cleanup = () => {
        req.off('data', onData)
        req.off('end', onEnd)
        req.off('error', onError)
        req.off('aborted', onAborted)
        signal?.removeEventListener('abort', onAbort)
      }
      const onData = (chunk: Buffer) => body += chunk
      const onEnd = () => {
        cleanup()
        resolve(body)
      }
      const onError = (error: Error) => {
        cleanup()
        reject(error)
      }
      const onAborted = () => {
        cleanup()
        reject(new Error('Client disconnected'))
      }
      const onAbort = () => {
        cleanup()
        reject(this.getAbortError(signal))
      }
      if (signal?.aborted) {
        reject(this.getAbortError(signal))
        return
      }
      req.on('data', onData)
      req.on('end', onEnd)
      req.on('error', onError)
      req.on('aborted', onAborted)
      signal?.addEventListener('abort', onAbort, { once: true })
    })
  }

  // 发送错误响应
  private sendError(res: http.ServerResponse, status: number, message: string, format: 'openai' | 'anthropic' = 'openai'): void {
    if (res.writableEnded || res.destroyed) return
    res.writeHead(status, { 'Content-Type': 'application/json' })
    if (format === 'anthropic') {
      res.end(JSON.stringify({
        type: 'error',
        error: {
          type: this.getAnthropicErrorType(status),
          message
        }
      }))
      return
    }
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
