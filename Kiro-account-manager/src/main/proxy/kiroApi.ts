// Kiro API 调用核心模块
import { v4 as uuidv4 } from 'uuid'
import { fetch as undiciFetch, type RequestInit as UndiciRequestInit, type Dispatcher } from 'undici'
import type {
  KiroPayload,
  KiroUserInputMessage,
  KiroHistoryMessage,
  KiroToolWrapper,
  KiroToolResult,
  KiroImage,
  KiroDocument,
  KiroToolUse,
  KiroCachePoint,
  KiroRequestContext,
  KiroUsage,
  ProxyAccount
} from './types'
import { proxyLogger } from './logger'
import { getKProxyService } from '../kproxy'
import { getSystemProxy, safeCreateProxyAgent } from './systemProxy'
import {
  countTokens,
  getModelContextLength,
  setModelContextWindow,
  getModelContextWindow
} from './tokenCounter'
// 重新导出以保持向后兼容（proxyServer.ts 等模块仍 from './kiroApi' 导入）
export { setModelContextWindow, getModelContextWindow }

// 是否使用 K-Proxy 代理发送 API 请求（从主进程导入）
let useKProxyForApi = false
let logStreamEvents = false

export function setUseKProxyForApiInProxy(enabled: boolean): void {
  useKProxyForApi = enabled
}

export function setLogStreamEvents(enabled: boolean): void {
  logStreamEvents = enabled
}

// Payload 大小限制（KB），用户可在高级设置中调整
let payloadSizeLimitKB = 1536 // 默认 1.5MB
export function setPayloadSizeLimitKB(limitKB: number): void {
  payloadSizeLimitKB = Math.max(256, Math.min(10240, limitKB))
}

// Token buffer reserve 开关（默认 false = 完全跳过 trimHistoryByTokens）
// 关闭时后端不再裁剪任何旧消息，超出 context window 由 Kiro 后端原样返回错误
let enableTokenBufferReserve = false
export function setEnableTokenBufferReserve(enabled: boolean): void {
  enableTokenBufferReserve = !!enabled
}
export function getEnableTokenBufferReserve(): boolean {
  return enableTokenBufferReserve
}

// Token buffer reserve（仅在 enableTokenBufferReserve=true 时生效）
// 为 model context window 预留的余量，覆盖 system + tools + current + output + 估算偏差 + schema 开销
// 默认 20K：开关启用后的合理初始值（200K → effective 180K, 1M → effective 980K）
let tokenBufferReserve = 20000
export function setTokenBufferReserve(tokens: number): void {
  tokenBufferReserve = Math.max(5000, Math.min(150000, tokens))
}
export function getTokenBufferReserve(): number {
  return tokenBufferReserve
}

// 根据 modelId 和 buffer 计算 effective token limit
// 仅在 enableTokenBufferReserve=true 时被调用
// 查不到 model 时 fallback 到 200K context (Claude 默认)
function getEffectiveTokenLimit(modelId?: string): number {
  // 复用 getModelContextLength（支持 cache 命中 → 模糊匹配 → 关键词兜底）
  const ctx = modelId ? getModelContextLength(modelId) : 200000
  return Math.max(8000, ctx - tokenBufferReserve)
}

// Token 估算 (UTF-8 字节数 / 3.5，对中英混合场景做安全偏保守估算)
// 比真实 cl100k_base tokenizer 略偏高 (10-20%), 用于触发裁剪阈值是安全的
function estimateTokensFromString(str: string): number {
  return Math.ceil(Buffer.byteLength(str, 'utf-8') / 3.5)
}

function estimatePayloadTokens(payload: KiroPayload): number {
  return estimateTokensFromString(JSON.stringify(payload))
}

/**
 * 获取网络代理 agent
 * 优先级（从高到低）：
 *   1. 账号自身绑定的 proxyUrl（实现"N 个号一个 IP"分桶反代）
 *   2. K-Proxy（如果启用）
 *   3. 环境变量代理
 *   4. 系统代理
 *
 * 传入 account 让账号级代理覆盖全局；不传则走全局逻辑。
 */
function getNetworkAgent(account?: ProxyAccount): Dispatcher | undefined {
  // 1. 账号专属代理：实现"N 个账号共用 1 个 IP"的分桶反代
  if (account?.proxyUrl) {
    const agent = safeCreateProxyAgent(account.proxyUrl)
    if (agent) {
      proxyLogger.debug('KiroAPI', `Using account-bound proxy for ${account.email || account.id}`)
      return agent
    }
  }
  // 2. K-Proxy
  if (useKProxyForApi) {
    const kproxyService = getKProxyService()
    if (kproxyService?.isRunning()) {
      const config = kproxyService.getConfig()
      const proxyUrl = `http://${config.host}:${config.port}`
      const agent = safeCreateProxyAgent(proxyUrl)
      if (agent) return agent
    }
  }
  // 3. 环境变量
  const envProxy = process.env.HTTPS_PROXY || process.env.https_proxy || process.env.HTTP_PROXY || process.env.http_proxy
  const envAgent = safeCreateProxyAgent(envProxy)
  if (envAgent) return envAgent
  // 4. 系统代理
  return safeCreateProxyAgent(getSystemProxy())
}

/**
 * 使用代理的 fetch 函数
 * 传入 account 时会优先使用账号绑定的代理（账号-代理 N:1 分桶）
 */
async function fetchWithProxy(url: string, options: RequestInit, account?: ProxyAccount): Promise<Response> {
  const agent = getNetworkAgent(account)
  if (agent) {
    proxyLogger.debug('KiroAPI', `Using proxy agent: ${agent.constructor.name}`)
    return await undiciFetch(url, { ...options, dispatcher: agent } as UndiciRequestInit) as unknown as Response
  }
  return await fetch(url, options)
}

// Kiro API 端点配置
const KIRO_ENDPOINTS = [
  {
    url: 'https://codewhisperer.us-east-1.amazonaws.com/generateAssistantResponse',
    origin: 'AI_EDITOR',
    amzTarget: 'AmazonCodeWhispererStreamingService.GenerateAssistantResponse',
    name: 'CodeWhisperer',
    protocol: 'generateAssistantResponse' as const
  },
  {
    url: 'https://q.us-east-1.amazonaws.com/generateAssistantResponse',
    origin: 'AI_EDITOR',
    amzTarget: 'AmazonCodeWhispererStreamingService.GenerateAssistantResponse',
    name: 'AmazonQ',
    protocol: 'generateAssistantResponse' as const
  },
  {
    url: 'https://q.us-east-1.amazonaws.com/SendMessageStreaming',
    origin: 'CLI',
    amzTarget: 'AmazonQDeveloperStreamingService.SendMessage',
    name: 'AmazonQCLI'
  }
]

// Kiro 版本号（跟随官方 IDE 更新）
const KIRO_VERSION = '0.12.155'
const AWS_SDK_VERSION = '1.0.34'
const AWS_STREAMING_API_VERSION = '1.0.34'

const OS_PLATFORM = process.platform === 'win32' ? 'win32' : process.platform === 'darwin' ? 'macos' : 'linux'
const OS_RELEASE = (() => { try { return require('os').release() } catch { return '10.0.0' } })()
const NODE_VERSION = process.versions.node || '22.22.0'

function getKiroUserAgent(machineId?: string): string {
  const suffix = machineId ? `KiroIDE-${KIRO_VERSION}-${machineId}` : `KiroIDE-${KIRO_VERSION}`
  return `aws-sdk-js/${AWS_SDK_VERSION} ua/2.1 os/${OS_PLATFORM}#${OS_RELEASE} lang/js md/nodejs#${NODE_VERSION} api/codewhispererstreaming#${AWS_STREAMING_API_VERSION} m/E ${suffix}`
}

function getKiroAmzUserAgent(machineId?: string): string {
  const suffix = machineId ? `KiroIDE ${KIRO_VERSION} ${machineId}` : `KiroIDE-${KIRO_VERSION}`
  return `aws-sdk-js/${AWS_SDK_VERSION} ${suffix}`
}

const KIRO_CLI_OS = OS_PLATFORM === 'win32' ? 'windows' : OS_PLATFORM === 'macos' ? 'macos' : 'linux'
const KIRO_CLI_USER_AGENT = `aws-sdk-rust/1.3.9 os/${KIRO_CLI_OS} lang/rust/1.87.0`
const KIRO_CLI_AMZ_USER_AGENT = `aws-sdk-rust/1.3.9 ua/2.1 api/ssooidc/1.88.0 os/${KIRO_CLI_OS} lang/rust/1.87.0 m/E app/AmazonQ-For-CLI`

// Agent 模式
const AGENT_MODE_SPEC = 'spec' // IDE 模式
const AGENT_MODE_VIBE = 'vibe' // CLI 模式

// NOTE: AWS Builder ID accounts have no profile concept, so no BuilderId
// profileArn constant is needed — see resolveProfileArn below.
const KIRO_SOCIAL_PROFILE_ARN = 'arn:aws:codewhisperer:us-east-1:699475941385:profile/EHGA3GRVQMUK'

function resolveProfileArn(account: ProxyAccount): string | undefined {
  if (account.profileArn) return account.profileArn
  if (account.provider === 'Github' || account.provider === 'Google') return KIRO_SOCIAL_PROFILE_ARN
  // AWS Builder ID accounts have no profile concept. Attaching any profileArn
  // (including the placeholder constant) makes CodeWhisperer return
  // 403 "User is not authorized to make this call." So omit it for BuilderId.
  return undefined
}

// Agentic 模式系统提示 - 防止大文件写入超时
const AGENTIC_SYSTEM_PROMPT = `# CRITICAL: CHUNKED WRITE PROTOCOL (MANDATORY)

You MUST follow these rules for ALL file operations. Violation causes server timeouts and task failure.

## ABSOLUTE LIMITS
- **MAXIMUM 350 LINES** per single write/edit operation - NO EXCEPTIONS
- **RECOMMENDED 300 LINES** or less for optimal performance
- **NEVER** write entire files in one operation if >300 lines

## MANDATORY CHUNKED WRITE STRATEGY

### For NEW FILES (>300 lines total):
1. FIRST: Write initial chunk (first 250-300 lines) using write_to_file/fsWrite
2. THEN: Append remaining content in 250-300 line chunks using file append operations
3. REPEAT: Continue appending until complete

### For EDITING EXISTING FILES:
1. Use surgical edits (apply_diff/targeted edits) - change ONLY what's needed
2. NEVER rewrite entire files - use incremental modifications
3. Split large refactors into multiple small, focused edits

REMEMBER: When in doubt, write LESS per operation. Multiple small operations > one large operation.`

// Thinking 模式标签
const THINKING_MODE_PROMPT = `<thinking_mode>enabled</thinking_mode>
<max_thinking_length>200000</max_thinking_length>`

const CODEWHISPERER_DEFAULT_MODEL_ID = 'CLAUDE_SONNET_4_20250514_V1_0'
const CODEWHISPERER_MODEL_CACHE_TTL = 5 * 60 * 1000

const codeWhispererModelCache = new Map<string, { models: KiroModel[]; timestamp: number }>()

// 模型 ID 映射
const MODEL_ID_MAP: Record<string, string> = {
  // Claude 4.5 系列
  'claude-sonnet-4-5': 'claude-sonnet-4.5',
  'claude-sonnet-4.5': 'claude-sonnet-4.5',
  'claude-haiku-4-5': 'claude-haiku-4.5',
  'claude-haiku-4.5': 'claude-haiku-4.5',
  'claude-opus-4-5': 'claude-opus-4.5',
  'claude-opus-4.5': 'claude-opus-4.5',
  // Claude 4 系列
  'claude-sonnet-4': 'claude-sonnet-4',
  'claude-sonnet-4-20250514': 'claude-sonnet-4',
  // Claude 3.5 系列 (映射到 Sonnet 4.5)
  'claude-3-5-sonnet': 'claude-sonnet-4.5',
  'claude-3-opus': 'claude-sonnet-4.5',
  'claude-3-sonnet': 'claude-sonnet-4',
  'claude-3-haiku': 'claude-haiku-4.5',
  // GPT 兼容映射 (映射到 Sonnet 4.5)
  'gpt-4': 'claude-sonnet-4.5',
  'gpt-4o': 'claude-sonnet-4.5',
  'gpt-4-turbo': 'claude-sonnet-4.5',
  'gpt-3.5-turbo': 'claude-sonnet-4.5',
  'default': 'claude-sonnet-4.5'
}

/**
 * 归一化 Claude 版本号：把版本号里的短横线转成点号。
 *
 * 背景：部分客户端（如 Claude Code）不允许模型名里出现 "."，会把 "claude-opus-4.6"
 * 写成 "claude-opus-4-6"，若原样透传给 Kiro 会被解析成 "claude-opus-4"（丢掉 minor），
 * 导致 1M 上下文等特性设置失败。这里把 claude-{family}-{major}-{minor} 的最后一段
 * 版本短横转成点号，兼容未来任意新版本（4.6 / 4.7 / 5.0 ...）。
 *
 * 仅当 minor 是 1~2 位数字且其后不是更多数字时才转换，避免误伤日期快照后缀
 * （如 claude-sonnet-4-20250514 不会被改）。
 */
function normalizeClaudeVersion(modelId: string): string {
  return modelId.replace(
    /^(claude-(?:sonnet|haiku|opus))-(\d+)-(\d{1,2})(?=$|[^\d])/i,
    '$1-$2.$3'
  )
}

export function mapModelId(model: string): string {
  let modelId = model.trim()
  if (!modelId) return MODEL_ID_MAP.default
  if (isCodeWhispererModelId(modelId)) return modelId
  // 0) 归一化版本号短横 → 点号（claude-opus-4-6 → claude-opus-4.6），兼容不支持 "." 的客户端
  modelId = normalizeClaudeVersion(modelId)
  const lower = modelId.toLowerCase()
  // 1) 显式 alias 映射优先
  if (MODEL_ID_MAP[lower]) return MODEL_ID_MAP[lower]
  // 2) 看似 Kiro 支持的 Claude 模型格式 (claude-{sonnet|haiku|opus}-{ver})，原样透传
  //    用于向前兼容尚未加入 MODEL_ID_MAP 的新发布模型
  if (/^claude-(sonnet|haiku|opus)-/.test(lower)) return modelId
  // 3) 完全未知的 model（用户拼错/不存在），兜底到 default 避免直接 400
  console.warn(`[Kiro API] Unknown model "${modelId}" → fallback to "${MODEL_ID_MAP.default}"`)
  return MODEL_ID_MAP.default
}

function clonePayload(payload: KiroPayload): KiroPayload {
  return JSON.parse(JSON.stringify(payload)) as KiroPayload
}

function normalizeModelKey(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, '')
}

function modelTokens(value: string): string[] {
  return value.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean)
}

function matchesRequestedModel(model: KiroModel, requestedModelId: string): boolean {
  // 1. modelId 级精确匹配（去除符号后比较）
  const requestedKey = normalizeModelKey(requestedModelId)
  const modelIdKey = normalizeModelKey(model.modelId)
  if (modelIdKey === requestedKey || modelIdKey.includes(requestedKey)) return true
  // 2. modelName 精确匹配
  if (model.modelName && normalizeModelKey(model.modelName).includes(requestedKey)) return true
  // 3. token 匹配（所有请求 token 必须在 modelId+modelName 中命中，不搜索 description 避免误匹配）
  const tokens = modelTokens(requestedModelId).filter(token => token !== 'latest' && token !== 'model')
  if (tokens.length === 0) return false
  const candidateTokens = new Set(modelTokens(`${model.modelId} ${model.modelName || ''}`))
  // 必须全部 token 命中
  if (!tokens.every(token => candidateTokens.has(token))) return false
  // 防止模型家族冲突：如果请求包含 opus/sonnet/haiku，候选必须也包含对应的
  const families = ['opus', 'sonnet', 'haiku']
  for (const family of families) {
    if (tokens.includes(family) && !candidateTokens.has(family)) return false
    if (!tokens.includes(family) && candidateTokens.has(family)) return false
  }
  return true
}

function isCodeWhispererModelId(modelId: string): boolean {
  return /^[A-Z0-9_]+$/.test(modelId) && modelId.includes('_')
}

function getModelCacheKey(account: ProxyAccount): string {
  return `${account.id}:${account.region || 'us-east-1'}:${resolveProfileArn(account) || 'no-arn'}`
}

async function getCachedCodeWhispererModels(account: ProxyAccount, signal?: AbortSignal): Promise<KiroModel[]> {
  const key = getModelCacheKey(account)
  const cached = codeWhispererModelCache.get(key)
  if (cached && Date.now() - cached.timestamp < CODEWHISPERER_MODEL_CACHE_TTL) return cached.models
  const models = await fetchKiroModels(account, signal)
  codeWhispererModelCache.set(key, { models, timestamp: Date.now() })
  return models
}

async function resolveCodeWhispererModelId(account: ProxyAccount, requestedModelId?: string, signal?: AbortSignal): Promise<string> {
  const modelId = requestedModelId?.trim()
  if (!modelId) return CODEWHISPERER_DEFAULT_MODEL_ID
  if (isCodeWhispererModelId(modelId)) return modelId
  const models = await getCachedCodeWhispererModels(account, signal)
  return models.find(model => matchesRequestedModel(model, modelId))?.modelId || CODEWHISPERER_DEFAULT_MODEL_ID
}

function getPayloadModelId(payload: KiroPayload): string | undefined {
  const currentModelId = payload.conversationState.currentMessage.userInputMessage.modelId
  if (currentModelId) return currentModelId
  return payload.conversationState.history?.find(message => message.userInputMessage?.modelId)?.userInputMessage?.modelId
}

function applyPayloadModelId(payload: KiroPayload, modelId: string): void {
  payload.conversationState.currentMessage.userInputMessage.modelId = modelId
  for (const message of payload.conversationState.history ?? []) {
    if (message.userInputMessage) message.userInputMessage.modelId = modelId
  }
}

function applyPayloadOrigin(payload: KiroPayload, origin: string): void {
  payload.conversationState.currentMessage.userInputMessage.origin = origin
  for (const message of payload.conversationState.history ?? []) {
    if (message.userInputMessage) message.userInputMessage.origin = origin
  }
}

// 检测是否为 Agentic 模式请求
export function isAgenticRequest(model: string, tools?: unknown[]): boolean {
  const lower = model.toLowerCase()
  // 模型名称包含 -agentic 或有工具调用
  return lower.includes('-agentic') || lower.includes('agentic') || Boolean(tools && tools.length > 0)
}

// 检测是否启用 Thinking 模式
export function isThinkingEnabled(headers?: Record<string, string>): boolean {
  if (!headers) return false
  // 检查 Anthropic-Beta 头是否包含 thinking
  const betaHeader = headers['anthropic-beta'] || headers['Anthropic-Beta'] || ''
  return betaHeader.toLowerCase().includes('thinking')
}

// 注入系统提示
export function injectSystemPrompts(
  content: string,
  isAgentic: boolean,
  thinkingEnabled: boolean
): string {
  let result = content
  
  // 注入时间戳
  const timestamp = new Date().toISOString()
  const timestampPrompt = `Current time: ${timestamp}`
  
  // 注入 Thinking 模式（必须在最前面）
  if (thinkingEnabled) {
    result = THINKING_MODE_PROMPT + '\n\n' + result
  }
  
  // 注入 Agentic 模式提示
  if (isAgentic) {
    result = result + '\n\n' + AGENTIC_SYSTEM_PROMPT
  }
  
  // 注入时间戳
  result = timestampPrompt + '\n\n' + result
  
  return result
}

// ============= 消息清理逻辑（参考 Kiro 官方实现）=============

// 占位消息
const HELLO_MESSAGE: KiroHistoryMessage = {
  userInputMessage: { content: 'Hello', origin: 'AI_EDITOR' }
}

const CONTINUE_MESSAGE: KiroHistoryMessage = {
  userInputMessage: { content: 'Continue', origin: 'AI_EDITOR' }
}

const UNDERSTOOD_MESSAGE: KiroHistoryMessage = {
  assistantResponseMessage: { content: 'understood' }
}

// 创建失败的工具结果消息
function createFailedToolUseMessage(toolUseIds: string[]): KiroHistoryMessage {
  return {
    userInputMessage: {
      content: '',
      origin: 'AI_EDITOR',
      userInputMessageContext: {
        toolResults: toolUseIds.map(createFailedToolResult)
      }
    }
  }
}

// 类型检查函数
function isUserInputMessage(message: KiroHistoryMessage): boolean {
  return message != null && 'userInputMessage' in message && message.userInputMessage != null
}

function isAssistantResponseMessage(message: KiroHistoryMessage): boolean {
  return message != null && 'assistantResponseMessage' in message && message.assistantResponseMessage != null
}

function hasToolResults(message: KiroHistoryMessage): boolean {
  return !!(message.userInputMessage?.userInputMessageContext?.toolResults?.length)
}

function hasToolUses(message: KiroHistoryMessage): boolean {
  return !!(message.assistantResponseMessage?.toolUses?.length)
}

function hasMatchingToolResults(
  toolUses: KiroToolUse[] | undefined,
  toolResults: KiroToolResult[] | undefined
): boolean {
  if (!toolUses || !toolUses.length) return true
  if (!toolResults || !toolResults.length) return false
  
  const allToolUsesHaveResults = toolUses.every(
    toolUse => toolResults.some(result => result.toolUseId === toolUse.toolUseId)
  )
  const allToolResultsHaveUses = toolResults.every(
    result => toolUses.some(toolUse => result.toolUseId === toolUse.toolUseId)
  )
  return allToolUsesHaveResults && allToolResultsHaveUses
}

function createFailedToolResult(toolUseId: string): KiroToolResult {
  return {
    toolUseId,
    content: [{ text: 'Tool execution failed' }],
    status: 'error'
  }
}

function stripInvalidToolResults(message: KiroHistoryMessage): KiroHistoryMessage | null {
  if (message.userInputMessage?.content?.trim()) {
    return {
      userInputMessage: {
        ...message.userInputMessage,
        userInputMessageContext: undefined
      }
    }
  }
  return null
}

// 确保以 user 消息开始
function ensureStartsWithUserMessage(messages: KiroHistoryMessage[]): KiroHistoryMessage[] {
  if (messages.length === 0 || isUserInputMessage(messages[0])) {
    return messages
  }
  return [HELLO_MESSAGE, ...messages]
}

// 确保以 user 消息结束
function ensureEndsWithUserMessage(messages: KiroHistoryMessage[]): KiroHistoryMessage[] {
  if (messages.length === 0) return [HELLO_MESSAGE]
  if (isUserInputMessage(messages[messages.length - 1])) return messages
  return [...messages, CONTINUE_MESSAGE]
}

// 确保消息交替
function ensureAlternatingMessages(messages: KiroHistoryMessage[]): KiroHistoryMessage[] {
  if (messages.length <= 1) return messages
  
  const result: KiroHistoryMessage[] = [messages[0]]
  for (let i = 1; i < messages.length; i++) {
    const prevMessage = result[result.length - 1]
    const currentMessage = messages[i]
    
    if (isUserInputMessage(prevMessage) && isUserInputMessage(currentMessage)) {
      result.push(UNDERSTOOD_MESSAGE)
    } else if (isAssistantResponseMessage(prevMessage) && isAssistantResponseMessage(currentMessage)) {
      result.push(CONTINUE_MESSAGE)
    }
    result.push(currentMessage)
  }
  return result
}

function relocateToolResultMessages(messages: KiroHistoryMessage[]): KiroHistoryMessage[] {
  const assistantToolUseIndexes: number[] = []
  const toolResultIndexById = new Map<string, number>()
  for (let i = 0; i < messages.length; i++) {
    const message = messages[i]
    if (isAssistantResponseMessage(message) && hasToolUses(message)) {
      assistantToolUseIndexes.push(i)
    } else if (isUserInputMessage(message) && hasToolResults(message)) {
      for (const toolResult of message.userInputMessage?.userInputMessageContext?.toolResults ?? []) {
        if (toolResult.toolUseId && !toolResultIndexById.has(toolResult.toolUseId)) {
          toolResultIndexById.set(toolResult.toolUseId, i)
        }
      }
    }
  }

  if (assistantToolUseIndexes.length === 0) return messages

  const result: KiroHistoryMessage[] = []
  const usedIndexes = new Set<number>()
  for (let i = 0; i < messages.length; i++) {
    if (usedIndexes.has(i)) continue
    const message = messages[i]
    result.push(message)
    usedIndexes.add(i)

    if (isAssistantResponseMessage(message) && hasToolUses(message)) {
      for (const toolUse of message.assistantResponseMessage?.toolUses ?? []) {
        const toolResultIndex = toolResultIndexById.get(toolUse.toolUseId)
        if (toolResultIndex !== undefined && toolResultIndex !== i + 1 && !usedIndexes.has(toolResultIndex)) {
          const toolResultMessage = messages[toolResultIndex]
          if (toolResultMessage) {
            result.push(toolResultMessage)
            usedIndexes.add(toolResultIndex)
          }
        }
      }
    }
  }
  return result
}

function removeInvalidToolResultMessages(messages: KiroHistoryMessage[]): KiroHistoryMessage[] {
  const result: KiroHistoryMessage[] = []
  for (let i = 0; i < messages.length; i++) {
    const message = messages[i]
    const previousMessage = i > 0 ? messages[i - 1] : null
    if (!isUserInputMessage(message) || !hasToolResults(message)) {
      result.push(message)
      continue
    }
    if (!previousMessage || !isAssistantResponseMessage(previousMessage) || !hasToolUses(previousMessage)) {
      const stripped = stripInvalidToolResults(message)
      if (stripped) result.push(stripped)
      continue
    }

    const validToolUseIds = new Set((previousMessage.assistantResponseMessage?.toolUses ?? []).map(toolUse => toolUse.toolUseId).filter(Boolean))
    const seenToolUseIds = new Set<string>()
    const toolResults = message.userInputMessage?.userInputMessageContext?.toolResults ?? []
    const filteredToolResults = toolResults.filter(toolResult => {
      if (!toolResult.toolUseId || !validToolUseIds.has(toolResult.toolUseId) || seenToolUseIds.has(toolResult.toolUseId)) return false
      seenToolUseIds.add(toolResult.toolUseId)
      return true
    })

    if (filteredToolResults.length === toolResults.length) {
      result.push(message)
    } else if (filteredToolResults.length > 0) {
      result.push({
        userInputMessage: {
          ...message.userInputMessage!,
          userInputMessageContext: {
            ...message.userInputMessage!.userInputMessageContext,
            toolResults: filteredToolResults
          }
        }
      })
    } else {
      const stripped = stripInvalidToolResults(message)
      if (stripped) result.push(stripped)
    }
  }
  return result
}

// 确保工具调用有对应结果
function ensureValidToolUsesAndResults(messages: KiroHistoryMessage[]): KiroHistoryMessage[] {
  const result: KiroHistoryMessage[] = []
  
  for (let i = 0; i < messages.length; i++) {
    const message = messages[i]
    result.push(message)
    
    if (isAssistantResponseMessage(message) && hasToolUses(message)) {
      const nextMessage = i + 1 < messages.length ? messages[i + 1] : null
      const toolUses = message.assistantResponseMessage?.toolUses ?? []
      const toolUseIds = toolUses.map((tu, idx) => tu.toolUseId ?? `toolUse_${idx + 1}`)
      
      if (!nextMessage || !isUserInputMessage(nextMessage) || !hasToolResults(nextMessage)) {
        // 没有对应的工具结果，添加失败消息
        result.push(createFailedToolUseMessage(toolUseIds))
      } else if (!hasMatchingToolResults(
        message.assistantResponseMessage?.toolUses,
        nextMessage.userInputMessage?.userInputMessageContext?.toolResults
      ) && !messages.some((candidate, index) => (
        index !== i
        && isAssistantResponseMessage(candidate)
        && hasToolUses(candidate)
        && hasMatchingToolResults(candidate.assistantResponseMessage?.toolUses, nextMessage.userInputMessage?.userInputMessageContext?.toolResults)
      ))) {
        // 工具结果不匹配，添加失败消息
        const existingToolResults = nextMessage.userInputMessage?.userInputMessageContext?.toolResults ?? []
        const validToolUseIds = new Set(toolUseIds)
        const usedToolUseIds = new Set<string>()
        const completedToolResults = existingToolResults.filter(toolResult => {
          if (!toolResult.toolUseId || !validToolUseIds.has(toolResult.toolUseId) || usedToolUseIds.has(toolResult.toolUseId)) return false
          usedToolUseIds.add(toolResult.toolUseId)
          return true
        })
        for (const toolUseId of toolUseIds) {
          if (!usedToolUseIds.has(toolUseId)) completedToolResults.push(createFailedToolResult(toolUseId))
        }
        result.push({
          userInputMessage: {
            ...nextMessage.userInputMessage!,
            userInputMessageContext: {
              ...nextMessage.userInputMessage!.userInputMessageContext,
              toolResults: completedToolResults
            }
          }
        })
        i++
      }
    }
  }
  return result
}

// 移除空的 user 消息
function removeEmptyUserMessages(messages: KiroHistoryMessage[]): KiroHistoryMessage[] {
  if (messages.length <= 1) return messages
  
  const firstUserMessageIndex = messages.findIndex(isUserInputMessage)
  return messages.filter((message, index) => {
    if (isAssistantResponseMessage(message)) return true
    if (isUserInputMessage(message) && index === firstUserMessageIndex) return true
    if (isUserInputMessage(message)) {
      const hasContent = message.userInputMessage?.content?.trim() !== ''
      return hasContent || hasToolResults(message)
    }
    return true
  })
}

function validateConversation(messages: KiroHistoryMessage[]): string[] {
  const errors: string[] = []
  if (messages.length === 0 || !isUserInputMessage(messages[0])) {
    errors.push('STARTS_WITH_USER_MESSAGE:index=0')
  }
  if (messages.length === 0 || !isUserInputMessage(messages[messages.length - 1])) {
    errors.push(`ENDS_WITH_USER_MESSAGE:index=${Math.max(messages.length - 1, 0)}`)
  }
  for (let i = 1; i < messages.length; i++) {
    const previousMessage = messages[i - 1]
    const currentMessage = messages[i]
    if (isUserInputMessage(previousMessage) && isUserInputMessage(currentMessage)) {
      errors.push(`ALTERNATING_MESSAGES:index=${i}`)
      break
    }
    if (isAssistantResponseMessage(previousMessage) && isAssistantResponseMessage(currentMessage)) {
      errors.push(`ALTERNATING_MESSAGES:index=${i}`)
      break
    }
  }
  for (let i = 0; i < messages.length - 1; i++) {
    const message = messages[i]
    const nextMessage = messages[i + 1]
    if (isAssistantResponseMessage(message) && hasToolUses(message) && (!isUserInputMessage(nextMessage) || !hasMatchingToolResults(message.assistantResponseMessage?.toolUses, nextMessage?.userInputMessage?.userInputMessageContext?.toolResults))) {
      errors.push(`TOOL_USES_AND_RESULTS:index=${i + 1}`)
      break
    }
    if (isAssistantResponseMessage(message) && !hasToolUses(message) && isUserInputMessage(nextMessage) && hasToolResults(nextMessage)) {
      errors.push(`TOOL_RESULTS_AND_NO_USES:index=${i}`)
      break
    }
  }
  for (let i = 1; i < messages.length; i++) {
    const previousMessage = messages[i - 1]
    const currentMessage = messages[i]
    if (!isAssistantResponseMessage(previousMessage) || !hasToolUses(previousMessage) || !isUserInputMessage(currentMessage) || !hasToolResults(currentMessage)) continue
    const toolUseIds = new Set((previousMessage.assistantResponseMessage?.toolUses ?? []).map(toolUse => toolUse.toolUseId).filter(Boolean))
    const seenToolUseIds = new Set<string>()
    const hasInvalidToolResult = (currentMessage.userInputMessage?.userInputMessageContext?.toolResults ?? []).some(toolResult => {
      if (!toolResult.toolUseId || !toolUseIds.has(toolResult.toolUseId) || seenToolUseIds.has(toolResult.toolUseId)) return true
      seenToolUseIds.add(toolResult.toolUseId)
      return false
    })
    if (hasInvalidToolResult) {
      errors.push(`TOOL_RESULTS_ORPHAN_IDS:index=${i}`)
      break
    }
  }
  for (let i = 0; i < messages.length; i++) {
    const message = messages[i]
    if (isUserInputMessage(message) && !message.userInputMessage?.content?.trim() && !hasToolResults(message)) {
      errors.push(`NON_EMPTY_USER_MESSAGE:index=${i}`)
      break
    }
  }
  return errors
}

function getToolNames(tools: KiroToolWrapper[]): Set<string> {
  return new Set(tools.flatMap(tool => 'toolSpecification' in tool ? [tool.toolSpecification.name] : []))
}

function stringifyToolInput(input: unknown): string {
  if (input === undefined) return ''
  if (typeof input === 'string') return input
  try {
    return JSON.stringify(input)
  } catch {
    return String(input)
  }
}

function flattenContent(content: string, extra: string): string {
  const trimmedContent = content.trim()
  if (!trimmedContent) return extra
  if (!extra) return trimmedContent
  return `${trimmedContent}\n\n${extra}`
}

function formatToolUses(toolUses: KiroToolUse[]): string {
  return toolUses.map(toolUse => [
    `<tool_use id="${toolUse.toolUseId}" name="${toolUse.name}">`,
    stringifyToolInput(toolUse.input),
    '</tool_use>'
  ].filter(Boolean).join('\n')).join('\n\n')
}

function formatToolResults(toolResults: KiroToolResult[]): string {
  return toolResults.map(toolResult => [
    `<tool_result id="${toolResult.toolUseId}" status="${toolResult.status}">`,
    toolResult.content.map(content => content.text).join('\n'),
    '</tool_result>'
  ].filter(Boolean).join('\n')).join('\n\n')
}

function normalizeToolHistory(messages: KiroHistoryMessage[], tools: KiroToolWrapper[]): KiroHistoryMessage[] {
  const toolNames = getToolNames(tools)
  const hasUnknownToolUse = messages.some(message => (
    message.assistantResponseMessage?.toolUses?.some(toolUse => !toolNames.has(toolUse.name)) ?? false
  ))
  if (!hasUnknownToolUse) return messages

  return messages.map(message => {
    if (message.assistantResponseMessage?.toolUses?.length) {
      return {
        assistantResponseMessage: {
          ...message.assistantResponseMessage,
          content: flattenContent(message.assistantResponseMessage.content, formatToolUses(message.assistantResponseMessage.toolUses)),
          toolUses: undefined
        }
      }
    }
    if (message.userInputMessage?.userInputMessageContext?.toolResults?.length) {
      return {
        userInputMessage: {
          ...message.userInputMessage,
          content: flattenContent(message.userInputMessage.content, formatToolResults(message.userInputMessage.userInputMessageContext.toolResults)),
          userInputMessageContext: {
            ...message.userInputMessage.userInputMessageContext,
            toolResults: undefined
          }
        }
      }
    }
    return message
  })
}

// 清理会话消息（参考 Kiro 官方实现）
function sanitizeConversation(messages: KiroHistoryMessage[]): KiroHistoryMessage[] {
  let sanitized = [...messages]
  sanitized = ensureStartsWithUserMessage(sanitized)
  sanitized = removeEmptyUserMessages(sanitized)
  sanitized = relocateToolResultMessages(sanitized)
  sanitized = removeInvalidToolResultMessages(sanitized)
  sanitized = ensureValidToolUsesAndResults(sanitized)
  sanitized = ensureAlternatingMessages(sanitized)
  sanitized = ensureEndsWithUserMessage(sanitized)
  const validationErrors = validateConversation(sanitized)
  if (validationErrors.length > 0) {
    throw new Error(`Invalid Kiro conversation after sanitization: ${validationErrors.join(', ')}`)
  }
  return sanitized
}

// 按 token 估算成对裁剪 history 最旧消息 (避免后端 CONTENT_LENGTH_EXCEEDS_THRESHOLD)
// 切点保证不破坏 toolUse↔toolResult 配对：assistant(toolUse) 必须连同后续 user(toolResult) 一起裁
// 裁剪后用 ensureStartsWithUserMessage 兜底重新规范化
function trimHistoryByTokens(payload: KiroPayload, maxTokens: number): { trimmed: number; finalTokens: number; iterations: number } {
  let history = payload.conversationState.history
  if (!history || history.length === 0) {
    return { trimmed: 0, finalTokens: estimatePayloadTokens(payload), iterations: 0 }
  }

  let totalTrimmed = 0
  let iterations = 0
  let currentTokens = estimatePayloadTokens(payload)
  const MAX_ITERATIONS = 100 // 防止极端情况死循环

  while (currentTokens > maxTokens && history.length >= 4 && iterations < MAX_ITERATIONS) {
    iterations++
    // 计算安全切点：从 index 0 开始至少裁掉 1 组 (user+assistant)，并连带 toolUse/toolResult 配对
    let cutAt = 0
    while (cutAt < history.length - 2) {
      const msg = history[cutAt]
      // assistant(toolUse) → 下一条 user(toolResult) 必须一起裁，避免配对断裂
      if (isAssistantResponseMessage(msg) && hasToolUses(msg)) {
        cutAt += 2
      } else {
        cutAt += 1
      }
      if (cutAt >= 2) break
    }

    if (cutAt === 0) break // 无法继续裁剪

    history = history.slice(cutAt)
    totalTrimmed += cutAt

    // 裁剪后 history 可能以 assistant 起头 → 补 HELLO 重新规范
    history = ensureStartsWithUserMessage(history)
    payload.conversationState.history = history
    currentTokens = estimatePayloadTokens(payload)
  }

  return { trimmed: totalTrimmed, finalTokens: currentTokens, iterations }
}

// ============= 构建 Kiro API 请求负载（参考 Kiro 官方实现）=============

export function buildKiroPayload(
  content: string,
  modelId: string,
  origin: string,
  history: KiroHistoryMessage[] = [],
  tools: KiroToolWrapper[] = [],
  toolResults: KiroToolResult[] = [],
  images: KiroImage[] = [],
  profileArn?: string,
  inferenceConfig?: { maxTokens?: number; temperature?: number; topP?: number },
  messageOptions?: { cachePoint?: KiroCachePoint | undefined; clientCacheConfig?: unknown; documents?: KiroDocument[]; conversationId?: string; context?: KiroRequestContext },
  additionalModelRequestFields?: Record<string, unknown>
): KiroPayload {
  // 构建当前消息
  const finalContent = content.trim() || (toolResults.length > 0 ? '' : 'Continue')
  
  const currentUserInputMessage: KiroUserInputMessage = {
    content: finalContent,
    modelId,
    origin
  }

  if (images.length > 0) {
    currentUserInputMessage.images = images
  }

  if (messageOptions?.documents?.length) {
    currentUserInputMessage.documents = messageOptions.documents
  }

  if (messageOptions?.cachePoint) {
    currentUserInputMessage.cachePoint = messageOptions.cachePoint
  }

  if (messageOptions?.clientCacheConfig !== undefined) {
    currentUserInputMessage.clientCacheConfig = messageOptions.clientCacheConfig
  }

  // 构建 userInputMessageContext（包含 tools 和 toolResults）
  // 注意：tools 只放在最后一条消息（currentMessage）的 userInputMessageContext 中
  if (tools.length > 0 || toolResults.length > 0) {
    currentUserInputMessage.userInputMessageContext = {}
    if (tools.length > 0) {
      currentUserInputMessage.userInputMessageContext.tools = tools
    }
    if (toolResults.length > 0) {
      currentUserInputMessage.userInputMessageContext.toolResults = toolResults
    }
  }

  if (messageOptions?.context) {
    currentUserInputMessage.userInputMessageContext = {
      ...currentUserInputMessage.userInputMessageContext,
      ...(messageOptions.context.editorState !== undefined ? { editorState: messageOptions.context.editorState } : {}),
      ...(messageOptions.context.shellState !== undefined ? { shellState: messageOptions.context.shellState } : {}),
      ...(messageOptions.context.gitState !== undefined ? { gitState: messageOptions.context.gitState } : {}),
      ...(messageOptions.context.envState !== undefined ? { envState: messageOptions.context.envState } : {}),
      ...(messageOptions.context.additionalContext !== undefined ? { additionalContext: messageOptions.context.additionalContext } : {})
    }
  }

  // 构建 currentMessage
  const currentMessage: KiroHistoryMessage = {
    userInputMessage: currentUserInputMessage
  }

  // 清理并准备所有消息（history + currentMessage）
  const allMessages = [...history, currentMessage]
  const sanitizedMessages = sanitizeConversation(normalizeToolHistory(allMessages, tools))
  
  // 分离 history 和 currentMessage
  // currentMessage 是最后一条消息，history 是其余的
  const sanitizedHistory = sanitizedMessages.slice(0, -1)
  let finalCurrentMessage = sanitizedMessages.at(-1)!

  // 确保 currentMessage 是 user 消息（sanitizeConversation 保证以 user 消息结束）
  // 并确保包含 tools
  if (!finalCurrentMessage.userInputMessage) {
    // 如果清理后最后一条不是 user 消息，创建一个新的
    finalCurrentMessage = {
      userInputMessage: {
        content: finalContent || 'Continue',
        modelId,
        origin
      }
    }
  }
  
  finalCurrentMessage.userInputMessage!.userInputMessageContext = {
    ...finalCurrentMessage.userInputMessage!.userInputMessageContext,
    ...(tools.length > 0 ? { tools } : {})
  }

  // conversationId 稳定化：同一会话的多轮请求复用同一个 conversationId
  // 优先级：客户端显式 conversation_id → sessionHint（header 提取）→ history fingerprint → 新 UUID
  const conversationId = resolveConversationId(history, messageOptions?.conversationId)
  const payload: KiroPayload = {
    conversationState: {
      agentContinuationId: uuidv4(),
      agentTaskType: 'vibe',
      chatTriggerType: 'MANUAL',
      conversationId,
      currentMessage: {
        userInputMessage: finalCurrentMessage.userInputMessage!
      },
      history: sanitizedHistory.length > 0 ? sanitizedHistory : undefined
    }
  }

  if (profileArn !== undefined) {
    payload.profileArn = profileArn
  }

  if (inferenceConfig && (inferenceConfig.maxTokens || inferenceConfig.temperature !== undefined || inferenceConfig.topP !== undefined)) {
    payload.inferenceConfig = {}
    if (inferenceConfig.maxTokens) {
      payload.inferenceConfig.maxTokens = inferenceConfig.maxTokens
    }
    if (inferenceConfig.temperature !== undefined) {
      payload.inferenceConfig.temperature = inferenceConfig.temperature
    }
    if (inferenceConfig.topP !== undefined) {
      payload.inferenceConfig.topP = inferenceConfig.topP
    }
  }

  // additionalModelRequestFields（thinking 等模型级参数）
  if (additionalModelRequestFields && Object.keys(additionalModelRequestFields).length > 0) {
    payload.additionalModelRequestFields = additionalModelRequestFields
  }

  // ====== 第一阶段：按 token 估算成对裁剪旧 history ======
  // 避免 Kiro 后端 CONTENT_LENGTH_EXCEEDS_THRESHOLD（token 维度的拒绝）
  // 注意：byte size 充足但 token 超限是常见情况（长对话+大量小消息）
  // effectiveLimit 按模型 context window 自动算：ctx - tokenBufferReserve（开关启用时，默认 20K）
  // 例：sonnet-4.5 (200K) → 180K, sonnet-4.5 with 1M beta → 980K
  // 开关关闭时完全跳过，超出 context window 由 Kiro 后端原样返回错误
  if (enableTokenBufferReserve) {
    const effectiveTokenLimit = getEffectiveTokenLimit(modelId)
    const tokenTrimResult = trimHistoryByTokens(payload, effectiveTokenLimit)
    if (tokenTrimResult.trimmed > 0) {
      const modelCtx = getModelContextLength(modelId)
      console.log(`[KiroPayload] Trimmed ${tokenTrimResult.trimmed} oldest history messages by token estimate (≈${tokenTrimResult.finalTokens.toLocaleString()} / ${effectiveTokenLimit.toLocaleString()} tokens [model ctx ${modelCtx.toLocaleString()} - buffer ${tokenBufferReserve.toLocaleString()}], ${tokenTrimResult.iterations} iter)`)
    }
  }

  // ====== 第二阶段：按 byte 截断 tool result 内容 ======
  // 避免 HTTP body 过大被 Kiro 网关拒绝
  // 用户可在高级设置中调整限制值（默认 1536KB = 1.5MB）
  const PAYLOAD_SIZE_LIMIT = (payloadSizeLimitKB || 1536) * 1024
  const TOOL_RESULT_TRUNCATE_LENGTH = 4000
  let initialPayloadSize = JSON.stringify(payload).length
  if (initialPayloadSize > PAYLOAD_SIZE_LIMIT && payload.conversationState.history) {
    const historyMessages = payload.conversationState.history
    let truncatedCount = 0
    for (const message of historyMessages) {
      if (initialPayloadSize <= PAYLOAD_SIZE_LIMIT) break
      const userToolResults = message.userInputMessage?.userInputMessageContext?.toolResults
      if (!userToolResults) continue
      for (const toolResult of userToolResults) {
        if (initialPayloadSize <= PAYLOAD_SIZE_LIMIT) break
        if (!toolResult.content) continue
        for (const contentItem of toolResult.content) {
          if (initialPayloadSize <= PAYLOAD_SIZE_LIMIT) break
          if (contentItem.text && contentItem.text.length > TOOL_RESULT_TRUNCATE_LENGTH) {
            const originalLen = contentItem.text.length
            contentItem.text = `${contentItem.text.slice(0, TOOL_RESULT_TRUNCATE_LENGTH)}\n\n[Truncated by proxy: original ${originalLen} chars]`
            truncatedCount++
            initialPayloadSize = JSON.stringify(payload).length
          }
        }
      }
    }
    if (truncatedCount > 0) {
      console.log(`[KiroPayload] Truncated ${truncatedCount} large tool results to fit payload size limit (final size: ${initialPayloadSize} bytes)`)
    }
  }

  // 调试日志
  console.log(`[KiroPayload] Built payload (native history mode):`, {
    contentLength: finalContent.length,
    originalHistoryLength: history.length,
    sanitizedHistoryLength: sanitizedHistory.length,
    toolsCount: tools.length,
    toolResultsCount: toolResults.length,
    hasProfileArn: payload.profileArn !== undefined,
    hasThinking: !!additionalModelRequestFields?.thinking,
    payloadSize: initialPayloadSize
  })

  return payload
}

// conversationId 稳定化：同一会话的多轮请求复用同一个 conversationId
// 策略：sessionHint（由 proxyServer 从 header/body 提取）→ 稳定映射到固定 conversationId
// 无 sessionHint 时用 history fingerprint 兜底
const conversationCache = new Map<string, { id: string; timestamp: number }>()
const CONVERSATION_CACHE_TTL = 2 * 60 * 60 * 1000 // 2 小时
const CONVERSATION_CACHE_MAX = 1000

function resolveConversationId(history: KiroHistoryMessage[], sessionHint?: string): string {
  // sessionHint 已包含 API Key hash 前缀（由 proxyServer 注入），天然隔离不同用户
  const key = sessionHint || fingerprintFromHistory(history)
  if (!key) return uuidv4()

  const now = Date.now()
  const cached = conversationCache.get(key)
  if (cached) {
    cached.timestamp = now
    return cached.id
  }

  // 清理过期缓存
  if (conversationCache.size > CONVERSATION_CACHE_MAX) {
    const cutoff = now - CONVERSATION_CACHE_TTL
    for (const [k, v] of conversationCache) {
      if (v.timestamp < cutoff) conversationCache.delete(k)
    }
  }

  const id = uuidv4()
  conversationCache.set(key, { id, timestamp: now })
  return id
}

function fingerprintFromHistory(history: KiroHistoryMessage[]): string | undefined {
  if (history.length === 0) return undefined
  const fp = history.slice(0, 2).map(msg =>
    `${msg.userInputMessage?.content || ''}|${msg.assistantResponseMessage?.content || ''}`
  ).join('::')
  const crypto = require('crypto')
  return crypto.createHash('sha256').update(fp).digest('hex').slice(0, 32)
}

// 清除所有内存缓存
export function clearAllCaches(): { conversation: number; model: number } {
  const conversationCount = conversationCache.size
  const modelCount = codeWhispererModelCache.size
  conversationCache.clear()
  codeWhispererModelCache.clear()
  return { conversation: conversationCount, model: modelCount }
}

// machineId 稳定生成缓存（用于无绑定 machineId 且 K-Proxy 不可用时的兆底）
const fallbackMachineIds = new Map<string, string>()

function generateStableMachineId(accountId: string): string {
  const cached = fallbackMachineIds.get(accountId)
  if (cached) return cached
  const crypto = require('crypto')
  const hash = crypto.createHash('sha256').update(`kiro-device-${accountId}`).digest('hex')
  fallbackMachineIds.set(accountId, hash)
  return hash
}

// 获取账号绑定的 Machine ID（保证永远不为空）
function getAccountMachineId(accountId: string, accountMachineId?: string): string {
  if (accountMachineId) return accountMachineId
  const kproxyService = getKProxyService()
  if (kproxyService) {
    const deviceId = kproxyService.getDeviceIdForAccount(accountId)
    if (deviceId) return deviceId
  }
  return generateStableMachineId(accountId)
}

// 获取认证方式对应的请求头
function getAuthHeaders(account: ProxyAccount, _endpoint: typeof KIRO_ENDPOINTS[0]): Record<string, string> {
  const isIDC = account.authMethod?.toLowerCase() === 'idc'
  const machineId = getAccountMachineId(account.id, account.machineId)
  const agentMode = isIDC ? AGENT_MODE_VIBE : AGENT_MODE_SPEC
  
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    'x-amzn-kiro-agent-mode': agentMode,
    'x-amz-user-agent': isIDC ? KIRO_CLI_AMZ_USER_AGENT : getKiroAmzUserAgent(machineId),
    'user-agent': isIDC ? KIRO_CLI_USER_AGENT : getKiroUserAgent(machineId),
    'amz-sdk-invocation-id': uuidv4(),
    'amz-sdk-request': 'attempt=1; max=3',
    'Authorization': `Bearer ${account.accessToken}`
  }
  return headers
}

// 获取排序后的端点列表（根据首选端点配置）
function getSortedEndpoints(preferredEndpoint?: 'codewhisperer' | 'amazonq' | 'amazonq-cli'): typeof KIRO_ENDPOINTS {
  if (!preferredEndpoint) return KIRO_ENDPOINTS.filter(ep => ep.name !== 'AmazonQCLI')
  
  // AmazonQ CLI 模式：只用这一个端点，失败不回退
  if (preferredEndpoint === 'amazonq-cli') {
    return KIRO_ENDPOINTS.filter(ep => ep.name === 'AmazonQCLI')
  }
  
  const preferredName = preferredEndpoint === 'codewhisperer' ? 'CodeWhisperer' : 'AmazonQ'
  
  const sorted = KIRO_ENDPOINTS.filter(ep => ep.name !== 'AmazonQCLI')
  sorted.sort((a, b) => {
    if (a.name === preferredName) return -1
    if (b.name === preferredName) return 1
    return 0
  })
  
  return sorted
}

function getAbortError(signal?: AbortSignal): Error {
  if (signal?.reason instanceof Error) return signal.reason
  if (signal?.reason) return new Error(String(signal.reason))
  return new Error('Request aborted')
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw getAbortError(signal)
}

// 调用 Kiro API（流式）
export async function callKiroApiStream(
  account: ProxyAccount,
  payload: KiroPayload,
  onChunk: (text: string, toolUse?: KiroToolUse, isThinking?: boolean, reasoningSignature?: string, redactedContent?: string) => void,
  onComplete: (usage: KiroUsage) => void,
  onError: (error: Error) => void,
  signal?: AbortSignal,
  preferredEndpoint?: 'codewhisperer' | 'amazonq' | 'amazonq-cli'
): Promise<void> {
  const endpoints = getSortedEndpoints(preferredEndpoint)
  let lastError: Error | null = null

  for (const endpoint of endpoints) {
    try {
      throwIfAborted(signal)
      const requestPayload = clonePayload(payload)
      const reqProfileArn = resolveProfileArn(account)
      if (reqProfileArn) requestPayload.profileArn = reqProfileArn
      else delete requestPayload.profileArn
      const requestedModelId = getPayloadModelId(requestPayload)
      if (endpoint.name === 'CodeWhisperer') {
        applyPayloadModelId(requestPayload, await resolveCodeWhispererModelId(account, requestedModelId, signal))
      }

      applyPayloadOrigin(requestPayload, endpoint.origin)

      // AmazonQCLI 端点不支持 agentContinuationId/agentTaskType
      if (endpoint.name === 'AmazonQCLI') {
        delete (requestPayload.conversationState as unknown as Record<string, unknown>).agentContinuationId
        delete (requestPayload.conversationState as unknown as Record<string, unknown>).agentTaskType
      }

      const payloadStr = JSON.stringify(requestPayload)
      const headers = getAuthHeaders(account, endpoint)
      const currentUserInput = requestPayload.conversationState.currentMessage.userInputMessage
      const historyMessages = requestPayload.conversationState.history ?? []
      const historyToolUseCount = historyMessages.reduce((count, message) => count + (message.assistantResponseMessage?.toolUses?.length ?? 0), 0)
      const historyToolResultCount = historyMessages.reduce((count, message) => count + (message.userInputMessage?.userInputMessageContext?.toolResults?.length ?? 0), 0)
      console.log(`[KiroAPI] Request to ${endpoint.name}:`)
      console.log(`[KiroAPI]   - Content length: ${currentUserInput?.content?.length || 0}`)
      console.log(`[KiroAPI]   - Tools count: ${currentUserInput?.userInputMessageContext?.tools?.length || 0}`)
      console.log(`[KiroAPI]   - Current tool results: ${currentUserInput?.userInputMessageContext?.toolResults?.length || 0}`)
      console.log(`[KiroAPI]   - History messages: ${historyMessages.length}`)
      console.log(`[KiroAPI]   - History tool uses/results: ${historyToolUseCount}/${historyToolResultCount}`)
      console.log(`[KiroAPI]   - Model ID: ${currentUserInput?.modelId || 'default'}`)
      console.log(`[KiroAPI]   - Has profileArn: ${requestPayload.profileArn !== undefined}`)
      console.log(`[KiroAPI]   - Agent mode: ${headers['x-amzn-kiro-agent-mode']}`)
      console.log(`[KiroAPI]   - Payload size: ${payloadStr.length} bytes`)
      
      const agent = getNetworkAgent(account)
      if (agent) proxyLogger.debug('KiroAPI', `Stream request via proxy to ${endpoint.name}`)
      const response = agent
        ? await undiciFetch(endpoint.url, { method: 'POST', headers, body: payloadStr, signal, dispatcher: agent } as UndiciRequestInit) as unknown as Response
        : await fetch(endpoint.url, { method: 'POST', headers, body: payloadStr, signal })

      if (response.status === 429) {
        console.log(`[KiroAPI] Endpoint ${endpoint.name} quota exhausted, trying next...`)
        lastError = new Error(`Quota exhausted on ${endpoint.name}`)
        continue
      }

      if (response.status === 401 || response.status === 403) {
        throwIfAborted(signal)
        const body = await response.text()
        throwIfAborted(signal)
        throw new Error(`Auth error ${response.status}: ${body}`)
      }

      if (!response.ok) {
        throwIfAborted(signal)
        const body = await response.text()
        throwIfAborted(signal)
        throw new Error(`API error ${response.status}: ${body}`)
      }

      // 解析 Event Stream
      // 传入 modelId + payloadStr 用于精确 token 计算（contextUsage 反推 + tiktoken）
      const inputChars = payloadStr.length
      await parseEventStream(response.body!, onChunk, onComplete, onError, inputChars, signal, requestedModelId, payloadStr)
      return
    } catch (error) {
      if (signal?.aborted) {
        onError(getAbortError(signal))
        return
      }
      lastError = error as Error
      console.error(`[KiroAPI] Endpoint ${endpoint.name} failed:`, error)
      
      // 如果是认证错误，不继续尝试其他端点
      if ((error as Error).message.includes('Auth error')) {
        onError(error as Error)
        return
      }
    }
  }

  if (lastError) {
    onError(lastError)
  }
}

// 从 headers 中提取 event type
function extractEventType(headers: Uint8Array): string {
  let offset = 0
  while (offset < headers.length) {
    if (offset >= headers.length) break
    const nameLen = headers[offset]
    offset++
    if (offset + nameLen > headers.length) break
    const name = new TextDecoder().decode(headers.slice(offset, offset + nameLen))
    offset += nameLen
    if (offset >= headers.length) break
    const valueType = headers[offset]
    offset++
    
    if (valueType === 7) { // String type
      if (offset + 2 > headers.length) break
      const valueLen = (headers[offset] << 8) | headers[offset + 1]
      offset += 2
      if (offset + valueLen > headers.length) break
      const value = new TextDecoder().decode(headers.slice(offset, offset + valueLen))
      offset += valueLen
      if (name === ':event-type') {
        return value
      }
      continue
    }
    
    // Skip other value types
    const skipSizes: Record<number, number> = { 0: 0, 1: 0, 2: 1, 3: 2, 4: 4, 5: 8, 8: 8, 9: 16 }
    if (valueType === 6) {
      if (offset + 2 > headers.length) break
      const len = (headers[offset] << 8) | headers[offset + 1]
      offset += 2 + len
    } else if (skipSizes[valueType] !== undefined) {
      offset += skipSizes[valueType]
    } else {
      break
    }
  }
  return ''
}

// Tool Use 状态跟踪
interface ToolUseState {
  toolUseId: string
  name: string
  inputBuffer: string
}

// Token 估算（被 promptCacheTracker 等模块使用，用于 cache 块大小判定）
// 优先使用 tiktoken cl100k_base 精确计算（±5%），失败时自动降级到字符系数（±15%）
export function estimateTokens(text: string): number {
  return countTokens(text)
}

// 解析 AWS Event Stream 二进制格式
async function parseEventStream(
  body: ReadableStream<Uint8Array>,
  onChunk: (text: string, toolUse?: KiroToolUse, isThinking?: boolean, reasoningSignature?: string, redactedContent?: string) => void,
  onComplete: (usage: KiroUsage) => void,
  onError: (error: Error) => void,
  inputChars: number = 0,  // 输入字符长度（兜底估算用）
  signal?: AbortSignal,
  modelId?: string,        // 模型 ID，用于 contextUsagePercentage 反推 inputTokens
  payloadStr?: string      // 请求 payload JSON 字符串，用于 tiktoken 精确计算
): Promise<void> {
  const reader = body.getReader()
  const abort = () => {
    reader.cancel(getAbortError(signal)).catch(() => undefined)
  }
  let buffer = new Uint8Array(0)
  let usage = { 
    inputTokens: 0, 
    outputTokens: 0, 
    credits: 0,
    cacheReadTokens: 0,
    cacheWriteTokens: 0,
    reasoningTokens: 0
  }
  
  // 累积输出文本长度，用于估算 tokens
  let totalOutputChars = 0
  // 累积输出文本内容，用于 tiktoken 精确计算 output tokens
  let collectedOutputText = ''
  // 是否已拿到 Kiro 真实 tokenUsage（最高优先级，锁定后不再被 contextUsage/tiktoken 覆盖）
  let hasRealTokenUsage = false
  
  // 流式事件聚合计数（logStreamEvents 开启时，结束后输出摘要而非逐条输出）
  const streamEventCounts: Record<string, number> = {}
  
  // 初始化 input tokens 估算（优先级链路：tokenUsage > contextUsage 反推 > tiktoken > 字符系数）
  // 这里只是兜底初值，后续真实事件会覆盖
  if (payloadStr) {
    // 用 tiktoken cl100k_base 精确计算（±5%）
    usage.inputTokens = countTokens(payloadStr)
  } else if (inputChars > 0) {
    // 字符系数兜底（针对 payload JSON 经验值 0.42）
    usage.inputTokens = Math.max(1, Math.round(inputChars * 0.42))
  }
  
  // Tool use 状态跟踪 - 用于累积输入片段
  let currentToolUse: ToolUseState | null = null
  const processedIds = new Set<string>()

  try {
    throwIfAborted(signal)
    signal?.addEventListener('abort', abort, { once: true })
    while (true) {
      throwIfAborted(signal)
      const { done, value } = await reader.read()
      throwIfAborted(signal)
      
      if (done) {
        break
      }

      // 合并缓冲区
      const newBuffer = new Uint8Array(buffer.length + value.length)
      newBuffer.set(buffer)
      newBuffer.set(value, buffer.length)
      buffer = newBuffer

      // 尝试解析消息
      while (buffer.length >= 16) {
        // AWS Event Stream 格式：
        // - 4 bytes: total length
        // - 4 bytes: headers length
        // - 4 bytes: prelude CRC
        // - headers
        // - payload
        // - 4 bytes: message CRC

        const totalLength = new DataView(buffer.buffer, buffer.byteOffset).getUint32(0, false)
        
        if (buffer.length < totalLength) {
          break // 等待更多数据
        }

        const headersLength = new DataView(buffer.buffer, buffer.byteOffset).getUint32(4, false)
        
        // 从 headers 中提取 event type
        const headersStart = 12
        const headersEnd = 12 + headersLength
        const eventType = extractEventType(buffer.slice(headersStart, headersEnd))
        
        // 提取 payload
        const payloadStart = 12 + headersLength
        const payloadEnd = totalLength - 4 // 减去 message CRC
        
        if (payloadStart < payloadEnd) {
          const payloadBytes = buffer.slice(payloadStart, payloadEnd)
          
          try {
            const payloadText = new TextDecoder().decode(payloadBytes)
            const event = JSON.parse(payloadText)
            
            // 根据 event type 处理不同类型的事件
            if (eventType === 'assistantResponseEvent' || event.assistantResponseEvent) {
              const assistantResp = event.assistantResponseEvent || event
              const content = assistantResp.content
              if (content) {
                onChunk(content)
                // 累积输出字符长度（兜底估算用）
                totalOutputChars += content.length
                // 累积输出文本（tiktoken 精确计算用）
                collectedOutputText += content
              }
            }

            // AmazonQ CLI 协议特有：CodeEvent (代码片段流式输出)
            // 来自 amzn_qdeveloper_streaming_client 的 ChatResponseStream::CodeEvent { content: String }
            // CodeWhisperer/AmazonQ 端点用 AssistantResponseEvent 包代码，CLI 端点单独用 CodeEvent
            if (eventType === 'codeEvent' || event.codeEvent) {
              const codeResp = event.codeEvent || event
              const content = codeResp.content
              if (content) {
                onChunk(content)
                totalOutputChars += content.length
                collectedOutputText += content
              }
            }
            
            if (eventType === 'toolUseEvent' || event.toolUseEvent) {
              const toolUseData = event.toolUseEvent || event
              const toolUseId = toolUseData.toolUseId
              const toolName = toolUseData.name
              const isStop = toolUseData.stop === true
              
              // 获取输入 - 可能是字符串片段或完整对象
              let inputFragment = ''
              let inputObj: Record<string, unknown> | null = null
              if (typeof toolUseData.input === 'string') {
                inputFragment = toolUseData.input
              } else if (typeof toolUseData.input === 'object' && toolUseData.input !== null) {
                inputObj = toolUseData.input
              }
              
              // 新的 tool use 开始
              if (toolUseId && toolName) {
                if (currentToolUse && currentToolUse.toolUseId !== toolUseId) {
                  // 前一个 tool use 被中断，完成它
                  if (!processedIds.has(currentToolUse.toolUseId)) {
                    let finalInput: Record<string, unknown> = {}
                    try {
                      if (currentToolUse.inputBuffer) {
                        finalInput = JSON.parse(currentToolUse.inputBuffer)
                      }
                    } catch { /* 忽略解析错误 */ }
                    onChunk('', {
                      toolUseId: currentToolUse.toolUseId,
                      name: currentToolUse.name,
                      input: finalInput
                    })
                    totalOutputChars += currentToolUse.name.length + currentToolUse.inputBuffer.length
                    processedIds.add(currentToolUse.toolUseId)
                  }
                  currentToolUse = null
                }
                
                if (!currentToolUse) {
                  if (processedIds.has(toolUseId)) {
                    // 跳过重复的 tool use
                  } else {
                    currentToolUse = {
                      toolUseId,
                      name: toolName,
                      inputBuffer: ''
                    }
                  }
                }
              }
              
              // 累积输入片段
              if (currentToolUse && inputFragment) {
                currentToolUse.inputBuffer += inputFragment
              }
              
              // 如果直接提供了完整输入对象
              if (currentToolUse && inputObj) {
                currentToolUse.inputBuffer = JSON.stringify(inputObj)
              }
              
              // Tool use 完成
              if (isStop && currentToolUse) {
                let finalInput: Record<string, unknown> = {}
                let parseError = false
                try {
                  if (currentToolUse.inputBuffer) {
                    if (logStreamEvents) proxyLogger.debug('Kiro', 'Tool input buffer: ' + currentToolUse.inputBuffer.substring(0, 200))
                    finalInput = JSON.parse(currentToolUse.inputBuffer)
                    if (logStreamEvents) proxyLogger.debug('Kiro', 'Parsed tool input: ' + JSON.stringify(finalInput).substring(0, 200))
                  }
                } catch (e) {
                  parseError = true
                  console.error('[Kiro] Failed to parse tool input:', e, 'Buffer:', currentToolUse.inputBuffer?.substring(0, 100))
                  // 当 JSON 解析失败时，创建一个包含错误信息的 input
                  // 这样客户端可以看到工具调用失败的原因
                  finalInput = {
                    _error: 'Tool input truncated by Kiro API (output token limit exceeded)',
                    _partialInput: currentToolUse.inputBuffer?.substring(0, 500) || ''
                  }
                }
                
                // 只有在成功解析或有错误信息时才发送
                onChunk('', {
                  toolUseId: currentToolUse.toolUseId,
                  name: currentToolUse.name,
                  input: finalInput
                })
                totalOutputChars += currentToolUse.name.length + currentToolUse.inputBuffer.length
                
                // 如果解析失败，额外发送一条文本消息告知用户
                if (parseError) {
                  onChunk(`\n\n⚠️ Tool "${currentToolUse.name}" input was truncated by Kiro API. The output may be incomplete due to token limits.`)
                }
                
                processedIds.add(currentToolUse.toolUseId)
                currentToolUse = null
              }
            }
            
            // 处理 messageMetadataEvent - 包含 token 使用量
            if (eventType === 'messageMetadataEvent' || eventType === 'metadataEvent' || event.messageMetadataEvent || event.metadataEvent) {
              const metadata = event.messageMetadataEvent || event.metadataEvent || event
              proxyLogger.info('Kiro', 'messageMetadataEvent', metadata)
              
              // 检查 tokenUsage 对象
              if (metadata.tokenUsage) {
                const tokenUsage = metadata.tokenUsage
                proxyLogger.info('Kiro', 'tokenUsage', tokenUsage)
                // 计算 inputTokens = uncachedInputTokens + cacheReadInputTokens + cacheWriteInputTokens
                const uncached = tokenUsage.uncachedInputTokens || 0
                const cacheRead = tokenUsage.cacheReadInputTokens || 0
                const cacheWrite = tokenUsage.cacheWriteInputTokens || 0
                const calculatedInput = uncached + cacheRead + cacheWrite
                
                if (calculatedInput > 0) {
                  usage.inputTokens = calculatedInput
                  hasRealTokenUsage = true  // 真实值，锁定不再被 contextUsage/tiktoken 覆盖
                }
                if (tokenUsage.outputTokens) usage.outputTokens = tokenUsage.outputTokens
                if (tokenUsage.totalTokens) {
                  // 如果有 totalTokens，用它来推算
                  if (usage.inputTokens === 0 && usage.outputTokens > 0) {
                    usage.inputTokens = tokenUsage.totalTokens - usage.outputTokens
                    hasRealTokenUsage = true
                  }
                }
                
                // 保存 cache tokens
                usage.cacheReadTokens = cacheRead
                usage.cacheWriteTokens = cacheWrite
                
                // 记录上下文使用百分比
                if (tokenUsage.contextUsagePercentage !== undefined) {
                  proxyLogger.info('Kiro', 'Context usage: ' + tokenUsage.contextUsagePercentage.toFixed(2) + '%')
                }
                
                // 详细的 token 分解日志
                proxyLogger.info('Kiro', 'Token breakdown', {
                  uncached,
                  cacheRead,
                  cacheWrite,
                  inputTotal: calculatedInput,
                  output: tokenUsage.outputTokens || 0,
                  total: tokenUsage.totalTokens || 0,
                  contextUsage: tokenUsage.contextUsagePercentage ? `${tokenUsage.contextUsagePercentage.toFixed(2)}%` : 'N/A'
                })
              }
              
              // 直接在 metadata 中的 tokens
              if (metadata.inputTokens) {
                usage.inputTokens = metadata.inputTokens
                hasRealTokenUsage = true
              }
              if (metadata.outputTokens) usage.outputTokens = metadata.outputTokens
            }
            
            if (logStreamEvents) {
              // 聚合流式事件（不逐条输出，在 onComplete 时输出摘要）
              streamEventCounts[eventType || 'unknown'] = (streamEventCounts[eventType || 'unknown'] || 0) + 1
            }
            
            // 处理 usageEvent
            if (eventType === 'usageEvent' || eventType === 'usage' || event.usageEvent || event.usage) {
              const usageData = event.usageEvent || event.usage || event
              if (usageData.inputTokens) {
                usage.inputTokens = usageData.inputTokens
                hasRealTokenUsage = true
              }
              if (usageData.outputTokens) usage.outputTokens = usageData.outputTokens
            }
            
            // 处理 meteringEvent - Kiro API 返回 credit 使用量
            if (eventType === 'meteringEvent' || event.meteringEvent) {
              const metering = event.meteringEvent || event
              if (metering.usage && typeof metering.usage === 'number') {
                // 累加 credit 使用量
                usage.credits += metering.usage
                proxyLogger.info('Kiro', `meteringEvent - credit: ${metering.usage}, total: ${usage.credits}`)
              }
            }
            
            // 处理 supplementaryWebLinksEvent - 网页链接引用
            if (eventType === 'supplementaryWebLinksEvent' || event.supplementaryWebLinksEvent) {
              const webLinksEvent = event.supplementaryWebLinksEvent || event
              if (webLinksEvent.supplementaryWebLinks && Array.isArray(webLinksEvent.supplementaryWebLinks)) {
                // 格式化网页链接引用
                const links = webLinksEvent.supplementaryWebLinks
                  .filter((link: { url?: string; title?: string; snippet?: string }) => link.url)
                  .map((link: { url?: string; title?: string; snippet?: string }) => {
                    const title = link.title || link.url
                    return `- [${title}](${link.url})`
                  })
                if (links.length > 0) {
                  onChunk(`\n\n🔗 **Web References:**\n${links.join('\n')}`)
                }
              }
              proxyLogger.debug('Kiro', 'supplementaryWebLinksEvent', JSON.stringify(webLinksEvent).slice(0, 300))
            }
            
            // 处理 contextUsageEvent - 上下文使用百分比（反推真实 inputTokens）
            if (eventType === 'contextUsageEvent' || event.contextUsageEvent) {
              const contextEvent = event.contextUsageEvent || event
              if (contextEvent.contextUsagePercentage !== undefined) {
                const percentage = contextEvent.contextUsagePercentage
                // 若已拿到真实 tokenUsage，仅记录百分比，不覆盖 inputTokens
                if (hasRealTokenUsage) {
                  proxyLogger.info('Kiro', `contextUsageEvent - Context usage: ${percentage.toFixed(2)}% (real tokenUsage already received)`)
                } else {
                  // 反推真实 inputTokens：modelContext × percentage / 100
                  const contextLen = getModelContextLength(modelId)
                  const reverseInput = Math.round(contextLen * percentage / 100)
                  if (reverseInput > 0) {
                    usage.inputTokens = reverseInput
                    proxyLogger.info('Kiro', `contextUsageEvent ${percentage.toFixed(2)}% → inputTokens=${reverseInput} (modelContext=${contextLen}, model=${modelId || 'unknown'})`)
                  } else {
                    proxyLogger.info('Kiro', `contextUsageEvent - Context usage: ${percentage.toFixed(2)}%`)
                  }
                }
                // 如果上下文使用率超过 80%，发送警告
                if (percentage > 80) {
                  console.warn('[Kiro] Warning: Context usage is high:', percentage.toFixed(2) + '%')
                }
              }
            }
            
            // 处理 reasoningContentEvent - Thinking 模式的推理内容
            // Kiro ReasoningContentEvent 字段：[text, redactedContent, signature]
            if (eventType === 'reasoningContentEvent' || event.reasoningContentEvent) {
              const reasoning = event.reasoningContentEvent || event
              if (reasoning.text) {
                proxyLogger.info('Kiro', `Received reasoning content (isThinking=true): ${reasoning.text.slice(0, 50)}...`)
                onChunk(reasoning.text, undefined, true, reasoning.signature, undefined)
                totalOutputChars += reasoning.text.length
                usage.reasoningTokens += Math.max(1, Math.round(reasoning.text.length * 0.4))
              } else if (reasoning.signature && !reasoning.redactedContent) {
                onChunk('', undefined, true, reasoning.signature, undefined)
              }
              // 处理 redactedContent（重编辑的加密 thinking 内容）
              if (reasoning.redactedContent) {
                proxyLogger.info('Kiro', `Received redacted thinking content (len=${reasoning.redactedContent.length})`)
                onChunk('', undefined, true, undefined, reasoning.redactedContent)
              }
              proxyLogger.debug('Kiro', 'reasoningContentEvent', JSON.stringify(reasoning).slice(0, 200))
            }
            
            // 处理 codeReferenceEvent - 代码引用/许可证信息
            if (eventType === 'codeReferenceEvent' || event.codeReferenceEvent) {
              const codeRef = event.codeReferenceEvent || event
              if (codeRef.references && Array.isArray(codeRef.references)) {
                // 格式化代码引用信息
                const refTexts = codeRef.references
                  .filter((ref: { licenseName?: string; repository?: string; url?: string }) => ref.licenseName || ref.repository)
                  .map((ref: { licenseName?: string; repository?: string; url?: string }) => {
                    const parts: string[] = []
                    if (ref.licenseName) parts.push(`License: ${ref.licenseName}`)
                    if (ref.repository) parts.push(`Repo: ${ref.repository}`)
                    if (ref.url) parts.push(`URL: ${ref.url}`)
                    return parts.join(', ')
                  })
                if (refTexts.length > 0) {
                  onChunk(`\n\n📚 **Code References:**\n${refTexts.join('\n')}`)
                }
              }
              proxyLogger.debug('Kiro', 'codeReferenceEvent', JSON.stringify(codeRef).slice(0, 300))
            }
            
            // 处理 followupPromptEvent - 后续提示建议
            if (eventType === 'followupPromptEvent' || event.followupPromptEvent) {
              const followup = event.followupPromptEvent || event
              if (followup.followupPrompt) {
                const prompt = followup.followupPrompt
                if (prompt.content || prompt.userIntent) {
                  // 将后续提示作为建议输出
                  const suggestion = prompt.content || prompt.userIntent
                  onChunk(`\n\n💡 **Suggested follow-up:** ${suggestion}`)
                }
              }
              proxyLogger.debug('Kiro', 'followupPromptEvent', JSON.stringify(followup).slice(0, 200))
            }
            
            // 处理 intentsEvent - 意图事件（artifact、deeplinks 等）
            if (eventType === 'intentsEvent' || event.intentsEvent) {
              const intents = event.intentsEvent || event
              // 意图事件主要用于 UI 渲染，记录日志即可
              proxyLogger.debug('Kiro', 'intentsEvent', JSON.stringify(intents).slice(0, 300))
            }
            
            // 处理 interactionComponentsEvent - 交互组件事件
            if (eventType === 'interactionComponentsEvent' || event.interactionComponentsEvent) {
              const components = event.interactionComponentsEvent || event
              // 交互组件主要用于 UI 渲染，记录日志即可
              proxyLogger.debug('Kiro', 'interactionComponentsEvent', JSON.stringify(components).slice(0, 300))
            }
            
            // 处理 invalidStateEvent - 无效状态事件（错误处理）
            if (eventType === 'invalidStateEvent' || event.invalidStateEvent) {
              const invalid = event.invalidStateEvent || event
              const reason = invalid.reason || 'UNKNOWN'
              const message = invalid.message || 'Invalid state detected'
              console.error('[Kiro] invalidStateEvent:', reason, message)
              // 将无效状态作为错误消息输出
              onChunk(`\n\n⚠️ **Warning:** ${message} (reason: ${reason})`)
            }
            
            // 处理 citationEvent - 引用事件
            if (eventType === 'citationEvent' || event.citationEvent) {
              const citation = event.citationEvent || event
              if (citation.citations && Array.isArray(citation.citations)) {
                // 格式化引用信息
                const citationTexts = citation.citations
                  .filter((c: { title?: string; url?: string; content?: string }) => c.title || c.url)
                  .map((c: { title?: string; url?: string; content?: string }, i: number) => {
                    const parts = [`[${i + 1}]`]
                    if (c.title) parts.push(c.title)
                    if (c.url) parts.push(`(${c.url})`)
                    return parts.join(' ')
                  })
                if (citationTexts.length > 0) {
                  onChunk(`\n\n📖 **Citations:**\n${citationTexts.join('\n')}`)
                }
              }
              proxyLogger.debug('Kiro', 'citationEvent', JSON.stringify(citation).slice(0, 300))
            }
            
            // 检查错误
            if (event._type || event.error) {
              const errMsg = event.message || event.error?.message || 'Unknown stream error'
              throw new Error(errMsg)
            }
          } catch (parseError) {
            if (parseError instanceof SyntaxError) {
              // JSON 解析错误，忽略
              console.debug('[EventStream] JSON parse error:', parseError)
            } else {
              throw parseError
            }
          }
        }
        
        // 移动到下一条消息
        buffer = buffer.slice(totalLength)
      }
    }
    
    // 完成任何未完成的 tool use
    if (currentToolUse && !processedIds.has(currentToolUse.toolUseId)) {
      let finalInput: Record<string, unknown> = {}
      try {
        if (currentToolUse.inputBuffer) {
          finalInput = JSON.parse(currentToolUse.inputBuffer)
        }
      } catch { /* 忽略解析错误 */ }
      onChunk('', {
        toolUseId: currentToolUse.toolUseId,
        name: currentToolUse.name,
        input: finalInput
      })
      totalOutputChars += currentToolUse.name.length + currentToolUse.inputBuffer.length
    }
    
    // 如果 API 没有返回 token 信息，优先用 tiktoken 精确计算，兜底字符系数
    if (usage.outputTokens === 0 && totalOutputChars > 0) {
      if (collectedOutputText) {
        // tiktoken cl100k_base 精确计算（±5%）
        usage.outputTokens = Math.max(1, countTokens(collectedOutputText))
        proxyLogger.info('Kiro', `Estimated output tokens (tiktoken): ${totalOutputChars} chars -> ${usage.outputTokens} tokens`)
      } else {
        // 字符系数兜底（自然语言中英混合约 0.4 token/字符）
        usage.outputTokens = Math.max(1, Math.round(totalOutputChars * 0.4))
        proxyLogger.info('Kiro', `Estimated output tokens (fallback): ${totalOutputChars} chars -> ${usage.outputTokens} tokens`)
      }
    }
    
    // 流式事件聚合摘要
    if (logStreamEvents && Object.keys(streamEventCounts).length > 0) {
      const total = Object.values(streamEventCounts).reduce((a, b) => a + b, 0)
      proxyLogger.debug('Kiro', `Stream events summary (${total} total)`, streamEventCounts)
    }
    
    throwIfAborted(signal)
    proxyLogger.info('Kiro', 'Stream complete, final usage', usage)
    onComplete(usage)
  } catch (error) {
    onError(signal?.aborted ? getAbortError(signal) : error as Error)
  } finally {
    signal?.removeEventListener('abort', abort)
    reader.releaseLock()
  }
}

// 非流式调用（等待完整响应）
export async function callKiroApi(
  account: ProxyAccount,
  payload: KiroPayload,
  signal?: AbortSignal
): Promise<{
  content: string
  toolUses: KiroToolUse[]
  usage: KiroUsage
  reasoningContent?: { text?: string; signature?: string; redactedContent?: string }
}> {
  return new Promise((resolve, reject) => {
    let content = ''
    let reasoningText = ''
    let reasoningSignature: string | undefined
    let redactedContent = ''
    const toolUses: KiroToolUse[] = []
    let usage: KiroUsage = { inputTokens: 0, outputTokens: 0, credits: 0 }

    callKiroApiStream(
      account,
      payload,
      (text, toolUse, isThinking, signature, redacted) => {
        if (isThinking) {
          if (text) reasoningText += text
          if (signature) reasoningSignature = signature
          if (redacted) redactedContent += redacted
        } else {
          content += text
        }
        if (toolUse) {
          toolUses.push(toolUse)
        }
      },
      (u) => {
        usage = u
        if (reasoningText || redactedContent) {
          const rc: { text?: string; signature?: string; redactedContent?: string } = {}
          if (reasoningText) rc.text = reasoningText
          if (reasoningSignature) rc.signature = reasoningSignature
          if (redactedContent) rc.redactedContent = redactedContent
          resolve({ content, toolUses, usage, reasoningContent: rc })
          return
        }
        resolve({ content, toolUses, usage })
      },
      reject,
      signal
    ).catch(reject)
  })
}

// Kiro 官方模型信息
export interface KiroModel {
  modelId: string
  modelName: string
  description: string
  modelProvider?: string | null
  rateMultiplier?: number
  rateUnit?: string
  status?: string | null
  supportedInputTypes?: string[]
  tokenLimits?: {
    maxInputTokens?: number | null
    maxOutputTokens?: number | null
  }
  promptCaching?: {
    supportsPromptCaching: boolean
    maximumCacheCheckpointsPerRequest?: number | null
    minimumTokensPerCacheCheckpoint?: number | null
  } | null
  additionalModelRequestFieldsSchema?: Record<string, unknown> | null
  availableOrigins?: string[] | null
}

// 根据账号区域获取 Q Service 端点（官方插件使用 q.{region}.amazonaws.com）
function getQServiceEndpoint(region?: string): string {
  if (region?.startsWith('eu-')) return 'https://q.eu-central-1.amazonaws.com'
  return 'https://q.us-east-1.amazonaws.com'
}

// 获取 Kiro 官方模型列表（支持分页，与官方插件一致传递 profileArn）
export async function fetchKiroModels(account: ProxyAccount, signal?: AbortSignal): Promise<KiroModel[]> {
  const baseUrl = getQServiceEndpoint(account.region)
  const machineId = getAccountMachineId(account.id, account.machineId)
  
  const headers: Record<string, string> = {
    'Authorization': `Bearer ${account.accessToken}`,
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'User-Agent': getKiroUserAgent(machineId),
    'x-amz-user-agent': getKiroAmzUserAgent(machineId),
    'x-amzn-codewhisperer-optout': 'true'
  }

  const allModels: KiroModel[] = []
  let nextToken: string | undefined

  try {
    do {
      const params = new URLSearchParams({ origin: 'AI_EDITOR', maxResults: '50' })
      const listProfileArn = resolveProfileArn(account)
      if (listProfileArn) params.set('profileArn', listProfileArn)
      if (nextToken) params.set('nextToken', nextToken)

      const url = `${baseUrl}/ListAvailableModels?${params.toString()}`
      throwIfAborted(signal)
      const response = await fetchWithProxy(url, { method: 'GET', headers, signal }, account)
      throwIfAborted(signal)
      
      if (!response.ok) {
        console.error('[KiroAPI] ListAvailableModels failed:', response.status)
        break
      }

      const data = await response.json()
      allModels.push(...(data.models || []))
      nextToken = data.nextToken
    } while (nextToken)

    return allModels
  } catch (error) {
    if (signal?.aborted) throw getAbortError(signal)
    console.error('[KiroAPI] ListAvailableModels error:', error)
    return allModels.length > 0 ? allModels : []
  }
}

// 订阅计划信息
export interface SubscriptionPlan {
  name: string  // KIRO_FREE, KIRO_PRO, KIRO_PRO_PLUS, KIRO_POWER
  qSubscriptionType: string
  description: {
    title: string
    billingInterval: string
    featureHeader: string
    features: string[]
  }
  pricing: {
    amount: number
    currency: string
  }
}

// 订阅列表响应
export interface SubscriptionListResponse {
  disclaimer?: string[]
  subscriptionPlans?: SubscriptionPlan[]
}

// 订阅请求专用 User-Agent（匹配 Kiro IDE 实际报文格式）
const KIRO_SUBSCRIPTION_VERSION = '0.12.155'

function getSubscriptionUserAgent(machineId?: string): string {
  const suffix = machineId ? `KiroIDE-${KIRO_SUBSCRIPTION_VERSION}-${machineId}` : `KiroIDE-${KIRO_SUBSCRIPTION_VERSION}`
  return `aws-sdk-js/1.0.0 ua/2.1 os/win32#10.0.19043 lang/js md/nodejs#22.22.0 api/codewhispererruntime#1.0.0 m/N,E ${suffix}`
}

function getSubscriptionAmzUserAgent(machineId?: string): string {
  const suffix = machineId ? `KiroIDE-${KIRO_SUBSCRIPTION_VERSION}-${machineId}` : `KiroIDE-${KIRO_SUBSCRIPTION_VERSION}`
  return `aws-sdk-js/1.0.0 ${suffix}`
}

// 获取可用订阅列表
export async function fetchAvailableSubscriptions(account: ProxyAccount): Promise<SubscriptionListResponse> {
  const baseUrl = getQServiceEndpoint(account.region)
  const url = `${baseUrl}/listAvailableSubscriptions`
  const machineId = getAccountMachineId(account.id, account.machineId)
  
  const headers: Record<string, string> = {
    'Authorization': `Bearer ${account.accessToken}`,
    'content-type': 'application/json',
    'user-agent': getSubscriptionUserAgent(machineId),
    'x-amz-user-agent': getSubscriptionAmzUserAgent(machineId),
    'amz-sdk-invocation-id': uuidv4(),
    'amz-sdk-request': 'attempt=1; max=1'
  }

  const profileArn = resolveProfileArn(account)
  const body = JSON.stringify({ profileArn })

  console.log(`[KiroAPI] ListAvailableSubscriptions [${account.email || account.id.slice(0, 8)}]`, {
    url
  })

  try {
    const response = await fetchWithProxy(url, { method: 'POST', headers, body }, account)
    const responseText = await response.text()
    console.log(`[KiroAPI] ListAvailableSubscriptions → ${response.status}`, JSON.parse(responseText))
    
    if (!response.ok) {
      return {}
    }

    return JSON.parse(responseText)
  } catch (error) {
    console.error('[KiroAPI] ListAvailableSubscriptions error:', error)
    return {}
  }
}

// 订阅 Token 响应
export interface SubscriptionTokenResponse {
  encodedVerificationUrl?: string
  status?: string
  token?: string | null
  message?: string
}

// 获取订阅管理/支付链接
export async function fetchSubscriptionToken(
  account: ProxyAccount,
  subscriptionType?: string
): Promise<SubscriptionTokenResponse> {
  const baseUrl = getQServiceEndpoint(account.region)
  const url = `${baseUrl}/CreateSubscriptionToken`
  const machineId = getAccountMachineId(account.id, account.machineId)
  
  const headers: Record<string, string> = {
    'Authorization': `Bearer ${account.accessToken}`,
    'content-type': 'application/json',
    'user-agent': getSubscriptionUserAgent(machineId),
    'x-amz-user-agent': getSubscriptionAmzUserAgent(machineId),
    'amz-sdk-invocation-id': uuidv4(),
    'amz-sdk-request': 'attempt=1; max=1'
  }

  const profileArn = resolveProfileArn(account)

  // clientToken 是必需参数，需要生成 UUID
  const payload: Record<string, string> = {
    clientToken: uuidv4(),
    provider: 'STRIPE'
  }
  if (profileArn) payload.profileArn = profileArn
  if (subscriptionType) {
    payload.subscriptionType = subscriptionType
  }

  try {
    const response = await fetchWithProxy(url, { method: 'POST', headers, body: JSON.stringify(payload) }, account)
    
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}))
      console.error('[KiroAPI] CreateSubscriptionToken failed:', response.status, errorData)
      return { message: errorData.message || `Request failed with status ${response.status}` }
    }

    const data = await response.json()
    return data
  } catch (error) {
    console.error('[KiroAPI] CreateSubscriptionToken error:', error)
    return { message: error instanceof Error ? error.message : 'Unknown error' }
  }
}

// 设置用户偏好（超额开启/关闭）
export async function setUserPreference(
  account: ProxyAccount,
  overageStatus: 'ENABLED' | 'DISABLED'
): Promise<{ success: boolean; error?: string }> {
  const baseUrl = getQServiceEndpoint(account.region)
  const url = `${baseUrl}/setUserPreference`
  const machineId = getAccountMachineId(account.id, account.machineId)

  const headers: Record<string, string> = {
    'Authorization': `Bearer ${account.accessToken}`,
    'content-type': 'application/json',
    'user-agent': getSubscriptionUserAgent(machineId),
    'x-amz-user-agent': getSubscriptionAmzUserAgent(machineId),
    'amz-sdk-invocation-id': uuidv4(),
    'amz-sdk-request': 'attempt=1; max=1'
  }

  const profileArn = resolveProfileArn(account)
  const body = JSON.stringify({
    overageConfiguration: { overageStatus },
    profileArn
  })

  try {
    const response = await fetchWithProxy(url, { method: 'POST', headers, body }, account)
    if (!response.ok) {
      const errorText = await response.text().catch(() => '')
      return { success: false, error: `HTTP ${response.status}: ${errorText.substring(0, 200)}` }
    }
    return { success: true }
  } catch (error) {
    return { success: false, error: error instanceof Error ? error.message : 'Unknown error' }
  }
}
