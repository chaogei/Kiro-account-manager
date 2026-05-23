// Kiro Proxy 类型定义

// ============ OpenAI 兼容格式 ============
export interface OpenAIChatRequest {
  model: string
  messages: OpenAIMessage[]
  temperature?: number
  top_p?: number
  max_tokens?: number
  stream?: boolean
  tools?: OpenAITool[]
  tool_choice?: string | { type: string; function: { name: string } }
  response_format?: { type: string; json_schema?: unknown }
  conversation_id?: string
  metadata?: Record<string, unknown>
  kiro_context?: KiroRequestContext
  reasoning_effort?: 'low' | 'medium' | 'high' | 'max' | string
  thinking?: { type: 'enabled'; budget_tokens?: number } | { type: 'adaptive' } | { type: 'disabled' }
}

export interface OpenAIMessage {
  role: 'system' | 'user' | 'assistant' | 'tool'
  content: string | OpenAIContentPart[]
  reasoning_content?: string
  name?: string
  tool_calls?: OpenAIToolCall[]
  tool_call_id?: string
  cache_control?: ClaudeCacheControl
}

export interface OpenAIContentPart {
  type: 'text' | 'image_url' | 'file' | 'document'
  text?: string
  image_url?: { url: string; detail?: string }
  file?: { filename?: string; file_data?: string }
  source?: ClaudeDocumentSource
  name?: string
  cache_control?: ClaudeCacheControl
}

export interface OpenAITool {
  type: 'function'
  function: {
    name: string
    description: string
    parameters: unknown
  }
  cache_control?: ClaudeCacheControl
}

export interface OpenAIToolCall {
  id: string
  type: 'function'
  function: {
    name: string
    arguments: string
  }
}

export interface OpenAIChatResponse {
  id: string
  object: 'chat.completion'
  created: number
  model: string
  choices: OpenAIChoice[]
  usage: {
    prompt_tokens: number
    completion_tokens: number
    total_tokens: number
    prompt_tokens_details?: {
      cached_tokens?: number
    }
    completion_tokens_details?: {
      reasoning_tokens?: number
    }
  }
}

export interface OpenAIChoice {
  index: number
  message: {
    role: 'assistant'
    content: string | null
    reasoning_content?: string
    tool_calls?: OpenAIToolCall[]
  }
  finish_reason: 'stop' | 'length' | 'tool_calls' | null
}

export interface OpenAIStreamChunk {
  id: string
  object: 'chat.completion.chunk'
  created: number
  model: string
  choices: {
    index: number
    delta: {
      role?: 'assistant'
      content?: string
      reasoning_content?: string
      tool_calls?: Partial<OpenAIToolCall>[]
    }
    finish_reason: 'stop' | 'length' | 'tool_calls' | null
  }[]
}

export interface OpenAIResponsesRequest {
  model: string
  input: string | OpenAIResponseInputItem[]
  instructions?: string
  temperature?: number
  top_p?: number
  max_output_tokens?: number
  stream?: boolean
  tools?: OpenAITool[]
  tool_choice?: string | { type: string; name?: string; function?: { name: string } }
  previous_response_id?: string
  reasoning?: unknown
  metadata?: Record<string, unknown>
  kiro_context?: KiroRequestContext
}

export interface OpenAIResponseInputItem {
  type?: 'message' | 'function_call' | 'function_call_output'
  role?: 'system' | 'user' | 'assistant' | 'tool'
  content?: string | OpenAIResponseContentPart[]
  call_id?: string
  name?: string
  arguments?: string
  output?: string
}

export interface OpenAIResponseContentPart {
  type: 'input_text' | 'output_text' | 'input_image' | 'input_file'
  text?: string
  image_url?: string
  file_data?: string
  filename?: string
}

export interface OpenAIResponsesResponse {
  id: string
  object: 'response'
  created_at: number
  model: string
  output: OpenAIResponseOutputItem[]
  previous_response_id?: string
  usage: {
    input_tokens: number
    output_tokens: number
    total_tokens: number
    input_tokens_details?: { cached_tokens?: number }
    output_tokens_details?: { reasoning_tokens?: number }
  }
}

export type OpenAIResponseOutputItem =
  | { type: 'message'; id: string; role: 'assistant'; content: { type: 'output_text'; text: string }[] }
  | { type: 'function_call'; id: string; call_id: string; name: string; arguments: string }

// ============ Claude 兼容格式 ============
export interface ClaudeRequest {
  model: string
  messages: ClaudeMessage[]
  max_tokens: number
  temperature?: number
  top_p?: number
  stream?: boolean
  system?: string | ClaudeSystemBlock[]
  tools?: ClaudeTool[]
  tool_choice?: { type: string; name?: string }
  thinking?: { type: 'enabled'; budget_tokens: number } | { type: 'adaptive'; display?: string } | { type: 'disabled' }
  conversation_id?: string
  metadata?: Record<string, unknown>
  kiro_context?: KiroRequestContext
  anthropic_beta?: string[]
  output_config?: { effort?: string; task_budget?: { type: 'tokens'; total: number; remaining?: number } }
  context_management?: { type?: string; [key: string]: unknown }
}

export interface ClaudeMessage {
  role: 'user' | 'assistant'
  content: string | ClaudeContentBlock[]
  cache_control?: ClaudeCacheControl
}

export interface ClaudeSystemBlock {
  type: 'text'
  text: string
  cache_control?: ClaudeCacheControl
}

export interface ClaudeContentBlock {
  type: 'text' | 'image' | 'document' | 'tool_use' | 'tool_result' | 'thinking' | 'redacted_thinking'
  text?: string
  thinking?: string
  signature?: string
  data?: string
  source?: { type: 'base64'; media_type: string; data: string } | { type: 'url'; url: string } | ClaudeDocumentSource
  id?: string
  name?: string
  input?: unknown
  tool_use_id?: string
  content?: string | ClaudeContentBlock[]
  cache_control?: ClaudeCacheControl
}

export type ClaudeDocumentSource =
  | { type: 'base64'; media_type: string; data: string }
  | { type: 'text'; media_type?: string; data: string }

export interface ClaudeTool {
  name: string
  description: string
  input_schema: unknown
  cache_control?: ClaudeCacheControl
}

export interface ClaudeCacheControl {
  type: string
}

export interface ClaudeResponse {
  id: string
  type: 'message'
  role: 'assistant'
  content: ClaudeContentBlock[]
  model: string
  stop_reason: 'end_turn' | 'max_tokens' | 'tool_use' | null
  stop_sequence: string | null
  usage: {
    input_tokens: number
    output_tokens: number
    cache_creation_input_tokens?: number
    cache_read_input_tokens?: number
  }
}

export interface ClaudeStreamEvent {
  type: 'message_start' | 'content_block_start' | 'content_block_delta' | 'content_block_stop' | 'message_delta' | 'message_stop' | 'ping' | 'error'
  message?: Partial<ClaudeResponse>
  index?: number
  content_block?: ClaudeContentBlock
  delta?: { type: string; text?: string; thinking?: string; signature?: string; data?: string; reasoning_content?: string; stop_reason?: string; stop_sequence?: string }
  usage?: { input_tokens?: number; output_tokens: number; cache_creation_input_tokens?: number; cache_read_input_tokens?: number }
  error?: { type: string; message: string }
}

// ============ Kiro API 格式 ============
export interface KiroPayload {
  conversationState: KiroConversationState
  profileArn?: string
  inferenceConfig?: KiroInferenceConfig
  additionalModelRequestFields?: Record<string, unknown>
}

export interface KiroConversationState {
  agentContinuationId?: string
  agentTaskType?: string
  chatTriggerType: 'MANUAL'
  conversationId: string
  currentMessage: KiroCurrentMessage
  history?: KiroHistoryMessage[]
}

export interface KiroCurrentMessage {
  userInputMessage: KiroUserInputMessage
}

export interface KiroUserInputMessage {
  content: string
  modelId?: string  // 可选，占位消息不需要
  origin: string
  images?: KiroImage[]
  documents?: KiroDocument[]
  cachePoint?: KiroCachePoint
  clientCacheConfig?: unknown
  userInputMessageContext?: KiroUserInputMessageContext
}

export interface KiroImage {
  format: string
  source: { bytes: string }
}

export interface KiroDocument {
  format: string
  name: string
  source: { bytes: string }
}

export interface KiroUserInputMessageContext {
  toolResults?: KiroToolResult[]
  tools?: KiroToolWrapper[]
  editorState?: unknown
  shellState?: unknown
  gitState?: unknown
  envState?: unknown
  additionalContext?: unknown
}

export interface KiroToolResult {
  content: { text: string }[]
  status: 'success' | 'error'
  toolUseId: string
}

export type KiroToolWrapper = {
  toolSpecification: {
    name: string
    description: string
    inputSchema: { json: unknown }
  }
} | {
  cachePoint: KiroCachePoint
}

export interface KiroHistoryMessage {
  userInputMessage?: KiroUserInputMessage
  assistantResponseMessage?: KiroAssistantResponseMessage
}

export interface KiroAssistantResponseMessage {
  content: string
  cachePoint?: KiroCachePoint
  reasoningContent?: KiroReasoningContent
  toolUses?: KiroToolUse[]
}

export interface KiroToolUse {
  toolUseId: string
  name: string
  input: Record<string, unknown>
}

export interface KiroInferenceConfig {
  maxTokens?: number
  temperature?: number
  topP?: number
}

export interface KiroCachePoint {
  type: 'default'
}

export interface KiroReasoningContent {
  reasoningText?: {
    text: string
    signature?: string
  }
  redactedContent?: string
}

export interface KiroRequestContext {
  editorState?: unknown
  shellState?: unknown
  gitState?: unknown
  envState?: unknown
  additionalContext?: unknown
}

export interface KiroUsage {
  inputTokens: number
  outputTokens: number
  credits: number
  cacheReadTokens?: number
  cacheWriteTokens?: number
  reasoningTokens?: number
}

// ============ 账号和代理配置 ============
export interface ProxyAccount {
  id: string
  email?: string
  accessToken: string
  refreshToken?: string
  clientId?: string
  clientSecret?: string
  region?: string
  authMethod?: 'social' | 'idc' | 'IdC' | 'external_idp'
  provider?: string
  profileArn?: string
  expiresAt?: number
  machineId?: string  // 账户绑定的设备 ID（64位十六进制）
  // 运行时状态
  lastUsed?: number
  requestCount?: number
  errorCount?: number
  isAvailable?: boolean
  cooldownUntil?: number
  // 配额追踪
  quotaUsed?: number
  quotaLimit?: number
  quotaExhaustedAt?: number // 配额耗尽时间戳
  quotaResetAt?: number // 下次配额重置时间
  // 长期封禁追踪（区分于临时 errorCount 冷却）
  // Kiro 后端 TEMPORARILY_SUSPENDED / AccountSuspendedException 等风控触发时设置
  // 需要联系 AWS Support 人工解封，账号池会持续跳过直到 clearSuspended
  suspendedAt?: number       // 封禁时间戳
  suspendReason?: string     // 封禁原因 (如 'TEMPORARILY_SUSPENDED')
  suspendMessage?: string    // 封禁完整错误消息 (含联系链接)
}

// API Key 格式类型
export type ApiKeyFormat = 'sk' | 'simple' | 'token'

// API Key 用量记录
export interface ApiKeyUsageRecord {
  timestamp: number
  model: string
  inputTokens: number
  outputTokens: number
  credits: number
  path: string
}

// API Key 类型
export interface ApiKey {
  id: string
  name: string
  key: string
  format: ApiKeyFormat  // 密钥格式
  enabled: boolean
  createdAt: number
  lastUsedAt?: number
  // 额度限制
  creditsLimit?: number  // Credits 上限（undefined 表示无限制）
  // 用量统计
  usage: {
    totalRequests: number
    totalCredits: number
    totalInputTokens: number
    totalOutputTokens: number
    // 按日期统计（YYYY-MM-DD -> usage）
    daily: Record<string, {
      requests: number
      credits: number
      inputTokens: number
      outputTokens: number
    }>
    // 按模型统计
    byModel?: Record<string, {
      requests: number
      credits: number
      inputTokens: number
      outputTokens: number
    }>
  }
  // 用量历史记录（最近 100 条）
  usageHistory?: ApiKeyUsageRecord[]
}

// 模型映射规则
export interface ModelMappingRule {
  id: string
  name: string  // 规则名称
  enabled: boolean
  // 映射类型：replace(替换), alias(别名), loadbalance(负载均衡)
  type: 'replace' | 'alias' | 'loadbalance'
  // 源模型（用户请求的模型名，支持通配符 *）
  sourceModel: string
  // 目标模型列表（负载均衡时随机选择）
  targetModels: string[]
  // 负载均衡权重（可选，默认平均）
  weights?: number[]
  // 优先级（数字越小优先级越高）
  priority: number
  // 适用的 API Key ID 列表（空表示全局）
  apiKeyIds?: string[]
}

export interface ProxyConfig {
  enabled: boolean
  port: number
  host: string
  apiKey?: string  // 保留兼容性
  apiKeys?: ApiKey[]  // 多 API Key 支持
  enableMultiAccount: boolean
  selectedAccountIds: string[]
  logRequests: boolean
  logStreamEvents?: boolean
  maxConcurrent: number
  // 重试配置
  maxRetries?: number
  retryDelayMs?: number
  // 首选端点配置
  preferredEndpoint?: 'codewhisperer' | 'amazonq' | 'amazonq-cli'
  // Token 刷新提前量（秒）
  tokenRefreshBeforeExpiry?: number
  // TLS/HTTPS 配置
  tls?: TlsConfig
  // 自动启动
  autoStart?: boolean
  clientDrivenToolExecution?: boolean
  // 禁用工具调用（移除 tools 参数）
  disableTools?: boolean
  // Payload 大小限制（KB），超过时截断工具结果（byte 维度）
  payloadSizeLimitKB?: number
  // Token buffer reserve 开关（默认 false = 完全跳过 trimHistoryByTokens）
  // 关闭时后端不再裁剪任何旧消息，超出 context window 由 Kiro 后端原样返回错误
  enableTokenBufferReserve?: boolean
  // Token buffer reserve（仅在 enableTokenBufferReserve=true 时生效）
  // effective limit = model.maxInputTokens - buffer
  // 默认 20K：覆盖 system + tools + current message + output + 估算偏差
  tokenBufferReserve?: number
  // 单账号模式下额度耗尽自动切换到下一个账号
  autoSwitchOnQuotaExhausted?: boolean
  // 多账号选择策略 (仅 enableMultiAccount=true 时生效)
  // - round-robin: 每次请求成功后切到下一个账号 (默认, 负载均衡)
  // - sticky: 一个账号成功就粘住, 直到失败才切换 (保留 prompt cache, 牺牲均衡)
  accountSelectionStrategy?: 'round-robin' | 'sticky'
  // 模型映射规则
  modelMappings?: ModelMappingRule[]
}

export interface TlsConfig {
  enabled: boolean
  certPath?: string // 证书文件路径
  keyPath?: string // 私钥文件路径
  // 或直接提供 PEM 内容
  cert?: string
  key?: string
}

// Token 刷新回调类型
export type TokenRefreshCallback = (account: ProxyAccount) => Promise<{
  success: boolean
  accessToken?: string
  refreshToken?: string
  expiresAt?: number
  error?: string
}>

export interface ProxyStats {
  totalRequests: number
  successRequests: number
  failedRequests: number
  totalTokens: number
  totalCredits: number // 累计总 credits（所有请求）
  inputTokens: number
  outputTokens: number
  cacheReadTokens: number
  cacheWriteTokens: number
  reasoningTokens: number
  startTime: number
  accountStats: Map<string, AccountStats>
  // 按端点统计
  endpointStats: Map<string, EndpointStats>
  // 按模型统计
  modelStats: Map<string, ModelStats>
  // 最近请求日志
  recentRequests: RequestLog[]
}

export interface AccountStats {
  requests: number
  tokens: number
  inputTokens: number
  outputTokens: number
  errors: number
  lastUsed: number
  avgResponseTime: number
  totalResponseTime: number
}

export interface EndpointStats {
  name: string
  requests: number
  successes: number
  failures: number
  quotaErrors: number
}

export interface ModelStats {
  model: string
  requests: number
  tokens: number
}

export interface RequestLog {
  timestamp: number
  path: string
  model: string
  accountId: string
  inputTokens: number
  outputTokens: number
  cacheReadTokens?: number
  cacheWriteTokens?: number
  reasoningTokens?: number
  credits?: number // Kiro API 返回的 credit 使用量
  responseTime: number
  success: boolean
  error?: string
}

// ============ Event Stream 解析 ============
export interface KiroEventStreamMessage {
  type: string
  payload: unknown
}

export interface KiroAssistantResponseEvent {
  content?: string
  toolUse?: KiroToolUse
}

export interface KiroUsageEvent {
  inputTokens?: number
  outputTokens?: number
  totalTokens?: number
}
