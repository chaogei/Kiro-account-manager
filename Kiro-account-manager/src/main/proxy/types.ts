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
}

export interface OpenAIMessage {
  role: 'system' | 'user' | 'assistant' | 'tool'
  content: string | OpenAIContentPart[]
  name?: string
  tool_calls?: OpenAIToolCall[]
  tool_call_id?: string
}

export interface OpenAIContentPart {
  type: 'text' | 'image_url'
  text?: string
  image_url?: { url: string; detail?: string }
}

export interface OpenAITool {
  type: 'function'
  function: {
    name: string
    description: string
    parameters: unknown
  }
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
  }
}

export interface OpenAIChoice {
  index: number
  message: {
    role: 'assistant'
    content: string | null
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
      tool_calls?: Partial<OpenAIToolCall>[]
    }
    finish_reason: 'stop' | 'length' | 'tool_calls' | null
  }[]
}

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
}

export interface ClaudeMessage {
  role: 'user' | 'assistant'
  content: string | ClaudeContentBlock[]
}

export interface ClaudeSystemBlock {
  type: 'text'
  text: string
}

export interface ClaudeContentBlock {
  type: 'text' | 'image' | 'tool_use' | 'tool_result' | 'thinking'
  text?: string
  thinking?: string
  source?: { type: 'base64'; media_type: string; data: string }
  id?: string
  name?: string
  input?: unknown
  tool_use_id?: string
  content?: string | ClaudeContentBlock[]
}

export interface ClaudeTool {
  name: string
  description: string
  input_schema: unknown
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
  }
}

export interface ClaudeStreamEvent {
  type: 'message_start' | 'content_block_start' | 'content_block_delta' | 'content_block_stop' | 'message_delta' | 'message_stop' | 'ping' | 'error'
  message?: Partial<ClaudeResponse>
  index?: number
  content_block?: ClaudeContentBlock
  delta?: { type: string; text?: string; thinking?: string; reasoning_content?: string; stop_reason?: string; stop_sequence?: string }
  usage?: { input_tokens?: number; output_tokens: number }
  error?: { type: string; message: string }
}

// ============ Kiro API 格式 ============
export interface KiroPayload {
  conversationState: KiroConversationState
  profileArn?: string
  inferenceConfig?: KiroInferenceConfig
}

export interface KiroConversationState {
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
  userInputMessageContext?: KiroUserInputMessageContext
}

export interface KiroImage {
  format: string
  source: { bytes: string }
}

export interface KiroUserInputMessageContext {
  toolResults?: KiroToolResult[]
  tools?: KiroToolWrapper[]
}

export interface KiroToolResult {
  content: { text: string }[]
  status: 'success' | 'error'
  toolUseId: string
}

export interface KiroToolWrapper {
  toolSpecification: {
    name: string
    description: string
    inputSchema: { json: unknown }
  }
}

export interface KiroHistoryMessage {
  userInputMessage?: KiroUserInputMessage
  assistantResponseMessage?: KiroAssistantResponseMessage
}

export interface KiroAssistantResponseMessage {
  content: string
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

// ============ 账号和代理配置 ============
export interface ProxyAccount {
  id: string
  email?: string
  accessToken: string
  refreshToken?: string
  clientId?: string
  clientSecret?: string
  region?: string
  authMethod?: 'social' | 'idc'
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
  maxConcurrent: number
  // 重试配置
  maxRetries?: number
  retryDelayMs?: number
  // 首选端点配置
  preferredEndpoint?: 'codewhisperer' | 'amazonq'
  // Token 刷新提前量（秒）
  tokenRefreshBeforeExpiry?: number
  // TLS/HTTPS 配置
  tls?: TlsConfig
  // 自动启动
  autoStart?: boolean
  // 工具调用后自动继续（最大轮数）
  autoContinueRounds?: number
  // 禁用工具调用（移除 tools 参数）
  disableTools?: boolean
  // 单账号模式下额度耗尽自动切换到下一个账号
  autoSwitchOnQuotaExhausted?: boolean
  // 模型思考模式配置（模型名 -> 是否默认启用思考模式）
  modelThinkingMode?: Record<string, boolean>
  // 思考内容输出格式：reasoning_content / thinking / think
  thinkingOutputFormat?: 'reasoning_content' | 'thinking' | 'think'
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
