// OpenAI/Claude 格式与 Kiro 格式转换器
import { v4 as uuidv4 } from 'uuid'
import type {
  OpenAIChatRequest,
  OpenAIMessage,
  OpenAITool,
  OpenAIChatResponse,
  OpenAIStreamChunk,
  OpenAIResponsesRequest,
  OpenAIResponsesResponse,
  OpenAIResponseContentPart,
  OpenAIResponseOutputItem,
  ClaudeRequest,
  ClaudeMessage,
  ClaudeResponse,
  ClaudeStreamEvent,
  ClaudeContentBlock,
  KiroPayload,
  KiroHistoryMessage,
  KiroToolWrapper,
  KiroToolResult,
  KiroImage,
  KiroDocument,
  KiroToolUse,
  KiroUserInputMessage,
  KiroCachePoint,
  KiroReasoningContent,
  KiroUsage
} from './types'
import { buildKiroPayload, mapModelId } from './kiroApi'
import { ToolNameRegistry } from './toolNameRegistry'

const KIRO_CACHE_POINT: KiroCachePoint = { type: 'default' }

/** 模型 thinking 能力元数据（由 proxyServer 从模型缓存中查询后传入） */
export interface ThinkingConfig {
  schemaPath: 'output_config' | 'reasoning'
  efforts: string[]
  defaultEffort?: string
}

/**
 * 将客户端 effort / thinking 参数 + 模型 schema path 映射为 Kiro additionalModelRequestFields。
 * 官方 Kiro IDE 的 kr() 函数逻辑：
 *   output_config → { thinking: { type: 'adaptive', display: 'summarized' }, output_config: { effort } }
 *   reasoning     → { reasoning: { effort } }
 */
function buildThinkingFields(
  thinkingConfig: ThinkingConfig | undefined,
  clientThinking?: { type: string; budget_tokens?: number; display?: string },
  clientReasoningEffort?: string
): Record<string, unknown> | undefined {
  // 客户端明确关闭 thinking
  if (clientThinking?.type === 'disabled') return undefined

  // 没有模型元数据时，回退到旧逻辑：仅传 { thinking: { type: 'adaptive' } }
  if (!thinkingConfig) {
    if (clientThinking && clientThinking.type !== 'disabled') {
      return { thinking: { type: 'adaptive' } }
    }
    if (clientReasoningEffort) {
      return { thinking: { type: 'adaptive' } }
    }
    return undefined
  }

  // 客户端没请求 thinking 也没请求 reasoning_effort → 不启用
  const wantsThinking = !!(clientThinking && clientThinking.type !== 'disabled') || !!clientReasoningEffort
  if (!wantsThinking) return undefined

  // 映射 effort level（直接使用客户端值，不做强制转换）
  const mapEffort = (input: string): string => input.toLowerCase()

  let effort: string
  if (clientReasoningEffort) {
    effort = mapEffort(clientReasoningEffort)
  } else if (clientThinking?.type === 'enabled' && clientThinking.budget_tokens) {
    // budget_tokens 粗略映射到 effort level
    const b = clientThinking.budget_tokens
    if (b <= 4000) effort = 'low'
    else if (b <= 16000) effort = 'medium'
    else if (b <= 64000) effort = 'high'
    else effort = 'xhigh'
  } else {
    effort = thinkingConfig.defaultEffort || 'high'
  }

  // 确保 effort 在可用范围内，否则取最接近的
  if (!thinkingConfig.efforts.includes(effort)) {
    effort = thinkingConfig.efforts[thinkingConfig.efforts.length - 1] || 'high'
  }

  switch (thinkingConfig.schemaPath) {
    case 'output_config':
      return {
        thinking: { type: 'adaptive', display: 'summarized' },
        output_config: { effort }
      }
    case 'reasoning':
      return { reasoning: { effort } }
    default:
      return { thinking: { type: 'adaptive' } }
  }
}

function toKiroCachePoint(cacheControl?: { type: string }): KiroCachePoint | undefined {
  if (!cacheControl) return undefined
  if (cacheControl.type !== 'ephemeral') {
    throw new Error(`Unsupported cache_control type: ${cacheControl.type}`)
  }
  return KIRO_CACHE_POINT
}

function mergeCachePoint(
  first?: KiroCachePoint,
  second?: KiroCachePoint
): KiroCachePoint | undefined {
  return first || second
}

export function responsesToOpenAIChat(request: OpenAIResponsesRequest): OpenAIChatRequest {
  if (!request || typeof request !== 'object') {
    throw new Error('Responses request body must be an object')
  }
  if (!request.model) {
    throw new Error('Responses request requires model')
  }
  if (request.input === undefined) {
    throw new Error('Responses request requires input')
  }

  const messages: OpenAIMessage[] = []
  if (request.instructions) {
    messages.push({ role: 'system', content: request.instructions })
  }
  if (typeof request.input === 'string') {
    messages.push({ role: 'user', content: request.input })
  } else {
    if (!Array.isArray(request.input)) {
      throw new Error('Responses input must be a string or an array')
    }
    for (const item of request.input) {
      const itemType = item.type as string | undefined
      if (itemType === 'function_call_output') {
        if (!item.call_id) {
          throw new Error('function_call_output requires call_id')
        }
        if (item.output === undefined) {
          throw new Error('function_call_output requires output')
        }
        messages.push({
          role: 'tool',
          content: item.output,
          tool_call_id: item.call_id
        })
      } else if (itemType === 'function_call') {
        if (!item.call_id) {
          throw new Error('function_call requires call_id')
        }
        if (!item.name) {
          throw new Error('function_call requires name')
        }
        if (item.arguments === undefined) {
          throw new Error('function_call requires arguments')
        }
        messages.push({
          role: 'assistant',
          content: '',
          tool_calls: [{
            id: item.call_id,
            type: 'function',
            function: {
              name: encodeResponseToolName(item.namespace, item.name),
              arguments: item.arguments
            }
          }]
        })
      } else {
        if (itemType !== undefined && itemType !== 'message') {
          throw new Error(`Unsupported responses input item type: ${itemType}`)
        }
        if (item.content === undefined) {
          throw new Error('message input item requires content')
        }
        messages.push({
          role: item.role === 'assistant' ? 'assistant' : item.role === 'system' ? 'system' : 'user',
          content: convertResponseInputContent(item.content)
        })
      }
    }
  }

  const chatRequest: OpenAIChatRequest = {
    model: request.model,
    messages
  }
  if (request.temperature !== undefined) chatRequest.temperature = request.temperature
  if (request.top_p !== undefined) chatRequest.top_p = request.top_p
  if (request.reasoning?.effort !== undefined) chatRequest.reasoning_effort = request.reasoning.effort
  if (request.max_output_tokens !== undefined) chatRequest.max_tokens = request.max_output_tokens
  if (request.stream !== undefined) chatRequest.stream = request.stream
  if (request.tools !== undefined) chatRequest.tools = convertResponseTools(request.tools)
  const toolChoice = convertResponseToolChoice(request.tool_choice)
  if (toolChoice !== undefined) chatRequest.tool_choice = toolChoice
  if (request.previous_response_id !== undefined) chatRequest.conversation_id = request.previous_response_id
  if (request.metadata !== undefined) chatRequest.metadata = request.metadata
  if (request.kiro_context !== undefined) chatRequest.kiro_context = request.kiro_context
  return chatRequest
}

const RESPONSE_HOSTED_TOOL_TYPES = new Set([
  'web_search',
  'web_search_preview',
  'file_search',
  'computer_use_preview',
  'code_interpreter',
  'image_generation'
])

function convertResponseTools(tools: NonNullable<OpenAIResponsesRequest['tools']>): OpenAITool[] {
  if (!Array.isArray(tools)) {
    throw new Error('Responses tools must be an array')
  }

  return tools.flatMap(tool => {
    const rawTool = tool as unknown as Record<string, unknown>
    const toolType = rawTool.type

    if (toolType === 'namespace') {
      const namespace = rawTool.name
      const nestedTools = rawTool.tools
      if (typeof namespace !== 'string' || !Array.isArray(nestedTools)) {
        throw new Error('Responses namespace tool requires name and tools')
      }

      return nestedTools.map(nestedToolValue => {
        const nestedTool = nestedToolValue as Record<string, unknown>
        if (nestedTool.type !== 'function' || typeof nestedTool.name !== 'string') {
          throw new Error(`Unsupported tool in Responses namespace: ${String(nestedTool.type)}`)
        }
        return {
          type: 'function' as const,
          function: {
            name: encodeResponseToolName(namespace, nestedTool.name),
            description: typeof nestedTool.description === 'string'
              ? nestedTool.description
              : typeof rawTool.description === 'string'
                ? rawTool.description
                : `Tool: ${namespace}/${nestedTool.name}`,
            parameters: nestedTool.parameters ?? { type: 'object', properties: {} }
          }
        }
      })
    }

    // Hosted OpenAI tools execute inside OpenAI's platform and cannot be
    // translated to Kiro's client-executed function tool protocol.
    if (typeof toolType === 'string' && RESPONSE_HOSTED_TOOL_TYPES.has(toolType)) {
      return []
    }
    if (toolType !== 'function') {
      throw new Error(`Unsupported responses tool type: ${String(toolType)}`)
    }

    const nestedFunction = rawTool.function as Record<string, unknown> | undefined
    if (nestedFunction) {
      if (typeof nestedFunction.name !== 'string') {
        throw new Error('Responses function tool requires name')
      }
      return [{
        type: 'function' as const,
        function: {
          name: nestedFunction.name,
          description: typeof nestedFunction.description === 'string'
            ? nestedFunction.description
            : `Tool: ${nestedFunction.name}`,
          parameters: nestedFunction.parameters ?? { type: 'object', properties: {} }
        }
      }]
    }

    if (typeof rawTool.name !== 'string') {
      throw new Error('Responses function tool requires name')
    }
    return [{
      type: 'function' as const,
      function: {
        name: rawTool.name,
        description: typeof rawTool.description === 'string' ? rawTool.description : `Tool: ${rawTool.name}`,
        parameters: rawTool.parameters ?? { type: 'object', properties: {} }
      }
    }]
  })
}

const RESPONSE_NAMESPACE_PREFIX = '__kiro_ns_'

function encodeResponseToolName(namespace: string | undefined, name: string): string {
  return namespace ? `${RESPONSE_NAMESPACE_PREFIX}${namespace.length}__${namespace}${name}` : name
}

function decodeResponseToolName(encodedName: string): { name: string; namespace?: string } {
  if (!encodedName.startsWith(RESPONSE_NAMESPACE_PREFIX)) return { name: encodedName }
  const lengthEnd = encodedName.indexOf('__', RESPONSE_NAMESPACE_PREFIX.length)
  if (lengthEnd < 0) return { name: encodedName }

  const namespaceLength = Number(encodedName.slice(RESPONSE_NAMESPACE_PREFIX.length, lengthEnd))
  if (!Number.isInteger(namespaceLength) || namespaceLength < 1) return { name: encodedName }

  const namespaceStart = lengthEnd + 2
  const nameStart = namespaceStart + namespaceLength
  if (nameStart >= encodedName.length) return { name: encodedName }
  return {
    namespace: encodedName.slice(namespaceStart, nameStart),
    name: encodedName.slice(nameStart)
  }
}

function convertResponseInputContent(content: string | OpenAIResponseContentPart[] | undefined): OpenAIMessage['content'] {
  if (typeof content === 'string') return content
  if (content === undefined) return ''
  if (!Array.isArray(content)) {
    throw new Error('message content must be a string or an array')
  }
  return content.map(part => {
    const partType = part.type as string
    if (partType === 'input_image') {
      if (!part.image_url) {
        throw new Error('input_image requires image_url')
      }
      return { type: 'image_url', image_url: { url: part.image_url } }
    }
    if (partType === 'input_file') {
      if (!part.file_data) {
        throw new Error('input_file requires file_data')
      }
      return {
        type: 'file',
        file: {
          file_data: part.file_data,
          ...(part.filename !== undefined ? { filename: part.filename } : {})
        }
      }
    }
    if (partType !== 'input_text' && partType !== 'output_text') {
      throw new Error(`Unsupported responses content part type: ${partType}`)
    }
    if (part.text === undefined) {
      throw new Error(`${partType} requires text`)
    }
    return { type: 'text', text: part.text }
  })
}

function convertResponseToolChoice(toolChoice: OpenAIResponsesRequest['tool_choice']): OpenAIChatRequest['tool_choice'] {
  if (!toolChoice || typeof toolChoice === 'string') return toolChoice
  if (toolChoice.type === 'none' || toolChoice.type === 'auto') return toolChoice.type
  if (toolChoice.type === 'function' && toolChoice.name) {
    return { type: 'function', function: { name: encodeResponseToolName(toolChoice.namespace, toolChoice.name) } }
  }
  if (toolChoice.function?.name) return { type: 'function', function: { name: toolChoice.function.name } }
  throw new Error('Unsupported responses tool_choice')
}

interface ResponsesConversationState {
  messages: OpenAIMessage[]
  tools?: OpenAITool[]
}

const RESPONSES_CONVERSATION_CACHE_MAX = 100
const responsesConversationCache = new Map<string, ResponsesConversationState>()

export function restorePreviousResponse(
  chatRequest: OpenAIChatRequest,
  previousResponseId?: string
): OpenAIChatRequest {
  if (!previousResponseId) return chatRequest
  const previous = responsesConversationCache.get(previousResponseId)
  if (!previous) return chatRequest

  // Refresh LRU order while rebuilding the full tool transcript required by
  // Kiro's stateless runtime endpoint.
  responsesConversationCache.delete(previousResponseId)
  responsesConversationCache.set(previousResponseId, previous)
  return {
    ...chatRequest,
    messages: [...previous.messages, ...chatRequest.messages],
    tools: chatRequest.tools ?? previous.tools
  }
}

export function rememberResponseConversation(
  responseId: string,
  processedRequest: OpenAIChatRequest,
  chatResponse: OpenAIChatResponse
): void {
  const assistantMessages: OpenAIMessage[] = chatResponse.choices.map(choice => ({
    role: 'assistant',
    content: choice.message.content ?? '',
    ...(choice.message.reasoning_content !== undefined
      ? { reasoning_content: choice.message.reasoning_content }
      : {}),
    ...(choice.message.tool_calls !== undefined ? { tool_calls: choice.message.tool_calls } : {})
  }))

  responsesConversationCache.set(responseId, {
    messages: [...processedRequest.messages, ...assistantMessages],
    tools: processedRequest.tools
  })
  while (responsesConversationCache.size > RESPONSES_CONVERSATION_CACHE_MAX) {
    const oldestResponseId = responsesConversationCache.keys().next().value
    if (oldestResponseId === undefined) break
    responsesConversationCache.delete(oldestResponseId)
  }
}

export function openAIChatToResponsesResponse(
  response: OpenAIChatResponse,
  previousResponseId?: string
): OpenAIResponsesResponse {
  const output: OpenAIResponseOutputItem[] = response.choices.flatMap<OpenAIResponseOutputItem>(choice => {
    if (choice.message.tool_calls?.length) {
      return choice.message.tool_calls.map(toolCall => {
        const decodedName = decodeResponseToolName(toolCall.function.name)
        return {
          type: 'function_call' as const,
          id: `fc_${uuidv4()}`,
          call_id: toolCall.id,
          name: decodedName.name,
          ...(decodedName.namespace ? { namespace: decodedName.namespace } : {}),
          arguments: toolCall.function.arguments
        }
      })
    }
    return [{
      type: 'message' as const,
      id: `msg_${uuidv4()}`,
      role: 'assistant' as const,
      content: [{ type: 'output_text' as const, text: choice.message.content || '' }]
    }]
  })

  const usage: OpenAIResponsesResponse['usage'] = {
    input_tokens: response.usage.prompt_tokens,
    output_tokens: response.usage.completion_tokens,
    total_tokens: response.usage.total_tokens
  }
  const cachedTokens = response.usage.prompt_tokens_details?.cached_tokens
  if (cachedTokens !== undefined) {
    usage.input_tokens_details = { cached_tokens: cachedTokens }
  }
  const reasoningTokens = response.usage.completion_tokens_details?.reasoning_tokens
  if (reasoningTokens !== undefined) {
    usage.output_tokens_details = { reasoning_tokens: reasoningTokens }
  }

  const responsesResponse: OpenAIResponsesResponse = {
    id: `resp_${uuidv4()}`,
    object: 'response',
    created_at: response.created,
    status: 'completed',
    model: response.model,
    output,
    usage
  }
  if (previousResponseId !== undefined) {
    responsesResponse.previous_response_id = previousResponseId
  }
  return responsesResponse
}

// ============ OpenAI -> Kiro 转换 ============

export function openaiToKiro(
  request: OpenAIChatRequest,
  profileArn?: string,
  toolNameRegistry: ToolNameRegistry = new ToolNameRegistry(),
  thinkingConfig?: ThinkingConfig
): KiroPayload {
  const modelId = mapModelId(request.model)
  const origin = 'AI_EDITOR'

  // 提取系统提示
  let systemPrompt = ''
  let systemCachePoint: KiroCachePoint | undefined
  const nonSystemMessages: OpenAIMessage[] = []

  for (const msg of request.messages) {
    if (msg.role === 'system') {
      systemCachePoint = mergeCachePoint(systemCachePoint, toKiroCachePoint(msg.cache_control))
      if (typeof msg.content === 'string') {
        systemPrompt += (systemPrompt ? '\n' : '') + msg.content
      } else if (Array.isArray(msg.content)) {
        for (const part of msg.content) {
          systemCachePoint = mergeCachePoint(systemCachePoint, toKiroCachePoint(part.cache_control))
          if (part.type === 'text' && part.text) {
            systemPrompt += (systemPrompt ? '\n' : '') + part.text
          }
        }
      }
    } else {
      nonSystemMessages.push(msg)
    }
  }

  // 注入时间戳
  const timestamp = new Date().toISOString()
  systemPrompt = `[Context: Current time is ${timestamp}]\n\n${systemPrompt}`

  // 注入执行导向指令（防止 AI 在探索过程中丢失目标）
  const executionDirective = `
<execution_discipline>
当用户要求执行特定任务时，你必须遵循以下纪律：
1. **目标锁定**：在整个会话中始终牢记用户的原始目标，不要在代码探索过程中迷失方向
2. **行动优先**：优先执行任务而非仅分析或总结，除非用户明确只要求分析
3. **计划执行**：为任务创建明确的步骤计划，逐步执行并标记完成状态
4. **禁止确认性收尾**：在任务未完成前，禁止输出"需要我继续吗？"、"需要深入分析吗？"等确认性问题
5. **持续推进**：如果发现部分任务已完成，立即继续执行剩余未完成的任务
6. **完整交付**：直到所有任务步骤都执行完毕才算完成
</execution_discipline>
`
  systemPrompt = systemPrompt + '\n\n' + executionDirective

  // 构建历史消息（参考 Proxycast 实现）
  const history: KiroHistoryMessage[] = []
  const toolResults: KiroToolResult[] = []
  let currentContent = ''
  let currentCachePoint: KiroCachePoint | undefined
  const images: KiroImage[] = []
  const documents: KiroDocument[] = []
  for (let i = 0; i < nonSystemMessages.length; i++) {
    const msg = nonSystemMessages[i]
    const isLast = i === nonSystemMessages.length - 1

    if (msg.role === 'user') {
      const { content: userContent, images: userImages, documents: userDocuments, cachePoint } = extractOpenAIContent(msg)
      
      const mergedContent = userContent || 'Continue'
      const messageCachePoint = cachePoint
      
      if (isLast) {
        currentContent = mergedContent
        currentCachePoint = messageCachePoint
        images.push(...userImages)
        documents.push(...userDocuments)
      } else {
        history.push({
          userInputMessage: {
            content: mergedContent,
            modelId,
            origin,
            images: userImages.length > 0 ? userImages : undefined,
            documents: userDocuments.length > 0 ? userDocuments : undefined,
            ...(messageCachePoint ? { cachePoint: messageCachePoint } : {})
          }
        })
      }
    } else if (msg.role === 'assistant') {
      // Kiro API 要求 content 非空
      // 注意: 故意不读取 msg.reasoning_content (history 中不传给 Kiro)
      // Kiro 后端 schema 仅在响应输出中支持 assistantResponseMessage.reasoningContent，
      // 在请求 history 中传入此字段会触发 400 "Improperly formed request"
      let assistantContent = typeof msg.content === 'string' ? msg.content : ''
      if (!assistantContent.trim() && msg.tool_calls && msg.tool_calls.length > 0) {
        assistantContent = ' '
      } else if (!assistantContent.trim()) {
        assistantContent = 'I understand.'
      }
      const toolUses: KiroToolUse[] = []

      if (msg.tool_calls) {
        for (const tc of msg.tool_calls) {
          if (tc.type === 'function') {
            let input = {}
            try {
              input = JSON.parse(tc.function.arguments)
            } catch { /* ignore */ }
            toolUses.push({
              toolUseId: tc.id,
              name: toolNameRegistry.toKiroName(tc.function.name),
              input
            })
          }
        }
      }

      history.push({
        assistantResponseMessage: {
          content: assistantContent,
          toolUses: toolUses.length > 0 ? toolUses : undefined
        }
      })
    } else if (msg.role === 'tool') {
      // Tool result - 收集到待处理列表
      if (msg.tool_call_id) {
        let rawText = ''
        let extractedImageCount = 0
        // content 是数组时（部分客户端把图像/多模态结果挂在这里）：
        // 提取所有 text 块拼接为文本；image_url 块提取到外层 images，避免被 JSON.stringify 序列化丢失
        if (Array.isArray(msg.content)) {
          const textParts: string[] = []
          for (const part of msg.content) {
            if (part.type === 'text' && typeof part.text === 'string') {
              textParts.push(part.text)
            } else if (part.type === 'image_url' && part.image_url?.url) {
              const img = parseImageUrl(part.image_url.url)
              if (img) { images.push(img); extractedImageCount++ }
            }
          }
          rawText = textParts.join('')
          if (!rawText && extractedImageCount === 0) {
            // 退化：把不识别的结构 stringify 让模型至少看到原始结构
            rawText = JSON.stringify(msg.content)
          }
          if (extractedImageCount > 0) {
            rawText = (rawText ? rawText + '\n\n' : '') +
              `[Tool returned ${extractedImageCount} image${extractedImageCount > 1 ? 's' : ''}, attached to this message]`
          }
        } else {
          rawText = typeof msg.content === 'string' ? msg.content : JSON.stringify(msg.content)
        }
        toolResults.push({
          toolUseId: msg.tool_call_id,
          content: [{ text: rawText || '(no output)' }],
          status: 'success'
        })
      }
      
      // 检查下一条消息：如果不是 tool 消息或已到末尾，将收集的 toolResults 添加为 user 消息
      const nextMsg = nonSystemMessages[i + 1]
      const shouldFlush = !nextMsg || nextMsg.role !== 'tool'
      
      if (shouldFlush && toolResults.length > 0 && !isLast) {
        // 将 toolResults 作为 user 消息添加到 history
        history.push({
          userInputMessage: {
            content: 'Tool results provided.',
            modelId,
            origin,
            userInputMessageContext: {
              toolResults: [...toolResults]
            }
          }
        })
        // 清空已处理的 toolResults
        toolResults.length = 0
      }
    }
  }

  // 如果最后一条是 assistant 消息，自动发送 Continue（参考 Proxycast）
  if (history.length > 0 && history[history.length - 1].assistantResponseMessage && !currentContent) {
    currentContent = 'Continue.'
  }

  // 如果没有当前内容但有工具结果（最后一轮的），保留它们传给 currentMessage
  if (!currentContent && toolResults.length > 0) {
    currentContent = 'Tool results provided.'
  }

  // System prompt 以 Kiro 官方方式注入：作为 Human/AI pair 插入到 history 头部
  if (systemPrompt) {
    const systemMessages: KiroHistoryMessage[] = [
      {
        userInputMessage: {
          content: systemPrompt,
          userInputMessageContext: {},
          origin,
          ...(systemCachePoint ? { cachePoint: systemCachePoint } : {})
        }
      },
      {
        assistantResponseMessage: {
          content: 'I will follow these instructions.'
        }
      }
    ]
    history.unshift(...systemMessages)
  }
  const finalContent = currentContent || 'Continue.'

  // 转换工具定义
  const kiroTools = convertOpenAITools(request.tools, toolNameRegistry)

  // OpenAI 兼容请求的 thinking/reasoning_effort 映射到 Kiro additionalModelRequestFields
  // Codex may call /v1/responses before /v1/models has populated the schema
  // cache. Current GPT 5.6 models use Kiro's reasoning.effort schema rather
  // than Anthropic's thinking object, so retain a safe family fallback.
  const effectiveThinkingConfig = thinkingConfig ?? (/^gpt-5\.6-/i.test(modelId)
    ? { schemaPath: 'reasoning' as const, efforts: ['none', 'low', 'medium', 'high', 'xhigh', 'max'] }
    : undefined)
  const additionalModelRequestFields = buildThinkingFields(
    effectiveThinkingConfig,
    request.thinking as { type: string; budget_tokens?: number },
    request.reasoning_effort
  )

  return buildKiroPayload(
    finalContent,
    modelId,
    origin,
    history,
    kiroTools,
    toolResults,
    images,
    profileArn,
    {
      maxTokens: request.max_tokens,
      temperature: request.temperature,
      topP: request.top_p
    },
    {
      cachePoint: currentCachePoint,
      documents,
      conversationId: request.conversation_id,
      context: request.kiro_context
    },
    additionalModelRequestFields
  )
}

function extractOpenAIContent(msg: OpenAIMessage): { content: string; images: KiroImage[]; documents: KiroDocument[]; cachePoint?: KiroCachePoint } {
  const images: KiroImage[] = []
  const documents: KiroDocument[] = []
  let content = ''
  let cachePoint = toKiroCachePoint(msg.cache_control)

  if (typeof msg.content === 'string') {
    content = msg.content
  } else if (Array.isArray(msg.content)) {
    for (const part of msg.content) {
      cachePoint = mergeCachePoint(cachePoint, toKiroCachePoint(part.cache_control))
      if (part.type === 'text' && part.text) {
        content += part.text
      } else if (part.type === 'image_url' && part.image_url?.url) {
        const image = parseImageUrl(part.image_url.url)
        if (image) {
          images.push(image)
        }
      } else if (part.type === 'file' || part.type === 'document') {
        if (part.file?.file_data) {
          const name = part.file.filename || part.name
          if (!name) {
            throw new Error(`${part.type} requires filename or name`)
          }
          documents.push(parseOpenAIFileData(part.file.file_data, name))
        } else if (part.source) {
          if (!part.name) {
            throw new Error(`${part.type} requires name`)
          }
          documents.push(parseClaudeDocumentSource(part.source, part.name))
        } else {
          throw new Error(`${part.type} requires file_data or source`)
        }
      }
    }
  }

  return { content, images, documents, cachePoint }
}

// 解析图像 URL（支持 data URL 和 HTTP URL）
function parseImageUrl(url: string): KiroImage | null {
  if (url.startsWith('data:')) {
    // 解析 data URL: data:image/png;base64,xxxxx
    const match = url.match(/^data:image\/(\w+);base64,(.+)$/)
    if (match) {
      return {
        format: normalizeImageFormat(match[1]),
        source: { bytes: match[2] }
      }
    }
  }
  return null
}

function parseOpenAIFileData(fileData: string, name: string): KiroDocument {
  const dataUrlMatch = fileData.match(/^data:([^;]+);base64,(.+)$/)
  if (dataUrlMatch) {
    return {
      format: normalizeDocumentFormat(dataUrlMatch[1], name),
      name,
      source: { bytes: dataUrlMatch[2] }
    }
  }

  return {
    format: normalizeDocumentFormat(undefined, name),
    name,
    source: { bytes: fileData }
  }
}

function parseClaudeDocumentSource(source: NonNullable<ClaudeContentBlock['source']>, name: string): KiroDocument {
  if (source.type === 'base64') {
    return {
      format: normalizeDocumentFormat(source.media_type, name),
      name,
      source: { bytes: source.data }
    }
  }
  if (source.type === 'text') {
    return {
      format: normalizeDocumentFormat(source.media_type, name),
      name,
      source: { bytes: Buffer.from(source.data, 'utf8').toString('base64') }
    }
  }
  throw new Error(`Unsupported document source type: ${source.type}`)
}

// 标准化图像格式
function normalizeImageFormat(format: string): string {
  const lower = format.toLowerCase()
  const formatMap: Record<string, string> = {
    'jpg': 'jpeg',
    'jpeg': 'jpeg',
    'png': 'png',
    'gif': 'gif',
    'webp': 'webp'
  }
  const normalized = formatMap[lower]
  if (!normalized) {
    throw new Error(`Unsupported image format: ${format}`)
  }
  return normalized
}

function normalizeDocumentFormat(mediaType: string | undefined, name: string): string {
  const lowerMediaType = mediaType?.toLowerCase()
  if (lowerMediaType === 'application/pdf') return 'pdf'
  if (lowerMediaType === 'text/markdown') return 'md'
  if (lowerMediaType === 'text/csv') return 'csv'
  if (lowerMediaType === 'text/html') return 'html'
  if (lowerMediaType?.startsWith('text/')) return 'txt'
  const extension = name.split('.').pop()?.toLowerCase()
  if (extension === 'pdf') return 'pdf'
  if (extension === 'md' || extension === 'markdown') return 'md'
  if (extension === 'csv') return 'csv'
  if (extension === 'html' || extension === 'htm') return 'html'
  return 'txt'
}


// Kiro API 工具描述最大长度
const KIRO_MAX_TOOL_DESC_LEN = 10237 // 留出 "..." 的空间

function convertOpenAITools(
  tools: OpenAITool[] | undefined,
  toolNameRegistry: ToolNameRegistry
): KiroToolWrapper[] {
  if (!tools) return []

  return tools.flatMap(tool => {
    let description = tool.function.description || `Tool: ${tool.function.name}`
    // 截断过长的描述
    if (description.length > KIRO_MAX_TOOL_DESC_LEN) {
      description = description.substring(0, KIRO_MAX_TOOL_DESC_LEN) + '...'
    }
    const kiroTool: KiroToolWrapper = {
      toolSpecification: {
        name: shortenToolName(tool.function.name, toolNameRegistry),
        description,
        inputSchema: { json: tool.function.parameters }
      }
    }
    const cachePoint = toKiroCachePoint(tool.cache_control)
    return cachePoint ? [kiroTool, { cachePoint }] : [kiroTool]
  })
}

function shortenToolName(name: string, toolNameRegistry: ToolNameRegistry): string {
  return toolNameRegistry.toKiroName(name)
}

// ============ Kiro -> OpenAI 转换 ============

export function kiroToOpenaiResponse(
  content: string,
  toolUses: KiroToolUse[],
  usage: KiroUsage,
  model: string,
  toolNameRegistry: ToolNameRegistry = new ToolNameRegistry(),
  reasoningContent?: { text?: string; signature?: string; redactedContent?: string }
): OpenAIChatResponse {
  const restoredToolUses = toolNameRegistry.restoreToolUses(toolUses)
  const openaiUsage: OpenAIChatResponse['usage'] = {
    prompt_tokens: usage.inputTokens,
    completion_tokens: usage.outputTokens,
    total_tokens: usage.inputTokens + usage.outputTokens
  }
  if (usage.cacheReadTokens) {
    openaiUsage.prompt_tokens_details = {
      cached_tokens: usage.cacheReadTokens
    }
  }
  if (usage.reasoningTokens) {
    openaiUsage.completion_tokens_details = {
      reasoning_tokens: usage.reasoningTokens
    }
  }
  const response: OpenAIChatResponse = {
    id: `chatcmpl-${uuidv4()}`,
    object: 'chat.completion',
    created: Math.floor(Date.now() / 1000),
    model,
    choices: [{
      index: 0,
      message: {
        role: 'assistant',
        content: (restoredToolUses.length > 0 || !content?.trim()) ? null : content,
        ...(reasoningContent?.text ? { reasoning_content: reasoningContent.text } : {}),
        tool_calls: restoredToolUses.length > 0 ? restoredToolUses.map(tu => ({
          id: tu.toolUseId,
          type: 'function' as const,
          function: {
            name: tu.name,
            arguments: JSON.stringify(tu.input)
          }
        })) : undefined
      },
      finish_reason: restoredToolUses.length > 0 ? 'tool_calls' : 'stop'
    }],
    usage: openaiUsage
  }

  return response
}

export interface OpenAIUsage {
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

export function createOpenaiStreamChunk(
  id: string,
  model: string,
  delta: { role?: 'assistant'; content?: string; reasoning_content?: string; tool_calls?: { index: number; id?: string; type?: 'function'; function?: { name?: string; arguments?: string } }[] },
  finishReason: 'stop' | 'tool_calls' | null = null,
  usage?: OpenAIUsage
): OpenAIStreamChunk & { usage?: OpenAIUsage } {
  const chunk: OpenAIStreamChunk & { usage?: OpenAIUsage } = {
    id,
    object: 'chat.completion.chunk',
    created: Math.floor(Date.now() / 1000),
    model,
    choices: [{
      index: 0,
      delta: delta as OpenAIStreamChunk['choices'][0]['delta'],
      finish_reason: finishReason
    }]
  }
  if (usage) {
    chunk.usage = usage
  }
  return chunk
}

// ============ Claude -> Kiro 转换 ============

export function claudeToKiro(
  request: ClaudeRequest,
  profileArn?: string,
  toolNameRegistry: ToolNameRegistry = new ToolNameRegistry(),
  thinkingConfig?: ThinkingConfig
): KiroPayload {
  const modelId = mapModelId(request.model)
  const origin = 'AI_EDITOR'

  // 提取系统提示
  let systemPrompt = ''
  let systemCachePoint: KiroCachePoint | undefined
  if (typeof request.system === 'string') {
    systemPrompt = request.system
  } else if (Array.isArray(request.system)) {
    systemPrompt = request.system.map(b => {
      systemCachePoint = mergeCachePoint(systemCachePoint, toKiroCachePoint(b.cache_control))
      return b.text
    }).join('\n')
  }

  // 注入时间戳
  const timestamp = new Date().toISOString()
  systemPrompt = `[Context: Current time is ${timestamp}]\n\n${systemPrompt}`

  // 注入执行导向指令（防止 AI 在探索过程中丢失目标）
  const executionDirective = `
<execution_discipline>
当用户要求执行特定任务时，你必须遵循以下纪律：
1. **目标锁定**：在整个会话中始终牢记用户的原始目标，不要在代码探索过程中迷失方向
2. **行动优先**：优先执行任务而非仅分析或总结，除非用户明确只要求分析
3. **计划执行**：为任务创建明确的步骤计划，逐步执行并标记完成状态
4. **禁止确认性收尾**：在任务未完成前，禁止输出"需要我继续吗？"、"需要深入分析吗？"等确认性问题
5. **持续推进**：如果发现部分任务已完成，立即继续执行剩余未完成的任务
6. **完整交付**：直到所有任务步骤都执行完毕才算完成
</execution_discipline>
`
  systemPrompt = systemPrompt + '\n\n' + executionDirective

  // 构建历史消息 - Kiro API 要求严格的 user -> assistant 交替
  const history: KiroHistoryMessage[] = []
  let currentToolResults: KiroToolResult[] = []  // 只保存最后一条消息的 toolResults
  let currentContent = ''
  let currentCachePoint: KiroCachePoint | undefined
  const images: KiroImage[] = []
  const documents: KiroDocument[] = []

  // 临时存储，用于合并连续的同类型消息
  let pendingUserContent = ''
  let pendingUserImages: KiroImage[] = []
  let pendingUserDocuments: KiroDocument[] = []
  let pendingToolResults: KiroToolResult[] = []
  let pendingUserCachePoint: KiroCachePoint | undefined

  for (let i = 0; i < request.messages.length; i++) {
    const msg = request.messages[i]
    const isLast = i === request.messages.length - 1

    if (msg.role === 'user') {
      const { content: userContent, images: userImages, documents: userDocuments, toolResults: userToolResults, cachePoint: userCachePoint } = extractClaudeContent(msg)

      if (isLast) {
        // 最后一条消息：合并之前的 pending 内容，toolResults 放入 currentMessage
        currentContent = pendingUserContent ? pendingUserContent + '\n' + userContent : userContent
        images.push(...pendingUserImages, ...userImages)
        documents.push(...pendingUserDocuments, ...userDocuments)
        currentToolResults = [...pendingToolResults, ...userToolResults]
        currentCachePoint = mergeCachePoint(pendingUserCachePoint, userCachePoint)
        pendingUserContent = ''
        pendingUserImages = []
        pendingUserDocuments = []
        pendingToolResults = []
        pendingUserCachePoint = undefined
      } else {
        // 非最后一条：检查下一条是否是 assistant
        const nextMsg = request.messages[i + 1]
        if (nextMsg && nextMsg.role === 'assistant') {
          // 下一条是 assistant，可以安全添加到 history
          const finalUserContent = pendingUserContent ? pendingUserContent + '\n' + userContent : userContent
          const finalUserImages = [...pendingUserImages, ...userImages]
          const finalUserDocuments = [...pendingUserDocuments, ...userDocuments]
          const finalToolResults = [...pendingToolResults, ...userToolResults]
          const finalCachePoint = mergeCachePoint(pendingUserCachePoint, userCachePoint)
          
          if (finalUserContent.trim() || finalUserImages.length > 0 || finalUserDocuments.length > 0 || finalToolResults.length > 0) {
            const userInputMessage: KiroUserInputMessage = {
              content: finalUserContent || (finalToolResults.length > 0 ? 'Tool results provided.' : 'Continue'),
              modelId,
              origin,
              images: finalUserImages.length > 0 ? finalUserImages : undefined,
              documents: finalUserDocuments.length > 0 ? finalUserDocuments : undefined,
              ...(finalCachePoint ? { cachePoint: finalCachePoint } : {})
            }
            // 如果有 toolResults，放入 userInputMessageContext
            if (finalToolResults.length > 0) {
              userInputMessage.userInputMessageContext = {
                toolResults: finalToolResults
              }
            }
            history.push({ userInputMessage })
          }
          pendingUserContent = ''
          pendingUserImages = []
          pendingUserDocuments = []
          pendingToolResults = []
          pendingUserCachePoint = undefined
        } else {
          // 下一条不是 assistant（可能是连续 user 或结束），累积内容
          pendingUserContent = pendingUserContent ? pendingUserContent + '\n' + userContent : userContent
          pendingUserImages.push(...userImages)
          pendingUserDocuments.push(...userDocuments)
          pendingToolResults.push(...userToolResults)
          pendingUserCachePoint = mergeCachePoint(pendingUserCachePoint, userCachePoint)
        }
      }
    } else if (msg.role === 'assistant') {
      // 注意: 故意丢弃 reasoningContent (history 中不传给 Kiro)
      // Kiro 后端 schema 仅在响应输出中支持 assistantResponseMessage.reasoningContent，
      // 在请求 history 中传入此字段会触发 400 "Improperly formed request"
      // 当前消息的 thinking 开关由 additionalModelRequestFields.thinking 控制
      const { content: assistantContent, toolUses } = extractClaudeAssistantContent(msg, toolNameRegistry)

      // 如果有 pending 的 user 内容但还没添加到 history，先添加
      if (pendingUserContent.trim() || pendingUserImages.length > 0 || pendingUserDocuments.length > 0 || pendingToolResults.length > 0) {
        const userInputMessage: KiroUserInputMessage = {
          content: pendingUserContent || (pendingToolResults.length > 0 ? 'Tool results provided.' : 'Continue'),
          modelId,
          origin,
          images: pendingUserImages.length > 0 ? pendingUserImages : undefined,
          documents: pendingUserDocuments.length > 0 ? pendingUserDocuments : undefined,
          ...(pendingUserCachePoint ? { cachePoint: pendingUserCachePoint } : {})
        }
        if (pendingToolResults.length > 0) {
          userInputMessage.userInputMessageContext = {
            toolResults: pendingToolResults
          }
        }
        history.push({ userInputMessage })
        pendingUserContent = ''
        pendingUserImages = []
        pendingUserDocuments = []
        pendingToolResults = []
        pendingUserCachePoint = undefined
      }

      const assistantResponseMessage = {
        content: assistantContent,
        ...(toolUses.length > 0 ? { toolUses } : {})
      }
      history.push({ assistantResponseMessage })
    }
  }

  // 处理剩余的 pending 内容（如果最后几条都是 user 且不是 isLast）
  if (pendingUserContent.trim() || pendingUserImages.length > 0 || pendingUserDocuments.length > 0 || pendingToolResults.length > 0) {
    currentContent = pendingUserContent + (currentContent ? '\n' + currentContent : '')
    images.unshift(...pendingUserImages)
    documents.unshift(...pendingUserDocuments)
    currentToolResults = [...pendingToolResults, ...currentToolResults]
    currentCachePoint = mergeCachePoint(pendingUserCachePoint, currentCachePoint)
  }

  // 确保 history 以 user 开始（Kiro API 要求）
  // 如果 history 以 assistant 开始，在前面插入一个空的 user 消息
  if (history.length > 0 && history[0].assistantResponseMessage) {
    history.unshift({
      userInputMessage: {
        content: 'Begin conversation',
        modelId,
        origin
      }
    })
  }

  // 构建最终内容
  // System prompt 以 Kiro 官方方式注入：作为 Human/AI pair 插入到 history 头部
  // 官方 Kiro IDE: [Human(systemPrompt, forcedRole), AI("I will follow these instructions.", forcedRole)]
  if (systemPrompt) {
    const systemMessages: KiroHistoryMessage[] = [
      {
        userInputMessage: {
          content: systemPrompt,
          userInputMessageContext: {},
          origin,
          ...(systemCachePoint ? { cachePoint: systemCachePoint } : {})
        }
      },
      {
        assistantResponseMessage: {
          content: 'I will follow these instructions.'
        }
      }
    ]
    history.unshift(...systemMessages)
  }
  const finalContent = currentContent || (currentToolResults.length > 0 ? 'Tool results provided.' : 'Continue')

  // 转换工具定义
  const kiroTools = convertClaudeTools(request.tools, toolNameRegistry)

  // 将 Claude thinking 参数映射为 Kiro additionalModelRequestFields
  const additionalModelRequestFields = buildThinkingFields(
    thinkingConfig,
    request.thinking as { type: string; budget_tokens?: number; display?: string },
    undefined
  )

  return buildKiroPayload(
    finalContent,
    modelId,
    origin,
    history,
    kiroTools,
    currentToolResults,
    images,
    profileArn,
    {
      maxTokens: request.max_tokens,
      temperature: request.temperature,
      topP: request.top_p
    },
    {
      cachePoint: currentCachePoint,
      documents,
      conversationId: request.conversation_id,
      context: request.kiro_context
    },
    additionalModelRequestFields
  )
}

function extractClaudeContent(msg: ClaudeMessage): { content: string; images: KiroImage[]; documents: KiroDocument[]; toolResults: KiroToolResult[]; cachePoint?: KiroCachePoint } {
  const images: KiroImage[] = []
  const documents: KiroDocument[] = []
  const toolResults: KiroToolResult[] = []
  let content = ''
  let cachePoint = toKiroCachePoint(msg.cache_control)

  if (typeof msg.content === 'string') {
    content = msg.content
  } else if (Array.isArray(msg.content)) {
    for (const block of msg.content) {
      cachePoint = mergeCachePoint(cachePoint, toKiroCachePoint(block.cache_control))
      if (block.type === 'text' && block.text) {
        content += block.text
      } else if (block.type === 'image' && block.source?.type === 'base64') {
        const mediaTypeParts = block.source.media_type.split('/')
        const imageFormat = mediaTypeParts[1]
        if (mediaTypeParts[0] !== 'image' || !imageFormat) {
          throw new Error(`Unsupported image media_type: ${block.source.media_type}`)
        }
        images.push({
          format: normalizeImageFormat(imageFormat),
          source: { bytes: block.source.data }
        })
      } else if (block.type === 'document' && block.source) {
        if (!block.name) {
          throw new Error('document requires name')
        }
        documents.push(parseClaudeDocumentSource(block.source, block.name))
      } else if (block.type === 'tool_result' && block.tool_use_id) {
        let resultContent = ''
        // Kiro tool_result.content 只支持 text，但用户层 images 可以承载图片。
        // 把内嵌 image block 提取到外层 images，避免「读取本地图片」这类场景图像内容被静默丢弃。
        let extractedImageCount = 0
        if (typeof block.content === 'string') {
          resultContent = block.content || '(empty)'
        } else if (Array.isArray(block.content)) {
          const textParts: string[] = []
          for (const b of block.content) {
            if (b.type === 'text') {
              textParts.push(b.text || '')
            } else if (b.type === 'image' && b.source?.type === 'base64' && b.source.data) {
              const mediaTypeParts = (b.source.media_type || '').split('/')
              const imageFormat = mediaTypeParts[1]
              if (mediaTypeParts[0] === 'image' && imageFormat) {
                try {
                  images.push({
                    format: normalizeImageFormat(imageFormat),
                    source: { bytes: b.source.data }
                  })
                  extractedImageCount++
                } catch {
                  // 不支持的格式：跳过但不抛错（保留旧行为，避免整轮失败）
                }
              }
            }
          }
          resultContent = textParts.join('')
          if (!resultContent) {
            resultContent = extractedImageCount > 0
              ? `(tool returned ${extractedImageCount} image${extractedImageCount > 1 ? 's' : ''}, attached to this message)`
              : '(no text output)'
          } else if (extractedImageCount > 0) {
            // 既有文本又有图片：在文本末尾提示模型有附图
            resultContent += `\n\n[Tool also returned ${extractedImageCount} image${extractedImageCount > 1 ? 's' : ''}, attached to this message]`
          }
        } else if (block.content === undefined || block.content === null) {
          resultContent = '(no output)'
        } else {
          resultContent = String(block.content) || '(empty)'
        }
        toolResults.push({
          toolUseId: block.tool_use_id,
          content: [{ text: resultContent }],
          status: 'success'
        })
      }
    }
  }

  return { content, images, documents, toolResults, cachePoint }
}

function extractClaudeAssistantContent(
  msg: ClaudeMessage,
  toolNameRegistry: ToolNameRegistry
): { content: string; toolUses: KiroToolUse[]; reasoningContent?: KiroReasoningContent } {
  const toolUses: KiroToolUse[] = []
  let content = ''
  let thinking = ''
  let signature: string | undefined
  let redactedContent: string | undefined

  if (typeof msg.content === 'string') {
    content = msg.content
  } else if (Array.isArray(msg.content)) {
    for (const block of msg.content) {
      if (block.type === 'text' && block.text) {
        content += block.text
      } else if (block.type === 'thinking' && block.thinking) {
        thinking += block.thinking
        signature = block.signature || signature
      } else if (block.type === 'redacted_thinking' && block.data) {
        // redacted_thinking 是加密的思考内容，原样保留
        redactedContent = (redactedContent || '') + block.data
      } else if (block.type === 'tool_use' && block.id && block.name) {
        if (!block.input || typeof block.input !== 'object' || Array.isArray(block.input)) {
          throw new Error(`tool_use requires object input: ${block.name}`)
        }
        toolUses.push({
          toolUseId: block.id,
          name: toolNameRegistry.toKiroName(block.name),
          input: block.input as Record<string, unknown>
        })
      }
    }
  }

  // Kiro API 要求 content 非空
  if (!content.trim() && toolUses.length > 0) {
    content = ' '
  }

  if (thinking || redactedContent) {
    const reasoningContent: KiroReasoningContent = {}
    if (thinking) {
      reasoningContent.reasoningText = signature ? { text: thinking, signature } : { text: thinking }
    }
    if (redactedContent) {
      reasoningContent.redactedContent = redactedContent
    }
    return { content, toolUses, reasoningContent }
  }

  return { content, toolUses }
}

function convertClaudeTools(
  tools: { name: string; description: string; input_schema: unknown; cache_control?: { type: string } }[] | undefined,
  toolNameRegistry: ToolNameRegistry
): KiroToolWrapper[] {
  if (!tools) return []

  return tools.flatMap(tool => {
    let description = tool.description || `Tool: ${tool.name}`
    // 截断过长的描述
    if (description.length > KIRO_MAX_TOOL_DESC_LEN) {
      description = description.substring(0, KIRO_MAX_TOOL_DESC_LEN) + '...'
    }
    const kiroTool: KiroToolWrapper = {
      toolSpecification: {
        name: shortenToolName(tool.name, toolNameRegistry),
        description,
        inputSchema: { json: tool.input_schema }
      }
    }
    const cachePoint = toKiroCachePoint(tool.cache_control)
    return cachePoint ? [kiroTool, { cachePoint }] : [kiroTool]
  })
}

// ============ Kiro -> Claude 转换 ============

export function kiroToClaudeResponse(
  content: string,
  toolUses: KiroToolUse[],
  usage: KiroUsage,
  model: string,
  toolNameRegistry: ToolNameRegistry = new ToolNameRegistry(),
  reasoningContent?: { text?: string; signature?: string; redactedContent?: string }
): ClaudeResponse {
  const contentBlocks: ClaudeContentBlock[] = []
  const restoredToolUses = toolNameRegistry.restoreToolUses(toolUses)

  if (reasoningContent?.text) {
    contentBlocks.push(reasoningContent.signature ? {
      type: 'thinking',
      thinking: reasoningContent.text,
      signature: reasoningContent.signature
    } : {
      type: 'thinking',
      thinking: reasoningContent.text
    })
  }
  if (reasoningContent?.redactedContent) {
    contentBlocks.push({
      type: 'redacted_thinking',
      data: reasoningContent.redactedContent
    })
  }

  // 仅在有实际文本内容时添加 text block
  if (content && content.trim()) {
    contentBlocks.push({ type: 'text', text: content })
  }

  for (const tu of restoredToolUses) {
    contentBlocks.push({
      type: 'tool_use',
      id: tu.toolUseId,
      name: tu.name,
      input: tu.input
    })
  }

  const claudeUsage: ClaudeResponse['usage'] = {
    input_tokens: usage.inputTokens,
    output_tokens: usage.outputTokens
  }
  if (usage.cacheWriteTokens) {
    claudeUsage.cache_creation_input_tokens = usage.cacheWriteTokens
  }
  if (usage.cacheReadTokens) {
    claudeUsage.cache_read_input_tokens = usage.cacheReadTokens
  }

  const response: ClaudeResponse = {
    id: `msg_${uuidv4()}`,
    type: 'message',
    role: 'assistant',
    content: contentBlocks,
    model,
    stop_reason: restoredToolUses.length > 0 ? 'tool_use' : 'end_turn',
    stop_sequence: null,
    usage: claudeUsage
  }
  return response
}

export function createClaudeStreamEvent(
  type: ClaudeStreamEvent['type'],
  data?: Partial<ClaudeStreamEvent>
): ClaudeStreamEvent {
  return { type, ...data } as ClaudeStreamEvent
}
