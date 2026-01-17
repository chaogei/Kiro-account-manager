// OpenAI/Claude 格式与 Kiro 格式转换器
import { v4 as uuidv4 } from 'uuid'
import type {
  OpenAIChatRequest,
  OpenAIMessage,
  OpenAITool,
  OpenAIChatResponse,
  OpenAIStreamChunk,
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
  KiroToolUse
} from './types'
import { buildKiroPayload, mapModelId } from './kiroApi'

// ============ OpenAI -> Kiro 转换 ============

export function openaiToKiro(
  request: OpenAIChatRequest,
  profileArn?: string
): KiroPayload {
  const modelId = mapModelId(request.model)
  const origin = 'AI_EDITOR'

  // 提取系统提示
  let systemPrompt = ''
  const nonSystemMessages: OpenAIMessage[] = []

  for (const msg of request.messages) {
    if (msg.role === 'system') {
      if (typeof msg.content === 'string') {
        systemPrompt += (systemPrompt ? '\n' : '') + msg.content
      } else if (Array.isArray(msg.content)) {
        for (const part of msg.content) {
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

  // 构建历史消息
  const history: KiroHistoryMessage[] = []
  const toolResults: KiroToolResult[] = []
  let currentContent = ''
  const images: KiroImage[] = []

  for (let i = 0; i < nonSystemMessages.length; i++) {
    const msg = nonSystemMessages[i]
    const isLast = i === nonSystemMessages.length - 1

    if (msg.role === 'user') {
      const { content: userContent, images: userImages } = extractOpenAIContent(msg)
      
      if (isLast) {
        currentContent = userContent
        images.push(...userImages)
      } else {
        history.push({
          userInputMessage: {
            content: userContent || 'Continue',
            modelId,
            origin,
            images: userImages.length > 0 ? userImages : undefined
          }
        })
      }
    } else if (msg.role === 'assistant') {
      // Kiro API 要求 content 非空
      let assistantContent = typeof msg.content === 'string' ? msg.content : ''
      if (!assistantContent.trim() && msg.tool_calls && msg.tool_calls.length > 0) {
        assistantContent = 'Using tools.'
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
              name: tc.function.name,
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
      // Tool result
      if (msg.tool_call_id) {
        toolResults.push({
          toolUseId: msg.tool_call_id,
          content: [{ text: typeof msg.content === 'string' ? msg.content : JSON.stringify(msg.content) }],
          status: 'success'
        })
      }
    }
  }

  // 如果没有当前内容但有工具结果，创建一个占位内容
  if (!currentContent && toolResults.length > 0) {
    currentContent = 'Tool results provided.'
  }

  // 构建最终内容
  let finalContent = ''
  if (systemPrompt) {
    finalContent = `--- SYSTEM PROMPT ---\n${systemPrompt}\n--- END SYSTEM PROMPT ---\n\n`
  }
  finalContent += currentContent || 'Continue'

  // 转换工具定义
  const kiroTools = convertOpenAITools(request.tools)

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
    }
  )
}

function extractOpenAIContent(msg: OpenAIMessage): { content: string; images: KiroImage[] } {
  const images: KiroImage[] = []
  let content = ''

  if (typeof msg.content === 'string') {
    content = msg.content
  } else if (Array.isArray(msg.content)) {
    for (const part of msg.content) {
      if (part.type === 'text' && part.text) {
        content += part.text
      } else if (part.type === 'image_url' && part.image_url?.url) {
        const image = parseImageUrl(part.image_url.url)
        if (image) {
          images.push(image)
        }
      }
    }
  }

  return { content, images }
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
  } else if (url.startsWith('http://') || url.startsWith('https://')) {
    // HTTP URL - 需要异步下载，这里先记录 URL
    // 实际下载会在请求处理时进行
    console.log(`[Translator] Image URL detected: ${url.substring(0, 50)}...`)
    // TODO: 实现异步图像下载
  }
  return null
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
  return formatMap[lower] || 'png'
}

// Kiro API 工具描述最大长度
const KIRO_MAX_TOOL_DESC_LEN = 10237 // 留出 "..." 的空间

function convertOpenAITools(tools?: OpenAITool[]): KiroToolWrapper[] {
  if (!tools) return []

  return tools.map(tool => {
    let description = tool.function.description || `Tool: ${tool.function.name}`
    // 截断过长的描述
    if (description.length > KIRO_MAX_TOOL_DESC_LEN) {
      description = description.substring(0, KIRO_MAX_TOOL_DESC_LEN) + '...'
    }
    return {
      toolSpecification: {
        name: shortenToolName(tool.function.name),
        description,
        inputSchema: { json: tool.function.parameters }
      }
    }
  })
}

function shortenToolName(name: string): string {
  const limit = 64
  if (name.length <= limit) return name
  
  // MCP tools: mcp__server__tool -> mcp__tool
  if (name.startsWith('mcp__')) {
    const lastIdx = name.lastIndexOf('__')
    if (lastIdx > 5) {
      const shortened = 'mcp__' + name.substring(lastIdx + 2)
      return shortened.length > limit ? shortened.substring(0, limit) : shortened
    }
  }
  
  return name.substring(0, limit)
}

// ============ Kiro -> OpenAI 转换 ============

export function kiroToOpenaiResponse(
  content: string,
  toolUses: KiroToolUse[],
  usage: { inputTokens: number; outputTokens: number },
  model: string
): OpenAIChatResponse {
  const response: OpenAIChatResponse = {
    id: `chatcmpl-${uuidv4()}`,
    object: 'chat.completion',
    created: Math.floor(Date.now() / 1000),
    model,
    choices: [{
      index: 0,
      message: {
        role: 'assistant',
        content: toolUses.length > 0 ? null : content,
        tool_calls: toolUses.length > 0 ? toolUses.map(tu => ({
          id: tu.toolUseId,
          type: 'function' as const,
          function: {
            name: tu.name,
            arguments: JSON.stringify(tu.input)
          }
        })) : undefined
      },
      finish_reason: toolUses.length > 0 ? 'tool_calls' : 'stop'
    }],
    usage: {
      prompt_tokens: usage.inputTokens,
      completion_tokens: usage.outputTokens,
      total_tokens: usage.inputTokens + usage.outputTokens
    }
  }

  return response
}

export function createOpenaiStreamChunk(
  id: string,
  model: string,
  delta: { role?: 'assistant'; content?: string; tool_calls?: { index: number; id?: string; type?: 'function'; function?: { name?: string; arguments?: string } }[] },
  finishReason: 'stop' | 'tool_calls' | null = null
): OpenAIStreamChunk {
  return {
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
}

// ============ Claude -> Kiro 转换 ============

export function claudeToKiro(
  request: ClaudeRequest,
  profileArn?: string
): KiroPayload {
  const modelId = mapModelId(request.model)
  const origin = 'AI_EDITOR'

  // 提取系统提示
  let systemPrompt = ''
  if (typeof request.system === 'string') {
    systemPrompt = request.system
  } else if (Array.isArray(request.system)) {
    systemPrompt = request.system.map(b => b.text).join('\n')
  }

  // 注入时间戳
  const timestamp = new Date().toISOString()
  systemPrompt = `[Context: Current time is ${timestamp}]\n\n${systemPrompt}`

  // 构建历史消息
  const history: KiroHistoryMessage[] = []
  const toolResults: KiroToolResult[] = []
  let currentContent = ''
  const images: KiroImage[] = []

  for (let i = 0; i < request.messages.length; i++) {
    const msg = request.messages[i]
    const isLast = i === request.messages.length - 1

    if (msg.role === 'user') {
      const { content: userContent, images: userImages, toolResults: userToolResults } = extractClaudeContent(msg)
      toolResults.push(...userToolResults)

      if (isLast) {
        currentContent = userContent
        images.push(...userImages)
      } else {
        history.push({
          userInputMessage: {
            content: userContent || 'Continue',
            modelId,
            origin,
            images: userImages.length > 0 ? userImages : undefined
          }
        })
      }
    } else if (msg.role === 'assistant') {
      const { content: assistantContent, toolUses } = extractClaudeAssistantContent(msg)

      history.push({
        assistantResponseMessage: {
          content: assistantContent,
          toolUses: toolUses.length > 0 ? toolUses : undefined
        }
      })
    }
  }

  // 构建最终内容
  let finalContent = ''
  if (systemPrompt) {
    finalContent = `--- SYSTEM PROMPT ---\n${systemPrompt}\n--- END SYSTEM PROMPT ---\n\n`
  }
  finalContent += currentContent || 'Continue'

  // 转换工具定义
  const kiroTools = convertClaudeTools(request.tools)

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
    }
  )
}

function extractClaudeContent(msg: ClaudeMessage): { content: string; images: KiroImage[]; toolResults: KiroToolResult[] } {
  const images: KiroImage[] = []
  const toolResults: KiroToolResult[] = []
  let content = ''

  if (typeof msg.content === 'string') {
    content = msg.content
  } else if (Array.isArray(msg.content)) {
    for (const block of msg.content) {
      if (block.type === 'text' && block.text) {
        content += block.text
      } else if (block.type === 'image' && block.source) {
        images.push({
          format: block.source.media_type.split('/')[1] || 'png',
          source: { bytes: block.source.data }
        })
      } else if (block.type === 'tool_result' && block.tool_use_id) {
        let resultContent = ''
        if (typeof block.content === 'string') {
          resultContent = block.content
        } else if (Array.isArray(block.content)) {
          resultContent = block.content.map(b => b.text || '').join('')
        }
        toolResults.push({
          toolUseId: block.tool_use_id,
          content: [{ text: resultContent }],
          status: 'success'
        })
      }
    }
  }

  return { content, images, toolResults }
}

function extractClaudeAssistantContent(msg: ClaudeMessage): { content: string; toolUses: KiroToolUse[] } {
  const toolUses: KiroToolUse[] = []
  let content = ''

  if (typeof msg.content === 'string') {
    content = msg.content
  } else if (Array.isArray(msg.content)) {
    for (const block of msg.content) {
      if (block.type === 'text' && block.text) {
        content += block.text
      } else if (block.type === 'tool_use' && block.id && block.name) {
        toolUses.push({
          toolUseId: block.id,
          name: block.name,
          input: (block.input as Record<string, unknown>) || {}
        })
      }
    }
  }

  return { content, toolUses }
}

function convertClaudeTools(tools?: { name: string; description: string; input_schema: unknown }[]): KiroToolWrapper[] {
  if (!tools) return []

  return tools.map(tool => ({
    toolSpecification: {
      name: shortenToolName(tool.name),
      description: tool.description || `Tool: ${tool.name}`,
      inputSchema: { json: tool.input_schema }
    }
  }))
}

// ============ Kiro -> Claude 转换 ============

export function kiroToClaudeResponse(
  content: string,
  toolUses: KiroToolUse[],
  usage: { inputTokens: number; outputTokens: number },
  model: string
): ClaudeResponse {
  const contentBlocks: ClaudeContentBlock[] = []

  if (content) {
    contentBlocks.push({ type: 'text', text: content })
  }

  for (const tu of toolUses) {
    contentBlocks.push({
      type: 'tool_use',
      id: tu.toolUseId,
      name: tu.name,
      input: tu.input
    })
  }

  return {
    id: `msg_${uuidv4()}`,
    type: 'message',
    role: 'assistant',
    content: contentBlocks,
    model,
    stop_reason: toolUses.length > 0 ? 'tool_use' : 'end_turn',
    stop_sequence: null,
    usage: {
      input_tokens: usage.inputTokens,
      output_tokens: usage.outputTokens
    }
  }
}

export function createClaudeStreamEvent(
  type: ClaudeStreamEvent['type'],
  data?: Partial<ClaudeStreamEvent>
): ClaudeStreamEvent {
  return { type, ...data } as ClaudeStreamEvent
}
