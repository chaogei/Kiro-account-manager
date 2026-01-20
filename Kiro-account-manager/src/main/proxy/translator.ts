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
  KiroToolUse,
  KiroUserInputMessage
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

  // 构建历史消息（参考 Proxycast 实现）
  const history: KiroHistoryMessage[] = []
  const toolResults: KiroToolResult[] = []
  let currentContent = ''
  const images: KiroImage[] = []
  let systemPromptMerged = false // 标记 system prompt 是否已合并

  for (let i = 0; i < nonSystemMessages.length; i++) {
    const msg = nonSystemMessages[i]
    const isLast = i === nonSystemMessages.length - 1

    if (msg.role === 'user') {
      const { content: userContent, images: userImages } = extractOpenAIContent(msg)
      
      // 第一条 user 消息合并 system prompt（参考 Proxycast）
      let mergedContent = userContent || 'Continue'
      if (!systemPromptMerged && systemPrompt) {
        mergedContent = `${systemPrompt}\n\n${mergedContent}`
        systemPromptMerged = true
      }
      
      if (isLast) {
        currentContent = mergedContent
        images.push(...userImages)
      } else {
        history.push({
          userInputMessage: {
            content: mergedContent,
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
      // Tool result - 收集到待处理列表
      if (msg.tool_call_id) {
        toolResults.push({
          toolUseId: msg.tool_call_id,
          content: [{ text: typeof msg.content === 'string' ? msg.content : JSON.stringify(msg.content) }],
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

  // 如果 system prompt 还未合并（没有 user 消息），直接作为 currentContent
  let finalContent = currentContent || 'Continue.'
  if (!systemPromptMerged && systemPrompt) {
    finalContent = `${systemPrompt}\n\n${finalContent}`
  }

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

  // 构建历史消息 - Kiro API 要求严格的 user -> assistant 交替
  const history: KiroHistoryMessage[] = []
  let currentToolResults: KiroToolResult[] = []  // 只保存最后一条消息的 toolResults
  let currentContent = ''
  const images: KiroImage[] = []

  // 临时存储，用于合并连续的同类型消息
  let pendingUserContent = ''
  let pendingUserImages: KiroImage[] = []
  let pendingToolResults: KiroToolResult[] = []

  for (let i = 0; i < request.messages.length; i++) {
    const msg = request.messages[i]
    const isLast = i === request.messages.length - 1

    if (msg.role === 'user') {
      const { content: userContent, images: userImages, toolResults: userToolResults } = extractClaudeContent(msg)

      if (isLast) {
        // 最后一条消息：合并之前的 pending 内容，toolResults 放入 currentMessage
        currentContent = pendingUserContent ? pendingUserContent + '\n' + userContent : userContent
        images.push(...pendingUserImages, ...userImages)
        currentToolResults = [...pendingToolResults, ...userToolResults]
        pendingUserContent = ''
        pendingUserImages = []
        pendingToolResults = []
      } else {
        // 非最后一条：检查下一条是否是 assistant
        const nextMsg = request.messages[i + 1]
        if (nextMsg && nextMsg.role === 'assistant') {
          // 下一条是 assistant，可以安全添加到 history
          const finalUserContent = pendingUserContent ? pendingUserContent + '\n' + userContent : userContent
          const finalUserImages = [...pendingUserImages, ...userImages]
          const finalToolResults = [...pendingToolResults, ...userToolResults]
          
          if (finalUserContent.trim() || finalUserImages.length > 0 || finalToolResults.length > 0) {
            const userInputMessage: KiroUserInputMessage = {
              content: finalUserContent || (finalToolResults.length > 0 ? 'Tool results provided.' : 'Continue'),
              modelId,
              origin,
              images: finalUserImages.length > 0 ? finalUserImages : undefined
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
          pendingToolResults = []
        } else {
          // 下一条不是 assistant（可能是连续 user 或结束），累积内容
          pendingUserContent = pendingUserContent ? pendingUserContent + '\n' + userContent : userContent
          pendingUserImages.push(...userImages)
          pendingToolResults.push(...userToolResults)
        }
      }
    } else if (msg.role === 'assistant') {
      const { content: assistantContent, toolUses } = extractClaudeAssistantContent(msg)

      // 如果有 pending 的 user 内容但还没添加到 history，先添加
      if (pendingUserContent.trim() || pendingUserImages.length > 0 || pendingToolResults.length > 0) {
        const userInputMessage: KiroUserInputMessage = {
          content: pendingUserContent || (pendingToolResults.length > 0 ? 'Tool results provided.' : 'Continue'),
          modelId,
          origin,
          images: pendingUserImages.length > 0 ? pendingUserImages : undefined
        }
        if (pendingToolResults.length > 0) {
          userInputMessage.userInputMessageContext = {
            toolResults: pendingToolResults
          }
        }
        history.push({ userInputMessage })
        pendingUserContent = ''
        pendingUserImages = []
        pendingToolResults = []
      }

      history.push({
        assistantResponseMessage: {
          content: assistantContent,
          toolUses: toolUses.length > 0 ? toolUses : undefined
        }
      })
    }
  }

  // 处理剩余的 pending 内容（如果最后几条都是 user 且不是 isLast）
  if (pendingUserContent.trim() || pendingUserImages.length > 0 || pendingToolResults.length > 0) {
    currentContent = pendingUserContent + (currentContent ? '\n' + currentContent : '')
    images.unshift(...pendingUserImages)
    currentToolResults = [...pendingToolResults, ...currentToolResults]
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
  let finalContent = ''
  if (systemPrompt) {
    finalContent = `--- SYSTEM PROMPT ---\n${systemPrompt}\n--- END SYSTEM PROMPT ---\n\n`
  }
  finalContent += currentContent || (currentToolResults.length > 0 ? 'Tool results provided.' : 'Continue')

  // 转换工具定义
  const kiroTools = convertClaudeTools(request.tools)

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

  // Kiro API 要求 content 非空
  if (!content.trim() && toolUses.length > 0) {
    content = 'Using tools.'
  }

  return { content, toolUses }
}

function convertClaudeTools(tools?: { name: string; description: string; input_schema: unknown }[]): KiroToolWrapper[] {
  if (!tools) return []

  return tools.map(tool => {
    let description = tool.description || `Tool: ${tool.name}`
    // 截断过长的描述
    if (description.length > KIRO_MAX_TOOL_DESC_LEN) {
      description = description.substring(0, KIRO_MAX_TOOL_DESC_LEN) + '...'
    }
    return {
      toolSpecification: {
        name: shortenToolName(tool.name),
        description,
        inputSchema: { json: tool.input_schema }
      }
    }
  })
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
