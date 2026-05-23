/**
 * Token 计数工具：使用 js-tiktoken cl100k_base 编码精确计算，
 * 失败时降级到字节系数估算；并提供按模型 ID 查询 context 窗口大小，
 * 以便从 Kiro 后端的 contextUsagePercentage 反推真实 input tokens。
 */
import { getEncoding, type Tiktoken } from 'js-tiktoken'

let encoder: Tiktoken | null = null
let encoderInitFailed = false

/** 懒加载 cl100k_base 编码器（GPT-4/Claude 通用近似） */
function getEncoder(): Tiktoken | null {
  if (encoder) return encoder
  if (encoderInitFailed) return null
  try {
    encoder = getEncoding('cl100k_base')
    return encoder
  } catch (err) {
    console.warn('[TokenCounter] Failed to load cl100k_base encoder:', err)
    encoderInitFailed = true
    return null
  }
}

/**
 * 使用 tiktoken cl100k_base 精确计算 token 数。
 * 兜底：UTF-8 字节数 / 3.0（针对 payload JSON 经验值，误差 ±10%）。
 */
export function countTokens(text: string): number {
  if (!text) return 0
  const enc = getEncoder()
  if (enc) {
    try {
      return enc.encode(text).length
    } catch (err) {
      console.warn('[TokenCounter] encode failed, using fallback:', err)
    }
  }
  return Math.ceil(Buffer.byteLength(text, 'utf-8') / 3.0)
}

// ============ 模型 context 窗口缓存 ============
// 由 proxyServer 在 fetchKiroModels 后通过 setModelContextWindow 填充
// modelId → maxInputTokens
const modelContextWindowCache = new Map<string, number>()

export function setModelContextWindow(modelId: string, maxInputTokens: number): void {
  if (modelId && maxInputTokens > 0) {
    modelContextWindowCache.set(modelId, maxInputTokens)
  }
}

export function getModelContextWindow(modelId: string): number | undefined {
  return modelContextWindowCache.get(modelId)
}

/**
 * 归一化 model ID 用于模糊匹配：
 *   claude-sonnet-4.5                   → claudesonnet45
 *   CLAUDE_SONNET_4_5_20251001_V1_0     → claudesonnet45
 *   claude-3.7-sonnet                   → claude37sonnet
 */
function normalizeModelId(id: string): string {
  return id
    .toLowerCase()
    .replace(/[-._]/g, '')
    .replace(/\d{8}/g, '')   // 移除日期 (20251001)
    .replace(/v\d+$/g, '')    // 移除尾部版本号 (v1)
    .replace(/v\d+_\d+$/g, '') // 移除 v1_0 形式
}

/**
 * 从缓存中按模糊匹配查找 context window。
 * 例如：用户传 alias `claude-sonnet-4.5`，但 cache 里存的是 CW 内部 ID
 * `CLAUDE_SONNET_4_5_20251001_V1_0`，归一化后都是 `claudesonnet45`。
 */
function guessContextFromCache(modelId: string): number | undefined {
  if (modelContextWindowCache.size === 0) return undefined
  const queryNorm = normalizeModelId(modelId)
  if (!queryNorm) return undefined

  // 精确归一化匹配
  for (const [id, ctx] of modelContextWindowCache) {
    if (normalizeModelId(id) === queryNorm) return ctx
  }
  // 双向子串匹配（处理别名简短形式）
  for (const [id, ctx] of modelContextWindowCache) {
    const idNorm = normalizeModelId(id)
    if (idNorm.includes(queryNorm) || queryNorm.includes(idNorm)) return ctx
  }
  return undefined
}

/**
 * 根据 model ID 返回 context 窗口大小（用于 contextUsagePercentage 反推 inputTokens）。
 *
 * 优先级：
 *   1. 直接命中 cache（Kiro 真实拉取的 maxInputTokens，最准确）
 *   2. 模糊匹配 cache（处理 alias ↔ CW 内部 ID 映射）
 *   3. 关键词匹配兜底（cache 未填充时）
 */
export function getModelContextLength(modelId: string | undefined | null): number {
  if (!modelId) return 200000

  // 1. 优先用 Kiro 后端真实返回的 maxInputTokens
  const cached = modelContextWindowCache.get(modelId)
  if (cached && cached > 0) return cached

  // 2. 模糊匹配 cache（alias ↔ CW 内部 ID）
  const guessed = guessContextFromCache(modelId)
  if (guessed && guessed > 0) return guessed

  // 3. 关键词匹配兜底（首次请求 cache 未填充时使用）
  const id = modelId.toLowerCase()

  // Claude 系列（默认 200K）
  if (id.includes('claude-opus-4') || id.includes('claude-sonnet-4') || id.includes('claude-haiku-4')) return 200000
  if (id.includes('claude-3-7') || id.includes('claude-3.7')) return 200000
  if (id.includes('claude-3-5') || id.includes('claude-3.5')) return 200000
  if (id.includes('claude-3')) return 200000
  if (id.includes('claude-2.1')) return 200000
  if (id.includes('claude-2')) return 100000
  if (id.includes('claude-instant')) return 100000

  // GPT 系列
  if (id.includes('gpt-4o') || id.includes('gpt-4-turbo')) return 128000
  if (id.includes('gpt-4.1')) return 1000000
  if (id.includes('gpt-4-32k')) return 32768
  if (id.includes('gpt-4')) return 8192
  if (id.includes('gpt-3.5-turbo-16k')) return 16384
  if (id.includes('gpt-3.5')) return 4096
  if (id.includes('o1') || id.includes('o3')) return 128000

  // Gemini 系列
  if (id.includes('gemini-2.5') || id.includes('gemini-2.0') || id.includes('gemini-1.5')) return 1000000
  if (id.includes('gemini')) return 32768

  // Amazon Titan / Nova 系列
  if (id.includes('nova-pro') || id.includes('nova-lite')) return 300000
  if (id.includes('nova-micro')) return 128000
  if (id.includes('titan')) return 8000

  // CodeWhisperer/Q Developer 内部模型一般跟 Claude 看齐
  return 200000
}
