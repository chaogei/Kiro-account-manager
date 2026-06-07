/**
 * Steering 文件加载器：读取工作区 .kiro/steering/*.md 并解析为可注入的规则文本。
 *
 * Steering 文件支持三种包含模式（通过 YAML frontmatter 指定）：
 *   - always（默认）— 每次请求都注入
 *   - fileMatch — 当请求涉及匹配 fileMatchPattern 的文件时注入
 *   - manual — 仅用户显式引用时注入（反代默认跳过）
 */
import * as fs from 'fs'
import * as path from 'path'

export interface SteeringDocument {
  /** 文件名（不含路径） */
  name: string
  /** frontmatter 指定的包含模式 */
  inclusion: 'always' | 'fileMatch' | 'manual'
  /** fileMatch 模式下的匹配 glob */
  fileMatchPattern?: string
  /** 正文内容（去除 frontmatter 后） */
  content: string
}

/**
 * 从工作区路径加载所有 steering 文件。
 * 返回按 inclusion 分类的文档列表（always 优先）。
 */
export function loadSteeringDocuments(workspacePath: string): SteeringDocument[] {
  const steeringDir = path.join(workspacePath, '.kiro', 'steering')
  if (!fs.existsSync(steeringDir)) return []

  const files = fs.readdirSync(steeringDir).filter(f => f.endsWith('.md'))
  const docs: SteeringDocument[] = []

  for (const file of files) {
    try {
      const fullPath = path.join(steeringDir, file)
      const raw = fs.readFileSync(fullPath, 'utf-8')
      const { frontmatter, content } = parseFrontmatter(raw)

      docs.push({
        name: file,
        inclusion: (frontmatter.inclusion as SteeringDocument['inclusion']) || 'always',
        fileMatchPattern: frontmatter.fileMatchPattern as string | undefined,
        content: content.trim()
      })
    } catch (e) {
      console.warn(`[Steering] Failed to read ${file}:`, e)
    }
  }

  // always 排前面
  docs.sort((a, b) => {
    if (a.inclusion === 'always' && b.inclusion !== 'always') return -1
    if (a.inclusion !== 'always' && b.inclusion === 'always') return 1
    return 0
  })

  return docs
}

/**
 * 将 steering 文档列表格式化为可注入到 system prompt 的文本。
 * 仅包含 inclusion=always 的文档（反代没有 file context 信息，无法判断 fileMatch）。
 */
export function formatSteeringForPrompt(docs: SteeringDocument[]): string {
  const alwaysDocs = docs.filter(d => d.inclusion === 'always')
  if (alwaysDocs.length === 0) return ''

  const parts = alwaysDocs.map(d => `<!-- steering: ${d.name} -->\n${d.content}`)
  return `<steering-files>\n${parts.join('\n\n')}\n</steering-files>`
}

/**
 * 解析简单 YAML frontmatter（--- 分隔的 key: value 块）。
 */
function parseFrontmatter(raw: string): { frontmatter: Record<string, string>; content: string } {
  const frontmatter: Record<string, string> = {}

  if (!raw.startsWith('---')) {
    return { frontmatter, content: raw }
  }

  const endIdx = raw.indexOf('\n---', 3)
  if (endIdx === -1) {
    return { frontmatter, content: raw }
  }

  const fmBlock = raw.slice(4, endIdx)
  const content = raw.slice(endIdx + 4)

  for (const line of fmBlock.split('\n')) {
    const colonIdx = line.indexOf(':')
    if (colonIdx > 0) {
      const key = line.slice(0, colonIdx).trim()
      const value = line.slice(colonIdx + 1).trim().replace(/^['"]|['"]$/g, '')
      if (key && value) frontmatter[key] = value
    }
  }

  return { frontmatter, content }
}
