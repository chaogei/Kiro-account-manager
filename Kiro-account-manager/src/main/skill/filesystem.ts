import { access, lstat, readFile, readdir, stat } from 'fs/promises'
import { join, resolve, sep } from 'path'

export interface SkillDirEntry {
  dir: string
  name: string
  description: string
}

export function isPathSafe(basePath: string, targetPath: string): boolean {
  const normalizedBase = resolve(basePath)
  const normalizedTarget = resolve(targetPath)
  return normalizedTarget === normalizedBase || normalizedTarget.startsWith(normalizedBase + sep)
}

export async function pathExists(path: string): Promise<boolean> {
  try {
    await access(path)
    return true
  } catch {
    return false
  }
}

async function isDirectoryOrSymlinkToDirectory(path: string): Promise<boolean> {
  try {
    const st = await lstat(path)
    if (st.isDirectory()) return true
    if (!st.isSymbolicLink()) return false
    return (await stat(path)).isDirectory()
  } catch {
    return false
  }
}

function parseFrontmatter(content: string): { name?: string; description?: string } {
  const match = content.match(/^---\s*\n([\s\S]*?)\n---/)
  if (!match) return {}
  const data = match[1]

  const unquote = (value: string): string => value.trim().replace(/^['"]|['"]$/g, '')

  const foldBlock = (lines: string[]): string => {
    const paragraphs: string[][] = [[]]
    for (const line of lines) {
      if (!line.trim()) {
        if (paragraphs[paragraphs.length - 1].length) paragraphs.push([])
        continue
      }
      paragraphs[paragraphs.length - 1].push(line.trim())
    }
    return paragraphs
      .filter((paragraph) => paragraph.length)
      .map((paragraph) => paragraph.join(' '))
      .join('\n')
  }

  const readField = (field: string): string | undefined => {
    const lines = data.split(/\r?\n/)
    const fieldIndex = lines.findIndex((line) => line.match(new RegExp(`^${field}:\\s*(.*)$`)))
    if (fieldIndex === -1) return undefined

    const fieldValue = lines[fieldIndex].match(new RegExp(`^${field}:\\s*(.*)$`))?.[1]?.trim()
    if (!fieldValue) return undefined

    const blockMatch = fieldValue.match(/^([>|])[-+]?\s*(?:#.*)?$/)
    if (!blockMatch) return unquote(fieldValue)

    const blockLines: string[] = []
    for (let i = fieldIndex + 1; i < lines.length; i += 1) {
      const line = lines[i]
      if (line.trim() && !/^\s/.test(line)) break
      blockLines.push(line)
    }

    const minIndent = blockLines
      .filter((line) => line.trim())
      .reduce((min, line) => Math.min(min, line.match(/^\s*/)?.[0].length ?? 0), Infinity)
    const normalized = blockLines.map((line) =>
      Number.isFinite(minIndent) ? line.slice(minIndent) : line
    )
    const value = blockMatch[1] === '|' ? normalized.join('\n').trim() : foldBlock(normalized)
    return value || undefined
  }
  return { name: readField('name'), description: readField('description') }
}

async function readSkillDir(skillDir: string): Promise<Omit<SkillDirEntry, 'dir'> | null> {
  try {
    const content = await readFile(join(skillDir, 'SKILL.md'), 'utf-8')
    const fm = parseFrontmatter(content)
    if (!fm.name || !fm.description) return null
    return { name: fm.name, description: fm.description }
  } catch {
    return null
  }
}

export async function readSkillDirs(baseDir: string): Promise<SkillDirEntry[]> {
  try {
    const entries = await readdir(baseDir, { withFileTypes: true })
    const results = await Promise.all(
      entries.map(async (entry) => {
        const dir = join(baseDir, entry.name)
        if (!(entry.isDirectory() || entry.isSymbolicLink())) return null
        if (!(await isDirectoryOrSymlinkToDirectory(dir))) return null
        const skill = await readSkillDir(dir)
        return skill ? { dir, ...skill } : null
      })
    )
    return results.filter((v): v is SkillDirEntry => !!v)
  } catch {
    return []
  }
}
