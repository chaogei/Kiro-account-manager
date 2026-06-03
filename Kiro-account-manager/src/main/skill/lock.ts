import { mkdir, readFile, writeFile } from 'fs/promises'
import { dirname, join } from 'path'
import { canonicalGlobalSkillsDir, home } from './agents'
import { normalizeSkillName } from './config'
import type { LockEntry } from './types'

function getGlobalLockPath(): string {
  return process.env.XDG_STATE_HOME
    ? join(process.env.XDG_STATE_HOME, 'skills', '.skill-lock.json')
    : join(home, '.agents', '.skill-lock.json')
}

export async function readGlobalLock(): Promise<Record<string, LockEntry>> {
  try {
    const raw = await readFile(getGlobalLockPath(), 'utf-8')
    const parsed = JSON.parse(raw) as { skills?: Record<string, LockEntry> }
    return parsed.skills || {}
  } catch {
    return {}
  }
}

async function writeGlobalLockSkills(skills: Record<string, LockEntry>): Promise<void> {
  const lockPath = getGlobalLockPath()
  let lock: Record<string, unknown> = { version: 3, skills: {} }
  try {
    lock = JSON.parse(await readFile(lockPath, 'utf-8')) as Record<string, unknown>
  } catch {
    // create a new lock below
  }
  lock.version = 3
  lock.skills = skills
  await mkdir(dirname(lockPath), { recursive: true })
  await writeFile(lockPath, JSON.stringify(lock, null, 2), 'utf-8')
}

export async function removeGlobalLockEntry(skillName: string): Promise<void> {
  const lock = await readGlobalLock()
  if (lock[skillName]) {
    delete lock[skillName]
    await writeGlobalLockSkills(lock)
  }
}

export function lockForSkill(
  lock: Record<string, LockEntry>,
  skillName: string
): LockEntry | undefined {
  return (
    lock[skillName] ||
    lock[normalizeSkillName(skillName)] ||
    Object.entries(lock).find(
      ([name]) => normalizeSkillName(name) === normalizeSkillName(skillName)
    )?.[1]
  )
}

export async function getGitHubTree(
  ownerRepo: string,
  ref?: string
): Promise<Array<{ path: string; type: string; sha: string }> | null> {
  const refs = ref ? [ref] : ['main', 'master']
  for (const item of refs) {
    try {
      const resp = await fetch(
        `https://api.github.com/repos/${ownerRepo}/git/trees/${encodeURIComponent(item)}?recursive=1`
      )
      if (!resp.ok) continue
      const data = (await resp.json()) as { tree?: Array<{ path: string; type: string; sha: string }> }
      return data.tree || null
    } catch {
      // try next ref
    }
  }
  return null
}

export { canonicalGlobalSkillsDir }
