import { cp, lstat, mkdir, realpath, rm, stat, symlink } from 'fs/promises'
import { basename, dirname, join, relative, resolve } from 'path'
import {
  agentDefinitions,
  canonicalGlobalSkillsDir,
  detectAgent,
  getAgentById,
  getAgentSkillDirs,
  getInstalledAgentDefinitions,
  supportsAgentSymlinkProjection,
  toPackageAgentId
} from './agents'
import { runNpxSkills } from './commands'
import {
  defaultSkillsManagerConfig,
  getSkillConfigKey,
  normalizeSkillName,
  normalizeSkillsManagerConfig
} from './config'
import { isPathSafe, pathExists, readSkillDirs } from './filesystem'
import { getGitHubTree, lockForSkill, readGlobalLock, removeGlobalLockEntry } from './lock'
import type {
  SkillUpdateStatus,
  SkillsAgentView,
  SkillsAgentsResult,
  SkillsInstallInput,
  SkillsManagerConfig,
  SkillsOperationResult,
  SkillsSkillView
} from './types'

/** Extract GitLab host and project path from SSH or HTTPS URL */
function extractGitLabInfo(url: string): { host: string; projectPath: string } | null {
  // git@gitlab.example.com:group/repo.git
  const sshMatch = url.match(/^git@([^:]+):([^/][^:]+?)(?:\.git)?$/)
  if (sshMatch) return { host: `https://${sshMatch[1]}`, projectPath: sshMatch[2] }
  // https://gitlab.example.com/group/repo.git
  const httpsMatch = url.match(/^(https?:\/\/[^/]+)\/(.+?)(?:\.git)?$/)
  if (httpsMatch) return { host: httpsMatch[1], projectPath: httpsMatch[2] }
  return null
}

export {
  defaultSkillsManagerConfig,
  getSkillConfigKey,
  normalizeSkillName,
  normalizeSkillsManagerConfig
}
export type {
  SkillUpdateStatus,
  SkillsAgentView,
  SkillsAgentsResult,
  SkillsInstallInput,
  SkillsManagerConfig,
  SkillsOperationResult,
  SkillsSkillView
}

export async function listSkillsState(configValue: unknown): Promise<SkillsAgentsResult> {
  const config = normalizeSkillsManagerConfig(configValue)
  const lock = await readGlobalLock()
  const agents = await Promise.all(
    agentDefinitions.map(async (agent) => {
      const installed = detectAgent(agent)
      if (!installed) return null
      const byName = new Map<string, SkillsSkillView>()
      for (const dir of getAgentSkillDirs(agent)) {
        const skills = await readSkillDirs(dir)
        for (const skill of skills) {
          const key = normalizeSkillName(skill.name)
          if (byName.has(key)) continue
          const lockEntry = lockForSkill(lock, skill.name)
          const cfg = config.skillConfigs[getSkillConfigKey(agent.id, skill.name)]
          byName.set(key, {
            name: skill.name,
            description: skill.description,
            agent: agent.id,
            source: lockEntry?.source,
            sourceType: lockEntry?.sourceType,
            sourceUrl: lockEntry?.sourceUrl,
            ref: lockEntry?.ref,
            path: skill.dir,
            canonicalPath:
              dir === canonicalGlobalSkillsDir
                ? skill.dir
                : join(canonicalGlobalSkillsDir, normalizeSkillName(skill.name)),
            installedAt: lockEntry?.installedAt,
            updatedAt: lockEntry?.updatedAt,
            pluginName: lockEntry?.pluginName,
            autoUpdate: cfg?.autoUpdate ?? false,
            updateStatus: 'unknown'
          })
        }
      }
      const skills = Array.from(byName.values()).sort((a, b) => a.name.localeCompare(b.name))
      return {
        id: agent.id,
        displayName: agent.displayName,
        installed: true,
        universal: agent.universal === true,
        supportsSymlinkProjection: supportsAgentSymlinkProjection(agent),
        effectiveInstallMode: agent.universal
          ? 'shared'
          : config.defaultInstallMode === 'copy' || !supportsAgentSymlinkProjection(agent)
            ? 'copy'
            : 'symlink',
        globalSkillsDir: agent.globalSkillsDir,
        count: skills.length,
        skills
      } as SkillsAgentView
    })
  )

  return { agents: agents.filter((agent): agent is SkillsAgentView => agent !== null), config }
}

async function copyDirectory(src: string, dest: string): Promise<void> {
  if (await isSamePath(src, dest)) return
  await rm(dest, { recursive: true, force: true })
  await mkdir(dest, { recursive: true })
  await cp(src, dest, { recursive: true, dereference: true })
}

async function isSamePath(a: string, b: string): Promise<boolean> {
  const [left, right] = await Promise.all([
    realpath(a).catch(() => resolve(a)),
    realpath(b).catch(() => resolve(b))
  ])
  return left === right
}

async function createRelativeSymlink(target: string, linkPath: string): Promise<boolean> {
  try {
    const targetReal = await stat(target)
      .then(() => resolve(target))
      .catch(() => resolve(target))
    const linkReal = resolve(linkPath)
    if (targetReal === linkReal) return true
    const existing = await lstat(linkPath).catch(() => null)
    if (existing) await rm(linkPath, { recursive: true, force: true })
    await mkdir(dirname(linkPath), { recursive: true })
    await symlink(
      relative(dirname(linkPath), target),
      linkPath,
      process.platform === 'win32' ? 'junction' : undefined
    )
    return true
  } catch {
    return false
  }
}

function getCanonicalSkillDir(skillName: string): string {
  return join(canonicalGlobalSkillsDir, normalizeSkillName(skillName))
}

function getAgentProjectionDir(agent: NonNullable<ReturnType<typeof getAgentById>>, skillName: string): string {
  const normalized = normalizeSkillName(skillName)
  return agent.universal ? getCanonicalSkillDir(normalized) : join(agent.globalSkillsDir, normalized)
}

async function ensureCanonicalSkillDir(
  skillName: string,
  sourceDir: string,
  overwrite?: boolean
): Promise<string> {
  const canonicalDir = getCanonicalSkillDir(skillName)
  if (overwrite || !(await pathExists(canonicalDir))) {
    await copyDirectory(sourceDir, canonicalDir)
  }
  return canonicalDir
}

async function projectCanonicalSkillToAgent(
  agent: NonNullable<ReturnType<typeof getAgentById>>,
  skillName: string,
  overwrite = true,
  preferredMode: SkillsManagerConfig['defaultInstallMode'] = 'symlink'
): Promise<boolean> {
  const canonicalDir = getCanonicalSkillDir(skillName)
  if (!(await pathExists(canonicalDir))) return false
  if (agent.universal) return true

  const targetDir = getAgentProjectionDir(agent, skillName)
  if (!overwrite && (await pathExists(targetDir))) return true

  const useCopy = preferredMode === 'copy' || !supportsAgentSymlinkProjection(agent)
  if (!useCopy) {
    const linked = await createRelativeSymlink(canonicalDir, targetDir)
    if (linked) return true
  }
  await copyDirectory(canonicalDir, targetDir)
  return true
}

async function findSkillSourceDir(sourceAgentId: string, skillName: string): Promise<string | null> {
  const sourceAgent = getAgentById(sourceAgentId)
  if (!sourceAgent) return null
  const normalized = normalizeSkillName(skillName)
  for (const dir of getAgentSkillDirs(sourceAgent)) {
    const entries = await readSkillDirs(dir)
    const match = entries.find(
      (skill) =>
        normalizeSkillName(skill.name) === normalized ||
        normalizeSkillName(basename(skill.dir)) === normalized
    )
    if (match) return match.dir
  }
  return null
}

async function listCanonicalSkillNames(): Promise<string[]> {
  const skills = await readSkillDirs(canonicalGlobalSkillsDir)
  return skills.map((skill) => skill.name)
}

async function refreshExistingSkillProjections(
  skillNames: string[],
  preferredMode: SkillsManagerConfig['defaultInstallMode']
): Promise<void> {
  const agents = getInstalledAgentDefinitions()
  for (const skillName of skillNames) {
    const normalized = normalizeSkillName(skillName)
    for (const agent of agents) {
      if (agent.universal) continue
      const targetDir = join(agent.globalSkillsDir, normalized)
      if (!(await pathExists(targetDir))) continue
      await projectCanonicalSkillToAgent(agent, skillName, true, preferredMode)
    }
  }
}

async function projectSkillsToAgents(
  skillNames: string[],
  agentIds: string[],
  preferredMode: SkillsManagerConfig['defaultInstallMode']
): Promise<void> {
  for (const skillName of skillNames) {
    for (const agentId of agentIds) {
      const agent = getAgentById(agentId)
      if (!agent) continue
      await projectCanonicalSkillToAgent(agent, skillName, true, preferredMode)
    }
  }
}

export async function syncSkills(
  input: { sourceAgent: string; skillNames: string[]; targetAgents: string[]; overwrite?: boolean },
  configValue: unknown,
  saveConfig: (config: SkillsManagerConfig) => void
): Promise<SkillsOperationResult> {
  const config = normalizeSkillsManagerConfig(configValue)
  const results: NonNullable<SkillsOperationResult['results']> = []
  for (const skillName of input.skillNames) {
    const sourceDir = await findSkillSourceDir(input.sourceAgent, skillName)
    if (!sourceDir) {
      results.push({ skillName, success: false, error: 'Source skill not found' })
      continue
    }
    await ensureCanonicalSkillDir(skillName, sourceDir, input.overwrite)
    for (const targetAgentId of input.targetAgents) {
      const targetAgent = getAgentById(targetAgentId)
      if (!targetAgent) {
        results.push({ skillName, agent: targetAgentId, success: false, error: 'Unknown agent' })
        continue
      }
      try {
        await projectCanonicalSkillToAgent(
          targetAgent,
          skillName,
          true,
          config.defaultInstallMode
        )
        const cfgKey = getSkillConfigKey(targetAgentId, skillName)
        if (!config.skillConfigs[cfgKey]) {
          const now = Date.now()
          config.skillConfigs[cfgKey] = {
            agent: targetAgentId,
            skillName,
            autoUpdate: config.defaultAutoUpdate,
            createdAt: now,
            updatedAt: now
          }
        }
        results.push({ skillName, agent: targetAgentId, success: true })
      } catch (error) {
        results.push({
          skillName,
          agent: targetAgentId,
          success: false,
          error: error instanceof Error ? error.message : String(error)
        })
      }
    }
  }
  saveConfig(config)
  return { success: results.every((result) => result.success), results }
}

export async function deleteSkills(
  input: { agent: string; skillNames: string[]; allAgents?: boolean },
  configValue: unknown,
  saveConfig: (config: SkillsManagerConfig) => void
): Promise<SkillsOperationResult> {
  const config = normalizeSkillsManagerConfig(configValue)
  const targetAgents = input.allAgents
    ? getInstalledAgentDefinitions().map((agent) => agent.id)
    : [input.agent]
  const results: NonNullable<SkillsOperationResult['results']> = []

  for (const skillName of input.skillNames) {
    const normalized = normalizeSkillName(skillName)
    for (const agentId of targetAgents) {
      const agent = getAgentById(agentId)
      if (!agent) continue
      for (const baseDir of getAgentSkillDirs(agent)) {
        const target = join(baseDir, normalized)
        if (!isPathSafe(baseDir, target)) continue
        await rm(target, { recursive: true, force: true }).catch(() => undefined)
      }
      delete config.skillConfigs[getSkillConfigKey(agentId, skillName)]
      results.push({ skillName, agent: agentId, success: true })
    }

    if (input.allAgents) {
      await rm(join(canonicalGlobalSkillsDir, normalized), { recursive: true, force: true }).catch(
        () => undefined
      )
      await removeGlobalLockEntry(skillName)
      for (const key of Object.keys(config.skillConfigs)) {
        if (key.endsWith(`:${normalized}`)) delete config.skillConfigs[key]
      }
    }
  }

  saveConfig(config)
  return { success: true, results }
}

export async function setSkillAutoUpdate(
  input: { agent: string; skillName: string; enabled: boolean },
  configValue: unknown,
  saveConfig: (config: SkillsManagerConfig) => void
): Promise<SkillsOperationResult> {
  const config = normalizeSkillsManagerConfig(configValue)
  const key = getSkillConfigKey(input.agent, input.skillName)
  const now = Date.now()
  config.skillConfigs[key] = {
    agent: input.agent,
    skillName: input.skillName,
    autoUpdate: input.enabled,
    createdAt: config.skillConfigs[key]?.createdAt || now,
    updatedAt: now
  }
  saveConfig(config)
  return { success: true }
}

export async function saveSkillsConfigPatch(
  patch: Partial<SkillsManagerConfig>,
  configValue: unknown,
  saveConfig: (config: SkillsManagerConfig) => void
): Promise<SkillsManagerConfig> {
  const current = normalizeSkillsManagerConfig(configValue)
  const next = normalizeSkillsManagerConfig({
    ...current,
    ...patch,
    skillConfigs: patch.skillConfigs || current.skillConfigs
  })
  saveConfig(next)
  return next
}

export async function checkSkillUpdate(input: {
  agent: string
  skillName: string
}, config?: SkillsManagerConfig): Promise<{ success: boolean; status: SkillUpdateStatus; reason?: string }> {
  const lock = await readGlobalLock()
  const entry = lockForSkill(lock, input.skillName)
  if (!entry) return { success: true, status: 'unsupported', reason: '缺少版本追踪记录' }
  if (entry.sourceType === 'local') {
    return { success: true, status: 'unsupported', reason: '本地路径来源无法自动检查' }
  }
  if (entry.sourceType === 'git') {
    if (!entry.sourceUrl && !entry.source) {
      return { success: true, status: 'unsupported', reason: '缺少 git 远端地址' }
    }
    if (!entry.skillFolderHash || !entry.skillPath) {
      return { success: true, status: 'unsupported', reason: '缺少 skillPath 或 hash' }
    }
    const url = entry.sourceUrl || entry.source || ''
    const ref = entry.ref || 'HEAD'
    const skillDir = entry.skillPath.replace(/\/?SKILL\.md$/, '')
    // 尝试用 GitLab API
    const gitlabToken = config?.gitlabToken
    if (gitlabToken) {
      try {
        const gitlabInfo = extractGitLabInfo(url)
        if (gitlabInfo) {
          const encodedPath = encodeURIComponent(gitlabInfo.projectPath)
          const encodedDir = encodeURIComponent(skillDir)
          const apiRef = ref === 'HEAD' ? '' : `&ref_name=${encodeURIComponent(ref)}`
          // 获取该目录最新 commit
          const resp = await fetch(
            `${gitlabInfo.host}/api/v4/projects/${encodedPath}/repository/commits?path=${encodedDir}${apiRef}&per_page=1`,
            { headers: { 'PRIVATE-TOKEN': gitlabToken } }
          )
          if (resp.ok) {
            const commits = await resp.json() as Array<{ committed_date: string }>
            if (commits.length > 0) {
              const remoteDate = new Date(commits[0].committed_date).getTime()
              const localDate = entry.updatedAt ? new Date(entry.updatedAt).getTime() : 0
              if (remoteDate <= localDate) {
                return { success: true, status: 'latest' }
              }
              return { success: true, status: 'available' }
            }
          }
        }
      } catch {
        // fallback below
      }
    }
    // 没有 GitLab Token 无法检查
    if (!config?.gitlabToken) {
      return { success: true, status: 'unsupported', reason: '需要配置 GitLab Token' }
    }
    return { success: false, status: 'failed', reason: '无法连接远端仓库' }
  }
  if (!entry.skillFolderHash || !entry.skillPath) {
    return { success: true, status: 'unsupported', reason: '缺少 skillPath 或 hash' }
  }
  const source = entry.source || ''
  if (!/^[^/\s]+\/[^/\s]+$/.test(source)) {
    return { success: true, status: 'unsupported', reason: '仅支持 GitHub owner/repo 来源' }
  }
  const tree = await getGitHubTree(source, entry.ref)
  if (!tree) return { success: false, status: 'failed', reason: '获取上游版本失败' }
  const skillDir = entry.skillPath.replace(/\/?SKILL\.md$/, '')
  const latest = tree.find((item) => item.type === 'tree' && item.path === skillDir)?.sha
  if (!latest) return { success: true, status: 'unsupported', reason: '上游 skill 不存在或已删除' }
  return { success: true, status: latest === entry.skillFolderHash ? 'latest' : 'available' }
}

export async function installSkills(
  input: SkillsInstallInput,
  configValue: unknown,
  saveConfig: (config: SkillsManagerConfig) => void
): Promise<SkillsOperationResult> {
  if (!input.source?.trim()) return { success: false, error: 'Missing source' }
  const config = normalizeSkillsManagerConfig(configValue)
  const beforeNames = new Set((await listCanonicalSkillNames()).map((name) => normalizeSkillName(name)))
  const args = ['add', input.source.trim(), '-g', '-y']
  const agents = input.agents?.length ? input.agents : ['*']
  for (const agent of agents) args.push('-a', agent === '*' ? agent : toPackageAgentId(agent))
  if ((input.copy ?? (config.defaultInstallMode === 'copy')) === true) args.push('--copy')
  for (const skill of input.skills || []) args.push('-s', skill)
  const result = await runNpxSkills(args)
  if (result.success) {
    const afterNames = await listCanonicalSkillNames()
    const installedSkillNames = input.skills?.length
      ? input.skills
      : afterNames.filter((name) => !beforeNames.has(normalizeSkillName(name)))
    const targetAgentIds = agents.includes('*')
      ? getInstalledAgentDefinitions().map((agent) => agent.id)
      : input.agents
    if (installedSkillNames.length > 0) {
      await projectSkillsToAgents(installedSkillNames, targetAgentIds, config.defaultInstallMode)
    }
    saveConfig(config)
  }
  return result
}

export async function updateSkills(input: {
  agent: string
  skillNames: string[]
}, configValue?: unknown): Promise<SkillsOperationResult> {
  const args = ['update', '-g', '-y', ...input.skillNames]
  const result = await runNpxSkills(args)
  if (result.success) {
    const config = normalizeSkillsManagerConfig(configValue)
    await refreshExistingSkillProjections(input.skillNames, config.defaultInstallMode)
  }
  return result
}
