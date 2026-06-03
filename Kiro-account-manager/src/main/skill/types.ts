export type SkillUpdateStatus = 'unknown' | 'latest' | 'available' | 'unsupported' | 'failed'
export type SkillInstallMode = 'symlink' | 'copy'

export interface SkillsManagerConfig {
  version: 1
  defaultAutoUpdate: boolean
  defaultInstallMode: SkillInstallMode
  gitlabToken?: string
  skillConfigs: Record<string, SkillManagerSkillConfig>
  lastSelectedAgent?: string
}

export interface SkillManagerSkillConfig {
  agent: string
  skillName: string
  autoUpdate?: boolean
  createdAt: number
  updatedAt: number
}

export interface SkillsSkillView {
  name: string
  description: string
  agent: string
  source?: string
  sourceType?: string
  sourceUrl?: string
  ref?: string
  path: string
  canonicalPath?: string
  installedAt?: string
  updatedAt?: string
  pluginName?: string
  autoUpdate: boolean
  updateStatus?: SkillUpdateStatus
  updateReason?: string
}

export interface SkillsAgentView {
  id: string
  displayName: string
  installed: boolean
  universal?: boolean
  supportsSymlinkProjection?: boolean
  effectiveInstallMode?: SkillInstallMode | 'shared'
  globalSkillsDir?: string
  count: number
  skills: SkillsSkillView[]
}

export interface SkillsAgentsResult {
  agents: SkillsAgentView[]
  config: SkillsManagerConfig
}

export interface SkillsOperationResult {
  success: boolean
  message?: string
  results?: Array<{ skillName?: string; agent?: string; success: boolean; error?: string }>
  error?: string
}

export interface SkillsInstallInput {
  source: string
  agents: string[]
  skills?: string[]
  copy?: boolean
  yes?: boolean
}

export interface AgentDefinition {
  id: string
  packageAgentId?: string
  displayName: string
  skillsDir: string
  globalSkillsDir: string
  detectCommands?: string[]
  detectPaths?: string[]
  detectBySkillsDir?: boolean
  universal?: boolean
  supportsSymlinkProjection?: boolean
}

export interface LockEntry {
  source?: string
  sourceType?: string
  sourceUrl?: string
  ref?: string
  skillPath?: string
  skillFolderHash?: string
  installedAt?: string
  updatedAt?: string
  pluginName?: string
}
