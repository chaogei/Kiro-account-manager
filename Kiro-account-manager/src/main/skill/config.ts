import type { SkillsManagerConfig } from './types'

export function defaultSkillsManagerConfig(): SkillsManagerConfig {
  return { version: 1, defaultAutoUpdate: true, defaultInstallMode: 'symlink', skillConfigs: {} }
}

export function normalizeSkillName(name: string): string {
  return (
    (name || '')
      .toLowerCase()
      .replace(/[^a-z0-9._]+/g, '-')
      .replace(/^[.-]+|[.-]+$/g, '')
      .slice(0, 255) || 'unnamed-skill'
  )
}

export function normalizeSkillsManagerConfig(value: unknown): SkillsManagerConfig {
  const input = value && typeof value === 'object' ? (value as Partial<SkillsManagerConfig>) : {}
  return {
    version: 1,
    defaultAutoUpdate: input.defaultAutoUpdate === true,
    defaultInstallMode: input.defaultInstallMode === 'copy' ? 'copy' : 'symlink',
    gitlabToken: typeof input.gitlabToken === 'string' ? input.gitlabToken : undefined,
    skillConfigs:
      input.skillConfigs && typeof input.skillConfigs === 'object' ? input.skillConfigs : {},
    lastSelectedAgent: typeof input.lastSelectedAgent === 'string' ? input.lastSelectedAgent : undefined
  }
}

export function getSkillConfigKey(agent: string, skillName: string): string {
  return `${agent}:${normalizeSkillName(skillName)}`
}
