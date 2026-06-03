import { existsSync } from 'fs'
import { spawnSync } from 'child_process'
import { homedir } from 'os'
import { join } from 'path'
import type { AgentDefinition } from './types'

export const home = homedir()
const configHome = process.env.XDG_CONFIG_HOME || join(home, '.config')
const appDataHome = process.env.APPDATA || join(home, 'AppData', 'Roaming')
const localAppDataHome = process.env.LOCALAPPDATA || join(home, 'AppData', 'Local')
const programFiles = process.env.ProgramFiles || 'C:\\Program Files'
const programFilesX86 = process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)'
const codexHome = process.env.CODEX_HOME?.trim() || join(home, '.codex')
const claudeHome = process.env.CLAUDE_CONFIG_DIR?.trim() || join(home, '.claude')

export const canonicalGlobalSkillsDir = join(home, '.agents', 'skills')

function appPaths(appName: string, linuxDesktopName?: string): string[] {
  const linuxName = linuxDesktopName || appName.toLowerCase()
  return [
    join('/Applications', `${appName}.app`),
    join(home, 'Applications', `${appName}.app`),
    join(programFiles, appName, `${appName}.exe`),
    join(programFilesX86, appName, `${appName}.exe`),
    join(localAppDataHome, 'Programs', appName, `${appName}.exe`),
    join(appDataHome, appName),
    join('/usr/share/applications', `${linuxName}.desktop`),
    join('/usr/local/share/applications', `${linuxName}.desktop`),
    join(home, '.local', 'share', 'applications', `${linuxName}.desktop`)
  ]
}

export const agentDefinitions: AgentDefinition[] = [
  {
    id: 'codex',
    displayName: 'Codex',
    skillsDir: '.agents/skills',
    globalSkillsDir: join(codexHome, 'skills'),
    detectCommands: ['codex'],
    detectPaths: [
      ...appPaths('Codex', 'codex'),
      join(appDataHome, 'OpenAI', 'Codex'),
      join(appDataHome, 'com.openai.codex')
    ],
    universal: true
  },
  {
    id: 'claude-code',
    displayName: 'Claude Code',
    skillsDir: '.claude/skills',
    globalSkillsDir: join(claudeHome, 'skills'),
    detectCommands: ['claude'],
    detectPaths: [
      ...appPaths('Claude', 'claude'),
      claudeHome,
      join(appDataHome, 'Claude'),
      join(localAppDataHome, 'Claude')
    ]
  },
  {
    id: 'kiro',
    packageAgentId: 'kiro-cli',
    displayName: 'Kiro',
    skillsDir: '.kiro/skills',
    globalSkillsDir: join(home, '.kiro', 'skills'),
    detectCommands: ['kiro', 'kiro-cli'],
    detectPaths: [
      ...appPaths('Kiro', 'kiro'),
      join(appDataHome, 'Kiro'),
      join(localAppDataHome, 'Kiro'),
      join(home, 'Library', 'Application Support', 'Kiro')
    ],
    supportsSymlinkProjection: false
  },
  {
    id: 'opencode',
    displayName: 'OpenCode',
    skillsDir: '.agents/skills',
    globalSkillsDir: join(configHome, 'opencode', 'skills'),
    detectCommands: ['opencode'],
    universal: true
  },
  {
    id: 'cursor',
    displayName: 'Cursor',
    skillsDir: '.agents/skills',
    globalSkillsDir: join(home, '.cursor', 'skills'),
    detectCommands: ['cursor'],
    detectPaths: [
      ...appPaths('Cursor', 'cursor'),
      join(appDataHome, 'Cursor'),
      join(localAppDataHome, 'Programs', 'Cursor', 'Cursor.exe'),
      join(home, 'Library', 'Application Support', 'Cursor')
    ],
    universal: true
  },
  {
    id: 'cline',
    displayName: 'Cline',
    skillsDir: '.agents/skills',
    globalSkillsDir: canonicalGlobalSkillsDir,
    detectCommands: ['cline'],
    universal: true
  },
  {
    id: 'gemini-cli',
    displayName: 'Gemini CLI',
    skillsDir: '.agents/skills',
    globalSkillsDir: join(home, '.gemini', 'skills'),
    detectCommands: ['gemini'],
    universal: true
  },
  {
    id: 'goose',
    displayName: 'Goose',
    skillsDir: '.goose/skills',
    globalSkillsDir: join(configHome, 'goose', 'skills'),
    detectCommands: ['goose']
  },
  {
    id: 'windsurf',
    displayName: 'Windsurf',
    skillsDir: '.windsurf/skills',
    globalSkillsDir: join(home, '.codeium', 'windsurf', 'skills'),
    detectCommands: ['windsurf']
  },
  {
    id: 'roo',
    displayName: 'Roo Code',
    skillsDir: '.roo/skills',
    globalSkillsDir: join(home, '.roo', 'skills'),
    detectCommands: ['roo']
  },
  {
    id: 'qwen-code',
    displayName: 'Qwen Code',
    skillsDir: '.qwen/skills',
    globalSkillsDir: join(home, '.qwen', 'skills'),
    detectCommands: ['qwen']
  },
  {
    id: 'continue',
    displayName: 'Continue',
    skillsDir: '.continue/skills',
    globalSkillsDir: join(home, '.continue', 'skills'),
    detectCommands: ['continue']
  },
  {
    id: 'github-copilot',
    displayName: 'GitHub Copilot',
    skillsDir: '.agents/skills',
    globalSkillsDir: join(home, '.copilot', 'skills'),
    detectCommands: ['github-copilot'],
    universal: true
  },
  {
    id: 'amp',
    displayName: 'Amp',
    skillsDir: '.agents/skills',
    globalSkillsDir: join(configHome, 'agents', 'skills'),
    detectCommands: ['amp'],
    universal: true
  },
  {
    id: 'warp',
    displayName: 'Warp',
    skillsDir: '.agents/skills',
    globalSkillsDir: canonicalGlobalSkillsDir,
    detectCommands: ['warp-agent'],
    universal: true
  },
  {
    id: 'zencoder',
    displayName: 'Zencoder',
    skillsDir: '.zencoder/skills',
    globalSkillsDir: join(home, '.zencoder', 'skills'),
    detectCommands: ['zencoder']
  },
  {
    id: 'trae',
    displayName: 'Trae',
    skillsDir: '.trae/skills',
    globalSkillsDir: join(home, '.trae', 'skills'),
    detectCommands: ['trae']
  },
  {
    id: 'qoder',
    displayName: 'Qoder',
    skillsDir: '.qoder/skills',
    globalSkillsDir: join(home, '.qoder', 'skills'),
    detectCommands: ['qoder']
  }
]

export function getAgentById(agentId: string): AgentDefinition | undefined {
  return agentDefinitions.find((agent) => agent.id === agentId)
}

export function getAgentSkillDirs(agent: AgentDefinition): string[] {
  if (agent.universal) return [canonicalGlobalSkillsDir]
  const dirs = [agent.globalSkillsDir]
  return Array.from(new Set(dirs))
}

export function supportsAgentSymlinkProjection(agent: AgentDefinition): boolean {
  if (agent.universal) return false
  return agent.supportsSymlinkProjection !== false
}

export function detectAgent(agent: AgentDefinition): boolean {
  const hasCommand = agent.detectCommands?.some((command) => {
    const isWindows = process.platform === 'win32'
    const result = spawnSync(isWindows ? 'where' : 'which', isWindows ? [command] : ['-a', command], {
      encoding: 'utf-8'
    })
    if (result.status !== 0) return false
    return result.stdout
      .split(/\r?\n/)
      .map((line) => line.trim())
      .some((line) => line.startsWith('/') || /^[A-Z]:\\/i.test(line))
  })
  if (hasCommand) return true
  if (agent.detectPaths?.some((path) => existsSync(path))) return true
  if (agent.detectBySkillsDir) return agent.detectPaths?.some((path) => existsSync(path)) === true
  return false
}

export function getInstalledAgentDefinitions(): AgentDefinition[] {
  return agentDefinitions.filter((agent) => detectAgent(agent))
}

export function toPackageAgentId(agentId: string): string {
  return getAgentById(agentId)?.packageAgentId || agentId
}
