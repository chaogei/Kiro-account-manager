import { existsSync } from 'fs'
import { mkdir, readFile, writeFile } from 'fs/promises'
import { homedir } from 'os'
import { dirname, join } from 'path'
import { agentDefinitions, detectAgent } from '../skill/agents'
import { normalizeMcpName } from './config'
import type {
  ManagedMcpServer,
  McpAgentAdapter,
  McpAgentConfigReadResult,
  McpWriteResult
} from './types'

const home = homedir()
const configHome = process.env.XDG_CONFIG_HOME || join(home, '.config')

interface AdapterDefinition {
  id: string
  displayName: string
  configPath: string
  kind: 'mcpServers' | 'settingsMcpServers' | 'codexToml' | 'kiro' | 'opencode' | 'vscodeServers'
}

const definitions: AdapterDefinition[] = [
  {
    id: 'codex',
    displayName: 'Codex',
    configPath: join(process.env.CODEX_HOME?.trim() || join(home, '.codex'), 'config.toml'),
    kind: 'codexToml'
  },
  {
    id: 'claude-code',
    displayName: 'Claude Code',
    configPath: join(home, '.claude.json'),
    kind: 'mcpServers'
  },
  {
    id: 'kiro',
    displayName: 'Kiro',
    configPath: join(home, '.kiro', 'settings', 'mcp.json'),
    kind: 'kiro'
  },
  {
    id: 'cursor',
    displayName: 'Cursor',
    configPath: join(home, '.cursor', 'mcp.json'),
    kind: 'mcpServers'
  },
  {
    id: 'cline',
    displayName: 'Cline',
    configPath: join(home, '.cline', 'mcp.json'),
    kind: 'mcpServers'
  },
  {
    id: 'gemini-cli',
    displayName: 'Gemini CLI',
    configPath: join(home, '.gemini', 'settings.json'),
    kind: 'settingsMcpServers'
  },
  {
    id: 'qwen-code',
    displayName: 'Qwen Code',
    configPath: join(home, '.qwen', 'settings.json'),
    kind: 'settingsMcpServers'
  },
  {
    id: 'opencode',
    displayName: 'OpenCode',
    configPath: join(configHome, 'opencode', 'opencode.json'),
    kind: 'opencode'
  },
  {
    id: 'github-copilot',
    displayName: 'GitHub Copilot',
    configPath: join(home, '.vscode', 'mcp.json'),
    kind: 'vscodeServers'
  }
]

export function getMcpAdapters(): McpAgentAdapter[] {
  return definitions.map(createAdapter)
}

export function getMcpAdapterById(agentId: string): McpAgentAdapter | undefined {
  return getMcpAdapters().find((adapter) => adapter.id === agentId)
}

export function getAllMcpAgentViews(): Array<{
  id: string
  displayName: string
  installed: boolean
  supported: boolean
  adapter?: McpAgentAdapter
}> {
  const adapters = new Map(getMcpAdapters().map((adapter) => [adapter.id, adapter]))
  return agentDefinitions.map((agent) => {
    const adapter = adapters.get(agent.id)
    return {
      id: agent.id,
      displayName: agent.displayName,
      installed: detectAgent(agent),
      supported: Boolean(adapter?.supported),
      adapter
    }
  })
}

function createAdapter(definition: AdapterDefinition): McpAgentAdapter {
  const adapter: McpAgentAdapter = {
    id: definition.id,
    displayName: definition.displayName,
    supported: true,
    detect: () => {
      const agent = agentDefinitions.find((item) => item.id === definition.id)
      return agent ? detectAgent(agent) : existsSync(definition.configPath)
    },
    getConfigPath: () => definition.configPath,
    read: () => readNativeServers(definition),
    writeServer: (server, oldName) => writeNativeServer(definition, server, oldName),
    deleteServer: (name) => deleteNativeServer(definition, name),
    toNative: (server) => toNative(definition, server),
    fromNative: (name, value) => fromNative(definition, name, value),
    getNativeTransport
  }
  return adapter
}

async function readJson(path: string): Promise<Record<string, unknown>> {
  try {
    const raw = await readFile(path, 'utf-8')
    const parsed = JSON.parse(raw)
    return parsed && typeof parsed === 'object' ? (parsed as Record<string, unknown>) : {}
  } catch {
    return {}
  }
}

async function writeJson(path: string, value: Record<string, unknown>): Promise<void> {
  await mkdir(dirname(path), { recursive: true })
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, 'utf-8')
}

async function readNativeServers(definition: AdapterDefinition): Promise<McpAgentConfigReadResult> {
  try {
    if (definition.kind === 'codexToml') {
      return {
        success: true,
        configPath: definition.configPath,
        servers: readCodexTomlServers(await readText(definition.configPath))
      }
    }
    const root = await readJson(definition.configPath)
    return {
      success: true,
      configPath: definition.configPath,
      servers: getServerContainer(definition, root)
    }
  } catch (error) {
    return {
      success: false,
      configPath: definition.configPath,
      servers: {},
      error: error instanceof Error ? error.message : String(error)
    }
  }
}

async function writeNativeServer(
  definition: AdapterDefinition,
  server: ManagedMcpServer,
  oldName?: string
): Promise<McpWriteResult> {
  try {
    if (definition.kind === 'codexToml') {
      const previous = await readText(definition.configPath)
      const currentServers = readCodexTomlServers(previous)
      const oldKey = oldName ? findNativeName(currentServers, oldName) : undefined
      const existingName = findNativeName(currentServers, server.name)
      const next = writeCodexTomlServer(previous, server, oldKey)
      await writeText(definition.configPath, next)
      return {
        success: true,
        status: existingName ? 'updated' : 'created',
        configPath: definition.configPath
      }
    }

    const root = await readJson(definition.configPath)
    const container = getMutableServerContainer(definition, root)
    const oldKey = oldName ? findNativeName(container, oldName) : undefined
    if (oldKey && normalizeMcpName(oldKey) !== normalizeMcpName(server.name))
      delete container[oldKey]
    const existingName = findNativeName(container, server.name)
    container[server.name] = toNative(definition, server)
    await writeJson(definition.configPath, root)
    return {
      success: true,
      status: existingName ? 'updated' : 'created',
      configPath: definition.configPath
    }
  } catch (error) {
    return {
      success: false,
      status: 'failed',
      configPath: definition.configPath,
      error: error instanceof Error ? error.message : String(error)
    }
  }
}

async function deleteNativeServer(
  definition: AdapterDefinition,
  name: string
): Promise<McpWriteResult> {
  try {
    if (definition.kind === 'codexToml') {
      const previous = await readText(definition.configPath)
      const servers = readCodexTomlServers(previous)
      const nativeName = findNativeName(servers, name)
      if (!nativeName)
        return { success: true, status: 'skipped', configPath: definition.configPath }
      await writeText(definition.configPath, removeCodexTomlServer(previous, nativeName))
      return { success: true, status: 'deleted', configPath: definition.configPath }
    }
    const root = await readJson(definition.configPath)
    const container = getMutableServerContainer(definition, root)
    const nativeName = findNativeName(container, name)
    if (!nativeName) return { success: true, status: 'skipped', configPath: definition.configPath }
    delete container[nativeName]
    await writeJson(definition.configPath, root)
    return { success: true, status: 'deleted', configPath: definition.configPath }
  } catch (error) {
    return {
      success: false,
      status: 'failed',
      configPath: definition.configPath,
      error: error instanceof Error ? error.message : String(error)
    }
  }
}

function getServerContainer(
  definition: AdapterDefinition,
  root: Record<string, unknown>
): Record<string, unknown> {
  const key =
    definition.kind === 'opencode'
      ? 'mcp'
      : definition.kind === 'vscodeServers'
        ? 'servers'
        : 'mcpServers'
  const value = root[key]
  return value && typeof value === 'object' ? (value as Record<string, unknown>) : {}
}

function getMutableServerContainer(
  definition: AdapterDefinition,
  root: Record<string, unknown>
): Record<string, unknown> {
  const key =
    definition.kind === 'opencode'
      ? 'mcp'
      : definition.kind === 'vscodeServers'
        ? 'servers'
        : 'mcpServers'
  if (!root[key] || typeof root[key] !== 'object') root[key] = {}
  return root[key] as Record<string, unknown>
}

function toNative(definition: AdapterDefinition, server: ManagedMcpServer): unknown {
  if (definition.kind === 'codexToml') return toCodexNative(server)

  if (
    definition.kind === 'kiro' &&
    (server.transport === 'http' || server.transport === 'sse') &&
    server.url
  ) {
    const args = ['mcp-remote', server.url]
    for (const [key, value] of Object.entries(server.headers || {})) {
      args.push('--header', `${key}:${value}`)
    }
    if (requiresKiroAllowHttp(server.url)) args.push('--allow-http')

    return compactObject({
      command: 'npx',
      args,
      env: server.env,
      disabled: server.disabled,
      autoApprove: server.autoApprove,
      disabledTools: server.disabledTools
    })
  }
  if (definition.kind === 'opencode') {
    if ((server.transport === 'http' || server.transport === 'sse') && server.url) {
      return compactObject({
        type: 'remote',
        url: server.url,
        headers: server.headers,
        enabled: server.disabled === true ? false : undefined
      })
    }
    return compactObject({
      type: 'local',
      command: [server.command || '', ...(server.args || [])].filter(Boolean),
      environment: server.env,
      enabled: server.disabled === true ? false : undefined
    })
  }
  if ((server.transport === 'http' || server.transport === 'sse') && server.url) {
    return compactObject({
      type: server.transport === 'sse' ? 'sse' : 'http',
      url: server.url,
      httpUrl: definition.kind === 'settingsMcpServers' ? server.url : undefined,
      headers: server.headers,
      env: server.env,
      disabled: server.disabled,
      timeout: server.timeout
    })
  }
  return compactObject({
    command: server.command,
    args: server.args,
    cwd: server.cwd,
    env: server.env,
    disabled: server.disabled,
    autoApprove: server.autoApprove,
    disabledTools: server.disabledTools,
    timeout: server.timeout
  })
}

function fromNative(
  definition: AdapterDefinition,
  name: string,
  value: unknown
): ManagedMcpServer | null {
  if (!value || typeof value !== 'object') return null
  const raw = value as Record<string, unknown>
  const now = Date.now()
  const server: ManagedMcpServer = {
    name,
    transport: 'stdio',
    createdAt: now,
    updatedAt: now,
    source: definition.kind === 'kiro' ? 'kiro-settings' : 'imported'
  }
  if (typeof raw.disabled === 'boolean') server.disabled = raw.disabled
  if (typeof raw.timeout === 'number') server.timeout = raw.timeout
  if (raw.env && typeof raw.env === 'object') server.env = raw.env as Record<string, string>
  if (raw.headers && typeof raw.headers === 'object')
    server.headers = raw.headers as Record<string, string>
  if (raw.http_headers && typeof raw.http_headers === 'object')
    server.headers = raw.http_headers as Record<string, string>
  if (Array.isArray(raw.autoApprove)) server.autoApprove = raw.autoApprove.map(String)
  if (Array.isArray(raw.disabledTools)) server.disabledTools = raw.disabledTools.map(String)

  if (definition.kind === 'opencode') {
    if (raw.type === 'remote' && typeof raw.url === 'string') {
      server.transport = 'http'
      server.url = raw.url
      if (raw.enabled === false) server.disabled = true
      return server
    }
    if (Array.isArray(raw.command)) {
      const command = raw.command.map(String)
      server.command = command[0]
      server.args = command.slice(1)
      if (raw.environment && typeof raw.environment === 'object')
        server.env = raw.environment as Record<string, string>
      if (raw.enabled === false) server.disabled = true
      return server.command ? server : null
    }
  }

  if (definition.kind === 'kiro' && typeof raw.command === 'string' && Array.isArray(raw.args)) {
    const args = raw.args.map(String)
    const remoteIndex = args.findIndex((arg) => /^mcp-remote(?:@.+)?$/.test(arg))
    const url =
      remoteIndex >= 0
        ? args.slice(remoteIndex + 1).find((arg) => /^https?:\/\//.test(arg))
        : undefined
    if (isNpxCommand(raw.command) && url) {
      server.transport = 'http'
      server.url = url
      const headers = parseMcpRemoteHeaders(args.slice(remoteIndex + 1))
      if (Object.keys(headers).length > 0) server.headers = headers
      return server
    }
  }

  const url =
    typeof raw.url === 'string'
      ? raw.url
      : typeof raw.httpUrl === 'string'
        ? raw.httpUrl
        : undefined
  if (url) {
    server.transport = raw.type === 'sse' ? 'sse' : 'http'
    server.url = url
    return server
  }

  if (typeof raw.command === 'string') {
    server.command = raw.command
    server.args = Array.isArray(raw.args) ? raw.args.map(String) : undefined
    server.cwd = typeof raw.cwd === 'string' ? raw.cwd : undefined
    return server
  }
  return null
}

function isNpxCommand(command: string): boolean {
  return /(^|[\\/])npx(?:\.cmd)?$/i.test(command.trim())
}

function parseMcpRemoteHeaders(args: string[]): Record<string, string> {
  const headers: Record<string, string> = {}
  for (let index = 0; index < args.length - 1; index += 1) {
    if (args[index] !== '--header') continue
    const header = args[index + 1]
    const separator = header.indexOf(':')
    if (separator <= 0) continue
    const key = header.slice(0, separator).trim()
    const value = header.slice(separator + 1).trim()
    if (key) headers[key] = value
    index += 1
  }
  return headers
}

function requiresKiroAllowHttp(url: string): boolean {
  try {
    const parsed = new URL(url)
    if (parsed.protocol !== 'http:') return false
    const hostname = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase()
    return hostname !== 'localhost' && hostname !== '127.0.0.1' && hostname !== '::1'
  } catch {
    return false
  }
}

function getNativeTransport(value: unknown): string {
  if (!value || typeof value !== 'object') return 'unknown'
  const raw = value as Record<string, unknown>
  if (raw.type === 'sse') return 'sse'
  if (typeof raw.url === 'string' || typeof raw.httpUrl === 'string' || raw.type === 'remote')
    return 'http'
  if (typeof raw.command === 'string' || Array.isArray(raw.command)) return 'stdio'
  return 'unknown'
}

function findNativeName(servers: Record<string, unknown>, name: string): string | undefined {
  const normalized = normalizeMcpName(name)
  return Object.keys(servers).find((key) => normalizeMcpName(key) === normalized)
}

function compactObject(value: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {}
  for (const [key, val] of Object.entries(value)) {
    if (val === undefined) continue
    if (Array.isArray(val) && val.length === 0) continue
    if (val && typeof val === 'object' && !Array.isArray(val) && Object.keys(val).length === 0)
      continue
    result[key] = val
  }
  return result
}

async function readText(path: string): Promise<string> {
  return readFile(path, 'utf-8').catch(() => '')
}

async function writeText(path: string, value: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true })
  await writeFile(path, value.endsWith('\n') ? value : `${value}\n`, 'utf-8')
}

export function readCodexTomlServers(text: string): Record<string, unknown> {
  const servers: Record<string, unknown> = {}
  const lines = text.split(/\r?\n/)
  let current: Record<string, unknown> | null = null
  for (const line of lines) {
    const section = line.match(/^\s*\[mcp_servers\.([^\]]+)\]\s*$/)
    if (section) {
      const parsedSection = parseCodexMcpSection(section[1])
      if (!parsedSection) {
        current = null
        continue
      }
      const server = (servers[parsedSection.name] ||= {}) as Record<string, unknown>
      if (parsedSection.child) {
        current = (server[parsedSection.child] ||= {}) as Record<string, unknown>
      } else {
        current = server
      }
      continue
    }
    if (/^\s*\[/.test(line)) {
      current = null
      continue
    }
    if (!current) continue
    const match = line.match(/^\s*([A-Za-z0-9_-]+)\s*=\s*(.+?)\s*$/)
    if (!match) continue
    current[match[1]] = parseTomlValue(match[2])
  }
  return servers
}

function writeCodexTomlServer(text: string, server: ManagedMcpServer, oldName?: string): string {
  const withoutOld = oldName
    ? removeCodexTomlServer(text, oldName)
    : removeCodexTomlServer(text, server.name)
  const native = toCodexNative(server)
  const section = [`[mcp_servers.${quoteTomlKey(server.name)}]`]
  for (const [key, value] of Object.entries(native)) {
    section.push(`${key} = ${formatTomlValue(value)}`)
  }
  const trimmed = withoutOld.trimEnd()
  return `${trimmed}${trimmed ? '\n\n' : ''}${section.join('\n')}\n`
}

function removeCodexTomlServer(text: string, name: string): string {
  const normalized = normalizeMcpName(name)
  const lines = text.split(/\r?\n/)
  const output: string[] = []
  let skipping = false
  for (const line of lines) {
    const section = line.match(/^\s*\[mcp_servers\.([^\]]+)\]\s*$/)
    if (section) {
      const parsedSection = parseCodexMcpSection(section[1])
      skipping = Boolean(parsedSection && normalizeMcpName(parsedSection.name) === normalized)
    } else if (skipping && /^\s*\[/.test(line)) {
      skipping = false
    }
    if (!skipping) output.push(line)
  }
  return output.join('\n').replace(/\n{3,}/g, '\n\n')
}

function parseCodexMcpSection(value: string): { name: string; child?: string } | null {
  const trimmed = value.trim()
  const quoted = trimmed.match(/^"((?:\\.|[^"])*)"(?:\.([A-Za-z0-9_-]+))?$/)
  if (quoted) {
    return {
      name: unquoteTomlKey(`"${quoted[1]}"`),
      child: quoted[2]
    }
  }

  const [name, child, ...rest] = trimmed.split('.')
  if (!name || rest.length > 0) return null
  return { name, child }
}

function toCodexNative(server: ManagedMcpServer): Record<string, unknown> {
  if ((server.transport === 'http' || server.transport === 'sse') && server.url) {
    return compactObject({
      url: server.url,
      http_headers: server.headers,
      disabled: server.disabled
    })
  }
  return compactObject({
    command: server.command,
    args: server.args,
    env: server.env,
    disabled: server.disabled
  })
}

function parseTomlValue(value: string): unknown {
  const trimmed = value.trim()
  if (trimmed === 'true') return true
  if (trimmed === 'false') return false
  if (trimmed.startsWith('"')) return trimmed.replace(/^"|"$/g, '').replace(/\\"/g, '"')
  if (trimmed.startsWith('[')) {
    const raw = trimmed.replace(/^\[|\]$/g, '').trim()
    if (!raw) return []
    return splitTomlItems(raw).map((item) => String(parseTomlValue(item.trim())))
  }
  if (trimmed.startsWith('{')) {
    const raw = trimmed.replace(/^\{|\}$/g, '').trim()
    const result: Record<string, unknown> = {}
    if (!raw) return result
    for (const item of splitTomlItems(raw)) {
      const separator = findTomlSeparator(item, '=')
      if (separator < 0) continue
      const key = unquoteTomlKey(item.slice(0, separator))
      if (key) result[key] = parseTomlValue(item.slice(separator + 1))
    }
    return result
  }
  return trimmed
}

function splitTomlItems(value: string): string[] {
  const items: string[] = []
  let start = 0
  let quoted = false
  let escaped = false
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index]
    if (escaped) {
      escaped = false
      continue
    }
    if (character === '\\' && quoted) {
      escaped = true
      continue
    }
    if (character === '"') {
      quoted = !quoted
      continue
    }
    if (character === ',' && !quoted) {
      items.push(value.slice(start, index).trim())
      start = index + 1
    }
  }
  items.push(value.slice(start).trim())
  return items.filter(Boolean)
}

function findTomlSeparator(value: string, separator: string): number {
  let quoted = false
  let escaped = false
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index]
    if (escaped) {
      escaped = false
      continue
    }
    if (character === '\\' && quoted) {
      escaped = true
      continue
    }
    if (character === '"') {
      quoted = !quoted
      continue
    }
    if (character === separator && !quoted) return index
  }
  return -1
}

function formatTomlValue(value: unknown): string {
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  if (Array.isArray(value)) return `[${value.map(formatTomlValue).join(', ')}]`
  if (value && typeof value === 'object') {
    return `{ ${Object.entries(value as Record<string, unknown>)
      .map(([key, val]) => `${key} = ${formatTomlValue(val)}`)
      .join(', ')} }`
  }
  return `"${String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`
}

function quoteTomlKey(value: string): string {
  return `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`
}

function unquoteTomlKey(value: string): string {
  return value.trim().replace(/^"|"$/g, '').replace(/\\"/g, '"')
}
