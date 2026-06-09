import type { ManagedMcpServer, McpManagerConfig, McpTransport } from './types'

export function normalizeMcpName(name: string): string {
  return (
    (name || '')
      .toLowerCase()
      .replace(/[^a-z0-9._-]+/g, '-')
      .replace(/^[.-]+|[.-]+$/g, '')
      .slice(0, 128) || 'unnamed-mcp'
  )
}

export function defaultMcpManagerConfig(): McpManagerConfig {
  return { version: 1, servers: {}, managedKeys: [], autoSyncOnStartup: true }
}

export function normalizeMcpTransport(value: unknown): McpTransport {
  return value === 'http' || value === 'sse' || value === 'stdio' ? value : 'stdio'
}

export function normalizeMcpServer(value: unknown, fallbackName = ''): ManagedMcpServer | null {
  if (!value || typeof value !== 'object') return null
  const input = value as Partial<ManagedMcpServer>
  const name =
    typeof input.name === 'string' && input.name.trim() ? input.name.trim() : fallbackName
  if (!name) return null
  const now = Date.now()
  const transport = normalizeMcpTransport(input.transport)
  const server: ManagedMcpServer = {
    name,
    transport,
    createdAt: typeof input.createdAt === 'number' ? input.createdAt : now,
    updatedAt: typeof input.updatedAt === 'number' ? input.updatedAt : now
  }
  if (typeof input.title === 'string') server.title = input.title
  if (typeof input.description === 'string') server.description = input.description
  if (typeof input.command === 'string') server.command = input.command
  if (Array.isArray(input.args)) server.args = input.args.map(String)
  if (typeof input.cwd === 'string') server.cwd = input.cwd
  if (input.env && typeof input.env === 'object') server.env = stringRecord(input.env)
  if (typeof input.url === 'string') server.url = input.url
  if (input.headers && typeof input.headers === 'object')
    server.headers = stringRecord(input.headers)
  if (typeof input.disabled === 'boolean') server.disabled = input.disabled
  if (Array.isArray(input.autoApprove)) server.autoApprove = input.autoApprove.map(String)
  if (Array.isArray(input.disabledTools)) server.disabledTools = input.disabledTools.map(String)
  if (typeof input.timeout === 'number' && Number.isFinite(input.timeout))
    server.timeout = input.timeout
  if (
    input.source === 'manual' ||
    input.source === 'imported' ||
    input.source === 'kiro-settings'
  ) {
    server.source = input.source
  }
  return server
}

export function normalizeMcpManagerConfig(value: unknown): McpManagerConfig {
  const input = value && typeof value === 'object' ? (value as Partial<McpManagerConfig>) : {}
  const servers: Record<string, ManagedMcpServer> = {}
  const rawServers = input.servers && typeof input.servers === 'object' ? input.servers : {}
  for (const [key, rawServer] of Object.entries(rawServers)) {
    const server = normalizeMcpServer(rawServer, key)
    if (server) servers[normalizeMcpName(server.name)] = server
  }
  const managedKeys = Array.from(
    new Set([
      ...(Array.isArray(input.managedKeys)
        ? input.managedKeys.map((key) => normalizeMcpName(String(key)))
        : []),
      ...Object.keys(servers)
    ])
  )
  return {
    version: 1,
    servers,
    managedKeys,
    lastSelectedAgent:
      typeof input.lastSelectedAgent === 'string' ? input.lastSelectedAgent : undefined,
    autoSyncOnStartup: input.autoSyncOnStartup !== false,
    lastSyncAt: typeof input.lastSyncAt === 'string' ? input.lastSyncAt : undefined
  }
}

function stringRecord(value: object): Record<string, string> {
  const record: Record<string, string> = {}
  for (const [key, val] of Object.entries(value)) {
    if (key.trim()) record[key.trim()] = String(val)
  }
  return record
}
