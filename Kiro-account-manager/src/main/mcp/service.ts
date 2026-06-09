import { normalizeMcpManagerConfig, normalizeMcpName, normalizeMcpServer } from './config'
import { getAllMcpAgentViews } from './adapters'
import type {
  ManagedMcpServer,
  McpAgentAdapter,
  McpAgentView,
  McpListResult,
  McpManagerConfig,
  McpOperationResult,
  McpSyncEntry,
  McpSyncResult
} from './types'

export { defaultMcpManagerConfig, normalizeMcpManagerConfig, normalizeMcpName } from './config'
export type {
  ManagedMcpServer,
  McpAgentView,
  McpListResult,
  McpManagerConfig,
  McpOperationResult,
  McpSyncResult
} from './types'

export async function listMcpState(configValue: unknown): Promise<McpListResult> {
  const config = normalizeMcpManagerConfig(configValue)
  const servers = Object.values(config.servers).sort((a, b) => a.name.localeCompare(b.name))
  const managedNames = new Set(servers.map((server) => normalizeMcpName(server.name)))
  const agents: McpAgentView[] = []

  for (const agent of getAllMcpAgentViews()) {
    if (!agent.installed) continue
    if (!agent.adapter) {
      agents.push({
        id: agent.id,
        displayName: agent.displayName,
        installed: true,
        supported: false,
        count: 0,
        servers: []
      })
      continue
    }
    const read = await agent.adapter.read()
    const nativeServers = Object.entries(read.servers).map(([name, native]) => {
      const managed = managedNames.has(normalizeMcpName(name))
      const canonical = config.servers[normalizeMcpName(name)]
      const parsed = agent.adapter!.fromNative(name, native)
      return {
        name,
        managed,
        synced: Boolean(canonical && nativeEquals(agent.adapter!, native, canonical)),
        nativeTransport:
          canonical?.transport || parsed?.transport || agent.adapter!.getNativeTransport(native),
        configPath: read.configPath,
        server: canonical || parsed || undefined,
        warning: read.success ? undefined : read.error
      }
    })
    agents.push({
      id: agent.id,
      displayName: agent.displayName,
      installed: true,
      supported: true,
      configPath: read.configPath,
      count: nativeServers.length,
      servers: nativeServers.sort((a, b) => a.name.localeCompare(b.name))
    })
  }
  return { servers, agents, config }
}

export async function saveMcpServer(
  input: { server: unknown; oldName?: string },
  configValue: unknown,
  saveConfig: (config: McpManagerConfig) => void
): Promise<McpOperationResult> {
  const config = normalizeMcpManagerConfig(configValue)
  const server = normalizeMcpServer(input.server)
  if (!server) return { success: false, error: 'Invalid MCP server' }
  if (server.transport === 'stdio' && !server.command?.trim())
    return { success: false, error: 'Command is required' }
  if ((server.transport === 'http' || server.transport === 'sse') && !server.url?.trim())
    return { success: false, error: 'URL is required' }

  const now = Date.now()
  const oldKey = input.oldName ? normalizeMcpName(input.oldName) : undefined
  const key = normalizeMcpName(server.name)
  const previous = oldKey ? config.servers[oldKey] : config.servers[key]
  const next: ManagedMcpServer = {
    ...server,
    name: server.name.trim(),
    createdAt: previous?.createdAt || server.createdAt || now,
    updatedAt: now,
    source: server.source || previous?.source || 'manual'
  }
  if (oldKey && oldKey !== key) {
    delete config.servers[oldKey]
    config.managedKeys = config.managedKeys.filter((item) => item !== oldKey)
  }
  config.servers[key] = next
  if (!config.managedKeys.includes(key)) config.managedKeys.push(key)
  saveConfig(config)

  const sync = await syncSingleMcpServer(next, input.oldName)
  config.lastSyncAt = sync.syncedAt
  saveConfig(config)
  return {
    success: sync.success,
    server: next,
    config,
    results: sync.results,
    error: sync.success ? undefined : 'Some agents failed to sync'
  }
}

export async function deleteMcpServer(
  input: { name: string },
  configValue: unknown,
  saveConfig: (config: McpManagerConfig) => void
): Promise<McpOperationResult> {
  const config = normalizeMcpManagerConfig(configValue)
  const key = normalizeMcpName(input.name)
  delete config.servers[key]
  config.managedKeys = config.managedKeys.filter((item) => item !== key)
  saveConfig(config)

  const results: McpSyncEntry[] = []
  for (const { adapter } of getInstalledSupportedAdapters()) {
    const result = await adapter.deleteServer(input.name)
    results.push({
      serverName: input.name,
      agent: adapter.id,
      success: result.success,
      status: result.status,
      configPath: result.configPath,
      error: result.error
    })
  }
  const syncedAt = new Date().toISOString()
  config.lastSyncAt = syncedAt
  saveConfig(config)
  return { success: results.every((result) => result.success), results, config }
}

export async function syncMcpServers(
  configValue: unknown,
  oldName?: string
): Promise<McpSyncResult> {
  const config = normalizeMcpManagerConfig(configValue)
  const results: McpSyncEntry[] = []
  for (const server of Object.values(config.servers)) {
    for (const { adapter } of getInstalledSupportedAdapters()) {
      const result = await adapter.writeServer(server, oldName)
      results.push({
        serverName: server.name,
        agent: adapter.id,
        success: result.success,
        status: result.status,
        configPath: result.configPath,
        error: result.error
      })
    }
  }
  return {
    success: results.every((result) => result.success),
    results,
    syncedAt: new Date().toISOString()
  }
}

async function syncSingleMcpServer(
  server: ManagedMcpServer,
  oldName?: string
): Promise<McpSyncResult> {
  const results: McpSyncEntry[] = []
  for (const { adapter } of getInstalledSupportedAdapters()) {
    const result = await adapter.writeServer(server, oldName)
    results.push({
      serverName: server.name,
      agent: adapter.id,
      success: result.success,
      status: result.status,
      configPath: result.configPath,
      error: result.error
    })
  }
  return {
    success: results.every((result) => result.success),
    results,
    syncedAt: new Date().toISOString()
  }
}

export async function syncAndSaveMcpServers(
  configValue: unknown,
  saveConfig: (config: McpManagerConfig) => void
): Promise<McpSyncResult> {
  const config = normalizeMcpManagerConfig(configValue)
  const result = await syncMcpServers(config)
  config.lastSyncAt = result.syncedAt
  saveConfig(config)
  return result
}

export async function importMcpFromAgents(
  input: { agents?: string[]; overwrite?: boolean },
  configValue: unknown,
  saveConfig: (config: McpManagerConfig) => void
): Promise<McpOperationResult> {
  const config = normalizeMcpManagerConfig(configValue)
  const agentFilter = new Set(input.agents || [])
  const results: McpSyncEntry[] = []
  for (const { adapter } of getInstalledSupportedAdapters()) {
    if (agentFilter.size > 0 && !agentFilter.has(adapter.id)) continue
    const read = await adapter.read()
    if (!read.success) {
      results.push({
        agent: adapter.id,
        success: false,
        status: 'failed',
        configPath: read.configPath,
        error: read.error
      })
      continue
    }
    for (const [name, native] of Object.entries(read.servers)) {
      const server = adapter.fromNative(name, native)
      if (!server) continue
      const key = normalizeMcpName(server.name)
      const existing = config.servers[key]
      if (!input.overwrite && existing) {
        const enriched = enrichMcpServer(existing, server)
        const updated = !sameMcpServer(existing, enriched)
        if (updated) config.servers[key] = enriched
        results.push({
          serverName: server.name,
          agent: adapter.id,
          success: true,
          status: updated ? 'updated' : 'skipped',
          configPath: read.configPath
        })
        continue
      }
      config.servers[key] = { ...server, updatedAt: Date.now() }
      if (!config.managedKeys.includes(key)) config.managedKeys.push(key)
      results.push({
        serverName: server.name,
        agent: adapter.id,
        success: true,
        status: 'created',
        configPath: read.configPath
      })
    }
  }
  saveConfig(config)
  const sync = await syncAndSaveMcpServers(config, saveConfig)
  return {
    success: results.every((result) => result.success) && sync.success,
    results: [...results, ...sync.results],
    config
  }
}

export async function saveMcpConfigPatch(
  patch: Partial<McpManagerConfig>,
  configValue: unknown,
  saveConfig: (config: McpManagerConfig) => void
): Promise<McpOperationResult> {
  const config = normalizeMcpManagerConfig({ ...normalizeMcpManagerConfig(configValue), ...patch })
  saveConfig(config)
  return { success: true, config }
}

function enrichMcpServer(
  existing: ManagedMcpServer,
  incoming: ManagedMcpServer
): ManagedMcpServer {
  const sameRemote =
    (existing.transport === 'http' || existing.transport === 'sse') &&
    (incoming.transport === 'http' || incoming.transport === 'sse') &&
    existing.url === incoming.url
  const sameStdio =
    existing.transport === 'stdio' &&
    incoming.transport === 'stdio' &&
    existing.command === incoming.command

  if (!sameRemote && !sameStdio) return existing

  const headers = { ...(incoming.headers || {}), ...(existing.headers || {}) }
  const env = { ...(incoming.env || {}), ...(existing.env || {}) }
  return {
    ...existing,
    headers: Object.keys(headers).length > 0 ? headers : undefined,
    env: Object.keys(env).length > 0 ? env : undefined,
    updatedAt: Date.now()
  }
}

function sameMcpServer(left: ManagedMcpServer, right: ManagedMcpServer): boolean {
  return stableStringify({ ...left, updatedAt: 0 }) === stableStringify({ ...right, updatedAt: 0 })
}

function getInstalledSupportedAdapters(): Array<{ adapter: McpAgentAdapter }> {
  return getAllMcpAgentViews()
    .filter((agent) => agent.installed && agent.adapter?.supported)
    .map((agent) => ({ adapter: agent.adapter! }))
}

function nativeEquals(
  adapter: McpAgentAdapter,
  native: unknown,
  server: ManagedMcpServer
): boolean {
  return stableStringify(native) === stableStringify(adapter.toNative(server))
}

function stableStringify(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`
  if (value && typeof value === 'object') {
    return `{${Object.entries(value as Record<string, unknown>)
      .filter(([, val]) => val !== undefined)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, val]) => `${JSON.stringify(key)}:${stableStringify(val)}`)
      .join(',')}}`
  }
  return JSON.stringify(value)
}
