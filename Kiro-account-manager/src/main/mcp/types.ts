export type McpTransport = 'stdio' | 'http' | 'sse'
export type McpSyncStatus = 'created' | 'updated' | 'skipped' | 'deleted' | 'failed'

export interface ManagedMcpServer {
  name: string
  title?: string
  description?: string
  transport: McpTransport
  command?: string
  args?: string[]
  cwd?: string
  env?: Record<string, string>
  url?: string
  headers?: Record<string, string>
  disabled?: boolean
  autoApprove?: string[]
  disabledTools?: string[]
  timeout?: number
  source?: 'manual' | 'imported' | 'kiro-settings'
  createdAt: number
  updatedAt: number
}

export interface McpManagerConfig {
  version: 1
  servers: Record<string, ManagedMcpServer>
  managedKeys: string[]
  lastSelectedAgent?: string
  autoSyncOnStartup: boolean
  lastSyncAt?: string
}

export interface NativeMcpServerView {
  name: string
  managed: boolean
  synced: boolean
  nativeTransport: string
  configPath: string
  server?: ManagedMcpServer
  warning?: string
}

export interface McpAgentView {
  id: string
  displayName: string
  installed: boolean
  supported: boolean
  configPath?: string
  count: number
  servers: NativeMcpServerView[]
}

export interface McpListResult {
  servers: ManagedMcpServer[]
  agents: McpAgentView[]
  config: McpManagerConfig
}

export interface McpOperationResult {
  success: boolean
  message?: string
  results?: McpSyncEntry[]
  server?: ManagedMcpServer
  config?: McpManagerConfig
  error?: string
}

export interface McpSyncEntry {
  serverName?: string
  agent: string
  success: boolean
  status: McpSyncStatus
  configPath?: string
  error?: string
}

export interface McpSyncResult {
  success: boolean
  results: McpSyncEntry[]
  syncedAt: string
  error?: string
}

export interface McpAgentConfigReadResult {
  success: boolean
  configPath: string
  servers: Record<string, unknown>
  error?: string
}

export interface McpWriteResult {
  success: boolean
  status: McpSyncStatus
  configPath: string
  error?: string
}

export interface McpAgentAdapter {
  id: string
  displayName: string
  supported: boolean
  detect: () => boolean
  getConfigPath: () => string
  read: () => Promise<McpAgentConfigReadResult>
  writeServer: (server: ManagedMcpServer, oldName?: string) => Promise<McpWriteResult>
  deleteServer: (name: string) => Promise<McpWriteResult>
  toNative: (server: ManagedMcpServer) => unknown
  fromNative: (name: string, value: unknown) => ManagedMcpServer | null
  getNativeTransport: (value: unknown) => string
}
