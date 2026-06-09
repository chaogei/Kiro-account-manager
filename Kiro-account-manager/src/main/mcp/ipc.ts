import { ipcMain, type BrowserWindow } from 'electron'
import {
  defaultMcpManagerConfig,
  importMcpFromAgents,
  listMcpState,
  normalizeMcpManagerConfig,
  saveMcpConfigPatch,
  saveMcpServer,
  deleteMcpServer,
  type McpManagerConfig
} from './service'

interface StoreLike {
  get: (key: string, defaultValue?: unknown) => unknown
  set: (key: string, value: unknown) => void
}

const STORE_KEY = 'mcpManagerConfig'

export function registerMcpManagerIpcHandlers(
  getStore: () => StoreLike | null,
  getWindow?: () => BrowserWindow | null
): void {
  const readConfig = (): McpManagerConfig => {
    const store = getStore()
    return normalizeMcpManagerConfig(store?.get(STORE_KEY, defaultMcpManagerConfig()))
  }

  const saveConfig = (config: McpManagerConfig): void => {
    const store = getStore()
    if (!store) return
    store.set(STORE_KEY, normalizeMcpManagerConfig(config))
  }

  ipcMain.handle('mcp:list', async () => listMcpState(readConfig()))

  ipcMain.handle('mcp:get-config', async () => readConfig())

  ipcMain.handle('mcp:save-config', async (_event, patch: Partial<McpManagerConfig>) => {
    try {
      return await saveMcpConfigPatch(patch, readConfig(), saveConfig)
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : String(error) }
    }
  })

  ipcMain.handle(
    'mcp:save-server',
    async (_event, input: { server: unknown; oldName?: string }) => {
      try {
        const result = await saveMcpServer(input, readConfig(), saveConfig)
        getWindow?.()?.webContents.send('mcp:config-changed')
        return result
      } catch (error) {
        return { success: false, error: error instanceof Error ? error.message : String(error) }
      }
    }
  )

  ipcMain.handle('mcp:delete-server', async (_event, input: { name: string }) => {
    try {
      const result = await deleteMcpServer(input, readConfig(), saveConfig)
      getWindow?.()?.webContents.send('mcp:config-changed')
      return result
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : String(error) }
    }
  })

  ipcMain.handle(
    'mcp:import-from-agents',
    async (_event, input: { agents?: string[]; overwrite?: boolean }) => {
      try {
        const result = await importMcpFromAgents(input, readConfig(), saveConfig)
        getWindow?.()?.webContents.send('mcp:config-changed')
        return result
      } catch (error) {
        return { success: false, error: error instanceof Error ? error.message : String(error) }
      }
    }
  )
}

export async function runMcpStartupSync(
  getStore: () => StoreLike | null,
  getWindow?: () => BrowserWindow | null
): Promise<void> {
  const store = getStore()
  if (!store) return
  const config = normalizeMcpManagerConfig(store.get(STORE_KEY, defaultMcpManagerConfig()))
  try {
    const result = await importMcpFromAgents(
      { overwrite: false },
      config,
      (next) => store.set(STORE_KEY, next)
    )
    getWindow?.()?.webContents.send('mcp:config-changed')
    console.log(`[MCP] Startup reconciliation complete: ${result.results?.length || 0} operation(s)`)
  } catch (error) {
    console.warn('[MCP] Startup reconciliation failed:', error instanceof Error ? error.message : error)
  }
}
