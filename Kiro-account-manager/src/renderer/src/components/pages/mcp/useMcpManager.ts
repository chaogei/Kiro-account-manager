import { useCallback, useEffect, useMemo, useState } from 'react'
import { App } from 'antd'
import type { ManagedMcpServer, McpAgentView, McpBusy, McpListResult, McpManagerConfig } from './types'

export function useMcpManager(isEn: boolean) {
  const { message, modal } = App.useApp()
  const [servers, setServers] = useState<ManagedMcpServer[]>([])
  const [agents, setAgents] = useState<McpAgentView[]>([])
  const [activeAgent, setActiveAgent] = useState('')
  const [query, setQuery] = useState('')
  const [busy, setBusy] = useState<McpBusy>('load')
  const [editing, setEditing] = useState<ManagedMcpServer | null | undefined>(undefined)
  const [showEditDialog, setShowEditDialog] = useState(false)
  const hasMcpApi = typeof window.api.mcpList === 'function'

  const load = useCallback(async () => {
    if (!hasMcpApi) {
      message.error(
        isEn
          ? 'MCP API is not loaded. Please restart the Electron app.'
          : 'MCP API 尚未加载，请重启 Electron 应用。'
      )
      setBusy(null)
      return
    }
    setBusy('load')
    try {
      const result = (await window.api.mcpList()) as McpListResult
      setServers(result.servers)
      setAgents(result.agents)
      const nextAgent = result.config.lastSelectedAgent || activeAgent || result.agents[0]?.id || ''
      setActiveAgent(
        result.agents.some((agent) => agent.id === nextAgent)
          ? nextAgent
          : result.agents[0]?.id || ''
      )
    } catch (error) {
      message.error(error instanceof Error ? error.message : String(error))
    } finally {
      setBusy(null)
    }
  }, [activeAgent, hasMcpApi, isEn, message])

  useEffect(() => {
    void load()
  }, [load])

  useEffect(() => {
    const unsubscribe = window.api.onMcpConfigChanged?.(() => {
      void load()
    })
    return () => unsubscribe?.()
  }, [load])

  const currentAgent = useMemo(
    () => agents.find((agent) => agent.id === activeAgent),
    [activeAgent, agents]
  )
  const kiroInstalled = useMemo(
    () => agents.some((agent) => agent.id === 'kiro' && agent.installed),
    [agents]
  )

  const setActiveAndPersist = useCallback(async (agentId: string) => {
    setActiveAgent(agentId)
    await window.api.mcpSaveConfig({ lastSelectedAgent: agentId } as Partial<McpManagerConfig>)
  }, [])

  const openCreate = useCallback(() => {
    setEditing(null)
    setShowEditDialog(true)
  }, [])

  const openEdit = useCallback((server: ManagedMcpServer) => {
    setEditing(server)
    setShowEditDialog(true)
  }, [])

  const saveServer = useCallback(
    async (server: ManagedMcpServer, oldName?: string) => {
      setBusy('save')
      const result = (await window.api.mcpSaveServer({ server, oldName })) as {
        success: boolean
        error?: string
      }
      setBusy(null)
      if (!result.success) {
        message.error(result.error || (isEn ? 'Save failed' : '保存失败'))
        await load()
        return
      }
      message.success(isEn ? 'Saved' : '已保存')
      setShowEditDialog(false)
      await load()
    },
    [isEn, load, message]
  )

  const deleteServer = useCallback(
    async (server: Pick<ManagedMcpServer, 'name'>) => {
      const confirmed = await modal.confirm({
        title: isEn ? 'Delete MCP registration?' : '删除 MCP 注册？',
        content: isEn
          ? `This will delete "${server.name}" from all supported local agents.`
          : `这会从所有支持的本地 Agent 中删除「${server.name}」。`,
        okText: isEn ? 'Delete' : '删除',
        cancelText: isEn ? 'Cancel' : '取消'
      })
      if (!confirmed) return
      setBusy('delete')
      const result = (await window.api.mcpDeleteServer({ name: server.name })) as {
        success: boolean
        error?: string
      }
      setBusy(null)
      if (!result.success) {
        message.error(result.error || (isEn ? 'Delete failed' : '删除失败'))
        await load()
        return
      }
      message.success(isEn ? 'Deleted' : '已删除')
      await load()
    },
    [isEn, load, message, modal]
  )

  const importFromAgents = useCallback(async () => {
    setBusy('import')
    const result = await window.api.mcpImportFromAgents({ overwrite: false })
    setBusy(null)
    if (!result.success) {
      message.warning(result.error || (isEn ? 'Some configs failed to import' : '部分配置导入失败'))
    } else {
      message.success(isEn ? 'Import complete' : '导入完成')
    }
    await load()
  }, [isEn, load, message])

  return {
    activeAgent,
    agents,
    busy,
    currentAgent,
    editing,
    hasMcpApi,
    kiroInstalled,
    query,
    servers,
    showEditDialog,
    deleteServer,
    importFromAgents,
    load,
    openCreate,
    openEdit,
    saveServer,
    setActiveAndPersist,
    setQuery,
    setShowEditDialog
  }
}
