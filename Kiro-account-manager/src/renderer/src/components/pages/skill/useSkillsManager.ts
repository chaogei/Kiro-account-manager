import { useCallback, useEffect, useMemo, useState } from 'react'
import { App } from 'antd'
import type { OperationBusy, SkillsAgentView, SkillsManagerConfig, SkillUpdateStatus } from './types'

// The return shape is intentionally broad because this hook is the page's local module boundary.
// eslint-disable-next-line @typescript-eslint/explicit-function-return-type
export function useSkillsManager(isEn: boolean) {
  const { message, modal } = App.useApp()
  const [agents, setAgents] = useState<SkillsAgentView[]>([])
  const [config, setConfig] = useState<SkillsManagerConfig | null>(null)
  const [activeAgent, setActiveAgent] = useState('')
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState<string[]>([])
  const [busy, setBusy] = useState<OperationBusy>('load')
  const [installSource, setInstallSource] = useState('')
  const [installSkillNames, setInstallSkillNames] = useState('')
  const [installTargets, setInstallTargets] = useState<string[]>([])
  const [showInstallDialog, setShowInstallDialog] = useState(false)
  const [syncTargets, setSyncTargets] = useState<string[]>([])
  const [showSyncDialog, setShowSyncDialog] = useState(false)
  const [syncSource, setSyncSource] = useState('')
  const [fullSyncTargets, setFullSyncTargets] = useState<string[]>([])
  const [showFullSyncDialog, setShowFullSyncDialog] = useState(false)
  const [showSettingsDialog, setShowSettingsDialog] = useState(false)
  const [showMarketDialog, setShowMarketDialog] = useState(false)
  const [updateStatuses, setUpdateStatuses] = useState<
    Record<string, { status: SkillUpdateStatus; reason?: string }>
  >({})
  const hasSkillsApi = typeof window.api.skillsList === 'function'
  const initialCheckDone = useMemo(() => ({ current: false }), [])

  const load = useCallback(async () => {
    if (!hasSkillsApi) {
      message.error(
        isEn
          ? 'Skills API is not loaded. Please restart the Electron app.'
          : 'Skills API 尚未加载，请重启 Electron 应用。'
      )
      setBusy(null)
      return
    }

    setBusy('load')
    try {
      const result = await window.api.skillsList()
      setAgents(result.agents)
      setConfig(result.config)
      const nextActive = result.config.lastSelectedAgent || activeAgent || result.agents[0]?.id || ''
      const resolvedActive = result.agents.some((agent) => agent.id === nextActive)
        ? nextActive
        : result.agents[0]?.id || ''
      setActiveAgent(resolvedActive)
      if (installTargets.length === 0) {
        setInstallTargets(result.agents.map((agent) => agent.id))
      }
      if (syncTargets.length === 0) {
        setSyncTargets(result.agents.filter((agent) => agent.id !== resolvedActive).map((agent) => agent.id))
      }
      if (fullSyncTargets.length === 0 && resolvedActive) {
        setFullSyncTargets([resolvedActive])
      }
    } catch (error) {
      message.error(error instanceof Error ? error.message : String(error))
    } finally {
      setBusy(null)
    }
  }, [activeAgent, fullSyncTargets.length, hasSkillsApi, installTargets.length, isEn, message, syncTargets.length])

  useEffect(() => {
    void load()
  }, [load])

  const currentAgent = useMemo(
    () => agents.find((agent) => agent.id === activeAgent),
    [agents, activeAgent]
  )

  const otherAgents = useMemo(
    () => agents.filter((agent) => agent.id !== currentAgent?.id),
    [agents, currentAgent?.id]
  )

  const filteredSkills = useMemo(() => {
    const lower = query.trim().toLowerCase()
    const skills = currentAgent?.skills || []
    if (!lower) return skills
    return skills.filter(
      (skill) =>
        skill.name.toLowerCase().includes(lower) ||
        skill.description.toLowerCase().includes(lower) ||
        (skill.source || '').toLowerCase().includes(lower) ||
        skill.path.toLowerCase().includes(lower)
    )
  }, [currentAgent?.skills, query])

  const fullSyncSourceAgent = useMemo(
    () => agents.find((agent) => agent.id === syncSource),
    [agents, syncSource]
  )

  const fullSyncTargetOptions = useMemo(
    () => agents.filter((agent) => agent.id !== syncSource),
    [agents, syncSource]
  )

  const effectiveSyncTargets = useMemo(
    () => syncTargets.filter((id) => otherAgents.some((agent) => agent.id === id)),
    [otherAgents, syncTargets]
  )

  const effectiveFullSyncTargets = useMemo(
    () => fullSyncTargets.filter((id) => fullSyncTargetOptions.some((agent) => agent.id === id)),
    [fullSyncTargetOptions, fullSyncTargets]
  )

  const setActiveAndPersist = useCallback(
    async (agentId: string) => {
      setActiveAgent(agentId)
      setSelected([])
      setSyncTargets(agents.filter((agent) => agent.id !== agentId).map((agent) => agent.id))
      setFullSyncTargets([agentId])
      await window.api.skillsSaveConfig({ lastSelectedAgent: agentId })
    },
    [agents]
  )

  const saveConfigPatch = useCallback(
    async (patch: Partial<SkillsManagerConfig>) => {
      setConfig((prev) => (prev ? { ...prev, ...patch } : prev))
      const result = await window.api.skillsSaveConfig(patch)
      if (!result.success) {
        message.error(result.error || (isEn ? 'Save failed' : '保存失败'))
        await load()
        return false
      }
      if (result.config) {
        setConfig(result.config)
      }
      return true
    },
    [isEn, load, message]
  )

  const updateSkillAutoUpdate = useCallback(
    async (skillName: string, enabled: boolean) => {
      if (!currentAgent) return
      const result = await window.api.skillsSetAutoUpdate({
        agent: currentAgent.id,
        skillName,
        enabled
      })
      if (!result.success) {
        message.error(result.error || (isEn ? 'Save failed' : '保存失败'))
        return
      }
      setAgents((prev) =>
        prev.map((agent) =>
          agent.id !== currentAgent.id
            ? agent
            : {
                ...agent,
                skills: agent.skills.map((skill) =>
                  skill.name === skillName ? { ...skill, autoUpdate: enabled } : skill
                )
              }
        )
      )
    },
    [currentAgent, isEn, message]
  )

  const runInstall = useCallback(async () => {
    if (!installSource.trim() || installTargets.length === 0) return
    setBusy('install')
    const skillNames = installSkillNames
      .split(',')
      .map((value) => value.trim())
      .filter(Boolean)
    const result = await window.api.skillsInstall({
      source: installSource.trim(),
      agents: installTargets,
      skills: skillNames,
      copy: config?.defaultInstallMode === 'copy'
    })
    setBusy(null)
    if (result.success) {
      message.success(isEn ? 'Install complete' : '安装完成')
      setInstallSource('')
      setInstallSkillNames('')
      setShowInstallDialog(false)
      await load()
      return
    }
    message.error(result.error || (isEn ? 'Install failed' : '安装失败'))
  }, [installSkillNames, installSource, installTargets, isEn, load, message])

  const runDelete = useCallback(
    async (allAgents = false, names = selected) => {
      if (!currentAgent || names.length === 0) return
      const confirmed = await modal.confirm({
        title: isEn ? 'Delete skills?' : '确认删除 skills？',
        content: isEn
          ? `Delete ${names.length} skill(s)? Related auto-update settings will be removed.`
          : `确定删除 ${names.length} 个 skill 吗？相关自动更新配置会被清理。`
      })
      if (!confirmed) return

      setBusy('delete')
      const result = await window.api.skillsDelete({
        agent: currentAgent.id,
        skillNames: names,
        allAgents
      })
      setBusy(null)
      if (result.success) {
        message.success(isEn ? 'Deleted' : '已删除')
        setSelected([])
        await load()
        return
      }
      message.error(result.error || (isEn ? 'Delete failed' : '删除失败'))
    },
    [currentAgent, isEn, load, message, modal, selected]
  )

  const runSync = useCallback(
    async (skillNames = selected, targetAgents = effectiveSyncTargets) => {
      if (!currentAgent || skillNames.length === 0 || targetAgents.length === 0) return
      setBusy('sync')
      const result = await window.api.skillsSync({
        sourceAgent: currentAgent.id,
        skillNames,
        targetAgents
      })
      setBusy(null)
      if (result.success) {
        message.success(isEn ? 'Synced' : '同步完成')
        setShowSyncDialog(false)
        await load()
        return
      }
      message.error(result.error || (isEn ? 'Sync failed' : '同步失败'))
    },
    [currentAgent, effectiveSyncTargets, isEn, load, message, selected]
  )

  const runSyncFromAgent = useCallback(
    async (targetAgents = effectiveFullSyncTargets) => {
      if (!syncSource || targetAgents.length === 0) return
      const source = agents.find((agent) => agent.id === syncSource)
      if (!source || source.skills.length === 0) return
      setBusy('sync')
      const result = await window.api.skillsSync({
        sourceAgent: source.id,
        skillNames: source.skills.map((skill) => skill.name),
        targetAgents,
        overwrite: true
      })
      setBusy(null)
      if (result.success) {
        message.success(isEn ? 'Synced from agent' : '已从 Agent 全量同步')
        setShowFullSyncDialog(false)
        await load()
        return
      }
      message.error(result.error || (isEn ? 'Sync failed' : '同步失败'))
    },
    [agents, effectiveFullSyncTargets, isEn, load, message, syncSource]
  )

  const runUpdate = useCallback(
    async (skillNames = selected) => {
      if (!currentAgent || skillNames.length === 0) return
      setBusy('update')
      const result = await window.api.skillsUpdate({ agent: currentAgent.id, skillNames })
      setBusy(null)
      if (result.success) {
        message.success(isEn ? 'Update complete' : '更新完成')
        await load()
        return
      }
      message.error(result.error || (isEn ? 'Update failed' : '更新失败'))
    },
    [currentAgent, isEn, load, message, selected]
  )

  const runCheck = useCallback(
    async (skillName: string) => {
      if (!currentAgent) return
      setBusy('check')
      const result = await window.api.skillsCheckUpdate({
        agent: currentAgent.id,
        skillName
      })
      setBusy(null)
      setUpdateStatuses((prev) => ({
        ...prev,
        [`${currentAgent.id}:${skillName}`]: {
          status: result.status,
          reason: result.reason
        }
      }))
      if (!result.success || result.reason) {
        message[result.success ? 'info' : 'error'](
          result.reason || (isEn ? 'Check failed' : '检查失败')
        )
      }
    },
    [currentAgent, isEn, message]
  )

  const runCheckAll = useCallback(
    async () => {
      if (!currentAgent) return
      setBusy('check')
      const skills = filteredSkills.filter((s) => !!s.sourceType)
      const nextStatuses: Record<string, { status: string; reason?: string }> = {}
      for (const skill of skills) {
        const result = await window.api.skillsCheckUpdate({
          agent: currentAgent.id,
          skillName: skill.name
        })
        nextStatuses[`${currentAgent.id}:${skill.name}`] = {
          status: result.status,
          reason: result.reason
        }
      }
      setUpdateStatuses((prev) => ({ ...prev, ...nextStatuses }))
      setBusy(null)
    },
    [currentAgent, filteredSkills, isEn, message]
  )

  useEffect(() => {
    if (initialCheckDone.current) return
    if (busy === null && currentAgent && filteredSkills.length > 0) {
      initialCheckDone.current = true
      void runCheckAll()
    }
  }, [busy, currentAgent, filteredSkills.length, initialCheckDone, runCheckAll])

  return {
    activeAgent,
    agents,
    busy,
    config,
    currentAgent,
    effectiveFullSyncTargets,
    effectiveSyncTargets,
    filteredSkills,
    fullSyncSourceAgent,
    fullSyncTargetOptions,
    fullSyncTargets,
    hasSkillsApi,
    installSkillNames,
    installSource,
    installTargets,
    otherAgents,
    query,
    selected,
    showFullSyncDialog,
    showInstallDialog,
    showMarketDialog,
    showSettingsDialog,
    showSyncDialog,
    syncSource,
    syncTargets,
    updateStatuses,
    load,
    runCheck,
    runCheckAll,
    runDelete,
    runInstall,
    runSync,
    runSyncFromAgent,
    runUpdate,
    setActiveAndPersist,
    setFullSyncTargets,
    setInstallSkillNames,
    setInstallSource,
    setInstallTargets,
    setQuery,
    setSelected,
    setShowFullSyncDialog,
    setShowInstallDialog,
    setShowMarketDialog,
    setShowSettingsDialog,
    setShowSyncDialog,
    setSyncSource,
    setSyncTargets,
    updateSkillAutoUpdate,
    saveConfigPatch
  }
}
