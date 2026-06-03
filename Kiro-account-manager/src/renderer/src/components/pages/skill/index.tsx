import { useEffect, useRef, useState } from 'react'
import {
  Alert,
  Badge,
  Button,
  Input,
  Space,
  Switch,
  Table,
  Tabs,
  Tag,
  Tooltip,
  Typography
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import {
  Copy,
  PackagePlus,
  Radar,
  Repeat2,
  RefreshCw,
  RotateCw,
  Search,
  Settings2,
  Store,
  Trash2
} from 'lucide-react'
import { useTranslation } from '@/hooks/useTranslation'
import { BatchSyncModal } from './BatchSyncModal'
import { FullSyncModal } from './FullSyncModal'
import { SourceIcon, StatusIcon } from './icons'
import { InstallModal } from './InstallModal'
import { statusLabelEn, statusLabelZh } from './labels'
import { MarketManagementModal } from './MarketManagementModal'
import { SettingsModal } from './SettingsModal'
import type { SkillsSkillView } from './types'
import { useSkillsManager } from './useSkillsManager'

export function SkillsPage(): React.ReactNode {
  const tableContainerRef = useRef<HTMLDivElement | null>(null)
  const [tableScrollY, setTableScrollY] = useState(480)
  const { t } = useTranslation()
  const isEn = t('common.unknown') === 'Unknown'
  const {
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
    updateStatuses,
    load,
    runCheck,
    runCheckAll,
    runDelete,
    runInstall,
    runSync,
    runSyncFromAgent,
    runUpdate,
    saveConfigPatch,
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
    updateSkillAutoUpdate
  } = useSkillsManager(isEn)

  const statusLabel = isEn ? statusLabelEn : statusLabelZh

  useEffect(() => {
    const container = tableContainerRef.current
    if (!container) return

    const updateTableScrollY = (): void => {
      const title = container.querySelector('.ant-table-title') as HTMLElement | null
      const header = container.querySelector('.ant-table-thead') as HTMLElement | null
      const pagination = container.querySelector('.ant-table-pagination') as HTMLElement | null
      const containerHeight = container.clientHeight
      const titleHeight = title?.offsetHeight || 0
      const headerHeight = header?.offsetHeight || 0
      const paginationHeight = pagination?.offsetHeight || 0
      const nextHeight = Math.max(200, containerHeight - titleHeight - headerHeight - paginationHeight - 8)
      setTableScrollY(nextHeight)
    }

    updateTableScrollY()
    const observer = new ResizeObserver(() => updateTableScrollY())
    observer.observe(container)
    window.addEventListener('resize', updateTableScrollY)

    return () => {
      observer.disconnect()
      window.removeEventListener('resize', updateTableScrollY)
    }
  }, [activeAgent, filteredSkills.length, query, selected.length])

  const columns: ColumnsType<SkillsSkillView> = [
    {
      title: isEn ? 'Skill' : 'Skill',
      dataIndex: 'name',
      key: 'name',
      width: 320,
      render: (_value, skill) => (
        <div className="min-w-0">
          <div className="font-medium text-foreground">{skill.name}</div>
          <div className="line-clamp-2 text-xs text-muted-foreground">{skill.description}</div>
          <div className="truncate font-mono text-[10px] text-muted-foreground/80">{skill.path}</div>
        </div>
      )
    },
    {
      title: isEn ? 'Source' : '来源',
      key: 'source',
      width: 180,
      render: (_value, skill) => (
        <div className="flex min-w-0 items-center gap-2">
          <SourceIcon skill={skill} />
          <span className="truncate">{skill.source || (isEn ? 'Local' : '本地')}</span>
        </div>
      )
    },
    {
      title: isEn ? 'Status' : '状态',
      key: 'status',
      width: 150,
      render: (_value, skill) => {
        const isLocal = !skill.sourceType
        if (isLocal) return <span className="text-muted-foreground">-</span>
        const status = updateStatuses[`${skill.agent}:${skill.name}`]
        const resolvedStatus = status?.status || 'unknown'
        if (resolvedStatus === 'unknown') {
          return <span className="text-muted-foreground">{isEn ? 'Checking...' : '检查中...'}</span>
        }
        return (
          <div>
            <div className="flex items-center gap-2">
              <StatusIcon status={resolvedStatus} />
              <span>{statusLabel[resolvedStatus]}</span>
            </div>
            {status?.reason ? (
              <div className="mt-1 text-[10px] text-muted-foreground">{status.reason}</div>
            ) : null}
          </div>
        )
      }
    },
    {
      title: isEn ? 'Auto Update' : '自动更新',
      key: 'autoUpdate',
      width: 88,
      render: (_value, skill) => {
        if (!skill.sourceType) return <span className="text-muted-foreground">-</span>
        return (
          <Switch
            size="small"
            checked={skill.autoUpdate}
            onChange={(enabled) => void updateSkillAutoUpdate(skill.name, enabled)}
          />
        )
      }
    },
    {
      title: isEn ? 'Actions' : '操作',
      key: 'actions',
      width: 148,
      fixed: 'right',
      render: (_value, skill) => {
        const isLocal = !skill.sourceType
        return (
          <Space size={4}>
            {!isLocal ? (
              <>
                <Tooltip title={isEn ? 'Check update' : '检查更新'}>
                  <Button size="small" type="text" icon={<Radar className="h-3.5 w-3.5" />} onClick={() => void runCheck(skill.name)} />
                </Tooltip>
                <Tooltip title={isEn ? 'Update' : '更新'}>
                  <Button size="small" type="text" icon={<RotateCw className="h-3.5 w-3.5" />} onClick={() => void runUpdate([skill.name])} />
                </Tooltip>
              </>
            ) : null}
            <Tooltip title={isEn ? 'Sync to all' : '同步到全部'}>
              <Button
                size="small"
                type="text"
                icon={<Copy className="h-3.5 w-3.5" />}
                onClick={() => void runSync([skill.name], otherAgents.map((agent) => agent.id))}
              />
            </Tooltip>
            <Tooltip title={isEn ? 'Delete' : '删除'}>
              <Button
                size="small"
                type="text"
                danger
                icon={<Trash2 className="h-3.5 w-3.5" />}
                onClick={() => void runDelete(false, [skill.name])}
              />
            </Tooltip>
          </Space>
        )
      }
    }
  ]

  return (
    <div className="flex h-full flex-col gap-3 overflow-hidden p-4">
      <div className="flex items-center gap-3">
        <div className="bg-primary/10 p-2">
          <Settings2 className="h-5 w-5 text-primary" />
        </div>
        <div className="min-w-0 flex-1">
          <Typography.Title level={4} style={{ margin: 0 }}>
            {isEn ? 'Skills Manager' : 'Skills 管理'}
          </Typography.Title>
          <Typography.Text type="secondary">
            {isEn ? 'Manage local agent skills across installed agents' : '管理本机已安装 Agent 的本地 skills'}
          </Typography.Text>
        </div>
        <Button icon={<Store className="h-4 w-4" />} onClick={() => setShowMarketDialog(true)}>
          {isEn ? 'Market' : '市场管理'}
        </Button>
        <Button icon={<Settings2 className="h-4 w-4" />} onClick={() => setShowSettingsDialog(true)}>
          {isEn ? 'Settings' : '设置'}
        </Button>
        <Button icon={<RefreshCw className="h-4 w-4" />} onClick={() => void load()} loading={busy === 'load'}>
          {isEn ? 'Refresh' : '刷新'}
        </Button>
      </div>

      {!hasSkillsApi ? (
        <Alert
          type="error"
          showIcon
          message={
            isEn
              ? 'Skills API is not loaded. Please restart the Electron app.'
              : 'Skills API 尚未加载，请重启 Electron 应用。'
          }
        />
      ) : null}

      <div
        className="border px-4 py-3"
        style={{
          background: 'transparent',
          borderColor: 'var(--color-border)'
        }}
      >
        <div className="flex flex-wrap items-center gap-2">
          <Button type="primary" icon={<PackagePlus className="h-4 w-4" />} onClick={() => setShowInstallDialog(true)}>
            {isEn ? 'Install' : '安装'}
          </Button>
          <Button icon={<Radar className="h-4 w-4" />} onClick={() => void runCheckAll()} loading={busy === 'check'}>
            {isEn ? 'Check all' : '检查全部'}
          </Button>
          <Button
            icon={<Repeat2 className="h-4 w-4" />}
            onClick={() => {
              if (!syncSource) {
                setSyncSource(otherAgents.find((agent) => agent.skills.length > 0)?.id || '')
              }
              if (fullSyncTargets.length === 0 && currentAgent) {
                setFullSyncTargets([currentAgent.id])
              }
              setShowFullSyncDialog(true)
            }}
            disabled={agents.filter((agent) => agent.skills.length > 0).length === 0}
          >
            {isEn ? 'Sync' : '同步'}
          </Button>
        </div>
      </div>

      <Tabs
        style={{ marginBottom: 0 }}
        tabBarStyle={{ marginBottom: 8 }}
        activeKey={activeAgent}
        onChange={(key) => void setActiveAndPersist(key)}
        items={agents.map((agent) => ({
          key: agent.id,
          label: (
            <Badge
              count={agent.count}
              size="small"
              offset={[10, -2]}
              styles={{
                indicator: {
                  backgroundColor: 'var(--color-primary)',
                  color: 'var(--color-primary-foreground)',
                  boxShadow: '0 0 0 1px var(--color-background)'
                }
              }}
            >
              <span className="inline-block">{agent.displayName}</span>
            </Badge>
          )
        }))}
      />

      <div ref={tableContainerRef} className="min-h-0 flex-1 overflow-hidden">
        <Table
          rowKey={(skill) => `${skill.agent}:${skill.name}`}
          columns={columns}
          dataSource={filteredSkills}
          pagination={false}
          size="middle"
          loading={busy === 'load'}
          styles={{
            root: { borderRadius: 8, overflow: 'hidden' }
          }}
          title={() => (
            <div className="flex flex-wrap items-center gap-2">
              <Tag color="blue">{isEn ? 'Selected' : '已选'} {selected.length}</Tag>
              <Button icon={<RotateCw className="h-4 w-4" />} disabled={selected.length === 0} onClick={() => void runUpdate()}>
                {isEn ? 'Batch update' : '批量更新'}
              </Button>
              <Button danger icon={<Trash2 className="h-4 w-4" />} disabled={selected.length === 0} onClick={() => void runDelete(false)}>
                {isEn ? 'Batch delete' : '批量删除'}
              </Button>
              <Button icon={<Trash2 className="h-4 w-4" />} disabled={selected.length === 0} onClick={() => void runDelete(true)}>
                {isEn ? 'Delete all agents' : '从所有 Agents 删除'}
              </Button>
              <Button icon={<Copy className="h-4 w-4" />} disabled={selected.length === 0 || otherAgents.length === 0} onClick={() => setShowSyncDialog(true)}>
                {isEn ? 'Batch sync' : '批量同步'}
              </Button>
              <Input
                allowClear
                variant="filled"
                prefix={<Search className="h-3.5 w-3.5" />}
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder={isEn ? 'Search skills...' : '搜索 skills...'}
                className="ml-auto"
                style={{ width: 280 }}
              />
            </div>
          )}
          rowSelection={{
            type: 'checkbox',
            selectedRowKeys: selected.map((name) => `${activeAgent}:${name}`),
            onChange: (keys) =>
              setSelected(
                keys
                  .map((key) => String(key).split(':').slice(1).join(':'))
                  .filter(Boolean)
              )
          }}
          scroll={{ x: 1080, y: tableScrollY }}
          locale={{
            emptyText: isEn ? 'No skills found' : '暂无 skills'
          }}
        />
      </div>

      <InstallModal
        busy={busy === 'install'}
        isEn={isEn}
        open={showInstallDialog}
        source={installSource}
        skillNames={installSkillNames}
        targets={installTargets}
        agents={agents}
        onCancel={() => setShowInstallDialog(false)}
        onSourceChange={setInstallSource}
        onSkillNamesChange={setInstallSkillNames}
        onTargetsChange={setInstallTargets}
        onSubmit={() => void runInstall()}
      />

      <BatchSyncModal
        busy={busy === 'sync'}
        isEn={isEn}
        open={showSyncDialog}
        currentAgentName={currentAgent?.displayName || '-'}
        selectedCount={selected.length}
        targets={effectiveSyncTargets}
        agents={otherAgents}
        onCancel={() => setShowSyncDialog(false)}
        onTargetsChange={setSyncTargets}
        onSubmit={() => void runSync(selected, effectiveSyncTargets)}
      />

      <FullSyncModal
        busy={busy === 'sync'}
        isEn={isEn}
        open={showFullSyncDialog}
        sourceAgentId={syncSource}
        sourceAgentName={fullSyncSourceAgent?.displayName}
        sourceAgents={agents.filter((agent) => agent.skills.length > 0)}
        targets={effectiveFullSyncTargets}
        targetAgents={fullSyncTargetOptions}
        onCancel={() => setShowFullSyncDialog(false)}
        onSourceChange={(value) => {
          setSyncSource(value)
          setFullSyncTargets((prev) => prev.filter((id) => id !== value))
        }}
        onTargetsChange={setFullSyncTargets}
        onSubmit={() => void runSyncFromAgent(effectiveFullSyncTargets)}
      />

      <SettingsModal
        busy={busy === 'load'}
        isEn={isEn}
        open={showSettingsDialog}
        defaultAutoUpdate={config?.defaultAutoUpdate === true}
        defaultInstallMode={config?.defaultInstallMode || 'symlink'}
        gitlabToken={config?.gitlabToken}
        agents={agents}
        onCancel={() => setShowSettingsDialog(false)}
        onSubmit={async (values) => {
          const success = await saveConfigPatch(values)
          if (success) {
            setShowSettingsDialog(false)
          }
        }}
      />

      <MarketManagementModal
        isEn={isEn}
        open={showMarketDialog}
        onCancel={() => setShowMarketDialog(false)}
      />
    </div>
  )
}
