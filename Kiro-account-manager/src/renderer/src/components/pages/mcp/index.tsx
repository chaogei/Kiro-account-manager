import { Alert, Badge, Button, Input, Space, Table, Tabs, Tag, Tooltip, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { Download, Edit, Plug, Plus, RefreshCw, Search, Trash2 } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { useTranslation } from '@/hooks/useTranslation'
import { EditModal } from './EditModal'
import type { ManagedMcpServer } from './types'
import { useMcpManager } from './useMcpManager'

type LocalMcpRegistration = {
  name: string
  managed: boolean
  nativeTransport: string
  configPath: string
  warning?: string
  managedServer?: ManagedMcpServer
}

export function McpPage(): React.ReactNode {
  const tableContainerRef = useRef<HTMLDivElement | null>(null)
  const [tableScrollY, setTableScrollY] = useState(480)
  const { t } = useTranslation()
  const isEn = t('common.unknown') === 'Unknown'
  const {
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
  } = useMcpManager(isEn)

  const lowerQuery = query.trim().toLowerCase()
  const currentRegistrations: LocalMcpRegistration[] = (currentAgent?.servers || [])
    .map((registration) => ({
      ...registration,
      managedServer:
        servers.find((server) => server.name.toLowerCase() === registration.name.toLowerCase()) ||
        registration.server || {
          name: registration.name,
          transport:
            registration.nativeTransport === 'http' || registration.nativeTransport === 'sse'
              ? registration.nativeTransport
              : 'stdio',
          createdAt: Date.now(),
          updatedAt: Date.now(),
          source: 'imported'
        }
    }))
    .filter((registration) => {
      if (!lowerQuery) return true
      const managed = registration.managedServer
      return (
        registration.name.toLowerCase().includes(lowerQuery) ||
        registration.nativeTransport.toLowerCase().includes(lowerQuery) ||
        registration.configPath.toLowerCase().includes(lowerQuery) ||
        (managed?.url || '').toLowerCase().includes(lowerQuery) ||
        (managed?.command || '').toLowerCase().includes(lowerQuery)
      )
    })

  useEffect(() => {
    const container = tableContainerRef.current
    if (!container) return

    const updateTableScrollY = (): void => {
      const title = container.querySelector('.ant-table-title') as HTMLElement | null
      const header = container.querySelector('.ant-table-thead') as HTMLElement | null
      const containerHeight = container.clientHeight
      const titleHeight = title?.offsetHeight || 0
      const headerHeight = header?.offsetHeight || 0
      setTableScrollY(Math.max(200, containerHeight - titleHeight - headerHeight - 8))
    }

    updateTableScrollY()
    const observer = new ResizeObserver(() => updateTableScrollY())
    observer.observe(container)
    window.addEventListener('resize', updateTableScrollY)

    return () => {
      observer.disconnect()
      window.removeEventListener('resize', updateTableScrollY)
    }
  }, [activeAgent, currentRegistrations.length, query])

  const columns: ColumnsType<LocalMcpRegistration> = [
    {
      title: 'MCP',
      key: 'registration',
      width: 320,
      render: (_value, registration) => (
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-medium text-foreground">{registration.name}</span>
            {registration.managedServer?.disabled ? (
              <Tag color="default">{isEn ? 'Disabled' : '已禁用'}</Tag>
            ) : null}
          </div>
          {registration.managedServer?.description ? (
            <div className="line-clamp-2 text-xs text-muted-foreground">
              {registration.managedServer.description}
            </div>
          ) : null}
          <div className="truncate font-mono text-[10px] text-muted-foreground/80">
            {registration.managedServer?.url ||
              [
                registration.managedServer?.command,
                ...(registration.managedServer?.args || [])
              ]
                .filter(Boolean)
                .join(' ') ||
              registration.configPath}
          </div>
        </div>
      )
    },
    {
      title: isEn ? 'Transport' : '传输',
      dataIndex: 'nativeTransport',
      width: 90,
      render: (transport: string) =>
        transport === 'unknown' ? (
          <span className="text-muted-foreground">-</span>
        ) : (
          <Tag color={transport === 'stdio' ? 'blue' : 'green'}>{transport}</Tag>
        )
    },
    {
      title: isEn ? 'Config File' : '配置文件',
      key: 'configPath',
      render: (_value, registration) => (
        <div className="truncate font-mono text-[11px] text-muted-foreground">
          {registration.configPath}
        </div>
      )
    },
    {
      title: isEn ? 'Actions' : '操作',
      key: 'actions',
      width: 96,
      fixed: 'right',
      render: (_value, registration) => (
        <Space size={4}>
          <Tooltip title={isEn ? 'Edit' : '编辑'}>
            <Button
              size="small"
              type="text"
              icon={<Edit className="h-4 w-4" />}
              onClick={() => openEdit(registration.managedServer!)}
            />
          </Tooltip>
          <Tooltip title={isEn ? 'Delete from all agents' : '从所有 Agent 删除'}>
            <Button
              size="small"
              type="text"
              danger
              icon={<Trash2 className="h-4 w-4" />}
              onClick={() => void deleteServer({ name: registration.name })}
            />
          </Tooltip>
        </Space>
      )
    }
  ]

  return (
    <div className="flex h-full flex-col gap-3 overflow-hidden p-4">
      <div className="flex items-center gap-3">
        <div className="bg-primary/10 p-2">
          <Plug className="h-5 w-5 text-primary" />
        </div>
        <div className="min-w-0 flex-1">
          <Typography.Title level={4} style={{ margin: 0 }}>
            {isEn ? 'MCP Manager' : 'MCP 管理'}
          </Typography.Title>
          <Typography.Text type="secondary">
            {isEn ? 'Manage local MCP registrations' : '管理本机 MCP 注册'}
          </Typography.Text>
        </div>
        <Button
          icon={<RefreshCw className="h-4 w-4" />}
          onClick={() => void load()}
          loading={busy === 'load'}
        >
          {isEn ? 'Refresh' : '刷新'}
        </Button>
      </div>

      {!hasMcpApi ? (
        <Alert
          type="error"
          showIcon
          message={
            isEn
              ? 'MCP API is not loaded. Please restart the Electron app.'
              : 'MCP API 尚未加载，请重启 Electron 应用。'
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
          <Button type="primary" icon={<Plus className="h-4 w-4" />} onClick={openCreate}>
            {isEn ? 'Add' : '添加'}
          </Button>
          <Button
            icon={<Download className="h-4 w-4" />}
            loading={busy === 'import'}
            onClick={() => void importFromAgents()}
          >
            {isEn ? 'Import existing' : '导入已有'}
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

      {currentAgent && !currentAgent.supported ? (
        <Alert
          className="mb-3"
          type="info"
          showIcon
          message={
            isEn
              ? 'This agent is detected, but MCP registration editing is not supported yet.'
              : '已检测到该 Agent，但暂未支持 MCP 注册编辑。'
          }
        />
      ) : null}

      <div ref={tableContainerRef} className="min-h-0 flex-1 overflow-hidden">
        <Table
          rowKey={(registration) => `${activeAgent}:${registration.name}`}
          columns={columns}
          dataSource={currentRegistrations}
          pagination={false}
          size="middle"
          loading={busy === 'load'}
          styles={{
            root: { borderRadius: 8, overflow: 'hidden' }
          }}
          title={() => (
            <div className="flex flex-wrap items-center gap-2" style={{ paddingLeft: 14 }}>
              <Input
                allowClear
                variant="filled"
                prefix={<Search className="h-3.5 w-3.5" />}
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder={isEn ? 'Search MCP registrations...' : '搜索 MCP 注册...'}
                className="ml-auto"
                style={{ width: 280 }}
              />
            </div>
          )}
          scroll={{ x: 980, y: tableScrollY }}
          locale={{ emptyText: isEn ? 'No MCP registrations' : '暂无 MCP 注册' }}
        />
      </div>

      <EditModal
        open={showEditDialog}
        isEn={isEn}
        server={editing}
        kiroInstalled={kiroInstalled}
        saving={busy === 'save'}
        onCancel={() => setShowEditDialog(false)}
        onSave={(server, oldName) => void saveServer(server, oldName)}
      />
    </div>
  )
}
