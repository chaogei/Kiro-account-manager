import { useEffect, useMemo, useState } from 'react'
import { Alert, Button, Checkbox, Input, Modal, Segmented, Space, Typography } from 'antd'
import { Plus, Trash2 } from 'lucide-react'
import type { ManagedMcpServer, McpTransport } from './types'

interface EditModalProps {
  open: boolean
  isEn: boolean
  server?: ManagedMcpServer | null
  kiroInstalled: boolean
  saving: boolean
  onCancel: () => void
  onSave: (server: ManagedMcpServer, oldName?: string) => void
}

const nowServer = (): ManagedMcpServer => ({
  name: '',
  transport: 'stdio',
  args: [],
  env: {},
  headers: {},
  createdAt: Date.now(),
  updatedAt: Date.now(),
  source: 'manual'
})

export function EditModal({
  open,
  isEn,
  server,
  kiroInstalled,
  saving,
  onCancel,
  onSave
}: EditModalProps): React.ReactNode {
  const [draft, setDraft] = useState<ManagedMcpServer>(nowServer())
  const [envRows, setEnvRows] = useState<Array<{ key: string; value: string }>>([])
  const [headerRows, setHeaderRows] = useState<Array<{ key: string; value: string }>>([])
  const oldName = server?.name

  useEffect(() => {
    const next = server ? { ...server } : nowServer()
    setDraft(next)
    setEnvRows(Object.entries(next.env || {}).map(([key, value]) => ({ key, value })))
    setHeaderRows(Object.entries(next.headers || {}).map(([key, value]) => ({ key, value })))
  }, [server, open])

  const hasKiroHeaderWarning = useMemo(
    () =>
      kiroInstalled &&
      (draft.transport === 'http' || draft.transport === 'sse') &&
      headerRows.some((row) => row.key.trim()),
    [draft.transport, headerRows, kiroInstalled]
  )

  const updateDraft = (patch: Partial<ManagedMcpServer>): void => {
    setDraft((prev) => ({ ...prev, ...patch }))
  }

  const buildRecord = (
    rows: Array<{ key: string; value: string }>
  ): Record<string, string> | undefined => {
    const result: Record<string, string> = {}
    for (const row of rows) {
      if (row.key.trim()) result[row.key.trim()] = row.value
    }
    return Object.keys(result).length > 0 ? result : undefined
  }

  const handleSave = (): void => {
    const next: ManagedMcpServer = {
      ...draft,
      name: draft.name.trim(),
      command: draft.command?.trim(),
      url: draft.url?.trim(),
      args: (draft.args || []).filter((arg) => arg.trim()),
      env: buildRecord(envRows),
      headers: buildRecord(headerRows),
      updatedAt: Date.now()
    }
    if (!next.name) return
    if (next.transport === 'stdio' && !next.command) return
    if ((next.transport === 'http' || next.transport === 'sse') && !next.url) return
    onSave(next, oldName)
  }

  const renderKeyValueRows = (
    rows: Array<{ key: string; value: string }>,
    setRows: (rows: Array<{ key: string; value: string }>) => void,
    addLabel: string
  ): React.ReactNode => (
    <div className="space-y-2">
      {rows.map((row, index) => (
        <div key={index} className="flex gap-2">
          <Input
            variant="filled"
            className="w-1/3"
            value={row.key}
            placeholder={isEn ? 'Key' : '键'}
            onChange={(event) => {
              const next = [...rows]
              next[index] = { ...next[index], key: event.target.value }
              setRows(next)
            }}
          />
          <Input
            variant="filled"
            value={row.value}
            placeholder={isEn ? 'Value' : '值'}
            onChange={(event) => {
              const next = [...rows]
              next[index] = { ...next[index], value: event.target.value }
              setRows(next)
            }}
          />
          <Button
            type="text"
            icon={<Trash2 className="h-4 w-4" />}
            onClick={() => setRows(rows.filter((_, i) => i !== index))}
          />
        </div>
      ))}
      <Button
        size="small"
        icon={<Plus className="h-3.5 w-3.5" />}
        onClick={() => setRows([...rows, { key: '', value: '' }])}
      >
        {addLabel}
      </Button>
    </div>
  )

  return (
    <Modal
      open={open}
      title={
        server
          ? isEn
            ? 'Edit MCP'
            : '编辑 MCP'
          : isEn
            ? 'Add MCP'
            : '添加 MCP'
      }
      onCancel={onCancel}
      onOk={handleSave}
      okText={isEn ? 'Save' : '保存'}
      cancelText={isEn ? 'Cancel' : '取消'}
      okButtonProps={{
        loading: saving,
        disabled:
          !draft.name.trim() ||
          (draft.transport === 'stdio' ? !draft.command?.trim() : !draft.url?.trim())
      }}
      width={720}
      destroyOnHidden
    >
      <Space orientation="vertical" size={16} className="w-full">
        <div>
          <Typography.Text strong>{isEn ? 'Name' : '名称'}</Typography.Text>
          <Input
            variant="filled"
            className="mt-2"
            value={draft.name}
            disabled={Boolean(server)}
            placeholder="context7"
            onChange={(event) => updateDraft({ name: event.target.value })}
          />
        </div>

        <div>
          <Typography.Text strong>{isEn ? 'Transport' : '传输类型'}</Typography.Text>
          <div className="mt-2">
            <Segmented
              value={draft.transport}
              options={['stdio', 'http', 'sse']}
              onChange={(value) => updateDraft({ transport: value as McpTransport })}
            />
          </div>
        </div>

        {draft.transport === 'stdio' ? (
          <>
            <div>
              <Typography.Text strong>{isEn ? 'Command' : '命令'}</Typography.Text>
              <Input
                variant="filled"
                className="mt-2"
                value={draft.command}
                placeholder="npx"
                onChange={(event) => updateDraft({ command: event.target.value })}
              />
            </div>

            <div>
              <Typography.Text strong>{isEn ? 'Working Dir' : '工作目录'}</Typography.Text>
              <Input
                variant="filled"
                className="mt-2"
                value={draft.cwd}
                placeholder={isEn ? 'Optional' : '可选'}
                onChange={(event) => updateDraft({ cwd: event.target.value })}
              />
            </div>
            <div>
              <Typography.Text strong>{isEn ? 'Arguments' : '参数'}</Typography.Text>
              <div className="mt-2 space-y-2">
                {(draft.args || []).map((arg, index) => (
                  <div key={index} className="flex gap-2">
                    <Input
                      variant="filled"
                      value={arg}
                      onChange={(event) => {
                        const next = [...(draft.args || [])]
                        next[index] = event.target.value
                        updateDraft({ args: next })
                      }}
                    />
                    <Button
                      type="text"
                      icon={<Trash2 className="h-4 w-4" />}
                      onClick={() =>
                        updateDraft({ args: (draft.args || []).filter((_, i) => i !== index) })
                      }
                    />
                  </div>
                ))}
                <Button
                  size="small"
                  icon={<Plus className="h-3.5 w-3.5" />}
                  onClick={() => updateDraft({ args: [...(draft.args || []), ''] })}
                >
                  {isEn ? 'Add Argument' : '添加参数'}
                </Button>
              </div>
            </div>
          </>
        ) : (
          <>
            <div>
              <Typography.Text strong>URL</Typography.Text>
              <Input
                variant="filled"
                className="mt-2"
                value={draft.url}
                placeholder="https://example.com/mcp"
                onChange={(event) => updateDraft({ url: event.target.value })}
              />
            </div>
            <div>
              <Typography.Text strong>Headers</Typography.Text>
              <div className="mt-2">
                {renderKeyValueRows(headerRows, setHeaderRows, isEn ? 'Add Header' : '添加 Header')}
              </div>
            </div>
            {hasKiroHeaderWarning ? (
              <Alert
                type="warning"
                showIcon
                message={isEn ? 'Kiro compatibility' : 'Kiro 兼容提示'}
                description={
                  isEn
                    ? 'Kiro will be registered through npx mcp-remote. Headers are kept for agents that support native HTTP, but are not passed to Kiro in this version.'
                    : 'Kiro 会通过 npx mcp-remote 注册。Headers 会保留给原生支持 HTTP 的 Agent，本版本不会传递给 Kiro。'
                }
              />
            ) : null}
          </>
        )}

        <div>
          <Typography.Text strong>{isEn ? 'Environment Variables' : '环境变量'}</Typography.Text>
          <div className="mt-2">
            {renderKeyValueRows(envRows, setEnvRows, isEn ? 'Add Env Var' : '添加环境变量')}
          </div>
        </div>

        <Checkbox
          checked={draft.disabled}
          onChange={(event) => updateDraft({ disabled: event.target.checked })}
        >
          {isEn ? 'Disable this MCP' : '禁用此 MCP'}
        </Checkbox>
      </Space>
    </Modal>
  )
}
