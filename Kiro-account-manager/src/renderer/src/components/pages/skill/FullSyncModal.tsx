import { Modal, Button, Checkbox, Select, Typography } from 'antd'
import type { SkillsAgentView } from './types'

interface FullSyncModalProps {
  busy: boolean
  isEn: boolean
  open: boolean
  sourceAgentId: string
  sourceAgentName?: string
  sourceAgents: SkillsAgentView[]
  targets: string[]
  targetAgents: SkillsAgentView[]
  onCancel: () => void
  onSourceChange: (value: string) => void
  onTargetsChange: (value: string[]) => void
  onSubmit: () => void
}

export function FullSyncModal(props: FullSyncModalProps): React.ReactNode {
  const {
    busy,
    isEn,
    open,
    sourceAgentId,
    sourceAgentName,
    sourceAgents,
    targets,
    targetAgents,
    onCancel,
    onSourceChange,
    onTargetsChange,
    onSubmit
  } = props

  return (
    <Modal
      open={open}
      title={isEn ? 'Full Sync' : '全量同步'}
      onCancel={onCancel}
      onOk={onSubmit}
      okText={isEn ? 'Sync' : '同步'}
      cancelText={isEn ? 'Cancel' : '取消'}
      okButtonProps={{ loading: busy, disabled: !sourceAgentId || targets.length === 0 }}
      width={680}
      destroyOnHidden
    >
      <div className="space-y-4">
        <div>
          <Typography.Text strong>{isEn ? 'Skill source' : 'Skill 来源'}</Typography.Text>
          <Select
            className="mt-2 w-full"
            variant="filled"
            value={sourceAgentId || undefined}
            placeholder={isEn ? 'Select source agent' : '选择来源 Agent'}
            onChange={onSourceChange}
            options={sourceAgents.map((agent) => ({
              label: `${agent.displayName} (${agent.count})`,
              value: agent.id
            }))}
          />
        </div>

        <div className="border border-border/70 bg-muted/30 px-3 py-2 text-xs text-muted-foreground">
          {isEn
            ? `Add missing skills and overwrite existing skills with the same name. Skills not present in ${sourceAgentName || 'the source'} will not be deleted from targets.`
            : `会新增目标缺失的 skill，并覆盖目标中已有的同名 skill；来源 ${sourceAgentName || 'Agent'} 中没有的 skill 不会从目标删除。`}
        </div>

        <div>
          <div className="mb-2 flex items-center justify-between">
            <Typography.Text strong>{isEn ? 'Sync to agents' : '同步至 Agents'}</Typography.Text>
            <Button
              size="small"
              type="text"
              disabled={!sourceAgentId}
              onClick={() => onTargetsChange(targets.length === targetAgents.length ? [] : targetAgents.map((agent) => agent.id))}
            >
              {targets.length === targetAgents.length ? (isEn ? 'Clear' : '清空') : (isEn ? 'Select all' : '全选')}
            </Button>
          </div>

          <Checkbox.Group
            className="grid grid-cols-2 gap-2"
            value={targets}
            onChange={(values) => onTargetsChange(values as string[])}
            options={targetAgents.map((agent) => ({
              label: `${agent.displayName} (${agent.count})`,
              value: agent.id
            }))}
          />
        </div>
      </div>
    </Modal>
  )
}
