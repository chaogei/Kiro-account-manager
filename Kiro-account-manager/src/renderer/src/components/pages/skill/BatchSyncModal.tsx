import { Modal, Button, Checkbox, Typography } from 'antd'
import type { SkillsAgentView } from './types'

interface BatchSyncModalProps {
  busy: boolean
  isEn: boolean
  open: boolean
  currentAgentName: string
  selectedCount: number
  targets: string[]
  agents: SkillsAgentView[]
  onCancel: () => void
  onTargetsChange: (value: string[]) => void
  onSubmit: () => void
}

export function BatchSyncModal(props: BatchSyncModalProps): React.ReactNode {
  const {
    busy,
    isEn,
    open,
    currentAgentName,
    selectedCount,
    targets,
    agents,
    onCancel,
    onTargetsChange,
    onSubmit
  } = props

  return (
    <Modal
      open={open}
      title={isEn ? 'Batch Sync' : '批量同步'}
      onCancel={onCancel}
      onOk={onSubmit}
      okText={isEn ? 'Sync' : '同步'}
      cancelText={isEn ? 'Cancel' : '取消'}
      okButtonProps={{ loading: busy, disabled: selectedCount === 0 || targets.length === 0 }}
      width={640}
      destroyOnHidden
    >
      <div className="mb-4 border border-border/70 bg-muted/30 px-3 py-2 text-xs text-muted-foreground">
        {isEn
          ? `Sync ${selectedCount} selected skill(s) from ${currentAgentName} to selected agents.`
          : `将 ${selectedCount} 个已选 skill 从 ${currentAgentName} 同步到选中的 Agents。`}
      </div>

      <div className="mb-2 flex items-center justify-between">
        <Typography.Text strong>{isEn ? 'Sync to agents' : '同步至 Agents'}</Typography.Text>
        <Button size="small" type="text" onClick={() => onTargetsChange(targets.length === agents.length ? [] : agents.map((agent) => agent.id))}>
          {targets.length === agents.length ? (isEn ? 'Clear' : '清空') : (isEn ? 'Select all' : '全选')}
        </Button>
      </div>

      <Checkbox.Group
        className="grid grid-cols-2 gap-2"
        value={targets}
        onChange={(values) => onTargetsChange(values as string[])}
        options={agents.map((agent) => ({
          label: `${agent.displayName} (${agent.count})`,
          value: agent.id
        }))}
      />
    </Modal>
  )
}
