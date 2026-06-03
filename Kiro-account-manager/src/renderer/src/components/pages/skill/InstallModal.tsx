import { Modal, Input, Button, Checkbox, Typography, Space } from 'antd'
import type { SkillsAgentView } from './types'

interface InstallModalProps {
  busy: boolean
  isEn: boolean
  open: boolean
  source: string
  skillNames: string
  targets: string[]
  agents: SkillsAgentView[]
  onCancel: () => void
  onSourceChange: (value: string) => void
  onSkillNamesChange: (value: string) => void
  onTargetsChange: (value: string[]) => void
  onSubmit: () => void
}

export function InstallModal(props: InstallModalProps): React.ReactNode {
  const {
    busy,
    isEn,
    open,
    source,
    skillNames,
    targets,
    agents,
    onCancel,
    onSourceChange,
    onSkillNamesChange,
    onTargetsChange,
    onSubmit
  } = props

  return (
    <Modal
      open={open}
      title={isEn ? 'Install Skill' : '安装 Skill'}
      onCancel={onCancel}
      onOk={onSubmit}
      okText={isEn ? 'Install' : '安装'}
      cancelText={isEn ? 'Cancel' : '取消'}
      okButtonProps={{ loading: busy, disabled: !source.trim() || targets.length === 0 }}
      width={720}
      destroyOnHidden
    >
      <Space direction="vertical" size={16} className="w-full">
        <div>
          <Typography.Text strong>{isEn ? 'Source' : '来源'}</Typography.Text>
          <Input
            variant="filled"
            value={source}
            onChange={(event) => onSourceChange(event.target.value)}
            placeholder={
              isEn
                ? 'GitHub URL, owner/repo, git URL, local path'
                : 'GitHub URL、owner/repo、Git URL、本地路径'
            }
            className="mt-2"
          />
        </div>

        <div>
          <Typography.Text strong>{isEn ? 'Skill names' : 'Skill 名称'}</Typography.Text>
          <Input
            variant="filled"
            value={skillNames}
            onChange={(event) => onSkillNamesChange(event.target.value)}
            placeholder={isEn ? 'Optional, comma separated' : '可选，多个用逗号分隔'}
            className="mt-2"
          />
        </div>

        <div>
          <div className="mb-2 flex items-center justify-between">
            <Typography.Text strong>{isEn ? 'Install to agents' : '安装到 Agents'}</Typography.Text>
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
        </div>
      </Space>
    </Modal>
  )
}
