import { useEffect, useState } from 'react'
import { Input, Modal, Radio, Space, Switch, Typography } from 'antd'
import type { SkillInstallMode, SkillsAgentView } from './types'

interface SettingsModalProps {
  busy: boolean
  isEn: boolean
  open: boolean
  defaultAutoUpdate: boolean
  defaultInstallMode: SkillInstallMode
  gitlabToken?: string
  agents: SkillsAgentView[]
  onCancel: () => void
  onSubmit: (values: {
    defaultAutoUpdate: boolean
    defaultInstallMode: SkillInstallMode
    gitlabToken?: string
  }) => void | Promise<void>
}

export function SettingsModal(props: SettingsModalProps): React.ReactNode {
  const { busy, isEn, open, defaultAutoUpdate, defaultInstallMode, gitlabToken, agents, onCancel, onSubmit } = props
  const [draftAutoUpdate, setDraftAutoUpdate] = useState(defaultAutoUpdate)
  const [draftInstallMode, setDraftInstallMode] = useState<SkillInstallMode>(defaultInstallMode)
  const [draftGitlabToken, setDraftGitlabToken] = useState(gitlabToken || '')

  useEffect(() => {
    if (!open) return
    setDraftAutoUpdate(defaultAutoUpdate)
    setDraftInstallMode(defaultInstallMode)
    setDraftGitlabToken(gitlabToken || '')
  }, [defaultAutoUpdate, defaultInstallMode, gitlabToken, open])

  const unsupportedSymlinkAgents = agents.filter(
    (agent) => !agent.universal && agent.supportsSymlinkProjection === false
  )

  return (
    <Modal
      open={open}
      title={isEn ? 'Skills Settings' : 'Skills 设置'}
      onCancel={onCancel}
      onOk={() =>
        onSubmit({
          defaultAutoUpdate: draftAutoUpdate,
          defaultInstallMode: draftInstallMode,
          gitlabToken: draftGitlabToken.trim() || undefined
        })
      }
      okText={isEn ? 'Save' : '保存'}
      cancelText={isEn ? 'Cancel' : '取消'}
      okButtonProps={{ loading: busy }}
      width={560}
      destroyOnHidden
    >
      <Space direction="vertical" size={20} className="w-full">
        <div className="flex items-center justify-between gap-4">
          <div>
            <Typography.Text strong>{isEn ? 'Auto update' : '自动更新'}</Typography.Text>
            <div className="mt-1 text-xs text-muted-foreground">
              {isEn
                ? 'Newly installed skills will auto-update by default.'
                : '新安装的 skill 默认开启自动更新。'}
            </div>
          </div>
          <Switch checked={draftAutoUpdate} onChange={setDraftAutoUpdate} />
        </div>

        <div>
          <Typography.Text strong>{isEn ? 'Install mode' : '安装方式'}</Typography.Text>
          <Radio.Group
            className="w-full"
            style={{ marginTop: 12 }}
            value={draftInstallMode}
            onChange={(event) => setDraftInstallMode(event.target.value as SkillInstallMode)}
          >
            <Space direction="vertical" size={12} className="w-full">
              <label className="flex cursor-pointer items-start gap-3 border border-border/70 px-3 py-3">
                <Radio value="symlink" className="mt-0.5">
                  <span className="font-medium text-foreground">{isEn ? 'Symlink' : '软链'}</span>
                  {unsupportedSymlinkAgents.length > 0 ? (
                    <span className="ml-1 text-xs text-muted-foreground">
                      {isEn
                        ? `(${unsupportedSymlinkAgents.map((a) => a.displayName).join(', ')} will automatically fall back to copy)`
                        : `（不支持软链的 ${unsupportedSymlinkAgents.map((a) => a.displayName).join('、')} 会自动变为复制）`}
                    </span>
                  ) : null}
                </Radio>
              </label>

              <label className="flex cursor-pointer items-start gap-3 border border-border/70 px-3 py-3">
                <Radio value="copy" className="mt-0.5">
                  <span className="font-medium text-foreground">{isEn ? 'Copy' : '复制'}</span>
                  <span className="ml-1 text-xs text-muted-foreground">
                    {isEn
                      ? '(uses more disk space, leaves multiple physical copies locally)'
                      : '（会占用更多磁盘空间，并在本地留下多份物理副本）'}
                  </span>
                </Radio>
              </label>
            </Space>
          </Radio.Group>
        </div>

        <div>
          <Typography.Text strong>{isEn ? 'GitLab Token' : 'GitLab Token'}</Typography.Text>
          <div className="mt-1 text-xs text-muted-foreground">
            {isEn
              ? 'Required for checking updates of skills from GitLab. Needs read_repository scope.'
              : '检查 GitLab 来源 skill 更新时需要，需 read_repository 权限。'}
          </div>
          <div className="mt-3">
            <Input.Password
              placeholder={isEn ? 'GitLab Personal Access Token' : 'GitLab 个人访问令牌'}
              value={draftGitlabToken}
              onChange={(e) => setDraftGitlabToken(e.target.value)}
            />
          </div>
        </div>
      </Space>
    </Modal>
  )
}
