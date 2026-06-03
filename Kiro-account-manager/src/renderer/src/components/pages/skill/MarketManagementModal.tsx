import { Alert, Modal, Space, Typography } from 'antd'

interface MarketManagementModalProps {
  isEn: boolean
  open: boolean
  onCancel: () => void
}

export function MarketManagementModal(props: MarketManagementModalProps): React.ReactNode {
  const { isEn, open, onCancel } = props

  return (
    <Modal
      open={open}
      title={isEn ? 'Market Management' : '市场管理'}
      onCancel={onCancel}
      footer={null}
      width={640}
      destroyOnHidden
    >
      <Space direction="vertical" size={16} className="w-full">
        <Alert
          type="info"
          showIcon
          message={isEn ? 'Coming soon' : '即将支持'}
          description={
            isEn
              ? 'Market source management will live here, including reusable source presets and future marketplace integration.'
              : '这里将用于管理 skill 市场来源，包括可复用的来源预设，以及后续的 marketplace 集成。'
          }
        />
        <Typography.Text type="secondary">
          {isEn
            ? 'The entry is in place first so the global actions area stays structurally stable.'
            : '先把入口放到位，这样顶部全局操作区的结构和位置会保持稳定。'}
        </Typography.Text>
      </Space>
    </Modal>
  )
}
