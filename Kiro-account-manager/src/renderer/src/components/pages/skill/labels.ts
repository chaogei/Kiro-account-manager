import type { SkillUpdateStatus } from './types'

export const statusLabelZh: Record<SkillUpdateStatus, string> = {
  unknown: '未检查',
  latest: '最新',
  available: '可更新',
  unsupported: '无法检查',
  failed: '检查失败'
}

export const statusLabelEn: Record<SkillUpdateStatus, string> = {
  unknown: 'Unknown',
  latest: 'Latest',
  available: 'Update',
  unsupported: 'Unsupported',
  failed: 'Failed'
}
