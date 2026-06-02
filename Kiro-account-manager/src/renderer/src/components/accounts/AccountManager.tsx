import { useState, useEffect } from 'react'
import { useAccountsStore } from '@/store/accounts'
import { useTranslation } from '@/hooks/useTranslation'
import { AccountToolbar, type AccountViewMode } from './AccountToolbar'
import { AccountGrid } from './AccountGrid'
import { AccountList } from './AccountList'
import { AddAccountDialog } from './AddAccountDialog'
import { EditAccountDialog } from './EditAccountDialog'
import { GroupManageDialog } from './GroupManageDialog'
import { TagManageDialog } from './TagManageDialog'
import { ExportDialog } from './ExportDialog'
import { Button } from '../ui'
import type { Account } from '@/types/account'
import { splitCredentialLine } from '@/lib/utils'
import { ArrowLeft, Loader2, Users } from 'lucide-react'

interface AccountManagerProps {
  onBack?: () => void
}

export function AccountManager({ onBack }: AccountManagerProps): React.ReactNode {
  const {
    isLoading,
    accounts,
    importFromExportData,
    importAccounts,
    selectedIds,
    activeGroupTab,
    groups
  } = useAccountsStore()

  const [showAddDialog, setShowAddDialog] = useState(false)
  const [editingAccount, setEditingAccount] = useState<Account | null>(null)
  const [showGroupDialog, setShowGroupDialog] = useState(false)
  const [showTagDialog, setShowTagDialog] = useState(false)
  const [showExportDialog, setShowExportDialog] = useState(false)
  const [isFilterExpanded, setIsFilterExpanded] = useState(false)
  // 视图模式：grid（卡片，默认）/ list（紧凑列表），持久化到 localStorage
  const [viewMode, setViewMode] = useState<AccountViewMode>(() => {
    const saved = localStorage.getItem('accounts_viewMode')
    return saved === 'list' ? 'list' : 'grid'
  })
  useEffect(() => {
    localStorage.setItem('accounts_viewMode', viewMode)
  }, [viewMode])
  const { t } = useTranslation()
  const isEn = t('common.unknown') === 'Unknown'

  // 获取要导出的账号列表
  const getExportAccounts = () => {
    const accountList = Array.from(accounts.values())
    if (selectedIds.size > 0) {
      return accountList.filter(acc => selectedIds.has(acc.id))
    }
    return accountList
  }

  // 导出
  const handleExport = (): void => {
    setShowExportDialog(true)
  }

  // 解析 CSV 行（处理引号和逗号）
  const parseCSVLine = (line: string): string[] => {
    const result: string[] = []
    let current = ''
    let inQuotes = false
    
    for (let i = 0; i < line.length; i++) {
      const char = line[i]
      if (char === '"') {
        if (inQuotes && line[i + 1] === '"') {
          current += '"'
          i++
        } else {
          inQuotes = !inQuotes
        }
      } else if (char === ',' && !inQuotes) {
        result.push(current.trim())
        current = ''
      } else {
        current += char
      }
    }
    result.push(current.trim())
    return result
  }

  // 导入
  const handleImport = async (): Promise<void> => {
    // 文件导入归入"当前打开的分组"（activeGroupTab 为真实分组时），否则未分组
    const currentGroupId = (activeGroupTab !== 'all' && activeGroupTab !== 'ungrouped' && groups.has(activeGroupTab)) ? activeGroupTab : undefined
    const groupName = currentGroupId ? (groups.get(currentGroupId)?.name ?? '未分组') : '未分组'
    const fileData = await window.api.importFromFile()

    if (!fileData) return

    const { content, format } = fileData

    try {
      if (format === 'json') {
        // JSON 格式：完整导出数据
        const data = JSON.parse(content)
        if (data.version && data.accounts) {
          const result = importFromExportData(data)
          const skippedInfo = result.errors.find(e => e.id === 'skipped')
          const skippedMsg = skippedInfo ? `，${skippedInfo.error}` : ''
          alert(`导入完成：成功 ${result.success} 个${skippedMsg}`)
        } else {
          alert('无效的 JSON 文件格式')
        }
      } else if (format === 'csv') {
        // CSV 格式：邮箱,昵称,登录方式,RefreshToken,ClientId,ClientSecret,Region
        const lines = content.split('\n').filter(line => line.trim())
        if (lines.length < 2) {
          alert('CSV 文件为空或只有标题行')
          return
        }

        // 跳过标题行，解析数据行
        const items = lines.slice(1).map(line => {
          const cols = parseCSVLine(line)
          return {
            email: cols[0] || '',
            nickname: cols[1] || undefined,
            idp: cols[2] || 'Google',
            refreshToken: cols[3] || '',
            clientId: cols[4] || '',
            clientSecret: cols[5] || '',
            region: cols[6] || 'us-east-1',
            groupId: currentGroupId
          }
        }).filter(item => item.email && item.refreshToken)

        if (items.length === 0) {
          alert('未找到有效的账号数据（需要邮箱和 RefreshToken）')
          return
        }

        const result = importAccounts(items)
        alert(`导入完成：成功 ${result.success} 个，失败 ${result.failed} 个（分组：${groupName}）`)
      } else if (format === 'txt') {
        // TXT 格式：自动识别卡密格式或普通格式
        const lines = content.split('\n').filter(line => line.trim() && !line.startsWith('#'))

        // 检测是否为卡密格式（包含 ---- 分隔符）
        const isKamiFormat = lines.some(line => line.includes('----'))

        if (isKamiFormat) {
          // 卡密格式：邮箱----密码----RefreshToken----ClientId----ClientSecret
          // 自动识别分隔符：----、\t、连续空格
          const items = lines.map(line => {
            const parts = splitCredentialLine(line)
            const rawPwd = parts[1]?.trim()
            const clientId = parts[3]?.trim() || undefined
            const clientSecret = parts[4]?.trim() || undefined
            // 第6字段为登录方式(idp)：新卡密直接带；旧卡密无此字段时按 ClientId/Secret 推断
            // social(Github/Google) 只有 refreshToken，IdC(BuilderId) 才有 ClientId/Secret
            const rawIdp = parts[5]?.trim()
            const idp = rawIdp || ((!clientId && !clientSecret) ? 'Google' : 'BuilderId')
            return {
              email: parts[0]?.trim() || '',
              password: (rawPwd && rawPwd !== 'no_password') ? rawPwd : undefined,
              refreshToken: parts[2]?.trim() || '',
              clientId,
              clientSecret,
              idp,
              groupId: currentGroupId
            }
          }).filter(item => item.email && item.refreshToken)

          if (items.length === 0) {
            alert('未找到有效的卡密数据（格式：邮箱----密码----RefreshToken----ClientId----ClientSecret）')
            return
          }

          const result = importAccounts(items)
          alert(`卡密导入完成：成功 ${result.success} 个，失败 ${result.failed} 个（分组：${groupName}）`)
        } else {
          // 普通 TXT 格式：邮箱,RefreshToken 或 邮箱|RefreshToken
          const items = lines.map(line => {
            const parts = line.includes('|') ? line.split('|') : line.split(',')
            return {
              email: parts[0]?.trim() || '',
              refreshToken: parts[1]?.trim() || '',
              nickname: parts[2]?.trim() || undefined,
              idp: parts[3]?.trim() || 'Google',
              groupId: currentGroupId
            }
          }).filter(item => item.email && item.refreshToken)

          if (items.length === 0) {
            alert('未找到有效的账号数据（格式：邮箱,RefreshToken 或 卡密格式：邮箱----密码----Token----ID----Secret）')
            return
          }

          const result = importAccounts(items)
          alert(`导入完成：成功 ${result.success} 个，失败 ${result.failed} 个（分组：${groupName}）`)
        }
      } else {
        alert(`不支持的文件格式：${format}`)
      }
    } catch (e) {
      console.error('Import error:', e)
      alert('解析导入文件失败')
    }
  }

  // 管理分组
  const handleManageGroups = (): void => {
    setShowGroupDialog(true)
  }

  // 管理标签
  const handleManageTags = (): void => {
    setShowTagDialog(true)
  }

  // 编辑账号
  const handleEditAccount = (account: Account): void => {
    setEditingAccount(account)
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="flex flex-col items-center gap-4">
          <Loader2 className="h-8 w-8 animate-spin text-primary" />
          <p className="text-muted-foreground">加载账号数据...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="flex flex-col h-full">
      {/* 顶部工具栏 - 玻璃态（relative z-20 抬升 stacking context，确保下拉菜单浮在卡片之上） */}
      <header className="relative z-20 flex items-center justify-between gap-4 px-3 py-3 glass-toolbar">
        <div className="flex items-center gap-4">
          {onBack && (
            <Button variant="ghost" size="icon" onClick={onBack}>
              <ArrowLeft className="h-5 w-5" />
            </Button>
          )}
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-primary/10">
              <Users className="h-5 w-5 text-primary" />
            </div>
            <h1 className="text-lg font-semibold text-primary">{isEn ? 'Accounts' : '账户管理'}</h1>
          </div>
        </div>
        
        {/* 工具栏 */}
        <AccountToolbar
          onAddAccount={() => setShowAddDialog(true)}
          onImport={handleImport}
          onExport={handleExport}
          viewMode={viewMode}
          onViewModeChange={setViewMode}
          onManageGroups={handleManageGroups}
          onManageTags={handleManageTags}
          isFilterExpanded={isFilterExpanded}
          onToggleFilter={() => setIsFilterExpanded(!isFilterExpanded)}
        />
      </header>

      {/* 主内容区域 */}
      <div className="flex-1 overflow-hidden flex flex-col px-3 py-3 gap-3">
        {/* 账号列表（卡片 或 紧凑列表） */}
        <div className="flex-1 overflow-hidden">
          {viewMode === 'grid' ? (
            <AccountGrid
              onAddAccount={() => setShowAddDialog(true)}
              onEditAccount={handleEditAccount}
            />
          ) : (
            <AccountList
              onAddAccount={() => setShowAddDialog(true)}
              onEditAccount={handleEditAccount}
            />
          )}
        </div>
      </div>

      {/* 添加账号对话框 */}
      <AddAccountDialog
        isOpen={showAddDialog}
        onClose={() => setShowAddDialog(false)}
      />

      {/* 编辑账号对话框 */}
      <EditAccountDialog
        open={!!editingAccount}
        onOpenChange={(open) => !open && setEditingAccount(null)}
        account={editingAccount}
      />

      {/* 分组管理对话框 */}
      <GroupManageDialog
        isOpen={showGroupDialog}
        onClose={() => setShowGroupDialog(false)}
      />

      {/* 标签管理对话框 */}
      <TagManageDialog
        isOpen={showTagDialog}
        onClose={() => setShowTagDialog(false)}
      />

      {/* 导出对话框 */}
      <ExportDialog
        open={showExportDialog}
        onClose={() => setShowExportDialog(false)}
        accounts={getExportAccounts()}
        selectedCount={selectedIds.size}
      />
    </div>
  )
}
