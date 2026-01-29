import { useState, useRef, useEffect } from 'react'
import { Button, Badge } from '../ui'
import { useAccountsStore } from '@/store/accounts'
import { useTranslation } from '@/hooks/useTranslation'
import { AccountFilterPanel } from './AccountFilter'
import {
  Search,
  Plus,
  Upload,
  Download,
  RefreshCw,
  Trash2,
  Tag,
  FolderPlus,
  CheckSquare,
  Square,
  Loader2,
  Eye,
  EyeOff,
  Filter,
  ChevronDown,
  Check,
  X,
  Minus
} from 'lucide-react'

interface AccountToolbarProps {
  onAddAccount: () => void
  onImport: () => void
  onExport: () => void
  onManageGroups: () => void
  onManageTags: () => void
  isFilterExpanded: boolean
  onToggleFilter: () => void
}

export function AccountToolbar({
  onAddAccount,
  onImport,
  onExport,
  onManageGroups,
  onManageTags,
  isFilterExpanded,
  onToggleFilter
}: AccountToolbarProps): React.ReactNode {
  const {
    filter,
    setFilter,
    selectedIds,
    selectAll,
    deselectAll,
    removeAccounts,
    batchRefreshTokens,
    batchCheckStatus,
    getFilteredAccounts,
    getStats,
    privacyMode,
    setPrivacyMode,
    groups,
    tags,
    accounts,
    moveAccountsToGroup,
    addTagToAccounts,
    removeTagFromAccounts
  } = useAccountsStore()

  const [isRefreshing, setIsRefreshing] = useState(false)
  const [isChecking, setIsChecking] = useState(false)
  const [showGroupMenu, setShowGroupMenu] = useState(false)
  const [showTagMenu, setShowTagMenu] = useState(false)
  
  const groupMenuRef = useRef<HTMLDivElement>(null)
  const tagMenuRef = useRef<HTMLDivElement>(null)
  
  // 点击外部关闭菜单
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (groupMenuRef.current && !groupMenuRef.current.contains(e.target as Node)) {
        setShowGroupMenu(false)
      }
      if (tagMenuRef.current && !tagMenuRef.current.contains(e.target as Node)) {
        setShowTagMenu(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])
  
  // 获取选中账户的分组和标签状态
  const getSelectedAccountsGroupStatus = () => {
    const selectedAccounts = Array.from(selectedIds).map(id => accounts.get(id)).filter(Boolean)
    const groupCounts = new Map<string | undefined, number>()
    
    selectedAccounts.forEach(acc => {
      if (acc) {
        const gid = acc.groupId
        groupCounts.set(gid, (groupCounts.get(gid) || 0) + 1)
      }
    })
    
    return { selectedAccounts, groupCounts }
  }
  
  const getSelectedAccountsTagStatus = () => {
    const selectedAccounts = Array.from(selectedIds).map(id => accounts.get(id)).filter(Boolean)
    const tagCounts = new Map<string, number>()
    
    selectedAccounts.forEach(acc => {
      if (acc?.tags) {
        acc.tags.forEach(tagId => {
          tagCounts.set(tagId, (tagCounts.get(tagId) || 0) + 1)
        })
      }
    })
    
    return { selectedAccounts, tagCounts, total: selectedAccounts.length }
  }
  
  // 处理分组操作
  const handleMoveToGroup = (groupId: string | undefined) => {
    if (selectedIds.size === 0) return
    moveAccountsToGroup(Array.from(selectedIds), groupId)
    setShowGroupMenu(false)
  }
  
  // 处理标签操作
  const handleAddTag = (tagId: string) => {
    if (selectedIds.size === 0) return
    addTagToAccounts(Array.from(selectedIds), tagId)
  }
  
  const handleRemoveTag = (tagId: string) => {
    if (selectedIds.size === 0) return
    removeTagFromAccounts(Array.from(selectedIds), tagId)
  }
  
  const handleToggleTag = (tagId: string) => {
    const { tagCounts, total } = getSelectedAccountsTagStatus()
    const count = tagCounts.get(tagId) || 0
    
    if (count === total) {
      // 所有选中账户都有此标签，移除
      handleRemoveTag(tagId)
    } else {
      // 部分或无账户有此标签，添加
      handleAddTag(tagId)
    }
  }

  const { t } = useTranslation()
  const isEn = t('common.unknown') === 'Unknown'
  const stats = getStats()
  const filteredCount = getFilteredAccounts().length
  const selectedCount = selectedIds.size

  const handleSearch = (value: string): void => {
    setFilter({ ...filter, search: value || undefined })
  }

  const handleBatchRefresh = async (): Promise<void> => {
    if (selectedCount === 0) return
    setIsRefreshing(true)
    await batchRefreshTokens(Array.from(selectedIds))
    setIsRefreshing(false)
  }

  const handleBatchCheck = async (): Promise<void> => {
    if (selectedCount === 0) return
    setIsChecking(true)
    await batchCheckStatus(Array.from(selectedIds))
    setIsChecking(false)
  }

  const handleBatchDelete = (): void => {
    if (selectedCount === 0) return
    if (confirm(isEn ? `Delete ${selectedCount} selected accounts?` : `确定要删除选中的 ${selectedCount} 个账号吗？`)) {
      removeAccounts(Array.from(selectedIds))
    }
  }

  const handleToggleSelectAll = (): void => {
    if (selectedCount === filteredCount && filteredCount > 0) {
      deselectAll()
    } else {
      selectAll()
    }
  }

  return (
    <div className="space-y-3">
      {/* 搜索和主要操作 */}
      <div className="flex items-center gap-3">
        {/* 搜索框 */}
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <input
            type="text"
            placeholder={isEn ? 'Search accounts...' : '搜索账号...'}
            className="w-full pl-9 pr-4 py-2 text-sm border rounded-lg bg-background focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary"
            value={filter.search ?? ''}
            onChange={(e) => handleSearch(e.target.value)}
          />
        </div>

        {/* 主要操作按钮 - 右对齐 */}
        <div className="flex items-center gap-2 ml-auto">
          <Button onClick={onAddAccount}>
            <Plus className="h-4 w-4 mr-1" />
            {isEn ? 'Add' : '添加账号'}
          </Button>
          <Button variant="outline" onClick={onImport}>
            <Upload className="h-4 w-4 mr-1" />
            {isEn ? 'Import' : '导入'}
          </Button>
          <Button variant="outline" onClick={onExport}>
            <Download className="h-4 w-4 mr-1" />
            {isEn ? 'Export' : '导出'}
          </Button>
        </div>
      </div>

      {/* 统计和选择操作 */}
      <div className="flex items-center justify-between">
        {/* 左侧：统计信息 */}
        <div className="flex items-center gap-4 text-sm">
          <span className="text-muted-foreground">
            {isEn ? '' : '共 '}<span className="font-medium text-foreground">{stats.total}</span> {isEn ? 'accounts' : '个账号'}
            {filteredCount !== stats.total && (
              <span>{isEn ? ', ' : '，已筛选 '}<span className="font-medium text-foreground">{filteredCount}</span> {isEn ? 'filtered' : '个'}</span>
            )}
          </span>
          {stats.expiringSoonCount > 0 && (
            <Badge variant="destructive" className="gap-1">
              {stats.expiringSoonCount} {isEn ? 'expiring' : '个即将到期'}
            </Badge>
          )}
        </div>

        {/* 右侧：选择操作和管理 - 缩小间距 */}
        <div className="flex items-center gap-1">
          {/* 分组下拉菜单 */}
          <div className="relative" ref={groupMenuRef}>
            <Button 
              variant={showGroupMenu ? "default" : "ghost"} 
              size="sm" 
              onClick={() => {
                if (selectedCount > 0) {
                  setShowGroupMenu(!showGroupMenu)
                  setShowTagMenu(false)
                } else {
                  onManageGroups()
                }
              }}
              title={selectedCount > 0 ? (isEn ? 'Set group' : '批量设置分组') : (isEn ? 'Manage groups' : '管理分组')}
            >
              <FolderPlus className="h-4 w-4 mr-1" />
              {isEn ? 'Group' : '分组'}
              {selectedCount > 0 && <ChevronDown className="h-3 w-3 ml-1" />}
            </Button>
            
            {showGroupMenu && selectedCount > 0 && (
              <div className="absolute left-0 top-full mt-2 z-50 min-w-[200px] bg-popover border rounded-lg shadow-lg p-2">
                <div className="absolute -top-2 left-4 w-4 h-4 bg-popover border-l border-t rotate-45" />
                <div className="text-xs text-muted-foreground px-2 py-1 mb-1">
                  {isEn ? `${selectedCount} selected` : `已选 ${selectedCount} 个账户`}
                </div>
                <div className="border-t my-1" />
                
                {/* 移除分组 */}
                <button
                  className="w-full flex items-center gap-2 px-2 py-1.5 text-sm rounded hover:bg-muted text-left"
                  onClick={() => handleMoveToGroup(undefined)}
                >
                  <X className="h-4 w-4 text-muted-foreground" />
                  <span>{isEn ? 'Remove group' : '移除分组'}</span>
                  {(() => {
                    const { groupCounts, selectedAccounts } = getSelectedAccountsGroupStatus()
                    const noGroupCount = groupCounts.get(undefined) || 0
                    if (noGroupCount === selectedAccounts.length) {
                      return <Check className="h-4 w-4 ml-auto text-primary" />
                    }
                    return null
                  })()}
                </button>
                
                <div className="border-t my-1" />
                
                {/* 分组列表 */}
                {Array.from(groups.values()).map(group => {
                  const { groupCounts, selectedAccounts } = getSelectedAccountsGroupStatus()
                  const count = groupCounts.get(group.id) || 0
                  const isAllInGroup = count === selectedAccounts.length
                  
                  return (
                    <button
                      key={group.id}
                      className="w-full flex items-center gap-2 px-2 py-1.5 text-sm rounded hover:bg-muted text-left"
                      onClick={() => handleMoveToGroup(group.id)}
                    >
                      <div 
                        className="w-3 h-3 rounded-full shrink-0" 
                        style={{ backgroundColor: group.color || '#888' }} 
                      />
                      <span className="truncate flex-1">{group.name}</span>
                      {isAllInGroup && <Check className="h-4 w-4 text-primary" />}
                      {count > 0 && !isAllInGroup && (
                        <span className="text-xs text-muted-foreground">{count}</span>
                      )}
                    </button>
                  )
                })}
                
                {groups.size === 0 && (
                  <div className="text-sm text-muted-foreground px-2 py-2 text-center">
                    {isEn ? 'No groups' : '暂无分组'}
                  </div>
                )}
                
                <div className="border-t my-1" />
                <button
                  className="w-full flex items-center gap-2 px-2 py-1.5 text-sm rounded hover:bg-muted text-primary"
                  onClick={() => {
                    setShowGroupMenu(false)
                    onManageGroups()
                  }}
                >
                  <Plus className="h-4 w-4" />
                  <span>{isEn ? 'Manage groups' : '管理分组'}</span>
                </button>
              </div>
            )}
          </div>
          
          {/* 标签下拉菜单 */}
          <div className="relative" ref={tagMenuRef}>
            <Button 
              variant={showTagMenu ? "default" : "ghost"} 
              size="sm" 
              onClick={() => {
                if (selectedCount > 0) {
                  setShowTagMenu(!showTagMenu)
                  setShowGroupMenu(false)
                } else {
                  onManageTags()
                }
              }}
              title={selectedCount > 0 ? (isEn ? 'Set tags' : '批量设置标签') : (isEn ? 'Manage tags' : '管理标签')}
            >
              <Tag className="h-4 w-4 mr-1" />
              {isEn ? 'Tags' : '标签'}
              {selectedCount > 0 && <ChevronDown className="h-3 w-3 ml-1" />}
            </Button>
            
            {showTagMenu && selectedCount > 0 && (
              <div className="absolute left-0 top-full mt-2 z-50 min-w-[220px] bg-popover border rounded-lg shadow-lg p-2">
                <div className="absolute -top-2 left-4 w-4 h-4 bg-popover border-l border-t rotate-45" />
                <div className="text-xs text-muted-foreground px-2 py-1 mb-1">
                  {isEn ? `${selectedCount} selected (multi)` : `已选 ${selectedCount} 个账户（可多选）`}
                </div>
                <div className="border-t my-1" />
                
                {/* 标签列表 */}
                <div className="max-h-[300px] overflow-y-auto">
                  {Array.from(tags.values()).map(tag => {
                    const { tagCounts, total } = getSelectedAccountsTagStatus()
                    const count = tagCounts.get(tag.id) || 0
                    const isAll = count === total
                    const isPartial = count > 0 && count < total
                    
                    return (
                      <button
                        key={tag.id}
                        className="w-full flex items-center gap-2 px-2 py-1.5 text-sm rounded hover:bg-muted text-left"
                        onClick={() => handleToggleTag(tag.id)}
                      >
                        <div 
                          className="w-4 h-4 rounded border flex items-center justify-center shrink-0"
                          style={{ 
                            backgroundColor: isAll ? (tag.color || '#888') : 'transparent',
                            borderColor: tag.color || '#888'
                          }}
                        >
                          {isAll && <Check className="h-3 w-3 text-white" />}
                          {isPartial && <Minus className="h-3 w-3" style={{ color: tag.color || '#888' }} />}
                        </div>
                        <span className="truncate flex-1">{tag.name}</span>
                        {isPartial && (
                          <span className="text-xs text-muted-foreground">{count}/{total}</span>
                        )}
                      </button>
                    )
                  })}
                </div>
                
                {tags.size === 0 && (
                  <div className="text-sm text-muted-foreground px-2 py-2 text-center">
                    {isEn ? 'No tags' : '暂无标签'}
                  </div>
                )}
                
                <div className="border-t my-1" />
                <button
                  className="w-full flex items-center gap-2 px-2 py-1.5 text-sm rounded hover:bg-muted text-primary"
                  onClick={() => {
                    setShowTagMenu(false)
                    onManageTags()
                  }}
                >
                  <Plus className="h-4 w-4" />
                  <span>{isEn ? 'Manage tags' : '管理标签'}</span>
                </button>
              </div>
            )}
          </div>
          <Button
            variant={privacyMode ? "default" : "ghost"}
            size="sm"
            onClick={() => setPrivacyMode(!privacyMode)}
            title={privacyMode ? (isEn ? 'Disable privacy' : '关闭隐私模式') : (isEn ? 'Enable privacy' : '开启隐私模式')}
          >
            {privacyMode ? (
              <EyeOff className="h-4 w-4 mr-1" />
            ) : (
              <Eye className="h-4 w-4 mr-1" />
            )}
            {isEn ? 'Privacy' : '隐私'}
          </Button>
          {/* 筛选按钮与气泡 */}
          <div className="relative">
            <Button
              variant={isFilterExpanded ? "default" : "ghost"}
              size="sm"
              onClick={onToggleFilter}
              title={isEn ? 'Toggle filter' : '展开/收起高级筛选'}
            >
              <Filter className="h-4 w-4 mr-1" />
              {isEn ? 'Filter' : '筛选'}
            </Button>
            {/* 筛选气泡面板 */}
            {isFilterExpanded && (
              <div className="absolute right-0 top-full mt-2 z-50 min-w-[600px] bg-popover border rounded-lg shadow-lg">
                {/* 气泡箭头 */}
                <div className="absolute -top-2 right-4 w-4 h-4 bg-popover border-l border-t rotate-45" />
                <AccountFilterPanel />
              </div>
            )}
          </div>

          <div className="w-px h-6 bg-border mx-1" />

          {/* 批量操作 */}
          <Button
            variant="ghost"
            size="sm"
            onClick={handleBatchCheck}
            disabled={isChecking || selectedCount === 0}
            title={isEn ? 'Check account info' : '检查账户信息：刷新用量、订阅详情、封禁状态等'}
          >
            {isChecking ? (
              <Loader2 className="h-4 w-4 mr-1 animate-spin" />
            ) : (
              <RefreshCw className="h-4 w-4 mr-1" />
            )}
            {isEn ? 'Check' : '检查'}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            className="text-destructive hover:text-destructive"
            onClick={handleBatchDelete}
            disabled={selectedCount === 0}
            title={isEn ? 'Delete selected' : '删除选中的账号'}
          >
            <Trash2 className="h-4 w-4 mr-1" />
            {isEn ? 'Delete' : '删除'}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={handleBatchRefresh}
            disabled={isRefreshing || selectedCount === 0}
            title={isEn ? 'Refresh Token' : '刷新 Token：仅刷新访问令牌，用于保持登录状态'}
          >
            {isRefreshing ? (
              <Loader2 className="h-4 w-4 mr-1 animate-spin" />
            ) : (
              <RefreshCw className="h-4 w-4 mr-1" />
            )}
            {isEn ? 'Refresh' : '刷新'}
          </Button>

          <div className="w-px h-6 bg-border mx-1" />

          {/* 全选 */}
          <Button
            variant="ghost"
            size="sm"
            onClick={handleToggleSelectAll}
          >
            {selectedCount === filteredCount && filteredCount > 0 ? (
              <CheckSquare className="h-4 w-4 mr-1" />
            ) : (
              <Square className="h-4 w-4 mr-1" />
            )}
            {selectedCount > 0 ? (isEn ? `${selectedCount} sel` : `已选 ${selectedCount}`) : (isEn ? 'All' : '全选')}
          </Button>
        </div>
      </div>
    </div>
  )
}
