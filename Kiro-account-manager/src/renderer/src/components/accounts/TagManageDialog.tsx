import { useState } from 'react'
import { Button, Card, CardContent, CardHeader, CardTitle } from '../ui'
import { useAccountsStore } from '@/store/accounts'
import { useTranslation } from '@/hooks/useTranslation'
import type { AccountTag } from '@/types/account'
import { X, Plus, Edit2, Trash2, Tag, Check, Palette } from 'lucide-react'

interface TagManageDialogProps {
  isOpen: boolean
  onClose: () => void
}

// Preset colors (with alpha)
const PRESET_COLORS = [
  { name: { en: 'Red', zh: '红色' }, value: '#ffef4444' },
  { name: { en: 'Orange', zh: '橙色' }, value: '#fff97316' },
  { name: { en: 'Yellow', zh: '黄色' }, value: '#ffeab308' },
  { name: { en: 'Green', zh: '绿色' }, value: '#ff22c55e' },
  { name: { en: 'Cyan', zh: '青色' }, value: '#ff06b6d4' },
  { name: { en: 'Blue', zh: '蓝色' }, value: '#ff3b82f6' },
  { name: { en: 'Purple', zh: '紫色' }, value: '#ff8b5cf6' },
  { name: { en: 'Pink', zh: '粉色' }, value: '#ffec4899' },
  { name: { en: 'Gray', zh: '灰色' }, value: '#ff6b7280' },
  // Semi-transparent variants
  { name: { en: 'Light Red', zh: '浅红' }, value: '#80ef4444' },
  { name: { en: 'Light Green', zh: '浅绿' }, value: '#8022c55e' },
  { name: { en: 'Light Blue', zh: '浅蓝' }, value: '#803b82f6' },
  { name: { en: 'Light Purple', zh: '浅紫' }, value: '#808b5cf6' },
]

// 解析 ARGB 颜色
function parseArgb(color: string): { alpha: number; rgb: string } {
  // 支持格式: #AARRGGBB 或 #RRGGBB
  if (color.length === 9 && color.startsWith('#')) {
    const alpha = parseInt(color.slice(1, 3), 16)
    const rgb = '#' + color.slice(3)
    return { alpha, rgb }
  }
  return { alpha: 255, rgb: color }
}

// 转换为 ARGB 格式
function toArgb(rgb: string, alpha: number): string {
  const hex = rgb.startsWith('#') ? rgb.slice(1) : rgb
  const alphaHex = Math.round(alpha).toString(16).padStart(2, '0')
  return `#${alphaHex}${hex}`
}

// 转换为 CSS rgba
function toRgba(argbColor: string): string {
  const { alpha, rgb } = parseArgb(argbColor)
  const hex = rgb.startsWith('#') ? rgb.slice(1) : rgb
  const r = parseInt(hex.slice(0, 2), 16)
  const g = parseInt(hex.slice(2, 4), 16)
  const b = parseInt(hex.slice(4, 6), 16)
  return `rgba(${r}, ${g}, ${b}, ${alpha / 255})`
}

export function TagManageDialog({ isOpen, onClose }: TagManageDialogProps): React.ReactNode {
  const { tags, accounts, addTag, updateTag, removeTag, addTagToAccounts, removeTagFromAccounts } = useAccountsStore()
  const { t } = useTranslation()
  const isEn = t('common.unknown') === 'Unknown'

  // 编辑状态
  const [editingId, setEditingId] = useState<string | null>(null)
  const [editName, setEditName] = useState('')
  const [editColor, setEditColor] = useState('#ff3b82f6')
  const [editAlpha, setEditAlpha] = useState(255)

  // 新建状态
  const [isCreating, setIsCreating] = useState(false)
  const [newName, setNewName] = useState('')
  const [newColor, setNewColor] = useState('#3b82f6')
  const [newAlpha, setNewAlpha] = useState(255)

  // 分配账号状态
  const [assigningTagId, setAssigningTagId] = useState<string | null>(null)

  // 获取标签的账号数量
  const getTagAccountCount = (tagId: string): number => {
    return Array.from(accounts.values()).filter(acc => acc.tags.includes(tagId)).length
  }

  // 获取未标记的账号数量
  const getUntaggedCount = (): number => {
    return Array.from(accounts.values()).filter(acc => acc.tags.length === 0).length
  }

  // 创建标签
  const handleCreate = () => {
    if (!newName.trim()) return
    const argbColor = toArgb(newColor, newAlpha)
    addTag({
      name: newName.trim(),
      color: argbColor
    })
    setNewName('')
    setNewColor('#3b82f6')
    setNewAlpha(255)
    setIsCreating(false)
  }

  // 开始编辑
  const handleStartEdit = (tag: AccountTag) => {
    setEditingId(tag.id)
    setEditName(tag.name)
    const { alpha, rgb } = parseArgb(tag.color)
    setEditColor(rgb)
    setEditAlpha(alpha)
  }

  // 保存编辑
  const handleSaveEdit = () => {
    if (!editingId || !editName.trim()) return
    const argbColor = toArgb(editColor, editAlpha)
    updateTag(editingId, {
      name: editName.trim(),
      color: argbColor
    })
    setEditingId(null)
  }

  // 删除标签
  const handleDelete = (id: string, name: string) => {
    const count = getTagAccountCount(id)
    const msg = count > 0
      ? (isEn
          ? `Are you sure you want to delete tag "${name}"?\nIt is applied to ${count} account(s) and will be removed from them.`
          : `确定要删除标签「${name}」吗？\n该标签已应用于 ${count} 个账号，删除后将从这些账号移除。`)
      : (isEn
          ? `Are you sure you want to delete tag "${name}"?`
          : `确定要删除标签「${name}」吗？`)
    if (confirm(msg)) {
      removeTag(id)
    }
  }

  // 获取带有此标签的账号列表
  const getTaggedAccounts = (tagId: string) => {
    return Array.from(accounts.values()).filter(acc => acc.tags.includes(tagId))
  }

  // 获取可添加此标签的账号列表
  const getUntaggedByTag = (tagId: string) => {
    return Array.from(accounts.values()).filter(acc => !acc.tags.includes(tagId))
  }

  const tagList = Array.from(tags.values())

  if (!isOpen) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/50" onClick={onClose} />

      <Card className="relative w-full max-w-2xl max-h-[85vh] overflow-hidden z-10 flex flex-col">
        <CardHeader className="flex flex-row items-center justify-between pb-2 shrink-0">
          <CardTitle className="flex items-center gap-2">
            <Tag className="h-5 w-5" />
            {isEn ? 'Tag Management' : '标签管理'}
          </CardTitle>
          <Button variant="ghost" size="icon" onClick={onClose} className="rounded-lg hover:bg-red-500 hover:text-white transition-colors">
            <X className="h-4 w-4" />
          </Button>
        </CardHeader>

        <CardContent className="flex-1 overflow-auto space-y-4">
          {/* 统计信息 */}
          <div className="flex gap-4 text-sm text-muted-foreground">
            <span>{isEn ? `${tagList.length} tags` : `共 ${tagList.length} 个标签`}</span>
            <span>•</span>
            <span>{isEn ? `${getUntaggedCount()} untagged` : `${getUntaggedCount()} 个未标记账号`}</span>
          </div>

          {/* 新建标签 */}
          {isCreating ? (
            <div className="p-4 border rounded-lg space-y-3 bg-muted/30">
              <div className="flex items-center gap-2">
                <div 
                  className="w-8 h-8 rounded border cursor-pointer flex items-center justify-center"
                  style={{ backgroundColor: toRgba(toArgb(newColor, newAlpha)) }}
                >
                  <input
                    type="color"
                    value={newColor}
                    onChange={(e) => setNewColor(e.target.value)}
                    className="w-full h-full opacity-0 cursor-pointer"
                  />
                </div>
                <input
                  type="text"
                  placeholder={isEn ? 'Tag name' : '标签名称'}
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  className="flex-1 px-3 py-2 border rounded-lg text-sm"
                  autoFocus
                />
              </div>
              
              {/* 透明度滑块 */}
              <div className="flex items-center gap-3">
                <Palette className="h-4 w-4 text-muted-foreground" />
                <span className="text-sm text-muted-foreground w-16">{isEn ? 'Opacity' : '透明度'}</span>
                <input
                  type="range"
                  min="0"
                  max="255"
                  value={newAlpha}
                  onChange={(e) => setNewAlpha(parseInt(e.target.value))}
                  className="flex-1"
                />
                <span className="text-sm w-12 text-right">{Math.round(newAlpha / 255 * 100)}%</span>
              </div>

              {/* 预设颜色 */}
              <div className="flex flex-wrap gap-1">
                {PRESET_COLORS.map((preset) => (
                  <button
                    key={preset.value}
                    className="w-6 h-6 rounded border hover:scale-110 transition-transform"
                    style={{ backgroundColor: toRgba(preset.value) }}
                    onClick={() => {
                      const { alpha, rgb } = parseArgb(preset.value)
                      setNewColor(rgb)
                      setNewAlpha(alpha)
                    }}
                    title={isEn ? preset.name.en : preset.name.zh}
                  />
                ))}
              </div>

              <div className="flex justify-end gap-2">
                <Button variant="outline" size="sm" onClick={() => setIsCreating(false)}>
                  {isEn ? 'Cancel' : '取消'}
                </Button>
                <Button size="sm" onClick={handleCreate} disabled={!newName.trim()}>
                  <Check className="h-4 w-4 mr-1" />
                  {isEn ? 'Create' : '创建'}
                </Button>
              </div>
            </div>
          ) : (
            <Button variant="outline" className="w-full" onClick={() => setIsCreating(true)}>
              <Plus className="h-4 w-4 mr-2" />
              {isEn ? 'New Tag' : '新建标签'}
            </Button>
          )}

          {/* 标签列表 */}
          <div className="space-y-2">
            {tagList.map((tag) => (
              <div
                key={tag.id}
                className="p-3 border rounded-lg hover:bg-muted/30 transition-colors"
              >
                {editingId === tag.id ? (
                  // 编辑模式
                  <div className="space-y-3">
                    <div className="flex items-center gap-2">
                      <div 
                        className="w-8 h-8 rounded border cursor-pointer flex items-center justify-center"
                        style={{ backgroundColor: toRgba(toArgb(editColor, editAlpha)) }}
                      >
                        <input
                          type="color"
                          value={editColor}
                          onChange={(e) => setEditColor(e.target.value)}
                          className="w-full h-full opacity-0 cursor-pointer"
                        />
                      </div>
                      <input
                        type="text"
                        value={editName}
                        onChange={(e) => setEditName(e.target.value)}
                        className="flex-1 px-3 py-1.5 border rounded text-sm"
                        autoFocus
                      />
                    </div>
                    
                    {/* 透明度滑块 */}
                    <div className="flex items-center gap-3">
                      <span className="text-sm text-muted-foreground w-16">{isEn ? 'Opacity' : '透明度'}</span>
                      <input
                        type="range"
                        min="0"
                        max="255"
                        value={editAlpha}
                        onChange={(e) => setEditAlpha(parseInt(e.target.value))}
                        className="flex-1"
                      />
                      <span className="text-sm w-12 text-right">{Math.round(editAlpha / 255 * 100)}%</span>
                    </div>

                    {/* 预设颜色 */}
                    <div className="flex flex-wrap gap-1">
                      {PRESET_COLORS.map((preset) => (
                        <button
                          key={preset.value}
                          className="w-6 h-6 rounded border hover:scale-110 transition-transform"
                          style={{ backgroundColor: toRgba(preset.value) }}
                          onClick={() => {
                            const { alpha, rgb } = parseArgb(preset.value)
                            setEditColor(rgb)
                            setEditAlpha(alpha)
                          }}
                          title={isEn ? preset.name.en : preset.name.zh}
                        />
                      ))}
                    </div>

                    <div className="flex justify-end gap-2">
                      <Button variant="outline" size="sm" onClick={() => setEditingId(null)}>
                        {isEn ? 'Cancel' : '取消'}
                      </Button>
                      <Button size="sm" onClick={handleSaveEdit}>
                        {isEn ? 'Save' : '保存'}
                      </Button>
                    </div>
                  </div>
                ) : assigningTagId === tag.id ? (
                  // 分配账号模式
                  <div className="space-y-3">
                    <div className="flex items-center gap-2">
                      <span
                        className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium text-white"
                        style={{ backgroundColor: toRgba(tag.color) }}
                      >
                        {tag.name}
                      </span>
                      <span className="text-sm text-muted-foreground">{isEn ? '- Select accounts to tag' : '- 选择要添加标签的账号'}</span>
                    </div>
                    
                    {/* 已标记的账号 */}
                    {getTaggedAccounts(tag.id).length > 0 && (
                      <div className="space-y-1">
                        <p className="text-xs text-muted-foreground">{isEn ? 'Tagged accounts:' : '已标记的账号：'}</p>
                        <div className="flex flex-wrap gap-1">
                          {getTaggedAccounts(tag.id).map(acc => (
                            <span
                              key={acc.id}
                              className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs"
                              style={{ backgroundColor: toRgba(tag.color), color: 'white' }}
                            >
                              {acc.email}
                              <button
                                onClick={() => removeTagFromAccounts([acc.id], tag.id)}
                                className="hover:opacity-70"
                                title={isEn ? 'Remove tag' : '移除标签'}
                              >
                                <X className="h-3 w-3" />
                              </button>
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* 可添加标签的账号 */}
                    {getUntaggedByTag(tag.id).length > 0 && (
                      <div className="space-y-1">
                        <p className="text-xs text-muted-foreground">{isEn ? 'Click to add tag:' : '点击添加标签：'}</p>
                        <div className="flex flex-wrap gap-1 max-h-32 overflow-auto">
                          {getUntaggedByTag(tag.id).map(acc => (
                            <button
                              key={acc.id}
                              onClick={() => addTagToAccounts([acc.id], tag.id)}
                              className="px-2 py-0.5 bg-muted hover:bg-primary/20 rounded text-xs transition-colors"
                            >
                              {acc.email}
                            </button>
                          ))}
                        </div>
                      </div>
                    )}

                    <div className="flex justify-end">
                      <Button variant="outline" size="sm" onClick={() => setAssigningTagId(null)}>
                        {isEn ? 'Done' : '完成'}
                      </Button>
                    </div>
                  </div>
                ) : (
                  // 显示模式
                  <div className="flex items-center gap-3">
                    <span
                      className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium text-white shrink-0"
                      style={{ backgroundColor: toRgba(tag.color) }}
                    >
                      {tag.name}
                    </span>
                    <span className="text-xs text-muted-foreground">
                      {isEn ? `${getTagAccountCount(tag.id)} accounts` : `${getTagAccountCount(tag.id)} 个账号`}
                    </span>
                    <div className="flex-1" />
                    <div className="flex items-center gap-1 shrink-0">
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-8 w-8"
                        onClick={() => setAssigningTagId(tag.id)}
                        title={isEn ? 'Manage accounts' : '管理账号'}
                      >
                        <Tag className="h-4 w-4" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-8 w-8"
                        onClick={() => handleStartEdit(tag)}
                        title={isEn ? 'Edit' : '编辑'}
                      >
                        <Edit2 className="h-4 w-4" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-8 w-8 text-destructive hover:text-destructive"
                        onClick={() => handleDelete(tag.id, tag.name)}
                        title={isEn ? 'Delete' : '删除'}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                )}
              </div>
            ))}

            {tagList.length === 0 && !isCreating && (
              <div className="text-center py-8 text-muted-foreground">
                <Tag className="h-12 w-12 mx-auto mb-2 opacity-50" />
                <p>{isEn ? 'No tags' : '暂无标签'}</p>
                <p className="text-sm">{isEn ? 'Click the button above to create your first tag' : '点击上方按钮创建第一个标签'}</p>
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

// 导出工具函数供其他组件使用
export { toRgba, parseArgb, toArgb }
