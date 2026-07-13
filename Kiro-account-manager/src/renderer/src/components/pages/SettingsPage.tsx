import { useAccountsStore } from '@/store/accounts'
import { Card, CardContent, CardHeader, CardTitle, Button } from '../ui'
import { Eye, EyeOff, RefreshCw, Clock, Trash2, Download, Upload, Globe, Repeat, Palette, Moon, Sun, Fingerprint, Info, ChevronDown, ChevronUp, Settings, Database, Layers, UserX, Monitor } from 'lucide-react'
import { useState, useEffect } from 'react'
import { ExportDialog } from '../accounts/ExportDialog'
import { useTranslation } from '@/hooks/useTranslation'

// 主题配置 - 按色系分组
const themeGroupsZh = [
  {
    name: '蓝色系',
    themes: [
      { id: 'default', name: '天空蓝', color: '#3b82f6' },
      { id: 'indigo', name: '靖蓝', color: '#6366f1' },
      { id: 'cyan', name: '清新青', color: '#06b6d4' },
      { id: 'sky', name: '晴空蓝', color: '#0ea5e9' },
      { id: 'teal', name: '水鸭蓝', color: '#14b8a6' },
    ]
  },
  {
    name: '紫红系',
    themes: [
      { id: 'purple', name: '优雅紫', color: '#a855f7' },
      { id: 'violet', name: '紫罗兰', color: '#8b5cf6' },
      { id: 'fuchsia', name: '洋红', color: '#d946ef' },
      { id: 'pink', name: '粉红', color: '#ec4899' },
      { id: 'rose', name: '玑瑰红', color: '#f43f5e' },
    ]
  },
  {
    name: '暖色系',
    themes: [
      { id: 'red', name: '热情红', color: '#ef4444' },
      { id: 'orange', name: '活力橙', color: '#f97316' },
      { id: 'amber', name: '琥珀金', color: '#f59e0b' },
      { id: 'yellow', name: '明黄', color: '#eab308' },
    ]
  },
  {
    name: '绿色系',
    themes: [
      { id: 'emerald', name: '翠绿', color: '#10b981' },
      { id: 'green', name: '草绿', color: '#22c55e' },
      { id: 'lime', name: '青柠', color: '#84cc16' },
    ]
  },
  {
    name: '中性色',
    themes: [
      { id: 'slate', name: '石板灰', color: '#64748b' },
      { id: 'zinc', name: '锌灰', color: '#71717a' },
      { id: 'stone', name: '暖灰', color: '#78716c' },
      { id: 'neutral', name: '中性灰', color: '#737373' },
    ]
  },
  {
    name: '奢华配色',
    themes: [
      { id: 'gold', name: '奢华金', color: '#C9A227' },
      { id: 'navy', name: '海军蓝', color: '#1E40AF' },
      { id: 'wine', name: '酒红', color: '#9F1239' },
      { id: 'champagne', name: '香槟', color: '#B89968' },
    ]
  },
  {
    name: '莫兰迪',
    themes: [
      { id: 'dustyblue', name: '烟雾蓝', color: '#64748B' },
      { id: 'terracotta', name: '陶土橙', color: '#B45434' },
      { id: 'sage', name: '鼠尾草', color: '#6B8E5A' },
      { id: 'mauve', name: '烟紫', color: '#8E7CC3' },
    ]
  },
  {
    name: '自然深色',
    themes: [
      { id: 'coral', name: '珊瑚粉', color: '#F87171' },
      { id: 'forest', name: '森林绿', color: '#166534' },
      { id: 'ocean', name: '深海青', color: '#155E75' },
    ]
  }
]

const themeGroupsEn = [
  {
    name: 'Blue',
    themes: [
      { id: 'default', name: 'Sky Blue', color: '#3b82f6' },
      { id: 'indigo', name: 'Indigo', color: '#6366f1' },
      { id: 'cyan', name: 'Cyan', color: '#06b6d4' },
      { id: 'sky', name: 'Sky', color: '#0ea5e9' },
      { id: 'teal', name: 'Teal', color: '#14b8a6' },
    ]
  },
  {
    name: 'Purple',
    themes: [
      { id: 'purple', name: 'Purple', color: '#a855f7' },
      { id: 'violet', name: 'Violet', color: '#8b5cf6' },
      { id: 'fuchsia', name: 'Fuchsia', color: '#d946ef' },
      { id: 'pink', name: 'Pink', color: '#ec4899' },
      { id: 'rose', name: 'Rose', color: '#f43f5e' },
    ]
  },
  {
    name: 'Warm',
    themes: [
      { id: 'red', name: 'Red', color: '#ef4444' },
      { id: 'orange', name: 'Orange', color: '#f97316' },
      { id: 'amber', name: 'Amber', color: '#f59e0b' },
      { id: 'yellow', name: 'Yellow', color: '#eab308' },
    ]
  },
  {
    name: 'Green',
    themes: [
      { id: 'emerald', name: 'Emerald', color: '#10b981' },
      { id: 'green', name: 'Green', color: '#22c55e' },
      { id: 'lime', name: 'Lime', color: '#84cc16' },
    ]
  },
  {
    name: 'Neutral',
    themes: [
      { id: 'slate', name: 'Slate', color: '#64748b' },
      { id: 'zinc', name: 'Zinc', color: '#71717a' },
      { id: 'stone', name: 'Stone', color: '#78716c' },
      { id: 'neutral', name: 'Neutral', color: '#737373' },
    ]
  },
  {
    name: 'Luxury',
    themes: [
      { id: 'gold', name: 'Gold', color: '#C9A227' },
      { id: 'navy', name: 'Navy', color: '#1E40AF' },
      { id: 'wine', name: 'Wine', color: '#9F1239' },
      { id: 'champagne', name: 'Champagne', color: '#B89968' },
    ]
  },
  {
    name: 'Morandi',
    themes: [
      { id: 'dustyblue', name: 'Dusty Blue', color: '#64748B' },
      { id: 'terracotta', name: 'Terracotta', color: '#B45434' },
      { id: 'sage', name: 'Sage', color: '#6B8E5A' },
      { id: 'mauve', name: 'Mauve', color: '#8E7CC3' },
    ]
  },
  {
    name: 'Natural',
    themes: [
      { id: 'coral', name: 'Coral', color: '#F87171' },
      { id: 'forest', name: 'Forest', color: '#166534' },
      { id: 'ocean', name: 'Ocean', color: '#155E75' },
    ]
  }
]

export function SettingsPage() {
  const { 
    privacyMode, 
    setPrivacyMode,
    usagePrecision,
    setUsagePrecision,
    autoRefreshEnabled,
    autoRefreshInterval,
    autoRefreshConcurrency,
    autoRefreshSyncInfo,
    proactiveRenewalEnabled,
    proactiveRenewalLeadMinutes,
    setProactiveRenewalEnabled,
    setAutoRefresh,
    setAutoRefreshConcurrency,
    setAutoRefreshSyncInfo,
    checkAndRefreshExpiringTokens,
    proxyEnabled,
    proxyUrl,
    setProxy,
    autoSwitchEnabled,
    autoSwitchThreshold,
    autoSwitchInterval,
    setAutoSwitch,
    batchImportConcurrency,
    setBatchImportConcurrency,
    loginPrivateMode,
    setLoginPrivateMode,
    switchTarget,
    setSwitchTarget,
    theme,
    darkMode,
    setTheme,
    setDarkMode,
    language,
    setLanguage,
    accounts,
    importFromExportData
  } = useAccountsStore()

  const { t } = useTranslation()
  const isEn = t('common.unknown') === 'Unknown'
  const [showExportDialog, setShowExportDialog] = useState(false)
  const [isImporting, setIsImporting] = useState(false)
  const [tempProxyUrl, setTempProxyUrl] = useState(proxyUrl)
  const [themeExpanded, setThemeExpanded] = useState(false)
  const [isManualRefreshing, setIsManualRefreshing] = useState(false)
  
  // 托盘设置状态
  const [traySettings, setTraySettings] = useState({
    enabled: true,
    closeAction: 'ask' as 'ask' | 'minimize' | 'quit',
    showNotifications: true,
    minimizeOnStart: false
  })
  const [trayLoading, setTrayLoading] = useState(true)

  // 快捷键设置状态
  const [showWindowShortcut, setShowWindowShortcut] = useState('')
  const [shortcutLoading, setShortcutLoading] = useState(true)
  const [shortcutError, setShortcutError] = useState('')
  const [isRecordingShortcut, setIsRecordingShortcut] = useState(false)

  // 加载快捷键设置
  useEffect(() => {
    const loadShortcut = async () => {
      try {
        const shortcut = await window.api.getShowWindowShortcut()
        setShowWindowShortcut(shortcut)
      } catch (error) {
        console.error('Failed to load shortcut:', error)
      } finally {
        setShortcutLoading(false)
      }
    }
    loadShortcut()
  }, [])

  // 保存快捷键设置
  const handleShortcutChange = async (shortcut: string) => {
    setShowWindowShortcut(shortcut)
    setShortcutError('')
    try {
      const result = await window.api.setShowWindowShortcut(shortcut)
      if (!result.success) {
        setShortcutError(result.error || 'Failed to set shortcut')
      }
    } catch (error) {
      setShortcutError(String(error))
    }
  }

  // 按键录制处理
  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (!isRecordingShortcut) return
    e.preventDefault()
    
    const parts: string[] = []
    if (e.ctrlKey) parts.push('Ctrl')
    if (e.metaKey) parts.push('Command')
    if (e.altKey) parts.push('Alt')
    if (e.shiftKey) parts.push('Shift')
    
    // 忽略单独的修饰键
    const key = e.key
    if (!['Control', 'Meta', 'Alt', 'Shift'].includes(key)) {
      // 转换特殊键名
      const keyName = key.length === 1 ? key.toUpperCase() : key
      parts.push(keyName)
      
      const shortcut = parts.join('+')
      handleShortcutChange(shortcut)
      setIsRecordingShortcut(false)
    }
  }

  // Usage API 类型状态
  const [usageApiType, setUsageApiType] = useState<'rest' | 'cbor'>('rest')
  const [usageApiLoading, setUsageApiLoading] = useState(true)

  // 加载 Usage API 类型设置
  useEffect(() => {
    const loadUsageApiType = async () => {
      try {
        const type = await window.api.getUsageApiType()
        setUsageApiType(type)
      } catch (error) {
        console.error('Failed to load usage API type:', error)
      } finally {
        setUsageApiLoading(false)
      }
    }
    loadUsageApiType()
  }, [])

  // 保存 Usage API 类型
  const handleUsageApiTypeChange = async (type: 'rest' | 'cbor') => {
    setUsageApiType(type)
    try {
      await window.api.setUsageApiType(type)
    } catch (error) {
      console.error('Failed to save usage API type:', error)
    }
  }

  // K-Proxy 代理设置状态
  const [useKProxyForApi, setUseKProxyForApi] = useState(false)
  const [kproxyLoading, setKproxyLoading] = useState(true)

  // 加载 K-Proxy 代理设置
  useEffect(() => {
    const loadKProxySettings = async () => {
      try {
        const enabled = await window.api.getUseKProxyForApi()
        setUseKProxyForApi(enabled)
      } catch (error) {
        console.error('Failed to load K-Proxy settings:', error)
      } finally {
        setKproxyLoading(false)
      }
    }
    loadKProxySettings()
  }, [])

  // 保存 K-Proxy 代理设置
  const handleKProxyChange = async (enabled: boolean) => {
    setUseKProxyForApi(enabled)
    try {
      await window.api.setUseKProxyForApi(enabled)
    } catch (error) {
      console.error('Failed to save K-Proxy settings:', error)
    }
  }

  // 加载托盘设置
  useEffect(() => {
    const loadTraySettings = async () => {
      try {
        const settings = await window.api.getTraySettings()
        setTraySettings(settings)
      } catch (error) {
        console.error('Failed to load tray settings:', error)
      } finally {
        setTrayLoading(false)
      }
    }
    loadTraySettings()
  }, [])

  // 保存托盘设置
  const handleTraySettingChange = async (key: keyof typeof traySettings, value: boolean | string) => {
    const newSettings = { ...traySettings, [key]: value }
    setTraySettings(newSettings)
    try {
      await window.api.saveTraySettings({ [key]: value })
    } catch (error) {
      console.error('Failed to save tray settings:', error)
    }
  }

  const handleManualRefresh = async () => {
    setIsManualRefreshing(true)
    try {
      await checkAndRefreshExpiringTokens()
    } finally {
      setIsManualRefreshing(false)
    }
  }
  const themeGroups = isEn ? themeGroupsEn : themeGroupsZh

  const handleExport = () => {
    setShowExportDialog(true)
  }

  const handleImport = async () => {
    setIsImporting(true)
    try {
      const fileData = await window.api.importFromFile()
      if (fileData && fileData.format === 'json') {
        const data = JSON.parse(fileData.content)
        const importResult = importFromExportData(data)
        alert(isEn
          ? `Import complete: ${importResult.success} succeeded, ${importResult.failed} failed`
          : `导入完成：成功 ${importResult.success} 个，失败 ${importResult.failed} 个`)
      } else if (fileData) {
        alert(isEn
          ? 'Settings page only supports JSON import. Use the Accounts page for CSV/TXT.'
          : '设置页面仅支持 JSON 格式导入，请使用账号管理页面导入 CSV/TXT')
      }
    } catch (e) {
      alert(isEn
        ? `Import failed: ${e instanceof Error ? e.message : 'Unknown error'}`
        : `导入失败: ${e instanceof Error ? e.message : '未知错误'}`)
    } finally {
      setIsImporting(false)
    }
  }

  const handleClearData = () => {
    if (confirm(isEn
      ? 'Are you sure you want to clear all account data? This cannot be undone!'
      : '确定要清除所有账号数据吗？此操作不可恢复！')) {
      if (confirm(isEn
        ? 'Confirm again: this will delete ALL accounts, groups, and tag data!'
        : '再次确认：这将删除所有账号、分组和标签数据！')) {
        // 清除所有数据
        Array.from(accounts.keys()).forEach(id => {
          useAccountsStore.getState().removeAccount(id)
        })
        alert(isEn ? 'All data has been cleared' : '所有数据已清除')
      }
    }
  }

  return (
    <div className="flex-1 p-6 space-y-6 overflow-auto">
      {/* 页面头部 */}
      <div className="page-hero p-6">
        <div className="absolute top-0 right-0 w-32 h-32 bg-gradient-to-br from-primary/20 to-transparent rounded-full blur-2xl" />
        <div className="absolute bottom-0 left-0 w-24 h-24 bg-gradient-to-tr from-primary/20 to-transparent rounded-full blur-2xl" />
        <div className="relative flex items-center gap-4">
          <div className="p-3 rounded-xl bg-primary shadow-lg shadow-primary/25">
            <Settings className="h-6 w-6 text-primary-foreground" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-primary">{t('settings.title')}</h1>
            <p className="text-muted-foreground">{isEn ? 'Configure app features' : '配置应用的各项功能'}</p>
          </div>
        </div>
      </div>

      {/* 语言设置 */}
      <Card className="hover-lift">
        <CardHeader className="pb-2">
          <CardTitle className="text-base flex items-center gap-3">
            <div className="p-2 rounded-lg bg-primary/10">
              <Globe className="h-4 w-4 text-primary" />
            </div>
            Language / 语言
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="font-medium">Display Language / 显示语言</p>
              <p className="text-sm text-muted-foreground">Select interface language / 选择界面显示语言</p>
            </div>
            <select
              className="w-[160px] h-9 px-3 rounded-lg border bg-background text-sm focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary"
              value={language}
              onChange={(e) => setLanguage(e.target.value as 'auto' | 'en' | 'zh')}
            >
              <option value="auto">🌐 Auto (自动)</option>
              <option value="en">🇺🇸 English</option>
              <option value="zh">🇨🇳 简体中文</option>
            </select>
          </div>
          <div className="text-xs text-muted-foreground bg-muted/50 rounded-lg p-3 space-y-1">
            <p>• Auto mode will follow system language</p>
            <p>• 自动模式会根据系统语言自动选择</p>
            <p>• Custom translation files supported (coming soon)</p>
          </div>
        </CardContent>
      </Card>

      {/* 主题设置 */}
      <Card className="hover-lift">
        <CardHeader className="pb-2">
          <CardTitle className="text-base flex items-center gap-3">
            <div className="p-2 rounded-lg bg-primary/10">
              <Palette className="h-4 w-4 text-primary" />
            </div>
            {isEn ? 'Theme' : '主题设置'}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* 深色模式 */}
          <div className="flex items-center justify-between">
            <div>
              <p className="font-medium">{isEn ? 'Dark Mode' : '深色模式'}</p>
              <p className="text-sm text-muted-foreground">{isEn ? 'Toggle dark/light theme' : '切换深色/浅色主题'}</p>
            </div>
            <Button
              variant={darkMode ? "default" : "outline"}
              size="sm"
              onClick={() => setDarkMode(!darkMode)}
            >
              {darkMode ? <Moon className="h-4 w-4 mr-2" /> : <Sun className="h-4 w-4 mr-2" />}
              {darkMode ? (isEn ? 'Dark' : '深色') : (isEn ? 'Light' : '浅色')}
            </Button>
          </div>

          {/* 主题颜色 */}
          <div className="pt-2 border-t">
            <button 
              className="flex items-center justify-between w-full text-left"
              onClick={() => setThemeExpanded(!themeExpanded)}
            >
              <div className="flex items-center gap-2">
                <p className="font-medium">{isEn ? 'Theme Color' : '主题颜色'}</p>
                {!themeExpanded && (
                  <div 
                    className="w-5 h-5 rounded-full ring-2 ring-primary ring-offset-1"
                    style={{ backgroundColor: themeGroups.flatMap(g => g.themes).find(t => t.id === theme)?.color || '#3b82f6' }}
                  />
                )}
              </div>
              {themeExpanded ? (
                <ChevronUp className="h-4 w-4 text-muted-foreground" />
              ) : (
                <ChevronDown className="h-4 w-4 text-muted-foreground" />
              )}
            </button>
            {themeExpanded && (
              <div className="space-y-3 mt-3">
                {themeGroups.map((group) => (
                  <div key={group.name} className="flex items-center gap-3">
                    <span className="text-xs text-muted-foreground w-14 shrink-0">{group.name}</span>
                    <div className="flex flex-wrap gap-2">
                      {group.themes.map((t) => (
                        <button
                          key={t.id}
                          className={`group relative w-7 h-7 rounded-full transition-all ${
                            theme === t.id 
                              ? 'ring-2 ring-primary ring-offset-2 scale-110' 
                              : 'hover:scale-110 hover:shadow-md'
                          }`}
                          style={{ backgroundColor: t.color }}
                          onClick={() => setTheme(t.id)}
                          title={t.name}
                        >
                          <span className="absolute -bottom-6 left-1/2 -translate-x-1/2 text-[10px] text-muted-foreground whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity bg-popover px-1.5 py-0.5 rounded shadow-sm border pointer-events-none z-10">
                            {t.name}
                          </span>
                        </button>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* 隐私设置 */}
      <Card className="hover-lift">
        <CardHeader className="pb-2">
          <CardTitle className="text-base flex items-center gap-3">
            <div className="p-2 rounded-lg bg-primary/10">
              {privacyMode ? <EyeOff className="h-4 w-4 text-primary" /> : <Eye className="h-4 w-4 text-primary" />}
            </div>
            {isEn ? 'Privacy' : '隐私设置'}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="font-medium">{isEn ? 'Privacy Mode' : '隐私模式'}</p>
              <p className="text-sm text-muted-foreground">{isEn ? 'Hide emails and sensitive info' : '隐藏邮箱和账号敏感信息'}</p>
            </div>
            <Button
              variant={privacyMode ? "default" : "outline"}
              size="sm"
              onClick={() => setPrivacyMode(!privacyMode)}
            >
              {privacyMode ? <EyeOff className="h-4 w-4 mr-2" /> : <Eye className="h-4 w-4 mr-2" />}
              {privacyMode ? (isEn ? 'On' : '已开启') : (isEn ? 'Off' : '已关闭')}
            </Button>
          </div>
          <div className="flex items-center justify-between pt-2 border-t">
            <div>
              <p className="font-medium">{isEn ? 'Usage Precision' : '使用量精度'}</p>
              <p className="text-sm text-muted-foreground">{isEn ? 'Show decimal places for usage values' : '显示使用量的小数精度（如 1.22 而非 1）'}</p>
            </div>
            <Button
              variant={usagePrecision ? "default" : "outline"}
              size="sm"
              onClick={() => setUsagePrecision(!usagePrecision)}
            >
              {usagePrecision ? (isEn ? 'Decimal' : '小数') : (isEn ? 'Integer' : '整数')}
            </Button>
          </div>
          <div className="flex items-center justify-between pt-2 border-t">
            <div>
              <p className="font-medium">{isEn ? 'Switch Target' : '切号目标'}</p>
              <p className="text-sm text-muted-foreground">{isEn ? 'Which client to switch account credentials to' : '切换账号凭证写入的客户端'}</p>
            </div>
            <select
              className="h-9 px-3 rounded-lg border bg-background text-sm focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary"
              value={switchTarget}
              onChange={(e) => setSwitchTarget(e.target.value as 'ide' | 'cli' | 'both')}
            >
              <option value="ide">Kiro IDE</option>
              <option value="cli">Kiro CLI</option>
              <option value="both">{isEn ? 'Both (IDE + CLI)' : '两者 (IDE + CLI)'}</option>
            </select>
          </div>
          <div className="flex items-center justify-between pt-2 border-t">
            <div>
              <p className="font-medium">{isEn ? 'Login Private Mode' : '登录隐私模式'}</p>
              <p className="text-sm text-muted-foreground">{isEn ? 'Open browser in incognito/private mode when logging in' : '在线登录时使用浏览器无痕/隐私模式打开'}</p>
            </div>
            <Button
              variant={loginPrivateMode ? "default" : "outline"}
              size="sm"
              onClick={() => setLoginPrivateMode(!loginPrivateMode)}
            >
              <UserX className="h-4 w-4 mr-2" />
              {loginPrivateMode ? (isEn ? 'On' : '已开启') : (isEn ? 'Off' : '已关闭')}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Token 刷新设置 */}
      <Card className="hover-lift">
        <CardHeader className="pb-2">
          <CardTitle className="text-base flex items-center gap-3">
            <div className="p-2 rounded-lg bg-primary/10">
              <RefreshCw className="h-4 w-4 text-primary" />
            </div>
            {isEn ? 'Auto Refresh' : '自动刷新'}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="font-medium">{isEn ? 'Auto Refresh' : '自动刷新'}</p>
              <p className="text-sm text-muted-foreground">{isEn ? 'Auto refresh tokens before expiration' : 'Token 过期前自动刷新，并同步更新账户信息'}</p>
            </div>
            <Button
              variant={autoRefreshEnabled ? "default" : "outline"}
              size="sm"
              onClick={() => setAutoRefresh(!autoRefreshEnabled)}
            >
              {autoRefreshEnabled ? (isEn ? 'On' : '已开启') : (isEn ? 'Off' : '已关闭')}
            </Button>
          </div>

          <div className="text-xs text-muted-foreground bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-900 rounded-lg p-3 space-y-1">
            <p className="font-medium text-amber-700 dark:text-amber-300">
              {isEn ? 'About Kiro IDE auto refresh' : '关于 Kiro IDE 自动刷新'}
            </p>
            <p>
              {isEn
                ? '• Kiro IDE has its own internal refresh loop (independent of this app). Disabling Auto Refresh here only stops this app from refreshing — it does NOT stop Kiro IDE.'
                : '• Kiro IDE 自带独立的刷新循环，关闭本工具的"自动刷新"不会停止 IDE 自己的刷新。'}
            </p>
            <p>
              {isEn
                ? '• When switching accounts or refreshing tokens here, the new token is synced to ~/.aws/sso/cache/kiro-auth-token.json only for the IDE current active account; other accounts only update the local store.'
                : '• 切号 / 刷新 Token 时，仅当该账号是 Kiro IDE 当前激活账号才会同步到磁盘文件；非激活账号仅更新本工具内部 store。'}
            </p>
            <p>
              {isEn
                ? '• If IDE refreshes the token itself, this app detects the file change and syncs the new token back to its store (bidirectional sync).'
                : '• 当 Kiro IDE 自己 refresh 后，本工具会监听磁盘文件变化并反向同步到 store（双向同步）。'}
            </p>
          </div>

          {/* 主动续期开关（默认关闭） */}
          <div className="flex items-center justify-between pt-3 border-t">
            <div>
              <p className="font-medium">
                {isEn ? 'Proactive Token Renewal for IDE' : 'IDE 主动续期'}
                <span className="ml-2 text-xs text-muted-foreground">
                  ({isEn ? 'Advanced' : '进阶'})
                </span>
              </p>
              <p className="text-sm text-muted-foreground">
                {isEn
                  ? `Renew IDE's active token ~${proactiveRenewalLeadMinutes} min before expiry, so Kiro IDE never refreshes by itself (eliminates all race conditions).`
                  : `在 IDE 激活账号的 token 剩 ~${proactiveRenewalLeadMinutes} 分钟时抢先 refresh，让 Kiro IDE 永远不自己 refresh（彻底消除竞争条件）。`}
              </p>
            </div>
            <Button
              variant={proactiveRenewalEnabled ? 'default' : 'outline'}
              size="sm"
              onClick={async () => {
                const result = await setProactiveRenewalEnabled(!proactiveRenewalEnabled)
                if (!result.success && result.error) {
                  alert(
                    (isEn ? 'Failed to toggle proactive renewal: ' : '切换主动续期失败：') +
                      result.error
                  )
                }
              }}
            >
              {proactiveRenewalEnabled ? (isEn ? 'On' : '已开启') : (isEn ? 'Off' : '已关闭')}
            </Button>
          </div>
          {proactiveRenewalEnabled && (
            <div className="text-xs text-muted-foreground bg-emerald-50 dark:bg-emerald-950/30 border border-emerald-200 dark:border-emerald-900 rounded-lg p-3 space-y-1">
              <p>
                {isEn
                  ? `• On: a single in-process timer renews token ${proactiveRenewalLeadMinutes} min before expiry; Kiro IDE keeps seeing fresh tokens (≥${60 - proactiveRenewalLeadMinutes} min remaining) and never invokes OIDC by itself.`
                  : `• 启用后：账号管理器主进程会在 token 剩 ${proactiveRenewalLeadMinutes} 分钟时自动续期，Kiro IDE 始终看到剩余 ≥ ${60 - proactiveRenewalLeadMinutes} 分钟的 token，永远不会自己调 OIDC。`}
              </p>
              <p>
                {isEn
                  ? '• Only the IDE current active account is renewed. Switching accounts re-schedules the timer for the new active account.'
                  : '• 仅对 IDE 当前激活账号续期。切号时 timer 会自动重新调度到新账号。'}
              </p>
              <p>
                {isEn
                  ? '• If a renewal fails (e.g. server outage), the timer stops; IDE\'s own refresh loop takes over as fallback.'
                  : '• 续期失败时 timer 停止，由 IDE 自己的 refresh loop 接管（双向同步仍生效）。'}
              </p>
            </div>
          )}

          {autoRefreshEnabled && (
            <>
              <div className="text-xs text-muted-foreground bg-muted/50 rounded-lg p-3 space-y-1">
                <p>• {isEn ? 'Auto refresh tokens to keep login' : 'Token 即将过期时自动刷新，保持登录状态'}</p>
                <p>• {isEn ? 'Update usage and subscription info after refresh' : 'Token 刷新后自动更新账户用量、订阅等信息'}</p>
                <p>• {isEn ? 'Check all balances when auto-switch is on' : '开启自动换号时，会定期检查所有账户余额'}</p>
              </div>
              <div className="flex items-center justify-between pt-2 border-t">
                <div>
                  <p className="font-medium">{isEn ? 'Check Interval' : '检查间隔'}</p>
                  <p className="text-sm text-muted-foreground">{isEn ? 'How often to check account status' : '每隔多久检查一次账户状态'}</p>
                </div>
                <select
                  className="w-[120px] h-9 px-3 rounded-lg border bg-background text-sm focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary"
                  value={autoRefreshInterval}
                  onChange={(e) => setAutoRefresh(true, parseInt(e.target.value))}
                >
                  <option value="1">{isEn ? '1 min' : '1 分钟'}</option>
                  <option value="3">{isEn ? '3 min' : '3 分钟'}</option>
                  <option value="5">{isEn ? '5 min' : '5 分钟'}</option>
                  <option value="10">{isEn ? '10 min' : '10 分钟'}</option>
                  <option value="15">{isEn ? '15 min' : '15 分钟'}</option>
                  <option value="20">{isEn ? '20 min' : '20 分钟'}</option>
                  <option value="30">{isEn ? '30 min' : '30 分钟'}</option>
                  <option value="45">{isEn ? '45 min' : '45 分钟'}</option>
                  <option value="60">{isEn ? '60 min' : '60 分钟'}</option>
                </select>
              </div>
              <div className="flex items-center justify-between pt-2 border-t">
                <div>
                  <p className="font-medium">{isEn ? 'Concurrency' : '刷新并发数'}</p>
                  <p className="text-sm text-muted-foreground">{isEn ? 'Number of accounts to refresh simultaneously' : '同时刷新的账号数量，过大可能卡顿'}</p>
                </div>
                <input
                  type="number"
                  className="w-24 h-9 px-3 rounded-lg border bg-background text-sm text-center focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary"
                  value={autoRefreshConcurrency}
                  min={1}
                  max={500}
                  onChange={(e) => setAutoRefreshConcurrency(parseInt(e.target.value) || 50)}
                />
              </div>
              <div className="flex items-center justify-between pt-2 border-t">
                <div>
                  <p className="font-medium">{isEn ? 'Sync Account Info' : '同步检测账户信息'}</p>
                  <p className="text-sm text-muted-foreground">{isEn ? 'Detect usage, subscription, and ban status' : '刷新 Token 时同步检测用量、订阅、封禁状态'}</p>
                </div>
                <Button
                  variant={autoRefreshSyncInfo ? "default" : "outline"}
                  size="sm"
                  onClick={() => setAutoRefreshSyncInfo(!autoRefreshSyncInfo)}
                >
                  {autoRefreshSyncInfo ? (isEn ? 'On' : '已开启') : (isEn ? 'Off' : '已关闭')}
                </Button>
              </div>
              <div className="flex items-center justify-between pt-2 border-t">
                <div>
                  <p className="font-medium">{isEn ? 'Manual Trigger' : '手动触发'}</p>
                  <p className="text-sm text-muted-foreground">{isEn ? 'Manually trigger auto-refresh for debugging' : '手动触发一次自动刷新流程（用于调试）'}</p>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleManualRefresh}
                  disabled={isManualRefreshing}
                >
                  {isManualRefreshing ? (isEn ? 'Refreshing...' : '刷新中...') : (isEn ? 'Trigger Now' : '立即触发')}
                </Button>
              </div>
            </>
          )}
        </CardContent>
      </Card>

      {/* API 类型设置 */}
      <Card className="hover-lift">
        <CardHeader className="pb-2">
          <CardTitle className="text-base flex items-center gap-3">
            <div className="p-2 rounded-lg bg-primary/10">
              <Database className="h-4 w-4 text-primary" />
            </div>
            {isEn ? 'API Settings' : 'API 设置'}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="font-medium">{isEn ? 'Usage API Type' : '用量查询 API'}</p>
              <p className="text-sm text-muted-foreground">{isEn ? 'Select API type for querying usage limits' : '选择查询账户用量的 API 类型'}</p>
            </div>
            <select
              className="w-[180px] h-9 px-3 rounded-lg border bg-background text-sm focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary"
              value={usageApiType}
              onChange={(e) => handleUsageApiTypeChange(e.target.value as 'rest' | 'cbor')}
              disabled={usageApiLoading}
            >
              <option value="rest">REST (GetUsageLimits)</option>
              <option value="cbor">CBOR (GetUserUsageAndLimits)</option>
            </select>
          </div>
          <div className="text-xs text-muted-foreground bg-muted/50 rounded-lg p-3 space-y-1">
            <p>• <strong>REST</strong>: {isEn ? 'Official Kiro IDE format, recommended' : '官方 Kiro IDE 使用的格式，推荐使用'}</p>
            <p>• <strong>CBOR</strong>: {isEn ? 'Web portal format, may have different fields' : '网页端格式，字段可能有差异'}</p>
          </div>
          <div className="flex items-center justify-between pt-2 border-t">
            <div>
              <p className="font-medium">{isEn ? 'Use K-Proxy for API' : 'API 请求走 K-Proxy'}</p>
              <p className="text-sm text-muted-foreground">{isEn ? 'Route API requests through K-Proxy MITM proxy' : 'API 请求通过 K-Proxy MITM 代理发送'}</p>
            </div>
            <Button
              variant={useKProxyForApi ? "default" : "outline"}
              size="sm"
              onClick={() => handleKProxyChange(!useKProxyForApi)}
              disabled={kproxyLoading}
            >
              {useKProxyForApi ? (isEn ? 'On' : '已开启') : (isEn ? 'Off' : '已关闭')}
            </Button>
          </div>
          {useKProxyForApi && (
            <div className="text-xs text-amber-500 bg-amber-500/10 rounded-lg p-3">
              {isEn ? '⚠️ K-Proxy must be running for this to work' : '⚠️ 需要先启动 K-Proxy MITM 代理才能生效'}
            </div>
          )}
        </CardContent>
      </Card>

      {/* 代理设置 */}
      <Card className="hover-lift">
        <CardHeader className="pb-2">
          <CardTitle className="text-base flex items-center gap-3">
            <div className="p-2 rounded-lg bg-primary/10">
              <Globe className="h-4 w-4 text-primary" />
            </div>
            {isEn ? 'Proxy' : '代理设置'}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="font-medium">{isEn ? 'Enable Proxy' : '启用代理'}</p>
              <p className="text-sm text-muted-foreground">{isEn ? 'All requests through proxy server' : '所有网络请求将通过代理服务器'}</p>
            </div>
            <Button
              variant={proxyEnabled ? "default" : "outline"}
              size="sm"
              onClick={() => setProxy(!proxyEnabled, tempProxyUrl)}
            >
              {proxyEnabled ? (isEn ? 'On' : '已开启') : (isEn ? 'Off' : '已关闭')}
            </Button>
          </div>

          <div className="space-y-2 pt-2 border-t">
            <label className="text-sm font-medium">{isEn ? 'Proxy URL' : '代理地址'}</label>
            <div className="flex gap-2">
              <input
                type="text"
                className="flex-1 h-9 px-3 rounded-lg border bg-background text-sm font-mono focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary"
                placeholder={isEn ? 'http://127.0.0.1:7890 or socks5://127.0.0.1:1080' : 'http://127.0.0.1:7890 或 socks5://127.0.0.1:1080'}
                value={tempProxyUrl}
                onChange={(e) => setTempProxyUrl(e.target.value)}
              />
              <Button 
                variant="outline" 
                size="sm"
                onClick={() => setProxy(proxyEnabled, tempProxyUrl)}
                disabled={tempProxyUrl === proxyUrl}
              >
                {isEn ? 'Save' : '保存'}
              </Button>
            </div>
            <p className="text-xs text-muted-foreground">
              {isEn ? 'Supports HTTP/HTTPS/SOCKS5, format: protocol://host:port' : '支持 HTTP/HTTPS/SOCKS5 代理，格式: protocol://host:port'}
            </p>
          </div>
        </CardContent>
      </Card>

      {/* 自动换号设置 */}
      <Card className="hover-lift">
        <CardHeader className="pb-2">
          <CardTitle className="text-base flex items-center gap-3">
            <div className="p-2 rounded-lg bg-primary/10">
              <Repeat className="h-4 w-4 text-primary" />
            </div>
            {isEn ? 'Auto Switch' : '自动换号'}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="font-medium">{isEn ? 'Enable Auto Switch' : '启用自动换号'}</p>
              <p className="text-sm text-muted-foreground">{isEn ? 'Auto switch when balance is low' : '余额不足时自动切换到其他可用账号'}</p>
            </div>
            <Button
              variant={autoSwitchEnabled ? "default" : "outline"}
              size="sm"
              onClick={() => setAutoSwitch(!autoSwitchEnabled)}
            >
              {autoSwitchEnabled ? (isEn ? 'On' : '已开启') : (isEn ? 'Off' : '已关闭')}
            </Button>
          </div>

          {autoSwitchEnabled && (
            <>
              <div className="flex items-center justify-between pt-2 border-t">
                <div>
                  <p className="font-medium">{isEn ? 'Balance Threshold' : '余额阈值'}</p>
                  <p className="text-sm text-muted-foreground">{isEn ? 'Switch when balance below this' : '余额低于此值时自动切换'}</p>
                </div>
                <input
                  type="number"
                  className="w-20 h-9 px-3 rounded-lg border bg-background text-sm text-center focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary"
                  value={autoSwitchThreshold}
                  min={0}
                  onChange={(e) => setAutoSwitch(true, parseInt(e.target.value) || 0)}
                />
              </div>

              <div className="flex items-center justify-between pt-2 border-t">
                <div>
                  <p className="font-medium flex items-center gap-2">
                    <Clock className="h-4 w-4" />
                    {isEn ? 'Check Interval' : '检查间隔'}
                  </p>
                  <p className="text-sm text-muted-foreground">{isEn ? 'How often to check balance' : '每隔多久检查一次余额'}</p>
                </div>
                <select
                  className="h-9 px-3 rounded-lg border bg-background text-sm focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary"
                  value={autoSwitchInterval}
                  onChange={(e) => setAutoSwitch(true, undefined, parseInt(e.target.value))}
                >
                  <option value="1">{isEn ? '1 min' : '1 分钟'}</option>
                  <option value="3">{isEn ? '3 min' : '3 分钟'}</option>
                  <option value="5">{isEn ? '5 min' : '5 分钟'}</option>
                  <option value="10">{isEn ? '10 min' : '10 分钟'}</option>
                  <option value="15">{isEn ? '15 min' : '15 分钟'}</option>
                  <option value="30">{isEn ? '30 min' : '30 分钟'}</option>
                </select>
              </div>
            </>
          )}
        </CardContent>
      </Card>

      {/* 批量导入设置 */}
      <Card className="hover-lift">
        <CardHeader className="pb-2">
          <CardTitle className="text-base flex items-center gap-3">
            <div className="p-2 rounded-lg bg-primary/10">
              <Layers className="h-4 w-4 text-primary" />
            </div>
            {isEn ? 'Batch Import' : '批量导入'}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="font-medium">{isEn ? 'Concurrency' : '并发数'}</p>
              <p className="text-sm text-muted-foreground">{isEn ? 'Too high may cause API rate limiting' : '同时验证的账号数量，过大可能导致 API 限流'}</p>
            </div>
            <input
              type="number"
              className="w-24 h-9 px-3 rounded-lg border bg-background text-sm text-center focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary"
              value={batchImportConcurrency}
              min={1}
              max={500}
              onChange={(e) => setBatchImportConcurrency(parseInt(e.target.value) || 100)}
            />
          </div>
          <p className="text-xs text-muted-foreground bg-muted/50 rounded-lg p-2">
            {isEn ? 'Recommended: 10-100. Too high may cause failures, too low is slow.' : '建议范围: 10-100。设置过大可能导致大量「验证失败」，设置过小则导入速度较慢。'}
          </p>
        </CardContent>
      </Card>

      {/* 系统托盘设置 */}
      <Card className="hover-lift">
        <CardHeader className="pb-2">
          <CardTitle className="text-base flex items-center gap-3">
            <div className="p-2 rounded-lg bg-primary/10">
              <Monitor className="h-4 w-4 text-primary" />
            </div>
            {isEn ? 'System Tray' : '系统托盘'}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {trayLoading ? (
            <div className="text-sm text-muted-foreground">{isEn ? 'Loading...' : '加载中...'}</div>
          ) : (
            <>
              <div className="flex items-center justify-between">
                <div>
                  <p className="font-medium">{isEn ? 'Enable System Tray' : '启用系统托盘'}</p>
                  <p className="text-sm text-muted-foreground">{isEn ? 'Show icon in system tray' : '在系统托盘显示图标'}</p>
                </div>
                <Button
                  variant={traySettings.enabled ? 'default' : 'outline'}
                  size="sm"
                  onClick={() => handleTraySettingChange('enabled', !traySettings.enabled)}
                >
                  {traySettings.enabled ? (isEn ? 'On' : '已开启') : (isEn ? 'Off' : '已关闭')}
                </Button>
              </div>

              {traySettings.enabled && (
                <>
                  <div className="flex items-center justify-between pt-2 border-t">
                    <div>
                      <p className="font-medium">{isEn ? 'Close Button Action' : '关闭按钮行为'}</p>
                      <p className="text-sm text-muted-foreground">{isEn ? 'What happens when you click X' : '点击关闭按钮时的行为'}</p>
                    </div>
                    <select
                      className="w-[140px] h-9 px-3 rounded-lg border bg-background text-sm focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary"
                      value={traySettings.closeAction}
                      onChange={(e) => handleTraySettingChange('closeAction', e.target.value)}
                    >
                      <option value="ask">{isEn ? 'Ask every time' : '每次询问'}</option>
                      <option value="minimize">{isEn ? 'Minimize to tray' : '最小化到托盘'}</option>
                      <option value="quit">{isEn ? 'Quit application' : '退出程序'}</option>
                    </select>
                  </div>
                </>
              )}

              <div className="text-xs text-muted-foreground bg-muted/50 rounded-lg p-3 space-y-1">
                <p>• {isEn ? 'Double-click tray icon to show window' : '双击托盘图标可以显示主窗口'}</p>
                <p>• {isEn ? 'Right-click tray icon to show menu' : '右键托盘图标可以显示菜单'}</p>
                <p>• {isEn ? 'Tray menu shows current account info and usage' : '托盘菜单可以查看当前账户信息和用量'}</p>
              </div>
            </>
          )}
        </CardContent>
      </Card>

      {/* 快捷键设置 */}
      <Card className="hover-lift">
        <CardHeader className="pb-2">
          <CardTitle className="text-base flex items-center gap-3">
            <div className="p-2 rounded-lg bg-primary/10">
              <Settings className="h-4 w-4 text-primary" />
            </div>
            {isEn ? 'Keyboard Shortcuts' : '快捷键'}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {shortcutLoading ? (
            <div className="text-sm text-muted-foreground">{isEn ? 'Loading...' : '加载中...'}</div>
          ) : (
            <>
              <div className="flex items-center justify-between">
                <div>
                  <p className="font-medium">{isEn ? 'Show Window' : '显示主窗口'}</p>
                  <p className="text-sm text-muted-foreground">{isEn ? 'Global shortcut to show main window' : '全局快捷键唤起主窗口'}</p>
                </div>
                <div className="flex items-center gap-2">
                  <input
                    type="text"
                    className={`w-[160px] h-9 px-3 rounded-lg border bg-background text-sm focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary text-center ${isRecordingShortcut ? 'border-primary ring-1 ring-primary animate-pulse' : ''}`}
                    value={isRecordingShortcut ? (isEn ? 'Press keys...' : '请按键...') : showWindowShortcut}
                    onKeyDown={handleKeyDown}
                    onFocus={() => setIsRecordingShortcut(true)}
                    onBlur={() => setIsRecordingShortcut(false)}
                    readOnly
                    placeholder={isEn ? 'Click to record' : '点击录制'}
                  />
                  {showWindowShortcut && (
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-9 px-2"
                      onClick={() => handleShortcutChange('')}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  )}
                </div>
              </div>
              {shortcutError && (
                <p className="text-sm text-destructive">{shortcutError}</p>
              )}
              <div className="text-xs text-muted-foreground bg-muted/50 rounded-lg p-3 space-y-1">
                <p>• {isEn ? 'Click input and press key combination to record' : '点击输入框后按下组合键自动录制'}</p>
                <p>• {isEn ? 'macOS use Command, Windows/Linux use Ctrl' : 'macOS 使用 Command，Windows/Linux 使用 Ctrl'}</p>
                <p>• {isEn ? 'Click trash icon to clear shortcut' : '点击垃圾桶图标可清除快捷键'}</p>
              </div>
            </>
          )}
        </CardContent>
      </Card>

      {/* 机器码管理提示 */}
      <Card className="hover-lift bg-primary/5">
        <CardContent className="py-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-primary/10">
              <Fingerprint className="h-5 w-5 text-primary" />
            </div>
            <div className="flex-1">
              <p className="font-medium text-sm">{isEn ? 'Machine ID' : '机器码管理'}</p>
              <p className="text-xs text-muted-foreground">
                {isEn ? 'Device identifier, auto-switch, account binding' : '修改设备标识符、切号自动换码、账户机器码绑定等功能'}
              </p>
            </div>
            <div className="flex items-center gap-1 text-xs text-muted-foreground">
              <Info className="h-3 w-3" />
              <span>{isEn ? 'Set in sidebar "Machine ID"' : '请在侧边栏「机器码」中设置'}</span>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* 数据管理 */}
      <Card className="hover-lift">
        <CardHeader className="pb-2">
          <CardTitle className="text-base flex items-center gap-3">
            <div className="p-2 rounded-lg bg-primary/10">
              <Database className="h-4 w-4 text-primary" />
            </div>
            {isEn ? 'Data Management' : '数据管理'}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="font-medium">{isEn ? 'Export Data' : '导出数据'}</p>
              <p className="text-sm text-muted-foreground">{isEn ? 'Supports JSON, TXT, CSV, Clipboard' : '支持 JSON、TXT、CSV、剪贴板等多种格式'}</p>
            </div>
            <Button variant="outline" size="sm" onClick={handleExport}>
              <Download className="h-4 w-4 mr-2" />
              {isEn ? 'Export' : '导出'}
            </Button>
          </div>

          <div className="flex items-center justify-between pt-2 border-t">
            <div>
              <p className="font-medium">{isEn ? 'Import Data' : '导入数据'}</p>
              <p className="text-sm text-muted-foreground">{isEn ? 'Import accounts from JSON file' : '从 JSON 文件导入账号数据'}</p>
            </div>
            <Button variant="outline" size="sm" onClick={handleImport} disabled={isImporting}>
              <Upload className="h-4 w-4 mr-2" />
              {isImporting ? (isEn ? 'Importing...' : '导入中...') : (isEn ? 'Import' : '导入')}
            </Button>
          </div>

          <div className="flex items-center justify-between pt-2 border-t">
            <div>
              <p className="font-medium text-destructive">{isEn ? 'Clear All Data' : '清除所有数据'}</p>
              <p className="text-sm text-muted-foreground">{isEn ? 'Delete all accounts, groups and tags' : '删除所有账号、分组和标签'}</p>
            </div>
            <Button variant="destructive" size="sm" onClick={handleClearData}>
              <Trash2 className="h-4 w-4 mr-2" />
              {isEn ? 'Clear' : '清除'}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* 配置同步（不含敏感凭据，便于多设备共享） */}
      <ConfigSyncCard isEn={isEn} />

      {/* 导出对话框 */}
      <ExportDialog
        open={showExportDialog}
        onClose={() => setShowExportDialog(false)}
        accounts={Array.from(accounts.values())}
        selectedCount={0}
      />
    </div>
  )
}

/**
 * 配置同步卡片：把所有"非敏感"配置（代理池、Webhook、模板、限速、定时、各种 localStorage）打包导出/导入。
 * 不包含：账号 token / 私密凭据。
 */
function ConfigSyncCard({ isEn }: { isEn: boolean }): React.ReactNode {
  const proxyPool = useAccountsStore((s) => s.proxyPool)
  const proxyPoolConfig = useAccountsStore((s) => s.proxyPoolConfig)

  // 收集所有可同步的 localStorage key
  const COLLECTED_LS_KEYS = [
    'kiro-register-config',
    'kiro-register-history',  // 可选：用户可决定要不要
    'kiro-register-templates',
    'kiro-register-ratelimit-enabled',
    'kiro-register-ratelimit-max',
    'kiro-register-autobackoff',
    'kiro-register-dailyquota-limit',
    'kiro-register-schedule-enabled',
    'kiro-register-schedule-time',
    'kiro-register-mixed-sources',
    'kiro-webhooks',
    'accounts_viewMode',
    'accounts_activeGroupTab',
    'systemLogs_displayLimit',
    'kiro-diagnose-moemail',
    'proxyLogs_timeRange',
    'proxyLogs_displayLimit'
  ]

  const handleExport = (): void => {
    const localData: Record<string, string> = {}
    for (const key of COLLECTED_LS_KEYS) {
      const v = localStorage.getItem(key)
      if (v != null) localData[key] = v
    }
    const payload = {
      version: 1,
      type: 'kiro-account-manager-config',
      exportedAt: Date.now(),
      // 代理池条目（不含敏感账号）
      proxyPool: Object.fromEntries(proxyPool),
      proxyPoolConfig,
      // 各种 localStorage
      localStorage: localData
    }
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `kiro-config-${new Date().toISOString().replace(/[:.]/g, '-')}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const handleImport = async (): Promise<void> => {
    const fileData = await window.api.importFromFile()
    if (!fileData || fileData.format !== 'json') {
      alert(isEn ? 'Please select a JSON file' : '请选择 JSON 文件')
      return
    }
    try {
      const payload = JSON.parse(fileData.content)
      if (payload.type !== 'kiro-account-manager-config') {
        alert(isEn ? 'Not a valid config file' : '不是有效的配置文件')
        return
      }
      if (!confirm(isEn ? 'This will overwrite proxy pool / webhooks / templates. Continue?' : '这将覆盖代理池 / Webhook / 模板等配置，确定继续？')) {
        return
      }

      // 恢复 localStorage
      if (payload.localStorage && typeof payload.localStorage === 'object') {
        for (const [k, v] of Object.entries(payload.localStorage)) {
          if (COLLECTED_LS_KEYS.includes(k) && typeof v === 'string') {
            try { localStorage.setItem(k, v) } catch { /* ignore */ }
          }
        }
      }

      // 恢复代理池（通过 store 接口）
      if (payload.proxyPool && typeof payload.proxyPool === 'object') {
        const store = useAccountsStore.getState()
        store.clearProxyPool()
        // 直接通过 set 重建 Map（绕过 addProxy 的解析步骤，保留原 ID）
        useAccountsStore.setState({
          proxyPool: new Map(Object.entries(payload.proxyPool as Record<string, never>)) as Parameters<typeof useAccountsStore.setState>[0] extends infer T ? (T extends { proxyPool: infer P } ? P : never) : never
        } as Parameters<typeof useAccountsStore.setState>[0])
      }
      if (payload.proxyPoolConfig) {
        useAccountsStore.getState().setProxyPoolConfig(payload.proxyPoolConfig)
      }

      alert(isEn
        ? 'Config imported. Please restart the app to fully apply.'
        : '配置已导入。建议重启应用以完全生效。'
      )
    } catch (e) {
      alert((isEn ? 'Import failed: ' : '导入失败: ') + (e instanceof Error ? e.message : String(e)))
    }
  }

  return (
    <Card className="hover-lift">
      <CardHeader className="pb-2">
        <CardTitle className="text-base flex items-center gap-3">
          <div className="p-2 rounded-lg bg-primary/10">
            <Repeat className="h-4 w-4 text-primary" />
          </div>
          {isEn ? 'Configuration Sync' : '配置同步'}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-sm text-muted-foreground">
          {isEn
            ? 'Export all non-sensitive settings (proxy pool, webhooks, templates, rate limits, UI preferences) to a file, for backup or multi-device sync. Does NOT include account tokens or credentials.'
            : '导出所有"非敏感"配置（代理池、Webhook、注册模板、限速、UI 偏好等）到文件，便于备份或多设备同步。不含账号 Token 与凭据。'
          }
        </p>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={handleExport}>
            <Download className="h-4 w-4 mr-2" />
            {isEn ? 'Export Config' : '导出配置'}
          </Button>
          <Button variant="outline" size="sm" onClick={handleImport}>
            <Upload className="h-4 w-4 mr-2" />
            {isEn ? 'Import Config' : '导入配置'}
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}
