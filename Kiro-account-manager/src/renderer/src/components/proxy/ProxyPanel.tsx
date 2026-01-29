import { useState, useEffect, useCallback } from 'react'
import { Play, Square, RefreshCw, Copy, Check, Server, Activity, AlertCircle, Globe, Zap, Loader2, FileText, Eye, EyeOff, Dices, Cpu, UserCheck, RotateCcw, Users, Clock } from 'lucide-react'
import { Button, Card, CardContent, CardDescription, CardHeader, CardTitle, Input, Label, Switch, Badge, Select } from '../ui'
import { useAccountsStore } from '../../store/accounts'
import { useTranslation } from '../../hooks/useTranslation'
import { ProxyLogsDialog } from './ProxyLogsDialog'
import { ProxyDetailedLogsDialog } from './ProxyDetailedLogsDialog'
import { ModelsDialog } from './ModelsDialog'
import { AccountSelectDialog } from './AccountSelectDialog'
import { ApiKeyManager } from './ApiKeyManager'
import { createPortal } from 'react-dom'

interface ProxyStats {
  totalRequests: number
  successRequests: number
  failedRequests: number
  totalTokens: number
  totalCredits: number
  inputTokens: number
  outputTokens: number
  startTime: number
}

interface SessionStats {
  totalRequests: number
  successRequests: number
  failedRequests: number
  startTime: number
}

interface ProxyConfig {
  enabled: boolean
  port: number
  host: string
  apiKey?: string
  enableMultiAccount: boolean
  selectedAccountId?: string
  logRequests: boolean
  maxRetries?: number
  preferredEndpoint?: 'codewhisperer' | 'amazonq'
  autoStart?: boolean
  autoContinueRounds?: number
  disableTools?: boolean
  autoSwitchOnQuotaExhausted?: boolean
}

export function ProxyPanel() {
  const { t } = useTranslation()
  const isEn = t('common.unknown') === 'Unknown'
  const [isRunning, setIsRunning] = useState(false)
  const [config, setConfig] = useState<ProxyConfig>({
    enabled: false,
    port: 5580,
    host: '127.0.0.1',
    enableMultiAccount: true,
    logRequests: true
  })
  const [stats, setStats] = useState<ProxyStats | null>(null)
  const [sessionStats, setSessionStats] = useState<SessionStats | null>(null)
  const [accountCount, setAccountCount] = useState(0)
  const [availableCount, setAvailableCount] = useState(0)
  const [copied, setCopied] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [recentLogs, setRecentLogs] = useState<Array<{ time: string; path: string; status: number; tokens?: number; inputTokens?: number; outputTokens?: number; credits?: number; error?: string }>>([])
  const [isSyncing, setIsSyncing] = useState(false)
  const [isRefreshingModels, setIsRefreshingModels] = useState(false)
  const [syncSuccess, setSyncSuccess] = useState(false)
  const [refreshSuccess, setRefreshSuccess] = useState(false)
  const [showLogsDialog, setShowLogsDialog] = useState(false)
  const [showDetailedLogsDialog, setShowDetailedLogsDialog] = useState(false)
  const [showModelsDialog, setShowModelsDialog] = useState(false)
  const [showAccountSelectDialog, setShowAccountSelectDialog] = useState(false)
  const [showApiKeyManager, setShowApiKeyManager] = useState(false)
  const [showApiKey, setShowApiKey] = useState(false)
  const [apiKeyFormat, setApiKeyFormat] = useState<'sk' | 'simple' | 'token'>('sk')
  const [apiKeyCopied, setApiKeyCopied] = useState(false)
  const [apiKeyGenerated, setApiKeyGenerated] = useState(false)

  const accounts = useAccountsStore(state => state.accounts)

  // 生成随机 API Key
  const generateApiKey = useCallback(() => {
    const randomHex = (len: number) => {
      const chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
      return Array.from({ length: len }, () => chars[Math.floor(Math.random() * chars.length)]).join('')
    }
    
    let newKey: string
    switch (apiKeyFormat) {
      case 'sk':
        newKey = `sk-${randomHex(48)}`
        break
      case 'simple':
        newKey = `PROXY_KEY_${randomHex(32).toUpperCase()}`
        break
      case 'token':
        newKey = `PROXY_KEY:${randomHex(32)}`
        break
      default:
        newKey = `sk-${randomHex(48)}`
    }
    
    setConfig(prev => ({ ...prev, apiKey: newKey }))
    window.api.proxyUpdateConfig({ apiKey: newKey })
    setShowApiKey(true)
    setApiKeyGenerated(true)
    setTimeout(() => setApiKeyGenerated(false), 1500)
  }, [apiKeyFormat])

  // 复制 API Key
  const copyApiKey = useCallback(() => {
    if (config.apiKey) {
      navigator.clipboard.writeText(config.apiKey)
      setApiKeyCopied(true)
      setTimeout(() => setApiKeyCopied(false), 1500)
    }
  }, [config.apiKey])

  // 获取状态
  const fetchStatus = useCallback(async () => {
    try {
      const result = await window.api.proxyGetStatus()
      setIsRunning(result.running)
      if (result.config) {
        const cfg = result.config as ProxyConfig & { selectedAccountIds?: string[] }
        // 将 selectedAccountIds 数组转换为单个 selectedAccountId
        if (cfg.selectedAccountIds && cfg.selectedAccountIds.length > 0) {
          cfg.selectedAccountId = cfg.selectedAccountIds[0]
        }
        setConfig(cfg)
      }
      if (result.stats) {
        setStats(result.stats as ProxyStats)
      }
      if (result.sessionStats) {
        setSessionStats(result.sessionStats as SessionStats)
      }

      const accountsResult = await window.api.proxyGetAccounts()
      setAccountCount(accountsResult.accounts.length)
      setAvailableCount(accountsResult.availableCount)
    } catch (err) {
      console.error('Failed to fetch proxy status:', err)
    }
  }, [])

  // 同步账号到反代池
  const syncAccounts = useCallback(async () => {
    setIsSyncing(true)
    setSyncSuccess(false)
    try {
      const proxyAccounts = Array.from(accounts.values())
        .filter(acc => acc.status === 'active' && acc.credentials?.accessToken)
        .map(acc => ({
          id: acc.id,
          email: acc.email,
          accessToken: acc.credentials.accessToken,
          refreshToken: acc.credentials?.refreshToken,
          profileArn: (acc as any).profileArn,
          expiresAt: acc.credentials?.expiresAt,
          // Token 刷新所需字段
          clientId: acc.credentials?.clientId,
          clientSecret: acc.credentials?.clientSecret,
          region: acc.credentials?.region || 'us-east-1',
          authMethod: acc.credentials?.authMethod as 'social' | 'idc' | undefined
        }))

      const result = await window.api.proxySyncAccounts(proxyAccounts)
      if (result.success) {
        setAccountCount(result.accountCount || 0)
        await fetchStatus()
        setSyncSuccess(true)
        setTimeout(() => setSyncSuccess(false), 2000)
      }
    } catch (err) {
      console.error('Failed to sync accounts:', err)
    } finally {
      setIsSyncing(false)
    }
  }, [accounts, fetchStatus])

  // 启动服务器
  const handleStart = async () => {
    setError(null)
    try {
      // 先同步账号
      await syncAccounts()

      const result = await window.api.proxyStart({
        port: config.port,
        host: config.host,
        apiKey: config.apiKey,
        enableMultiAccount: config.enableMultiAccount,
        logRequests: config.logRequests
      })

      if (result.success) {
        setIsRunning(true)
        await fetchStatus()
      } else {
        setError(result.error || (isEn ? 'Failed to start' : '启动失败'))
      }
    } catch (err) {
      setError((err as Error).message)
    }
  }

  // 停止服务器
  const handleStop = async () => {
    setError(null)
    try {
      const result = await window.api.proxyStop()
      if (result.success) {
        setIsRunning(false)
        setStats(null)
      } else {
        setError(result.error || (isEn ? 'Failed to stop' : '停止失败'))
      }
    } catch (err) {
      setError((err as Error).message)
    }
  }

  // 复制地址
  const copyAddress = () => {
    const address = `http://${config.host}:${config.port}`
    navigator.clipboard.writeText(address)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  // 刷新模型缓存
  const handleRefreshModels = async () => {
    setIsRefreshingModels(true)
    setRefreshSuccess(false)
    try {
      const result = await window.api.proxyRefreshModels()
      if (result.success) {
        setRefreshSuccess(true)
        setTimeout(() => setRefreshSuccess(false), 2000)
      } else {
        setError(result.error || (isEn ? 'Failed to refresh models' : '刷新模型失败'))
      }
    } catch (err) {
      setError((err as Error).message)
    } finally {
      setIsRefreshingModels(false)
    }
  }

  // 加载历史日志
  useEffect(() => {
    window.api.proxyLoadLogs().then(result => {
      if (result.success && result.logs.length > 0) {
        setRecentLogs(result.logs)
      }
    })
  }, [])

  // 保存日志（防抖）
  useEffect(() => {
    if (recentLogs.length === 0) return
    const timer = setTimeout(() => {
      window.api.proxySaveLogs(recentLogs)
    }, 2000)
    return () => clearTimeout(timer)
  }, [recentLogs])

  // 初始化
  useEffect(() => {
    fetchStatus()

    // 监听事件
    const unsubRequest = window.api.onProxyRequest((info) => {
      console.log('[Proxy] Request:', info)
    })

    const unsubResponse = window.api.onProxyResponse((info) => {
      const now = new Date()
      const year = now.getFullYear()
      const month = (now.getMonth() + 1).toString().padStart(2, '0')
      const day = now.getDate().toString().padStart(2, '0')
      const hours = now.getHours().toString().padStart(2, '0')
      const minutes = now.getMinutes().toString().padStart(2, '0')
      const seconds = now.getSeconds().toString().padStart(2, '0')
      const ms = now.getMilliseconds().toString().padStart(3, '0')
      const fullTime = `${year}-${month}-${day} ${hours}:${minutes}:${seconds}.${ms}`
      setRecentLogs(prev => [{
        time: fullTime,
        path: info.path,
        status: info.status,
        tokens: info.tokens,
        inputTokens: info.inputTokens,
        outputTokens: info.outputTokens,
        credits: info.credits,
        error: info.error
      }, ...prev.slice(0, 99)]) // 保留最多 100 条

      // 更新统计
      fetchStatus()
    })

    const unsubError = window.api.onProxyError((err) => {
      console.error('[Proxy] Error:', err)
      setError(err)
    })

    const unsubStatus = window.api.onProxyStatusChange((status) => {
      setIsRunning(status.running)
      if (status.running) {
        setConfig(prev => ({ ...prev, port: status.port }))
      }
    })

    return () => {
      unsubRequest()
      unsubResponse()
      unsubError()
      unsubStatus()
    }
  }, [fetchStatus])

  // 账号变化时同步
  useEffect(() => {
    if (isRunning) {
      syncAccounts()
    }
  }, [accounts, isRunning, syncAccounts])

  // 实时更新运行时间
  const [uptime, setUptime] = useState(0)
  useEffect(() => {
    if (!isRunning || !stats) {
      setUptime(0)
      return
    }
    
    // 立即计算一次
    setUptime(Math.floor((Date.now() - stats.startTime) / 1000))
    
    // 每秒更新
    const timer = setInterval(() => {
      setUptime(Math.floor((Date.now() - stats.startTime) / 1000))
    }, 1000)
    
    return () => clearInterval(timer)
  }, [isRunning, stats])
  const formatUptime = (seconds: number) => {
    const h = Math.floor(seconds / 3600)
    const m = Math.floor((seconds % 3600) / 60)
    const s = seconds % 60
    return `${h}h ${m}m ${s}s`
  }

  return (
    <div className="space-y-4">
      {/* 状态卡片 */}
      <Card className="border-0 shadow-sm hover:shadow-md transition-shadow duration-200">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-primary/10">
                <Server className="h-5 w-5 text-primary" />
              </div>
              <div>
                <CardTitle className="text-lg text-primary">{isEn ? 'Kiro API Proxy' : 'Kiro API 反代'}</CardTitle>
                <CardDescription>
                  {isEn ? 'Provides OpenAI and Claude compatible API endpoints' : '提供 OpenAI 和 Claude 兼容的 API 端点'}
                </CardDescription>
              </div>
            </div>
            <Badge 
              variant={isRunning ? 'default' : 'secondary'} 
              className={isRunning 
                ? 'bg-green-500 text-white flex items-center gap-1.5 pr-2.5' 
                : 'bg-muted text-muted-foreground flex items-center gap-1.5 pr-2.5'}
            >
              <span className={isRunning 
                ? 'relative flex h-2 w-2' 
                : 'relative flex h-2 w-2'}>
                {isRunning && (
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-white opacity-75"></span>
                )}
                <span className={isRunning 
                  ? 'relative inline-flex rounded-full h-2 w-2 bg-white' 
                  : 'relative inline-flex rounded-full h-2 w-2 bg-muted-foreground'}></span>
              </span>
              {isRunning ? (isEn ? 'Running' : '运行中') : (isEn ? 'Stopped' : '已停止')}
            </Badge>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* 控制按钮 */}
          <div className="flex items-center gap-2">
            {!isRunning ? (
              <Button onClick={handleStart} className="gap-2">
                <Play className="h-4 w-4" />
                {isEn ? 'Start Service' : '启动服务'}
              </Button>
            ) : (
              <Button onClick={handleStop} variant="destructive" className="gap-2">
                <Square className="h-4 w-4" />
                {isEn ? 'Stop Service' : '停止服务'}
              </Button>
            )}
            <Button onClick={syncAccounts} variant="outline" className="gap-2" disabled={!isRunning || isSyncing}>
              {isSyncing ? <Loader2 className="h-4 w-4 animate-spin" /> : syncSuccess ? <Check className="h-4 w-4 text-green-500" /> : <RefreshCw className="h-4 w-4" />}
              {isSyncing ? (isEn ? 'Syncing...' : '同步中...') : syncSuccess ? (isEn ? 'Synced!' : '已同步') : (isEn ? 'Sync Accounts' : '同步账号')}
            </Button>
            <Button onClick={handleRefreshModels} variant="outline" className="gap-2" disabled={!isRunning || isRefreshingModels}>
              {isRefreshingModels ? <Loader2 className="h-4 w-4 animate-spin" /> : refreshSuccess ? <Check className="h-4 w-4 text-green-500" /> : <RefreshCw className="h-4 w-4" />}
              {isRefreshingModels ? (isEn ? 'Refreshing...' : '刷新中...') : refreshSuccess ? (isEn ? 'Refreshed!' : '已刷新') : (isEn ? 'Refresh Models' : '刷新模型')}
            </Button>
            <Button onClick={() => setShowModelsDialog(true)} variant="outline" className="gap-2" disabled={!isRunning}>
              <Cpu className="h-4 w-4" />
              {isEn ? 'View Models' : '查看模型'}
            </Button>
          </div>

          {/* 错误提示 */}
          {error && (
            <div className="flex items-center gap-2 text-destructive text-sm">
              <AlertCircle className="h-4 w-4" />
              {error}
            </div>
          )}

          {/* 服务地址 */}
          {isRunning && (
            <div className="flex items-center gap-2">
              <Label className="min-w-[80px]">{isEn ? 'Address:' : '服务地址:'}</Label>
              <code className="flex-1 px-3 py-2 bg-muted rounded text-sm">
                http://{config.host}:{config.port}
              </code>
              <Button variant="outline" size="icon" onClick={copyAddress}>
                {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
              </Button>
            </div>
          )}

          {/* 配置 */}
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="port">{isEn ? 'Port' : '端口'}</Label>
              <Input
                id="port"
                type="number"
                value={config.port}
                onChange={(e) => {
                  const newPort = parseInt(e.target.value) || 5580
                  setConfig(prev => ({ ...prev, port: newPort }))
                  window.api.proxyUpdateConfig({ port: newPort })
                }}
                disabled={isRunning}
              />
            </div>
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label htmlFor="host">{isEn ? 'Host' : '监听地址'}</Label>
                <div className="flex items-center gap-1.5">
                  <Switch
                    id="publicAccess"
                    checked={config.host === '0.0.0.0'}
                    onCheckedChange={(checked) => {
                      const newHost = checked ? '0.0.0.0' : '127.0.0.1'
                      setConfig(prev => ({ ...prev, host: newHost }))
                      window.api.proxyUpdateConfig({ host: newHost })
                    }}
                    disabled={isRunning}
                    className="scale-75"
                  />
                  <Label htmlFor="publicAccess" className="text-xs cursor-pointer">{isEn ? 'Public' : '外网'}</Label>
                </div>
              </div>
              <Input
                id="host"
                value={config.host}
                onChange={(e) => {
                  const newHost = e.target.value
                  setConfig(prev => ({ ...prev, host: newHost }))
                  window.api.proxyUpdateConfig({ host: newHost })
                }}
                disabled={isRunning}
              />
            </div>
          </div>

          {/* API Key 配置 */}
          <div className="space-y-2">
            <Label htmlFor="apiKey">{isEn ? 'API Key (Optional)' : 'API Key (可选)'}</Label>
            <div className="flex gap-2">
              <div className="relative flex-1">
                <Input
                  id="apiKey"
                  type={showApiKey ? 'text' : 'password'}
                  placeholder={isEn ? 'Leave empty to skip auth' : '留空则不验证'}
                  value={config.apiKey || ''}
                  onChange={(e) => {
                    const newApiKey = e.target.value || undefined
                    setConfig(prev => ({ ...prev, apiKey: newApiKey }))
                    window.api.proxyUpdateConfig({ apiKey: newApiKey })
                  }}
                  disabled={isRunning}
                  className="pr-10"
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="absolute right-0 top-0 h-full px-3 hover:bg-transparent"
                  onClick={() => setShowApiKey(!showApiKey)}
                  title={showApiKey ? (isEn ? 'Hide' : '隐藏') : (isEn ? 'Show' : '显示')}
                >
                  {showApiKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </Button>
              </div>
              <Select
                value={apiKeyFormat}
                options={[
                  { value: 'sk', label: 'sk-xxx' },
                  { value: 'simple', label: 'PROXY_KEY' },
                  { value: 'token', label: 'KEY:TOKEN' }
                ]}
                onChange={(v) => setApiKeyFormat(v as 'sk' | 'simple' | 'token')}
                className="w-[130px]"
              />
              <Button
                variant="outline"
                size="icon"
                onClick={generateApiKey}
                disabled={isRunning}
                title={isEn ? 'Generate Random Key' : '随机生成'}
                className={apiKeyGenerated ? 'border-green-500 text-green-500' : ''}
              >
                {apiKeyGenerated ? <Check className="h-4 w-4" /> : <Dices className="h-4 w-4" />}
              </Button>
              {config.apiKey && (
                <Button
                  variant="outline"
                  size="icon"
                  onClick={copyApiKey}
                  title={isEn ? 'Copy API Key' : '复制 API Key'}
                  className={apiKeyCopied ? 'border-green-500 text-green-500' : ''}
                >
                  {apiKeyCopied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                </Button>
              )}
              <Button
                variant="outline"
                size="icon"
                onClick={() => setShowApiKeyManager(true)}
                title={isEn ? 'Manage Multiple API Keys' : '管理多个 API Key'}
                className="text-xs w-auto px-2"
              >
                {isEn ? 'Manage' : '管理'}
              </Button>
            </div>
            <p className="text-xs text-muted-foreground">{isEn ? 'When set, requests must provide this key in Authorization or X-Api-Key header' : '设置后，请求需要在 Authorization 或 X-Api-Key 头中提供此密钥'}</p>
          </div>

          <div className="flex items-center justify-between flex-wrap gap-2">
            <div className="flex items-center gap-2">
              <Switch
                id="autoStart"
                checked={config.autoStart || false}
                onCheckedChange={(checked) => {
                  setConfig(prev => ({ ...prev, autoStart: checked }))
                  window.api.proxyUpdateConfig({ autoStart: checked })
                }}
              />
              <Label htmlFor="autoStart">{isEn ? 'Auto Start' : '随软件启动'}</Label>
            </div>
            <div className="flex items-center gap-2">
              <Switch
                id="multiAccount"
                checked={config.enableMultiAccount}
                onCheckedChange={(checked) => {
                  setConfig(prev => ({ ...prev, enableMultiAccount: checked }))
                  window.api.proxyUpdateConfig({ enableMultiAccount: checked })
                }}
                disabled={isRunning}
              />
              <Label htmlFor="multiAccount">{isEn ? 'Multi-Account' : '多账号轮询'}</Label>
            </div>
            {/* 关闭多账号轮询时显示账号选择按钮和自动切换开关 */}
            {!config.enableMultiAccount && (
              <>
                <div className="col-span-2">
                  <Button
                    variant="outline"
                    className="w-full justify-start"
                    onClick={() => setShowAccountSelectDialog(true)}
                    disabled={isRunning}
                  >
                    <UserCheck className="h-4 w-4 mr-2" />
                    {config.selectedAccountId ? (
                      (() => {
                        const acc = accounts.get(config.selectedAccountId)
                        return acc ? (acc.email || acc.id.substring(0, 12) + '...') : (isEn ? 'First Available' : '第一个可用账号')
                      })()
                    ) : (
                      isEn ? 'First Available' : '第一个可用账号'
                    )}
                  </Button>
                </div>
                <div className="col-span-2 flex items-center gap-2">
                  <Switch
                    id="autoSwitchOnQuotaExhausted"
                    checked={config.autoSwitchOnQuotaExhausted || false}
                    onCheckedChange={(checked) => {
                      setConfig(prev => ({ ...prev, autoSwitchOnQuotaExhausted: checked }))
                      window.api.proxyUpdateConfig({ autoSwitchOnQuotaExhausted: checked })
                    }}
                    disabled={isRunning}
                  />
                  <Label htmlFor="autoSwitchOnQuotaExhausted" className="text-sm">
                    {isEn ? 'Auto-switch on quota exhausted' : '额度耗尽自动切换账号'}
                  </Label>
                </div>
              </>
            )}
            <div className="flex items-center gap-2">
              <Switch
                id="logRequests"
                checked={config.logRequests}
                onCheckedChange={(checked) => {
                  setConfig(prev => ({ ...prev, logRequests: checked }))
                  window.api.proxyUpdateConfig({ logRequests: checked })
                }}
              />
              <Label htmlFor="logRequests">{isEn ? 'Log Requests' : '记录日志'}</Label>
            </div>
          </div>

          {/* 高级配置 */}
          <div className="border-t border-border pt-4 mt-4">
            <h4 className="text-sm font-medium mb-3 text-foreground">{isEn ? 'Advanced Settings' : '高级配置'}</h4>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="preferredEndpoint">{isEn ? 'Preferred Endpoint' : '首选端点'}</Label>
                <Select
                  value={config.preferredEndpoint || ''}
                  options={[
                    { value: '', label: isEn ? 'Auto Select' : '自动选择', description: isEn ? 'Auto select based on availability' : '根据可用性自动选择端点' },
                    { value: 'codewhisperer', label: 'CodeWhisperer', description: isEn ? 'IDE mode endpoint' : 'IDE 模式端点' },
                    { value: 'amazonq', label: 'AmazonQ', description: isEn ? 'CLI mode endpoint' : 'CLI 模式端点' }
                  ]}
                  onChange={(value) => {
                    const endpoint = value as 'codewhisperer' | 'amazonq' | undefined || undefined
                    setConfig(prev => ({ ...prev, preferredEndpoint: endpoint }))
                    window.api.proxyUpdateConfig({ preferredEndpoint: endpoint })
                  }}
                  placeholder={isEn ? 'Select endpoint' : '选择端点'}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="maxRetries">{isEn ? 'Max Retries' : '最大重试次数'}</Label>
                <Input
                  id="maxRetries"
                  type="number"
                  min={0}
                  max={10}
                  value={config.maxRetries || 3}
                  onChange={(e) => {
                  const retries = parseInt(e.target.value) || 3
                  setConfig(prev => ({ ...prev, maxRetries: retries }))
                  window.api.proxyUpdateConfig({ maxRetries: retries })
                }}
                  disabled={isRunning}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="autoContinueRounds">{isEn ? 'Auto Continue Rounds' : '自动继续轮数'}</Label>
                <Input
                  id="autoContinueRounds"
                  type="number"
                  min={0}
                  max={20}
                  value={config.autoContinueRounds || 0}
                  onChange={(e) => {
                    const rounds = parseInt(e.target.value) || 0
                    setConfig(prev => ({ ...prev, autoContinueRounds: rounds }))
                    window.api.proxyUpdateConfig({ autoContinueRounds: rounds })
                  }}
                  disabled={isRunning}
                />
                <p className="text-xs text-muted-foreground">{isEn ? '0 = disabled. Auto-send "Continue" after tool calls.' : '0 = 禁用。工具调用后自动发送"继续"。'}</p>
              </div>
              <div className="space-y-2">
                <Label htmlFor="disableTools">{isEn ? 'Disable Tool Calls' : '禁用工具调用'}</Label>
                <div className="flex items-center justify-between h-9 px-3 rounded-md border border-input bg-transparent">
                  <span className="text-sm text-muted-foreground">{isEn ? 'AI will not call any tools' : 'AI 不会调用任何工具'}</span>
                  <Switch
                    id="disableTools"
                    checked={config.disableTools || false}
                    onCheckedChange={(checked) => {
                      setConfig(prev => ({ ...prev, disableTools: checked }))
                      window.api.proxyUpdateConfig({ disableTools: checked })
                    }}
                    disabled={isRunning}
                  />
                </div>
              </div>
              <div className="space-y-2">
                <Label>{isEn ? 'Model Thinking Mode' : '模型思考模式'}</Label>
                <div className="grid grid-cols-4 gap-2 px-3 py-2 rounded-md border border-input bg-transparent">
                  {['claude-sonnet-4', 'claude-sonnet-4.5', 'claude-opus-4.5', 'claude-haiku-4.5'].map(model => (
                    <div key={model} className="flex items-center gap-1.5">
                      <Switch
                        checked={(config as any).modelThinkingMode?.[model] || false}
                        onCheckedChange={(checked) => {
                          const newMode = { ...(config as any).modelThinkingMode, [model]: checked }
                          setConfig(prev => ({ ...prev, modelThinkingMode: newMode } as any))
                          window.api.proxyUpdateConfig({ modelThinkingMode: newMode } as any)
                        }}
                        disabled={isRunning}
                      />
                      <span className="text-xs truncate">{model.replace('claude-', '')}</span>
                    </div>
                  ))}
                </div>
                <p className="text-xs text-muted-foreground">{isEn ? 'Auto-enable Extended Thinking for selected models' : '为选中的模型自动启用扩展思考模式'}</p>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* 统计卡片 */}
      {isRunning && (
        <div className="grid grid-cols-6 gap-3">
          <Card className="border-0 shadow-sm hover:shadow-md transition-shadow duration-200 bg-gradient-to-br from-blue-500/5 to-transparent">
            <CardContent className="pt-3 pb-3">
              <div className="flex items-center gap-1 text-xs text-muted-foreground mb-1">
                <Users className="h-3 w-3" />
                <span>{isEn ? 'Pool' : '账号池'}</span>
              </div>
              <div className="text-xl font-bold text-foreground">{availableCount}/{accountCount}</div>
            </CardContent>
          </Card>
          <Card className="border-0 shadow-sm hover:shadow-md transition-shadow duration-200 bg-gradient-to-br from-purple-500/5 to-transparent">
            <CardContent className="pt-3 pb-3">
              <div className="flex items-center justify-between mb-1">
                <div className="flex items-center gap-1 text-xs text-muted-foreground">
                  <Activity className="h-3 w-3" />
                  <span>{isEn ? 'Total' : '总请求'}</span>
                </div>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-4 w-4 text-muted-foreground hover:text-destructive"
                  onClick={async () => {
                    await window.api.proxyResetRequestStats()
                    const result = await window.api.proxyGetStatus()
                    if (result.stats) {
                      setStats(result.stats as ProxyStats)
                    }
                    if (result.sessionStats) {
                      setSessionStats(result.sessionStats as SessionStats)
                    }
                  }}
                  title={isEn ? 'Reset Statistics' : '重置统计'}
                >
                  <RotateCcw className="h-3 w-3" />
                </Button>
              </div>
              <div className="text-xl font-bold text-foreground">{stats?.totalRequests || 0}</div>
            </CardContent>
          </Card>
          <Card className="border-0 shadow-sm hover:shadow-md transition-shadow duration-200 bg-gradient-to-br from-green-500/5 to-transparent">
            <CardContent className="pt-3 pb-3">
              <div className="flex items-center gap-1 text-xs text-muted-foreground mb-1">
                <Check className="h-3 w-3" />
                <span>{isEn ? 'Total S/F' : '总计成功/失败'}</span>
              </div>
              <div className="text-xl font-bold">
                <span className="text-green-500">{stats?.successRequests || 0}</span>
                <span className="text-muted-foreground mx-1">/</span>
                <span className="text-red-500">{stats?.failedRequests || 0}</span>
              </div>
            </CardContent>
          </Card>
          <Card className="border-0 shadow-sm hover:shadow-md transition-shadow duration-200 bg-gradient-to-br from-cyan-500/5 to-transparent">
            <CardContent className="pt-3 pb-3">
              <div className="flex items-center gap-1 text-xs text-muted-foreground mb-1">
                <Zap className="h-3 w-3" />
                <span>{isEn ? 'Session' : '本次请求'}</span>
              </div>
              <div className="text-xl font-bold text-foreground">{sessionStats?.totalRequests || 0}</div>
            </CardContent>
          </Card>
          <Card className="border-0 shadow-sm hover:shadow-md transition-shadow duration-200 bg-gradient-to-br from-orange-500/5 to-transparent">
            <CardContent className="pt-3 pb-3">
              <div className="flex items-center gap-1 text-xs text-muted-foreground mb-1">
                <Activity className="h-3 w-3" />
                <span>{isEn ? 'Session S/F' : '本次成功/失败'}</span>
              </div>
              <div className="text-xl font-bold">
                <span className="text-green-500">{sessionStats?.successRequests || 0}</span>
                <span className="text-muted-foreground mx-1">/</span>
                <span className="text-red-500">{sessionStats?.failedRequests || 0}</span>
              </div>
            </CardContent>
          </Card>
          <Card className="border-0 shadow-sm hover:shadow-md transition-shadow duration-200 bg-gradient-to-br from-primary/5 to-transparent">
            <CardContent className="pt-3 pb-3">
              <div className="flex items-center gap-1 text-xs text-muted-foreground mb-1">
                <Clock className="h-3 w-3" />
                <span>{isEn ? 'Uptime' : '运行时间'}</span>
              </div>
              <div className="text-xl font-bold text-primary whitespace-nowrap">{formatUptime(uptime)}</div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* API 端点说明 */}
      <Card className="border-0 shadow-sm hover:shadow-md transition-shadow duration-200">
        <CardHeader className="pb-2">
          <CardTitle className="text-base flex items-center gap-2">
            <div className="p-1.5 rounded-lg bg-primary/10">
              <Globe className="h-4 w-4 text-primary" />
            </div>
            {isEn ? 'API Endpoints' : 'API 端点'}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-1.5 text-sm">
          <div className="flex items-center gap-2">
            <span className="text-orange-500 w-11 flex-shrink-0 font-mono">POST</span>
            <code className="text-muted-foreground flex-1 font-mono">/v1/chat/completions</code>
            <span className="text-xs text-muted-foreground">{isEn ? 'OpenAI Compatible' : 'OpenAI 兼容'}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-orange-500 w-11 flex-shrink-0 font-mono">POST</span>
            <code className="text-muted-foreground flex-1 font-mono">/v1/messages</code>
            <span className="text-xs text-muted-foreground">{isEn ? 'Claude Compatible' : 'Claude 兼容'}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-orange-500 w-11 flex-shrink-0 font-mono">POST</span>
            <code className="text-muted-foreground flex-1 font-mono">/anthropic/v1/messages</code>
            <span className="text-xs text-muted-foreground">{isEn ? 'Claude Code' : 'Claude Code'}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-orange-500 w-11 flex-shrink-0 font-mono">POST</span>
            <code className="text-muted-foreground flex-1 font-mono">/v1/messages/count_tokens</code>
            <span className="text-xs text-muted-foreground">{isEn ? 'Token Count' : 'Token 计数'}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-green-500 w-11 flex-shrink-0 font-mono">GET</span>
            <code className="text-muted-foreground flex-1 font-mono">/v1/models</code>
            <span className="text-xs text-muted-foreground">{isEn ? 'Model List' : '模型列表'}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-green-500 w-11 flex-shrink-0 font-mono">GET</span>
            <code className="text-muted-foreground flex-1 font-mono">/health</code>
            <span className="text-xs text-muted-foreground">{isEn ? 'Health Check' : '健康检查'}</span>
          </div>
          <div className="border-t pt-2 mt-2 space-y-1.5">
            <div className="text-xs text-muted-foreground mb-1">{isEn ? 'Admin API (Requires API Key)' : '管理 API (需要 API Key)'}</div>
            <div className="flex items-center gap-2">
              <span className="text-green-500 w-11 flex-shrink-0 font-mono">GET</span>
              <code className="text-muted-foreground flex-1 font-mono">/admin/stats</code>
              <span className="text-xs text-muted-foreground">{isEn ? 'Detailed Stats' : '详细统计'}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-green-500 w-11 flex-shrink-0 font-mono">GET</span>
              <code className="text-muted-foreground flex-1 font-mono">/admin/accounts</code>
              <span className="text-xs text-muted-foreground">{isEn ? 'Account List' : '账号列表'}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-green-500 w-11 flex-shrink-0 font-mono">GET</span>
              <code className="text-muted-foreground flex-1 font-mono">/admin/logs</code>
              <span className="text-xs text-muted-foreground">{isEn ? 'Request Logs' : '请求日志'}</span>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* 最近请求日志 */}
      {recentLogs.length > 0 && (
        <Card className="border-0 shadow-sm hover:shadow-md transition-shadow duration-200">
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <CardTitle className="text-base flex items-center gap-2">
                <div className="p-1.5 rounded-lg bg-primary/10">
                  <Activity className="h-4 w-4 text-primary" />
                </div>
                {isEn ? 'Recent Requests' : '最近请求'}
              </CardTitle>
              <div className="flex items-center gap-2">
                <Badge variant="secondary" className="text-xs">{recentLogs.length}</Badge>
                <Button variant="outline" size="sm" className="h-7 text-xs" onClick={() => setShowLogsDialog(true)}>
                  <FileText className="h-3 w-3 mr-1" />
                  {isEn ? 'View All' : '查看全部'}
                </Button>
                <Button variant="outline" size="sm" className="h-7 text-xs" onClick={() => setShowDetailedLogsDialog(true)}>
                  <Activity className="h-3 w-3 mr-1" />
                  {isEn ? 'Detailed Logs' : '详细日志'}
                </Button>
              </div>
            </div>
          </CardHeader>
          <CardContent className="pt-2">
            <div className="max-h-[150px] overflow-y-auto text-xs font-mono space-y-0.5">
              {recentLogs.slice(0, 5).map((log, idx) => (
                <div key={idx} className="grid gap-2 py-1 px-2 rounded hover:bg-muted/50 items-center" style={{ gridTemplateColumns: '2fr 1.5fr 0.5fr 1fr 1fr 1fr 1fr' }}>
                  <span className="text-muted-foreground whitespace-nowrap text-left">{log.time}</span>
                  <span className="truncate text-left" title={log.path}>{log.path}</span>
                  <span className={`text-center ${log.status >= 400 ? 'text-red-500' : 'text-green-500'}`}>{log.status}</span>
                  <span className="text-muted-foreground text-right">{log.inputTokens ? log.inputTokens.toLocaleString() : '-'}</span>
                  <span className="text-muted-foreground text-right">{log.outputTokens ? log.outputTokens.toLocaleString() : '-'}</span>
                  <span className="text-muted-foreground text-right">{log.tokens ? log.tokens.toLocaleString() : '-'}</span>
                  <span className="text-muted-foreground text-right">{log.credits ? log.credits.toFixed(4) : '-'}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* 功能说明 */}
      <Card className="border-0 shadow-sm hover:shadow-md transition-shadow duration-200">
        <CardHeader className="pb-2">
          <CardTitle className="text-base flex items-center gap-2">
            <div className="p-1.5 rounded-lg bg-primary/10">
              <Zap className="h-4 w-4 text-primary" />
            </div>
            {isEn ? 'Supported Features' : '支持的功能'}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
            <div className="flex items-center gap-2">
              <span className="text-primary">✓</span>
              <span className="text-foreground">{isEn ? 'Auto Token Refresh' : 'Token 自动刷新'}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-primary">✓</span>
              <span className="text-foreground">{isEn ? 'Request Retry' : '请求重试机制'}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-primary">✓</span>
              <span className="text-foreground">{isEn ? 'Multi-Account Rotation' : '多账号轮询'}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-primary">✓</span>
              <span className="text-foreground">{isEn ? 'IDC/Social Auth' : 'IDC/Social 认证'}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-primary">✓</span>
              <span className="text-foreground">{isEn ? 'Agentic Mode Detection' : 'Agentic 模式检测'}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-primary">✓</span>
              <span className="text-foreground">{isEn ? 'Thinking Mode Support' : 'Thinking 模式支持'}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-primary">✓</span>
              <span className="text-foreground">{isEn ? 'Image Processing' : '图像处理'}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-primary">✓</span>
              <span className="text-foreground">{isEn ? 'Usage Statistics' : '使用量统计'}</span>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* 日志弹窗 */}
      <ProxyLogsDialog
        open={showLogsDialog}
        onOpenChange={setShowLogsDialog}
        logs={recentLogs}
        totalCredits={stats?.totalCredits || 0}
        totalTokens={(stats?.inputTokens || 0) + (stats?.outputTokens || 0)}
        onClearLogs={() => {
          setRecentLogs([])
          window.api.proxySaveLogs([])
        }}
        onResetCredits={async () => {
          await window.api.proxyResetCredits()
          fetchStatus()
        }}
        onResetTokens={async () => {
          await window.api.proxyResetTokens()
          fetchStatus()
        }}
        isEn={isEn}
      />

      {/* 详细日志弹窗 */}
      <ProxyDetailedLogsDialog
        open={showDetailedLogsDialog}
        onOpenChange={setShowDetailedLogsDialog}
      />

      {/* 模型列表弹窗 */}
      <ModelsDialog
        open={showModelsDialog}
        onOpenChange={setShowModelsDialog}
        isEn={isEn}
      />

      {/* 账号选择弹窗 */}
      <AccountSelectDialog
        open={showAccountSelectDialog}
        onOpenChange={setShowAccountSelectDialog}
        accounts={accounts}
        selectedAccountId={config.selectedAccountId}
        onSelect={(accountId) => {
          setConfig(prev => ({ ...prev, selectedAccountId: accountId }))
          window.api.proxyUpdateConfig({ selectedAccountIds: accountId ? [accountId] : [] })
        }}
        isEn={isEn}
      />

      {/* API Key 管理弹窗 */}
      {showApiKeyManager && createPortal(
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={() => setShowApiKeyManager(false)} />
          <div className="relative bg-background rounded-lg shadow-lg w-[600px] max-h-[80vh] overflow-y-auto p-4">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold">{isEn ? 'API Key Management' : 'API Key 管理'}</h2>
              <Button variant="ghost" size="icon" onClick={() => setShowApiKeyManager(false)}>✕</Button>
            </div>
            <ApiKeyManager />
          </div>
        </div>,
        document.body
      )}
    </div>
  )
}
