import { useState, useEffect, useCallback } from 'react'
import { Play, Square, RefreshCw, Copy, Check, Server, Users, Activity, AlertCircle, Globe, Zap, Loader2, FileText, Eye, EyeOff, Dices, Cpu } from 'lucide-react'
import { Button, Card, CardContent, CardDescription, CardHeader, CardTitle, Input, Label, Switch, Badge, Select } from '../ui'
import { useAccountsStore } from '../../store/accounts'
import { useTranslation } from '../../hooks/useTranslation'
import { ProxyLogsDialog } from './ProxyLogsDialog'
import { ModelsDialog } from './ModelsDialog'

interface ProxyStats {
  totalRequests: number
  successRequests: number
  failedRequests: number
  totalTokens: number
  startTime: number
}

interface ProxyConfig {
  enabled: boolean
  port: number
  host: string
  apiKey?: string
  enableMultiAccount: boolean
  logRequests: boolean
  maxRetries?: number
  preferredEndpoint?: 'codewhisperer' | 'amazonq'
  autoStart?: boolean
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
  const [accountCount, setAccountCount] = useState(0)
  const [availableCount, setAvailableCount] = useState(0)
  const [copied, setCopied] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [recentLogs, setRecentLogs] = useState<Array<{ time: string; path: string; status: number; tokens?: number }>>([])
  const [isSyncing, setIsSyncing] = useState(false)
  const [isRefreshingModels, setIsRefreshingModels] = useState(false)
  const [syncSuccess, setSyncSuccess] = useState(false)
  const [refreshSuccess, setRefreshSuccess] = useState(false)
  const [showLogsDialog, setShowLogsDialog] = useState(false)
  const [showModelsDialog, setShowModelsDialog] = useState(false)
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
        setConfig(result.config as ProxyConfig)
      }
      if (result.stats) {
        setStats(result.stats as ProxyStats)
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
      setRecentLogs(prev => [{
        time: new Date().toLocaleTimeString(),
        path: info.path,
        status: info.status,
        tokens: info.tokens
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
              className={isRunning ? 'bg-green-500 text-white' : 'bg-muted text-muted-foreground'}
            >
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
                onCheckedChange={(checked) => setConfig(prev => ({ ...prev, enableMultiAccount: checked }))}
                disabled={isRunning}
              />
              <Label htmlFor="multiAccount">{isEn ? 'Multi-Account' : '多账号轮询'}</Label>
            </div>
            <div className="flex items-center gap-2">
              <Switch
                id="logRequests"
                checked={config.logRequests}
                onCheckedChange={(checked) => setConfig(prev => ({ ...prev, logRequests: checked }))}
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
                  onChange={(value) => setConfig(prev => ({ 
                    ...prev, 
                    preferredEndpoint: value as 'codewhisperer' | 'amazonq' | undefined || undefined
                  }))}
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
                  onChange={(e) => setConfig(prev => ({ ...prev, maxRetries: parseInt(e.target.value) || 3 }))}
                  disabled={isRunning}
                />
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* 统计卡片 */}
      {isRunning && (
        <div className="grid grid-cols-4 gap-4">
          <Card className="border-0 shadow-sm hover:shadow-md transition-shadow duration-200 bg-gradient-to-br from-blue-500/5 to-transparent">
            <CardContent className="pt-4">
              <div className="flex items-center gap-2">
                <div className="p-1.5 rounded-lg bg-blue-500/10">
                  <Users className="h-4 w-4 text-blue-500" />
                </div>
                <span className="text-sm text-muted-foreground">{isEn ? 'Account Pool' : '账号池'}</span>
              </div>
              <div className="text-2xl font-bold text-foreground mt-1">{availableCount}/{accountCount}</div>
            </CardContent>
          </Card>
          <Card className="border-0 shadow-sm hover:shadow-md transition-shadow duration-200 bg-gradient-to-br from-purple-500/5 to-transparent">
            <CardContent className="pt-4">
              <div className="flex items-center gap-2">
                <div className="p-1.5 rounded-lg bg-purple-500/10">
                  <Activity className="h-4 w-4 text-purple-500" />
                </div>
                <span className="text-sm text-muted-foreground">{isEn ? 'Total Requests' : '总请求'}</span>
              </div>
              <div className="text-2xl font-bold text-foreground mt-1">{stats?.totalRequests || 0}</div>
            </CardContent>
          </Card>
          <Card className="border-0 shadow-sm hover:shadow-md transition-shadow duration-200">
            <CardContent className="pt-4">
              <div className="text-sm text-muted-foreground">{isEn ? 'Success/Failed' : '成功/失败'}</div>
              <div className="text-2xl font-bold mt-1">
                <span className="text-green-500">{stats?.successRequests || 0}</span>
                <span className="text-muted-foreground mx-1">/</span>
                <span className="text-red-500">{stats?.failedRequests || 0}</span>
              </div>
            </CardContent>
          </Card>
          <Card className="border-0 shadow-sm hover:shadow-md transition-shadow duration-200 bg-gradient-to-br from-primary/5 to-transparent">
            <CardContent className="pt-4">
              <div className="text-sm text-muted-foreground">{isEn ? 'Uptime' : '运行时间'}</div>
              <div className="text-2xl font-bold text-primary mt-1">{formatUptime(uptime)}</div>
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
        <CardContent className="space-y-2 text-sm">
          <div className="flex justify-between">
            <code className="text-muted-foreground">POST /v1/chat/completions</code>
            <span>{isEn ? 'OpenAI Compatible' : 'OpenAI 兼容'}</span>
          </div>
          <div className="flex justify-between">
            <code className="text-muted-foreground">POST /v1/messages</code>
            <span>{isEn ? 'Claude Compatible' : 'Claude 兼容'}</span>
          </div>
          <div className="flex justify-between">
            <code className="text-muted-foreground">POST /anthropic/v1/messages</code>
            <span>{isEn ? 'Claude Code Compatible' : 'Claude Code 兼容'}</span>
          </div>
          <div className="flex justify-between">
            <code className="text-muted-foreground">POST /v1/messages/count_tokens</code>
            <span>{isEn ? 'Token Count' : 'Token 计数'}</span>
          </div>
          <div className="flex justify-between">
            <code className="text-muted-foreground">GET /v1/models</code>
            <span>{isEn ? 'Model List' : '模型列表'}</span>
          </div>
          <div className="flex justify-between">
            <code className="text-muted-foreground">GET /health</code>
            <span>{isEn ? 'Health Check' : '健康检查'}</span>
          </div>
          <div className="border-t pt-2 mt-2">
            <div className="text-xs text-muted-foreground mb-1">{isEn ? 'Admin API (Requires API Key)' : '管理 API (需要 API Key)'}</div>
            <div className="flex justify-between">
              <code className="text-muted-foreground">GET /admin/stats</code>
              <span>{isEn ? 'Detailed Stats' : '详细统计'}</span>
            </div>
            <div className="flex justify-between">
              <code className="text-muted-foreground">GET /admin/accounts</code>
              <span>{isEn ? 'Account List' : '账号列表'}</span>
            </div>
            <div className="flex justify-between">
              <code className="text-muted-foreground">GET /admin/logs</code>
              <span>{isEn ? 'Request Logs' : '请求日志'}</span>
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
              </div>
            </div>
          </CardHeader>
          <CardContent className="pt-2">
            <div className="max-h-[150px] overflow-y-auto text-xs font-mono space-y-0.5">
              {recentLogs.slice(0, 5).map((log, idx) => (
                <div key={idx} className="flex items-center gap-3 py-1 px-2 rounded hover:bg-muted/50">
                  <span className="text-muted-foreground shrink-0">{log.time}</span>
                  <span className="truncate" title={log.path}>{log.path}</span>
                  <span className={`shrink-0 ml-auto ${log.status >= 400 ? 'text-red-500' : 'text-green-500'}`}>{log.status}</span>
                  {log.tokens ? <span className="text-muted-foreground shrink-0">{log.tokens}</span> : null}
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
        onClearLogs={() => {
          setRecentLogs([])
          window.api.proxySaveLogs([])
        }}
        isEn={isEn}
      />

      {/* 模型列表弹窗 */}
      <ModelsDialog
        open={showModelsDialog}
        onOpenChange={setShowModelsDialog}
        isEn={isEn}
      />
    </div>
  )
}
