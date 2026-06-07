import { useState, useEffect, useCallback, useRef, useMemo } from 'react'
import { Play, Square, RefreshCw, Copy, Check, Server, Activity, AlertCircle, Globe, Zap, Loader2, FileText, Eye, EyeOff, Dices, Cpu, UserCheck, RotateCcw, Users, Clock, Settings2 } from 'lucide-react'
import { Button, Card, CardContent, CardDescription, CardHeader, CardTitle, Input, Label, Switch, Badge, Select } from '../ui'
import { ProxySecurityPanel } from './ProxySecurityPanel'
import { useAccountsStore } from '../../store/accounts'
import { useTranslation } from '../../hooks/useTranslation'
import { ProxyLogsDialog } from './ProxyLogsDialog'
import { ProxyDetailedLogsDialog } from './ProxyDetailedLogsDialog'
import { ModelsDialog } from './ModelsDialog'
import { ModelMappingDialog } from './ModelMappingDialog'
import { AccountSelectDialog } from './AccountSelectDialog'
import { ApiKeyManager } from './ApiKeyManager'
import { ClientConfigDialog } from './ClientConfigDialog'
import { createPortal } from 'react-dom'

function compactNumber(n: number): string {
  if (n >= 1_000_000_000) return `${(n / 1_000_000_000).toFixed(1)}B`
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`
  if (n >= 100_000) return `${(n / 1_000).toFixed(0)}K`
  return n.toLocaleString()
}

interface ProxyStats {
  totalRequests: number
  successRequests: number
  failedRequests: number
  totalTokens: number
  totalCredits: number
  inputTokens: number
  outputTokens: number
  cacheReadTokens?: number
  cacheWriteTokens?: number
  reasoningTokens?: number
  startTime: number
}

interface SessionStats {
  totalRequests: number
  successRequests: number
  failedRequests: number
  startTime: number
}

interface ModelMappingRule {
  id: string
  name: string
  enabled: boolean
  type: 'replace' | 'alias' | 'loadbalance'
  sourceModel: string
  targetModels: string[]
  weights?: number[]
  priority: number
  apiKeyIds?: string[]
}

interface ApiKeyInfo {
  id: string
  name: string
  key: string
  enabled: boolean
}

interface ProxyConfig {
  enabled: boolean
  port: number
  host: string
  apiKey?: string
  apiKeys?: ApiKeyInfo[]
  enableMultiAccount: boolean
  selectedAccountId?: string
  logRequests: boolean
  logStreamEvents?: boolean
  maxRetries?: number
  preferredEndpoint?: 'codewhisperer' | 'amazonq' | 'amazonq-cli'
  autoStart?: boolean
  clientDrivenToolExecution?: boolean
  disableTools?: boolean
  payloadSizeLimitKB?: number
  enableTokenBufferReserve?: boolean
  tokenBufferReserve?: number
  autoSwitchOnQuotaExhausted?: boolean
  accountSelectionStrategy?: 'round-robin' | 'sticky'
  // 多账号轮询范围（与 main/proxy/types.ts 保持一致）
  multiAccountSelectionMode?: 'all' | 'groups'
  multiAccountGroupIds?: string[]
  modelMappings?: ModelMappingRule[]
  // Agent 模式 + Steering
  agentMode?: 'vibe' | 'spec'
  workspacePath?: string
  // v1.8 安全 / 限流 / 可观测
  maxRequestBodyBytes?: number
  allowedIPs?: string[]
  deniedIPs?: string[]
  allowExternalWithoutApiKey?: boolean
  rateLimitPerKeyPerMinute?: number
  sessionAffinityEnabled?: boolean
  keepAliveTimeoutMs?: number
  headersTimeoutMs?: number
  recentRequestsLimit?: number
  enableMetrics?: boolean
  fallbackPort?: number
  enableAuditLog?: boolean
}

// 反代请求日志：模块级持久化 + 单次订阅，避免切到其它页面 unmount 后日志清空、中间请求事件丢失
type RecentLogEntry = { time: string; path: string; model?: string; status: number; tokens?: number; inputTokens?: number; outputTokens?: number; cacheReadTokens?: number; reasoningTokens?: number; credits?: number; responseTime?: number; error?: string }
let _proxyRecentLogs: RecentLogEntry[] = []
let _refSetProxyRecentLogs: ((v: RecentLogEntry[]) => void) | null = null
let _proxyResponseListenerRegistered = false
function ensureProxyResponseListenerRegistered(): void {
  if (_proxyResponseListenerRegistered) return
  _proxyResponseListenerRegistered = true
  window.api.onProxyResponse((info) => {
    const now = new Date()
    const year = now.getFullYear()
    const month = (now.getMonth() + 1).toString().padStart(2, '0')
    const day = now.getDate().toString().padStart(2, '0')
    const hours = now.getHours().toString().padStart(2, '0')
    const minutes = now.getMinutes().toString().padStart(2, '0')
    const seconds = now.getSeconds().toString().padStart(2, '0')
    const ms = now.getMilliseconds().toString().padStart(3, '0')
    const fullTime = `${year}-${month}-${day} ${hours}:${minutes}:${seconds}.${ms}`
    _proxyRecentLogs = [{
      time: fullTime,
      path: info.path,
      model: info.model,
      status: info.status,
      tokens: info.tokens,
      inputTokens: info.inputTokens,
      outputTokens: info.outputTokens,
      cacheReadTokens: info.cacheReadTokens,
      reasoningTokens: info.reasoningTokens,
      credits: info.credits,
      responseTime: info.responseTime,
      error: info.error
    }, ..._proxyRecentLogs.slice(0, 99)]
    _refSetProxyRecentLogs?.(_proxyRecentLogs)
  })
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
    logRequests: true,
    clientDrivenToolExecution: true
  })
  const [stats, setStats] = useState<ProxyStats | null>(null)
  const [sessionStats, setSessionStats] = useState<SessionStats | null>(null)
  const [accountCount, setAccountCount] = useState(0)
  const [availableCount, setAvailableCount] = useState(0)
  const [copied, setCopied] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [recentLogs, setRecentLogs] = useState<RecentLogEntry[]>(_proxyRecentLogs)
  const [isSyncing, setIsSyncing] = useState(false)
  const [isRefreshingModels, setIsRefreshingModels] = useState(false)
  const [syncSuccess, setSyncSuccess] = useState(false)
  const [refreshSuccess, setRefreshSuccess] = useState(false)
  const [showLogsDialog, setShowLogsDialog] = useState(false)
  const [showDetailedLogsDialog, setShowDetailedLogsDialog] = useState(false)
  const [showModelsDialog, setShowModelsDialog] = useState(false)
  const [showClientConfigDialog, setShowClientConfigDialog] = useState(false)
  const [showModelMappingDialog, setShowModelMappingDialog] = useState(false)
  const [availableModels, setAvailableModels] = useState<Array<{ id: string; name: string }>>([])
  const [showAccountSelectDialog, setShowAccountSelectDialog] = useState(false)
  const [showApiKeyManager, setShowApiKeyManager] = useState(false)
  const [showApiKey, setShowApiKey] = useState(false)
  const [apiKeyFormat, setApiKeyFormat] = useState<'sk' | 'simple' | 'token'>('sk')
  const [apiKeyCopied, setApiKeyCopied] = useState(false)
  const [apiKeyGenerated, setApiKeyGenerated] = useState(false)

  const accounts = useAccountsStore(state => state.accounts)
  const groups = useAccountsStore(state => state.groups)

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
        const clientDrivenToolExecution = cfg.clientDrivenToolExecution !== false
        setConfig({
          ...cfg,
          clientDrivenToolExecution
        })
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

  const loadAvailableModels = useCallback(async () => {
    try {
      const result = await window.api.proxyGetModels()
      if (result.success && result.models) {
        setAvailableModels(result.models.map((m: { id: string; name?: string }) => ({ id: m.id, name: m.name || m.id })))
      }
    } catch {
    }
  }, [])

  // 同步账号到反代池
  // override 用于「改了分组配置立即重同步」场景：setConfig 后闭包里的 config 可能是旧值，
  // 调用方传入新模式 / 新分组 ids，强制覆盖。
  const syncAccounts = useCallback(async (override?: {
    mode?: 'all' | 'groups'
    groupIds?: string[]
  }) => {
    setIsSyncing(true)
    setSyncSuccess(false)
    try {
      const selMode = override?.mode ?? config.multiAccountSelectionMode ?? 'all'
      const selGroupIds = override?.groupIds ?? config.multiAccountGroupIds ?? []
      let candidates = Array.from(accounts.values())
        .filter(acc => acc.status === 'active' && acc.credentials?.accessToken)

      // 多账号轮询 + 'groups' 范围：按选中分组过滤（'__ungrouped__' 表示未分组账号）
      if (config.enableMultiAccount && selMode === 'groups') {
        const gids = new Set(selGroupIds)
        candidates = candidates.filter(acc => {
          if (!acc.groupId) return gids.has('__ungrouped__')
          return gids.has(acc.groupId)
        })
      }

      const proxyAccounts = candidates.map(acc => ({
          id: acc.id,
          email: acc.email,
          accessToken: acc.credentials.accessToken,
          refreshToken: acc.credentials?.refreshToken,
          profileArn: acc.profileArn || acc.credentials?.profileArn,
          expiresAt: acc.credentials?.expiresAt,
          machineId: acc.machineId,
          // Token 刷新所需字段
          clientId: acc.credentials?.clientId,
          clientSecret: acc.credentials?.clientSecret,
          region: acc.credentials?.region || 'us-east-1',
          authMethod: acc.credentials?.authMethod,
          provider: acc.credentials?.provider || acc.idp,
          // 透传分组 ID：后端 getAvailableAccount 可据此做二次过滤（双保险），即便前端忘了重同步也安全
          groupId: acc.groupId
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
  }, [accounts, fetchStatus, config.enableMultiAccount, config.multiAccountSelectionMode, config.multiAccountGroupIds])

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
        logRequests: config.logRequests,
        clientDrivenToolExecution: config.clientDrivenToolExecution !== false,
        disableTools: config.disableTools
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

  // 复制地址（0.0.0.0 对人不可读，复制为 localhost）
  const copyAddress = () => {
    const displayHost = config.host === '0.0.0.0' ? 'localhost' : config.host
    const address = `http://${displayHost}:${config.port}`
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
        await loadAvailableModels()
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
    loadAvailableModels()

    // 监听事件
    const unsubRequest = window.api.onProxyRequest((info) => {
      console.log('[Proxy] Request:', info)
    })

    // onProxyResponse：模块级单次订阅；这里只注册 setter 通道 + 拉取请求触发统计刷新
    ensureProxyResponseListenerRegistered()
    _refSetProxyRecentLogs = setRecentLogs
    // 触发一次统计刷新即可（统计有独立的 fetchStatus，不依赖订阅）
    const unsubStatsHook = window.api.onProxyResponse(() => { fetchStatus() })

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
      unsubStatsHook()
      unsubError()
      unsubStatus()
      _refSetProxyRecentLogs = null
    }
  }, [fetchStatus, loadAvailableModels])

  // 用 ref 持有最新的 syncAccounts，避免把它放进下方 effect 依赖导致循环重触发
  const syncAccountsRef = useRef(syncAccounts)
  useEffect(() => { syncAccountsRef.current = syncAccounts }, [syncAccounts])

  /**
   * 账号集合签名：只反映"参与同步的账号 id + 分组"，**不含** token / 用量 / 状态时间戳。
   * 这样后台 token 刷新、用量更新等高频变动不会触发重新同步（避免按钮疯狂闪烁），
   * 仅在真正增删账号 / 改分组时才同步。token 更新由主进程账号池自身刷新逻辑处理。
   */
  const accountsSyncSignature = useMemo(() => {
    return Array.from(accounts.values())
      .filter(a => a.status === 'active' && a.credentials?.accessToken)
      .map(a => `${a.id}:${a.groupId || ''}`)
      .sort()
      .join('|')
  }, [accounts])

  // 账号集合变化时同步（防抖 600ms + 仅签名变化才触发；跳过首次 mount 避免每次进页面都同步）
  const syncMountedRef = useRef(false)
  useEffect(() => {
    if (!isRunning) return
    if (!syncMountedRef.current) {
      syncMountedRef.current = true
      return
    }
    const timer = setTimeout(() => { void syncAccountsRef.current() }, 600)
    return () => clearTimeout(timer)
  }, [accountsSyncSignature, isRunning])

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
      <Card className="hover-lift relative z-10">
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
                ? 'bg-success text-white flex items-center gap-1.5 pr-2.5' 
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
            <Button onClick={() => void syncAccounts()} variant="outline" className="gap-2" disabled={!isRunning || isSyncing}>
              {isSyncing ? <Loader2 className="h-4 w-4 animate-spin" /> : syncSuccess ? <Check className="h-4 w-4 text-success" /> : <RefreshCw className="h-4 w-4" />}
              {isSyncing ? (isEn ? 'Syncing...' : '同步中...') : syncSuccess ? (isEn ? 'Synced!' : '已同步') : (isEn ? 'Sync Accounts' : '同步账号')}
            </Button>
            <Button onClick={handleRefreshModels} variant="outline" className="gap-2" disabled={!isRunning || isRefreshingModels}>
              {isRefreshingModels ? <Loader2 className="h-4 w-4 animate-spin" /> : refreshSuccess ? <Check className="h-4 w-4 text-success" /> : <RefreshCw className="h-4 w-4" />}
              {isRefreshingModels ? (isEn ? 'Refreshing...' : '刷新中...') : refreshSuccess ? (isEn ? 'Refreshed!' : '已刷新') : (isEn ? 'Refresh Models' : '刷新模型')}
            </Button>
            <Button onClick={() => setShowModelsDialog(true)} variant="outline" className="gap-2" disabled={!isRunning}>
              <Cpu className="h-4 w-4" />
              {isEn ? 'View Models' : '查看模型'}
            </Button>
            <Button onClick={() => setShowClientConfigDialog(true)} variant="outline" className="gap-2">
              <Settings2 className="h-4 w-4" />
              {isEn ? 'Configure Clients' : '一键配置'}
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
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <Label className="min-w-[80px]">{isEn ? 'Address:' : '服务地址:'}</Label>
                <code className="flex-1 px-3 py-2 bg-muted rounded text-sm">
                  http://{config.host === '0.0.0.0' ? 'localhost' : config.host}:{config.port}
                </code>
                <Button variant="outline" size="icon" onClick={copyAddress}>
                  {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                </Button>
              </div>
              {config.host === '0.0.0.0' && (
                <p className="text-xs text-muted-foreground pl-[88px]">
                  {isEn
                    ? `LAN devices use http://<this-machine-IP>:${config.port}`
                    : `局域网设备请使用 http://<本机IP>:${config.port}`}
                </p>
              )}
            </div>
          )}

          {/* 基础配置 — 4 列紧凑布局：端口 + 监听 + API Key + 格式选择 */}
          <div className="grid grid-cols-12 gap-3">
            <div className="col-span-2 space-y-1.5">
              <Label htmlFor="port" className="text-xs">{isEn ? 'Port' : '端口'}</Label>
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
                className="h-9"
              />
            </div>
            <div className="col-span-3 space-y-1.5">
              <div className="flex items-center justify-between">
                <Label htmlFor="host" className="text-xs" title={config.host === '0.0.0.0' ? (isEn ? 'LAN access enabled. Set an API Key and allow port through firewall.' : '已开启外网访问，建议设置 API Key + 防火墙放行端口') : (isEn ? 'Loopback only. Toggle Public for LAN access.' : '仅本机访问，开启「外网」可让局域网设备访问')}>{isEn ? 'Host' : '监听地址'}</Label>
                <div className="flex items-center gap-1">
                  <Switch
                    id="publicAccess"
                    checked={config.host === '0.0.0.0'}
                    onCheckedChange={async (checked) => {
                      const newHost = checked ? '0.0.0.0' : '127.0.0.1'
                      setConfig(prev => ({ ...prev, host: newHost }))
                      await window.api.proxyUpdateConfig({ host: newHost })
                      if (isRunning) {
                        try {
                          await window.api.proxyStop()
                          await new Promise(r => setTimeout(r, 200))
                          await window.api.proxyStart()
                        } catch (err) {
                          console.error('[Proxy] Failed to restart after host change:', err)
                          setError(err instanceof Error ? err.message : String(err))
                        }
                      }
                    }}
                    className="scale-75"
                  />
                  <Label htmlFor="publicAccess" className="text-[10px] cursor-pointer">{isEn ? 'Public' : '外网'}</Label>
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
                className={`h-9 ${config.host === '0.0.0.0' ? 'border-warning/50' : ''}`}
              />
            </div>
            {/* API Key 区：占 7 列 */}
            <div className="col-span-7 space-y-1.5">
              <div className="flex items-center justify-between">
                <Label htmlFor="apiKey" className="text-xs" title={isEn ? 'When set, requests must provide this key in Authorization or X-Api-Key header' : '设置后，请求需在 Authorization 或 X-Api-Key 头中提供此密钥'}>{isEn ? 'API Key (Optional)' : 'API Key (可选)'}</Label>
                <div className="flex items-center gap-1">
                  <Select
                    value={apiKeyFormat}
                    options={[
                      { value: 'sk', label: 'sk-xxx' },
                      { value: 'simple', label: 'PROXY_KEY' },
                      { value: 'token', label: 'KEY:TOKEN' }
                    ]}
                    onChange={(v) => setApiKeyFormat(v as 'sk' | 'simple' | 'token')}
                    className="w-[120px] h-7 text-xs [&>button]:h-7 [&>button]:py-0 [&>button]:px-2.5"
                  />
                  <Button variant="ghost" size="icon" className="h-7 w-7" onClick={generateApiKey} disabled={isRunning} title={isEn ? 'Generate' : '随机生成'}>
                    {apiKeyGenerated ? <Check className="h-3.5 w-3.5 text-success" /> : <Dices className="h-3.5 w-3.5" />}
                  </Button>
                  {config.apiKey && (
                    <Button variant="ghost" size="icon" className="h-7 w-7" onClick={copyApiKey} title={isEn ? 'Copy' : '复制'}>
                      {apiKeyCopied ? <Check className="h-3.5 w-3.5 text-success" /> : <Copy className="h-3.5 w-3.5" />}
                    </Button>
                  )}
                  <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => setShowApiKeyManager(true)} title={isEn ? 'Manage Multiple API Keys' : '管理多个 API Key'}>
                    <Settings2 className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </div>
              <div className="relative">
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
                  className="pr-9 h-9"
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="absolute right-0 top-0 h-full px-2.5 hover:bg-transparent"
                  onClick={() => setShowApiKey(!showApiKey)}
                  title={showApiKey ? (isEn ? 'Hide' : '隐藏') : (isEn ? 'Show' : '显示')}
                >
                  {showApiKey ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                </Button>
              </div>
            </div>
          </div>


          {/* 运行模式开关区 — 网格化对齐，避免 flex-wrap 造成的凌乱布局 */}
          <div className="grid grid-cols-3 gap-x-4 gap-y-3 items-center">
            <div className="flex items-center gap-2">
              <Switch
                id="autoStart"
                checked={config.autoStart || false}
                onCheckedChange={(checked) => {
                  setConfig(prev => ({ ...prev, autoStart: checked }))
                  window.api.proxyUpdateConfig({ autoStart: checked })
                }}
              />
              <Label htmlFor="autoStart" className="text-sm cursor-pointer">{isEn ? 'Auto Start' : '随软件启动'}</Label>
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
              <Label htmlFor="multiAccount" className="text-sm cursor-pointer">{isEn ? 'Multi-Account' : '多账号轮询'}</Label>
            </div>
            {/* 开启多账号轮询时显示策略选择 */}
            {config.enableMultiAccount && (
              <div className="col-span-2 flex items-center gap-2">
                <Label className="text-sm shrink-0">
                  {isEn ? 'Strategy' : '选择策略'}:
                </Label>
                <div className="flex gap-1 bg-muted/30 rounded-lg p-0.5">
                  {(['round-robin', 'sticky'] as const).map(strategy => {
                    const active = (config.accountSelectionStrategy || 'round-robin') === strategy
                    const labelEn = strategy === 'round-robin' ? 'Round-Robin' : 'Sticky'
                    const labelZh = strategy === 'round-robin' ? '轮询' : '粘滞'
                    return (
                      <button
                        key={strategy}
                        type="button"
                        disabled={isRunning}
                        className={`px-3 py-1 rounded-md text-xs font-medium transition-all ${
                          active
                            ? 'bg-primary text-primary-foreground shadow-sm'
                            : 'text-muted-foreground hover:text-foreground hover:bg-muted/50'
                        } disabled:opacity-50 disabled:cursor-not-allowed`}
                        onClick={() => {
                          setConfig(prev => ({ ...prev, accountSelectionStrategy: strategy }))
                          window.api.proxyUpdateConfig({ accountSelectionStrategy: strategy })
                        }}
                      >
                        {isEn ? labelEn : labelZh}
                      </button>
                    )
                  })}
                </div>
                <span className="text-xs text-muted-foreground">
                  {(config.accountSelectionStrategy || 'round-robin') === 'round-robin'
                    ? (isEn ? 'Each request rotates to next account (load balanced)' : '每次请求轮询到下一个账号（负载均衡）')
                    : (isEn ? 'Stay on success account until failure (preserves prompt cache)' : '成功后粘住该账号直到失败（保留 prompt cache）')}
                </span>
              </div>
            )}
            {/* 多账号轮询范围：全部账号 / 指定分组 */}
            {config.enableMultiAccount && (() => {
              const selMode = config.multiAccountSelectionMode || 'all'
              const selectedGids = new Set(config.multiAccountGroupIds || [])
              const sortedGroups = Array.from(groups.values()).sort((a, b) => (a.order ?? 0) - (b.order ?? 0))
              const accountList = Array.from(accounts.values()).filter(a => a.status === 'active' && a.credentials?.accessToken)
              const ungroupedCount = accountList.filter(a => !a.groupId).length
              const countByGroup = new Map<string, number>()
              for (const a of accountList) if (a.groupId) countByGroup.set(a.groupId, (countByGroup.get(a.groupId) || 0) + 1)
              const selectedAccountTotal = selMode === 'all'
                ? accountList.length
                : accountList.filter(a => !a.groupId ? selectedGids.has('__ungrouped__') : selectedGids.has(a.groupId)).length
              const toggleGid = (gid: string) => {
                const next = new Set(selectedGids)
                if (next.has(gid)) next.delete(gid); else next.add(gid)
                const ids = Array.from(next)
                setConfig(prev => ({ ...prev, multiAccountGroupIds: ids }))
                window.api.proxyUpdateConfig({ multiAccountGroupIds: ids })
                // 关键：立即用新分组 ids 重新同步账号池，避免「改了分组但反代仍用旧账号」的体感 bug
                void syncAccounts({ mode: 'groups', groupIds: ids })
              }
              return (
                <div className="col-span-2 flex flex-col gap-2">
                  <div className="flex items-center gap-2 flex-wrap">
                    <Label className="text-sm shrink-0">{isEn ? 'Scope' : '轮询范围'}:</Label>
                    <div className="flex gap-1 bg-muted/30 rounded-lg p-0.5">
                      {(['all', 'groups'] as const).map(mode => {
                        const active = selMode === mode
                        const label = mode === 'all'
                          ? (isEn ? 'All Accounts' : '全部账号')
                          : (isEn ? 'Specific Groups' : '指定分组')
                        return (
                          <button
                            key={mode}
                            type="button"
                            disabled={isRunning}
                            className={`px-3 py-1 rounded-md text-xs font-medium transition-all ${
                              active ? 'bg-primary text-primary-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground hover:bg-muted/50'
                            } disabled:opacity-50 disabled:cursor-not-allowed`}
                            onClick={() => {
                              setConfig(prev => ({ ...prev, multiAccountSelectionMode: mode }))
                              window.api.proxyUpdateConfig({ multiAccountSelectionMode: mode })
                              // 关键：切换 all/groups 立即重新同步账号池
                              void syncAccounts({ mode, groupIds: Array.from(selectedGids) })
                            }}
                          >
                            {label}
                          </button>
                        )
                      })}
                    </div>
                    <span className="text-xs text-muted-foreground">
                      {selMode === 'all'
                        ? (isEn ? `${selectedAccountTotal} active accounts` : `${selectedAccountTotal} 个活跃账号`)
                        : (isEn ? `${selectedAccountTotal} accounts in selected groups` : `已选分组共 ${selectedAccountTotal} 个账号`)}
                    </span>
                  </div>

                  {/* 分组多选 chip：仅 groups 模式 */}
                  {selMode === 'groups' && (
                    <div className="flex flex-wrap items-center gap-1.5 pl-[60px]">
                      {/* 未分组特殊 chip */}
                      <button
                        type="button"
                        disabled={isRunning}
                        onClick={() => toggleGid('__ungrouped__')}
                        className={`flex items-center gap-1 px-2 h-7 rounded-md text-xs font-medium border transition-all ${
                          selectedGids.has('__ungrouped__')
                            ? 'bg-muted text-foreground border-muted-foreground/30'
                            : 'bg-background text-muted-foreground border-border hover:text-foreground hover:border-primary/40'
                        } disabled:opacity-50 disabled:cursor-not-allowed`}
                      >
                        {selectedGids.has('__ungrouped__') && <Check className="h-3 w-3" />}
                        <span>{isEn ? 'Ungrouped' : '未分组'}</span>
                        <span className="text-[10px] opacity-70">({ungroupedCount})</span>
                      </button>
                      {/* 用户分组 chips */}
                      {sortedGroups.map(group => {
                        const isSel = selectedGids.has(group.id)
                        const count = countByGroup.get(group.id) || 0
                        return (
                          <button
                            key={group.id}
                            type="button"
                            disabled={isRunning}
                            onClick={() => toggleGid(group.id)}
                            className={`flex items-center gap-1 px-2 h-7 rounded-md text-xs font-medium border transition-all ${
                              isSel ? 'text-foreground' : 'bg-background text-muted-foreground border-border hover:text-foreground hover:border-primary/40'
                            } disabled:opacity-50 disabled:cursor-not-allowed`}
                            style={isSel ? {
                              backgroundColor: (group.color || '#888') + '22',
                              borderColor: (group.color || '#888') + '66'
                            } : undefined}
                          >
                            {isSel && <Check className="h-3 w-3" style={{ color: group.color || undefined }} />}
                            <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: group.color || '#888' }} />
                            <span>{group.name}</span>
                            <span className="text-[10px] opacity-70">({count})</span>
                          </button>
                        )
                      })}
                      {sortedGroups.length === 0 && (
                        <span className="text-xs text-muted-foreground italic">
                          {isEn ? 'No groups defined yet. Create groups in Account Manager first.' : '尚未定义任何分组，请先在账户管理中创建分组'}
                        </span>
                      )}
                    </div>
                  )}
                </div>
              )
            })()}
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
                <div className="flex items-center gap-2">
                  <Switch
                    id="autoSwitchOnQuotaExhausted"
                    checked={config.autoSwitchOnQuotaExhausted || false}
                    onCheckedChange={(checked) => {
                      setConfig(prev => ({ ...prev, autoSwitchOnQuotaExhausted: checked }))
                      window.api.proxyUpdateConfig({ autoSwitchOnQuotaExhausted: checked })
                    }}
                    disabled={isRunning}
                  />
                  <Label htmlFor="autoSwitchOnQuotaExhausted" className="text-sm cursor-pointer truncate" title={isEn ? 'Auto-switch on quota exhausted' : '额度耗尽自动切换账号'}>
                    {isEn ? 'Auto-switch' : '额度切换'}
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
              <Label htmlFor="logRequests" className="text-sm cursor-pointer">{isEn ? 'Log Requests' : '记录日志'}</Label>
            </div>
            <div className="flex items-center gap-2">
              <Switch
                id="logStreamEvents"
                checked={config.logStreamEvents || false}
                onCheckedChange={(checked) => {
                  setConfig(prev => ({ ...prev, logStreamEvents: checked }))
                  window.api.proxyUpdateConfig({ logStreamEvents: checked })
                }}
              />
              <Label htmlFor="logStreamEvents" className="text-sm cursor-pointer">{isEn ? 'Stream Events' : '流式日志'}</Label>
            </div>
          </div>

          {/* 高级配置 — 3 列紧凑布局，描述移到 Label 的 title tooltip */}
          <div className="border-t border-border pt-3 overflow-visible">
            <h4 className="text-xs font-medium mb-2 text-muted-foreground uppercase tracking-wider flex items-center gap-1.5">
              <Settings2 className="h-3.5 w-3.5" />
              {isEn ? 'Advanced Settings' : '高级配置'}
            </h4>
            <div className="grid grid-cols-3 gap-x-3 gap-y-3 items-start overflow-visible">
              <div className="space-y-1.5 relative z-20">
                <Label htmlFor="preferredEndpoint" className="text-xs">{isEn ? 'Preferred Endpoint' : '首选端点'}</Label>
                <Select
                  value={config.preferredEndpoint || ''}
                  options={[
                    { value: '', label: isEn ? 'Auto Select' : '自动选择', description: isEn ? 'Auto select based on availability' : '根据可用性自动选择端点' },
                    { value: 'codewhisperer', label: 'CodeWhisperer', description: isEn ? 'IDE mode endpoint' : 'IDE 模式端点' },
                    { value: 'amazonq', label: 'AmazonQ', description: isEn ? 'IDE mode (q.amazonaws.com)' : 'IDE 模式 (q.amazonaws.com)' },
                    { value: 'amazonq-cli', label: 'AmazonQ CLI', description: isEn ? 'CLI mode (SendMessageStreaming)' : 'CLI 模式 (SendMessageStreaming)' }
                  ]}
                  onChange={(value) => {
                    const endpoint = (value || undefined) as 'codewhisperer' | 'amazonq' | 'amazonq-cli' | undefined
                    setConfig(prev => ({ ...prev, preferredEndpoint: endpoint }))
                    window.api.proxyUpdateConfig({ preferredEndpoint: endpoint })
                  }}
                  placeholder={isEn ? 'Select endpoint' : '选择端点'}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="maxRetries" className="text-xs">{isEn ? 'Max Retries' : '最大重试次数'}</Label>
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
                  className="h-9"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="payloadSizeLimit" className="text-xs" title={isEn ? 'When payload exceeds this limit, oldest tool results will be truncated. Default 1536KB (1.5MB).' : '超过此限制时，最旧工具结果将被截断。默认 1536KB (1.5MB)'}>{isEn ? 'Payload (KB)' : 'Payload (KB)'}</Label>
                <Input
                  id="payloadSizeLimit"
                  type="number"
                  min={256}
                  max={204800}
                  step={1024}
                  value={config.payloadSizeLimitKB || 153600}
                  onChange={(e) => {
                    const kb = parseInt(e.target.value) || 153600
                    setConfig(prev => ({ ...prev, payloadSizeLimitKB: kb }))
                    window.api.proxyUpdateConfig({ payloadSizeLimitKB: kb })
                  }}
                  disabled={isRunning}
                  className="h-9"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="clientDrivenToolExecution" className="text-xs" title={isEn ? 'Recommended for OpenCode and Claude Code. Disable only when the proxy should fabricate tool results.' : '推荐用于 OpenCode 和 Claude Code。仅在需要代理伪造工具结果时关闭。'}>{isEn ? 'Tool Execution' : '工具执行模式'}</Label>
                <div className="flex items-center justify-between h-9 px-3 rounded-md border border-input bg-transparent">
                  <span className="text-xs text-muted-foreground">{isEn ? 'Client-driven' : '客户端驱动'}</span>
                  <Switch
                    id="clientDrivenToolExecution"
                    checked={config.clientDrivenToolExecution !== false}
                    onCheckedChange={(checked) => {
                      setConfig(prev => ({ ...prev, clientDrivenToolExecution: checked }))
                      window.api.proxyUpdateConfig({ clientDrivenToolExecution: checked })
                    }}
                    disabled={isRunning}
                    className="scale-90"
                  />
                </div>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="disableTools" className="text-xs" title={isEn ? 'When enabled, the proxy strips all tool definitions from requests.' : '启用后代理会从请求中移除所有工具定义，适用于纯聊天。'}>{isEn ? 'Disable Tools' : '禁用工具调用'}</Label>
                <div className="flex items-center justify-between h-9 px-3 rounded-md border border-input bg-transparent">
                  <span className="text-xs text-muted-foreground">{isEn ? 'No tool calls' : '不调用工具'}</span>
                  <Switch
                    id="disableTools"
                    checked={config.disableTools || false}
                    onCheckedChange={(checked) => {
                      setConfig(prev => ({ ...prev, disableTools: checked }))
                      window.api.proxyUpdateConfig({ disableTools: checked })
                    }}
                    disabled={isRunning}
                    className="scale-90"
                  />
                </div>
              </div>
              {/* Token Buffer Reserve — 占 3 列合为一行：开关 + 输入 */}
              <div className="col-span-3 space-y-1.5">
                <Label htmlFor="tokenBufferReserve" className="text-xs" title={isEn ? 'When enabled, reserves N tokens below context window for trim (e.g. 200K → trim at 180K). When disabled, never trims.' : '启用后从模型 context window 预留 N 个 token 作为裁剪阈值（例：200K → 180K 裁剪）。关闭时不裁剪任何旧消息。'}>{isEn ? 'Token Buffer Reserve (auto-trim history)' : 'Token Buffer 预留 (自动裁旧 history)'}</Label>
                <div className="flex items-center gap-2">
                  <div className="flex items-center justify-between h-9 px-3 rounded-md border border-input bg-transparent w-[160px] flex-shrink-0">
                    <span className="text-xs text-muted-foreground">{isEn ? 'Auto-trim' : '启用裁剪'}</span>
                    <Switch
                      id="enableTokenBufferReserve"
                      checked={config.enableTokenBufferReserve || false}
                      onCheckedChange={(checked) => {
                        setConfig(prev => ({ ...prev, enableTokenBufferReserve: checked }))
                        window.api.proxyUpdateConfig({ enableTokenBufferReserve: checked })
                      }}
                      disabled={isRunning}
                      className="scale-90"
                    />
                  </div>
                  <Input
                    id="tokenBufferReserve"
                    type="number"
                    min={5000}
                    max={150000}
                    step={1000}
                    value={config.tokenBufferReserve || 20000}
                    onChange={(e) => {
                      const tokens = parseInt(e.target.value) || 20000
                      setConfig(prev => ({ ...prev, tokenBufferReserve: tokens }))
                      window.api.proxyUpdateConfig({ tokenBufferReserve: tokens })
                    }}
                    disabled={isRunning || !config.enableTokenBufferReserve}
                    placeholder={isEn ? 'Reserve tokens (default 20000)' : '预留 token 数（默认 20000）'}
                    className="h-9 flex-1"
                  />
                </div>
              </div>
              {/* Agent Mode + Workspace Path（Steering 文件注入） */}
              <div className="col-span-3 grid grid-cols-3 gap-x-3 items-end">
                <div className="space-y-1.5">
                  <Label className="text-xs" title={isEn ? 'Agent mode sent to Kiro backend. Vibe=chat-first, Spec=plan-first.' : 'Kiro 后端 Agent 模式。Vibe=对话优先，Spec=计划优先。'}>{isEn ? 'Agent Mode' : 'Agent 模式'}</Label>
                  <Select
                    value={config.agentMode || 'vibe'}
                    options={[
                      { value: 'vibe', label: 'Vibe', description: isEn ? 'Chat first, then build' : '对话优先，边聊边做' },
                      { value: 'spec', label: 'Spec', description: isEn ? 'Plan first, then build' : '先规划后执行' }
                    ]}
                    onChange={(value) => {
                      const mode = value as 'vibe' | 'spec'
                      setConfig(prev => ({ ...prev, agentMode: mode }))
                      window.api.proxyUpdateConfig({ agentMode: mode })
                    }}
                    placeholder={isEn ? 'Select mode' : '选择模式'}
                  />
                </div>
                <div className="col-span-2 space-y-1.5">
                  <Label className="text-xs" title={isEn ? 'Workspace path for loading .kiro/steering/*.md rules into system prompt' : '工作区路径，用于加载 .kiro/steering/*.md 规则注入到 system prompt'}>{isEn ? 'Workspace Path (Steering)' : '工作区路径 (Steering)'}</Label>
                  <Input
                    value={config.workspacePath || ''}
                    onChange={(e) => {
                      const p = e.target.value
                      setConfig(prev => ({ ...prev, workspacePath: p || undefined }))
                    }}
                    onBlur={() => {
                      window.api.proxyUpdateConfig({ workspacePath: config.workspacePath || undefined })
                    }}
                    placeholder={isEn ? 'e.g. C:/Projects/my-app (optional)' : '如 C:/Projects/my-app（可选）'}
                    className="h-9"
                  />
                </div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* v1.8 反代安全 / 可观测设置（独立卡片，可折叠） */}
      <ProxySecurityPanel
        config={config as unknown as Parameters<typeof ProxySecurityPanel>[0]['config']}
        setConfig={setConfig as unknown as Parameters<typeof ProxySecurityPanel>[0]['setConfig']}
        isRunning={isRunning}
        isEn={isEn}
      />

      {/* 统计卡片 */}
      {isRunning && (
        <div className="grid grid-cols-6 gap-3">
          <Card className="hover-lift bg-gradient-to-br from-blue-500/5 to-transparent">
            <CardContent className="pt-3 pb-3">
              <div className="flex items-center gap-1 text-xs text-muted-foreground mb-1">
                <Users className="h-3 w-3" />
                <span>{isEn ? 'Pool' : '账号池'}</span>
              </div>
              <div className="text-xl font-bold text-foreground">{availableCount}/{accountCount}</div>
            </CardContent>
          </Card>
          <Card className="hover-lift bg-gradient-to-br from-purple-500/5 to-transparent">
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
          <Card className="hover-lift bg-gradient-to-br from-green-500/5 to-transparent">
            <CardContent className="pt-3 pb-3">
              <div className="flex items-center gap-1 text-xs text-muted-foreground mb-1">
                <Check className="h-3 w-3" />
                <span>{isEn ? 'Total S/F' : '总计成功/失败'}</span>
              </div>
              <div className="text-xl font-bold">
                <span className="text-success">{stats?.successRequests || 0}</span>
                <span className="text-muted-foreground mx-1">/</span>
                <span className="text-destructive">{stats?.failedRequests || 0}</span>
              </div>
            </CardContent>
          </Card>
          <Card className="hover-lift bg-gradient-to-br from-cyan-500/5 to-transparent">
            <CardContent className="pt-3 pb-3">
              <div className="flex items-center gap-1 text-xs text-muted-foreground mb-1">
                <Zap className="h-3 w-3" />
                <span>{isEn ? 'Session' : '本次请求'}</span>
              </div>
              <div className="text-xl font-bold text-foreground">{sessionStats?.totalRequests || 0}</div>
            </CardContent>
          </Card>
          <Card className="hover-lift bg-gradient-to-br from-orange-500/5 to-transparent">
            <CardContent className="pt-3 pb-3">
              <div className="flex items-center gap-1 text-xs text-muted-foreground mb-1">
                <Activity className="h-3 w-3" />
                <span>{isEn ? 'Session S/F' : '本次成功/失败'}</span>
              </div>
              <div className="text-xl font-bold">
                <span className="text-success">{sessionStats?.successRequests || 0}</span>
                <span className="text-muted-foreground mx-1">/</span>
                <span className="text-destructive">{sessionStats?.failedRequests || 0}</span>
              </div>
            </CardContent>
          </Card>
          <Card className="hover-lift bg-gradient-to-br from-primary/5 to-transparent">
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

      {/* 第二行统计卡片 - Token 分解和 Cache */}
      {isRunning && stats && (
        <div className="grid grid-cols-6 gap-3">
          <Card className="hover-lift bg-gradient-to-br from-indigo-500/5 to-transparent">
            <CardContent className="pt-3 pb-3">
              <div className="flex items-center gap-1 text-xs text-muted-foreground mb-1">
                <Activity className="h-3 w-3" />
                <span>{isEn ? 'Total Tokens' : '总 Tokens'}</span>
              </div>
              <div className="text-xl font-bold text-indigo-500" title={((stats.inputTokens || 0) + (stats.outputTokens || 0)).toLocaleString()}>{compactNumber((stats.inputTokens || 0) + (stats.outputTokens || 0))}</div>
            </CardContent>
          </Card>
          <Card className="hover-lift bg-gradient-to-br from-blue-500/5 to-transparent">
            <CardContent className="pt-3 pb-3">
              <div className="flex items-center gap-1 text-xs text-muted-foreground mb-1">
                <Activity className="h-3 w-3" />
                <span>{isEn ? 'Input / Output' : '输入 / 输出'}</span>
              </div>
              <div className="text-sm font-bold">
                <span className="text-blue-500" title={(stats.inputTokens || 0).toLocaleString()}>{compactNumber(stats.inputTokens || 0)}</span>
                <span className="text-muted-foreground mx-1">/</span>
                <span className="text-purple-500" title={(stats.outputTokens || 0).toLocaleString()}>{compactNumber(stats.outputTokens || 0)}</span>
              </div>
            </CardContent>
          </Card>
          <Card className="hover-lift bg-gradient-to-br from-emerald-500/5 to-transparent">
            <CardContent className="pt-3 pb-3">
              <div className="flex items-center gap-1 text-xs text-muted-foreground mb-1">
                <Cpu className="h-3 w-3" />
                <span>{isEn ? 'Cache Hit' : '缓存命中'}</span>
                {(() => {
                  const read = stats.cacheReadTokens || 0
                  const total = read + (stats.cacheWriteTokens || 0)
                  const rate = total > 0 ? (read / total * 100) : 0
                  return rate > 0 ? (
                    <Badge variant="secondary" className="ml-1 text-[10px] px-1 py-0">{rate.toFixed(0)}%</Badge>
                  ) : null
                })()}
              </div>
              <div className="text-sm font-bold">
                <span className="text-emerald-500" title={`${isEn ? 'Cache Read' : '缓存读取'}: ${(stats.cacheReadTokens || 0).toLocaleString()}`}>{compactNumber(stats.cacheReadTokens || 0)}</span>
                <span className="text-muted-foreground mx-1">/</span>
                <span className="text-amber-500" title={`${isEn ? 'Cache Write' : '缓存写入'}: ${(stats.cacheWriteTokens || 0).toLocaleString()}`}>{compactNumber(stats.cacheWriteTokens || 0)}</span>
              </div>
            </CardContent>
          </Card>
          <Card className="hover-lift bg-gradient-to-br from-violet-500/5 to-transparent">
            <CardContent className="pt-3 pb-3">
              <div className="flex items-center gap-1 text-xs text-muted-foreground mb-1">
                <Zap className="h-3 w-3" />
                <span>{isEn ? 'Reasoning' : '推理 Tokens'}</span>
              </div>
              <div className="text-xl font-bold text-violet-500" title={(stats.reasoningTokens || 0).toLocaleString()}>{compactNumber(stats.reasoningTokens || 0)}</div>
            </CardContent>
          </Card>
          <Card className="hover-lift bg-gradient-to-br from-green-500/5 to-transparent">
            <CardContent className="pt-3 pb-3">
              <div className="flex items-center gap-1 text-xs text-muted-foreground mb-1">
                <UserCheck className="h-3 w-3" />
                <span>{isEn ? 'Success Rate' : '成功率'}</span>
              </div>
              <div className="text-xl font-bold text-success">
                {stats.totalRequests > 0 ? `${((stats.successRequests / stats.totalRequests) * 100).toFixed(1)}%` : '-'}
              </div>
            </CardContent>
          </Card>
          <Card className="hover-lift bg-gradient-to-br from-amber-500/5 to-transparent">
            <CardContent className="pt-3 pb-3">
              <div className="flex items-center gap-1 text-xs text-muted-foreground mb-1">
                <Server className="h-3 w-3" />
                <span>Credits</span>
              </div>
              <div className="text-xl font-bold text-amber-500">{(stats.totalCredits || 0).toFixed(4)}</div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* API 端点说明 */}
      <Card className="hover-lift">
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
            <code className="text-muted-foreground flex-1 font-mono">/v1/responses</code>
            <span className="text-xs text-muted-foreground">{isEn ? 'OpenAI Responses' : 'OpenAI Responses'}</span>
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
            <span className="text-orange-500 w-11 flex-shrink-0 font-mono">POST</span>
            <code className="text-muted-foreground flex-1 font-mono">/v1beta/models/*:generateContent</code>
            <span className="text-xs text-muted-foreground">{isEn ? 'Gemini Compatible' : 'Gemini 兼容'}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-green-500 w-11 flex-shrink-0 font-mono">GET</span>
            <code className="text-muted-foreground flex-1 font-mono">/v1beta/models</code>
            <span className="text-xs text-muted-foreground">{isEn ? 'Gemini Models' : 'Gemini 模型'}</span>
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
        <Card className="hover-lift">
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
                <div key={idx} className="grid gap-2 py-1 px-2 rounded hover:bg-muted/50 items-center" style={{ gridTemplateColumns: '2fr 1fr 1.2fr 0.5fr 0.8fr 0.8fr 0.8fr 0.8fr 0.6fr' }}>
                  <span className="text-muted-foreground whitespace-nowrap text-left">{log.time}</span>
                  <span className="truncate text-left" title={log.path}>{log.path}</span>
                  <span className="truncate text-left text-muted-foreground" title={log.model}>{log.model ? log.model.replace('anthropic.', '').replace('-v1:0', '') : '-'}</span>
                  <span className={`text-center ${log.status >= 400 ? 'text-destructive' : 'text-success'}`}>{log.status}</span>
                  <span className="text-muted-foreground text-right">{log.inputTokens ? log.inputTokens.toLocaleString() : '-'}</span>
                  <span className="text-muted-foreground text-right">{log.outputTokens ? log.outputTokens.toLocaleString() : '-'}</span>
                  <span className="text-success text-right">{log.cacheReadTokens ? log.cacheReadTokens.toLocaleString() : '-'}</span>
                  <span className="text-muted-foreground text-right">{log.credits ? log.credits.toFixed(4) : '-'}</span>
                  <span className="text-muted-foreground text-right">{log.responseTime ? `${(log.responseTime / 1000).toFixed(1)}s` : '-'}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* 功能说明 */}
      <Card className="hover-lift">
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
        onOpenModelMapping={async () => {
          // 获取可用模型列表
          try {
            const result = await window.api.proxyGetModels()
            if (result.success && result.models) {
              setAvailableModels(result.models.map((m: { id: string; name?: string }) => ({ id: m.id, name: m.name || m.id })))
            }
          } catch {
            // 忽略错误
          }
          setShowModelsDialog(false)
          setShowModelMappingDialog(true)
        }}
        mappingCount={config.modelMappings?.length || 0}
      />

      <ClientConfigDialog
        open={showClientConfigDialog}
        onOpenChange={setShowClientConfigDialog}
        isEn={isEn}
      />

      {/* 模型映射弹窗 */}
      <ModelMappingDialog
        open={showModelMappingDialog}
        onOpenChange={setShowModelMappingDialog}
        isEn={isEn}
        mappings={config.modelMappings || []}
        onMappingsChange={(mappings) => {
          setConfig(prev => ({ ...prev, modelMappings: mappings }))
          window.api.proxyUpdateConfig({ modelMappings: mappings })
        }}
        apiKeys={(config.apiKeys || []).map(k => ({ id: k.id, name: k.name }))}
        availableModels={availableModels}
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
          <div className="absolute inset-0 bg-black/50" onClick={() => setShowApiKeyManager(false)} />
          <div className="relative bg-background rounded-lg shadow-lg w-[800px] max-h-[80vh] overflow-y-auto p-4">
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


