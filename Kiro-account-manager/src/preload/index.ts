import { contextBridge, ipcRenderer } from 'electron'
import { electronAPI } from '@electron-toolkit/preload'

// Custom APIs for renderer
const api = {
  // 打开外部链接
  openExternal: (url: string, usePrivateMode?: boolean): void => {
    ipcRenderer.send('open-external', url, usePrivateMode)
  },

  // 获取应用版本
  getAppVersion: (): Promise<string> => {
    return ipcRenderer.invoke('get-app-version')
  },

  // 监听 OAuth 回调
  onAuthCallback: (callback: (data: { code: string; state: string }) => void): (() => void) => {
    const handler = (_event: Electron.IpcRendererEvent, data: { code: string; state: string }): void => {
      callback(data)
    }
    ipcRenderer.on('auth-callback', handler)
    return () => {
      ipcRenderer.removeListener('auth-callback', handler)
    }
  },

  // 账号管理 - 加载账号数据
  loadAccounts: (): Promise<unknown> => {
    return ipcRenderer.invoke('load-accounts')
  },

  // 账号管理 - 保存账号数据
  saveAccounts: (data: unknown): Promise<void> => {
    return ipcRenderer.invoke('save-accounts', data)
  },

  // 账号管理 - 刷新 Token
  refreshAccountToken: (account: unknown): Promise<unknown> => {
    return ipcRenderer.invoke('refresh-account-token', account)
  },

  // 账号管理 - 检查账号状态
  checkAccountStatus: (account: unknown): Promise<unknown> => {
    return ipcRenderer.invoke('check-account-status', account)
  },

  // 后台批量刷新账号（在主进程执行，不阻塞 UI）
  backgroundBatchRefresh: (accounts: Array<{
    id: string
    email: string
    idp?: string
    needsTokenRefresh?: boolean
    machineId?: string  // 账户绑定的设备 ID
    credentials: {
      refreshToken: string
      clientId?: string
      clientSecret?: string
      region?: string
      authMethod?: string
      accessToken?: string
      provider?: string
    }
  }>, concurrency?: number, syncInfo?: boolean): Promise<{ success: boolean; completed: number; successCount: number; failedCount: number }> => {
    return ipcRenderer.invoke('background-batch-refresh', accounts, concurrency, syncInfo)
  },

  // 监听后台刷新进度
  onBackgroundRefreshProgress: (callback: (data: { completed: number; total: number; success: number; failed: number }) => void): (() => void) => {
    const handler = (_event: Electron.IpcRendererEvent, data: { completed: number; total: number; success: number; failed: number }): void => {
      callback(data)
    }
    ipcRenderer.on('background-refresh-progress', handler)
    return () => {
      ipcRenderer.removeListener('background-refresh-progress', handler)
    }
  },

  // 监听后台刷新结果（单个账号）
  onBackgroundRefreshResult: (callback: (data: { id: string; success: boolean; data?: unknown; error?: string }) => void): (() => void) => {
    const handler = (_event: Electron.IpcRendererEvent, data: { id: string; success: boolean; data?: unknown; error?: string }): void => {
      callback(data)
    }
    ipcRenderer.on('background-refresh-result', handler)
    return () => {
      ipcRenderer.removeListener('background-refresh-result', handler)
    }
  },

  // 后台批量检查账号状态（不刷新 Token）
  backgroundBatchCheck: (accounts: Array<{
    id: string
    email: string
    credentials: {
      accessToken: string
      refreshToken?: string
      clientId?: string
      clientSecret?: string
      region?: string
      authMethod?: string
      provider?: string
    }
    idp?: string
  }>, concurrency?: number): Promise<{ success: boolean; completed: number; successCount: number; failedCount: number }> => {
    return ipcRenderer.invoke('background-batch-check', accounts, concurrency)
  },

  // 监听后台检查进度
  onBackgroundCheckProgress: (callback: (data: { completed: number; total: number; success: number; failed: number }) => void): (() => void) => {
    const handler = (_event: Electron.IpcRendererEvent, data: { completed: number; total: number; success: number; failed: number }): void => {
      callback(data)
    }
    ipcRenderer.on('background-check-progress', handler)
    return () => {
      ipcRenderer.removeListener('background-check-progress', handler)
    }
  },

  // 监听后台检查结果（单个账号）
  onBackgroundCheckResult: (callback: (data: { id: string; success: boolean; data?: unknown; error?: string }) => void): (() => void) => {
    const handler = (_event: Electron.IpcRendererEvent, data: { id: string; success: boolean; data?: unknown; error?: string }): void => {
      callback(data)
    }
    ipcRenderer.on('background-check-result', handler)
    return () => {
      ipcRenderer.removeListener('background-check-result', handler)
    }
  },

  // 切换账号 - 写入凭证到本地 SSO 缓存
  switchAccount: (credentials: {
    accessToken: string
    refreshToken: string
    clientId: string
    clientSecret: string
    region?: string
    startUrl?: string
    authMethod?: 'IdC' | 'social'
    provider?: 'BuilderId' | 'Github' | 'Google' | 'Enterprise'
  }): Promise<{ success: boolean; error?: string }> => {
    return ipcRenderer.invoke('switch-account', credentials)
  },

  // 退出登录 - 清除本地 SSO 缓存
  logoutAccount: (): Promise<{ success: boolean; deletedCount?: number; error?: string }> => {
    return ipcRenderer.invoke('logout-account')
  },

  // 文件操作 - 导出到文件
  exportToFile: (data: string, filename: string): Promise<boolean> => {
    return ipcRenderer.invoke('export-to-file', data, filename)
  },

  // 文件操作 - 从文件导入
  importFromFile: (): Promise<string | null> => {
    return ipcRenderer.invoke('import-from-file')
  },

  // 验证凭证并获取账号信息
  verifyAccountCredentials: (credentials: {
    refreshToken: string
    clientId: string
    clientSecret: string
    region?: string
    authMethod?: string  // 'IdC' 或 'social'
    provider?: string    // 'BuilderId', 'Github', 'Google'
  }): Promise<{
    success: boolean
    data?: {
      email: string
      userId: string
      accessToken: string
      refreshToken: string
      expiresIn?: number
      subscriptionType: string
      subscriptionTitle: string
      usage: { current: number; limit: number }
      daysRemaining?: number
      expiresAt?: number
    }
    error?: string
  }> => {
    return ipcRenderer.invoke('verify-account-credentials', credentials)
  },

  // 获取本地 SSO 缓存中当前使用的账号信息
  getLocalActiveAccount: (): Promise<{
    success: boolean
    data?: {
      refreshToken: string
      accessToken?: string
      authMethod?: string
      provider?: string
    }
    error?: string
  }> => {
    return ipcRenderer.invoke('get-local-active-account')
  },

  // 从 Kiro 本地配置导入凭证
  loadKiroCredentials: (): Promise<{
    success: boolean
    data?: {
      accessToken: string
      refreshToken: string
      clientId: string
      clientSecret: string
      region: string
      authMethod: string  // 'IdC' 或 'social'
      provider: string    // 'BuilderId', 'Github', 'Google'
    }
    error?: string
  }> => {
    return ipcRenderer.invoke('load-kiro-credentials')
  },

  // 从 AWS SSO Token (x-amz-sso_authn) 导入账号
  importFromSsoToken: (bearerToken: string, region?: string): Promise<{
    success: boolean
    data?: {
      accessToken: string
      refreshToken: string
      clientId: string
      clientSecret: string
      region: string
      expiresIn?: number
      email?: string
      userId?: string
      idp?: string
      status?: string
    }
    error?: { message: string }
  }> => {
    return ipcRenderer.invoke('import-from-sso-token', bearerToken, region || 'us-east-1')
  },

  // ============ 手动登录 API ============

  // 启动 Builder ID 手动登录
  startBuilderIdLogin: (region?: string): Promise<{
    success: boolean
    userCode?: string
    verificationUri?: string
    expiresIn?: number
    interval?: number
    error?: string
  }> => {
    return ipcRenderer.invoke('start-builder-id-login', region || 'us-east-1')
  },

  // 轮询 Builder ID 授权状态
  pollBuilderIdAuth: (region?: string): Promise<{
    success: boolean
    completed?: boolean
    status?: string
    accessToken?: string
    refreshToken?: string
    clientId?: string
    clientSecret?: string
    region?: string
    expiresIn?: number
    error?: string
  }> => {
    return ipcRenderer.invoke('poll-builder-id-auth', region || 'us-east-1')
  },

  // 取消 Builder ID 登录
  cancelBuilderIdLogin: (): Promise<{ success: boolean }> => {
    return ipcRenderer.invoke('cancel-builder-id-login')
  },

  // 启动 IAM Identity Center SSO 登录 (Authorization Code flow)
  startIamSsoLogin: (startUrl: string, region?: string): Promise<{
    success: boolean
    authorizeUrl?: string
    expiresIn?: number
    error?: string
  }> => {
    return ipcRenderer.invoke('start-iam-sso-login', startUrl, region || 'us-east-1')
  },

  // 轮询 IAM SSO 授权状态
  pollIamSsoAuth: (region?: string): Promise<{
    success: boolean
    completed?: boolean
    status?: string
    accessToken?: string
    refreshToken?: string
    clientId?: string
    clientSecret?: string
    region?: string
    expiresIn?: number
    error?: string
  }> => {
    return ipcRenderer.invoke('poll-iam-sso-auth', region || 'us-east-1')
  },

  // 完成 IAM SSO 登录 (用授权码换取 token)
  completeIamSsoLogin: (code: string): Promise<{
    success: boolean
    completed?: boolean
    accessToken?: string
    refreshToken?: string
    clientId?: string
    clientSecret?: string
    region?: string
    expiresIn?: number
    error?: string
  }> => {
    return ipcRenderer.invoke('complete-iam-sso-login', code)
  },

  // 取消 IAM SSO 登录
  cancelIamSsoLogin: (): Promise<{ success: boolean }> => {
    return ipcRenderer.invoke('cancel-iam-sso-login')
  },

  // 启动 Social Auth 登录 (Google/GitHub)
  startSocialLogin: (provider: 'Google' | 'Github', usePrivateMode?: boolean): Promise<{
    success: boolean
    loginUrl?: string
    state?: string
    error?: string
  }> => {
    return ipcRenderer.invoke('start-social-login', provider, usePrivateMode)
  },

  // 交换 Social Auth token
  exchangeSocialToken: (code: string, state: string): Promise<{
    success: boolean
    accessToken?: string
    refreshToken?: string
    profileArn?: string
    expiresIn?: number
    authMethod?: string
    provider?: string
    error?: string
  }> => {
    return ipcRenderer.invoke('exchange-social-token', code, state)
  },

  // 取消 Social Auth 登录
  cancelSocialLogin: (): Promise<{ success: boolean }> => {
    return ipcRenderer.invoke('cancel-social-login')
  },

  // 监听 Social Auth 回调
  onSocialAuthCallback: (callback: (data: { code?: string; state?: string; error?: string }) => void): (() => void) => {
    const handler = (_event: Electron.IpcRendererEvent, data: { code?: string; state?: string; error?: string }): void => {
      callback(data)
    }
    ipcRenderer.on('social-auth-callback', handler)
    return () => {
      ipcRenderer.removeListener('social-auth-callback', handler)
    }
  },

  // 代理设置
  setProxy: (enabled: boolean, url: string): Promise<{ success: boolean; error?: string }> => {
    return ipcRenderer.invoke('set-proxy', enabled, url)
  },

  // ============ 机器码管理 API ============

  // 获取操作系统类型
  machineIdGetOSType: (): Promise<'windows' | 'macos' | 'linux' | 'unknown'> => {
    return ipcRenderer.invoke('machine-id:get-os-type')
  },

  // 获取当前机器码
  machineIdGetCurrent: (): Promise<{
    success: boolean
    machineId?: string
    error?: string
    requiresAdmin?: boolean
  }> => {
    return ipcRenderer.invoke('machine-id:get-current')
  },

  // 设置新机器码
  machineIdSet: (newMachineId: string): Promise<{
    success: boolean
    machineId?: string
    error?: string
    requiresAdmin?: boolean
  }> => {
    return ipcRenderer.invoke('machine-id:set', newMachineId)
  },

  // 生成随机机器码
  machineIdGenerateRandom: (): Promise<string> => {
    return ipcRenderer.invoke('machine-id:generate-random')
  },

  // 检查管理员权限
  machineIdCheckAdmin: (): Promise<boolean> => {
    return ipcRenderer.invoke('machine-id:check-admin')
  },

  // 请求管理员权限重启
  machineIdRequestAdminRestart: (): Promise<boolean> => {
    return ipcRenderer.invoke('machine-id:request-admin-restart')
  },

  // 备份机器码到文件
  machineIdBackupToFile: (machineId: string): Promise<boolean> => {
    return ipcRenderer.invoke('machine-id:backup-to-file', machineId)
  },

  // 从文件恢复机器码
  machineIdRestoreFromFile: (): Promise<{
    success: boolean
    machineId?: string
    error?: string
  }> => {
    return ipcRenderer.invoke('machine-id:restore-from-file')
  },

  // ============ 自动更新 ============
  
  // 检查更新 (electron-updater)
  checkForUpdates: (): Promise<{
    hasUpdate: boolean
    version?: string
    releaseDate?: string
    message?: string
    error?: string
  }> => {
    return ipcRenderer.invoke('check-for-updates')
  },

  // 手动检查更新 (GitHub API, 用于 AboutPage)
  checkForUpdatesManual: (): Promise<{
    hasUpdate: boolean
    currentVersion?: string
    latestVersion?: string
    releaseNotes?: string
    releaseName?: string
    releaseUrl?: string
    publishedAt?: string
    assets?: Array<{
      name: string
      downloadUrl: string
      size: number
    }>
    error?: string
  }> => {
    return ipcRenderer.invoke('check-for-updates-manual')
  },

  // 下载更新
  downloadUpdate: (): Promise<{ success: boolean; error?: string }> => {
    return ipcRenderer.invoke('download-update')
  },

  // 安装更新并重启
  installUpdate: (): Promise<void> => {
    return ipcRenderer.invoke('install-update')
  },

  // 监听更新事件
  onUpdateChecking: (callback: () => void): (() => void) => {
    const handler = (): void => callback()
    ipcRenderer.on('update-checking', handler)
    return () => ipcRenderer.removeListener('update-checking', handler)
  },

  onUpdateAvailable: (callback: (info: { version: string; releaseDate?: string; releaseNotes?: string }) => void): (() => void) => {
    const handler = (_event: Electron.IpcRendererEvent, info: { version: string; releaseDate?: string; releaseNotes?: string }): void => callback(info)
    ipcRenderer.on('update-available', handler)
    return () => ipcRenderer.removeListener('update-available', handler)
  },

  onUpdateNotAvailable: (callback: (info: { version: string }) => void): (() => void) => {
    const handler = (_event: Electron.IpcRendererEvent, info: { version: string }): void => callback(info)
    ipcRenderer.on('update-not-available', handler)
    return () => ipcRenderer.removeListener('update-not-available', handler)
  },

  onUpdateDownloadProgress: (callback: (progress: { percent: number; bytesPerSecond: number; transferred: number; total: number }) => void): (() => void) => {
    const handler = (_event: Electron.IpcRendererEvent, progress: { percent: number; bytesPerSecond: number; transferred: number; total: number }): void => callback(progress)
    ipcRenderer.on('update-download-progress', handler)
    return () => ipcRenderer.removeListener('update-download-progress', handler)
  },

  onUpdateDownloaded: (callback: (info: { version: string; releaseDate?: string; releaseNotes?: string }) => void): (() => void) => {
    const handler = (_event: Electron.IpcRendererEvent, info: { version: string; releaseDate?: string; releaseNotes?: string }): void => callback(info)
    ipcRenderer.on('update-downloaded', handler)
    return () => ipcRenderer.removeListener('update-downloaded', handler)
  },

  onUpdateError: (callback: (error: string) => void): (() => void) => {
    const handler = (_event: Electron.IpcRendererEvent, error: string): void => callback(error)
    ipcRenderer.on('update-error', handler)
    return () => ipcRenderer.removeListener('update-error', handler)
  },

  // ============ Kiro 设置管理 ============

  // 获取 Kiro 设置
  getKiroSettings: (): Promise<{
    settings?: Record<string, unknown>
    mcpConfig?: { mcpServers: Record<string, unknown> }
    steeringFiles?: string[]
    error?: string
  }> => {
    return ipcRenderer.invoke('get-kiro-settings')
  },

  // 保存 Kiro 设置
  saveKiroSettings: (settings: Record<string, unknown>): Promise<{ success: boolean; error?: string }> => {
    return ipcRenderer.invoke('save-kiro-settings', settings)
  },

  // 打开 Kiro MCP 配置文件
  openKiroMcpConfig: (type: 'user' | 'workspace'): Promise<{ success: boolean; error?: string }> => {
    return ipcRenderer.invoke('open-kiro-mcp-config', type)
  },

  // 打开 Kiro Steering 目录
  openKiroSteeringFolder: (): Promise<{ success: boolean; error?: string }> => {
    return ipcRenderer.invoke('open-kiro-steering-folder')
  },

  // 打开 Kiro settings.json 文件
  openKiroSettingsFile: (): Promise<{ success: boolean; error?: string }> => {
    return ipcRenderer.invoke('open-kiro-settings-file')
  },

  // 打开指定的 Steering 文件
  openKiroSteeringFile: (filename: string): Promise<{ success: boolean; error?: string }> => {
    return ipcRenderer.invoke('open-kiro-steering-file', filename)
  },

  // 创建默认的 rules.md 文件
  createKiroDefaultRules: (): Promise<{ success: boolean; error?: string }> => {
    return ipcRenderer.invoke('create-kiro-default-rules')
  },

  // 读取 Steering 文件内容
  readKiroSteeringFile: (filename: string): Promise<{ success: boolean; content?: string; error?: string }> => {
    return ipcRenderer.invoke('read-kiro-steering-file', filename)
  },

  // 保存 Steering 文件内容
  saveKiroSteeringFile: (filename: string, content: string): Promise<{ success: boolean; error?: string }> => {
    return ipcRenderer.invoke('save-kiro-steering-file', filename, content)
  },

  // 删除 Steering 文件
  deleteKiroSteeringFile: (filename: string): Promise<{ success: boolean; error?: string }> => {
    return ipcRenderer.invoke('delete-kiro-steering-file', filename)
  },

  // ============ MCP 服务器管理 ============

  // 保存 MCP 服务器配置
  saveMcpServer: (name: string, config: { command: string; args?: string[]; env?: Record<string, string> }, oldName?: string): Promise<{ success: boolean; error?: string }> => {
    return ipcRenderer.invoke('save-mcp-server', name, config, oldName)
  },

  // 删除 MCP 服务器
  deleteMcpServer: (name: string): Promise<{ success: boolean; error?: string }> => {
    return ipcRenderer.invoke('delete-mcp-server', name)
  },

  // ============ Kiro API 反代服务器 ============

  // 启动反代服务器
  proxyStart: (config?: { port?: number; host?: string; enableMultiAccount?: boolean; logRequests?: boolean }): Promise<{ success: boolean; port?: number; error?: string }> => {
    return ipcRenderer.invoke('proxy-start', config)
  },

  // 停止反代服务器
  proxyStop: (): Promise<{ success: boolean; error?: string }> => {
    return ipcRenderer.invoke('proxy-stop')
  },

  // 获取反代服务器状态
  proxyGetStatus: (): Promise<{ running: boolean; config: unknown; stats: unknown }> => {
    return ipcRenderer.invoke('proxy-get-status')
  },

  // 重置累计 credits
  proxyResetCredits: (): Promise<{ success: boolean }> => {
    return ipcRenderer.invoke('proxy-reset-credits')
  },

  // 重置累计 tokens
  proxyResetTokens: (): Promise<{ success: boolean }> => {
    return ipcRenderer.invoke('proxy-reset-tokens')
  },

  // 重置请求统计
  proxyResetRequestStats: (): Promise<{ success: boolean }> => {
    return ipcRenderer.invoke('proxy-reset-request-stats')
  },

  // 获取反代详细日志
  proxyGetLogs: (count?: number): Promise<Array<{ timestamp: string; level: string; category: string; message: string; data?: unknown }>> => {
    return ipcRenderer.invoke('proxy-get-logs', count)
  },

  // 清除反代详细日志
  proxyClearLogs: (): Promise<{ success: boolean }> => {
    return ipcRenderer.invoke('proxy-clear-logs')
  },

  // 获取反代日志数量
  proxyGetLogsCount: (): Promise<number> => {
    return ipcRenderer.invoke('proxy-get-logs-count')
  },

  // 更新反代服务器配置
  proxyUpdateConfig: (config: { port?: number; host?: string; apiKey?: string; enableMultiAccount?: boolean; selectedAccountIds?: string[]; logRequests?: boolean; autoStart?: boolean; maxRetries?: number; preferredEndpoint?: 'codewhisperer' | 'amazonq'; autoContinueRounds?: number; disableTools?: boolean; autoSwitchOnQuotaExhausted?: boolean; modelMappings?: Array<{ id: string; name: string; enabled: boolean; type: 'replace' | 'alias' | 'loadbalance'; sourceModel: string; targetModels: string[]; weights?: number[]; priority: number; apiKeyIds?: string[] }> }): Promise<{ success: boolean; config?: unknown; error?: string }> => {
    return ipcRenderer.invoke('proxy-update-config', config)
  },

  // 添加账号到反代池
  proxyAddAccount: (account: { id: string; email?: string; accessToken: string; refreshToken?: string; profileArn?: string; expiresAt?: number }): Promise<{ success: boolean; accountCount?: number; error?: string }> => {
    return ipcRenderer.invoke('proxy-add-account', account)
  },

  // 从反代池移除账号
  proxyRemoveAccount: (accountId: string): Promise<{ success: boolean; accountCount?: number; error?: string }> => {
    return ipcRenderer.invoke('proxy-remove-account', accountId)
  },

  // 同步账号到反代池（批量更新）
  proxySyncAccounts: (accounts: Array<{ id: string; email?: string; accessToken: string; refreshToken?: string; profileArn?: string; expiresAt?: number }>): Promise<{ success: boolean; accountCount?: number; error?: string }> => {
    return ipcRenderer.invoke('proxy-sync-accounts', accounts)
  },

  // 获取反代池账号列表
  proxyGetAccounts: (): Promise<{ accounts: unknown[]; availableCount: number }> => {
    return ipcRenderer.invoke('proxy-get-accounts')
  },

  // 重置反代池状态
  proxyResetPool: (): Promise<{ success: boolean; error?: string }> => {
    return ipcRenderer.invoke('proxy-reset-pool')
  },

  // 刷新模型缓存
  proxyRefreshModels: (): Promise<{ success: boolean; error?: string }> => {
    return ipcRenderer.invoke('proxy-refresh-models')
  },

  // 获取可用模型列表
  proxyGetModels: (): Promise<{ success: boolean; error?: string; models: Array<{ id: string; name: string; description: string; inputTypes?: string[]; maxInputTokens?: number | null; maxOutputTokens?: number | null; rateMultiplier?: number; rateUnit?: string }>; fromCache?: boolean }> => {
    return ipcRenderer.invoke('proxy-get-models')
  },

  // 获取账户可用模型列表
  accountGetModels: (accessToken: string): Promise<{ success: boolean; error?: string; models: Array<{ id: string; name: string; description: string; inputTypes?: string[]; maxInputTokens?: number | null; maxOutputTokens?: number | null; rateMultiplier?: number; rateUnit?: string }> }> => {
    return ipcRenderer.invoke('account-get-models', accessToken)
  },

  // 获取可用订阅列表
  accountGetSubscriptions: (accessToken: string): Promise<{ success: boolean; error?: string; plans: Array<{ name: string; qSubscriptionType: string; description: { title: string; billingInterval: string; featureHeader: string; features: string[] }; pricing: { amount: number; currency: string } }>; disclaimer?: string[] }> => {
    return ipcRenderer.invoke('account-get-subscriptions', accessToken)
  },

  // 获取订阅管理/支付链接
  accountGetSubscriptionUrl: (accessToken: string, subscriptionType?: string): Promise<{ success: boolean; error?: string; url?: string; status?: string }> => {
    return ipcRenderer.invoke('account-get-subscription-url', accessToken, subscriptionType)
  },

  // 在新窗口打开订阅链接
  openSubscriptionWindow: (url: string): Promise<{ success: boolean; error?: string }> => {
    return ipcRenderer.invoke('open-subscription-window', url)
  },

  // 保存代理日志
  proxySaveLogs: (logs: Array<{ time: string; path: string; status: number; tokens?: number }>): Promise<{ success: boolean; error?: string }> => {
    return ipcRenderer.invoke('proxy-save-logs', logs)
  },

  // 加载代理日志
  proxyLoadLogs: (): Promise<{ success: boolean; logs: Array<{ time: string; path: string; status: number; tokens?: number }> }> => {
    return ipcRenderer.invoke('proxy-load-logs')
  },

  // 监听反代请求事件
  onProxyRequest: (callback: (info: { path: string; method: string; accountId?: string }) => void): (() => void) => {
    const handler = (_event: Electron.IpcRendererEvent, info: { path: string; method: string; accountId?: string }): void => {
      callback(info)
    }
    ipcRenderer.on('proxy-request', handler)
    return () => {
      ipcRenderer.removeListener('proxy-request', handler)
    }
  },

  // 监听反代响应事件
  onProxyResponse: (callback: (info: { path: string; model?: string; status: number; tokens?: number; inputTokens?: number; outputTokens?: number; credits?: number; error?: string }) => void): (() => void) => {
    const handler = (_event: Electron.IpcRendererEvent, info: { path: string; model?: string; status: number; tokens?: number; inputTokens?: number; outputTokens?: number; credits?: number; error?: string }): void => {
      callback(info)
    }
    ipcRenderer.on('proxy-response', handler)
    return () => {
      ipcRenderer.removeListener('proxy-response', handler)
    }
  },

  // 监听反代错误事件
  onProxyError: (callback: (error: string) => void): (() => void) => {
    const handler = (_event: Electron.IpcRendererEvent, error: string): void => {
      callback(error)
    }
    ipcRenderer.on('proxy-error', handler)
    return () => {
      ipcRenderer.removeListener('proxy-error', handler)
    }
  },

  // 监听反代状态变化事件
  onProxyStatusChange: (callback: (status: { running: boolean; port: number }) => void): (() => void) => {
    const handler = (_event: Electron.IpcRendererEvent, status: { running: boolean; port: number }): void => {
      callback(status)
    }
    ipcRenderer.on('proxy-status-change', handler)
    return () => {
      ipcRenderer.removeListener('proxy-status-change', handler)
    }
  },

  // ============ Usage API 类型设置 ============

  // 获取 Usage API 类型
  getUsageApiType: (): Promise<'rest' | 'cbor'> => {
    return ipcRenderer.invoke('get-usage-api-type')
  },

  // 设置 Usage API 类型
  setUsageApiType: (type: 'rest' | 'cbor'): Promise<{ success: boolean; type: string }> => {
    return ipcRenderer.invoke('set-usage-api-type', type)
  },

  // 获取是否使用 K-Proxy 代理
  getUseKProxyForApi: (): Promise<boolean> => {
    return ipcRenderer.invoke('get-use-kproxy-for-api')
  },

  // 设置是否使用 K-Proxy 代理
  setUseKProxyForApi: (enabled: boolean): Promise<{ success: boolean; enabled: boolean }> => {
    return ipcRenderer.invoke('set-use-kproxy-for-api', enabled)
  },

  // ============ K-Proxy MITM 代理 ============

  // 初始化 K-Proxy
  kproxyInit: (): Promise<{ success: boolean; caInfo?: { certPath: string; fingerprint: string; validFrom: string; validTo: string }; error?: string }> => {
    return ipcRenderer.invoke('kproxy-init')
  },

  // 启动 K-Proxy
  kproxyStart: (config?: { port?: number; host?: string; mitmDomains?: string[]; deviceId?: string }): Promise<{ success: boolean; port?: number; error?: string }> => {
    return ipcRenderer.invoke('kproxy-start', config)
  },

  // 停止 K-Proxy
  kproxyStop: (): Promise<{ success: boolean; error?: string }> => {
    return ipcRenderer.invoke('kproxy-stop')
  },

  // 获取 K-Proxy 状态
  kproxyGetStatus: (): Promise<{ running: boolean; config: unknown; stats: unknown; caInfo: unknown }> => {
    return ipcRenderer.invoke('kproxy-get-status')
  },

  // 更新 K-Proxy 配置
  kproxyUpdateConfig: (config: { port?: number; host?: string; mitmDomains?: string[]; deviceId?: string; autoStart?: boolean; logRequests?: boolean }): Promise<{ success: boolean; config?: unknown; error?: string }> => {
    return ipcRenderer.invoke('kproxy-update-config', config)
  },

  // 设置当前设备 ID
  kproxySetDeviceId: (deviceId: string): Promise<{ success: boolean; error?: string }> => {
    return ipcRenderer.invoke('kproxy-set-device-id', deviceId)
  },

  // 生成新的设备 ID
  kproxyGenerateDeviceId: (): Promise<{ success: boolean; deviceId?: string }> => {
    return ipcRenderer.invoke('kproxy-generate-device-id')
  },

  // 添加设备 ID 映射
  kproxyAddDeviceMapping: (mapping: { accountId: string; deviceId: string; description?: string; createdAt: number }): Promise<{ success: boolean; error?: string }> => {
    return ipcRenderer.invoke('kproxy-add-device-mapping', mapping)
  },

  // 获取所有设备 ID 映射
  kproxyGetDeviceMappings: (): Promise<{ success: boolean; mappings: Array<{ accountId: string; deviceId: string; description?: string; createdAt: number; lastUsed?: number }> }> => {
    return ipcRenderer.invoke('kproxy-get-device-mappings')
  },

  // 切换到账号设备 ID
  kproxySwitchToAccount: (accountId: string): Promise<{ success: boolean; error?: string }> => {
    return ipcRenderer.invoke('kproxy-switch-to-account', accountId)
  },

  // 获取 CA 证书
  kproxyGetCaCert: (): Promise<{ success: boolean; certPem?: string; certPath?: string; fingerprint?: string; error?: string }> => {
    return ipcRenderer.invoke('kproxy-get-ca-cert')
  },

  // 导出 CA 证书
  kproxyExportCaCert: (exportPath?: string): Promise<{ success: boolean; path?: string; error?: string }> => {
    return ipcRenderer.invoke('kproxy-export-ca-cert', exportPath)
  },

  // 检查 CA 证书是否已安装
  kproxyCheckCaCertInstalled: (): Promise<{ success: boolean; installed: boolean; error?: string }> => {
    return ipcRenderer.invoke('kproxy-check-ca-cert-installed')
  },

  // ============ API Key 管理 ============
  
  // 获取所有 API Keys
  proxyGetApiKeys: (): Promise<{ success: boolean; apiKeys: Array<{ id: string; name: string; key: string; enabled: boolean; createdAt: number; lastUsedAt?: number; usage: { totalRequests: number; totalCredits: number; totalInputTokens: number; totalOutputTokens: number; daily: Record<string, { requests: number; credits: number; inputTokens: number; outputTokens: number }> } }>; error?: string }> => {
    return ipcRenderer.invoke('proxy-get-api-keys')
  },

  // 添加 API Key
  proxyAddApiKey: (apiKey: { name: string; key?: string; format?: 'sk' | 'simple' | 'token'; creditsLimit?: number }): Promise<{ success: boolean; apiKey?: { id: string; name: string; key: string; format?: 'sk' | 'simple' | 'token'; enabled: boolean; createdAt: number; creditsLimit?: number; usage: { totalRequests: number; totalCredits: number; totalInputTokens: number; totalOutputTokens: number; daily: Record<string, { requests: number; credits: number; inputTokens: number; outputTokens: number }> } }; error?: string }> => {
    return ipcRenderer.invoke('proxy-add-api-key', apiKey)
  },

  // 更新 API Key
  proxyUpdateApiKey: (id: string, updates: { name?: string; key?: string; enabled?: boolean; creditsLimit?: number | null }): Promise<{ success: boolean; apiKey?: { id: string; name: string; key: string; format?: 'sk' | 'simple' | 'token'; enabled: boolean; createdAt: number; creditsLimit?: number; usage: { totalRequests: number; totalCredits: number; totalInputTokens: number; totalOutputTokens: number; daily: Record<string, { requests: number; credits: number; inputTokens: number; outputTokens: number }> } }; error?: string }> => {
    return ipcRenderer.invoke('proxy-update-api-key', id, updates)
  },

  // 删除 API Key
  proxyDeleteApiKey: (id: string): Promise<{ success: boolean; error?: string }> => {
    return ipcRenderer.invoke('proxy-delete-api-key', id)
  },

  // 重置 API Key 用量统计
  proxyResetApiKeyUsage: (id: string): Promise<{ success: boolean; error?: string }> => {
    return ipcRenderer.invoke('proxy-reset-api-key-usage', id)
  },

  // 安装 CA 证书到系统信任存储
  kproxyInstallCaCert: (): Promise<{ success: boolean; message?: string; error?: string }> => {
    return ipcRenderer.invoke('kproxy-install-ca-cert')
  },

  // 卸载 CA 证书从系统信任存储
  kproxyUninstallCaCert: (): Promise<{ success: boolean; message?: string; error?: string }> => {
    return ipcRenderer.invoke('kproxy-uninstall-ca-cert')
  },

  // 重置 K-Proxy 统计
  kproxyResetStats: (): Promise<{ success: boolean }> => {
    return ipcRenderer.invoke('kproxy-reset-stats')
  },

  // 监听 K-Proxy 请求事件
  onKproxyRequest: (callback: (info: { timestamp: number; method: string; host: string; path: string; isMitm: boolean; deviceIdReplaced: boolean }) => void): (() => void) => {
    const handler = (_event: Electron.IpcRendererEvent, info: { timestamp: number; method: string; host: string; path: string; isMitm: boolean; deviceIdReplaced: boolean }): void => {
      callback(info)
    }
    ipcRenderer.on('kproxy-request', handler)
    return () => {
      ipcRenderer.removeListener('kproxy-request', handler)
    }
  },

  // 监听 K-Proxy 响应事件
  onKproxyResponse: (callback: (info: { timestamp: number; host: string; statusCode: number; duration: number }) => void): (() => void) => {
    const handler = (_event: Electron.IpcRendererEvent, info: { timestamp: number; host: string; statusCode: number; duration: number }): void => {
      callback(info)
    }
    ipcRenderer.on('kproxy-response', handler)
    return () => {
      ipcRenderer.removeListener('kproxy-response', handler)
    }
  },

  // 监听 K-Proxy 错误事件
  onKproxyError: (callback: (error: string) => void): (() => void) => {
    const handler = (_event: Electron.IpcRendererEvent, error: string): void => {
      callback(error)
    }
    ipcRenderer.on('kproxy-error', handler)
    return () => {
      ipcRenderer.removeListener('kproxy-error', handler)
    }
  },

  // 监听 K-Proxy 状态变化事件
  onKproxyStatusChange: (callback: (status: { running: boolean; port: number }) => void): (() => void) => {
    const handler = (_event: Electron.IpcRendererEvent, status: { running: boolean; port: number }): void => {
      callback(status)
    }
    ipcRenderer.on('kproxy-status-change', handler)
    return () => {
      ipcRenderer.removeListener('kproxy-status-change', handler)
    }
  },

  // 监听 K-Proxy MITM 拦截事件
  onKproxyMitm: (callback: (info: { host: string; modified: boolean }) => void): (() => void) => {
    const handler = (_event: Electron.IpcRendererEvent, info: { host: string; modified: boolean }): void => {
      callback(info)
    }
    ipcRenderer.on('kproxy-mitm', handler)
    return () => {
      ipcRenderer.removeListener('kproxy-mitm', handler)
    }
  },

  // ============ 托盘相关 API ============

  // 获取显示主窗口快捷键
  getShowWindowShortcut: (): Promise<string> => ipcRenderer.invoke('get-show-window-shortcut'),

  // 设置显示主窗口快捷键
  setShowWindowShortcut: (shortcut: string): Promise<{ success: boolean; error?: string }> => 
    ipcRenderer.invoke('set-show-window-shortcut', shortcut),

  // 获取托盘设置
  getTraySettings: (): Promise<{
    enabled: boolean
    closeAction: 'ask' | 'minimize' | 'quit'
    showNotifications: boolean
    minimizeOnStart: boolean
  }> => {
    return ipcRenderer.invoke('get-tray-settings')
  },

  // 保存托盘设置
  saveTraySettings: (settings: {
    enabled?: boolean
    closeAction?: 'ask' | 'minimize' | 'quit'
    showNotifications?: boolean
    minimizeOnStart?: boolean
  }): Promise<{ success: boolean; error?: string }> => {
    return ipcRenderer.invoke('save-tray-settings', settings)
  },

  // 更新托盘当前账户信息
  updateTrayAccount: (account: {
    id: string
    email: string
    idp: string
    status: string
    subscription?: string
    usage?: {
      usedCredits: number
      totalCredits: number
      totalRequests: number
      successRequests: number
      failedRequests: number
    }
  } | null): void => {
    ipcRenderer.send('update-tray-account', account)
  },

  // 更新托盘账户列表
  updateTrayAccountList: (accounts: {
    id: string
    email: string
    idp: string
    status: string
  }[]): void => {
    ipcRenderer.send('update-tray-account-list', accounts)
  },

  // 刷新托盘菜单
  refreshTrayMenu: (): void => {
    ipcRenderer.send('refresh-tray-menu')
  },

  // 更新托盘语言
  updateTrayLanguage: (language: 'en' | 'zh'): void => {
    ipcRenderer.send('update-tray-language', language)
  },

  // 监听托盘刷新账户事件
  onTrayRefreshAccount: (callback: () => void): (() => void) => {
    const handler = (): void => {
      callback()
    }
    ipcRenderer.on('tray-refresh-account', handler)
    return () => {
      ipcRenderer.removeListener('tray-refresh-account', handler)
    }
  },

  // 监听托盘切换账户事件
  onTraySwitchAccount: (callback: () => void): (() => void) => {
    const handler = (): void => {
      callback()
    }
    ipcRenderer.on('tray-switch-account', handler)
    return () => {
      ipcRenderer.removeListener('tray-switch-account', handler)
    }
  },

  // 监听显示关闭确认对话框事件
  onShowCloseConfirmDialog: (callback: () => void): (() => void) => {
    const handler = (): void => {
      callback()
    }
    ipcRenderer.on('show-close-confirm-dialog', handler)
    return () => {
      ipcRenderer.removeListener('show-close-confirm-dialog', handler)
    }
  },

  // 发送关闭确认对话框响应
  sendCloseConfirmResponse: (action: 'minimize' | 'quit' | 'cancel', rememberChoice: boolean): void => {
    ipcRenderer.send('close-confirm-response', action, rememberChoice)
  }
}

// Use `contextBridge` APIs to expose Electron APIs to
// renderer only if context isolation is enabled, otherwise
// just add to the DOM global.
if (process.contextIsolated) {
  try {
    contextBridge.exposeInMainWorld('electron', electronAPI)
    contextBridge.exposeInMainWorld('api', api)
  } catch (error) {
    console.error(error)
  }
} else {
  // @ts-ignore (define in dts)
  window.electron = electronAPI
  // @ts-ignore (define in dts)
  window.api = api
}
