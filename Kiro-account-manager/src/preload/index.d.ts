import { ElectronAPI } from '@electron-toolkit/preload'

interface AccountData {
  accounts: Record<string, unknown>
  groups: Record<string, unknown>
  tags: Record<string, unknown>
  activeAccountId: string | null
  autoRefreshEnabled: boolean
  autoRefreshInterval: number
  autoRefreshConcurrency?: number
  autoRefreshSyncInfo?: boolean
  statusCheckInterval: number
  privacyMode?: boolean
  usagePrecision?: boolean
  proxyEnabled?: boolean
  proxyUrl?: string
  autoSwitchEnabled?: boolean
  autoSwitchThreshold?: number
  autoSwitchInterval?: number
  theme?: string
  darkMode?: boolean
  language?: 'auto' | 'en' | 'zh'
  // 机器码管理
  machineIdConfig?: {
    autoSwitchOnAccountChange: boolean
    bindMachineIdToAccount: boolean
    useBindedMachineId: boolean
  }
  currentMachineId?: string
  originalMachineId?: string | null
  originalBackupTime?: number | null
  accountMachineIds?: Record<string, string>
  machineIdHistory?: Array<{
    id: string
    machineId: string
    timestamp: number
    action: 'initial' | 'manual' | 'auto_switch' | 'restore' | 'bind'
    accountId?: string
    accountEmail?: string
  }>
}

interface RefreshResult {
  success: boolean
  data?: {
    accessToken: string
    refreshToken?: string
    expiresIn: number
  }
  error?: { message: string }
}

interface BonusData {
  code: string
  name: string
  current: number
  limit: number
  expiresAt?: string
}

interface ResourceDetail {
  resourceType?: string
  displayName?: string
  displayNamePlural?: string
  currency?: string
  unit?: string
  overageRate?: number
  overageCap?: number
  overageEnabled?: boolean
}

interface StatusResult {
  success: boolean
  data?: {
    status: string
    email?: string
    userId?: string
    idp?: string // 身份提供商：BuilderId, Google, Github 等
    userStatus?: string // 用户状态：Active 等
    featureFlags?: string[] // 特性开关
    subscriptionTitle?: string
    usage?: { 
      current: number
      limit: number
      percentUsed: number
      lastUpdated: number
      baseLimit?: number
      baseCurrent?: number
      freeTrialLimit?: number
      freeTrialCurrent?: number
      freeTrialExpiry?: string
      bonuses?: BonusData[]
      nextResetDate?: string
      resourceDetail?: ResourceDetail
    }
    subscription?: { 
      type: string
      title?: string
      rawType?: string
      expiresAt?: number
      daysRemaining?: number
      upgradeCapability?: string
      overageCapability?: string
      managementTarget?: string
    }
    // 如果 token 被刷新，返回新凭证
    newCredentials?: {
      accessToken: string
      refreshToken?: string
      expiresAt?: number
    }
  }
  error?: { message: string }
}

interface KiroApi {
  openExternal: (url: string, usePrivateMode?: boolean) => void
  getAppVersion: () => Promise<string>
  onAuthCallback: (callback: (data: { code: string; state: string }) => void) => () => void

  // 账号管理
  loadAccounts: () => Promise<AccountData | null>
  saveAccounts: (data: AccountData) => Promise<void>
  refreshAccountToken: (account: unknown) => Promise<RefreshResult>
  checkAccountStatus: (account: unknown) => Promise<StatusResult>
  
  // 后台批量刷新（主进程执行，不阻塞 UI）
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
  }>, concurrency?: number, syncInfo?: boolean) => Promise<{ success: boolean; completed: number; successCount: number; failedCount: number }>
  onBackgroundRefreshProgress: (callback: (data: { completed: number; total: number; success: number; failed: number }) => void) => () => void
  onBackgroundRefreshResult: (callback: (data: { id: string; success: boolean; data?: unknown; error?: string }) => void) => () => void
  
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
  }>, concurrency?: number) => Promise<{ success: boolean; completed: number; successCount: number; failedCount: number }>
  onBackgroundCheckProgress: (callback: (data: { completed: number; total: number; success: number; failed: number }) => void) => () => void
  onBackgroundCheckResult: (callback: (data: { id: string; success: boolean; data?: unknown; error?: string }) => void) => () => void
  
  // 切换账号 - 写入凭证到本地 SSO 缓存
  switchAccount: (credentials: {
    accessToken: string
    refreshToken: string
    clientId: string
    clientSecret: string
    region?: string
    startUrl?: string
    authMethod?: 'IdC' | 'social'
    provider?: 'BuilderId' | 'Enterprise' | 'Github' | 'Google' | 'IAM_SSO'
  }) => Promise<{ success: boolean; error?: string }>

  // 退出登录 - 清除本地 SSO 缓存
  logoutAccount: () => Promise<{ success: boolean; deletedCount?: number; error?: string }>

  // 文件操作
  exportToFile: (data: string, filename: string) => Promise<boolean>
  importFromFile: () => Promise<{ content: string; format: string } | null>

  // 验证凭证并获取账号信息
  verifyAccountCredentials: (credentials: {
    refreshToken: string
    clientId: string
    clientSecret: string
    region?: string
    authMethod?: string  // 'IdC' 或 'social'
    provider?: string    // 'BuilderId', 'Github', 'Google'
  }) => Promise<{
    success: boolean
    data?: {
      email: string
      userId: string
      accessToken: string
      refreshToken: string
      expiresIn?: number
      subscriptionType: string
      subscriptionTitle: string
      subscription?: {
        rawType?: string
        managementTarget?: string
        upgradeCapability?: string
        overageCapability?: string
      }
      usage: { 
        current: number
        limit: number
        baseLimit?: number
        baseCurrent?: number
        freeTrialLimit?: number
        freeTrialCurrent?: number
        freeTrialExpiry?: string
        bonuses?: Array<{ code: string; name: string; current: number; limit: number; expiresAt?: string }>
        nextResetDate?: string
        resourceDetail?: {
          displayName?: string
          displayNamePlural?: string
          resourceType?: string
          currency?: string
          unit?: string
          overageRate?: number
          overageCap?: number
          overageEnabled?: boolean
        }
      }
      daysRemaining?: number
      expiresAt?: number
    }
    error?: string
  }>

  // 获取本地 SSO 缓存中当前使用的账号信息
  getLocalActiveAccount: () => Promise<{
    success: boolean
    data?: {
      refreshToken: string
      accessToken?: string
      authMethod?: string
      provider?: string
    }
    error?: string
  }>

  // 从 Kiro 本地配置导入凭证
  loadKiroCredentials: () => Promise<{
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
  }>

  // 从 AWS SSO Token (x-amz-sso_authn) 导入账号
  importFromSsoToken: (bearerToken: string, region?: string) => Promise<{
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
      subscriptionType?: string
      subscriptionTitle?: string
      subscription?: {
        managementTarget?: string
        upgradeCapability?: string
        overageCapability?: string
      }
      usage?: {
        current: number
        limit: number
        baseLimit?: number
        baseCurrent?: number
        freeTrialLimit?: number
        freeTrialCurrent?: number
        freeTrialExpiry?: string
        bonuses?: Array<{ code: string; name: string; current: number; limit: number; expiresAt?: string }>
        nextResetDate?: string
        resourceDetail?: {
          displayName?: string
          displayNamePlural?: string
          resourceType?: string
          currency?: string
          unit?: string
          overageRate?: number
          overageCap?: number
          overageEnabled?: boolean
        }
      }
      daysRemaining?: number
    }
    error?: { message: string }
  }>

  // ============ 手动登录 API ============

  // 启动 Builder ID 手动登录
  startBuilderIdLogin: (region?: string) => Promise<{
    success: boolean
    userCode?: string
    verificationUri?: string
    expiresIn?: number
    interval?: number
    error?: string
  }>

  // 轮询 Builder ID 授权状态
  pollBuilderIdAuth: (region?: string) => Promise<{
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
  }>

  // 取消 Builder ID 登录
  cancelBuilderIdLogin: () => Promise<{ success: boolean }>

  // 启动 IAM Identity Center SSO 登录 (Authorization Code flow)
  startIamSsoLogin: (startUrl: string, region?: string) => Promise<{
    success: boolean
    authorizeUrl?: string
    expiresIn?: number
    error?: string
  }>

  // 轮询 IAM SSO 授权状态
  pollIamSsoAuth: (region?: string) => Promise<{
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
  }>

  // 取消 IAM SSO 登录
  cancelIamSsoLogin: () => Promise<{ success: boolean }>

  // 启动 Social Auth 登录 (Google/GitHub)
  startSocialLogin: (provider: 'Google' | 'Github', usePrivateMode?: boolean) => Promise<{
    success: boolean
    loginUrl?: string
    state?: string
    error?: string
  }>

  // 交换 Social Auth token
  exchangeSocialToken: (code: string, state: string) => Promise<{
    success: boolean
    accessToken?: string
    refreshToken?: string
    profileArn?: string
    expiresIn?: number
    authMethod?: string
    provider?: string
    error?: string
  }>

  // 取消 Social Auth 登录
  cancelSocialLogin: () => Promise<{ success: boolean }>

  // 监听 Social Auth 回调
  onSocialAuthCallback: (callback: (data: { code?: string; state?: string; error?: string }) => void) => () => void

  // 代理设置
  setProxy: (enabled: boolean, url: string) => Promise<{ success: boolean; error?: string }>

  // ============ 机器码管理 API ============

  // 获取操作系统类型
  machineIdGetOSType: () => Promise<'windows' | 'macos' | 'linux' | 'unknown'>

  // 获取当前机器码
  machineIdGetCurrent: () => Promise<{
    success: boolean
    machineId?: string
    error?: string
    requiresAdmin?: boolean
  }>

  // 设置新机器码
  machineIdSet: (newMachineId: string) => Promise<{
    success: boolean
    machineId?: string
    error?: string
    requiresAdmin?: boolean
  }>

  // 生成随机机器码
  machineIdGenerateRandom: () => Promise<string>

  // 检查管理员权限
  machineIdCheckAdmin: () => Promise<boolean>

  // 请求管理员权限重启
  machineIdRequestAdminRestart: () => Promise<boolean>

  // 备份机器码到文件
  machineIdBackupToFile: (machineId: string) => Promise<boolean>

  // 从文件恢复机器码
  machineIdRestoreFromFile: () => Promise<{
    success: boolean
    machineId?: string
    error?: string
  }>

  // ============ 自动更新 API ============

  // 检查更新 (electron-updater)
  checkForUpdates: () => Promise<{
    hasUpdate: boolean
    version?: string
    releaseDate?: string
    message?: string
    error?: string
  }>

  // 手动检查更新 (GitHub API, 用于 AboutPage)
  checkForUpdatesManual: () => Promise<{
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
  }>

  // 下载更新
  downloadUpdate: () => Promise<{ success: boolean; error?: string }>

  // 安装更新并重启
  installUpdate: () => Promise<void>

  // 监听更新事件
  onUpdateChecking: (callback: () => void) => () => void
  onUpdateAvailable: (callback: (info: { version: string; releaseDate?: string; releaseNotes?: string }) => void) => () => void
  onUpdateNotAvailable: (callback: (info: { version: string }) => void) => () => void
  onUpdateDownloadProgress: (callback: (progress: { percent: number; bytesPerSecond: number; transferred: number; total: number }) => void) => () => void
  onUpdateDownloaded: (callback: (info: { version: string; releaseDate?: string; releaseNotes?: string }) => void) => () => void
  onUpdateError: (callback: (error: string) => void) => () => void

  // ============ Kiro 设置管理 API ============

  // 获取 Kiro 设置
  getKiroSettings: () => Promise<{
    settings?: Record<string, unknown>
    mcpConfig?: { mcpServers: Record<string, unknown> }
    steeringFiles?: string[]
    error?: string
  }>

  // 保存 Kiro 设置
  saveKiroSettings: (settings: Record<string, unknown>) => Promise<{ success: boolean; error?: string }>

  // 打开 Kiro MCP 配置文件
  openKiroMcpConfig: (type: 'user' | 'workspace') => Promise<{ success: boolean; error?: string }>

  // 打开 Kiro Steering 目录
  openKiroSteeringFolder: () => Promise<{ success: boolean; error?: string }>

  // 打开 Kiro settings.json 文件
  openKiroSettingsFile: () => Promise<{ success: boolean; error?: string }>

  // 打开指定的 Steering 文件
  openKiroSteeringFile: (filename: string) => Promise<{ success: boolean; error?: string }>

  // 创建默认的 rules.md 文件
  createKiroDefaultRules: () => Promise<{ success: boolean; error?: string }>

  // 读取 Steering 文件内容
  readKiroSteeringFile: (filename: string) => Promise<{ success: boolean; content?: string; error?: string }>

  // 保存 Steering 文件内容
  saveKiroSteeringFile: (filename: string, content: string) => Promise<{ success: boolean; error?: string }>

  // 删除 Steering 文件
  deleteKiroSteeringFile: (filename: string) => Promise<{ success: boolean; error?: string }>

  // ============ MCP 服务器管理 ============

  // 保存 MCP 服务器配置
  saveMcpServer: (name: string, config: { command: string; args?: string[]; env?: Record<string, string> }, oldName?: string) => Promise<{ success: boolean; error?: string }>

  // 删除 MCP 服务器
  deleteMcpServer: (name: string) => Promise<{ success: boolean; error?: string }>

  // ============ Kiro API 反代服务器 ============

  // 启动反代服务器
  proxyStart: (config?: { port?: number; host?: string; apiKey?: string; enableMultiAccount?: boolean; logRequests?: boolean }) => Promise<{ success: boolean; port?: number; error?: string }>

  // 停止反代服务器
  proxyStop: () => Promise<{ success: boolean; error?: string }>

  // 获取反代服务器状态
  proxyGetStatus: () => Promise<{ running: boolean; config: unknown; stats: unknown; sessionStats?: { totalRequests: number; successRequests: number; failedRequests: number; startTime: number } }>

  // 重置累计 credits
  proxyResetCredits: () => Promise<{ success: boolean }>

  // 重置累计 tokens
  proxyResetTokens: () => Promise<{ success: boolean }>

  // 重置请求统计
  proxyResetRequestStats: () => Promise<{ success: boolean }>

  // 获取反代详细日志
  proxyGetLogs: (count?: number) => Promise<Array<{ timestamp: string; level: string; category: string; message: string; data?: unknown }>>

  // 清除反代详细日志
  proxyClearLogs: () => Promise<{ success: boolean }>

  // 获取反代日志数量
  proxyGetLogsCount: () => Promise<number>

  // 更新反代服务器配置
  proxyUpdateConfig: (config: { port?: number; host?: string; apiKey?: string; enableMultiAccount?: boolean; selectedAccountIds?: string[]; logRequests?: boolean; autoStart?: boolean; maxRetries?: number; preferredEndpoint?: 'codewhisperer' | 'amazonq'; autoContinueRounds?: number; disableTools?: boolean; autoSwitchOnQuotaExhausted?: boolean }) => Promise<{ success: boolean; config?: unknown; error?: string }>

  // 添加账号到反代池
  proxyAddAccount: (account: { id: string; email?: string; accessToken: string; refreshToken?: string; profileArn?: string; expiresAt?: number }) => Promise<{ success: boolean; accountCount?: number; error?: string }>

  // 从反代池移除账号
  proxyRemoveAccount: (accountId: string) => Promise<{ success: boolean; accountCount?: number; error?: string }>

  // 同步账号到反代池（批量更新）
  proxySyncAccounts: (accounts: Array<{ id: string; email?: string; accessToken: string; refreshToken?: string; profileArn?: string; expiresAt?: number }>) => Promise<{ success: boolean; accountCount?: number; error?: string }>

  // 获取反代池账号列表
  proxyGetAccounts: () => Promise<{ accounts: unknown[]; availableCount: number }>

  // 重置反代池状态
  proxyResetPool: () => Promise<{ success: boolean; error?: string }>

  // 刷新模型缓存
  proxyRefreshModels: () => Promise<{ success: boolean; error?: string }>

  // 获取可用模型列表
  proxyGetModels: () => Promise<{ success: boolean; error?: string; models: Array<{ id: string; name: string; description: string; inputTypes?: string[]; maxInputTokens?: number | null; maxOutputTokens?: number | null; rateMultiplier?: number; rateUnit?: string }>; fromCache?: boolean }>

  // 获取账户可用模型列表
  accountGetModels: (accessToken: string) => Promise<{ success: boolean; error?: string; models: Array<{ id: string; name: string; description: string; inputTypes?: string[]; maxInputTokens?: number | null; maxOutputTokens?: number | null; rateMultiplier?: number; rateUnit?: string }> }>

  // 获取可用订阅列表
  accountGetSubscriptions: (accessToken: string) => Promise<{ success: boolean; error?: string; plans: Array<{ name: string; qSubscriptionType: string; description: { title: string; billingInterval: string; featureHeader: string; features: string[] }; pricing: { amount: number; currency: string } }>; disclaimer?: string[] }>

  // 获取订阅管理/支付链接
  accountGetSubscriptionUrl: (accessToken: string, subscriptionType?: string) => Promise<{ success: boolean; error?: string; url?: string; status?: string }>

  // 在新窗口打开订阅链接
  openSubscriptionWindow: (url: string) => Promise<{ success: boolean; error?: string }>

  // 保存代理日志
  proxySaveLogs: (logs: Array<{ time: string; path: string; status: number; tokens?: number }>) => Promise<{ success: boolean; error?: string }>

  // 加载代理日志
  proxyLoadLogs: () => Promise<{ success: boolean; logs: Array<{ time: string; path: string; status: number; tokens?: number }> }>

  // 监听反代请求事件
  onProxyRequest: (callback: (info: { path: string; method: string; accountId?: string }) => void) => () => void

  // 监听反代响应事件
  onProxyResponse: (callback: (info: { path: string; status: number; tokens?: number; inputTokens?: number; outputTokens?: number; credits?: number; error?: string }) => void) => () => void

  // 监听反代错误事件
  onProxyError: (callback: (error: string) => void) => () => void

  // 监听反代状态变化事件
  onProxyStatusChange: (callback: (status: { running: boolean; port: number }) => void) => () => void

  // ============ Usage API 类型设置 ============

  // 获取 Usage API 类型
  getUsageApiType: () => Promise<'rest' | 'cbor'>

  // 设置 Usage API 类型
  setUsageApiType: (type: 'rest' | 'cbor') => Promise<{ success: boolean; type: string }>

  // 获取是否使用 K-Proxy 代理
  getUseKProxyForApi: () => Promise<boolean>

  // 设置是否使用 K-Proxy 代理
  setUseKProxyForApi: (enabled: boolean) => Promise<{ success: boolean; enabled: boolean }>

  // ============ K-Proxy MITM 代理 ============

  // 初始化 K-Proxy
  kproxyInit: () => Promise<{ success: boolean; caInfo?: { certPath: string; fingerprint: string; validFrom: string; validTo: string }; error?: string }>

  // 启动 K-Proxy
  kproxyStart: (config?: { port?: number; host?: string; mitmDomains?: string[]; deviceId?: string }) => Promise<{ success: boolean; port?: number; error?: string }>

  // 停止 K-Proxy
  kproxyStop: () => Promise<{ success: boolean; error?: string }>

  // 获取 K-Proxy 状态
  kproxyGetStatus: () => Promise<{ running: boolean; config: unknown; stats: unknown; caInfo: unknown }>

  // 更新 K-Proxy 配置
  kproxyUpdateConfig: (config: { port?: number; host?: string; mitmDomains?: string[]; deviceId?: string; autoStart?: boolean; logRequests?: boolean }) => Promise<{ success: boolean; config?: unknown; error?: string }>

  // 设置当前设备 ID
  kproxySetDeviceId: (deviceId: string) => Promise<{ success: boolean; error?: string }>

  // 生成新的设备 ID
  kproxyGenerateDeviceId: () => Promise<{ success: boolean; deviceId?: string }>

  // 添加设备 ID 映射
  kproxyAddDeviceMapping: (mapping: { accountId: string; deviceId: string; description?: string; createdAt: number }) => Promise<{ success: boolean; error?: string }>

  // 获取所有设备 ID 映射
  kproxyGetDeviceMappings: () => Promise<{ success: boolean; mappings: Array<{ accountId: string; deviceId: string; description?: string; createdAt: number; lastUsed?: number }> }>

  // 切换到账号设备 ID
  kproxySwitchToAccount: (accountId: string) => Promise<{ success: boolean; error?: string }>

  // 获取 CA 证书
  kproxyGetCaCert: () => Promise<{ success: boolean; certPem?: string; certPath?: string; fingerprint?: string; error?: string }>

  // 导出 CA 证书
  kproxyExportCaCert: (exportPath?: string) => Promise<{ success: boolean; path?: string; error?: string }>

  // 检查 CA 证书是否已安装
  kproxyCheckCaCertInstalled: () => Promise<{ success: boolean; installed: boolean; error?: string }>

  // ============ API Key 管理 ============
  
  // 获取所有 API Keys
  proxyGetApiKeys: () => Promise<{ success: boolean; apiKeys: Array<{ id: string; name: string; key: string; enabled: boolean; createdAt: number; lastUsedAt?: number; usage: { totalRequests: number; totalCredits: number; totalInputTokens: number; totalOutputTokens: number; daily: Record<string, { requests: number; credits: number; inputTokens: number; outputTokens: number }> } }>; error?: string }>

  // 添加 API Key
  proxyAddApiKey: (apiKey: { name: string; key?: string; format?: 'sk' | 'simple' | 'token'; creditsLimit?: number }) => Promise<{ success: boolean; apiKey?: { id: string; name: string; key: string; format?: 'sk' | 'simple' | 'token'; enabled: boolean; createdAt: number; creditsLimit?: number; usage: { totalRequests: number; totalCredits: number; totalInputTokens: number; totalOutputTokens: number; daily: Record<string, { requests: number; credits: number; inputTokens: number; outputTokens: number }> } }; error?: string }>

  // 更新 API Key
  proxyUpdateApiKey: (id: string, updates: { name?: string; key?: string; enabled?: boolean; creditsLimit?: number | null }) => Promise<{ success: boolean; apiKey?: { id: string; name: string; key: string; format?: 'sk' | 'simple' | 'token'; enabled: boolean; createdAt: number; creditsLimit?: number; usage: { totalRequests: number; totalCredits: number; totalInputTokens: number; totalOutputTokens: number; daily: Record<string, { requests: number; credits: number; inputTokens: number; outputTokens: number }> } }; error?: string }>

  // 删除 API Key
  proxyDeleteApiKey: (id: string) => Promise<{ success: boolean; error?: string }>

  // 重置 API Key 用量统计
  proxyResetApiKeyUsage: (id: string) => Promise<{ success: boolean; error?: string }>

  // 安装 CA 证书到系统信任存储
  kproxyInstallCaCert: () => Promise<{ success: boolean; message?: string; error?: string }>

  // 卸载 CA 证书从系统信任存储
  kproxyUninstallCaCert: () => Promise<{ success: boolean; message?: string; error?: string }>

  // 重置 K-Proxy 统计
  kproxyResetStats: () => Promise<{ success: boolean }>

  // 监听 K-Proxy 请求事件
  onKproxyRequest: (callback: (info: { timestamp: number; method: string; host: string; path: string; isMitm: boolean; deviceIdReplaced: boolean }) => void) => () => void

  // 监听 K-Proxy 响应事件
  onKproxyResponse: (callback: (info: { timestamp: number; host: string; statusCode: number; duration: number }) => void) => () => void

  // 监听 K-Proxy 错误事件
  onKproxyError: (callback: (error: string) => void) => () => void

  // 监听 K-Proxy 状态变化事件
  onKproxyStatusChange: (callback: (status: { running: boolean; port: number }) => void) => () => void

  // 监听 K-Proxy MITM 拦截事件
  onKproxyMitm: (callback: (info: { host: string; modified: boolean }) => void) => () => void

  // ============ 托盘相关 API ============

  // 获取托盘设置
  getShowWindowShortcut: () => Promise<string>
  setShowWindowShortcut: (shortcut: string) => Promise<{ success: boolean; error?: string }>
  getTraySettings: () => Promise<{
    enabled: boolean
    closeAction: 'ask' | 'minimize' | 'quit'
    showNotifications: boolean
    minimizeOnStart: boolean
  }>

  // 保存托盘设置
  saveTraySettings: (settings: {
    enabled?: boolean
    closeAction?: 'ask' | 'minimize' | 'quit'
    showNotifications?: boolean
    minimizeOnStart?: boolean
  }) => Promise<{ success: boolean; error?: string }>

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
  } | null) => void

  // 更新托盘账户列表
  updateTrayAccountList: (accounts: {
    id: string
    email: string
    idp: string
    status: string
  }[]) => void

  // 刷新托盘菜单
  refreshTrayMenu: () => void

  // 更新托盘语言
  updateTrayLanguage: (language: 'en' | 'zh') => void

  // 监听托盘刷新账户事件
  onTrayRefreshAccount: (callback: () => void) => () => void

  // 监听托盘切换账户事件
  onTraySwitchAccount: (callback: () => void) => () => void

  // 监听显示关闭确认对话框事件
  onShowCloseConfirmDialog: (callback: () => void) => () => void

  // 发送关闭确认对话框响应
  sendCloseConfirmResponse: (action: 'minimize' | 'quit' | 'cancel', rememberChoice: boolean) => void
}

declare global {
  interface Window {
    electron: ElectronAPI
    api: KiroApi
  }
}
