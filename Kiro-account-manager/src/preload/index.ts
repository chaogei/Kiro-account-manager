import { contextBridge, ipcRenderer } from 'electron'
import { electronAPI } from '@electron-toolkit/preload'

// Custom APIs for renderer
const api = {
  // 打开外部链接
  openExternal: (url: string): void => {
    ipcRenderer.send('open-external', url)
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
    credentials: {
      refreshToken: string
      clientId?: string
      clientSecret?: string
      region?: string
      authMethod?: string
      accessToken?: string
    }
  }>, concurrency?: number): Promise<{ success: boolean; completed: number; successCount: number; failedCount: number }> => {
    return ipcRenderer.invoke('background-batch-refresh', accounts, concurrency)
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
    authMethod?: 'IdC' | 'social'
    provider?: 'BuilderId' | 'Github' | 'Google'
  }): Promise<{ success: boolean; error?: string }> => {
    return ipcRenderer.invoke('switch-account', credentials)
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

  // 启动 Social Auth 登录 (Google/GitHub)
  startSocialLogin: (provider: 'Google' | 'Github'): Promise<{
    success: boolean
    loginUrl?: string
    state?: string
    error?: string
  }> => {
    return ipcRenderer.invoke('start-social-login', provider)
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
