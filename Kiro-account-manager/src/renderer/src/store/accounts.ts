import { create } from 'zustand'
import { v4 as uuidv4 } from 'uuid'
import type {
  Account,
  AccountGroup,
  AccountTag,
  AccountFilter,
  AccountSort,
  AccountStatus,
  AccountStats,
  AccountExportData,
  AccountImportItem,
  BatchOperationResult,
  AccountSubscription,
  SubscriptionType,
  IdpType
} from '../types/account'
import type {
  ProxyEntry,
  ProxyPoolConfig,
  ProxyValidationResult,
  ProxyProtocol
} from '../types/proxy'
import { DEFAULT_PROXY_POOL_CONFIG } from '../types/proxy'
import { useWebhookStore, type WebhookEvent, type WebhookMessage } from './webhooks'

// ============================================
// 账号管理 Store
// ============================================

// 生成随机 64 位十六进制设备 ID
function generateRandomMachineId(): string {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
}

// 自动 Token 刷新定时器
let tokenRefreshTimer: ReturnType<typeof setInterval> | null = null
const TOKEN_REFRESH_BEFORE_EXPIRY = 5 * 60 * 1000 // 过期前 5 分钟刷新

// 持久化防抖：合并连续 mutation 为单次写盘，避免后台刷新风暴时 IPC + IO 风暴
const SAVE_DEBOUNCE_MS = 500
let saveDebounceTimer: ReturnType<typeof setTimeout> | null = null
let saveInFlight: Promise<void> | null = null

// ============ getFilteredAccounts / getStats 引用缓存 ============
// 大账号量场景下这两个 selector 每次 re-render 都跑 O(n) 计算（filter + sort）
// 通过引用比较缓存输入快照，命中时直接返回上次结果，将 N×n 计算降至 1×n
let _filterCache: {
  accounts: unknown
  filter: unknown
  sort: unknown
  activeGroupTab: unknown
  output: Account[]
} | null = null

let _statsCache: {
  accounts: unknown
  output: AccountStats
} | null = null

/**
 * 异步同步本地 SSO 缓存中的激活账号到 store。
 * 含潜在的网络请求（verifyAccountCredentials），从 loadFromStorage 中拆出来
 * 异步执行，避免阻塞首屏加载（isLoading）。
 */
type SetFn = (
  partial:
    | Partial<AccountsState>
    | ((state: AccountsState) => Partial<AccountsState>)
) => void

async function syncLocalSsoAccountAsync(
  get: () => AccountsStore,
  set: SetFn
): Promise<void> {
  try {
    const localResult = await window.api.getLocalActiveAccount()
    if (!localResult.success || !localResult.data?.refreshToken) return

    const localRefreshToken = localResult.data.refreshToken
    const currentAccounts = get().accounts

    // 查找匹配的账号
    let foundAccountId: string | null = null
    for (const [id, account] of currentAccounts) {
      if (account.credentials.refreshToken === localRefreshToken) {
        foundAccountId = id
        break
      }
    }

    if (foundAccountId) {
      // 找到匹配的账号，更新 activeAccountId
      set({ activeAccountId: foundAccountId })
      // 同步 isActive 字段
      set((state) => {
        const accounts = new Map(state.accounts)
        for (const [id, account] of accounts) {
          const shouldBeActive = id === foundAccountId
          if (account.isActive !== shouldBeActive) {
            accounts.set(id, { ...account, isActive: shouldBeActive })
          }
        }
        return { accounts }
      })
      console.log('[Store] Synced active account from local SSO cache:', foundAccountId)
      get().saveToStorage()
      return
    }

    // 未找到匹配账号，尝试自动导入（网络请求）
    console.log('[Store] Local account not found in app, importing...')
    const importResult = await window.api.loadKiroCredentials()
    if (!importResult.success || !importResult.data) return

    const verifyResult = await window.api.verifyAccountCredentials({
      refreshToken: importResult.data.refreshToken,
      clientId: importResult.data.clientId || '',
      clientSecret: importResult.data.clientSecret || '',
      region: importResult.data.region,
      authMethod: importResult.data.authMethod,
      provider: importResult.data.provider
    })
    if (!verifyResult.success || !verifyResult.data) return

    const now = Date.now()
    const newId = `${verifyResult.data.email}-${now}`
    const newAccount: Account = {
      id: newId,
      email: verifyResult.data.email,
      userId: verifyResult.data.userId,
      nickname: verifyResult.data.email ? verifyResult.data.email.split('@')[0] : undefined,
      idp: (importResult.data.provider || 'BuilderId') as 'BuilderId' | 'Enterprise' | 'Google' | 'Github',
      profileArn: importResult.data.profileArn,
      credentials: {
        accessToken: verifyResult.data.accessToken,
        csrfToken: '',
        refreshToken: verifyResult.data.refreshToken,
        clientId: importResult.data.clientId || '',
        clientSecret: importResult.data.clientSecret || '',
        region: importResult.data.region || 'us-east-1',
        expiresAt: verifyResult.data.expiresIn ? now + verifyResult.data.expiresIn * 1000 : now + 3600 * 1000,
        authMethod: importResult.data.authMethod as 'IdC' | 'social',
        provider: (importResult.data.provider || 'BuilderId') as 'BuilderId' | 'Enterprise' | 'Github' | 'Google'
      },
      subscription: {
        type: verifyResult.data.subscriptionType as SubscriptionType,
        title: verifyResult.data.subscriptionTitle,
        rawType: verifyResult.data.subscription?.rawType,
        daysRemaining: verifyResult.data.daysRemaining,
        expiresAt: verifyResult.data.expiresAt,
        managementTarget: verifyResult.data.subscription?.managementTarget,
        upgradeCapability: verifyResult.data.subscription?.upgradeCapability,
        overageCapability: verifyResult.data.subscription?.overageCapability
      },
      usage: {
        current: verifyResult.data.usage.current,
        limit: verifyResult.data.usage.limit,
        percentUsed: verifyResult.data.usage.limit > 0
          ? verifyResult.data.usage.current / verifyResult.data.usage.limit
          : 0,
        lastUpdated: now,
        baseLimit: verifyResult.data.usage.baseLimit,
        baseCurrent: verifyResult.data.usage.baseCurrent,
        freeTrialLimit: verifyResult.data.usage.freeTrialLimit,
        freeTrialCurrent: verifyResult.data.usage.freeTrialCurrent,
        freeTrialExpiry: verifyResult.data.usage.freeTrialExpiry,
        bonuses: verifyResult.data.usage.bonuses,
        nextResetDate: verifyResult.data.usage.nextResetDate,
        resourceDetail: verifyResult.data.usage.resourceDetail
      },
      status: 'active',
      createdAt: now,
      lastUsedAt: now,
      tags: [],
      isActive: true
    }

    set((state) => {
      const accounts = new Map(state.accounts)
      // 取消其它账号的激活状态
      for (const [id, account] of accounts) {
        if (account.isActive) {
          accounts.set(id, { ...account, isActive: false })
        }
      }
      accounts.set(newId, newAccount)
      return { accounts, activeAccountId: newId }
    })
    console.log('[Store] Auto-imported account from local SSO cache:', verifyResult.data.email)
    get().saveToStorage()
  } catch (e) {
    console.warn('[Store] Failed to sync local active account:', e)
  }
}

function isBannedAccountError(error?: string): boolean {
  if (!error) return false
  const lowerError = error.toLowerCase()
  const hasSuspendedSignal =
    lowerError.includes('accountsuspendedexception') ||
    lowerError.includes('account suspended') ||
    lowerError.includes('temporarily_suspended') ||
    lowerError.includes('temporarily suspended') ||
    (lowerError.includes('user id is') && lowerError.includes('suspended')) ||
    lowerError.includes('账户已封禁') ||
    lowerError.includes('已封禁') ||
    /\b423\b/.test(lowerError)
  if (hasSuspendedSignal) return true
  if (
    lowerError.includes('fetch failed') ||
    lowerError.includes('network') ||
    lowerError.includes('token expired') ||
    lowerError.includes('token 过期') ||
    lowerError.includes('刷新失败') ||
    lowerError.includes('unauthorizedexception')
  ) {
    return false
  }
  return false
}

// 自动换号定时器
let autoSwitchTimer: ReturnType<typeof setInterval> | null = null

// 定时自动保存定时器（防止数据丢失）
let autoSaveTimer: ReturnType<typeof setInterval> | null = null
const AUTO_SAVE_INTERVAL = 30 * 1000 // 每 30 秒自动保存一次
let lastSaveHash = '' // 用于检测数据是否变化

interface AccountsState {
  // 应用版本号
  appVersion: string

  // 数据
  accounts: Map<string, Account>
  groups: Map<string, AccountGroup>
  tags: Map<string, AccountTag>

  // 当前激活账号
  activeAccountId: string | null

  // 筛选和排序
  filter: AccountFilter
  /** 当前激活的分组 Tab：'all' | 'ungrouped' | <groupId>，互斥 */
  activeGroupTab: string
  sort: AccountSort

  // 选中的账号（用于批量操作）
  selectedIds: Set<string>

  // 加载状态
  isLoading: boolean
  isSyncing: boolean

  // 自动刷新设置
  autoRefreshEnabled: boolean
  autoRefreshInterval: number // 分钟
  autoRefreshConcurrency: number // 自动刷新并发数
  autoRefreshSyncInfo: boolean // 刷新时是否同步检测账户信息（用量、订阅、封禁状态）
  statusCheckInterval: number // 分钟

  // 隐私模式
  privacyMode: boolean

  // 使用量显示精度
  usagePrecision: boolean // true: 显示精确小数, false: 显示整数

  // 代理设置
  proxyEnabled: boolean
  proxyUrl: string // 格式: http://host:port 或 socks5://host:port

  // 自动换号设置
  autoSwitchEnabled: boolean
  autoSwitchThreshold: number // 余额阈值，低于此值时自动切换
  autoSwitchInterval: number // 检查间隔（分钟）

  // 批量导入设置
  batchImportConcurrency: number // 批量导入并发数

  // 登录浏览器隐私模式
  loginPrivateMode: boolean // 登录时使用浏览器隐私/无痕模式

  // 切号目标设置
  switchTarget: 'ide' | 'cli' | 'both' // ide=仅 Kiro IDE, cli=仅 Kiro CLI, both=两者都切

  // 主题设置
  theme: string // 主题名称: default, purple, emerald, orange, rose, cyan, amber
  darkMode: boolean // 深色模式

  // 语言设置
  language: 'auto' | 'en' | 'zh' // auto: 跟随系统

  // 机器码管理
  machineIdConfig: {
    autoSwitchOnAccountChange: boolean // 切号时自动更换机器码
    bindMachineIdToAccount: boolean // 账户机器码绑定
    useBindedMachineId: boolean // 使用绑定的机器码（否则随机生成）
  }
  currentMachineId: string // 当前机器码
  originalMachineId: string | null // 备份的原始机器码
  originalBackupTime: number | null // 原始机器码备份时间
  accountMachineIds: Record<string, string> // 账户绑定的机器码映射
  machineIdHistory: Array<{
    id: string
    machineId: string
    timestamp: number
    action: 'initial' | 'manual' | 'auto_switch' | 'restore' | 'bind'
    accountId?: string
    accountEmail?: string
  }>

  // ============ 代理池（用于注册时 IP 轮换）============
  /** 代理条目列表（Map 保证 O(1) 查找） */
  proxyPool: Map<string, ProxyEntry>
  /** 代理池配置（启用状态、调度策略等） */
  proxyPoolConfig: ProxyPoolConfig
  /** 轮询调度光标（仅用于 round_robin 策略） */
  proxyPoolCursor: number
  /** 账号-代理绑定映射（accountId → proxyId）；用于"反代时 N 个账号共用 1 个 IP" */
  accountProxyBindings: Record<string, string>
}

interface AccountsActions {
  // 账号 CRUD
  addAccount: (account: Omit<Account, 'id' | 'createdAt' | 'isActive'>) => string
  updateAccount: (id: string, updates: Partial<Account>) => void
  removeAccount: (id: string) => void
  removeAccounts: (ids: string[]) => BatchOperationResult

  // 激活账号
  setActiveAccount: (id: string | null) => void
  getActiveAccount: () => Account | null

  // 分组操作
  addGroup: (group: Omit<AccountGroup, 'id' | 'createdAt' | 'order'>) => string
  updateGroup: (id: string, updates: Partial<AccountGroup>) => void
  removeGroup: (id: string) => void
  moveAccountsToGroup: (accountIds: string[], groupId: string | undefined) => void

  // 标签操作
  addTag: (tag: Omit<AccountTag, 'id'>) => string
  updateTag: (id: string, updates: Partial<AccountTag>) => void
  removeTag: (id: string) => void
  addTagToAccounts: (accountIds: string[], tagId: string) => void
  removeTagFromAccounts: (accountIds: string[], tagId: string) => void

  // 筛选和排序
  setFilter: (filter: AccountFilter) => void
  clearFilter: () => void
  setActiveGroupTab: (tab: string) => void
  setSort: (sort: AccountSort) => void
  getFilteredAccounts: () => Account[]

  // 选择操作
  selectAccount: (id: string) => void
  deselectAccount: (id: string) => void
  selectAll: () => void
  deselectAll: () => void
  toggleSelection: (id: string) => void
  getSelectedAccounts: () => Account[]

  // 导入导出
  exportAccounts: (ids?: string[]) => AccountExportData
  importAccounts: (items: AccountImportItem[]) => BatchOperationResult
  importFromExportData: (data: AccountExportData) => BatchOperationResult

  // 状态管理
  updateAccountStatus: (id: string, status: AccountStatus, error?: string) => void
  refreshAccountToken: (id: string) => Promise<boolean>
  batchRefreshTokens: (ids: string[]) => Promise<BatchOperationResult>
  checkAccountStatus: (id: string) => Promise<void>
  batchCheckStatus: (ids: string[]) => Promise<BatchOperationResult>

  // 统计
  getStats: () => AccountStats

  // 持久化
  loadFromStorage: () => Promise<void>
  /** 防抖触发持久化（推荐：高频 mutation 自动合并写盘） */
  saveToStorage: () => Promise<void>
  /** 立即持久化（用于 beforeunload 或关键操作场景） */
  flushSaveImmediately: () => Promise<void>

  // 设置
  setAutoRefresh: (enabled: boolean, interval?: number) => void
  setAutoRefreshConcurrency: (concurrency: number) => void
  setAutoRefreshSyncInfo: (enabled: boolean) => void
  setStatusCheckInterval: (interval: number) => void

  // 隐私模式
  setPrivacyMode: (enabled: boolean) => void
  maskEmail: (email: string) => string
  maskNickname: (nickname: string | undefined) => string

  // 使用量精度
  setUsagePrecision: (enabled: boolean) => void

  // 代理设置
  setProxy: (enabled: boolean, url?: string) => Promise<void>

  // 主题设置
  setTheme: (theme: string) => void
  setDarkMode: (enabled: boolean) => void
  applyTheme: () => void

  // 语言设置
  setLanguage: (language: 'auto' | 'en' | 'zh') => void

  // 自动换号
  setAutoSwitch: (enabled: boolean, threshold?: number, interval?: number) => void

  // 批量导入并发数
  setBatchImportConcurrency: (concurrency: number) => void

  // 登录浏览器隐私模式
  setLoginPrivateMode: (enabled: boolean) => void

  // 切号目标设置
  setSwitchTarget: (target: 'ide' | 'cli' | 'both') => void

  startAutoSwitch: () => void
  stopAutoSwitch: () => void
  checkAndAutoSwitch: () => Promise<void>

  // 自动 Token 刷新
  startAutoTokenRefresh: () => void
  stopAutoTokenRefresh: () => void
  checkAndRefreshExpiringTokens: () => Promise<void>
  refreshExpiredTokensOnly: () => Promise<void>
  triggerBackgroundRefresh: () => Promise<void>
  handleBackgroundRefreshResult: (data: { id: string; success: boolean; data?: unknown; error?: string }) => void
  handleBackgroundCheckResult: (data: { id: string; success: boolean; data?: unknown; error?: string }) => void
  /** 批量处理后台刷新结果：一次 set 应用 N 条结果，消除 N 次 Map 全量复制 */
  applyBackgroundRefreshResults: (items: Array<{ id: string; success: boolean; data?: unknown; error?: string }>) => void
  /** 批量处理后台检查结果：一次 set 应用 N 条结果 */
  applyBackgroundCheckResults: (items: Array<{ id: string; success: boolean; data?: unknown; error?: string }>) => void

  // 定时自动保存（防止数据丢失）
  startAutoSave: () => void
  stopAutoSave: () => void

  // 机器码管理
  setMachineIdConfig: (config: Partial<{
    autoSwitchOnAccountChange: boolean
    bindMachineIdToAccount: boolean
    useBindedMachineId: boolean
  }>) => void
  refreshCurrentMachineId: () => Promise<void>
  changeMachineId: (newMachineId?: string) => Promise<boolean>
  restoreOriginalMachineId: () => Promise<boolean>
  bindMachineIdToAccount: (accountId: string, machineId?: string) => void
  getMachineIdForAccount: (accountId: string) => string | null
  backupOriginalMachineId: () => void
  clearMachineIdHistory: () => void

  // ============ 代理池操作 ============
  /** 添加单个代理（自动解析协议/主机/端口/认证） */
  addProxy: (url: string, options?: { label?: string; source?: string; tags?: string[] }) => string | null
  /** 批量导入（文本，每行一个，支持 http://host:port、socks5://user:pass@host:port、host:port 等） */
  importProxies: (text: string) => { added: number; skipped: number; failed: number }
  /** 删除代理 */
  removeProxy: (id: string) => void
  /** 批量删除 */
  removeProxies: (ids: string[]) => void
  /** 切换启用状态 */
  toggleProxyEnabled: (id: string, enabled?: boolean) => void
  /** 更新代理元数据 */
  updateProxy: (id: string, updates: Partial<ProxyEntry>) => void
  /** 测试单个代理（异步，主进程执行） */
  validateProxy: (id: string) => Promise<ProxyValidationResult>
  /** 批量测试（并发） */
  validateProxiesBatch: (ids: string[], concurrency?: number) => Promise<void>
  /** 清空所有代理 */
  clearProxyPool: () => void
  /** 更新代理池配置 */
  setProxyPoolConfig: (config: Partial<ProxyPoolConfig>) => void
  /** 按当前策略挑选下一个可用代理（注册流程内部调用） */
  pickNextProxy: () => ProxyEntry | null
  /** 标记代理使用结果（供注册流程上报，用于失败计数与自动停用） */
  reportProxyResult: (id: string, success: boolean, boundEmail?: string, errorMsg?: string) => void

  // ============ 账号-代理绑定（反代分桶）============
  /** 把账号绑定到指定代理 */
  bindAccountToProxy: (accountId: string, proxyId: string) => void
  /** 批量绑定（用于批量分配） */
  bindAccountsToProxy: (accountIds: string[], proxyId: string) => void
  /** 解除账号绑定 */
  unbindAccountFromProxy: (accountId: string) => void
  /** 清空全部账号绑定 */
  clearAccountProxyBindings: () => void
  /**
   * 自动分配：把账号按 N:1 比例平均分配到当前启用的代理上
   * @param accountsPerProxy 每个代理承载的账号数；为 0 表示尽量均分
   * @param onlyUnbound 是否仅分配尚未绑定的账号；false 则重新分配全部
   * @returns 分配统计
   */
  autoDistributeAccountsToProxies: (params: {
    accountsPerProxy?: number
    onlyUnbound?: boolean
    accountIds?: string[]  // 限定分配范围，不填则全部
  }) => { distributed: number; perProxy: Record<string, number>; skipped: number }
  /** 读取账号绑定的代理 URL（供主进程同步用） */
  getAccountProxyUrl: (accountId: string) => string | undefined
}

type AccountsStore = AccountsState & AccountsActions

// 默认排序
const defaultSort: AccountSort = { field: 'lastUsedAt', order: 'desc' }

// 默认筛选
const defaultFilter: AccountFilter = {}

// 从 localStorage 恢复分组 Tab（遵循 Electron renderer 环境总是可用）
const loadActiveGroupTab = (): string => {
  try {
    return localStorage.getItem('accounts_activeGroupTab') || 'all'
  } catch {
    return 'all'
  }
}

export const useAccountsStore = create<AccountsStore>()((set, get) => ({
  // 初始状态
  appVersion: '1.0.0',
  accounts: new Map(),
  groups: new Map(),
  tags: new Map(),
  activeAccountId: null,
  filter: defaultFilter,
  activeGroupTab: loadActiveGroupTab(),
  sort: defaultSort,
  selectedIds: new Set(),
  isLoading: false,
  isSyncing: false,
  autoRefreshEnabled: true,
  autoRefreshInterval: 5,
  autoRefreshConcurrency: 100,
  autoRefreshSyncInfo: true,
  statusCheckInterval: 60,
  privacyMode: false,
  usagePrecision: false,
  proxyEnabled: false,
  proxyUrl: '',
  autoSwitchEnabled: false,
  autoSwitchThreshold: 0,
  autoSwitchInterval: 5,
  batchImportConcurrency: 100,
  loginPrivateMode: false,
  switchTarget: 'ide' as const,
  theme: 'default',
  darkMode: false,
  language: 'auto',

  machineIdConfig: {
    autoSwitchOnAccountChange: false,
    bindMachineIdToAccount: false,
    useBindedMachineId: true
  },
  currentMachineId: '',
  originalMachineId: null,
  originalBackupTime: null,
  accountMachineIds: {},
  machineIdHistory: [],

  // 代理池初始状态
  proxyPool: new Map<string, ProxyEntry>(),
  proxyPoolConfig: { ...DEFAULT_PROXY_POOL_CONFIG },
  proxyPoolCursor: 0,
  accountProxyBindings: {},

  // ==================== 账号 CRUD ====================

  addAccount: (accountData) => {
    const id = uuidv4()
    const now = Date.now()

    // 如果没有提供 machineId，自动生成一个随机的 64 位十六进制设备 ID
    const machineId = accountData.machineId || generateRandomMachineId()

    const account: Account = {
      ...accountData,
      id,
      machineId,
      createdAt: now,
      lastUsedAt: now,
      isActive: false,
      tags: accountData.tags || []
    }

    set((state) => {
      const accounts = new Map(state.accounts)
      accounts.set(id, account)
      return { accounts }
    })

    get().saveToStorage()
    return id
  },

  updateAccount: (id, updates) => {
    set((state) => {
      const accounts = new Map(state.accounts)
      const account = accounts.get(id)
      if (account) {
        accounts.set(id, { ...account, ...updates })
      }
      return { accounts }
    })
    get().saveToStorage()
  },

  removeAccount: (id) => {
    set((state) => {
      const accounts = new Map(state.accounts)
      accounts.delete(id)

      const selectedIds = new Set(state.selectedIds)
      selectedIds.delete(id)

      const activeAccountId = state.activeAccountId === id ? null : state.activeAccountId

      // 同时清理账号-代理绑定
      const bindings = { ...state.accountProxyBindings }
      delete bindings[id]

      return { accounts, selectedIds, activeAccountId, accountProxyBindings: bindings }
    })
    get().saveToStorage()
  },

  removeAccounts: (ids) => {
    const result: BatchOperationResult = { success: 0, failed: 0, errors: [] }

    set((state) => {
      const accounts = new Map(state.accounts)
      const selectedIds = new Set(state.selectedIds)
      let activeAccountId = state.activeAccountId
      const bindings = { ...state.accountProxyBindings }

      for (const id of ids) {
        if (accounts.has(id)) {
          accounts.delete(id)
          selectedIds.delete(id)
          delete bindings[id]
          if (activeAccountId === id) activeAccountId = null
          result.success++
        } else {
          result.failed++
          result.errors.push({ id, error: 'Account not found' })
        }
      }

      return { accounts, selectedIds, activeAccountId, accountProxyBindings: bindings }
    })

    get().saveToStorage()
    return result
  },

  // ==================== 激活账号 ====================

  setActiveAccount: async (id) => {
    const state = get()
    
    set((s) => {
      const accounts = new Map(s.accounts)

      // 取消之前的激活状态
      if (s.activeAccountId) {
        const prev = accounts.get(s.activeAccountId)
        if (prev) {
          accounts.set(s.activeAccountId, { ...prev, isActive: false })
        }
      }

      // 设置新的激活状态
      if (id) {
        const account = accounts.get(id)
        if (account) {
          accounts.set(id, { ...account, isActive: true, lastUsedAt: Date.now() })
        }
      }

      return { accounts, activeAccountId: id }
    })
    
    // 切换账号时自动更换机器码（如果启用）
    if (id && state.machineIdConfig.autoSwitchOnAccountChange) {
      try {
        const account = state.accounts.get(id)
        
        if (state.machineIdConfig.bindMachineIdToAccount) {
          // 使用账户绑定的机器码
          let boundMachineId = state.accountMachineIds[id]
          
          if (!boundMachineId) {
            // 如果没有绑定机器码，为该账户生成一个
            boundMachineId = await window.api.machineIdGenerateRandom()
            get().bindMachineIdToAccount(id, boundMachineId)
          }
          
          if (state.machineIdConfig.useBindedMachineId) {
            // 使用绑定的机器码
            await get().changeMachineId(boundMachineId)
          } else {
            // 随机生成新机器码
            await get().changeMachineId()
          }
        } else {
          // 每次切换都随机生成新机器码
          await get().changeMachineId()
        }
        
        // 更新历史记录
        const newMachineId = get().currentMachineId
        set((s) => ({
          machineIdHistory: [
            ...s.machineIdHistory,
            {
              id: crypto.randomUUID(),
              machineId: newMachineId,
              timestamp: Date.now(),
              action: 'auto_switch' as const,
              accountId: id,
              accountEmail: account?.email
            }
          ]
        }))
        
        console.log(`[MachineId] Auto-switched machine ID for account: ${account?.email}`)
      } catch (error) {
        console.error('[MachineId] Failed to auto-switch machine ID:', error)
      }
    }
    
    get().saveToStorage()
  },

  getActiveAccount: () => {
    const { accounts, activeAccountId } = get()
    return activeAccountId ? accounts.get(activeAccountId) ?? null : null
  },

  // ==================== 分组操作 ====================

  addGroup: (groupData) => {
    const id = uuidv4()
    const { groups } = get()

    const group: AccountGroup = {
      ...groupData,
      id,
      order: groups.size,
      createdAt: Date.now()
    }

    set((state) => {
      const groups = new Map(state.groups)
      groups.set(id, group)
      return { groups }
    })

    get().saveToStorage()
    return id
  },

  updateGroup: (id, updates) => {
    set((state) => {
      const groups = new Map(state.groups)
      const group = groups.get(id)
      if (group) {
        groups.set(id, { ...group, ...updates })
      }
      return { groups }
    })
    get().saveToStorage()
  },

  removeGroup: (id) => {
    set((state) => {
      const groups = new Map(state.groups)
      groups.delete(id)

      // 移除账号的分组引用
      const accounts = new Map(state.accounts)
      for (const [accountId, account] of accounts) {
        if (account.groupId === id) {
          accounts.set(accountId, { ...account, groupId: undefined })
        }
      }

      return { groups, accounts }
    })
    get().saveToStorage()
  },

  moveAccountsToGroup: (accountIds, groupId) => {
    set((state) => {
      const accounts = new Map(state.accounts)
      for (const id of accountIds) {
        const account = accounts.get(id)
        if (account) {
          accounts.set(id, { ...account, groupId })
        }
      }
      return { accounts }
    })
    get().saveToStorage()
  },

  // ==================== 标签操作 ====================

  addTag: (tagData) => {
    const id = uuidv4()

    const tag: AccountTag = { ...tagData, id }

    set((state) => {
      const tags = new Map(state.tags)
      tags.set(id, tag)
      return { tags }
    })

    get().saveToStorage()
    return id
  },

  updateTag: (id, updates) => {
    set((state) => {
      const tags = new Map(state.tags)
      const tag = tags.get(id)
      if (tag) {
        tags.set(id, { ...tag, ...updates })
      }
      return { tags }
    })
    get().saveToStorage()
  },

  removeTag: (id) => {
    set((state) => {
      const tags = new Map(state.tags)
      tags.delete(id)

      // 移除账号的标签引用
      const accounts = new Map(state.accounts)
      for (const [accountId, account] of accounts) {
        if (account.tags.includes(id)) {
          accounts.set(accountId, {
            ...account,
            tags: account.tags.filter((t) => t !== id)
          })
        }
      }

      return { tags, accounts }
    })
    get().saveToStorage()
  },

  addTagToAccounts: (accountIds, tagId) => {
    set((state) => {
      const accounts = new Map(state.accounts)
      for (const id of accountIds) {
        const account = accounts.get(id)
        if (account && !account.tags.includes(tagId)) {
          accounts.set(id, { ...account, tags: [...account.tags, tagId] })
        }
      }
      return { accounts }
    })
    get().saveToStorage()
  },

  removeTagFromAccounts: (accountIds, tagId) => {
    set((state) => {
      const accounts = new Map(state.accounts)
      for (const id of accountIds) {
        const account = accounts.get(id)
        if (account) {
          accounts.set(id, {
            ...account,
            tags: account.tags.filter((t) => t !== tagId)
          })
        }
      }
      return { accounts }
    })
    get().saveToStorage()
  },

  // ==================== 筛选和排序 ====================

  setFilter: (filter) => {
    set({ filter })
  },

  clearFilter: () => {
    set({ filter: defaultFilter })
  },

  setActiveGroupTab: (tab) => {
    try { localStorage.setItem('accounts_activeGroupTab', tab) } catch { /* no-op */ }
    set({ activeGroupTab: tab })
  },

  setSort: (sort) => {
    set({ sort })
  },

  getFilteredAccounts: () => {
    const { accounts, filter, sort, activeGroupTab } = get()

    // 引用缓存命中：返回上次结果（数组同引用，便于消费方 useMemo 复用）
    if (
      _filterCache &&
      _filterCache.accounts === accounts &&
      _filterCache.filter === filter &&
      _filterCache.sort === sort &&
      _filterCache.activeGroupTab === activeGroupTab
    ) {
      return _filterCache.output
    }

    let result = Array.from(accounts.values())

    // 优先按分组 Tab 互斥过滤（与 filter.groupIds 独立）
    if (activeGroupTab === 'ungrouped') {
      result = result.filter((a) => !a.groupId)
    } else if (activeGroupTab !== 'all') {
      result = result.filter((a) => a.groupId === activeGroupTab)
    }

    // 应用筛选
    if (filter.search) {
      const search = filter.search.toLowerCase()
      result = result.filter(
        (a) =>
          a.email.toLowerCase().includes(search) ||
          a.nickname?.toLowerCase().includes(search)
      )
    }

    if (filter.subscriptionTypes?.length) {
      result = result.filter((a) => filter.subscriptionTypes!.includes(a.subscription.type))
    }

    if (filter.statuses?.length) {
      result = result.filter((a) => filter.statuses!.includes(a.status))
    }

    if (filter.idps?.length) {
      result = result.filter((a) => filter.idps!.includes(a.idp))
    }

    if (filter.groupIds?.length) {
      result = result.filter((a) => a.groupId && filter.groupIds!.includes(a.groupId))
    }

    if (filter.tagIds?.length) {
      result = result.filter((a) => filter.tagIds!.some((t) => a.tags.includes(t)))
    }

    if (filter.usageMin !== undefined) {
      result = result.filter((a) => a.usage.percentUsed >= filter.usageMin!)
    }

    if (filter.usageMax !== undefined) {
      result = result.filter((a) => a.usage.percentUsed <= filter.usageMax!)
    }

    if (filter.daysRemainingMin !== undefined) {
      result = result.filter(
        (a) => a.subscription.daysRemaining !== undefined &&
               a.subscription.daysRemaining >= filter.daysRemainingMin!
      )
    }

    if (filter.daysRemainingMax !== undefined) {
      result = result.filter(
        (a) => a.subscription.daysRemaining !== undefined &&
               a.subscription.daysRemaining <= filter.daysRemainingMax!
      )
    }

    // 封禁筛选
    if (filter.bannedOnly) {
      result = result.filter((a) => isBannedAccountError(a.lastError))
    }

    // 应用排序
    result.sort((a, b) => {
      let cmp = 0

      switch (sort.field) {
        case 'email':
          cmp = a.email.localeCompare(b.email)
          break
        case 'nickname':
          cmp = (a.nickname ?? '').localeCompare(b.nickname ?? '')
          break
        case 'subscription':
          cmp = a.subscription.type.localeCompare(b.subscription.type)
          break
        case 'usage':
          cmp = a.usage.percentUsed - b.usage.percentUsed
          break
        case 'daysRemaining':
          cmp = (a.subscription.daysRemaining ?? 999) - (b.subscription.daysRemaining ?? 999)
          break
        case 'lastUsedAt':
          cmp = a.lastUsedAt - b.lastUsedAt
          break
        case 'createdAt':
          cmp = a.createdAt - b.createdAt
          break
        case 'status':
          cmp = a.status.localeCompare(b.status)
          break
      }

      return sort.order === 'desc' ? -cmp : cmp
    })

    // 写入缓存：下次相同输入直接命中
    _filterCache = { accounts, filter, sort, activeGroupTab, output: result }
    return result
  },

  // ==================== 选择操作 ====================

  selectAccount: (id) => {
    set((state) => {
      const selectedIds = new Set(state.selectedIds)
      selectedIds.add(id)
      return { selectedIds }
    })
  },

  deselectAccount: (id) => {
    set((state) => {
      const selectedIds = new Set(state.selectedIds)
      selectedIds.delete(id)
      return { selectedIds }
    })
  },

  selectAll: () => {
    const filtered = get().getFilteredAccounts()
    set({ selectedIds: new Set(filtered.map((a) => a.id)) })
  },

  deselectAll: () => {
    set({ selectedIds: new Set() })
  },

  toggleSelection: (id) => {
    set((state) => {
      const selectedIds = new Set(state.selectedIds)
      if (selectedIds.has(id)) {
        selectedIds.delete(id)
      } else {
        selectedIds.add(id)
      }
      return { selectedIds }
    })
  },

  getSelectedAccounts: () => {
    const { accounts, selectedIds } = get()
    return Array.from(selectedIds)
      .map((id) => accounts.get(id))
      .filter((a): a is Account => a !== undefined)
  },

  // ==================== 导入导出 ====================

  exportAccounts: (ids) => {
    const { accounts, groups, tags } = get()

    let exportAccounts: Account[]
    if (ids?.length) {
      exportAccounts = ids
        .map((id) => accounts.get(id))
        .filter((a): a is Account => a !== undefined)
    } else {
      exportAccounts = Array.from(accounts.values())
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const data: AccountExportData = {
      version: get().appVersion,
      exportedAt: Date.now(),
      accounts: exportAccounts.map(({ isActive, ...rest }) => rest),
      groups: Array.from(groups.values()),
      tags: Array.from(tags.values())
    }

    return data
  },

  importAccounts: (items) => {
    const result: BatchOperationResult = { success: 0, failed: 0, errors: [] }

    // 验证 idp 是否有效
    const validIdps = ['Google', 'Github', 'BuilderId'] as const
    const normalizeIdp = (idp?: string): IdpType => {
      if (!idp) return 'Google'
      const normalized = validIdps.find(v => v.toLowerCase() === idp.toLowerCase())
      return normalized || 'Google'
    }

    // 批量构造账号对象 + 一次 set，避免 N 次 new Map(O(n²)) 与 N 次 re-render
    const newAccounts: Account[] = []
    for (const item of items) {
      try {
        const now = Date.now()
        const id = uuidv4()
        const machineId = generateRandomMachineId()

        const account: Account = {
          id,
          createdAt: now,
          isActive: false,
          machineId,
          email: item.email,
          password: item.password,
          nickname: item.nickname,
          idp: normalizeIdp(item.idp as string),
          credentials: {
            accessToken: item.accessToken || '',
            csrfToken: item.csrfToken || '',
            refreshToken: item.refreshToken,
            clientId: item.clientId,
            clientSecret: item.clientSecret,
            region: item.region || 'us-east-1',
            expiresAt: now + 3600 * 1000
          },
          subscription: {
            type: 'Free'
          },
          usage: {
            current: 0,
            limit: 25,
            percentUsed: 0,
            lastUpdated: now
          },
          groupId: item.groupId,
          tags: item.tags ?? [],
          status: 'unknown',
          lastUsedAt: now
        }
        newAccounts.push(account)
        result.success++
      } catch (error) {
        result.failed++
        result.errors.push({
          id: item.email,
          error: error instanceof Error ? error.message : 'Unknown error'
        })
      }
    }

    if (newAccounts.length > 0) {
      set((state) => {
        // 仅一次完整 Map 复制
        const accounts = new Map(state.accounts)
        for (const account of newAccounts) {
          accounts.set(account.id, account)
        }
        return { accounts }
      })
      // 防抖触发一次持久化
      get().saveToStorage()
    }

    return result
  },

  importFromExportData: (data) => {
    const result: BatchOperationResult = { success: 0, failed: 0, errors: [] }
    const { accounts: existingAccounts } = get()
    
    // 检查账户是否已存在（同邮箱+同provider 或 同userId 才算重复）
    const isAccountExists = (email: string, userId?: string, provider?: string): boolean => {
      return Array.from(existingAccounts.values()).some(acc => {
        // userId 相同则重复
        if (userId && acc.userId === userId) return true
        // email 相同且 provider 相同则重复（允许同邮箱不同登录方式）
        if (acc.email === email && acc.credentials.provider === provider) return true
        return false
      })
    }
    
    // 去重：文件内部去重
    const seenEmails = new Set<string>()
    const seenUserIds = new Set<string>()
    const uniqueAccounts = data.accounts.filter(acc => {
      if (seenEmails.has(acc.email) || (acc.userId && seenUserIds.has(acc.userId))) {
        return false
      }
      seenEmails.add(acc.email)
      if (acc.userId) seenUserIds.add(acc.userId)
      return true
    })

    // 收集所有变更，一次性 set，避免 N 次 new Map（O(n²)）
    let skipped = 0
    const accountsToAdd: Account[] = []

    for (const accountData of uniqueAccounts) {
      // 检查本地是否已存在（传入 provider 参数）
      if (isAccountExists(accountData.email, accountData.userId, accountData.credentials?.provider)) {
        skipped++
        continue
      }
      try {
        accountsToAdd.push({ ...accountData, isActive: false })
        result.success++
      } catch (error) {
        result.failed++
        result.errors.push({
          id: accountData.id,
          error: error instanceof Error ? error.message : 'Unknown error'
        })
      }
    }

    // 一次 set 应用所有分组、标签、账号 — 单次 re-render
    if (data.groups.length > 0 || data.tags.length > 0 || accountsToAdd.length > 0) {
      set((state) => {
        const groups = data.groups.length > 0 ? new Map(state.groups) : state.groups
        if (data.groups.length > 0) {
          for (const group of data.groups) groups.set(group.id, group)
        }
        const tags = data.tags.length > 0 ? new Map(state.tags) : state.tags
        if (data.tags.length > 0) {
          for (const tag of data.tags) tags.set(tag.id, tag)
        }
        const accounts = accountsToAdd.length > 0 ? new Map(state.accounts) : state.accounts
        if (accountsToAdd.length > 0) {
          for (const acc of accountsToAdd) accounts.set(acc.id, acc)
        }
        return { groups, tags, accounts }
      })
    }

    // 记录跳过数量
    if (skipped > 0) {
      result.errors.push({
        id: 'skipped',
        error: `跳过 ${skipped} 个已存在的账号`
      })
    }

    get().saveToStorage()
    return result
  },

  // ==================== 状态管理 ====================

  updateAccountStatus: (id, status, error) => {
    const wasBanned = isBannedAccountError(get().accounts.get(id)?.lastError)
    const isBanned = isBannedAccountError(error)
    set((state) => {
      const accounts = new Map(state.accounts)
      const account = accounts.get(id)
      if (account) {
        accounts.set(id, {
          ...account,
          status,
          lastError: error,
          lastCheckedAt: Date.now()
        })
      }
      return { accounts }
    })
    get().saveToStorage()
    // 触发 webhook：账号刚被封禁时通知（已封禁的不重复）
    if (isBanned && !wasBanned) {
      const acc = get().accounts.get(id)
      triggerWebhook('account-banned', {
        title: '账号被封禁',
        message: `账号 ${acc?.email || id} 状态变为封禁`,
        level: 'error',
        fields: { 邮箱: acc?.email || '-', 错误: error || '-' }
      })
    }
  },

  refreshAccountToken: async (id) => {
    const { accounts, updateAccountStatus } = get()
    const account = accounts.get(id)

    if (!account) return false

    updateAccountStatus(id, 'refreshing')

    try {
      // 通过主进程调用 Kiro API 刷新 Token（避免 CORS）
      const result = await window.api.refreshAccountToken(account)

      if (result.success && result.data) {
        set((state) => {
          const accounts = new Map(state.accounts)
          const acc = accounts.get(id)
          if (acc) {
            accounts.set(id, {
              ...acc,
              credentials: {
                ...acc.credentials,
                accessToken: result.data!.accessToken,
                // 如果返回了新的 refreshToken，更新它
                refreshToken: result.data!.refreshToken || acc.credentials.refreshToken,
                expiresAt: Date.now() + result.data!.expiresIn * 1000
              },
              status: 'active',
              lastError: undefined,
              lastCheckedAt: Date.now()
            })
          }
          return { accounts }
        })
        get().saveToStorage()
        return true
      } else {
        updateAccountStatus(id, 'error', result.error?.message)
        // 触发 webhook：Token 刷新失败
        triggerWebhook('token-expired', {
          title: 'Token 刷新失败',
          message: `账号 ${account.email} Token 刷新失败`,
          level: 'warn',
          fields: { 邮箱: account.email, 错误: result.error?.message || '-' }
        })
        return false
      }
    } catch (error) {
      updateAccountStatus(id, 'error', error instanceof Error ? error.message : 'Unknown error')
      return false
    }
  },

  batchRefreshTokens: async (ids) => {
    const { accounts, autoRefreshConcurrency } = get()
    
    // 收集需要刷新的账号
    const accountsToRefresh: Array<{
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
    }> = []

    for (const id of ids) {
      const account = accounts.get(id)
      if (!account?.credentials.refreshToken) continue
      
      accountsToRefresh.push({
        id,
        email: account.email,
        credentials: {
          refreshToken: account.credentials.refreshToken,
          clientId: account.credentials.clientId,
          clientSecret: account.credentials.clientSecret,
          region: account.credentials.region,
          authMethod: account.credentials.authMethod,
          accessToken: account.credentials.accessToken
        }
      })
    }

    if (accountsToRefresh.length === 0) {
      return { success: 0, failed: 0, errors: [] }
    }

    console.log(`[BatchRefresh] Triggering background refresh for ${accountsToRefresh.length} accounts...`)
    
    // 使用后台刷新 API（不阻塞 UI）
    const result = await window.api.backgroundBatchRefresh(accountsToRefresh, autoRefreshConcurrency)
    
    return { 
      success: result.successCount, 
      failed: result.failedCount, 
      errors: [] 
    }
  },

  checkAccountStatus: async (id) => {
    const { accounts, updateAccountStatus } = get()
    const account = accounts.get(id)

    if (!account) return

    // 设置刷新状态，提供视觉反馈
    updateAccountStatus(id, 'refreshing')

    try {
      // 通过主进程调用 Kiro API 获取状态（避免 CORS）
      const result = await window.api.checkAccountStatus(account)

      if (result.success && result.data) {
        set((state) => {
          const accounts = new Map(state.accounts)
          const acc = accounts.get(id)
          if (acc) {
            // 如果 token 被刷新，更新凭证
            const updatedCredentials = result.data!.newCredentials 
              ? {
                  ...acc.credentials,
                  accessToken: result.data!.newCredentials.accessToken,
                  refreshToken: result.data!.newCredentials.refreshToken ?? acc.credentials.refreshToken,
                  expiresAt: result.data!.newCredentials.expiresAt ?? acc.credentials.expiresAt
                }
              : acc.credentials

            // 合并 usage 数据，确保包含所有必要字段
            const apiUsage = result.data!.usage
            const mergedUsage = apiUsage ? {
              current: apiUsage.current ?? acc.usage.current,
              limit: apiUsage.limit ?? acc.usage.limit,
              percentUsed: apiUsage.limit > 0 ? apiUsage.current / apiUsage.limit : 0,
              lastUpdated: apiUsage.lastUpdated ?? Date.now(),
              baseLimit: apiUsage.baseLimit,
              baseCurrent: apiUsage.baseCurrent,
              freeTrialLimit: apiUsage.freeTrialLimit,
              freeTrialCurrent: apiUsage.freeTrialCurrent,
              freeTrialExpiry: apiUsage.freeTrialExpiry,
              bonuses: apiUsage.bonuses,
              nextResetDate: apiUsage.nextResetDate,
              resourceDetail: apiUsage.resourceDetail
            } : acc.usage

            // 合并订阅信息
            const apiSub = result.data!.subscription
            const mergedSubscription = apiSub ? {
              ...acc.subscription,
              ...apiSub
            } : acc.subscription

            // 转换 IDP 类型（保持原值优先，只有明确匹配时才更新）
            const apiIdp = result.data!.idp
            let idpType = acc.idp
            if (apiIdp) {
              if (apiIdp === 'BuilderId') idpType = 'BuilderId'
              else if (apiIdp === 'Google') idpType = 'Google'
              else if (apiIdp === 'Github') idpType = 'Github'
              else if (apiIdp === 'AWSIdC') idpType = 'AWSIdC'
              else if (apiIdp === 'Enterprise' || apiIdp === 'Internal') idpType = 'Enterprise'
              // 未知类型保持原值，不强制改为 Internal
            }

            accounts.set(id, {
              ...acc,
              // 更新邮箱（如果 API 返回了）
              email: result.data!.email ?? acc.email,
              userId: result.data!.userId ?? acc.userId,
              idp: idpType,
              status: result.data!.status as AccountStatus,
              usage: mergedUsage,
              subscription: mergedSubscription as AccountSubscription,
              credentials: updatedCredentials,
              lastCheckedAt: Date.now(),
              lastError: undefined
            })
          }
          return { accounts }
        })
        get().saveToStorage()
        
        // 如果刷新了 token，打印日志
        if (result.data.newCredentials) {
          console.log(`[Account] Token refreshed for ${account?.email}`)
        }
      } else {
        // 检查是否是封禁错误
        const isBanned = (result.error as { isBanned?: boolean })?.isBanned
        if (isBanned) {
          // 封禁账户：设置错误状态并标记为封禁
          updateAccountStatus(id, 'error', `账户已封禁: ${result.error?.message}`)
        } else {
          updateAccountStatus(id, 'error', result.error?.message)
        }
      }
    } catch (error) {
      updateAccountStatus(id, 'error', error instanceof Error ? error.message : 'Unknown error')
    }
  },

  batchCheckStatus: async (ids) => {
    const { accounts, autoRefreshConcurrency } = get()
    
    // 收集需要检查的账号（使用批量检查 API，不刷新 Token）
    const accountsToCheck: Array<{
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
    }> = []

    for (const id of ids) {
      const account = accounts.get(id)
      if (!account?.credentials.accessToken) continue
      
      accountsToCheck.push({
        id,
        email: account.email,
        credentials: {
          accessToken: account.credentials.accessToken,
          refreshToken: account.credentials.refreshToken,
          clientId: account.credentials.clientId,
          clientSecret: account.credentials.clientSecret,
          region: account.credentials.region,
          authMethod: account.credentials.authMethod,
          provider: account.credentials.provider
        },
        idp: account.idp
      })
    }

    if (accountsToCheck.length === 0) {
      return { success: 0, failed: 0, errors: [] }
    }

    console.log(`[BatchCheck] Triggering background check for ${accountsToCheck.length} accounts...`)
    
    // 使用后台检查 API（只检查状态，不刷新 Token）
    const result = await window.api.backgroundBatchCheck(accountsToCheck, autoRefreshConcurrency)
    
    return { 
      success: result.successCount, 
      failed: result.failedCount, 
      errors: [] 
    }
  },

  // ==================== 统计 ====================

  getStats: () => {
    const { accounts } = get()

    // 引用缓存命中：避免每次重渲染重新 O(n) 遍历
    if (_statsCache && _statsCache.accounts === accounts) {
      return _statsCache.output
    }

    const accountList = Array.from(accounts.values())

    const stats: AccountStats = {
      total: accountList.length,
      byStatus: {
        active: 0,
        expired: 0,
        error: 0,
        refreshing: 0,
        unknown: 0
      },
      bySubscription: {
        Free: 0,
        Pro: 0,
        Pro_Plus: 0,
        Enterprise: 0,
        Teams: 0
      },
      byIdp: {
        Google: 0,
        Github: 0,
        BuilderId: 0,
        Enterprise: 0,
        AWSIdC: 0,
        Internal: 0,
        IAM_SSO: 0
      },
      activeCount: 0,
      expiringSoonCount: 0,
      bannedCount: 0
    }

    for (const account of accountList) {
      stats.byStatus[account.status]++
      stats.bySubscription[account.subscription.type]++
      stats.byIdp[account.idp]++

      if (account.isActive) stats.activeCount++
      if (account.subscription.daysRemaining !== undefined &&
          account.subscription.daysRemaining <= 7) {
        stats.expiringSoonCount++
      }
      // 统计封禁账号
      if (isBannedAccountError(account.lastError)) {
        stats.bannedCount++
      }
    }

    _statsCache = { accounts, output: stats }
    return stats
  },

  // ==================== 持久化 ====================

  loadFromStorage: async () => {
    set({ isLoading: true })

    try {
      // 获取应用版本号
      const appVersion = await window.api.getAppVersion()
      set({ appVersion })

      const data = await window.api.loadAccounts()

      if (data) {
        const accounts = new Map(Object.entries(data.accounts ?? {}) as [string, Account][])
        const activeAccountId = data.activeAccountId ?? null

        // 为没有 machineId 的现有账户生成一个
        let needsSave = false
        for (const [id, account] of accounts) {
          if (!account.machineId) {
            account.machineId = generateRandomMachineId()
            accounts.set(id, account)
            needsSave = true
            console.log(`[Store] Generated machineId for account ${account.email}: ${account.machineId.substring(0, 16)}...`)
          }
        }

        // 根据 activeAccountId 重新同步所有账号的 isActive 状态，确保只有一个账号为激活状态
        for (const [id, account] of accounts) {
          const shouldBeActive = id === activeAccountId
          if (account.isActive !== shouldBeActive) {
            accounts.set(id, { ...account, isActive: shouldBeActive })
          }
        }

        set({
          accounts,
          groups: new Map(Object.entries(data.groups ?? {}) as [string, AccountGroup][]),
          tags: new Map(Object.entries(data.tags ?? {}) as [string, AccountTag][]),
          activeAccountId,
          autoRefreshEnabled: data.autoRefreshEnabled ?? true,
          autoRefreshInterval: data.autoRefreshInterval ?? 5,
          autoRefreshConcurrency: data.autoRefreshConcurrency ?? 100,
          autoRefreshSyncInfo: data.autoRefreshSyncInfo ?? true,
          statusCheckInterval: data.statusCheckInterval ?? 60,
          privacyMode: data.privacyMode ?? false,
          usagePrecision: data.usagePrecision ?? false,
          proxyEnabled: data.proxyEnabled ?? false,
          proxyUrl: data.proxyUrl ?? '',
          autoSwitchEnabled: data.autoSwitchEnabled ?? false,
          autoSwitchThreshold: data.autoSwitchThreshold ?? 0,
          autoSwitchInterval: data.autoSwitchInterval ?? 5,
          switchTarget: data.switchTarget ?? 'ide',
          theme: data.theme ?? 'default',
          darkMode: data.darkMode ?? false,
          language: data.language ?? 'auto',
          machineIdConfig: data.machineIdConfig ?? {
            autoSwitchOnAccountChange: false,
            bindMachineIdToAccount: false,
            useBindedMachineId: true
          },
          accountMachineIds: data.accountMachineIds ?? {},
          machineIdHistory: data.machineIdHistory ?? [],
          proxyPool: data.proxyPool
            ? new Map(Object.entries(data.proxyPool as Record<string, ProxyEntry>))
            : new Map<string, ProxyEntry>(),
          proxyPoolConfig: { ...DEFAULT_PROXY_POOL_CONFIG, ...(data.proxyPoolConfig as Partial<ProxyPoolConfig> | undefined) },
          proxyPoolCursor: typeof data.proxyPoolCursor === 'number' ? data.proxyPoolCursor : 0,
          accountProxyBindings: (data.accountProxyBindings as Record<string, string> | undefined) || {}
        })

        // 应用主题
        get().applyTheme()

        // 如果代理已启用，通过 store 的 setProxy（会自动 normalize URL 并回写 UI）
        if (data.proxyEnabled && data.proxyUrl) {
          void get().setProxy(true, data.proxyUrl)
        }

        // 如果自动换号已启用，启动定时器
        if (data.autoSwitchEnabled) {
          get().startAutoSwitch()
        }

        // 启动定时自动保存（防止数据丢失）
        get().startAutoSave()

        // 如果生成了新的 machineId，保存到存储
        if (needsSave) {
          console.log('[Store] Saving accounts with newly generated machineIds')
          get().saveToStorage()
        }

        // SSO 同步（含潜在网络请求）异步执行，不阻塞首屏加载
        // 完成后通过 set 应用结果，UI 会自然更新
        queueMicrotask(() => { void syncLocalSsoAccountAsync(get, set) })
      }
    } catch (error) {
      console.error('Failed to load accounts:', error)
    } finally {
      set({ isLoading: false })
    }
  },

  /**
   * 防抖触发持久化：连续 mutation 在 SAVE_DEBOUNCE_MS 内只写盘一次。
   * 调用方仍可 await 该 Promise；返回的 Promise 会在防抖窗口结束并完成实际落盘后 resolve。
   * 用于消除高频更新场景（如 1000 账号后台刷新风暴）下的 IPC/IO 抖动。
   */
  saveToStorage: async () => {
    return new Promise<void>((resolve) => {
      if (saveDebounceTimer) clearTimeout(saveDebounceTimer)
      saveDebounceTimer = setTimeout(async () => {
        saveDebounceTimer = null
        await get().flushSaveImmediately()
        resolve()
      }, SAVE_DEBOUNCE_MS)
    })
  },

  /**
   * 立即落盘（跳过防抖）。用于 beforeunload、关键操作前后强制持久化场景。
   * 并发调用会自动等待同一次 in-flight 保存，避免重入。
   */
  flushSaveImmediately: async () => {
    if (saveDebounceTimer) {
      clearTimeout(saveDebounceTimer)
      saveDebounceTimer = null
    }
    if (saveInFlight) return saveInFlight

    const {
      accounts,
      groups,
      tags,
      activeAccountId,
      autoRefreshEnabled,
      autoRefreshInterval,
      autoRefreshConcurrency,
      statusCheckInterval,
      privacyMode,
      usagePrecision,
      proxyEnabled,
      proxyUrl,
      autoSwitchEnabled,
      autoSwitchThreshold,
      autoSwitchInterval,
      switchTarget,
      theme,
      darkMode,
      language,
      machineIdConfig,
      accountMachineIds,
      machineIdHistory,
      proxyPool,
      proxyPoolConfig,
      proxyPoolCursor,
      accountProxyBindings
    } = get()

    set({ isSyncing: true })

    saveInFlight = (async () => {
      try {
        await window.api.saveAccounts({
          accounts: Object.fromEntries(accounts),
          groups: Object.fromEntries(groups),
          tags: Object.fromEntries(tags),
          activeAccountId,
          autoRefreshEnabled,
          autoRefreshInterval,
          autoRefreshConcurrency,
          statusCheckInterval,
          privacyMode,
          usagePrecision,
          proxyEnabled,
          proxyUrl,
          autoSwitchEnabled,
          autoSwitchThreshold,
          autoSwitchInterval,
          switchTarget,
          theme,
          darkMode,
          language,
          machineIdConfig,
          accountMachineIds,
          machineIdHistory,
          proxyPool: Object.fromEntries(proxyPool),
          proxyPoolConfig,
          proxyPoolCursor,
          accountProxyBindings
        })
      } catch (error) {
        console.error('Failed to save accounts:', error)
      } finally {
        set({ isSyncing: false })
        saveInFlight = null
      }
    })()

    return saveInFlight
  },

  // ==================== 设置 ====================

  setAutoRefresh: (enabled, interval) => {
    set({
      autoRefreshEnabled: enabled,
      autoRefreshInterval: interval ?? get().autoRefreshInterval
    })
    get().saveToStorage()
    
    // 重新启动定时器
    if (enabled) {
      get().startAutoTokenRefresh()
    } else {
      get().stopAutoTokenRefresh()
    }
  },

  setAutoRefreshConcurrency: (concurrency) => {
    set({ autoRefreshConcurrency: Math.max(1, Math.min(500, concurrency)) })
    get().saveToStorage()
  },

  setAutoRefreshSyncInfo: (enabled) => {
    set({ autoRefreshSyncInfo: enabled })
    get().saveToStorage()
  },

  setStatusCheckInterval: (interval) => {
    set({ statusCheckInterval: interval })
    get().saveToStorage()
  },

  // ==================== 隐私模式 ====================

  setPrivacyMode: (enabled) => {
    set({ privacyMode: enabled })
    get().saveToStorage()
  },

  maskEmail: (email) => {
    if (!get().privacyMode || !email) return email
    // 生成固定长度的随机字符串作为伪装邮箱
    const hash = email.split('').reduce((acc, char) => acc + char.charCodeAt(0), 0)
    const maskedName = `user${(hash % 100000).toString().padStart(5, '0')}`
    return `${maskedName}@***.com`
  },

  maskNickname: (nickname) => {
    if (!get().privacyMode || !nickname) return nickname || ''
    // 基于原始昵称生成固定的伪装昵称
    const hash = nickname.split('').reduce((acc, char) => acc + char.charCodeAt(0), 0)
    return `用户${(hash % 100000).toString().padStart(5, '0')}`
  },

  // ==================== 使用量精度 ====================

  setUsagePrecision: (enabled) => {
    set({ usagePrecision: enabled })
    get().saveToStorage()
  },

  // ==================== 代理设置 ====================

  setProxy: async (enabled, url) => {
    const targetUrl = url ?? get().proxyUrl
    set({ 
      proxyEnabled: enabled,
      proxyUrl: targetUrl
    })
    get().saveToStorage()
    // 通知主进程更新代理设置，并用规范化后的 URL 回写 store
    try {
      const result = await window.api.setProxy?.(enabled, targetUrl)
      if (result?.normalizedUrl && result.normalizedUrl !== targetUrl) {
        set({ proxyUrl: result.normalizedUrl })
        get().saveToStorage()
      }
    } catch (err) {
      console.error('[Store] setProxy IPC failed:', err)
    }
  },

  // ==================== 主题设置 ====================

  setTheme: (theme) => {
    set({ theme })
    get().saveToStorage()
    get().applyTheme()
  },

  setDarkMode: (enabled) => {
    set({ darkMode: enabled })
    get().saveToStorage()
    get().applyTheme()
  },

  // ==================== 语言设置 ====================

  setLanguage: (language) => {
    set({ language })
    get().saveToStorage()
    // 更新托盘菜单语言
    const actualLang = language === 'auto' 
      ? (navigator.language.startsWith('zh') ? 'zh' : 'en')
      : language
    window.api.updateTrayLanguage(actualLang)
  },

  applyTheme: () => {
    const { theme, darkMode } = get()
    const root = document.documentElement
    
    // 移除所有主题类（包含所有 32 个主题）
    root.classList.remove(
      'dark', 
      // 蓝色系
      'theme-indigo', 'theme-cyan', 'theme-sky', 'theme-teal',
      // 紫红系
      'theme-purple', 'theme-violet', 'theme-fuchsia', 'theme-pink', 'theme-rose',
      // 暖色系
      'theme-red', 'theme-orange', 'theme-amber', 'theme-yellow',
      // 绿色系
      'theme-emerald', 'theme-green', 'theme-lime',
      // 中性色
      'theme-slate', 'theme-zinc', 'theme-stone', 'theme-neutral',
      // 奢华配色
      'theme-gold', 'theme-navy', 'theme-wine', 'theme-champagne',
      // 莫兰迪
      'theme-dustyblue', 'theme-terracotta', 'theme-sage', 'theme-mauve',
      // 自然深色
      'theme-coral', 'theme-forest', 'theme-ocean'
    )
    
    // 应用深色模式
    if (darkMode) {
      root.classList.add('dark')
    }
    
    // 应用主题颜色
    if (theme !== 'default') {
      root.classList.add(`theme-${theme}`)
    }
  },

  // ==================== 自动换号 ====================

  setAutoSwitch: (enabled, threshold, interval) => {
    set({
      autoSwitchEnabled: enabled,
      autoSwitchThreshold: threshold ?? get().autoSwitchThreshold,
      autoSwitchInterval: interval ?? get().autoSwitchInterval
    })
    get().saveToStorage()
    
    // 重新启动定时器
    if (enabled) {
      get().startAutoSwitch()
    } else {
      get().stopAutoSwitch()
    }
  },

  setBatchImportConcurrency: (concurrency) => {
    set({ batchImportConcurrency: Math.max(1, Math.min(500, concurrency)) })
    get().saveToStorage()
  },

  setLoginPrivateMode: (enabled) => {
    set({ loginPrivateMode: enabled })
    get().saveToStorage()
  },

  setSwitchTarget: (target) => {
    set({ switchTarget: target })
    get().saveToStorage()
  },

  startAutoSwitch: () => {
    const { autoSwitchEnabled, autoSwitchInterval, checkAndAutoSwitch } = get()
    
    if (!autoSwitchEnabled) return
    
    // 清除现有定时器
    if (autoSwitchTimer) {
      clearInterval(autoSwitchTimer)
    }
    
    // 立即检查一次
    checkAndAutoSwitch()
    
    // 设置定时检查
    autoSwitchTimer = setInterval(() => {
      checkAndAutoSwitch()
    }, autoSwitchInterval * 60 * 1000)
    
    console.log(`[AutoSwitch] Started with interval: ${autoSwitchInterval} minutes`)
  },

  stopAutoSwitch: () => {
    if (autoSwitchTimer) {
      clearInterval(autoSwitchTimer)
      autoSwitchTimer = null
      console.log('[AutoSwitch] Stopped')
    }
  },

  checkAndAutoSwitch: async () => {
    const { accounts, autoSwitchThreshold, checkAccountStatus, setActiveAccount } = get()
    const activeAccount = get().getActiveAccount()
    
    if (!activeAccount) {
      console.log('[AutoSwitch] No active account')
      return
    }

    console.log(`[AutoSwitch] Checking active account: ${activeAccount.email}`)

    // 刷新当前账号状态获取最新余额
    await checkAccountStatus(activeAccount.id)
    
    // 重新获取更新后的账号信息
    const updatedAccount = get().accounts.get(activeAccount.id)
    if (!updatedAccount) return

    const remaining = updatedAccount.usage.limit - updatedAccount.usage.current
    console.log(`[AutoSwitch] Remaining: ${remaining}, Threshold: ${autoSwitchThreshold}`)

    // 检查是否需要切换
    if (remaining <= autoSwitchThreshold) {
      console.log(`[AutoSwitch] Account ${updatedAccount.email} reached threshold, switching...`)
      
      // 查找可用的账号
      const availableAccount = Array.from(accounts.values()).find(acc => {
        // 排除当前账号
        if (acc.id === activeAccount.id) return false
        // 排除被封禁的账号
        if (isBannedAccountError(acc.lastError)) return false
        // 排除余额不足的账号
        const accRemaining = acc.usage.limit - acc.usage.current
        if (accRemaining <= autoSwitchThreshold) return false
        return true
      })

      if (availableAccount) {
        console.log(`[AutoSwitch] Switching to: ${availableAccount.email}`)
        setActiveAccount(availableAccount.id)
        // 根据 switchTarget 设置决定切换目标
        const { switchTarget: target } = get()
        const creds = availableAccount.credentials
        if (target === 'ide' || target === 'both') {
          await window.api.switchAccount({
            accessToken: creds.accessToken || '',
            refreshToken: creds.refreshToken || '',
            clientId: creds.clientId || '',
            clientSecret: creds.clientSecret || '',
            region: creds.region || 'us-east-1',
            startUrl: creds.startUrl,
            authMethod: creds.authMethod,
            provider: creds.provider,
            profileArn: (availableAccount as { profileArn?: string }).profileArn
          })
        }
        if (target === 'cli' || target === 'both') {
          window.api.switchAccountCli?.({
            accessToken: creds.accessToken || '',
            refreshToken: creds.refreshToken || '',
            clientId: creds.clientId,
            clientSecret: creds.clientSecret,
            region: creds.region || 'us-east-1',
            profileArn: (availableAccount as { profileArn?: string }).profileArn,
            provider: creds.provider
          }).catch(err => console.warn('[AutoSwitch CLI] Failed:', err))
        }
      } else {
        console.log('[AutoSwitch] No available account to switch to')
      }
    }
  },

  // ==================== 自动 Token 刷新 ====================

  checkAndRefreshExpiringTokens: async () => {
    const { accounts, refreshAccountToken, checkAccountStatus, autoSwitchEnabled, autoRefreshConcurrency, autoRefreshSyncInfo } = get()
    const now = Date.now()

    console.log(`[AutoRefresh] Checking ${accounts.size} accounts... (syncInfo: ${autoRefreshSyncInfo}, autoSwitch: ${autoSwitchEnabled})`)

    // 筛选需要处理的账号
    const accountsToProcess: Array<{ id: string; email: string; needsTokenRefresh: boolean }> = []
    
    for (const [id, account] of accounts) {
      // 跳过已封禁或错误状态的账号
      if (isBannedAccountError(account.lastError)) {
        console.log(`[AutoRefresh] Skipping ${account.email} (banned/error)`)
        continue
      }

      const expiresAt = account.credentials.expiresAt
      const timeUntilExpiry = expiresAt ? expiresAt - now : Infinity
      const needsTokenRefresh = expiresAt && timeUntilExpiry <= TOKEN_REFRESH_BEFORE_EXPIRY

      accountsToProcess.push({ id, email: account.email, needsTokenRefresh: !!needsTokenRefresh })
    }

    console.log(`[AutoRefresh] Processing ${accountsToProcess.length} accounts...`)

    // 并发控制：使用配置的并发数，避免卡顿
    const BATCH_SIZE = autoRefreshConcurrency
    let successCount = 0
    let failCount = 0

    for (let i = 0; i < accountsToProcess.length; i += BATCH_SIZE) {
      const batch = accountsToProcess.slice(i, i + BATCH_SIZE)
      const results = await Promise.allSettled(
        batch.map(async ({ id, email, needsTokenRefresh }) => {
          try {
            if (needsTokenRefresh) {
              console.log(`[AutoRefresh] Refreshing token for ${email}...`)
              await refreshAccountToken(id)
              console.log(`[AutoRefresh] Token for ${email} refreshed`)
              // Token 刷新后同步刷新账户信息
              await checkAccountStatus(id)
              console.log(`[AutoRefresh] Account info for ${email} updated`)
            } else if (autoRefreshSyncInfo || autoSwitchEnabled) {
              // 开启同步检测账户信息或自动换号时，刷新账户信息
              await checkAccountStatus(id)
              console.log(`[AutoRefresh] Account info for ${email} updated`)
            }
            return { email, success: true }
          } catch (e) {
            console.error(`[AutoRefresh] Failed for ${email}:`, e)
            return { email, success: false, error: e }
          }
        })
      )
      
      successCount += results.filter(r => r.status === 'fulfilled' && r.value.success).length
      failCount += results.length - results.filter(r => r.status === 'fulfilled' && r.value.success).length
      
      // 批次间延迟
      if (i + BATCH_SIZE < accountsToProcess.length) {
        await new Promise(resolve => setTimeout(resolve, 200))
      }
    }

    console.log(`[AutoRefresh] Completed: ${successCount} success, ${failCount} failed`)
  },

  // 仅刷新失效的 Token（不刷新账户信息）
  refreshExpiredTokensOnly: async () => {
    const { accounts, refreshAccountToken, autoRefreshConcurrency } = get()
    const now = Date.now()

    // 筛选需要刷新 Token 的账号
    const expiredAccounts: Array<{ id: string; email: string }> = []
    
    for (const [id, account] of accounts) {
      // 跳过已封禁或错误状态的账号
      if (isBannedAccountError(account.lastError)) {
        continue
      }

      const expiresAt = account.credentials.expiresAt
      const timeUntilExpiry = expiresAt ? expiresAt - now : Infinity
      
      // Token 已过期或即将过期
      if (expiresAt && timeUntilExpiry <= TOKEN_REFRESH_BEFORE_EXPIRY) {
        expiredAccounts.push({ id, email: account.email })
      }
    }

    if (expiredAccounts.length === 0) {
      console.log('[AutoRefresh] No expired tokens found')
      return
    }

    console.log(`[AutoRefresh] Refreshing ${expiredAccounts.length} expired tokens...`)

    // 并发控制：使用配置的并发数，避免卡顿
    const BATCH_SIZE = autoRefreshConcurrency
    for (let i = 0; i < expiredAccounts.length; i += BATCH_SIZE) {
      const batch = expiredAccounts.slice(i, i + BATCH_SIZE)
      await Promise.allSettled(
        batch.map(async ({ id, email }) => {
          try {
            await refreshAccountToken(id)
            console.log(`[AutoRefresh] Token for ${email} refreshed`)
          } catch (e) {
            console.error(`[AutoRefresh] Failed to refresh token for ${email}:`, e)
          }
        })
      )
      // 批次间延迟
      if (i + BATCH_SIZE < expiredAccounts.length) {
        await new Promise(resolve => setTimeout(resolve, 200))
      }
    }
  },

  startAutoTokenRefresh: () => {
    const { autoRefreshEnabled, autoRefreshInterval } = get()
    
    // 如果已有定时器，先停止
    if (tokenRefreshTimer) {
      clearInterval(tokenRefreshTimer)
      tokenRefreshTimer = null
    }
    
    // 如果未启用，不启动定时器
    if (!autoRefreshEnabled) {
      console.log('[AutoRefresh] Auto-refresh is disabled')
      return
    }

    // 启动时触发后台刷新（在主进程执行，不阻塞 UI）
    get().triggerBackgroundRefresh()

    // 使用用户设置的间隔（分钟转毫秒）
    const intervalMs = autoRefreshInterval * 60 * 1000
    tokenRefreshTimer = setInterval(() => {
      get().triggerBackgroundRefresh()
    }, intervalMs)

    console.log(`[AutoRefresh] Token auto-refresh started with interval: ${autoRefreshInterval} minutes`)
  },

  stopAutoTokenRefresh: () => {
    if (tokenRefreshTimer) {
      clearInterval(tokenRefreshTimer)
      tokenRefreshTimer = null
      console.log('[AutoRefresh] Token auto-refresh stopped')
    }
  },

  // 触发后台刷新（在主进程执行，不阻塞 UI）
  triggerBackgroundRefresh: async () => {
    const { accounts, autoRefreshConcurrency, autoRefreshSyncInfo, autoSwitchEnabled } = get()
    const now = Date.now()

    // 筛选需要处理的账号
    const accountsToRefresh: Array<{
      id: string
      email: string
      idp?: string
      needsTokenRefresh: boolean
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
    }> = []
    
    for (const [id, account] of accounts) {
      // 跳过已封禁或错误状态的账号
      if (isBannedAccountError(account.lastError)) {
        continue
      }

      const expiresAt = account.credentials.expiresAt
      const timeUntilExpiry = expiresAt ? expiresAt - now : Infinity
      const needsTokenRefresh = expiresAt && timeUntilExpiry <= TOKEN_REFRESH_BEFORE_EXPIRY
      
      // Token 即将过期需要刷新，或开启了同步检测/自动换号需要检查账户信息
      if (needsTokenRefresh || autoRefreshSyncInfo || autoSwitchEnabled) {
        accountsToRefresh.push({
          id,
          email: account.email,
          idp: account.idp,
          needsTokenRefresh: !!needsTokenRefresh,
          machineId: account.machineId,  // 传递账户绑定的设备 ID
          credentials: {
            refreshToken: account.credentials.refreshToken || '',
            clientId: account.credentials.clientId,
            clientSecret: account.credentials.clientSecret,
            region: account.credentials.region,
            authMethod: account.credentials.authMethod,
            accessToken: account.credentials.accessToken,
            provider: account.credentials.provider
          }
        })
      }
    }

    if (accountsToRefresh.length === 0) {
      console.log('[BackgroundRefresh] No accounts need processing')
      return
    }

    console.log(`[BackgroundRefresh] Triggering refresh for ${accountsToRefresh.length} accounts (syncInfo: ${autoRefreshSyncInfo})...`)
    
    // 调用主进程后台刷新，不等待结果（通过 IPC 事件接收）
    window.api.backgroundBatchRefresh(accountsToRefresh, autoRefreshConcurrency, autoRefreshSyncInfo)
  },

  // 处理后台刷新结果（兼容入口；高频场景请走 applyBackgroundRefreshResults 批量）
  handleBackgroundRefreshResult: (data) => {
    get().applyBackgroundRefreshResults([data])
  },

  // 批量处理后台刷新结果：合并 N 条结果到一次 set，避免 N 次 Map 全量复制
  applyBackgroundRefreshResults: (items) => {
    if (!items || items.length === 0) return

    set((state) => {
      // 仅一次完整 Map 复制
      const accounts = new Map(state.accounts)
      const now = Date.now()

      for (const data of items) {
        const { id, success, data: resultData, error } = data
        const account = accounts.get(id)
        if (!account) continue

        if (!success) {
          accounts.set(id, {
            ...account,
            status: 'error',
            lastError: error,
            lastCheckedAt: now
          })
          continue
        }

        const refreshData = resultData as {
        accessToken?: string
        refreshToken?: string
        expiresIn?: number
        usage?: {
          current?: number
          limit?: number
          baseCurrent?: number
          baseLimit?: number
          freeTrialCurrent?: number
          freeTrialLimit?: number
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
        subscription?: { type?: string; title?: string; daysRemaining?: number; expiresAt?: number; overageCapability?: string; upgradeCapability?: string; subscriptionManagementTarget?: string }
        userInfo?: { email?: string; userId?: string }
        status?: string
        errorMessage?: string
      } | undefined

      // 检测封禁状态
      const newStatus = refreshData?.status === 'error' ? 'error' as AccountStatus : 'active' as AccountStatus
      const newError = refreshData?.errorMessage

      accounts.set(id, {
        ...account,
        credentials: {
          ...account.credentials,
          accessToken: refreshData?.accessToken || account.credentials.accessToken,
          refreshToken: refreshData?.refreshToken || account.credentials.refreshToken,
          expiresAt: refreshData?.expiresIn ? now + refreshData.expiresIn * 1000 : account.credentials.expiresAt
        },
        usage: refreshData?.usage ? (() => {
          const newCurrent = refreshData.usage.current ?? account.usage.current
          const newLimit = refreshData.usage.limit ?? account.usage.limit
          return {
            ...account.usage,
            current: newCurrent,
            limit: newLimit,
            percentUsed: newLimit > 0 ? newCurrent / newLimit : 0,
            baseCurrent: refreshData.usage.baseCurrent ?? account.usage.baseCurrent,
            baseLimit: refreshData.usage.baseLimit ?? account.usage.baseLimit,
            freeTrialCurrent: refreshData.usage.freeTrialCurrent ?? account.usage.freeTrialCurrent,
            freeTrialLimit: refreshData.usage.freeTrialLimit ?? account.usage.freeTrialLimit,
            freeTrialExpiry: refreshData.usage.freeTrialExpiry ?? account.usage.freeTrialExpiry,
            bonuses: refreshData.usage.bonuses ?? account.usage.bonuses,
            nextResetDate: refreshData.usage.nextResetDate ?? account.usage.nextResetDate,
            resourceDetail: refreshData.usage.resourceDetail ?? account.usage.resourceDetail,
            lastUpdated: now
          }
        })() : account.usage,
        subscription: refreshData?.subscription ? {
          ...account.subscription,
          type: (refreshData.subscription.type as SubscriptionType) || account.subscription.type,
          title: refreshData.subscription.title || account.subscription.title,
          daysRemaining: refreshData.subscription.daysRemaining ?? account.subscription.daysRemaining,
          expiresAt: refreshData.subscription.expiresAt ?? account.subscription.expiresAt,
          overageCapability: refreshData.subscription.overageCapability ?? account.subscription.overageCapability,
          upgradeCapability: refreshData.subscription.upgradeCapability ?? account.subscription.upgradeCapability,
          managementTarget: refreshData.subscription.subscriptionManagementTarget ?? account.subscription.managementTarget
        } : account.subscription,
        email: refreshData?.userInfo?.email || account.email,
        userId: refreshData?.userInfo?.userId || account.userId,
        status: newStatus,
        lastError: newError,
        lastCheckedAt: now
      })
      } // end for-loop

      return { accounts }
    })
  },

  // 处理后台检查结果（兼容入口；高频场景请走 applyBackgroundCheckResults 批量）
  handleBackgroundCheckResult: (data) => {
    get().applyBackgroundCheckResults([data])
  },

  // 批量处理后台检查结果：合并 N 条结果到一次 set
  applyBackgroundCheckResults: (items) => {
    if (!items || items.length === 0) return

    set((state) => {
      const accounts = new Map(state.accounts)
      const now = Date.now()

      for (const data of items) {
        const { id, success, data: resultData, error } = data
        const account = accounts.get(id)
        if (!account) continue

        if (!success) {
          accounts.set(id, {
            ...account,
            status: 'error',
            lastError: error,
            lastCheckedAt: now
          })
          continue
        }

        const checkData = resultData as {
        usage?: {
          current?: number
          limit?: number
          baseCurrent?: number
          baseLimit?: number
          freeTrialCurrent?: number
          freeTrialLimit?: number
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
        subscription?: { type?: string; title?: string; daysRemaining?: number; expiresAt?: number; overageCapability?: string; upgradeCapability?: string; subscriptionManagementTarget?: string }
        userInfo?: { email?: string; userId?: string }
        status?: string
        errorMessage?: string
        needsRefresh?: boolean
      } | undefined

      // 检测状态
      let newStatus: AccountStatus = 'active'
      if (checkData?.status === 'error') {
        newStatus = 'error'
      } else if (checkData?.status === 'expired' || checkData?.needsRefresh) {
        newStatus = 'expired'
      }
      const newError = checkData?.errorMessage

      accounts.set(id, {
        ...account,
        usage: checkData?.usage ? (() => {
          const newCurrent = checkData.usage.current ?? account.usage.current
          const newLimit = checkData.usage.limit ?? account.usage.limit
          return {
            ...account.usage,
            current: newCurrent,
            limit: newLimit,
            percentUsed: newLimit > 0 ? newCurrent / newLimit : 0,
            baseCurrent: checkData.usage.baseCurrent ?? account.usage.baseCurrent,
            baseLimit: checkData.usage.baseLimit ?? account.usage.baseLimit,
            freeTrialCurrent: checkData.usage.freeTrialCurrent ?? account.usage.freeTrialCurrent,
            freeTrialLimit: checkData.usage.freeTrialLimit ?? account.usage.freeTrialLimit,
            freeTrialExpiry: checkData.usage.freeTrialExpiry ?? account.usage.freeTrialExpiry,
            bonuses: checkData.usage.bonuses ?? account.usage.bonuses,
            nextResetDate: checkData.usage.nextResetDate ?? account.usage.nextResetDate,
            resourceDetail: checkData.usage.resourceDetail ?? account.usage.resourceDetail,
            lastUpdated: now
          }
        })() : account.usage,
        subscription: checkData?.subscription ? {
          ...account.subscription,
          type: (checkData.subscription.type as 'Free' | 'Pro' | 'Enterprise' | 'Teams') ?? account.subscription.type,
          title: checkData.subscription.title ?? account.subscription.title,
          daysRemaining: checkData.subscription.daysRemaining ?? account.subscription.daysRemaining,
          expiresAt: checkData.subscription.expiresAt ?? account.subscription.expiresAt,
          overageCapability: checkData.subscription.overageCapability ?? account.subscription.overageCapability,
          upgradeCapability: checkData.subscription.upgradeCapability ?? account.subscription.upgradeCapability,
          managementTarget: checkData.subscription.subscriptionManagementTarget ?? account.subscription.managementTarget
        } : account.subscription,
        email: checkData?.userInfo?.email || account.email,
        userId: checkData?.userInfo?.userId || account.userId,
        status: newStatus,
        lastError: newError,
        lastCheckedAt: now
      })
      } // end for-loop

      return { accounts }
    })
  },

  // ==================== 定时自动保存 ====================

  startAutoSave: () => {
    // 如果已有定时器，先停止
    if (autoSaveTimer) {
      clearInterval(autoSaveTimer)
    }

    // 计算当前数据的哈希值
    const computeHash = () => {
      const { accounts, groups, tags, activeAccountId } = get()
      return JSON.stringify({
        accounts: Object.fromEntries(accounts),
        groups: Object.fromEntries(groups),
        tags: Object.fromEntries(tags),
        activeAccountId
      })
    }

    // 初始化哈希值
    lastSaveHash = computeHash()

    // 设置定时保存
    autoSaveTimer = setInterval(async () => {
      const currentHash = computeHash()
      
      // 只有数据变化时才保存
      if (currentHash !== lastSaveHash) {
        console.log('[AutoSave] Data changed, saving...')
        await get().saveToStorage()
        lastSaveHash = currentHash
        console.log('[AutoSave] Data saved successfully')
      }
    }, AUTO_SAVE_INTERVAL)

    console.log(`[AutoSave] Auto-save started with interval: ${AUTO_SAVE_INTERVAL / 1000}s`)
  },

  stopAutoSave: () => {
    if (autoSaveTimer) {
      clearInterval(autoSaveTimer)
      autoSaveTimer = null
      console.log('[AutoSave] Auto-save stopped')
    }
  },

  // ==================== 机器码管理 ====================

  setMachineIdConfig: (config) => {
    set((state) => ({
      machineIdConfig: { ...state.machineIdConfig, ...config }
    }))
    get().saveToStorage()
  },

  refreshCurrentMachineId: async () => {
    try {
      const result = await window.api.machineIdGetCurrent()
      if (result.success && result.machineId) {
        set({ currentMachineId: result.machineId })
        
        // 首次获取时自动备份原始机器码
        const { originalMachineId } = get()
        if (!originalMachineId) {
          get().backupOriginalMachineId()
        }
      }
    } catch (error) {
      console.error('[MachineId] Failed to refresh current machine ID:', error)
    }
  },

  changeMachineId: async (newMachineId) => {
    const state = get()
    
    // 首次更改时备份原始机器码
    if (!state.originalMachineId) {
      state.backupOriginalMachineId()
    }

    // 生成新机器码（如果未提供）
    const machineIdToSet = newMachineId || await window.api.machineIdGenerateRandom()
    
    try {
      const result = await window.api.machineIdSet(machineIdToSet)
      
      if (result.success) {
        // 更新状态
        set((s) => ({
          currentMachineId: machineIdToSet,
          machineIdHistory: [
            ...s.machineIdHistory,
            {
              id: crypto.randomUUID(),
              machineId: machineIdToSet,
              timestamp: Date.now(),
              action: 'manual'
            }
          ]
        }))
        get().saveToStorage()
        return true
      } else if (result.requiresAdmin) {
        // 需要管理员权限，主进程会处理弹窗
        return false
      } else {
        console.error('[MachineId] Failed to change:', result.error)
        return false
      }
    } catch (error) {
      console.error('[MachineId] Error changing machine ID:', error)
      return false
    }
  },

  restoreOriginalMachineId: async () => {
    const { originalMachineId } = get()
    
    if (!originalMachineId) {
      console.warn('[MachineId] No original machine ID to restore')
      return false
    }

    try {
      const result = await window.api.machineIdSet(originalMachineId)
      
      if (result.success) {
        set((s) => ({
          currentMachineId: originalMachineId,
          machineIdHistory: [
            ...s.machineIdHistory,
            {
              id: crypto.randomUUID(),
              machineId: originalMachineId,
              timestamp: Date.now(),
              action: 'restore'
            }
          ]
        }))
        get().saveToStorage()
        return true
      }
      return false
    } catch (error) {
      console.error('[MachineId] Error restoring original machine ID:', error)
      return false
    }
  },

  bindMachineIdToAccount: (accountId, machineId) => {
    const account = get().accounts.get(accountId)
    if (!account) return

    // 生成或使用提供的机器码
    const boundMachineId = machineId || crypto.randomUUID()

    set((state) => ({
      accountMachineIds: {
        ...state.accountMachineIds,
        [accountId]: boundMachineId
      },
      machineIdHistory: [
        ...state.machineIdHistory,
        {
          id: crypto.randomUUID(),
          machineId: boundMachineId,
          timestamp: Date.now(),
          action: 'bind',
          accountId,
          accountEmail: account.email
        }
      ]
    }))
    get().saveToStorage()
  },

  getMachineIdForAccount: (accountId) => {
    return get().accountMachineIds[accountId] || null
  },

  backupOriginalMachineId: () => {
    const { currentMachineId, originalMachineId } = get()
    
    // 只有在没有备份且有当前机器码时才备份
    if (!originalMachineId && currentMachineId) {
      set({
        originalMachineId: currentMachineId,
        originalBackupTime: Date.now()
      })
      
      // 添加历史记录
      set((s) => ({
        machineIdHistory: [
          ...s.machineIdHistory,
          {
            id: crypto.randomUUID(),
            machineId: currentMachineId,
            timestamp: Date.now(),
            action: 'initial'
          }
        ]
      }))
      
      get().saveToStorage()
      console.log('[MachineId] Original machine ID backed up:', currentMachineId)
    }
  },

  clearMachineIdHistory: () => {
    set({ machineIdHistory: [] })
    get().saveToStorage()
  },

  // ==================== 代理池 ====================

  addProxy: (url, options) => {
    const parsed = parseProxyUrl(url)
    if (!parsed) return null

    // 去重：同 host:port 视为重复
    const existingPool = get().proxyPool
    for (const entry of existingPool.values()) {
      if (entry.host === parsed.host && entry.port === parsed.port && entry.protocol === parsed.protocol) {
        return null
      }
    }

    const id = uuidv4()
    const entry: ProxyEntry = {
      id,
      url: parsed.normalized,
      protocol: parsed.protocol,
      host: parsed.host,
      port: parsed.port,
      username: parsed.username,
      password: parsed.password,
      label: options?.label,
      source: options?.source ?? 'manual',
      tags: options?.tags,
      status: 'untested',
      usedCount: 0,
      failCount: 0,
      enabled: true,
      createdAt: Date.now()
    }

    set((state) => {
      const next = new Map(state.proxyPool)
      next.set(id, entry)
      return { proxyPool: next }
    })
    get().saveToStorage()
    return id
  },

  importProxies: (text) => {
    const result = { added: 0, skipped: 0, failed: 0 }
    const lines = text.split(/\r?\n/).map(l => l.trim()).filter(l => l && !l.startsWith('#'))
    if (lines.length === 0) return result

    // 批量构造新条目，最后只 set 一次，避免 O(n²) re-render
    const existingPool = get().proxyPool
    const existingKeys = new Set<string>()
    for (const entry of existingPool.values()) {
      existingKeys.add(`${entry.protocol}://${entry.host}:${entry.port}`)
    }
    const newEntries: ProxyEntry[] = []

    for (const line of lines) {
      const parsed = parseProxyUrl(line)
      if (!parsed) { result.failed++; continue }
      const key = `${parsed.protocol}://${parsed.host}:${parsed.port}`
      if (existingKeys.has(key)) { result.skipped++; continue }
      existingKeys.add(key)
      newEntries.push({
        id: uuidv4(),
        url: parsed.normalized,
        protocol: parsed.protocol,
        host: parsed.host,
        port: parsed.port,
        username: parsed.username,
        password: parsed.password,
        source: 'import',
        status: 'untested',
        usedCount: 0,
        failCount: 0,
        enabled: true,
        createdAt: Date.now()
      })
      result.added++
    }

    if (newEntries.length > 0) {
      set((state) => {
        const next = new Map(state.proxyPool)
        for (const e of newEntries) next.set(e.id, e)
        return { proxyPool: next }
      })
      get().saveToStorage()
    }
    return result
  },

  removeProxy: (id) => {
    // 收集受影响的账号（绑定到该代理的账号）
    const affectedAccountIds = Object.entries(get().accountProxyBindings)
      .filter(([, pid]) => pid === id)
      .map(([aid]) => aid)
    set((state) => {
      const next = new Map(state.proxyPool)
      next.delete(id)
      // 同步清理绑定
      const bindings = { ...state.accountProxyBindings }
      for (const aid of affectedAccountIds) delete bindings[aid]
      return { proxyPool: next, accountProxyBindings: bindings }
    })
    get().saveToStorage()
    // 通知主进程：这些账号现在无代理绑定，回退全局
    for (const aid of affectedAccountIds) syncAccountProxyToMain(aid)
  },

  removeProxies: (ids) => {
    if (ids.length === 0) return
    const idSet = new Set(ids)
    const affectedAccountIds = Object.entries(get().accountProxyBindings)
      .filter(([, pid]) => idSet.has(pid))
      .map(([aid]) => aid)
    set((state) => {
      const next = new Map(state.proxyPool)
      for (const id of ids) next.delete(id)
      const bindings = { ...state.accountProxyBindings }
      for (const aid of affectedAccountIds) delete bindings[aid]
      return { proxyPool: next, accountProxyBindings: bindings }
    })
    get().saveToStorage()
    for (const aid of affectedAccountIds) syncAccountProxyToMain(aid)
  },

  toggleProxyEnabled: (id, enabled) => {
    set((state) => {
      const next = new Map(state.proxyPool)
      const entry = next.get(id)
      if (entry) {
        next.set(id, { ...entry, enabled: enabled ?? !entry.enabled })
      }
      return { proxyPool: next }
    })
    get().saveToStorage()
    // 通知所有绑定该代理的账号更新主进程内存（启用变化会影响是否可用）
    syncAllAccountsBoundToProxy(id)
  },

  updateProxy: (id, updates) => {
    set((state) => {
      const next = new Map(state.proxyPool)
      const entry = next.get(id)
      if (entry) {
        next.set(id, { ...entry, ...updates })
      }
      return { proxyPool: next }
    })
    get().saveToStorage()
    // url / 启用状态 / 状态变化都需要同步绑定账号
    if ('url' in updates || 'enabled' in updates || 'status' in updates) {
      syncAllAccountsBoundToProxy(id)
    }
  },

  validateProxy: async (id) => {
    const entry = get().proxyPool.get(id)
    if (!entry) {
      return { success: false, error: 'Proxy not found' }
    }
    const { proxyPoolConfig } = get()

    // 先置为 testing 状态
    set((state) => {
      const next = new Map(state.proxyPool)
      const existing = next.get(id)
      if (existing) next.set(id, { ...existing, status: 'testing' })
      return { proxyPool: next }
    })

    let result: ProxyValidationResult
    try {
      result = await window.api.proxyPoolValidate({
        url: entry.url,
        testUrl: proxyPoolConfig.testUrl,
        timeoutMs: proxyPoolConfig.testTimeoutMs
      })
    } catch (err) {
      result = { success: false, error: err instanceof Error ? err.message : String(err) }
    }

    set((state) => {
      const next = new Map(state.proxyPool)
      const existing = next.get(id)
      if (existing) {
        const latencyMs = result.latencyMs
        const status: ProxyEntry['status'] = result.success
          ? (latencyMs !== undefined && latencyMs > 3000 ? 'slow' : 'alive')
          : 'dead'
        next.set(id, {
          ...existing,
          status,
          latencyMs: result.latencyMs,
          lastTestedAt: Date.now(),
          lastError: result.success ? undefined : result.error,
          // 验活失败也累计到 failCount，但不计入 reportProxyResult 的注册失败
          failCount: result.success ? existing.failCount : existing.failCount + 1,
          // 自动停用：累计失败超过阈值
          enabled: result.success
            ? existing.enabled
            : (state.proxyPoolConfig.autoDisableDead && existing.failCount + 1 >= state.proxyPoolConfig.failureThreshold
              ? false
              : existing.enabled)
        })
      }
      return { proxyPool: next }
    })
    get().saveToStorage()
    // 同步绑定账号：状态变化（alive/slow/dead）影响代理是否可用
    syncAllAccountsBoundToProxy(id)
    return result
  },

  validateProxiesBatch: async (ids, concurrency = 5) => {
    if (ids.length === 0) return
    const validateProxy = get().validateProxy
    let cursor = 0
    const worker = async (): Promise<void> => {
      while (cursor < ids.length) {
        const idx = cursor++
        try { await validateProxy(ids[idx]) } catch { /* per-item error logged */ }
      }
    }
    const workers = Array.from({ length: Math.max(1, Math.min(concurrency, ids.length)) }, () => worker())
    await Promise.all(workers)
  },

  clearProxyPool: () => {
    const affectedAccountIds = Object.keys(get().accountProxyBindings)
    set({ proxyPool: new Map(), proxyPoolCursor: 0, accountProxyBindings: {} })
    get().saveToStorage()
    // 通知所有曾被绑定的账号回退全局
    for (const aid of affectedAccountIds) syncAccountProxyToMain(aid)
  },

  setProxyPoolConfig: (config) => {
    set((state) => ({
      proxyPoolConfig: { ...state.proxyPoolConfig, ...config }
    }))
    get().saveToStorage()
  },

  pickNextProxy: () => {
    const { proxyPool, proxyPoolConfig, proxyPoolCursor } = get()
    if (!proxyPoolConfig.enabled) return null

    // 仅在启用且非 dead 的代理中挑选
    const candidates = Array.from(proxyPool.values())
      .filter(p => p.enabled && p.status !== 'dead')
    if (candidates.length === 0) return null

    let picked: ProxyEntry
    switch (proxyPoolConfig.strategy) {
      case 'random':
        picked = candidates[Math.floor(Math.random() * candidates.length)]
        break
      case 'least_used':
        picked = candidates.reduce((min, cur) => (cur.usedCount < min.usedCount ? cur : min))
        break
      case 'fastest':
        // 已测过的优先按延迟升序；未测过的排最后
        picked = candidates.slice().sort((a, b) => {
          const la = a.latencyMs ?? Number.POSITIVE_INFINITY
          const lb = b.latencyMs ?? Number.POSITIVE_INFINITY
          return la - lb
        })[0]
        break
      case 'round_robin':
      default: {
        const idx = proxyPoolCursor % candidates.length
        picked = candidates[idx]
        set({ proxyPoolCursor: proxyPoolCursor + 1 })
        break
      }
    }

    // 更新使用计数（即时反映到 UI，使用 saveToStorage 防抖）
    set((state) => {
      const next = new Map(state.proxyPool)
      const existing = next.get(picked.id)
      if (existing) {
        next.set(picked.id, { ...existing, usedCount: existing.usedCount + 1, lastUsedAt: Date.now() })
      }
      return { proxyPool: next }
    })
    get().saveToStorage()
    return picked
  },

  reportProxyResult: (id, success, boundEmail, errorMsg) => {
    let autoDisabled = false
    set((state) => {
      const next = new Map(state.proxyPool)
      const existing = next.get(id)
      if (!existing) return state
      const failCount = success ? existing.failCount : existing.failCount + 1
      const autoDisable = !success
        && state.proxyPoolConfig.autoDisableDead
        && failCount >= state.proxyPoolConfig.failureThreshold
      autoDisabled = autoDisable
      next.set(id, {
        ...existing,
        failCount,
        lastBoundEmail: boundEmail || existing.lastBoundEmail,
        lastError: success ? existing.lastError : errorMsg,
        enabled: autoDisable ? false : existing.enabled,
        status: autoDisable ? 'dead' : existing.status
      })
      return { proxyPool: next }
    })
    get().saveToStorage()
    // 仅在代理被自动停用时通知主进程（普通 used/failCount 计数变化无需同步）
    if (autoDisabled) {
      syncAllAccountsBoundToProxy(id)
    }
  },

  // ==================== 账号-代理绑定 ====================

  bindAccountToProxy: (accountId, proxyId) => {
    set((state) => ({
      accountProxyBindings: { ...state.accountProxyBindings, [accountId]: proxyId }
    }))
    get().saveToStorage()
    // 同步到主进程的账号池
    syncAccountProxyToMain(accountId)
  },

  bindAccountsToProxy: (accountIds, proxyId) => {
    if (accountIds.length === 0) return
    set((state) => {
      const next = { ...state.accountProxyBindings }
      for (const id of accountIds) next[id] = proxyId
      return { accountProxyBindings: next }
    })
    get().saveToStorage()
    for (const id of accountIds) syncAccountProxyToMain(id)
  },

  unbindAccountFromProxy: (accountId) => {
    set((state) => {
      const next = { ...state.accountProxyBindings }
      delete next[accountId]
      return { accountProxyBindings: next }
    })
    get().saveToStorage()
    syncAccountProxyToMain(accountId)
  },

  clearAccountProxyBindings: () => {
    const old = Object.keys(get().accountProxyBindings)
    set({ accountProxyBindings: {} })
    get().saveToStorage()
    for (const id of old) syncAccountProxyToMain(id)
  },

  autoDistributeAccountsToProxies: ({ accountsPerProxy = 0, onlyUnbound = false, accountIds }) => {
    const state = get()
    const aliveProxies = Array.from(state.proxyPool.values())
      .filter((p) => p.enabled && p.status !== 'dead')
    if (aliveProxies.length === 0) {
      return { distributed: 0, perProxy: {}, skipped: 0 }
    }

    // 候选账号
    const candidates = accountIds
      ? accountIds.map((id) => state.accounts.get(id)).filter((a): a is Account => !!a)
      : Array.from(state.accounts.values())
    const targets = onlyUnbound
      ? candidates.filter((a) => !state.accountProxyBindings[a.id])
      : candidates

    if (targets.length === 0) {
      return { distributed: 0, perProxy: {}, skipped: candidates.length }
    }

    const perProxy: Record<string, number> = {}
    aliveProxies.forEach((p) => { perProxy[p.id] = 0 })
    const newBindings = { ...state.accountProxyBindings }

    // 取消已绑定到失效/不存在代理的账号（仅 onlyUnbound=false 时统一重新分配）
    if (!onlyUnbound) {
      for (const id of Object.keys(newBindings)) {
        const proxyExists = aliveProxies.some((p) => p.id === newBindings[id])
        if (!proxyExists) delete newBindings[id]
      }
    }

    let distributed = 0
    let cursor = 0
    for (const account of targets) {
      // accountsPerProxy=0：均分；非 0：每代理填满 N 个再换下一个
      let chosenProxyId: string
      if (accountsPerProxy > 0) {
        // 找第一个还未填满的代理
        let found: string | undefined
        for (let i = 0; i < aliveProxies.length; i++) {
          const pid = aliveProxies[i].id
          if (perProxy[pid] < accountsPerProxy) {
            found = pid
            break
          }
        }
        if (!found) {
          // 全部代理都满了：跳过剩余账号
          break
        }
        chosenProxyId = found
      } else {
        chosenProxyId = aliveProxies[cursor % aliveProxies.length].id
        cursor++
      }
      newBindings[account.id] = chosenProxyId
      perProxy[chosenProxyId]++
      distributed++
    }

    set({ accountProxyBindings: newBindings })
    get().saveToStorage()
    // 同步到主进程
    for (const id of targets.slice(0, distributed)) {
      syncAccountProxyToMain(id.id)
    }
    return { distributed, perProxy, skipped: targets.length - distributed }
  },

  getAccountProxyUrl: (accountId) => {
    const state = get()
    const proxyId = state.accountProxyBindings[accountId]
    if (!proxyId) return undefined
    const proxy = state.proxyPool.get(proxyId)
    if (!proxy || !proxy.enabled || proxy.status === 'dead') return undefined
    return proxy.url
  }
}))

/**
 * 把单个账号的代理绑定信息同步到主进程账号池
 * （主进程账号池里的 ProxyAccount.proxyUrl 由此 IPC 设置）
 */
function syncAccountProxyToMain(accountId: string): void {
  try {
    const url = useAccountsStore.getState().getAccountProxyUrl(accountId)
    void window.api.accountSetProxyBinding?.(accountId, url)
  } catch (err) {
    console.warn('[Store] Failed to sync account proxy binding to main:', err)
  }
}

/**
 * 当某个代理发生变化（URL/启用状态/有效性）时，
 * 同步所有绑定到该代理的账号到主进程，确保主进程内存里的 ProxyAccount.proxyUrl 与代理池实际情况一致
 */
function syncAllAccountsBoundToProxy(proxyId: string): void {
  try {
    const state = useAccountsStore.getState()
    const affectedAccountIds = Object.entries(state.accountProxyBindings)
      .filter(([, pid]) => pid === proxyId)
      .map(([aid]) => aid)
    for (const aid of affectedAccountIds) {
      syncAccountProxyToMain(aid)
    }
  } catch (err) {
    console.warn('[Store] Failed to sync accounts bound to proxy:', err)
  }
}

/** 触发 Webhook 事件（封装错误处理，不阻塞主业务流程） */
function triggerWebhook(event: WebhookEvent, payload: WebhookMessage): void {
  try {
    void useWebhookStore.getState().triggerEvent(event, payload)
  } catch (err) {
    console.warn(`[Webhook] trigger ${event} failed:`, err)
  }
}

// ==================== 代理 URL 解析辅助 ====================

interface ParsedProxy {
  protocol: ProxyProtocol
  host: string
  port: number
  username?: string
  password?: string
  normalized: string
}

/**
 * 解析多种代理 URL 格式：
 *   - http://host:port
 *   - http://user:pass@host:port
 *   - socks5://host:port
 *   - host:port              （默认 http）
 *   - host:port:user:pass    （Stormproxies 等代理商常用格式）
 *   - user:pass@host:port    （省略 scheme）
 */
function parseProxyUrl(raw: string): ParsedProxy | null {
  const trimmed = (raw || '').trim()
  if (!trimmed) return null

  // 形式 1: scheme://...
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) {
    try {
      const u = new URL(trimmed)
      const protocol = normalizeProtocol(u.protocol.replace(':', ''))
      if (!protocol) return null
      const port = Number(u.port) || defaultPort(protocol)
      if (!u.hostname || !Number.isFinite(port)) return null
      return {
        protocol,
        host: u.hostname,
        port,
        username: u.username ? decodeURIComponent(u.username) : undefined,
        password: u.password ? decodeURIComponent(u.password) : undefined,
        normalized: buildProxyUrl(protocol, u.hostname, port, u.username, u.password)
      }
    } catch {
      return null
    }
  }

  // 形式 2: host:port:user:pass（4 段冒号分隔）
  const segs = trimmed.split(':')
  if (segs.length === 4 && /^\d+$/.test(segs[1])) {
    const [host, portStr, user, pass] = segs
    const port = Number(portStr)
    if (!host || !Number.isFinite(port)) return null
    return {
      protocol: 'http',
      host, port,
      username: user || undefined,
      password: pass || undefined,
      normalized: buildProxyUrl('http', host, port, user, pass)
    }
  }

  // 形式 3: user:pass@host:port（缺 scheme）
  if (trimmed.includes('@')) {
    const [authPart, hostPart] = trimmed.split('@')
    const [user, pass] = authPart.split(':')
    const [host, portStr] = (hostPart || '').split(':')
    const port = Number(portStr)
    if (!host || !Number.isFinite(port)) return null
    return {
      protocol: 'http',
      host, port,
      username: user || undefined,
      password: pass || undefined,
      normalized: buildProxyUrl('http', host, port, user, pass)
    }
  }

  // 形式 4: host:port（裸格式，默认 http）
  if (segs.length === 2 && /^\d+$/.test(segs[1])) {
    const port = Number(segs[1])
    if (!segs[0] || !Number.isFinite(port)) return null
    return {
      protocol: 'http',
      host: segs[0],
      port,
      normalized: buildProxyUrl('http', segs[0], port)
    }
  }

  return null
}

function normalizeProtocol(raw: string): ProxyProtocol | null {
  const p = raw.toLowerCase()
  if (p === 'http' || p === 'https' || p === 'socks5' || p === 'socks4') return p
  if (p === 'socks') return 'socks5'
  return null
}

function defaultPort(protocol: ProxyProtocol): number {
  switch (protocol) {
    case 'http': return 8080
    case 'https': return 443
    case 'socks5':
    case 'socks4': return 1080
  }
}

function buildProxyUrl(
  protocol: ProxyProtocol,
  host: string,
  port: number,
  username?: string,
  password?: string
): string {
  const auth = username
    ? `${encodeURIComponent(username)}${password ? `:${encodeURIComponent(password)}` : ''}@`
    : ''
  return `${protocol}://${auth}${host}:${port}`
}
