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

// ============================================
// 账号管理 Store
// ============================================

// 自动 Token 刷新定时器
let tokenRefreshTimer: ReturnType<typeof setInterval> | null = null
const TOKEN_REFRESH_BEFORE_EXPIRY = 5 * 60 * 1000 // 过期前 5 分钟刷新

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
  statusCheckInterval: number // 分钟

  // 隐私模式
  privacyMode: boolean

  // 代理设置
  proxyEnabled: boolean
  proxyUrl: string // 格式: http://host:port 或 socks5://host:port

  // 自动换号设置
  autoSwitchEnabled: boolean
  autoSwitchThreshold: number // 余额阈值，低于此值时自动切换
  autoSwitchInterval: number // 检查间隔（分钟）

  // 批量导入设置
  batchImportConcurrency: number // 批量导入并发数

  // 主题设置
  theme: string // 主题名称: default, purple, emerald, orange, rose, cyan, amber
  darkMode: boolean // 深色模式

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
  saveToStorage: () => Promise<void>

  // 设置
  setAutoRefresh: (enabled: boolean, interval?: number) => void
  setAutoRefreshConcurrency: (concurrency: number) => void
  setStatusCheckInterval: (interval: number) => void

  // 隐私模式
  setPrivacyMode: (enabled: boolean) => void
  maskEmail: (email: string) => string
  maskNickname: (nickname: string | undefined) => string

  // 代理设置
  setProxy: (enabled: boolean, url?: string) => void

  // 主题设置
  setTheme: (theme: string) => void
  setDarkMode: (enabled: boolean) => void
  applyTheme: () => void

  // 自动换号
  setAutoSwitch: (enabled: boolean, threshold?: number, interval?: number) => void

  // 批量导入并发数
  setBatchImportConcurrency: (concurrency: number) => void
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
}

type AccountsStore = AccountsState & AccountsActions

// 默认排序
const defaultSort: AccountSort = { field: 'lastUsedAt', order: 'desc' }

// 默认筛选
const defaultFilter: AccountFilter = {}

export const useAccountsStore = create<AccountsStore>()((set, get) => ({
  // 初始状态
  appVersion: '1.0.0',
  accounts: new Map(),
  groups: new Map(),
  tags: new Map(),
  activeAccountId: null,
  filter: defaultFilter,
  sort: defaultSort,
  selectedIds: new Set(),
  isLoading: false,
  isSyncing: false,
  autoRefreshEnabled: true,
  autoRefreshInterval: 5,
  autoRefreshConcurrency: 100,
  statusCheckInterval: 60,
  privacyMode: false,
  proxyEnabled: false,
  proxyUrl: '',
  autoSwitchEnabled: false,
  autoSwitchThreshold: 0,
  autoSwitchInterval: 5,
  batchImportConcurrency: 100,
  theme: 'default',
  darkMode: false,

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

  // ==================== 账号 CRUD ====================

  addAccount: (accountData) => {
    const id = uuidv4()
    const now = Date.now()

    const account: Account = {
      ...accountData,
      id,
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

      return { accounts, selectedIds, activeAccountId }
    })
    get().saveToStorage()
  },

  removeAccounts: (ids) => {
    const result: BatchOperationResult = { success: 0, failed: 0, errors: [] }

    set((state) => {
      const accounts = new Map(state.accounts)
      const selectedIds = new Set(state.selectedIds)
      let activeAccountId = state.activeAccountId

      for (const id of ids) {
        if (accounts.has(id)) {
          accounts.delete(id)
          selectedIds.delete(id)
          if (activeAccountId === id) activeAccountId = null
          result.success++
        } else {
          result.failed++
          result.errors.push({ id, error: 'Account not found' })
        }
      }

      return { accounts, selectedIds, activeAccountId }
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

  setSort: (sort) => {
    set({ sort })
  },

  getFilteredAccounts: () => {
    const { accounts, filter, sort } = get()

    let result = Array.from(accounts.values())

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

    for (const item of items) {
      try {
        const now = Date.now()

        const account: Omit<Account, 'id' | 'createdAt' | 'isActive'> = {
          email: item.email,
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

        get().addAccount(account)
        result.success++
      } catch (error) {
        result.failed++
        result.errors.push({
          id: item.email,
          error: error instanceof Error ? error.message : 'Unknown error'
        })
      }
    }

    return result
  },

  importFromExportData: (data) => {
    const result: BatchOperationResult = { success: 0, failed: 0, errors: [] }
    const { accounts: existingAccounts } = get()
    
    // 检查账户是否已存在（通过 email 或 userId）
    const isAccountExists = (email: string, userId?: string): boolean => {
      return Array.from(existingAccounts.values()).some(
        acc => acc.email === email || (userId && acc.userId === userId)
      )
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

    // 导入分组
    for (const group of data.groups) {
      set((state) => {
        const groups = new Map(state.groups)
        groups.set(group.id, group)
        return { groups }
      })
    }

    // 导入标签
    for (const tag of data.tags) {
      set((state) => {
        const tags = new Map(state.tags)
        tags.set(tag.id, tag)
        return { tags }
      })
    }

    // 导入账号（跳过已存在的）
    let skipped = 0
    for (const accountData of uniqueAccounts) {
      // 检查本地是否已存在
      if (isAccountExists(accountData.email, accountData.userId)) {
        skipped++
        continue
      }
      
      try {
        set((state) => {
          const accounts = new Map(state.accounts)
          accounts.set(accountData.id, { ...accountData, isActive: false })
          return { accounts }
        })
        result.success++
      } catch (error) {
        result.failed++
        result.errors.push({
          id: accountData.id,
          error: error instanceof Error ? error.message : 'Unknown error'
        })
      }
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

            // 转换 IDP 类型
            const apiIdp = result.data!.idp
            let idpType = acc.idp
            if (apiIdp) {
              if (apiIdp === 'BuilderId') idpType = 'BuilderId'
              else if (apiIdp === 'Google') idpType = 'Google'
              else if (apiIdp === 'Github') idpType = 'Github'
              else if (apiIdp === 'AWSIdC') idpType = 'AWSIdC'
              else idpType = 'Internal'
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
        updateAccountStatus(id, 'error', result.error?.message)
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
        AWSIdC: 0,
        Internal: 0
      },
      activeCount: 0,
      expiringSoonCount: 0
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
    }

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
        let activeAccountId = data.activeAccountId ?? null

        // 同步本地 SSO 缓存中的账号状态
        try {
          const localResult = await window.api.getLocalActiveAccount()
          if (localResult.success && localResult.data?.refreshToken) {
            const localRefreshToken = localResult.data.refreshToken
            // 查找匹配的账号
            let foundAccountId: string | null = null
            for (const [id, account] of accounts) {
              if (account.credentials.refreshToken === localRefreshToken) {
                foundAccountId = id
                break
              }
            }
            // 如果找到匹配的账号，设为当前使用
            if (foundAccountId) {
              activeAccountId = foundAccountId
              console.log('[Store] Synced active account from local SSO cache:', foundAccountId)
            } else {
              // 如果没有找到匹配的账号，自动导入
              console.log('[Store] Local account not found in app, importing...')
              const importResult = await window.api.loadKiroCredentials()
              if (importResult.success && importResult.data) {
                // 验证并获取账号信息
                const verifyResult = await window.api.verifyAccountCredentials({
                  refreshToken: importResult.data.refreshToken,
                  clientId: importResult.data.clientId || '',
                  clientSecret: importResult.data.clientSecret || '',
                  region: importResult.data.region,
                  authMethod: importResult.data.authMethod,
                  provider: importResult.data.provider
                })
                if (verifyResult.success && verifyResult.data) {
                  const now = Date.now()
                  const newId = `${verifyResult.data.email}-${now}`
                  const newAccount: Account = {
                    id: newId,
                    email: verifyResult.data.email,
                    userId: verifyResult.data.userId,
                    nickname: verifyResult.data.email ? verifyResult.data.email.split('@')[0] : undefined,
                    idp: (importResult.data.provider || 'BuilderId') as 'BuilderId' | 'Google' | 'Github',
                    credentials: {
                      accessToken: verifyResult.data.accessToken,
                      csrfToken: '',
                      refreshToken: verifyResult.data.refreshToken,
                      clientId: importResult.data.clientId || '',
                      clientSecret: importResult.data.clientSecret || '',
                      region: importResult.data.region || 'us-east-1',
                      expiresAt: verifyResult.data.expiresIn ? now + verifyResult.data.expiresIn * 1000 : now + 3600 * 1000,
                      authMethod: importResult.data.authMethod as 'IdC' | 'social',
                      provider: (importResult.data.provider || 'BuilderId') as 'BuilderId' | 'Github' | 'Google'
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
                  accounts.set(newId, newAccount)
                  activeAccountId = newId
                  console.log('[Store] Auto-imported account from local SSO cache:', verifyResult.data.email)
                }
              }
            }
          }
        } catch (e) {
          console.warn('[Store] Failed to sync local active account:', e)
        }

        set({
          accounts,
          groups: new Map(Object.entries(data.groups ?? {}) as [string, AccountGroup][]),
          tags: new Map(Object.entries(data.tags ?? {}) as [string, AccountTag][]),
          activeAccountId,
          autoRefreshEnabled: data.autoRefreshEnabled ?? true,
          autoRefreshInterval: data.autoRefreshInterval ?? 5,
          autoRefreshConcurrency: data.autoRefreshConcurrency ?? 100,
          statusCheckInterval: data.statusCheckInterval ?? 60,
          privacyMode: data.privacyMode ?? false,
          proxyEnabled: data.proxyEnabled ?? false,
          proxyUrl: data.proxyUrl ?? '',
          autoSwitchEnabled: data.autoSwitchEnabled ?? false,
          autoSwitchThreshold: data.autoSwitchThreshold ?? 0,
          autoSwitchInterval: data.autoSwitchInterval ?? 5,
          theme: data.theme ?? 'default',
          darkMode: data.darkMode ?? false,
          machineIdConfig: data.machineIdConfig ?? {
            autoSwitchOnAccountChange: false,
            bindMachineIdToAccount: false,
            useBindedMachineId: true
          },
          accountMachineIds: data.accountMachineIds ?? {},
          machineIdHistory: data.machineIdHistory ?? []
        })

        // 应用主题
        get().applyTheme()

        // 如果代理已启用，通知主进程
        if (data.proxyEnabled && data.proxyUrl) {
          window.api.setProxy?.(true, data.proxyUrl)
        }

        // 如果自动换号已启用，启动定时器
        if (data.autoSwitchEnabled) {
          get().startAutoSwitch()
        }

        // 启动定时自动保存（防止数据丢失）
        get().startAutoSave()
      }
    } catch (error) {
      console.error('Failed to load accounts:', error)
    } finally {
      set({ isLoading: false })
    }
  },

  saveToStorage: async () => {
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
      proxyEnabled,
      proxyUrl,
      autoSwitchEnabled,
      autoSwitchThreshold,
      autoSwitchInterval,
      theme,
      darkMode,
      machineIdConfig,
      accountMachineIds,
      machineIdHistory
    } = get()

    set({ isSyncing: true })

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
        proxyEnabled,
        proxyUrl,
        autoSwitchEnabled,
        autoSwitchThreshold,
        autoSwitchInterval,
        theme,
        darkMode,
        machineIdConfig,
        accountMachineIds,
        machineIdHistory
      })
    } catch (error) {
      console.error('Failed to save accounts:', error)
    } finally {
      set({ isSyncing: false })
    }
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

  // ==================== 代理设置 ====================

  setProxy: (enabled, url) => {
    set({ 
      proxyEnabled: enabled,
      proxyUrl: url ?? get().proxyUrl
    })
    get().saveToStorage()
    // 通知主进程更新代理设置
    window.api.setProxy?.(enabled, url ?? get().proxyUrl)
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

  applyTheme: () => {
    const { theme, darkMode } = get()
    const root = document.documentElement
    
    // 移除所有主题类（包含所有 21 个主题）
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
      'theme-slate', 'theme-zinc', 'theme-stone', 'theme-neutral'
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
        if (acc.lastError?.includes('UnauthorizedException') || 
            acc.lastError?.includes('AccountSuspendedException')) return false
        // 排除余额不足的账号
        const accRemaining = acc.usage.limit - acc.usage.current
        if (accRemaining <= autoSwitchThreshold) return false
        return true
      })

      if (availableAccount) {
        console.log(`[AutoSwitch] Switching to: ${availableAccount.email}`)
        setActiveAccount(availableAccount.id)
        // 通知主进程切换账号
        await window.api.switchAccount({
          accessToken: availableAccount.credentials.accessToken || '',
          refreshToken: availableAccount.credentials.refreshToken || '',
          clientId: availableAccount.credentials.clientId || '',
          clientSecret: availableAccount.credentials.clientSecret || '',
          region: availableAccount.credentials.region || 'us-east-1',
          authMethod: availableAccount.credentials.authMethod,
          provider: availableAccount.credentials.provider
        })
      } else {
        console.log('[AutoSwitch] No available account to switch to')
      }
    }
  },

  // ==================== 自动 Token 刷新 ====================

  checkAndRefreshExpiringTokens: async () => {
    const { accounts, refreshAccountToken, checkAccountStatus, autoSwitchEnabled, autoRefreshConcurrency } = get()
    const now = Date.now()

    console.log(`[AutoRefresh] Checking ${accounts.size} accounts...`)

    // 筛选需要处理的账号
    const accountsToProcess: Array<{ id: string; email: string; needsTokenRefresh: boolean }> = []
    
    for (const [id, account] of accounts) {
      // 跳过已封禁或错误状态的账号
      if (account.lastError?.includes('UnauthorizedException') || 
          account.lastError?.includes('AccountSuspendedException')) {
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
            } else if (autoSwitchEnabled) {
              // 仅在启用自动换号时才刷新账户信息（用于检测余额）
              await checkAccountStatus(id)
              console.log(`[AutoRefresh] Account info for ${email} updated (auto-switch enabled)`)
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
      if (account.lastError?.includes('UnauthorizedException') || 
          account.lastError?.includes('AccountSuspendedException')) {
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
    const { accounts, autoRefreshConcurrency } = get()
    const now = Date.now()

    // 筛选需要刷新 Token 的账号
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
    
    for (const [id, account] of accounts) {
      // 跳过已封禁或错误状态的账号
      if (account.lastError?.includes('UnauthorizedException') || 
          account.lastError?.includes('AccountSuspendedException')) {
        continue
      }

      const expiresAt = account.credentials.expiresAt
      const timeUntilExpiry = expiresAt ? expiresAt - now : Infinity
      
      // Token 已过期或即将过期
      if (expiresAt && timeUntilExpiry <= TOKEN_REFRESH_BEFORE_EXPIRY) {
        accountsToRefresh.push({
          id,
          email: account.email,
          credentials: {
            refreshToken: account.credentials.refreshToken || '',
            clientId: account.credentials.clientId,
            clientSecret: account.credentials.clientSecret,
            region: account.credentials.region,
            authMethod: account.credentials.authMethod,
            accessToken: account.credentials.accessToken
          }
        })
      }
    }

    if (accountsToRefresh.length === 0) {
      console.log('[BackgroundRefresh] No accounts need refresh')
      return
    }

    console.log(`[BackgroundRefresh] Triggering refresh for ${accountsToRefresh.length} accounts...`)
    
    // 调用主进程后台刷新，不等待结果（通过 IPC 事件接收）
    window.api.backgroundBatchRefresh(accountsToRefresh, autoRefreshConcurrency)
  },

  // 处理后台刷新结果（由 App.tsx 调用）
  handleBackgroundRefreshResult: (data) => {
    const { id, success, data: resultData, error } = data
    
    if (!success) {
      console.log(`[BackgroundRefresh] Account ${id} refresh failed:`, error)
      // 更新账号错误状态
      set((state) => {
        const accounts = new Map(state.accounts)
        const account = accounts.get(id)
        if (account) {
          accounts.set(id, {
            ...account,
            status: 'error',
            lastError: error,
            lastCheckedAt: Date.now()
          })
        }
        return { accounts }
      })
      return
    }

    // 更新账号状态
    set((state) => {
      const accounts = new Map(state.accounts)
      const account = accounts.get(id)
      
      if (!account) return state

      const now = Date.now()
      const refreshData = resultData as {
        accessToken?: string
        refreshToken?: string
        expiresIn?: number
        usage?: { current?: number; limit?: number; baseCurrent?: number; baseLimit?: number; freeTrialCurrent?: number; freeTrialLimit?: number; freeTrialExpiry?: string; nextResetDate?: string }
        subscription?: { type?: string; title?: string }
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
        usage: refreshData?.usage ? {
          ...account.usage,
          current: refreshData.usage.current ?? account.usage.current,
          limit: refreshData.usage.limit ?? account.usage.limit,
          baseCurrent: refreshData.usage.baseCurrent ?? account.usage.baseCurrent,
          baseLimit: refreshData.usage.baseLimit ?? account.usage.baseLimit,
          freeTrialCurrent: refreshData.usage.freeTrialCurrent ?? account.usage.freeTrialCurrent,
          freeTrialLimit: refreshData.usage.freeTrialLimit ?? account.usage.freeTrialLimit,
          freeTrialExpiry: refreshData.usage.freeTrialExpiry ?? account.usage.freeTrialExpiry,
          nextResetDate: refreshData.usage.nextResetDate ?? account.usage.nextResetDate,
          lastUpdated: now
        } : account.usage,
        email: refreshData?.userInfo?.email || account.email,
        userId: refreshData?.userInfo?.userId || account.userId,
        status: newStatus,
        lastError: newError,
        lastCheckedAt: now
      })

      return { accounts }
    })
  },

  // 处理后台检查结果（由 App.tsx 调用）
  handleBackgroundCheckResult: (data: { id: string; success: boolean; data?: unknown; error?: string }) => {
    const { id, success, data: resultData, error } = data
    
    if (!success) {
      console.log(`[BackgroundCheck] Account ${id} check failed:`, error)
      set((state) => {
        const accounts = new Map(state.accounts)
        const account = accounts.get(id)
        if (account) {
          accounts.set(id, {
            ...account,
            status: 'error',
            lastError: error,
            lastCheckedAt: Date.now()
          })
        }
        return { accounts }
      })
      return
    }

    // 更新账号状态
    set((state) => {
      const accounts = new Map(state.accounts)
      const account = accounts.get(id)
      
      if (!account) return state

      const now = Date.now()
      const checkData = resultData as {
        usage?: { current?: number; limit?: number; baseCurrent?: number; baseLimit?: number; freeTrialCurrent?: number; freeTrialLimit?: number; freeTrialExpiry?: string; nextResetDate?: string }
        subscription?: { type?: string; title?: string }
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
        usage: checkData?.usage ? {
          ...account.usage,
          current: checkData.usage.current ?? account.usage.current,
          limit: checkData.usage.limit ?? account.usage.limit,
          baseCurrent: checkData.usage.baseCurrent ?? account.usage.baseCurrent,
          baseLimit: checkData.usage.baseLimit ?? account.usage.baseLimit,
          freeTrialCurrent: checkData.usage.freeTrialCurrent ?? account.usage.freeTrialCurrent,
          freeTrialLimit: checkData.usage.freeTrialLimit ?? account.usage.freeTrialLimit,
          freeTrialExpiry: checkData.usage.freeTrialExpiry ?? account.usage.freeTrialExpiry,
          nextResetDate: checkData.usage.nextResetDate ?? account.usage.nextResetDate,
          lastUpdated: now
        } : account.usage,
        subscription: checkData?.subscription ? {
          ...account.subscription,
          type: (checkData.subscription.type as 'Free' | 'Pro' | 'Enterprise' | 'Teams') ?? account.subscription.type,
          title: checkData.subscription.title ?? account.subscription.title
        } : account.subscription,
        email: checkData?.userInfo?.email || account.email,
        userId: checkData?.userInfo?.userId || account.userId,
        status: newStatus,
        lastError: newError,
        lastCheckedAt: now
      })

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
  }
}))
