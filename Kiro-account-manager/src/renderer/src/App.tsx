import { useState, useEffect, useCallback, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { AccountManager } from './components/accounts'
import { Sidebar, TitleBar, type PageType } from './components/layout'
import { HomePage, AboutPage, SettingsPage, MachineIdPage, KiroSettingsPage, ProxyPage, KProxyPage, ProxyPoolPage, WebhooksPage, DiagnosePage, ConfigSyncPage, RegisterPage, SubscriptionPage, LogsPage } from './components/pages'
import { useWebhookStore } from './store/webhooks'
import { UpdateDialog } from './components/UpdateDialog'
import { CloseConfirmDialog } from './components/CloseConfirmDialog'
import { useAccountsStore, isBannedAccountError } from './store/accounts'

// 托盘信息防抖延迟：后台刷新风暴时合并多次跨进程 IPC 为单次
const TRAY_UPDATE_DEBOUNCE_MS = 400
// 后台刷新结果批量化间隔：N 条结果合并到一次 set，避免 N 次 Map 全量复制 + 渲染抖动
const BACKGROUND_RESULT_FLUSH_MS = 120

function App(): React.JSX.Element {
  const [currentPage, setCurrentPage] = useState<PageType>('home')
  const [sidebarCollapsed, setSidebarCollapsed] = useState(true)

  const {
    loadFromStorage,
    startAutoTokenRefresh,
    stopAutoTokenRefresh,
    applyBackgroundRefreshResults,
    applyBackgroundCheckResults,
    flushSaveImmediately,
    accounts,
    activeAccountId,
    setActiveAccount,
    checkAndRefreshExpiringTokens,
    updateAccountStatus,
    updateAccount
  } = useAccountsStore()

  // 切换到下一个可用账户
  const switchToNextAccount = useCallback(() => {
    const activeAccounts = Array.from(accounts.values()).filter(acc => acc.status === 'active')
    if (activeAccounts.length <= 1) return

    const currentIndex = activeAccounts.findIndex(acc => acc.id === activeAccountId)
    const nextIndex = (currentIndex + 1) % activeAccounts.length
    setActiveAccount(activeAccounts[nextIndex].id)
  }, [accounts, activeAccountId, setActiveAccount])

  // 托盘信息防抖：账号 Map 频繁变更（后台刷新风暴）时合并 N 次 IPC 为 1 次
  const trayDebounceRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const updateTrayInfo = useCallback(() => {
    if (trayDebounceRef.current) clearTimeout(trayDebounceRef.current)
    trayDebounceRef.current = setTimeout(() => {
      trayDebounceRef.current = null
      const currentState = useAccountsStore.getState()
      const currentAccounts = currentState.accounts
      const currentActiveId = currentState.activeAccountId

      const accountList = Array.from(currentAccounts.values()).map(acc => ({
        id: acc.id,
        email: acc.email || 'Unknown',
        idp: acc.idp || 'Unknown',
        status: acc.status
      }))
      window.api.updateTrayAccountList(accountList)

      if (currentActiveId) {
        const activeAccount = currentAccounts.get(currentActiveId)
        if (activeAccount) {
          window.api.updateTrayAccount({
            id: activeAccount.id,
            email: activeAccount.email || 'Unknown',
            idp: activeAccount.idp || 'Unknown',
            status: activeAccount.status,
            subscription: activeAccount.subscription?.title || undefined,
            usage: activeAccount.usage ? {
              usedCredits: activeAccount.usage.current || 0,
              totalCredits: activeAccount.usage.limit || 0,
              totalRequests: 0,
              successRequests: 0,
              failedRequests: 0
            } : undefined
          })
        } else {
          window.api.updateTrayAccount(null)
        }
      } else {
        window.api.updateTrayAccount(null)
      }
    }, TRAY_UPDATE_DEBOUNCE_MS)
  }, [])

  // 应用启动时加载数据并启动自动刷新
  useEffect(() => {
    loadFromStorage().then(() => {
      startAutoTokenRefresh()
    })
    // 同步主动续期开关（持久化在 main 进程的 electron-store）
    useAccountsStore.getState().loadProactiveRenewalEnabled()
    // 加载 Webhook 配置
    useWebhookStore.getState().loadFromStorage()

    return () => {
      stopAutoTokenRefresh()
    }
  }, [loadFromStorage, startAutoTokenRefresh, stopAutoTokenRefresh])

  // 订阅 Kiro IDE 自己 refresh token 后反代检测到的事件
  // 触发时间点：Kiro IDE 在后台 refresh loop 把磁盘 token 写新了，反代 watcher 反向同步到 store
  // 这里收到事件后从磁盘重新加载账号数据，让 UI 立刻显示最新 expiresAt / accessToken
  useEffect(() => {
    if (typeof window.api.onKiroIdeTokenChanged !== 'function') return
    const unsubscribe = window.api.onKiroIdeTokenChanged((data) => {
      console.log(`[App] Kiro IDE refreshed token for account ${data.accountId} (${data.reason}), reloading accounts...`)
      loadFromStorage().catch((e) => console.warn('[App] reload after IDE token change failed:', e))
    })
    return unsubscribe
  }, [loadFromStorage])

  // 反代关键事件 → 触发 webhook（v1.8 新增）
  // 由 main/proxyServer 内置的 webhookTrigger 通过 IPC 推送过来，统一在 renderer 调 useWebhookStore
  useEffect(() => {
    const unsubscribe = window.api.onProxyWebhookTrigger?.((event, payload) => {
      try {
        const store = useWebhookStore.getState()
        // 映射反代事件名 → Webhook 事件类型
        const webhookEventMap: Record<string, 'risk-warning' | 'account-banned'> = {
          'proxy-account-suspended': 'account-banned',
          'proxy-all-exhausted': 'risk-warning'
        }
        const targetEvent = webhookEventMap[event] || 'risk-warning'
        // 规范化 level（main 用 'error'/'info' 等字符串字面量，需要映射到 store 接受的类型）
        const rawLevel = (payload as { level?: string })?.level
        const level: 'info' | 'warn' | 'error' | 'success' =
          rawLevel === 'error' ? 'error'
          : rawLevel === 'info' ? 'info'
          : rawLevel === 'success' ? 'success'
          : 'warn'
        void store.triggerEvent(targetEvent, {
          title: String((payload as Record<string, unknown>).title ?? '反代告警'),
          message: String((payload as Record<string, unknown>).message ?? ''),
          level,
          fields: (payload as { fields?: Record<string, string | number> })?.fields
        })
      } catch (err) {
        console.error('[App] Proxy webhook trigger failed:', err)
      }
    })
    return () => { unsubscribe?.() }
  }, [])

  // 应用内页面跳转（轻量 CustomEvent，供深层组件无需 prop 钻取即可切页）
  useEffect(() => {
    const handler = (e: Event): void => {
      const detail = (e as CustomEvent<PageType>).detail
      if (detail) setCurrentPage(detail)
    }
    window.addEventListener('navigate-page', handler)
    return () => window.removeEventListener('navigate-page', handler)
  }, [])

  // 新增封禁账号 → 桌面通知（仅"新封禁"弹一次，去重 + 启动宽限期避免初次加载/批量刷新时刷屏）
  const bannedNotifyStartRef = useRef(Date.now())
  useEffect(() => {
    if (typeof Notification === 'undefined') return
    const KEY = 'kiro-notified-banned-ids'
    let notifiedSet: Set<string>
    try {
      notifiedSet = new Set<string>(JSON.parse(localStorage.getItem(KEY) || '[]'))
    } catch {
      notifiedSet = new Set<string>()
    }

    const currentBanned: string[] = []
    const fresh: { email: string; nickname?: string }[] = []
    for (const a of accounts.values()) {
      if (isBannedAccountError(a.lastError)) {
        currentBanned.push(a.id)
        if (!notifiedSet.has(a.id)) fresh.push({ email: a.email, nickname: a.nickname })
      }
    }

    // 启动后 8s 内只建立基线、不弹通知（覆盖异步加载 + 首次状态检查），之后才对新封禁弹窗
    const inGracePeriod = Date.now() - bannedNotifyStartRef.current < 8000
    if (!inGracePeriod && fresh.length > 0 && Notification.permission !== 'denied') {
      const fire = (): void => {
        const lang = useAccountsStore.getState().language
        const isEn = lang === 'en' || (lang === 'auto' && !navigator.language.startsWith('zh'))
        const title = fresh.length === 1
          ? (isEn ? 'Account banned' : '账号被封禁')
          : (isEn ? `${fresh.length} accounts banned` : `${fresh.length} 个账号被封禁`)
        const names = fresh.slice(0, 3).map((a) => a.nickname || a.email)
        const body = names.join('\n') + (fresh.length > 3 ? (isEn ? `\n+${fresh.length - 3} more` : `\n等 ${fresh.length} 个`) : '')
        try { new Notification(title, { body }) } catch { /* ignore */ }
      }
      if (Notification.permission === 'granted') fire()
      else void Notification.requestPermission().then((p) => { if (p === 'granted') fire() })
    }

    // 持久化当前仍封禁的集合：已解封的移出（将来再次封禁可重新提醒），新封禁的记入避免重复弹
    try { localStorage.setItem(KEY, JSON.stringify(currentBanned)) } catch { /* ignore */ }
  }, [accounts])

  // 关闭/刷新前强制 flush 防抖中的待保存数据，防止数据丢失
  useEffect(() => {
    const handleBeforeUnload = (): void => { void flushSaveImmediately() }
    window.addEventListener('beforeunload', handleBeforeUnload)
    return () => {
      window.removeEventListener('beforeunload', handleBeforeUnload)
      if (trayDebounceRef.current) clearTimeout(trayDebounceRef.current)
    }
  }, [flushSaveImmediately])

  // 账户/激活变化时触发托盘更新（内部防抖 + 直接从 store 读取最新数据，避免 stale closure）
  useEffect(() => {
    updateTrayInfo()
  }, [accounts, activeAccountId, updateTrayInfo])

  // 监听托盘刷新账户事件
  useEffect(() => {
    const unsubscribe = window.api.onTrayRefreshAccount(() => {
      checkAndRefreshExpiringTokens()
      updateTrayInfo()
    })
    return () => {
      unsubscribe()
    }
  }, [checkAndRefreshExpiringTokens, updateTrayInfo])

  // 监听托盘切换账户事件
  useEffect(() => {
    const unsubscribe = window.api.onTraySwitchAccount(() => {
      switchToNextAccount()
    })
    return () => {
      unsubscribe()
    }
  }, [switchToNextAccount])

  // 监听后台刷新结果：缓冲 + 批量化 flush，N 条结果合并为一次 set，消除 Map 复制风暴
  useEffect(() => {
    const refreshBuffer: Array<{ id: string; success: boolean; data?: unknown; error?: string }> = []
    let flushTimer: ReturnType<typeof setTimeout> | null = null

    const flush = (): void => {
      flushTimer = null
      if (refreshBuffer.length === 0) return
      const batch = refreshBuffer.splice(0)
      applyBackgroundRefreshResults(batch)
    }

    const unsubscribe = window.api.onBackgroundRefreshResult((data) => {
      refreshBuffer.push(data)
      if (!flushTimer) {
        flushTimer = setTimeout(flush, BACKGROUND_RESULT_FLUSH_MS)
      }
    })
    return () => {
      unsubscribe()
      if (flushTimer) {
        clearTimeout(flushTimer)
        // 卸载前 flush 剩余结果，防止丢失
        flush()
      }
    }
  }, [applyBackgroundRefreshResults])

  // 监听后台检查结果：同样的批量化策略
  useEffect(() => {
    const checkBuffer: Array<{ id: string; success: boolean; data?: unknown; error?: string }> = []
    let flushTimer: ReturnType<typeof setTimeout> | null = null

    const flush = (): void => {
      flushTimer = null
      if (checkBuffer.length === 0) return
      const batch = checkBuffer.splice(0)
      applyBackgroundCheckResults(batch)
    }

    const unsubscribe = window.api.onBackgroundCheckResult((data) => {
      checkBuffer.push(data)
      if (!flushTimer) {
        flushTimer = setTimeout(flush, BACKGROUND_RESULT_FLUSH_MS)
      }
    })
    return () => {
      unsubscribe()
      if (flushTimer) {
        clearTimeout(flushTimer)
        flush()
      }
    }
  }, [applyBackgroundCheckResults])

  // 监听反代账号被封禁事件（TEMPORARILY_SUSPENDED / AccountSuspendedException）
  // 反代触发后，把封禁状态同步到 store 让 UI 显示
  useEffect(() => {
    const unsubscribe = window.api.onProxyAccountSuspended((info) => {
      console.warn(`[App] Account suspended via proxy: ${info.email || info.id} (${info.reason})`)
      updateAccountStatus(info.id, 'error', `[${info.reason}] ${info.message}`)
    })
    return () => {
      unsubscribe()
    }
  }, [updateAccountStatus])

  // 监听反代账号更新事件（Enterprise profileArn 自愈），持久化到 store + 磁盘
  useEffect(() => {
    const unsubscribe = window.api.onProxyAccountUpdate((info) => {
      if (!info.profileArn) return
      const account = useAccountsStore.getState().accounts.get(info.id)
      if (!account || account.credentials?.profileArn === info.profileArn) return
      updateAccount(info.id, {
        profileArn: info.profileArn,
        credentials: { ...account.credentials, profileArn: info.profileArn }
      })
      console.log(`[App] Persisted Enterprise profileArn for ${info.id}`)
    })
    return () => {
      unsubscribe()
    }
  }, [updateAccount])

  const renderPage = () => {
    switch (currentPage) {
      case 'home':
        return <HomePage />
      case 'accounts':
        return <AccountManager />
      case 'machineId':
        return <MachineIdPage />
      case 'kiroSettings':
        return <KiroSettingsPage />
      case 'proxy':
        return <ProxyPage />
      case 'kproxy':
        return <KProxyPage />
      case 'proxyPool':
        return <ProxyPoolPage />
      case 'register':
        return <RegisterPage />
      case 'subscription':
        return <SubscriptionPage />
      case 'webhooks':
        return <WebhooksPage />
      case 'diagnose':
        return <DiagnosePage />
      case 'configSync':
        return <ConfigSyncPage />
      case 'logs':
        return <LogsPage />
      case 'settings':
        return <SettingsPage />
      case 'about':
        return <AboutPage />
      default:
        return <HomePage />
    }
  }

  return (
    <div className="h-screen ambient-bg overflow-hidden flex flex-col">
      <TitleBar />
      <div className="flex-1 min-h-0 flex gap-2 p-2">
        <Sidebar
          currentPage={currentPage}
          onPageChange={setCurrentPage}
          collapsed={sidebarCollapsed}
          onToggleCollapse={() => setSidebarCollapsed(!sidebarCollapsed)}
        />
        <main className="flex-1 min-w-0 overflow-hidden rounded-3xl page-surface">
          <AnimatePresence mode="wait">
            <motion.div
              key={currentPage}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -4 }}
              transition={{ duration: 0.25, ease: [0.4, 0, 0.2, 1] }}
              className="h-full flex flex-col"
            >
              {renderPage()}
            </motion.div>
          </AnimatePresence>
        </main>
      </div>
      <UpdateDialog />
      <CloseConfirmDialog />
    </div>
  )
}

export default App
