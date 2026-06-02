import { useState, useCallback, useEffect, useRef, useMemo } from 'react'
import { createPortal } from 'react-dom'
import { useVirtualizer } from '@tanstack/react-virtual'
import { useAccountsStore } from '@/store/accounts'
import { Button, Card, CardContent } from '../ui'
import { 
  CreditCard, 
  ExternalLink, 
  Copy, 
  Download, 
  Loader2, 
  CheckCircle, 
  XCircle, 
  CheckSquare, 
  Square, 
  Minus,
  RefreshCw,
  Trash2,
  Zap,
  ShieldCheck,
  AlertTriangle,
  Ban,
  Upload,
  ListChecks,
  X
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useTranslation } from '@/hooks/useTranslation'

/**
 * 订阅升级前预检：从一个账号视角判断它是否可参与批量升级
 * 返回 { eligible: bool, reason?: string }
 */
type EligibilityReason = 'ok' | 'no-token' | 'already-pro' | 'banned' | 'cant-upgrade' | 'unknown-status'
function checkUpgradeEligibility(account: ReturnType<typeof useAccountsStore.getState>['accounts'] extends Map<string, infer T> ? T : never): { eligible: boolean; reason: EligibilityReason; detail?: string } {
  if (!account.credentials?.accessToken) return { eligible: false, reason: 'no-token' }

  const type = (account.subscription?.type || '').toUpperCase()
  const title = (account.subscription?.title || '').toUpperCase()
  const isFreeTier = type.includes('FREE') || title.includes('FREE') || (!type && !title)
  const isAlreadyPaid = type.includes('PRO') || type.includes('ENTERPRISE') || type.includes('TEAMS')
    || title.includes('PRO') || title.includes('ENTERPRISE') || title.includes('TEAMS')

  if (isAlreadyPaid) {
    return { eligible: false, reason: 'already-pro', detail: account.subscription?.title || account.subscription?.type }
  }
  if (!isFreeTier) {
    return { eligible: false, reason: 'unknown-status', detail: account.subscription?.title || account.subscription?.type || '未检测' }
  }

  // 封禁检测
  const lastError = (account.lastError || '').toLowerCase()
  const isBanned = account.status === 'error' && (
    lastError.includes('suspended') || lastError.includes('封禁') || lastError.includes('temporarily')
  )
  if (isBanned) {
    return { eligible: false, reason: 'banned', detail: account.lastError }
  }

  // upgradeCapability 检查（API 明确表示不可升级时）
  const upgradeCap = account.subscription?.upgradeCapability
  if (upgradeCap && upgradeCap.toUpperCase().includes('NOT')) {
    return { eligible: false, reason: 'cant-upgrade', detail: upgradeCap }
  }

  return { eligible: true, reason: 'ok' }
}

type SubTab = 'overage' | 'links' | 'manage'

interface SubscriptionPlan {
  name: string
  qSubscriptionType: string
  description: { title: string; billingInterval: string; featureHeader: string; features: string[] }
  pricing: { amount: number; currency: string }
}

interface SubscriptionLink {
  accountId: string
  email: string
  status: 'pending' | 'loading' | 'success' | 'error' | 'expired'
  url?: string
  error?: string
  /** 链接生成时间（用于估算有效期） */
  generatedAt?: number
  /** 链接是否经过本地有效性探测且通过 */
  validated?: boolean
}

interface OverageItem {
  accountId: string
  email: string
  status: 'pending' | 'loading' | 'success' | 'error' | 'skipped'
  error?: string
}

// 模块级状态：组件卸载后仍保留（同一会话内）
let _links: SubscriptionLink[] = []
let _linksNotify: ((links: SubscriptionLink[]) => void) | null = null

export function appendSubscriptionLink(link: SubscriptionLink): void {
  _links = [..._links, link]
  _linksNotify?.(_links)
}

export function updateSubscriptionLink(accountId: string, update: Partial<SubscriptionLink>): void {
  _links = _links.map(l => l.accountId === accountId ? { ...l, ...update } : l)
  _linksNotify?.(_links)
}
let _availablePlans: SubscriptionPlan[] = []
let _selectedPlanType = ''
let _selectedLinkIds: Set<string> = new Set()
let _activeTab: SubTab = 'overage'
let _overageItems: OverageItem[] = []
let _quickPickCount = 10

/**
 * 解析批量导入的链接文本：每行一条，支持纯 URL 或「邮箱<分隔符>URL」
 * 分隔符兼容空格 / 逗号 / Tab / 竖线 / ----，URL 自动从行内提取
 */
function parseImportedLinks(text: string): Array<{ email: string; url: string }> {
  const out: Array<{ email: string; url: string }> = []
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim()
    if (!line) continue
    const m = line.match(/https?:\/\/[^\s,|]+/i)
    if (!m || m.index === undefined) continue
    const url = m[0].replace(/[)\]}>.,;'"]+$/, '')
    const prefix = line.slice(0, m.index).trim()
    const emailMatch = prefix.match(/[^\s,|<>"']+@[^\s,|<>"']+\.[^\s,|<>"']+/)
    out.push({ email: emailMatch ? emailMatch[0] : '', url })
  }
  return out
}

export function SubscriptionPage() {
  const { accounts, selectedIds, updateAccount } = useAccountsStore()
  const { actualLanguage } = useTranslation()
  const isEn = actualLanguage === 'en'

  const [activeTab, setActiveTabState] = useState<SubTab>(_activeTab)
  const setActiveTab = (v: SubTab) => { _activeTab = v; setActiveTabState(v) }
  
  const [links, setLinksState] = useState<SubscriptionLink[]>(_links)
  const [isFetching, setIsFetching] = useState(false)
  const [selectedLinkIds, setSelectedLinkIdsState] = useState<Set<string>>(_selectedLinkIds)
  // 批量导入链接对话框
  const [showImportDialog, setShowImportDialog] = useState(false)
  // 快选：从顶部按设定数量分批选择可用链接（默认 10，跨页面记忆）
  const [quickPickCount, setQuickPickCountState] = useState(_quickPickCount)
  const [quickPickCursor, setQuickPickCursor] = useState(0)
  const setQuickPickCount = (n: number) => { _quickPickCount = n; setQuickPickCountState(n) }
  
  // 计划选择相关
  const [availablePlans, setAvailablePlansState] = useState<SubscriptionPlan[]>(_availablePlans)
  const [selectedPlanType, setSelectedPlanTypeState] = useState<string>(_selectedPlanType)
  const [isLoadingPlans, setIsLoadingPlans] = useState(false)

  // 超额相关
  const [overageItems, setOverageItemsState] = useState<OverageItem[]>(_overageItems)
  const [isSettingOverage, setIsSettingOverage] = useState(false)
  const overageListRef = useRef<HTMLDivElement>(null)

  // 包装 setter，同步更新模块级变量
  const setLinks = (val: SubscriptionLink[] | ((prev: SubscriptionLink[]) => SubscriptionLink[])) => {
    setLinksState(prev => {
      const next = typeof val === 'function' ? val(prev) : val
      _links = next
      return next
    })
  }
  const setSelectedLinkIds = (val: Set<string> | ((prev: Set<string>) => Set<string>)) => {
    setSelectedLinkIdsState(prev => {
      const next = typeof val === 'function' ? val(prev) : val
      _selectedLinkIds = next
      return next
    })
  }
  const setAvailablePlans = (val: SubscriptionPlan[]) => {
    _availablePlans = val
    setAvailablePlansState(val)
  }
  const setSelectedPlanType = (val: string) => {
    _selectedPlanType = val
    setSelectedPlanTypeState(val)
  }
  const setOverageItems = (val: OverageItem[] | ((prev: OverageItem[]) => OverageItem[])) => {
    setOverageItemsState(prev => {
      const next = typeof val === 'function' ? val(prev) : val
      _overageItems = next
      return next
    })
  }

  // 注册外部写入回调（让 appendSubscriptionLink/updateSubscriptionLink 同步 React state）
  useEffect(() => {
    _linksNotify = setLinksState
    return () => { _linksNotify = null }
  }, [])

  // 超额列表自动滚动到底部
  useEffect(() => {
    const el = overageListRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [overageItems])

  // 获取可升级的 FREE 账户（从选中或全部）
  const getUpgradeableAccounts = useCallback(() => {
    const source = selectedIds.size > 0 
      ? Array.from(selectedIds).map(id => accounts.get(id)).filter(Boolean)
      : Array.from(accounts.values())
    
    return source.filter(acc => {
      if (!acc) return false
      const type = (acc.subscription?.type || '').toUpperCase()
      const title = (acc.subscription?.title || '').toUpperCase()
      const isFreeTier = type.includes('FREE') || title.includes('FREE') || (!type && !title)
      const hasToken = !!acc.credentials?.accessToken
      return isFreeTier && hasToken
    })
  }, [accounts, selectedIds])

  // 订阅升级前预检：基于"选中账号或全部账号"做完整检查，列出可升级 / 不可升级原因
  const preflightReport = useMemo(() => {
    const source = selectedIds.size > 0
      ? Array.from(selectedIds).map(id => accounts.get(id)).filter(Boolean)
      : Array.from(accounts.values())
    const eligible: typeof source = []
    const blocked: Array<{ account: NonNullable<typeof source[number]>; reason: EligibilityReason; detail?: string }> = []
    for (const acc of source) {
      if (!acc) continue
      const r = checkUpgradeEligibility(acc)
      if (r.eligible) eligible.push(acc)
      else blocked.push({ account: acc, reason: r.reason, detail: r.detail })
    }
    // 按 reason 分桶
    const reasonBuckets: Record<EligibilityReason, number> = {
      'ok': eligible.length,
      'no-token': 0, 'already-pro': 0, 'banned': 0, 'cant-upgrade': 0, 'unknown-status': 0
    }
    for (const b of blocked) reasonBuckets[b.reason]++
    return { eligible, blocked, reasonBuckets, totalScanned: source.length }
  }, [accounts, selectedIds])

  // 加载可用订阅计划（用任一可用账户调用）
  const handleLoadPlans = async () => {
    const upgradeableAccounts = getUpgradeableAccounts()
    if (upgradeableAccounts.length === 0) return

    setIsLoadingPlans(true)
    const acc = upgradeableAccounts[0]!
    
    try {
      const result = await window.api.accountGetSubscriptions(
        acc.credentials.accessToken,
        acc.credentials?.region,
        acc.profileArn,
        acc.machineId,
        acc.credentials?.provider || acc.idp,
        acc.credentials?.authMethod,
        acc.id
      )
      if (result.success && result.plans && result.plans.length > 0) {
        setAvailablePlans(result.plans)
        // 默认选择第一个 PRO 计划
        const defaultPlan = result.plans.find(p => 
          p.qSubscriptionType?.toUpperCase().includes('PRO') && !p.qSubscriptionType?.toUpperCase().includes('PLUS')
        ) || result.plans[0]
        setSelectedPlanType(defaultPlan.qSubscriptionType)
      }
    } catch (error) {
      console.error('[SubscriptionPage] Failed to load plans:', error)
    }
    setIsLoadingPlans(false)
  }

  // 并发数
  const [concurrency, setConcurrency] = useState(5)

  // 批量并发获取订阅链接
  const handleBatchFetch = async () => {
    const upgradeableAccounts = getUpgradeableAccounts()
    if (upgradeableAccounts.length === 0 || !selectedPlanType) return

    setIsFetching(true)
    
    // 初始化状态
    const initialLinks: SubscriptionLink[] = upgradeableAccounts.map(acc => ({
      accountId: acc!.id,
      email: acc!.email || 'Unknown',
      status: 'pending'
    }))
    setLinks(initialLinks)
    setSelectedLinkIds(new Set())

    // 单个账号获取任务
    const fetchOne = async (idx: number) => {
      const acc = upgradeableAccounts[idx]!
      setLinks(prev => prev.map((link, i) => 
        i === idx ? { ...link, status: 'loading' } : link
      ))

      try {
        const tokenResult = await window.api.accountGetSubscriptionUrl(
          acc.credentials.accessToken,
          selectedPlanType,
          acc.credentials?.region,
          acc.profileArn,
          acc.machineId,
          acc.credentials?.provider || acc.idp,
          acc.credentials?.authMethod,
          acc.id
        )

        if (tokenResult.success && tokenResult.url) {
          setLinks(prev => prev.map((link, i) => 
            i === idx ? { ...link, status: 'success', url: tokenResult.url, generatedAt: Date.now(), validated: false } : link
          ))
        } else {
          setLinks(prev => prev.map((link, i) => 
            i === idx ? { ...link, status: 'error', error: tokenResult.error || 'Failed to get URL' } : link
          ))
        }
      } catch (error) {
        setLinks(prev => prev.map((link, i) => 
          i === idx ? { ...link, status: 'error', error: error instanceof Error ? error.message : 'Unknown error' } : link
        ))
      }
    }

    // 并发池执行
    const indices = Array.from({ length: upgradeableAccounts.length }, (_, i) => i)
    let cursor = 0
    const runNext = async (): Promise<void> => {
      while (cursor < indices.length) {
        const idx = cursor++
        await fetchOne(idx)
      }
    }
    const workers = Array.from({ length: Math.min(concurrency, indices.length) }, () => runNext())
    await Promise.all(workers)

    setIsFetching(false)
  }

  // 选择/取消选择链接（允许任意状态）
  const toggleLinkSelection = (accountId: string) => {
    setSelectedLinkIds(prev => {
      const next = new Set(prev)
      if (next.has(accountId)) {
        next.delete(accountId)
      } else {
        next.add(accountId)
      }
      return next
    })
  }

  // 全选 / 取消全选当前列表所有链接（不再限制只能选 success）
  const toggleSelectAll = () => {
    if (selectedLinkIds.size === links.length && links.length > 0) {
      setSelectedLinkIds(new Set())
    } else {
      setSelectedLinkIds(new Set(links.map(l => l.accountId)))
    }
  }

  // 反选
  const invertSelection = () => {
    setSelectedLinkIds(prev => {
      const next = new Set<string>()
      for (const l of links) {
        if (!prev.has(l.accountId)) next.add(l.accountId)
      }
      return next
    })
  }

  // 取消多选（清空选择）
  const clearSelection = () => {
    setSelectedLinkIds(new Set())
  }

  // 按状态选择：把指定状态的链接加入到当前选择集（保留已有选择）
  const selectByStatus = (status: SubscriptionLink['status']) => {
    setSelectedLinkIds(prev => {
      const next = new Set(prev)
      for (const l of links) {
        if (l.status === status) next.add(l.accountId)
      }
      return next
    })
  }

  // 快选：从顶部开始选中前 N 个可用（success）链接，便于分批打开
  const quickPickTop = () => {
    const successList = links.filter(l => l.status === 'success' && l.url)
    const n = Math.max(1, quickPickCount)
    const picked = successList.slice(0, n)
    setSelectedLinkIds(new Set(picked.map(l => l.accountId)))
    setQuickPickCursor(picked.length)
  }

  // 快选下一批：从上次游标继续选 N 个可用链接，到末尾后循环回到开头
  const quickPickNext = () => {
    const successList = links.filter(l => l.status === 'success' && l.url)
    if (successList.length === 0) return
    const n = Math.max(1, quickPickCount)
    let start = quickPickCursor
    if (start >= successList.length) start = 0
    const picked = successList.slice(start, start + n)
    setSelectedLinkIds(new Set(picked.map(l => l.accountId)))
    setQuickPickCursor(start + picked.length)
  }

  // 批量导入外部链接：解析后以 success 状态追加进列表（按 url 去重），即可与现有链接一样多选/打开/导出
  const handleImportLinks = (text: string): number => {
    const parsed = parseImportedLinks(text)
    if (parsed.length === 0) return 0
    const existingUrls = new Set(links.map(l => l.url).filter(Boolean) as string[])
    const now = Date.now()
    const added: SubscriptionLink[] = []
    let seq = links.length
    for (const { email, url } of parsed) {
      if (existingUrls.has(url)) continue
      existingUrls.add(url)
      seq++
      added.push({
        accountId: `import-${crypto.randomUUID()}`,
        email: email || (isEn ? `(Imported #${seq})` : `(导入 #${seq})`),
        status: 'success',
        url,
        generatedAt: now,
        validated: false
      })
    }
    if (added.length > 0) setLinks(prev => [...prev, ...added])
    return added.length
  }

  // 批量删除选中的链接（从结果列表中移除，不会调用任何 API）
  const handleBatchDelete = () => {
    if (selectedLinkIds.size === 0) return
    if (!confirm(isEn
      ? `Remove ${selectedLinkIds.size} selected links from the list?`
      : `从列表移除选中的 ${selectedLinkIds.size} 个链接？`
    )) return
    setLinks(prev => prev.filter(l => !selectedLinkIds.has(l.accountId)))
    setSelectedLinkIds(new Set())
  }

  // 批量删除"失败 + 过期"：清理无效项，保留可用链接
  const handleDeleteFailed = () => {
    const count = links.filter(l => l.status === 'error' || l.status === 'expired').length
    if (count === 0) return
    if (!confirm(isEn
      ? `Remove ${count} failed/expired links?`
      : `移除 ${count} 个失败/过期的链接？`
    )) return
    setLinks(prev => {
      const filtered = prev.filter(l => l.status !== 'error' && l.status !== 'expired')
      // 移除的 ID 也从选择集里清掉
      const removedIds = prev.filter(l => l.status === 'error' || l.status === 'expired').map(l => l.accountId)
      if (removedIds.length > 0) {
        setSelectedLinkIds(s => {
          const next = new Set(s)
          for (const id of removedIds) next.delete(id)
          return next
        })
      }
      return filtered
    })
  }

  // 获取目标链接列表（选中的或全部成功的）
  const getTargetLinks = (mode: 'selected' | 'all'): SubscriptionLink[] => {
    const successLinks = links.filter(l => l.status === 'success' && l.url)
    if (mode === 'selected') {
      return successLinks.filter(l => selectedLinkIds.has(l.accountId))
    }
    return successLinks
  }

  // 打开单个链接
  const handleOpenLink = async (url: string) => {
    await window.api.openSubscriptionWindow(url)
  }

  // 重新生成单个链接（链接过期时调用）
  const handleRegenerateLink = async (accountId: string): Promise<void> => {
    if (!selectedPlanType) {
      alert(isEn ? 'Please select a plan first' : '请先选择计划')
      return
    }
    const acc = accounts.get(accountId)
    if (!acc || !acc.credentials?.accessToken) return

    setLinks(prev => prev.map((l) => l.accountId === accountId ? { ...l, status: 'loading', error: undefined } : l))
    try {
      const r = await window.api.accountGetSubscriptionUrl(
        acc.credentials.accessToken,
        selectedPlanType,
        acc.credentials?.region,
        acc.profileArn,
        acc.machineId,
        acc.credentials?.provider || acc.idp,
        acc.credentials?.authMethod,
        acc.id
      )
      setLinks(prev => prev.map((l) =>
        l.accountId === accountId
          ? (r.success && r.url
            ? { ...l, status: 'success', url: r.url, error: undefined, generatedAt: Date.now(), validated: false }
            : { ...l, status: 'error', error: r.error || 'Failed' }
          )
          : l
      ))
    } catch (err) {
      setLinks(prev => prev.map((l) =>
        l.accountId === accountId
          ? { ...l, status: 'error', error: err instanceof Error ? err.message : 'Unknown error' }
          : l
      ))
    }
  }

  // 检测所有链接有效性：基于生成时间 + 真实 HTTP HEAD 探测（C5）
  const [isValidatingLinks, setIsValidatingLinks] = useState(false)
  const handleValidateLinks = async (): Promise<void> => {
    setIsValidatingLinks(true)
    try {
      const targets = links.filter((l) => l.status === 'success' && l.url)
      const STALE_AFTER_MS = 15 * 60 * 1000
      const now = Date.now()

      // 先按时间标记 expired，剩下的并发用 HTTP 探测真实可达性
      const checkResults: Record<string, 'success' | 'expired'> = {}
      const realProbe = targets.filter((l) => {
        const age = l.generatedAt ? now - l.generatedAt : Number.POSITIVE_INFINITY
        if (age > STALE_AFTER_MS) {
          checkResults[l.accountId] = 'expired'
          return false
        }
        return true
      })

      // 并发探测剩余链接（限制并发以免 DDoS 自己 / 触发风控）
      let cursor = 0
      const worker = async (): Promise<void> => {
        while (cursor < realProbe.length) {
          const idx = cursor++
          const l = realProbe[idx]
          if (!l.url) continue
          try {
            const r = await window.api.diagnoseHttpProbe({ url: l.url, method: 'HEAD', timeoutMs: 6000 })
            // 4xx/5xx 视为失效，2xx/3xx 视为有效
            checkResults[l.accountId] = r.success || (r.status !== undefined && r.status < 400)
              ? 'success'
              : 'expired'
          } catch {
            checkResults[l.accountId] = 'expired'
          }
        }
      }
      const workers = Array.from({ length: Math.min(concurrency, realProbe.length) }, () => worker())
      await Promise.all(workers)

      const next = links.map((l) => {
        const result = checkResults[l.accountId]
        if (!result) return l
        if (result === 'expired') {
          return { ...l, status: 'expired' as const, error: '链接已失效（HTTP 探测失败或超过 15 分钟）' }
        }
        return { ...l, validated: true }
      })
      setLinks(next)

      const expired = next.filter((l) => l.status === 'expired').length
      const valid = next.filter((l) => l.status === 'success' && l.validated).length
      addLog(`[Validate] 检测完成：${valid} 个有效，${expired} 个失效`)
    } finally {
      setIsValidatingLinks(false)
    }
  }
  // 简易日志（订阅页没有 addLog，仅 console）
  function addLog(msg: string): void {
    console.log(`[SubscriptionPage] ${msg}`)
  }

  // 批量打开链接（全部同时打开）
  const handleBatchOpen = async (mode: 'selected' | 'all') => {
    const targetLinks = getTargetLinks(mode)
    await Promise.all(
      targetLinks
        .filter(l => l.url)
        .map(l => window.api.openSubscriptionWindow(l.url!))
    )
  }

  // 复制单个链接
  const handleCopyLink = async (url: string) => {
    await navigator.clipboard.writeText(url)
  }

  // 导出链接
  const handleExport = async (mode: 'selected' | 'all') => {
    const targetLinks = getTargetLinks(mode)
    const text = targetLinks.map(l => l.url).join('\n')
    await navigator.clipboard.writeText(text)
  }

  // ===== 一键超额功能 =====
  // 获取可设置超额的账号（仅未开启）：已订阅（非 Free）、有 token、超额能力可用、超额未开启
  const getOverageableAccounts = useCallback(() => {
    return getAllSubscribedAccounts().filter(acc => acc && acc.subscription?.overageCapability === 'OVERAGE_CAPABLE' && acc.usage?.resourceDetail?.overageEnabled !== true)
  }, [accounts, selectedIds])

  // 获取所有已订阅账号（不限制超额能力，不限制是否已开启）
  const getAllSubscribedAccounts = useCallback(() => {
    const source = selectedIds.size > 0
      ? Array.from(selectedIds).map(id => accounts.get(id)).filter(Boolean)
      : Array.from(accounts.values())

    return source.filter(acc => {
      if (!acc) return false
      const hasToken = !!acc.credentials?.accessToken
      const type = (acc.subscription?.type || '').toUpperCase()
      const title = (acc.subscription?.title || '').toUpperCase()
      const isSubscribed = type.includes('PRO') || type.includes('ENTERPRISE') || type.includes('TEAMS') || title.includes('PRO') || title.includes('ENTERPRISE') || title.includes('TEAMS')
      return hasToken && isSubscribed
    })
  }, [accounts, selectedIds])

  const handleBatchSetOverage = async (customTargets?: NonNullable<ReturnType<typeof getAllSubscribedAccounts>>) => {
    const targets = customTargets ?? getOverageableAccounts()
    if (targets.length === 0) return

    setIsSettingOverage(true)

    // 初始化列表
    const initialItems: OverageItem[] = targets.map(acc => ({
      accountId: acc!.id,
      email: acc!.email || 'Unknown',
      status: 'pending'
    }))
    setOverageItems(initialItems)

    const setOne = async (idx: number) => {
      const acc = targets[idx]!
      setOverageItems(prev => prev.map((item, i) =>
        i === idx ? { ...item, status: 'loading' } : item
      ))

      try {
        const res = await window.api.accountSetOverage(
          acc.credentials.accessToken,
          'ENABLED',
          acc.credentials?.region,
          acc.profileArn,
          acc.machineId,
          acc.credentials?.provider || acc.idp,
          acc.credentials?.authMethod,
          acc.id
        )
        if (res.success) {
          setOverageItems(prev => prev.map((item, i) =>
            i === idx ? { ...item, status: 'success' } : item
          ))
          // 更新 store 中账号的超额状态，使 UI 即时反映
          const existing = accounts.get(acc.id)
          if (existing) {
            updateAccount(acc.id, {
              usage: {
                ...existing.usage,
                resourceDetail: {
                  ...existing.usage?.resourceDetail,
                  overageEnabled: true
                }
              }
            })
          }
        } else {
          setOverageItems(prev => prev.map((item, i) =>
            i === idx ? { ...item, status: 'error', error: res.error || 'Unknown error' } : item
          ))
        }
      } catch (e) {
        setOverageItems(prev => prev.map((item, i) =>
          i === idx ? { ...item, status: 'error', error: e instanceof Error ? e.message : 'Unknown error' } : item
        ))
      }
    }

    // 并发池
    let cursor = 0
    const runNext = async (): Promise<void> => {
      while (cursor < targets.length) {
        const idx = cursor++
        await setOne(idx)
      }
    }
    const workers = Array.from({ length: Math.min(concurrency, targets.length) }, () => runNext())
    await Promise.all(workers)

    setIsSettingOverage(false)
  }

  const overageableCount = getOverageableAccounts().length
  const allSubscribedCount = getAllSubscribedAccounts().length
  const overageSuccessCount = overageItems.filter(i => i.status === 'success').length
  const overageErrorCount = overageItems.filter(i => i.status === 'error').length

  const successCount = links.filter(l => l.status === 'success').length
  const errorCount = links.filter(l => l.status === 'error').length
  const selectedCount = selectedLinkIds.size
  const upgradeableCount = getUpgradeableAccounts().length

  return (
    <div className="flex-1 p-6 space-y-6 overflow-auto">
      {/* Header */}
      <div className="page-hero p-6">
        <div className="absolute top-0 right-0 w-32 h-32 bg-gradient-to-br from-primary/20 to-transparent rounded-full blur-2xl" />
        <div className="absolute bottom-0 left-0 w-24 h-24 bg-gradient-to-tr from-primary/20 to-transparent rounded-full blur-2xl" />
        <div className="relative flex items-center gap-4">
          <div className="p-3 rounded-xl bg-primary/10">
            <CreditCard className="h-7 w-7 text-primary" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-primary">{isEn ? 'Batch Subscription' : '批量订阅'}</h1>
            <p className="text-sm text-muted-foreground">
              {selectedIds.size > 0
                ? (isEn ? `Using ${selectedIds.size} selected accounts` : `使用已选中的 ${selectedIds.size} 个账户`)
                : (isEn ? 'Using all accounts' : '使用全部账户')
              }
            </p>
          </div>
        </div>
      </div>

      {/* 内部 Tab 切换 */}
      <div className="flex gap-1 p-1 bg-muted rounded-lg w-fit">
        <button
          onClick={() => setActiveTab('overage')}
          className={cn(
            'px-4 py-1.5 rounded-md text-sm font-medium transition-colors flex items-center gap-1.5',
            activeTab === 'overage'
              ? 'bg-background shadow text-foreground'
              : 'text-muted-foreground hover:text-foreground'
          )}
        >
          <Zap className="h-4 w-4" />
          {isEn ? 'Overage Settings' : '超额设置'}
        </button>
        <button
          onClick={() => setActiveTab('links')}
          className={cn(
            'px-4 py-1.5 rounded-md text-sm font-medium transition-colors flex items-center gap-1.5',
            activeTab === 'links'
              ? 'bg-background shadow text-foreground'
              : 'text-muted-foreground hover:text-foreground'
          )}
        >
          <CreditCard className="h-4 w-4" />
          {isEn ? 'Subscription Links' : '获取链接'}
        </button>
        <button
          onClick={() => setActiveTab('manage')}
          className={cn(
            'px-4 py-1.5 rounded-md text-sm font-medium transition-colors flex items-center gap-1.5',
            activeTab === 'manage'
              ? 'bg-background shadow text-foreground'
              : 'text-muted-foreground hover:text-foreground'
          )}
        >
          <ShieldCheck className="h-4 w-4" />
          {isEn ? 'Manage Subscriptions' : '订阅管理'}
        </button>
      </div>

      {/* ===== 超额设置 Tab ===== */}
      {activeTab === 'overage' && (
        <>
          {/* 操作栏 */}
          <Card>
            <CardContent className="py-3 flex items-center gap-2 flex-wrap">
              <Button
                size="sm"
                onClick={() => handleBatchSetOverage()}
                disabled={isSettingOverage || overageableCount === 0}
              >
                {isSettingOverage ? (
                  <Loader2 className="h-4 w-4 mr-1 animate-spin" />
                ) : (
                  <Zap className="h-4 w-4 mr-1" />
                )}
                {isEn
                  ? `Enable Overage (${overageableCount})`
                  : `一键超额 (${overageableCount})`
                }
              </Button>

              <Button
                size="sm"
                variant="outline"
                onClick={() => handleBatchSetOverage(getAllSubscribedAccounts())}
                disabled={isSettingOverage || allSubscribedCount === 0}
              >
                {isSettingOverage ? (
                  <Loader2 className="h-4 w-4 mr-1 animate-spin" />
                ) : (
                  <Zap className="h-4 w-4 mr-1" />
                )}
                {isEn
                  ? `Set All (${allSubscribedCount})`
                  : `全部设置 (${allSubscribedCount})`
                }
              </Button>

              <Button
                variant="ghost"
                size="sm"
                onClick={() => setOverageItems([])}
                disabled={isSettingOverage || overageItems.length === 0}
              >
                <Trash2 className="h-4 w-4 mr-1" />
                {isEn ? 'Clear' : '清空'}
              </Button>

              {/* 仅删除失败项（保留成功结果便于审计） */}
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setOverageItems(prev => prev.filter(it => it.status !== 'error'))}
                disabled={isSettingOverage || overageErrorCount === 0}
                title={isEn ? 'Remove failed items only' : '仅移除失败项'}
              >
                <XCircle className="h-4 w-4 mr-1" />
                {isEn ? `Clear Failed (${overageErrorCount})` : `清失败 (${overageErrorCount})`}
              </Button>

              {/* 并发数控制 */}
              <div className="flex items-center gap-1 text-xs">
                <span className="text-muted-foreground">{isEn ? 'Concurrency:' : '并发:'}</span>
                <input
                  type="number"
                  min={1}
                  max={100}
                  value={concurrency}
                  onChange={(e) => {
                    const val = parseInt(e.target.value, 10)
                    if (val > 0) setConcurrency(val)
                  }}
                  disabled={isSettingOverage}
                  className="h-7 w-14 px-1.5 rounded border border-border bg-background text-xs text-center"
                />
              </div>

              <span className="text-xs text-muted-foreground ml-2">
                {overageableCount > 0
                  ? (isEn ? `${overageableCount} subscribed accounts without overage enabled` : `${overageableCount} 个已订阅账号未开启超额`)
                  : (isEn ? 'No accounts need overage enablement' : '没有需要开启超额的账号')
                }
              </span>

              {/* 统计 */}
              {overageItems.length > 0 && (
                <div className="ml-auto flex items-center gap-3 text-xs text-muted-foreground">
                  {overageSuccessCount > 0 && (
                    <span className="flex items-center gap-1 text-green-600">
                      <CheckCircle className="h-3 w-3" /> {overageSuccessCount}
                    </span>
                  )}
                  {overageErrorCount > 0 && (
                    <span className="flex items-center gap-1 text-red-500">
                      <XCircle className="h-3 w-3" /> {overageErrorCount}
                    </span>
                  )}
                  {isSettingOverage && (
                    <span className="flex items-center gap-1">
                      <Loader2 className="h-3 w-3 animate-spin" />
                      {overageItems.filter(i => i.status === 'pending' || i.status === 'loading').length}
                    </span>
                  )}
                </div>
              )}
            </CardContent>
          </Card>

          {/* 超额结果列表 */}
          {overageItems.length > 0 && (
            <Card>
              <CardContent className="py-2">
                {/* 表头 */}
                <div className="flex items-center gap-3 py-2 px-2 border-b text-xs font-medium text-muted-foreground">
                  <span className="w-8 text-center">#</span>
                  <span className="flex-1">{isEn ? 'Email' : '邮箱'}</span>
                  <span className="w-20 text-center">{isEn ? 'Status' : '状态'}</span>
                  <span className="flex-1 text-right">{isEn ? 'Details' : '详情'}</span>
                </div>

                {/* 列表 */}
                <div ref={overageListRef} className="max-h-[60vh] overflow-y-auto">
                  {overageItems.map((item, idx) => (
                    <div
                      key={item.accountId}
                      className="flex items-center gap-3 py-2 px-2 border-b last:border-b-0 hover:bg-muted/50 transition-colors"
                    >
                      <span className="w-8 text-center text-xs text-muted-foreground">{idx + 1}</span>
                      <span className="flex-1 text-sm truncate" title={item.email}>{item.email}</span>
                      <span className="w-20 flex justify-center">
                        {item.status === 'pending' && (
                          <span className="text-xs text-muted-foreground">{isEn ? 'Pending' : '等待中'}</span>
                        )}
                        {item.status === 'loading' && (
                          <Loader2 className="h-4 w-4 animate-spin text-blue-500" />
                        )}
                        {item.status === 'success' && (
                          <CheckCircle className="h-4 w-4 text-green-500" />
                        )}
                        {item.status === 'error' && (
                          <XCircle className="h-4 w-4 text-red-500" />
                        )}
                        {item.status === 'skipped' && (
                          <span className="text-xs text-muted-foreground">{isEn ? 'Skipped' : '跳过'}</span>
                        )}
                      </span>
                      <span className="flex-1 text-right text-xs truncate">
                        {item.status === 'success' && (
                          <span className="text-green-600">{isEn ? 'Overage enabled' : '超额已开启'}</span>
                        )}
                        {item.status === 'error' && (
                          <span className="text-red-500" title={item.error}>{item.error}</span>
                        )}
                      </span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* 账号超额状态总览（未执行批量操作时显示） */}
          {overageItems.length === 0 && (
            <Card>
              <CardContent className="py-2">
                <div className="flex items-center gap-3 py-2 px-2 border-b text-xs font-medium text-muted-foreground">
                  <span className="w-8 text-center">#</span>
                  <span className="flex-1">{isEn ? 'Email' : '邮箱'}</span>
                  <span className="w-24 text-center">{isEn ? 'Subscription' : '订阅类型'}</span>
                  <span className="w-24 text-center">{isEn ? 'Overage Capable' : '超额能力'}</span>
                  <span className="w-24 text-center">{isEn ? 'Overage Status' : '超额状态'}</span>
                </div>
                {allSubscribedCount > 0 ? (
                  <div className="max-h-[60vh] overflow-y-auto">
                    {getAllSubscribedAccounts().map((acc, idx) => {
                      if (!acc) return null
                      const capable = acc.subscription?.overageCapability === 'OVERAGE_CAPABLE'
                      const enabled = acc.usage?.resourceDetail?.overageEnabled === true
                      return (
                        <div
                          key={acc.id}
                          className="flex items-center gap-3 py-2 px-2 border-b last:border-b-0 hover:bg-muted/50 transition-colors"
                        >
                          <span className="w-8 text-center text-xs text-muted-foreground">{idx + 1}</span>
                          <span className="flex-1 text-sm truncate" title={acc.email}>{acc.email}</span>
                          <span className="w-24 text-center text-xs">
                            {acc.subscription?.title || acc.subscription?.type || '-'}
                          </span>
                          <span className="w-24 flex justify-center">
                            {capable ? (
                              <CheckCircle className="h-4 w-4 text-green-500" />
                            ) : (
                              <XCircle className="h-4 w-4 text-muted-foreground/40" />
                            )}
                          </span>
                          <span className="w-24 flex justify-center">
                            {enabled ? (
                              <span className="text-xs text-green-600 font-medium">{isEn ? 'ENABLED' : '已开启'}</span>
                            ) : capable ? (
                              <span className="text-xs text-amber-500 font-medium">{isEn ? 'DISABLED' : '未开启'}</span>
                            ) : (
                              <span className="text-xs text-muted-foreground">-</span>
                            )}
                          </span>
                        </div>
                      )
                    })}
                  </div>
                ) : (
                  <div className="py-12 text-center text-muted-foreground">
                    <Zap className="h-12 w-12 mx-auto mb-3 opacity-30" />
                    <p className="text-sm">
                      {isEn
                        ? 'No subscribed accounts found. Ensure accounts are checked first.'
                        : '未找到已订阅账号。请先检测账号状态。'}
                    </p>
                  </div>
                )}
              </CardContent>
            </Card>
          )}
        </>
      )}

      {/* ===== 订阅管理 Tab ===== */}
      {activeTab === 'manage' && (
        <ManageSubscriptionsTab
          getAllSubscribed={getAllSubscribedAccounts}
          updateAccount={updateAccount}
          concurrency={concurrency}
          isEn={isEn}
        />
      )}

      {false && false && (
        <>
          {/* 说明（被新的 ManageSubscriptionsTab 替代，保留作为 dead code 防止意外删除 - eslint 已忽略） */}
          <Card className="border-blue-200 dark:border-blue-800 bg-blue-50/50 dark:bg-blue-950/10">
            <CardContent className="py-3 space-y-2">
              <div className="flex items-center gap-2">
                <ShieldCheck className="h-4 w-4 text-blue-600" />
                <span className="text-sm font-medium">
                  {isEn ? 'Subscription Lifecycle Management' : '订阅生命周期管理'}
                </span>
              </div>
              <p className="text-xs text-muted-foreground">
                {isEn
                  ? 'Cancel or downgrade subscriptions. Kiro/AWS does not provide a direct cancel API for OIDC accounts — clicking "Get cancel URL" generates the same subscription portal link used for upgrade, where you can manage/cancel via AWS billing console.'
                  : '取消或降级订阅。Kiro/AWS 对 OIDC 账号未公开取消订阅的直接 API，点击"获取取消链接"会生成订阅门户链接，可在 AWS 计费控制台手动管理/取消订阅。'
                }
              </p>
            </CardContent>
          </Card>

          {/* 已订阅账号列表 */}
          <Card>
            <CardContent className="py-0 px-0">
              <div className="flex items-center gap-3 py-2 px-3 border-b text-xs font-medium text-muted-foreground bg-muted/30">
                <span className="w-8 text-center">#</span>
                <span className="flex-1">{isEn ? 'Email' : '邮箱'}</span>
                <span className="w-32 text-center">{isEn ? 'Plan' : '订阅类型'}</span>
                <span className="w-32 text-center">{isEn ? 'Expires' : '到期'}</span>
                <span className="w-40 text-center">{isEn ? 'Actions' : '操作'}</span>
              </div>

              {(() => {
                const subscribed = getAllSubscribedAccounts()
                if (subscribed.length === 0) {
                  return (
                    <div className="py-12 text-center text-muted-foreground">
                      <CreditCard className="h-12 w-12 mx-auto mb-3 opacity-30" />
                      <p className="text-sm">
                        {isEn
                          ? 'No subscribed accounts found. Run "Check Accounts" first to refresh status.'
                          : '未发现已订阅账号。请先在账户页"批量检查"刷新状态。'
                        }
                      </p>
                    </div>
                  )
                }
                return (
                  <div className="max-h-[60vh] overflow-y-auto">
                    {subscribed.map((acc, idx) => {
                      if (!acc) return null
                      const planName = acc.subscription?.title || acc.subscription?.type || '-'
                      const expiresAt = acc.subscription?.expiresAt
                      const daysLeft = acc.subscription?.daysRemaining
                      return (
                        <div
                          key={acc.id}
                          className="flex items-center gap-3 py-2 px-3 border-b last:border-b-0 hover:bg-muted/40 text-xs"
                        >
                          <span className="w-8 text-center text-muted-foreground">{idx + 1}</span>
                          <span className="flex-1 truncate" title={acc.email}>{acc.email}</span>
                          <span className="w-32 text-center">
                            <span className={cn(
                              'inline-block px-2 py-0.5 rounded text-[10px] font-medium',
                              planName.toUpperCase().includes('PRO+') || planName.toUpperCase().includes('PRO_PLUS')
                                ? 'bg-purple-500/15 text-purple-700 dark:text-purple-300'
                                : planName.toUpperCase().includes('POWER')
                                  ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300'
                                  : planName.toUpperCase().includes('PRO')
                                    ? 'bg-blue-500/15 text-blue-700 dark:text-blue-300'
                                    : 'bg-muted text-muted-foreground'
                            )}>
                              {planName}
                            </span>
                          </span>
                          <span className="w-32 text-center text-muted-foreground">
                            {expiresAt
                              ? new Date(expiresAt).toLocaleDateString('zh-CN')
                              : (daysLeft != null
                                ? (isEn ? `${daysLeft}d` : `${daysLeft} 天`)
                                : '-'
                              )
                            }
                          </span>
                          <span className="w-40 flex justify-center gap-1">
                            <button
                              onClick={async () => {
                                // 复用 fetchSubscriptionToken 获取门户链接，在浏览器无痕中打开
                                const r = await window.api.accountGetSubscriptionUrl(
                                  acc.credentials.accessToken,
                                  undefined,
                                  acc.credentials?.region,
                                  acc.profileArn,
                                  acc.machineId,
                                  acc.credentials?.provider || acc.idp,
                                  acc.credentials?.authMethod,
                                  acc.id
                                )
                                if (r.success && r.url) {
                                  await window.api.openSubscriptionWindow(r.url)
                                } else {
                                  alert(isEn ? `Failed: ${r.error}` : `失败: ${r.error}`)
                                }
                              }}
                              className="px-2 py-1 rounded text-[10px] bg-primary/10 text-primary hover:bg-primary/20"
                              title={isEn ? 'Open subscription portal to cancel/manage' : '打开订阅门户取消/管理'}
                            >
                              <ExternalLink className="h-3 w-3 inline mr-1" />
                              {isEn ? 'Manage' : '管理'}
                            </button>

                            {acc.usage?.resourceDetail?.overageEnabled && (
                              <button
                                onClick={async () => {
                                  if (!confirm(isEn
                                    ? `Disable overage for ${acc.email}?`
                                    : `关闭 ${acc.email} 的超额？`
                                  )) return
                                  const r = await window.api.accountSetOverage(
                                    acc.credentials.accessToken,
                                    'DISABLED',
                                    acc.credentials?.region,
                                    acc.profileArn,
                                    acc.machineId,
                                    acc.credentials?.provider || acc.idp,
                                    acc.credentials?.authMethod,
                                    acc.id
                                  )
                                  if (r.success) {
                                    updateAccount(acc.id, {
                                      usage: {
                                        ...acc.usage,
                                        resourceDetail: { ...acc.usage?.resourceDetail, overageEnabled: false }
                                      }
                                    })
                                  } else {
                                    alert(isEn ? `Failed: ${r.error}` : `失败: ${r.error}`)
                                  }
                                }}
                                className="px-2 py-1 rounded text-[10px] bg-amber-500/15 text-amber-700 hover:bg-amber-500/25"
                                title={isEn ? 'Disable overage' : '关闭超额'}
                              >
                                <Ban className="h-3 w-3 inline mr-0.5" />
                                {isEn ? 'No-Overage' : '关超额'}
                              </button>
                            )}
                          </span>
                        </div>
                      )
                    })}
                  </div>
                )
              })()}
            </CardContent>
          </Card>
        </>
      )}

      {/* ===== 获取链接 Tab ===== */}
      {activeTab === 'links' && (
        <>
          {/* 预检面板：展示可升级 / 阻塞原因 */}
          {preflightReport.totalScanned > 0 && (
            <Card className={cn(
              preflightReport.eligible.length === 0 && 'border-amber-200 dark:border-amber-800 bg-amber-50/50 dark:bg-amber-950/10'
            )}>
              <CardContent className="py-3 space-y-2">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="h-4 w-4 text-primary" />
                  <span className="text-sm font-medium">
                    {isEn ? 'Pre-flight Check' : '升级预检'}
                  </span>
                  <span className="text-xs text-muted-foreground">
                    {isEn
                      ? `Scanned ${preflightReport.totalScanned} accounts: ${preflightReport.eligible.length} eligible, ${preflightReport.blocked.length} blocked`
                      : `扫描 ${preflightReport.totalScanned} 个账号：${preflightReport.eligible.length} 可升级，${preflightReport.blocked.length} 不可升级`
                    }
                  </span>
                </div>

                {/* 阻塞分类徽章 */}
                {preflightReport.blocked.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 text-[10px]">
                    {preflightReport.reasonBuckets['already-pro'] > 0 && (
                      <span className="px-2 py-0.5 rounded bg-green-100 dark:bg-green-900/40 text-green-700 dark:text-green-300 inline-flex items-center gap-1">
                        <CheckCircle className="h-2.5 w-2.5" />
                        {isEn ? `Already subscribed: ${preflightReport.reasonBuckets['already-pro']}` : `已订阅 ${preflightReport.reasonBuckets['already-pro']}`}
                      </span>
                    )}
                    {preflightReport.reasonBuckets['no-token'] > 0 && (
                      <span className="px-2 py-0.5 rounded bg-muted text-muted-foreground inline-flex items-center gap-1">
                        <XCircle className="h-2.5 w-2.5" />
                        {isEn ? `No token: ${preflightReport.reasonBuckets['no-token']}` : `无 Token ${preflightReport.reasonBuckets['no-token']}`}
                      </span>
                    )}
                    {preflightReport.reasonBuckets['banned'] > 0 && (
                      <span className="px-2 py-0.5 rounded bg-red-100 dark:bg-red-900/40 text-red-700 dark:text-red-300 inline-flex items-center gap-1">
                        <Ban className="h-2.5 w-2.5" />
                        {isEn ? `Banned: ${preflightReport.reasonBuckets['banned']}` : `已封禁 ${preflightReport.reasonBuckets['banned']}`}
                      </span>
                    )}
                    {preflightReport.reasonBuckets['cant-upgrade'] > 0 && (
                      <span className="px-2 py-0.5 rounded bg-amber-100 dark:bg-amber-900/40 text-amber-700 dark:text-amber-300 inline-flex items-center gap-1">
                        <AlertTriangle className="h-2.5 w-2.5" />
                        {isEn ? `Can't upgrade: ${preflightReport.reasonBuckets['cant-upgrade']}` : `不可升级 ${preflightReport.reasonBuckets['cant-upgrade']}`}
                      </span>
                    )}
                    {preflightReport.reasonBuckets['unknown-status'] > 0 && (
                      <span className="px-2 py-0.5 rounded bg-blue-100 dark:bg-blue-900/40 text-blue-700 dark:text-blue-300 inline-flex items-center gap-1">
                        <AlertTriangle className="h-2.5 w-2.5" />
                        {isEn ? `Unknown status: ${preflightReport.reasonBuckets['unknown-status']}` : `状态未知 ${preflightReport.reasonBuckets['unknown-status']}`}
                      </span>
                    )}
                  </div>
                )}

                {preflightReport.eligible.length === 0 && preflightReport.totalScanned > 0 && (
                  <p className="text-xs text-amber-600 dark:text-amber-400">
                    {isEn
                      ? 'No eligible accounts. Run "Check Accounts" on the accounts page first to get latest status.'
                      : '无可升级账号。建议先在账户管理页"批量检查"获取最新状态。'
                    }
                  </p>
                )}
              </CardContent>
            </Card>
          )}

          {/* 计划选择 */}
          <Card>
            <CardContent className="py-3 space-y-3">
              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleLoadPlans}
                  disabled={isLoadingPlans || upgradeableCount === 0}
                >
                  {isLoadingPlans ? (
                    <Loader2 className="h-4 w-4 mr-1 animate-spin" />
                  ) : (
                    <RefreshCw className="h-4 w-4 mr-1" />
                  )}
                  {isEn ? 'Load Plans' : '加载计划'}
                </Button>
                <span className="text-xs text-muted-foreground">
                  {availablePlans.length > 0
                    ? (isEn ? `${availablePlans.length} plans available` : `已加载 ${availablePlans.length} 个计划`)
                    : (isEn ? 'Click to load available subscription plans' : '点击加载可用订阅计划')
                  }
                </span>
              </div>

              {availablePlans.length > 0 && (
                <div className="flex flex-wrap gap-2">
                  {availablePlans.map(plan => (
                    <button
                      key={plan.qSubscriptionType}
                      onClick={() => setSelectedPlanType(plan.qSubscriptionType)}
                      className={cn(
                        'px-3 py-1.5 rounded-md border text-xs font-medium transition-colors',
                        selectedPlanType === plan.qSubscriptionType
                          ? 'border-primary bg-primary/10 text-primary'
                          : 'border-border hover:border-primary/50'
                      )}
                    >
                      <div>{plan.description.title || plan.name}</div>
                      <div className="text-[10px] opacity-70">
                        ${plan.pricing.amount / 100}/{plan.description.billingInterval}
                      </div>
                    </button>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          {/* 操作栏 */}
          <Card>
            <CardContent className="py-3 flex items-center gap-2 flex-wrap">
              <Button
                size="sm"
                onClick={handleBatchFetch}
                disabled={isFetching || upgradeableCount === 0 || !selectedPlanType}
              >
                {isFetching ? (
                  <Loader2 className="h-4 w-4 mr-1 animate-spin" />
                ) : (
                  <CreditCard className="h-4 w-4 mr-1" />
                )}
                {isEn
                  ? `Fetch Links (${upgradeableCount})`
                  : `获取链接 (${upgradeableCount})`
                }
              </Button>

              <Button
                variant="ghost"
                size="sm"
                onClick={() => { setLinks([]); setSelectedLinkIds(new Set()) }}
                disabled={isFetching || links.length === 0}
                title={isEn ? 'Clear results' : '清空结果'}
              >
                <Trash2 className="h-4 w-4 mr-1" />
                {isEn ? 'Clear' : '清空'}
              </Button>

              {/* 批量导入外部链接 */}
              <Button
                variant="outline"
                size="sm"
                onClick={() => setShowImportDialog(true)}
                disabled={isFetching}
                title={isEn ? 'Import links from text (one per line)' : '从文本批量导入链接（每行一个）'}
              >
                <Upload className="h-4 w-4 mr-1" />
                {isEn ? 'Import' : '导入链接'}
              </Button>

              {/* 检测链接有效性 */}
              <Button
                variant="outline"
                size="sm"
                onClick={handleValidateLinks}
                disabled={isFetching || isValidatingLinks || links.filter(l => l.status === 'success').length === 0}
                title={isEn ? 'Detect expired links (>15min old)' : '检测过期链接（生成超过 15 分钟）'}
              >
                {isValidatingLinks ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <RefreshCw className="h-4 w-4 mr-1" />}
                {isEn ? 'Validate' : '检测有效性'}
              </Button>

              {/* 删除失败/过期 — 始终显示 */}
              <Button
                variant="outline"
                size="sm"
                onClick={handleDeleteFailed}
                disabled={isFetching || links.filter(l => l.status === 'error' || l.status === 'expired').length === 0}
                title={isEn ? 'Remove failed and expired links' : '移除失败和过期的链接'}
              >
                <Trash2 className="h-4 w-4 mr-1" />
                {isEn ? 'Remove Failed' : '清失败'}
                {' '}({links.filter(l => l.status === 'error' || l.status === 'expired').length})
              </Button>

              {/* 多选辅助操作（仅有结果时显示） */}
              {links.length > 0 && (
                <>
                  <div className="w-px h-6 bg-border" />
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={invertSelection}
                    disabled={isFetching}
                    title={isEn ? 'Invert selection' : '反选'}
                  >
                    <Minus className="h-4 w-4 mr-1" />
                    {isEn ? 'Invert' : '反选'}
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={clearSelection}
                    disabled={isFetching || selectedLinkIds.size === 0}
                    title={isEn ? 'Clear selection' : '取消多选'}
                  >
                    <Square className="h-4 w-4 mr-1" />
                    {isEn ? 'Deselect' : '取消多选'}
                  </Button>

                  {/* 快选：从顶部按数量分批选择可用链接 */}
                  <div className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded-md border border-dashed">
                    <ListChecks className="h-3.5 w-3.5 text-muted-foreground" />
                    <span className="text-[10px] text-muted-foreground">{isEn ? 'Quick pick' : '快选'}</span>
                    <input
                      type="number"
                      min={1}
                      value={quickPickCount}
                      onChange={(e) => {
                        const v = parseInt(e.target.value, 10)
                        if (v > 0) setQuickPickCount(v)
                      }}
                      disabled={isFetching}
                      className="h-6 w-12 px-1 rounded border border-border bg-background text-[11px] text-center"
                      title={isEn ? 'Number of links to pick' : '快选数量'}
                    />
                    <button
                      onClick={quickPickTop}
                      disabled={isFetching || successCount === 0}
                      className="text-[10px] px-1.5 py-0.5 rounded hover:bg-primary/15 text-primary disabled:opacity-40"
                      title={isEn ? `Select top ${quickPickCount} available links` : `从顶部选中前 ${quickPickCount} 个可用链接`}
                    >
                      {isEn ? 'Top' : '前N个'}
                    </button>
                    <button
                      onClick={quickPickNext}
                      disabled={isFetching || successCount === 0}
                      className="text-[10px] px-1.5 py-0.5 rounded hover:bg-primary/15 text-primary disabled:opacity-40"
                      title={isEn ? 'Select next batch (continue from last pick)' : '选中下一批（从上次位置继续）'}
                    >
                      {isEn ? 'Next' : '下一批'}
                    </button>
                  </div>

                  {/* 按状态快速选择 */}
                  <div className="relative inline-flex items-center gap-1 px-1.5 py-0.5 rounded-md border border-dashed">
                    <span className="text-[10px] text-muted-foreground">{isEn ? 'Pick:' : '选择:'}</span>
                    <button
                      className="text-[10px] px-1.5 py-0.5 rounded hover:bg-green-500/15 text-green-700 dark:text-green-300"
                      onClick={() => selectByStatus('success')}
                      disabled={isFetching}
                      title={isEn ? 'Add all "Success" to selection' : '把"成功"项加入选择'}
                    >
                      ✓ {isEn ? 'Success' : '成功'} ({links.filter(l => l.status === 'success').length})
                    </button>
                    <button
                      className="text-[10px] px-1.5 py-0.5 rounded hover:bg-amber-500/15 text-amber-700 dark:text-amber-300"
                      onClick={() => selectByStatus('expired')}
                      disabled={isFetching}
                      title={isEn ? 'Add all "Expired" to selection' : '把"过期"项加入选择'}
                    >
                      ⚠ {isEn ? 'Expired' : '过期'} ({links.filter(l => l.status === 'expired').length})
                    </button>
                    <button
                      className="text-[10px] px-1.5 py-0.5 rounded hover:bg-red-500/15 text-red-700 dark:text-red-300"
                      onClick={() => selectByStatus('error')}
                      disabled={isFetching}
                      title={isEn ? 'Add all "Error" to selection' : '把"失败"项加入选择'}
                    >
                      ✗ {isEn ? 'Error' : '失败'} ({links.filter(l => l.status === 'error').length})
                    </button>
                  </div>

                  {/* 批量删除选中 */}
                  {selectedLinkIds.size > 0 && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={handleBatchDelete}
                      className="text-destructive hover:text-destructive hover:bg-destructive/10"
                      title={isEn ? `Delete ${selectedLinkIds.size} selected links` : `删除选中的 ${selectedLinkIds.size} 个链接`}
                    >
                      <Trash2 className="h-4 w-4 mr-1" />
                      {isEn ? `Delete Selected (${selectedLinkIds.size})` : `删除选中 (${selectedLinkIds.size})`}
                    </Button>
                  )}
                </>
              )}

              {/* 并发数控制 */}
              <div className="flex items-center gap-1 text-xs">
                <span className="text-muted-foreground">{isEn ? 'Concurrency:' : '并发:'}</span>
                <input
                  type="number"
                  min={1}
                  max={100}
                  value={concurrency}
                  onChange={(e) => {
                    const val = parseInt(e.target.value, 10)
                    if (val > 0) setConcurrency(val)
                  }}
                  disabled={isFetching}
                  className="h-7 w-14 px-1.5 rounded border border-border bg-background text-xs text-center"
                />
              </div>

              <div className="w-px h-6 bg-border" />

              {successCount > 0 && (
                <>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleBatchOpen('selected')}
                    disabled={selectedCount === 0}
                    title={isEn ? 'Open selected in incognito' : '无痕打开选中链接'}
                  >
                    <ExternalLink className="h-4 w-4 mr-1" />
                    {isEn ? `Open Selected (${selectedCount})` : `打开选中 (${selectedCount})`}
                  </Button>

                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleBatchOpen('all')}
                    title={isEn ? 'Open all in incognito' : '无痕打开全部链接'}
                  >
                    <ExternalLink className="h-4 w-4 mr-1" />
                    {isEn ? `Open All (${successCount})` : `全部打开 (${successCount})`}
                  </Button>

                  <div className="w-px h-6 bg-border" />

                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleExport('selected')}
                    disabled={selectedCount === 0}
                    title={isEn ? 'Copy selected links' : '复制选中链接'}
                  >
                    <Copy className="h-4 w-4 mr-1" />
                    {isEn ? `Export Selected (${selectedCount})` : `导出选中 (${selectedCount})`}
                  </Button>

                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleExport('all')}
                    title={isEn ? 'Copy all links' : '复制全部链接'}
                  >
                    <Download className="h-4 w-4 mr-1" />
                    {isEn ? `Export All (${successCount})` : `全部导出 (${successCount})`}
                  </Button>
                </>
              )}

              {/* 统计 */}
              {links.length > 0 && (
                <div className="ml-auto flex items-center gap-3 text-xs text-muted-foreground">
                  {successCount > 0 && (
                    <span className="flex items-center gap-1 text-green-600">
                      <CheckCircle className="h-3 w-3" /> {successCount}
                    </span>
                  )}
                  {errorCount > 0 && (
                    <span className="flex items-center gap-1 text-red-500">
                      <XCircle className="h-3 w-3" /> {errorCount}
                    </span>
                  )}
                  {isFetching && (
                    <span className="flex items-center gap-1">
                      <Loader2 className="h-3 w-3 animate-spin" />
                      {links.filter(l => l.status === 'pending' || l.status === 'loading').length}
                    </span>
                  )}
                </div>
              )}
            </CardContent>
          </Card>

          {/* 链接列表 */}
          {links.length > 0 && (
            <Card>
              <CardContent className="py-2">
                {/* 表头 */}
                <div className="flex items-center gap-3 py-2 px-2 border-b text-xs font-medium text-muted-foreground">
                  <button
                    onClick={toggleSelectAll}
                    className="flex-shrink-0"
                    disabled={links.length === 0}
                    title={
                      selectedLinkIds.size === links.length && links.length > 0
                        ? (isEn ? 'Deselect all' : '取消全选')
                        : (isEn ? 'Select all' : '全选')
                    }
                  >
                    {selectedLinkIds.size === links.length && links.length > 0 ? (
                      <CheckSquare className="h-4 w-4 text-primary" />
                    ) : selectedLinkIds.size > 0 ? (
                      <Minus className="h-4 w-4 text-primary" />
                    ) : (
                      <Square className="h-4 w-4" />
                    )}
                  </button>
                  <span className="w-8 text-center">#</span>
                  <span className="flex-1">{isEn ? 'Email' : '邮箱'}</span>
                  <span className="w-20 text-center">{isEn ? 'Status' : '状态'}</span>
                  <span className="w-24 text-center">{isEn ? 'Actions' : '操作'}</span>
                </div>

                {/* 列表 */}
                <div className="max-h-[60vh] overflow-y-auto">
                  {links.map((link, idx) => (
                    <div
                      key={link.accountId}
                      className={cn(
                        "flex items-center gap-3 py-2 px-2 border-b last:border-b-0 hover:bg-muted/50 transition-colors",
                        selectedLinkIds.has(link.accountId) && 'bg-primary/5'
                      )}
                    >
                      {/* 选择框 — 任何状态都可选（便于批量删除/重试失败项） */}
                      <button
                        onClick={() => toggleLinkSelection(link.accountId)}
                        className="flex-shrink-0"
                      >
                        {selectedLinkIds.has(link.accountId) ? (
                          <CheckSquare className="h-4 w-4 text-primary" />
                        ) : (
                          <Square className="h-4 w-4" />
                        )}
                      </button>

                      {/* 序号 */}
                      <span className="w-8 text-center text-xs text-muted-foreground">{idx + 1}</span>

                      {/* 邮箱 */}
                      <span className="flex-1 text-sm truncate" title={link.email}>
                        {link.email}
                      </span>

                      {/* 状态 */}
                      <span className="w-20 flex justify-center">
                        {link.status === 'pending' && (
                          <span className="text-xs text-muted-foreground">{isEn ? 'Pending' : '等待中'}</span>
                        )}
                        {link.status === 'loading' && (
                          <Loader2 className="h-4 w-4 animate-spin text-blue-500" />
                        )}
                        {link.status === 'success' && (
                          <span className="inline-flex items-center gap-1">
                            <CheckCircle className="h-4 w-4 text-green-500" />
                            {link.generatedAt && (
                              <span className="text-[9px] text-muted-foreground tabular-nums" title={isEn ? 'Minutes since generated' : '生成至今分钟数'}>
                                {Math.round((Date.now() - link.generatedAt) / 60000)}m
                              </span>
                            )}
                          </span>
                        )}
                        {link.status === 'expired' && (
                          <span className="inline-flex items-center gap-1 text-amber-600" title={isEn ? 'May have expired' : '可能已过期'}>
                            <AlertTriangle className="h-4 w-4" />
                            <span className="text-[9px]">{isEn ? 'Expired' : '过期'}</span>
                          </span>
                        )}
                        {link.status === 'error' && (
                          <span className="text-xs text-red-500 truncate" title={link.error}>
                            <XCircle className="h-4 w-4 inline" />
                          </span>
                        )}
                      </span>

                      {/* 操作 */}
                      <span className="w-24 flex justify-center gap-1">
                        {(link.status === 'success' || link.status === 'expired') && link.url && (
                          <>
                            <button
                              onClick={() => handleOpenLink(link.url!)}
                              className="p-1 rounded hover:bg-muted"
                              title={isEn ? 'Open in incognito' : '无痕打开'}
                            >
                              <ExternalLink className="h-3.5 w-3.5" />
                            </button>
                            <button
                              onClick={() => handleCopyLink(link.url!)}
                              className="p-1 rounded hover:bg-muted"
                              title={isEn ? 'Copy link' : '复制链接'}
                            >
                              <Copy className="h-3.5 w-3.5" />
                            </button>
                          </>
                        )}
                        {(link.status === 'expired' || link.status === 'error') && (
                          <button
                            onClick={() => void handleRegenerateLink(link.accountId)}
                            className="p-1 rounded hover:bg-primary/10 text-primary"
                            title={isEn ? 'Regenerate' : '重新生成'}
                          >
                            <RefreshCw className="h-3.5 w-3.5" />
                          </button>
                        )}
                        {link.status === 'error' && (
                          <span className="text-[10px] text-red-500 truncate max-w-[80px]" title={link.error}>
                            {link.error}
                          </span>
                        )}
                      </span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* 空状态 */}
          {links.length === 0 && (
            <Card>
              <CardContent className="py-12 text-center text-muted-foreground">
                <CreditCard className="h-12 w-12 mx-auto mb-3 opacity-30" />
                <p className="text-sm">
                  {upgradeableCount > 0
                    ? (isEn
                        ? `${upgradeableCount} FREE accounts available for upgrade. Click "Fetch Links" to start.`
                        : `有 ${upgradeableCount} 个 FREE 账户可升级。点击"获取链接"开始。`)
                    : (isEn
                        ? 'No FREE tier accounts found. Select accounts in the Accounts page first.'
                        : '未找到 FREE 账户。请先在账户管理页面选择账户。')
                  }
                </p>
              </CardContent>
            </Card>
          )}

          {/* 批量导入链接对话框 */}
          <ImportLinksDialog
            open={showImportDialog}
            onClose={() => setShowImportDialog(false)}
            onImport={handleImportLinks}
            isEn={isEn}
          />
        </>
      )}
    </div>
  )
}

// ============ 批量导入链接对话框 ============

interface ImportLinksDialogProps {
  open: boolean
  onClose: () => void
  onImport: (text: string) => number
  isEn: boolean
}

function ImportLinksDialog({ open, onClose, onImport, isEn }: ImportLinksDialogProps): React.ReactNode {
  const [text, setText] = useState('')
  if (!open) return null

  const detectedCount = parseImportedLinks(text).length
  const handleConfirm = (): void => {
    const n = onImport(text)
    setText('')
    onClose()
    setTimeout(() => alert(isEn ? `Imported ${n} link(s)` : `成功导入 ${n} 个链接`), 0)
  }

  return createPortal(
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/50" onClick={onClose} />
      <div className="relative bg-background rounded-xl shadow-2xl w-full max-w-2xl max-h-[85vh] flex flex-col animate-in fade-in zoom-in-95 duration-200">
        {/* 标题栏 */}
        <div className="flex items-center justify-between px-6 py-4 border-b">
          <div className="flex items-center gap-2">
            <Upload className="h-5 w-5 text-primary" />
            <h2 className="text-lg font-semibold">{isEn ? 'Import Links' : '批量导入链接'}</h2>
          </div>
          <Button variant="ghost" size="sm" className="h-8 w-8 p-0 rounded-lg hover:bg-red-500 hover:text-white transition-colors" onClick={onClose}>
            <X className="h-4 w-4" />
          </Button>
        </div>

        {/* 内容 */}
        <div className="px-6 py-4 space-y-3 overflow-y-auto">
          <p className="text-xs text-muted-foreground">
            {isEn
              ? 'Paste links, one per line. Supports plain URLs or "email<sep>url" (sep = space / comma / tab / | / ----). URLs are auto-extracted; duplicates are skipped.'
              : '每行一个链接。支持纯 URL，或「邮箱<分隔符>URL」（分隔符可为 空格 / 逗号 / Tab / | / ----）。自动识别 URL，重复链接会跳过。'}
          </p>
          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            rows={12}
            autoFocus
            spellCheck={false}
            placeholder={'https://aws.amazon.com/...\nuser@mail.com  https://aws.amazon.com/...'}
            className="w-full rounded-lg border border-foreground/15 bg-[var(--glass-bg)] backdrop-blur-md px-3 py-2 text-sm font-mono resize-y focus-visible:outline-none focus-visible:border-primary/50 focus-visible:ring-2 focus-visible:ring-primary/30"
          />
          <p className="text-xs text-muted-foreground">
            {isEn ? `Detected ${detectedCount} valid link(s)` : `已识别 ${detectedCount} 个有效链接`}
          </p>
        </div>

        {/* 底部按钮 */}
        <div className="flex justify-end gap-3 px-6 py-4 border-t bg-muted/30">
          <Button variant="outline" onClick={onClose}>{isEn ? 'Cancel' : '取消'}</Button>
          <Button disabled={detectedCount === 0} onClick={handleConfirm}>
            <Upload className="h-4 w-4 mr-2" />
            {isEn ? `Import (${detectedCount})` : `导入 (${detectedCount})`}
          </Button>
        </div>
      </div>
    </div>,
    document.body
  )
}

// ============ 订阅管理 Tab：批量取消 + 批量关超额 ============

type AccountType = ReturnType<typeof useAccountsStore.getState>['accounts'] extends Map<string, infer T> ? T : never

interface ManageSubscriptionsTabProps {
  getAllSubscribed: () => Array<AccountType | undefined>
  updateAccount: ReturnType<typeof useAccountsStore.getState>['updateAccount']
  concurrency: number
  isEn: boolean
}

function ManageSubscriptionsTab({ getAllSubscribed, updateAccount, concurrency, isEn }: ManageSubscriptionsTabProps): React.ReactNode {
  const subscribed = getAllSubscribed()
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [isBatchOpening, setIsBatchOpening] = useState(false)
  const [isBatchDisablingOverage, setIsBatchDisablingOverage] = useState(false)

  const toggleSelect = (id: string): void => {
    setSelectedIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }
  const toggleSelectAll = (): void => {
    if (selectedIds.size === subscribed.length) setSelectedIds(new Set())
    else setSelectedIds(new Set(subscribed.map((a) => a!.id)))
  }

  /** 批量打开订阅门户（用于取消订阅） */
  const handleBatchOpenPortal = async (mode: 'selected' | 'all'): Promise<void> => {
    const targets = mode === 'selected'
      ? subscribed.filter((a) => a && selectedIds.has(a.id))
      : subscribed
    if (targets.length === 0) return
    if (!confirm(isEn
      ? `Open ${targets.length} subscription portal pages? (in browser incognito mode)`
      : `打开 ${targets.length} 个订阅门户页面？（浏览器无痕模式）`
    )) return

    setIsBatchOpening(true)
    try {
      // 并发池
      let cursor = 0
      const worker = async (): Promise<void> => {
        while (cursor < targets.length) {
          const idx = cursor++
          const acc = targets[idx]
          if (!acc) continue
          try {
            const r = await window.api.accountGetSubscriptionUrl(
              acc.credentials.accessToken,
              undefined,
              acc.credentials?.region,
              acc.profileArn,
              acc.machineId,
              acc.credentials?.provider || acc.idp,
              acc.credentials?.authMethod,
              acc.id
            )
            if (r.success && r.url) {
              await window.api.openSubscriptionWindow(r.url)
              // 每个之间留 500ms，让浏览器有时间响应
              await new Promise((resolve) => setTimeout(resolve, 500))
            }
          } catch (err) {
            console.warn('Open portal failed for', acc.email, err)
          }
        }
      }
      const workers = Array.from({ length: Math.min(concurrency, targets.length) }, () => worker())
      await Promise.all(workers)
    } finally {
      setIsBatchOpening(false)
    }
  }

  /** 批量关闭超额 */
  const handleBatchDisableOverage = async (mode: 'selected' | 'all'): Promise<void> => {
    const targets = (mode === 'selected'
      ? subscribed.filter((a) => a && selectedIds.has(a.id))
      : subscribed
    ).filter((a) => a?.usage?.resourceDetail?.overageEnabled === true)
    if (targets.length === 0) {
      alert(isEn ? 'No accounts with overage enabled' : '没有开启超额的账号')
      return
    }
    if (!confirm(isEn ? `Disable overage on ${targets.length} accounts?` : `关闭 ${targets.length} 个账号的超额？`)) return

    setIsBatchDisablingOverage(true)
    try {
      let cursor = 0
      const worker = async (): Promise<void> => {
        while (cursor < targets.length) {
          const idx = cursor++
          const acc = targets[idx]
          if (!acc) continue
          try {
            const r = await window.api.accountSetOverage(
              acc.credentials.accessToken,
              'DISABLED',
              acc.credentials?.region,
              acc.profileArn,
              acc.machineId,
              acc.credentials?.provider || acc.idp,
              acc.credentials?.authMethod,
              acc.id
            )
            if (r.success) {
              updateAccount(acc.id, {
                usage: {
                  ...acc.usage,
                  resourceDetail: { ...acc.usage?.resourceDetail, overageEnabled: false }
                }
              })
            }
          } catch (err) {
            console.warn('Disable overage failed for', acc.email, err)
          }
        }
      }
      const workers = Array.from({ length: Math.min(concurrency, targets.length) }, () => worker())
      await Promise.all(workers)
    } finally {
      setIsBatchDisablingOverage(false)
    }
  }

  if (subscribed.length === 0) {
    return (
      <Card>
        <CardContent className="py-12 text-center text-muted-foreground">
          <CreditCard className="h-12 w-12 mx-auto mb-3 opacity-30" />
          <p className="text-sm">
            {isEn
              ? 'No subscribed accounts found. Run "Check Accounts" first to refresh status.'
              : '未发现已订阅账号。请先在账户页"批量检查"刷新状态。'
            }
          </p>
        </CardContent>
      </Card>
    )
  }

  const selectedCount = selectedIds.size
  const overageEnabledCount = subscribed.filter((a) => a?.usage?.resourceDetail?.overageEnabled === true).length

  return (
    <>
      {/* 说明 */}
      <Card className="border-blue-200 dark:border-blue-800 bg-blue-50/50 dark:bg-blue-950/10">
        <CardContent className="py-3 space-y-2">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-blue-600" />
            <span className="text-sm font-medium">
              {isEn ? 'Subscription Lifecycle Management' : '订阅生命周期管理'}
            </span>
          </div>
          <p className="text-xs text-muted-foreground">
            {isEn
              ? 'Bulk open subscription portals in browser (cancel/manage there), or bulk disable overage.'
              : '批量打开订阅门户（在浏览器内取消/管理），或批量关闭超额。'
            }
          </p>
        </CardContent>
      </Card>

      {/* 批量操作栏 */}
      <Card>
        <CardContent className="py-3 flex items-center gap-2 flex-wrap">
          <Button
            size="sm"
            onClick={() => handleBatchOpenPortal('selected')}
            disabled={isBatchOpening || selectedCount === 0}
          >
            {isBatchOpening ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <ExternalLink className="h-4 w-4 mr-1" />}
            {isEn ? `Open Portal (Selected: ${selectedCount})` : `打开门户（已选 ${selectedCount}）`}
          </Button>
          <Button
            size="sm"
            variant="outline"
            onClick={() => handleBatchOpenPortal('all')}
            disabled={isBatchOpening}
          >
            <ExternalLink className="h-4 w-4 mr-1" />
            {isEn ? `Open All (${subscribed.length})` : `打开全部 (${subscribed.length})`}
          </Button>

          <div className="w-px h-6 bg-border" />

          <Button
            size="sm"
            variant="outline"
            onClick={() => handleBatchDisableOverage('selected')}
            disabled={isBatchDisablingOverage || selectedCount === 0}
          >
            {isBatchDisablingOverage ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <Ban className="h-4 w-4 mr-1" />}
            {isEn ? `Disable Overage (Selected)` : '关超额（已选）'}
          </Button>
          <Button
            size="sm"
            variant="outline"
            onClick={() => handleBatchDisableOverage('all')}
            disabled={isBatchDisablingOverage || overageEnabledCount === 0}
          >
            <Ban className="h-4 w-4 mr-1" />
            {isEn ? `Disable All Overage (${overageEnabledCount})` : `关全部超额 (${overageEnabledCount})`}
          </Button>

          <span className="ml-auto text-xs text-muted-foreground">
            {selectedCount > 0
              ? (isEn ? `${selectedCount} of ${subscribed.length} selected` : `已选 ${selectedCount} / ${subscribed.length}`)
              : (isEn ? `${subscribed.length} subscribed accounts` : `${subscribed.length} 个已订阅账号`)
            }
          </span>
        </CardContent>
      </Card>

      {/* 账号列表（多选） */}
      <Card>
        <CardContent className="py-0 px-0">
          <div className="flex items-center gap-3 py-2 px-3 border-b text-xs font-medium text-muted-foreground bg-muted/30">
            <button onClick={toggleSelectAll} className="flex-shrink-0">
              {selectedIds.size === subscribed.length && subscribed.length > 0
                ? <CheckSquare className="h-3.5 w-3.5 text-primary" />
                : selectedIds.size > 0
                  ? <Minus className="h-3.5 w-3.5 text-primary" />
                  : <Square className="h-3.5 w-3.5" />
              }
            </button>
            <span className="w-8 text-center">#</span>
            <span className="flex-1">{isEn ? 'Email' : '邮箱'}</span>
            <span className="w-28 text-center">{isEn ? 'Plan' : '订阅类型'}</span>
            <span className="w-20 text-center">{isEn ? 'Days Left' : '剩余天数'}</span>
            <span className="w-24 text-center">{isEn ? 'Overage' : '超额状态'}</span>
            <span className="w-32 text-center">{isEn ? 'Actions' : '操作'}</span>
          </div>

          <SubscribedAccountsVirtualList
            subscribed={subscribed}
            selectedIds={selectedIds}
            toggleSelect={toggleSelect}
            updateAccount={updateAccount}
            isEn={isEn}
          />

          {/* 占位防止下面 dead code 被误删（实际渲染走 SubscribedAccountsVirtualList） */}
          {false && (
            <div className="max-h-[60vh] overflow-y-auto">
              {subscribed.map((acc, idx) => {
                if (!acc) return null
                const planName = acc.subscription?.title || acc.subscription?.type || '-'
                const daysLeft = acc.subscription?.daysRemaining
                const overageEnabled = acc.usage?.resourceDetail?.overageEnabled === true
                const overageCapable = acc.subscription?.overageCapability === 'OVERAGE_CAPABLE'
                const selected = selectedIds.has(acc.id)

                return (
                  <div
                    key={acc.id}
                    className={cn(
                      'flex items-center gap-3 py-2 px-3 border-b last:border-b-0 hover:bg-muted/40 text-xs transition-colors',
                      selected && 'bg-primary/5'
                    )}
                  >
                    <button onClick={() => toggleSelect(acc.id)} className="flex-shrink-0">
                    {selected
                      ? <CheckSquare className="h-3.5 w-3.5 text-primary" />
                      : <Square className="h-3.5 w-3.5" />
                    }
                  </button>
                  <span className="w-8 text-center text-muted-foreground">{idx + 1}</span>
                  <span className="flex-1 truncate" title={acc.email}>{acc.email}</span>
                  <span className="w-28 text-center">
                    <span className={cn(
                      'inline-block px-2 py-0.5 rounded text-[10px] font-medium',
                      planName.toUpperCase().includes('PRO+') || planName.toUpperCase().includes('PRO_PLUS')
                        ? 'bg-purple-500/15 text-purple-700 dark:text-purple-300'
                        : planName.toUpperCase().includes('POWER')
                          ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300'
                          : planName.toUpperCase().includes('PRO')
                            ? 'bg-blue-500/15 text-blue-700 dark:text-blue-300'
                            : 'bg-muted text-muted-foreground'
                    )}>
                      {planName}
                    </span>
                  </span>
                  <span className="w-20 text-center text-muted-foreground">
                    {daysLeft != null
                      ? <span className={cn(
                          daysLeft <= 3 ? 'text-red-500' : daysLeft <= 7 ? 'text-amber-500' : ''
                        )}>{isEn ? `${daysLeft}d` : `${daysLeft} 天`}</span>
                      : '-'
                    }
                  </span>
                  <span className="w-24 text-center">
                    {overageEnabled
                      ? <span className="text-green-600 text-[10px]">{isEn ? 'ENABLED' : '已开启'}</span>
                      : overageCapable
                        ? <span className="text-muted-foreground text-[10px]">{isEn ? 'DISABLED' : '未开启'}</span>
                        : <span className="text-muted-foreground text-[10px]">-</span>
                    }
                  </span>
                  <span className="w-32 flex justify-center gap-1">
                    <button
                      onClick={async () => {
                        const r = await window.api.accountGetSubscriptionUrl(
                          acc.credentials.accessToken,
                          undefined,
                          acc.credentials?.region,
                          acc.profileArn,
                          acc.machineId,
                          acc.credentials?.provider || acc.idp,
                          acc.credentials?.authMethod,
                          acc.id
                        )
                        if (r.success && r.url) {
                          await window.api.openSubscriptionWindow(r.url)
                        } else {
                          alert(isEn ? `Failed: ${r.error}` : `失败: ${r.error}`)
                        }
                      }}
                      className="px-2 py-1 rounded text-[10px] bg-primary/10 text-primary hover:bg-primary/20"
                      title={isEn ? 'Open subscription portal' : '打开订阅门户'}
                    >
                      <ExternalLink className="h-3 w-3 inline mr-1" />
                      {isEn ? 'Manage' : '管理'}
                    </button>
                  </span>
                </div>
                )
              })}
            </div>
          )}
        </CardContent>
      </Card>
    </>
  )
}

/**
 * 订阅账号虚拟化列表（处理上千个已订阅账号时避免卡顿）
 */
interface SubscribedListProps {
  subscribed: Array<AccountType | undefined>
  selectedIds: Set<string>
  toggleSelect: (id: string) => void
  updateAccount: ReturnType<typeof useAccountsStore.getState>['updateAccount']
  isEn: boolean
}

function SubscribedAccountsVirtualList({ subscribed, selectedIds, toggleSelect, updateAccount, isEn }: SubscribedListProps): React.ReactNode {
  void updateAccount  // 暂未使用（保留参数对齐 API）
  const parentRef = useRef<HTMLDivElement>(null)
  const ROW_HEIGHT = 44
  const validItems = useMemo(() => subscribed.filter((a): a is AccountType => !!a), [subscribed])

  const virtualizer = useVirtualizer({
    count: validItems.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 10
  })

  // 不到 50 行时直接渲染
  if (validItems.length < 50) {
    return (
      <div ref={parentRef} className="max-h-[60vh] overflow-y-auto">
        {validItems.map((acc, idx) => (
          <SubscribedRow
            key={acc.id}
            acc={acc}
            idx={idx}
            selected={selectedIds.has(acc.id)}
            onToggleSelect={() => toggleSelect(acc.id)}
            isEn={isEn}
          />
        ))}
      </div>
    )
  }

  const items = virtualizer.getVirtualItems()
  return (
    <div ref={parentRef} className="max-h-[60vh] overflow-y-auto" style={{ contain: 'strict' }}>
      <div style={{ height: virtualizer.getTotalSize(), position: 'relative', width: '100%' }}>
        {items.map((virtualRow) => {
          const acc = validItems[virtualRow.index]
          if (!acc) return null
          return (
            <div
              key={virtualRow.key}
              style={{
                position: 'absolute',
                top: 0,
                left: 0,
                width: '100%',
                transform: `translateY(${virtualRow.start}px)`
              }}
            >
              <SubscribedRow
                acc={acc}
                idx={virtualRow.index}
                selected={selectedIds.has(acc.id)}
                onToggleSelect={() => toggleSelect(acc.id)}
                isEn={isEn}
              />
            </div>
          )
        })}
      </div>
    </div>
  )
}

function SubscribedRow({ acc, idx, selected, onToggleSelect, isEn }: {
  acc: AccountType
  idx: number
  selected: boolean
  onToggleSelect: () => void
  isEn: boolean
}): React.ReactNode {
  const planName = acc.subscription?.title || acc.subscription?.type || '-'
  const daysLeft = acc.subscription?.daysRemaining
  const overageEnabled = acc.usage?.resourceDetail?.overageEnabled === true
  const overageCapable = acc.subscription?.overageCapability === 'OVERAGE_CAPABLE'

  return (
    <div
      className={cn(
        'flex items-center gap-3 py-2 px-3 border-b last:border-b-0 hover:bg-muted/40 text-xs transition-colors',
        selected && 'bg-primary/5'
      )}
    >
      <button onClick={onToggleSelect} className="flex-shrink-0">
        {selected
          ? <CheckSquare className="h-3.5 w-3.5 text-primary" />
          : <Square className="h-3.5 w-3.5" />
        }
      </button>
      <span className="w-8 text-center text-muted-foreground">{idx + 1}</span>
      <span className="flex-1 truncate" title={acc.email}>{acc.email}</span>
      <span className="w-28 text-center">
        <span className={cn(
          'inline-block px-2 py-0.5 rounded text-[10px] font-medium',
          planName.toUpperCase().includes('PRO+') || planName.toUpperCase().includes('PRO_PLUS')
            ? 'bg-purple-500/15 text-purple-700 dark:text-purple-300'
            : planName.toUpperCase().includes('POWER')
              ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300'
              : planName.toUpperCase().includes('PRO')
                ? 'bg-blue-500/15 text-blue-700 dark:text-blue-300'
                : 'bg-muted text-muted-foreground'
        )}>{planName}</span>
      </span>
      <span className="w-20 text-center text-muted-foreground">
        {daysLeft != null
          ? <span className={cn(daysLeft <= 3 ? 'text-red-500' : daysLeft <= 7 ? 'text-amber-500' : '')}>{isEn ? `${daysLeft}d` : `${daysLeft} 天`}</span>
          : '-'
        }
      </span>
      <span className="w-24 text-center">
        {overageEnabled
          ? <span className="text-green-600 text-[10px]">{isEn ? 'ENABLED' : '已开启'}</span>
          : overageCapable
            ? <span className="text-muted-foreground text-[10px]">{isEn ? 'DISABLED' : '未开启'}</span>
            : <span className="text-muted-foreground text-[10px]">-</span>
        }
      </span>
      <span className="w-32 flex justify-center gap-1">
        <button
          onClick={async () => {
            const r = await window.api.accountGetSubscriptionUrl(
              acc.credentials.accessToken,
              undefined,
              acc.credentials?.region,
              acc.profileArn,
              acc.machineId,
              acc.credentials?.provider || acc.idp,
              acc.credentials?.authMethod,
              acc.id
            )
            if (r.success && r.url) {
              await window.api.openSubscriptionWindow(r.url)
            } else {
              alert(isEn ? `Failed: ${r.error}` : `失败: ${r.error}`)
            }
          }}
          className="px-2 py-1 rounded text-[10px] bg-primary/10 text-primary hover:bg-primary/20"
          title={isEn ? 'Open subscription portal' : '打开订阅门户'}
        >
          <ExternalLink className="h-3 w-3 inline mr-1" />
          {isEn ? 'Manage' : '管理'}
        </button>
      </span>
    </div>
  )
}
