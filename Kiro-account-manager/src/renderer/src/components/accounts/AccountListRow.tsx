import { memo, useState, useMemo, useCallback } from 'react'
import { useAccountsStore } from '@/store/accounts'
import { useTranslation } from '@/hooks/useTranslation'
import { Badge, Button } from '../ui'
import type { Account, AccountTag, AccountGroup } from '@/types/account'
import {
  Check,
  RefreshCw,
  Trash2,
  Edit,
  Info,
  AlertCircle,
  Power,
  LogOut,
  RotateCcw,
  ExternalLink,
  Loader2,
  Clock,
  KeyRound,
  FolderOpen,
  Copy
} from 'lucide-react'
import { cn } from '@/lib/utils'
import {
  toRgba,
  generateRowGlowStyle,
  unauthorizedRowStyle,
  getSubscriptionColor,
  getStatusBadgeClass,
  StatusLabelsZh,
  StatusLabelsEn,
  formatTokenExpiry,
  isBannedError
} from './_helpers'

interface AccountListRowProps {
  account: Account
  tags: Map<string, AccountTag>
  groups: Map<string, AccountGroup>
  isSelected: boolean
  onEdit: () => void
  onShowDetail: () => void
}

// 紧凑列表行 — 视觉对齐 AccountCard
// 高度 ~72px，圆角 + 流光边框 + 标签光晕 + 封禁红色背景
function AccountListRowComponent({
  account,
  tags,
  groups,
  isSelected,
  onEdit,
  onShowDetail
}: AccountListRowProps): React.ReactNode {
  const {
    setActiveAccount,
    removeAccount,
    checkAccountStatus,
    refreshAccountToken,
    toggleSelection,
    maskEmail,
    maskNickname,
    usagePrecision,
    updateAccountStatus,
    accountProxyBindings,
    proxyPool,
    unbindAccountFromProxy
  } = useAccountsStore()

  // 该账号绑定的代理（如有）
  const boundProxy = useMemo(() => {
    const proxyId = accountProxyBindings[account.id]
    if (!proxyId) return null
    return proxyPool.get(proxyId) || null
  }, [accountProxyBindings, account.id, proxyPool])

  const { t } = useTranslation()
  const isEn = t('common.unknown') === 'Unknown'

  const [isRefreshing, setIsRefreshing] = useState(false)
  const [isClearingSuspended, setIsClearingSuspended] = useState(false)
  const [emailCopied, setEmailCopied] = useState(false)

  // 封禁判定
  const isUnauthorized = isBannedError(account.lastError)

  // 标签
  const accountTags = useMemo(
    () => (account.tags || []).map(id => tags.get(id)).filter((t): t is AccountTag => !!t),
    [account.tags, tags]
  )
  const tagColors = useMemo(() => accountTags.map(t => t.color), [accountTags])

  // 分组
  const accountGroup = useMemo(() => {
    if (!account.groupId) return null
    return groups.get(account.groupId) || null
  }, [account.groupId, groups])

  // 显示名（昵称优先 + 隐私模式 mask）
  const displayName = useMemo(() => {
    if (account.nickname) return maskNickname(account.nickname)
    return maskEmail(account.email)
  }, [account.nickname, account.email, maskEmail, maskNickname])

  const maskedEmail = useMemo(() => maskEmail(account.email), [account.email, maskEmail])

  // Credits
  const formatUsage = (value: number): string => {
    if (usagePrecision) {
      return value.toLocaleString(undefined, { minimumFractionDigits: 0, maximumFractionDigits: 2 })
    }
    return Math.floor(value).toLocaleString()
  }
  const percentUsed = account.usage.percentUsed * 100
  const isHighUsage = percentUsed > 80
  const isCritical = percentUsed > 100

  // 到期
  const daysRemaining = account.subscription.daysRemaining
  const isExpiringSoon = daysRemaining !== undefined && daysRemaining <= 7
  const isTokenExpiringSoon =
    account.credentials.expiresAt !== undefined &&
    account.credentials.expiresAt - Date.now() < 5 * 60 * 1000

  // === 行外层样式合成 ===
  // 优先级：active 流光 > 封禁红色 > 标签光晕
  const rowStyle = useMemo(() => {
    if (account.isActive) return {} // active-glow-border class 处理
    if (isUnauthorized) return unauthorizedRowStyle
    if (tagColors.length > 0) return generateRowGlowStyle(tagColors)
    return {}
  }, [account.isActive, isUnauthorized, tagColors])

  // === Handlers ===
  const handleSwitch = useCallback(async (e: React.MouseEvent) => {
    e.stopPropagation()
    const { credentials } = account
    const { switchTarget } = useAccountsStore.getState()

    if (!credentials.refreshToken) {
      alert(isEn ? 'Incomplete credentials, cannot switch' : '账号凭证不完整，无法切换')
      return
    }
    if (credentials.authMethod !== 'social' && (!credentials.clientId || !credentials.clientSecret)) {
      alert(isEn ? 'Incomplete credentials, cannot switch' : '账号凭证不完整，无法切换')
      return
    }

    const cliPayload = {
      accessToken: credentials.accessToken,
      refreshToken: credentials.refreshToken,
      clientId: credentials.clientId,
      clientSecret: credentials.clientSecret,
      region: credentials.region || 'us-east-1',
      profileArn: account.profileArn,
      provider: credentials.provider
    }
    const idePayload = {
      accessToken: credentials.accessToken,
      refreshToken: credentials.refreshToken,
      clientId: credentials.clientId || '',
      clientSecret: credentials.clientSecret || '',
      region: credentials.region || 'us-east-1',
      startUrl: credentials.startUrl,
      authMethod: credentials.authMethod,
      provider: credentials.provider,
      profileArn: account.profileArn,
      accountId: account.id
    }

    let success = true
    let errorMsg = ''
    const target = switchTarget || 'ide'
    if (target === 'ide' || target === 'both') {
      const result = await window.api.switchAccount(idePayload)
      if (!result.success) {
        success = false
        errorMsg = result.error || ''
      } else if (result.refreshedCredentials) {
        // 同步 main 进程 refresh 后的最新 credentials 到 store，避免反代 store 留下已作废的 refreshToken
        const rc = result.refreshedCredentials
        useAccountsStore.setState((state) => {
          const accounts = new Map(state.accounts)
          const acc = accounts.get(account.id)
          if (acc) {
            accounts.set(account.id, {
              ...acc,
              credentials: {
                ...acc.credentials,
                accessToken: rc.accessToken,
                refreshToken: rc.refreshToken,
                expiresAt: Date.now() + rc.expiresIn * 1000
              }
            })
          }
          return { accounts }
        })
        useAccountsStore.getState().saveToStorage()
      }
    }
    if (target === 'cli' || target === 'both') {
      const result = await window.api.switchAccountCli(cliPayload)
      if (!result.success) {
        success = false
        const cliErr = result.error || 'CLI switch failed'
        errorMsg = errorMsg ? `${errorMsg}; CLI: ${cliErr}` : cliErr
      } else if (result.refreshedCredentials) {
        const rc = result.refreshedCredentials
        useAccountsStore.setState((state) => {
          const accounts = new Map(state.accounts)
          const acc = accounts.get(account.id)
          if (acc) {
            accounts.set(account.id, {
              ...acc,
              credentials: {
                ...acc.credentials,
                accessToken: rc.accessToken,
                refreshToken: rc.refreshToken,
                expiresAt: Date.now() + rc.expiresIn * 1000
              }
            })
          }
          return { accounts }
        })
        useAccountsStore.getState().saveToStorage()
      }
    }

    if (success) {
      setActiveAccount(account.id)
    } else {
      alert(isEn ? `Switch failed: ${errorMsg}` : `切换失败：${errorMsg}`)
    }
  }, [account, isEn, setActiveAccount])

  const handleRefresh = useCallback(async (e: React.MouseEvent) => {
    e.stopPropagation()
    if (isRefreshing) return
    setIsRefreshing(true)
    try {
      await refreshAccountToken(account.id)
      await checkAccountStatus(account.id)
    } finally {
      setIsRefreshing(false)
    }
  }, [account.id, isRefreshing, refreshAccountToken, checkAccountStatus])

  const handleDelete = useCallback((e: React.MouseEvent) => {
    e.stopPropagation()
    if (!confirm(isEn ? `Delete account "${account.email}"?` : `确定删除账号 "${account.email}"？`)) return
    removeAccount(account.id)
  }, [account.id, account.email, isEn, removeAccount])

  const handleLogout = useCallback(async (e: React.MouseEvent) => {
    e.stopPropagation()
    if (!confirm(isEn ? 'Clear local SSO cache and logout from Kiro?' : '清除本地 SSO 缓存并退出 Kiro 登录？')) return
    const result = await window.api.logoutAccount()
    if (result.success) {
      setActiveAccount(null)
    } else {
      alert(isEn ? `Logout failed: ${result.error}` : `退出失败：${result.error}`)
    }
  }, [isEn, setActiveAccount])

  const handleClearSuspended = useCallback(async (e: React.MouseEvent) => {
    e.stopPropagation()
    if (isClearingSuspended) return
    setIsClearingSuspended(true)
    try {
      const result = await window.api.proxyClearAccountSuspended(account.id)
      if (result.success) {
        updateAccountStatus(account.id, 'active', undefined)
      }
    } finally {
      setIsClearingSuspended(false)
    }
  }, [account.id, isClearingSuspended, updateAccountStatus])

  const handleCopyEmail = useCallback((e: React.MouseEvent) => {
    e.stopPropagation()
    const text = account.email || account.userId || ''
    if (text) {
      navigator.clipboard.writeText(text)
      setEmailCopied(true)
      setTimeout(() => setEmailCopied(false), 1500)
    }
  }, [account.email, account.userId])

  // ============ 渲染 ============

  return (
    <div
      className={cn(
        'group relative flex items-center gap-3 pl-3 pr-3 py-2.5 rounded-xl border bg-solid-card transition-all duration-300 cursor-pointer overflow-hidden',
        'hover:shadow-md',
        account.isActive && 'active-glow-border border-transparent',
        !account.isActive && !isUnauthorized && tagColors.length === 0 && !isSelected && 'border-border'
      )}
      style={rowStyle}
      onClick={() => toggleSelection(account.id)}
    >
      {/* 选中态独立覆盖层 — 避免被多标签 rowStyle 的 backgroundImage 覆盖 */}
      {isSelected && !account.isActive && !isUnauthorized && (
        <div className="absolute inset-0 pointer-events-none rounded-[inherit] ring-2 ring-inset ring-primary/60 bg-primary/[0.08] z-10" />
      )}

      {/* Checkbox */}
      <div
        className={cn(
          'flex-shrink-0 w-4 h-4 rounded border-2 flex items-center justify-center transition-colors cursor-pointer',
          isSelected
            ? 'bg-primary border-primary text-primary-foreground'
            : 'border-muted-foreground/30 hover:border-primary'
        )}
        onClick={(e) => { e.stopPropagation(); toggleSelection(account.id) }}
      >
        {isSelected && <Check className="h-3 w-3" />}
      </div>

      {/* === 邮箱列（固定 280px） === */}
      <div className="w-[280px] flex-shrink-0 flex flex-col gap-1 min-w-0">
        {/* 上行：邮箱/昵称 + 副邮箱 */}
        <div className="flex items-center gap-2 min-w-0">
          <h3
            className={cn(
              'font-semibold text-sm truncate cursor-pointer transition-colors min-w-0',
              emailCopied ? 'text-success' : 'text-foreground/90 hover:text-primary'
            )}
            title={`${displayName} (${isEn ? 'Click to copy' : '点击复制'})`}
            onClick={handleCopyEmail}
          >
            {emailCopied ? (isEn ? 'Copied!' : '已复制!') : displayName}
          </h3>
          {account.nickname && (
            <span className="text-xs text-muted-foreground truncate min-w-0" title={account.email}>
              {maskedEmail}
            </span>
          )}
        </div>

        {/* 下行：分组 + 标签 + 错误 + 复制 */}
        <div className="flex items-center gap-1.5 min-w-0 text-[10px] overflow-hidden">
          {accountGroup && (
            <span
              className="px-1.5 py-0.5 rounded flex items-center gap-1 flex-shrink-0"
              style={{ color: accountGroup.color, backgroundColor: accountGroup.color + '15' }}
            >
              <FolderOpen className="w-3 h-3" />
              {accountGroup.name}
            </span>
          )}
          {accountTags.slice(0, 4).map(tag => {
            const tagColor = toRgba(tag.color)
            return (
              <span
                key={tag.id}
                className="px-1.5 py-0.5 rounded-md font-medium flex-shrink-0 border"
                style={{
                  backgroundColor: tagColor.replace(/[\d.]+\)$/, '0.12)'),
                  color: tagColor,
                  borderColor: tagColor.replace(/[\d.]+\)$/, '0.30)')
                }}
              >
                {tag.name}
              </span>
            )
          })}
          {accountTags.length > 4 && (
            <span className="px-1.5 py-0.5 text-muted-foreground bg-muted rounded-sm flex-shrink-0">
              +{accountTags.length - 4}
            </span>
          )}

          {/* 错误信息（非封禁，因为封禁已用红色徽章显示） */}
          {account.lastError && !isUnauthorized && (
            <span className="text-destructive truncate flex-1 min-w-0 italic" title={account.lastError}>
              {account.lastError}
            </span>
          )}

          {/* 复制邮箱小图标 */}
          {!account.nickname && (
            <button
              type="button"
              onClick={handleCopyEmail}
              className="ml-auto text-muted-foreground/60 hover:text-primary transition-colors flex-shrink-0"
              title={isEn ? 'Copy email' : '复制邮箱'}
            >
              <Copy className="h-3 w-3" />
            </button>
          )}
        </div>
      </div>

      {/* === 徽章固定列（紧贴邮箱列，每个徽章等宽确保跨行对齐） === */}
      <div className="flex-shrink-0 flex items-center gap-1.5">
        {/* 状态徽章（min-w 保持等宽） */}
        <div
          className={cn(
            'text-[10px] font-medium h-5 px-2 rounded-full flex items-center justify-center gap-1 min-w-[52px]',
            getStatusBadgeClass(account.status, isUnauthorized)
          )}
        >
          {account.status === 'refreshing' && <Loader2 className="h-3 w-3 animate-spin" />}
          {isUnauthorized && <AlertCircle className="h-3 w-3" />}
          {isUnauthorized ? (
            <span
              className="cursor-pointer hover:underline"
              onClick={(e) => { e.stopPropagation(); onShowDetail() }}
            >
              {isEn ? 'Banned' : '已封禁'}
            </span>
          ) : (
            (isEn ? StatusLabelsEn : StatusLabelsZh)[account.status] || account.status
          )}
        </div>

        {/* 订阅徽章（min-w 保持等宽，PRO+/FREE 视觉对齐） */}
        <Badge
          className={cn(
            'text-white text-[10px] h-5 px-2 border-0 min-w-[90px] flex items-center justify-center',
            getSubscriptionColor(account.subscription.type, account.subscription.title)
          )}
        >
          {account.subscription.title || account.subscription.type}
        </Badge>

        {/* IDP（固定宽度，所有账号视觉对齐） */}
        <Badge
          variant="outline"
          className="text-[10px] h-5 px-1.5 text-muted-foreground font-normal border-muted-foreground/30 bg-muted/30 min-w-[72px] flex items-center justify-center"
        >
          {account.idp}
        </Badge>

        {/* 代理绑定徽章：可点击解绑（仅有绑定时显示） */}
        {boundProxy && (
          <Badge
            variant="outline"
            className={cn(
              'text-[10px] h-5 px-1.5 font-normal cursor-pointer group transition-colors',
              boundProxy.enabled && boundProxy.status !== 'dead'
                ? 'border-cyan-500/40 text-cyan-700 dark:text-cyan-300 bg-cyan-500/10 hover:bg-cyan-500/20'
                : 'border-amber-500/40 text-amber-700 dark:text-amber-300 bg-amber-500/10'
            )}
            title={`${isEn ? 'Bound proxy:' : '绑定代理：'} ${boundProxy.host}:${boundProxy.port}${boundProxy.label ? ` (${boundProxy.label})` : ''}\n${isEn ? 'Click to unbind' : '点击解绑'}`}
            onClick={(e) => {
              e.stopPropagation()
              if (confirm(isEn
                ? `Unbind ${account.email} from ${boundProxy.host}:${boundProxy.port}?`
                : `解绑 ${account.email} 与 ${boundProxy.host}:${boundProxy.port}？`
              )) {
                unbindAccountFromProxy(account.id)
              }
            }}
          >
            <span className="opacity-70 group-hover:hidden">⇄</span>
            <span className="hidden group-hover:inline">✕</span>
            <span className="ml-0.5 max-w-[80px] truncate inline-block align-middle">
              {boundProxy.host}
            </span>
          </Badge>
        )}

        {/* Active 容器（始终保留宽度，确保后续元素位置固定） */}
        <div className="w-[60px] flex items-center">
          {account.isActive && (
            <Badge className="h-5 px-2 bg-success text-white border-0 hover:bg-success/90 text-[10px] flex items-center justify-center w-full">
              <Power className="h-2.5 w-2.5 mr-0.5" />
              {isEn ? 'Active' : '当前'}
            </Badge>
          )}
        </div>
      </div>

      {/* === 弹性间隔（吃剩余空间） === */}
      <div className="flex-1 min-w-0" />

      {/* === Credits 区（中右） === */}
      <div className="flex-shrink-0 w-40 flex flex-col gap-0.5 px-2">
        <div className="flex items-center justify-between text-[10px]">
          <span className="text-muted-foreground">{isEn ? 'Usage' : '使用量'}</span>
          <span className={cn(
            'font-mono font-medium tabular-nums',
            isCritical ? 'text-destructive' : isHighUsage ? 'text-warning' : 'text-foreground'
          )}>
            {percentUsed.toFixed(usagePrecision ? 2 : 0)}%
            {isCritical && (
              <span className="ml-1 text-[9px] text-destructive font-semibold">
                +{(percentUsed - 100).toFixed(usagePrecision ? 2 : 0)}%
              </span>
            )}
          </span>
        </div>
        {(() => {
          if (isCritical) {
            const planRatioPct = (100 / percentUsed) * 100
            return (
              <div className="relative h-1.5 w-full overflow-hidden rounded-full bg-foreground/10">
                <div className="absolute inset-y-0 left-0 bg-warning transition-all duration-300" style={{ width: `${planRatioPct}%` }} />
                <div className="absolute inset-y-0 right-0 bg-destructive transition-all duration-300" style={{ left: `${planRatioPct}%` }} />
              </div>
            )
          }
          return (
            <div className="relative h-1.5 w-full overflow-hidden rounded-full bg-foreground/10">
              <div
                className={cn('absolute inset-y-0 left-0 transition-all duration-300', isHighUsage ? 'bg-warning' : 'bg-primary')}
                style={{ width: `${Math.min(percentUsed, 100)}%` }}
              />
            </div>
          )
        })()}
        <div className="flex justify-between text-[9px] text-muted-foreground pt-0.5">
          <span className={cn(isCritical && 'text-destructive font-semibold')}>
            {formatUsage(account.usage.current)}
            {isCritical && ` (+${formatUsage(account.usage.current - account.usage.limit)})`}
          </span>
          <span>/ {formatUsage(account.usage.limit)}</span>
        </div>
      </div>

      {/* === 时间信息区 === */}
      <div className="flex-shrink-0 hidden lg:flex flex-col leading-tight gap-0.5 text-[10px] text-muted-foreground w-28">
        <div className="flex items-center gap-1" title={isEn ? 'Subscription days left' : '订阅剩余天数'}>
          <Clock className="h-3 w-3" />
          <span className={isExpiringSoon ? 'text-warning font-medium' : ''}>
            {daysRemaining !== undefined ? (isEn ? `${daysRemaining}d` : `${daysRemaining}天`) : '-'}
          </span>
        </div>
        <div
          className="flex items-center gap-1"
          title={account.credentials.expiresAt
            ? new Date(account.credentials.expiresAt).toLocaleString(isEn ? 'en-US' : 'zh-CN')
            : (isEn ? 'Unknown' : '未知')
          }
        >
          <KeyRound className="h-3 w-3" />
          <span className={isTokenExpiringSoon ? 'text-destructive font-medium' : ''}>
            {account.credentials.expiresAt ? formatTokenExpiry(account.credentials.expiresAt, isEn) : '-'}
          </span>
        </div>
      </div>

      {/* === 操作区（hover 显示） === */}
      <div className="flex-shrink-0 flex items-center gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity duration-200 border-l border-border/40 pl-2 ml-1">
        {isUnauthorized && (
          <>
            <Button
              size="icon"
              variant="ghost"
              className="h-7 w-7 text-warning hover:bg-warning/10"
              onClick={handleClearSuspended}
              disabled={isClearingSuspended}
              title={isEn ? 'Reset Suspended' : '重置封禁状态'}
            >
              {isClearingSuspended ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : <RotateCcw className="h-3.5 w-3.5" />}
            </Button>
            <a
              href="https://support.aws.amazon.com/#/contacts/kiro"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center justify-center h-7 w-7 rounded-md text-primary hover:bg-primary/10"
              onClick={(e) => e.stopPropagation()}
              title={isEn ? 'Contact Support' : '联系支持'}
            >
              <ExternalLink className="h-3.5 w-3.5" />
            </a>
          </>
        )}

        {!account.isActive && !isUnauthorized && (
          <Button
            size="icon"
            variant="ghost"
            className="h-7 w-7 hover:bg-primary/10 hover:text-primary"
            onClick={handleSwitch}
            title={isEn ? 'Switch to this account' : '切换到该账号'}
          >
            <Power className="h-3.5 w-3.5" />
          </Button>
        )}

        <Button
          size="icon"
          variant="ghost"
          className="h-7 w-7 text-muted-foreground hover:text-foreground"
          onClick={handleRefresh}
          disabled={isRefreshing || account.status === 'refreshing'}
          title={isEn ? 'Check account info' : '检查账户信息'}
        >
          <RefreshCw className={cn('h-3.5 w-3.5', isRefreshing && 'animate-spin')} />
        </Button>

        <Button
          size="icon"
          variant="ghost"
          className="h-7 w-7 text-muted-foreground hover:text-foreground"
          onClick={(e) => { e.stopPropagation(); onShowDetail() }}
          title={isEn ? 'Details' : '详情'}
        >
          <Info className="h-3.5 w-3.5" />
        </Button>

        <Button
          size="icon"
          variant="ghost"
          className="h-7 w-7 text-muted-foreground hover:text-foreground"
          onClick={(e) => { e.stopPropagation(); onEdit() }}
          title={isEn ? 'Edit' : '编辑'}
        >
          <Edit className="h-3.5 w-3.5" />
        </Button>

        {account.isActive ? (
          <Button
            size="icon"
            variant="ghost"
            className="h-7 w-7 hover:bg-destructive/10 hover:text-destructive"
            onClick={handleLogout}
            title={isEn ? 'Logout (clear SSO cache)' : '退出登录（清除 SSO 缓存）'}
          >
            <LogOut className="h-3.5 w-3.5" />
          </Button>
        ) : (
          <Button
            size="icon"
            variant="ghost"
            className="h-7 w-7 hover:bg-destructive/10 hover:text-destructive"
            onClick={handleDelete}
            title={isEn ? 'Delete' : '删除'}
          >
            <Trash2 className="h-3.5 w-3.5" />
          </Button>
        )}
      </div>

      {/* 封禁角标（与卡片同款） */}
      {account.isActive && isUnauthorized && (
        <div className="banned-badge" title={isEn ? 'Banned' : '已封禁'} />
      )}
    </div>
  )
}

export const AccountListRow = memo(AccountListRowComponent)
