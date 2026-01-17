import { createPortal } from 'react-dom'
import { useState, useEffect } from 'react'
import { X, RefreshCw, User, CreditCard, Key, Cpu, Loader2, FileText, Image, Hash, Zap } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import type { Account } from '@/types/account'
import { cn } from '@/lib/utils'
import { useAccountsStore } from '@/store/accounts'
import { useTranslation } from '@/hooks/useTranslation'

interface ModelInfo {
  id: string
  name: string
  description: string
  inputTypes?: string[]
  maxInputTokens?: number | null
  maxOutputTokens?: number | null
  rateMultiplier?: number
  rateUnit?: string
}

interface AccountDetailDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  account: Account | null
  onRefresh?: () => void
  isRefreshing?: boolean
}

// 格式化日期
const formatDate = (date: unknown): string => {
  if (!date) return '-'
  try {
    if (typeof date === 'string') return date.split('T')[0]
    if (date instanceof Date) return date.toISOString().split('T')[0]
    return new Date(date as string | number).toISOString().split('T')[0]
  } catch {
    return String(date).split('T')[0]
  }
}

// 格式化完整日期时间
const formatDateTime = (date: unknown): string => {
  if (!date) return '-'
  try {
    const d = typeof date === 'string' ? new Date(date) : date instanceof Date ? date : new Date(date as number)
    return d.toLocaleString('zh-CN', { 
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit'
    })
  } catch {
    return String(date)
  }
}

export function AccountDetailDialog({
  open,
  onOpenChange,
  account,
  onRefresh,
  isRefreshing
}: AccountDetailDialogProps) {
  const [models, setModels] = useState<ModelInfo[]>([])
  const [modelsLoading, setModelsLoading] = useState(false)
  const [modelsError, setModelsError] = useState<string | null>(null)
  const { maskEmail, maskNickname, privacyMode, usagePrecision } = useAccountsStore()
  const { t } = useTranslation()
  const isEn = t('common.unknown') === 'Unknown'

  // 获取账户可用模型
  useEffect(() => {
    if (open && account?.credentials?.accessToken) {
      setModelsLoading(true)
      setModelsError(null)
      window.api.accountGetModels(account.credentials.accessToken)
        .then(result => {
          if (result.success) {
            setModels(result.models)
          } else {
            setModelsError(result.error || 'Failed to fetch models')
          }
        })
        .catch(err => setModelsError(err.message))
        .finally(() => setModelsLoading(false))
    } else {
      setModels([])
    }
  }, [open, account?.credentials?.accessToken])

  if (!open || !account) return null

  const usage = account.usage
  const subscription = account.subscription
  const credentials = account.credentials

  // 格式化使用量数值
  const formatUsage = (value: number): string => {
    if (usagePrecision) {
      return value.toLocaleString(undefined, { minimumFractionDigits: 0, maximumFractionDigits: 2 })
    }
    return Math.floor(value).toLocaleString()
  }

  // 计算奖励总计
  const bonusTotal = usage.bonuses?.reduce((sum, b) => sum + b.limit, 0) ?? 0
  const bonusUsed = usage.bonuses?.reduce((sum, b) => sum + b.current, 0) ?? 0

  return createPortal(
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/50" onClick={() => onOpenChange(false)} />

      <div className="relative bg-background rounded-xl shadow-2xl w-full max-w-2xl max-h-[90vh] overflow-y-auto m-4 animate-in zoom-in-95 duration-200 border">
        {/* 头部 */}
        <div className="sticky top-0 bg-background/95 backdrop-blur z-20 border-b p-4 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center shadow-inner">
              <User className="h-6 w-6 text-primary" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-lg">{maskEmail(account.email)}</span>
                <Badge className="bg-primary hover:bg-primary/90 text-white shadow-sm">
                  {subscription.title || subscription.type}
                </Badge>
              </div>
              <div className="flex items-center gap-2 mt-1 text-xs text-muted-foreground">
                 <span className="px-1.5 py-0.5 bg-muted rounded-md font-medium">{account.idp}</span>
                 <span>·</span>
                 <span>{isEn ? 'Added ' : '添加于 '}{formatDate(account.createdAt)}</span>
              </div>
            </div>
          </div>
          <Button variant="ghost" size="icon" onClick={() => onOpenChange(false)} className="rounded-full hover:bg-muted">
            <X className="h-5 w-5" />
          </Button>
        </div>

        {/* 内容 */}
        <div className="p-6 space-y-8">
          {/* 配额总览 */}
          <section className="space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="flex items-center gap-2 font-bold text-base text-foreground">
                <CreditCard className="h-5 w-5 text-primary" />
                {isEn ? 'Quota Overview' : '配额总览'}
              </h3>
              {onRefresh && (
                <Button variant="outline" size="sm" onClick={onRefresh} disabled={isRefreshing} className="h-8 rounded-lg">
                  <RefreshCw className={cn("h-3.5 w-3.5 mr-1.5", isRefreshing && "animate-spin")} />
                  {isEn ? 'Refresh' : '刷新数据'}
                </Button>
              )}
            </div>

            <div className="bg-muted/30 border rounded-xl p-5 space-y-4">
               {/* 总使用量 */}
               <div>
                 <div className="flex items-end justify-between mb-2">
                   <div className="space-y-1">
                     <div className="text-sm text-muted-foreground font-medium">{isEn ? 'Total Usage' : '总使用量'}</div>
                     <div className="flex items-baseline gap-1.5">
                       <span className="text-3xl font-bold tracking-tight text-foreground">{formatUsage(usage.current)}</span>
                       <span className="text-lg text-muted-foreground font-medium">/ {formatUsage(usage.limit)}</span>
                     </div>
                   </div>
                   <div className={cn(
                     "text-sm font-semibold px-2.5 py-1 rounded-lg",
                     usage.percentUsed > 0.9 ? "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400" : 
                     "bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400"
                   )}>
                     {(usage.percentUsed * 100).toFixed(usagePrecision ? 2 : 1)}% {isEn ? 'used' : '已使用'}
                   </div>
                 </div>
                 <Progress value={usage.percentUsed * 100} className="h-3 rounded-full" indicatorClassName={usage.percentUsed > 0.9 ? "bg-red-500" : "bg-primary"} />
               </div>

               <div className="grid grid-cols-3 gap-4 pt-2">
                 {/* 主配额 */}
                 <div className="p-4 bg-background rounded-xl border shadow-sm">
                   <div className="flex items-center gap-2 text-xs font-semibold text-blue-600 dark:text-blue-400 mb-2">
                     <div className="w-2 h-2 rounded-full bg-blue-500" />
                     {isEn ? 'Base' : '主配额'}
                   </div>
                   <div className="text-xl font-bold tracking-tight">
                     {formatUsage(usage.baseCurrent ?? 0)} <span className="text-sm text-muted-foreground font-normal">/ {formatUsage(usage.baseLimit ?? 0)}</span>
                   </div>
                   <div className="text-xs text-muted-foreground mt-1 font-medium">
                     {formatDate(usage.nextResetDate)} {isEn ? 'reset' : '重置'}
                   </div>
                 </div>
                 
                 {/* 免费试用 */}
                 <div className={cn("p-4 bg-background rounded-xl border shadow-sm", (usage.freeTrialLimit ?? 0) === 0 && "opacity-60 grayscale")}>
                   <div className="flex items-center gap-2 text-xs font-semibold text-purple-600 dark:text-purple-400 mb-2">
                     <div className="w-2 h-2 rounded-full bg-purple-500" />
                     {isEn ? 'Trial' : '免费试用'}
                     {(usage.freeTrialLimit ?? 0) > 0 && <Badge variant="secondary" className="text-[10px] px-1 h-4 ml-auto">ACTIVE</Badge>}
                   </div>
                   <div className="text-xl font-bold tracking-tight">
                     {formatUsage(usage.freeTrialCurrent ?? 0)} <span className="text-sm text-muted-foreground font-normal">/ {formatUsage(usage.freeTrialLimit ?? 0)}</span>
                   </div>
                   <div className="text-xs text-muted-foreground mt-1 font-medium">
                     {usage.freeTrialExpiry ? `${formatDate(usage.freeTrialExpiry)} ${isEn ? 'expires' : '过期'}` : (isEn ? 'No trial' : '无试用额度')}
                   </div>
                 </div>

                 {/* 奖励总计 */}
                 <div className={cn("p-4 bg-background rounded-xl border shadow-sm", bonusTotal === 0 && "opacity-60 grayscale")}>
                   <div className="flex items-center gap-2 text-xs font-semibold text-cyan-600 dark:text-cyan-400 mb-2">
                     <div className="w-2 h-2 rounded-full bg-cyan-500" />
                     {isEn ? 'Bonus' : '奖励总计'}
                   </div>
                   <div className="text-xl font-bold tracking-tight">
                     {formatUsage(bonusUsed)} <span className="text-sm text-muted-foreground font-normal">/ {formatUsage(bonusTotal)}</span>
                   </div>
                   <div className="text-xs text-muted-foreground mt-1 font-medium">
                     {isEn ? `${usage.bonuses?.length ?? 0} active` : `${usage.bonuses?.length ?? 0} 个生效奖励`}
                   </div>
                 </div>
               </div>
            </div>
          </section>

          {/* 奖励详情 */}
          {usage.bonuses && usage.bonuses.length > 0 && (
            <section className="space-y-3">
              <h3 className="font-bold text-sm text-muted-foreground uppercase tracking-wider pl-1">{isEn ? 'Active Bonuses' : '生效奖励明细'}</h3>
              <div className="grid grid-cols-1 gap-2">
                {usage.bonuses.map((bonus) => (
                  <div key={bonus.code} className="flex items-center justify-between p-4 bg-background border rounded-xl shadow-sm hover:shadow-md transition-shadow">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-sm">{bonus.name}</span>
                        <Badge variant="outline" className="text-[10px] h-5 px-1.5 text-green-600 border-green-200 bg-green-50">
                          ACTIVE
                        </Badge>
                      </div>
                      <div className="text-xs text-muted-foreground font-mono">
                        Code: {bonus.code} · {formatDateTime(bonus.expiresAt)} 过期
                      </div>
                    </div>
                    <div className="text-right">
                      <div className="text-sm font-bold">{formatUsage(bonus.current)} <span className="text-muted-foreground font-normal">/ {formatUsage(bonus.limit)}</span></div>
                      <div className="text-[10px] text-blue-600 font-medium">
                         {isEn ? 'Used' : '已用'} {((bonus.current / bonus.limit) * 100).toFixed(usagePrecision ? 2 : 0)}%
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </section>
          )}

          {/* 基本信息 & Token 凭证 - 并排布局 */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
             {/* 基本信息 */}
             <section className="space-y-3">
               <h3 className="flex items-center gap-2 font-bold text-base text-foreground">
                 <User className="h-5 w-5 text-primary" />
                 {isEn ? 'Basic Info' : '基本信息'}
               </h3>
               <div className="bg-muted/30 border rounded-xl p-4 space-y-4">
                 <div className="space-y-1">
                   <label className="text-xs font-medium text-muted-foreground">{isEn ? 'Email' : '邮箱地址'}</label>
                   <div className="text-sm font-mono break-all select-all">{maskEmail(account.email)}</div>
                 </div>
                 <div className="grid grid-cols-2 gap-4">
                   <div className="space-y-1">
                      <label className="text-xs font-medium text-muted-foreground">{isEn ? 'Nickname' : '账号别名'}</label>
                      <div className="text-sm font-medium">{maskNickname(account.nickname) || '-'}</div>
                   </div>
                   <div className="space-y-1">
                      <label className="text-xs font-medium text-muted-foreground">{isEn ? 'Provider' : '身份提供商'}</label>
                      <div className="text-sm font-medium">{account.idp}</div>
                   </div>
                 </div>
                 <div className="space-y-1">
                    <label className="text-xs font-medium text-muted-foreground">{isEn ? 'User ID' : '用户 ID'}</label>
                    <div className="text-xs font-mono break-all bg-background p-2 rounded border select-all">{privacyMode ? '********' : (account.userId || '-')}</div>
                 </div>
               </div>
             </section>

             {/* Token 凭证 */}
             <section className="space-y-3">
               <h3 className="flex items-center gap-2 font-bold text-base text-foreground">
                 <Key className="h-5 w-5 text-primary" />
                 {isEn ? 'Subscription' : '订阅详情'}
               </h3>
               <div className="bg-muted/30 border rounded-xl p-4 text-sm space-y-3">
                 <div className="flex justify-between items-center py-1 border-b border-border/50">
                   <span className="text-muted-foreground text-xs">Region</span>
                   <Badge variant="outline" className="font-mono">{credentials.region || 'us-east-1'}</Badge>
                 </div>
                 <div className="flex justify-between items-center py-1 border-b border-border/50">
                   <span className="text-muted-foreground text-xs">{isEn ? 'Token Expires' : 'Token 到期'}</span>
                   <span className="font-medium text-xs">{credentials.expiresAt ? formatDateTime(credentials.expiresAt) : '-'}</span>
                 </div>
                 <div className="flex justify-between items-center py-1 border-b border-border/50">
                   <span className="text-muted-foreground text-xs">{isEn ? 'Plan Type' : '订阅类型'}</span>
                   <span className="font-mono text-xs" title={subscription.rawType}>{subscription.rawType || '-'}</span>
                 </div>
                 <div className="flex justify-between items-center py-1 border-b border-border/50">
                   <span className="text-muted-foreground text-xs">{isEn ? 'Overage Rate' : '超额费率'}</span>
                   <span className="font-mono text-xs">
                     {usage.resourceDetail?.overageRate 
                       ? `$${usage.resourceDetail.overageRate}/${usage.resourceDetail.unit || 'INV'}`
                       : '-'}
                   </span>
                 </div>
                 <div className="flex justify-between items-center py-1 border-b border-border/50">
                   <span className="text-muted-foreground text-xs">{isEn ? 'Resource Type' : '资源类型'}</span>
                   <span className="font-mono text-xs">{usage.resourceDetail?.resourceType || '-'}</span>
                 </div>
                 <div className="flex justify-between items-center py-1">
                   <span className="text-muted-foreground text-xs">{isEn ? 'Upgradable' : '可升级'}</span>
                   <span className={cn("text-xs font-bold", subscription.upgradeCapability === 'UPGRADE_CAPABLE' ? "text-green-600" : "text-muted-foreground")}>
                      {subscription.upgradeCapability === 'UPGRADE_CAPABLE' ? 'YES' : 'NO'}
                   </span>
                 </div>
               </div>
             </section>
          </div>

          {/* 账户可用模型 */}
          <section className="space-y-3">
            <h3 className="flex items-center gap-2 font-bold text-base text-foreground">
              <Cpu className="h-5 w-5 text-primary" />
              {isEn ? 'Available Models' : '账户可用模型'}
              <Badge className="ml-auto bg-primary/10 text-primary border-primary/20">{models.length}</Badge>
            </h3>
            <div className="bg-gradient-to-br from-muted/20 to-muted/40 border rounded-xl p-4">
              {modelsLoading ? (
                <div className="flex items-center justify-center py-8 text-muted-foreground">
                  <Loader2 className="h-5 w-5 animate-spin mr-2" />
                  {isEn ? 'Loading models...' : '加载模型中...'}
                </div>
              ) : modelsError ? (
                <div className="text-center py-8 text-muted-foreground">
                  <p className="text-red-500 text-sm">{modelsError}</p>
                </div>
              ) : models.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground text-sm">
                  {isEn ? 'No models available' : '暂无可用模型'}
                </div>
              ) : (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 max-h-[320px] overflow-y-auto pr-1">
                  {models.map((model, index) => (
                    <div 
                      key={model.id} 
                      className={cn(
                        "group p-3 bg-background rounded-xl border shadow-sm hover:shadow-md hover:border-primary/30 transition-all duration-200",
                        index === 0 && "ring-1 ring-primary/20"
                      )}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1.5">
                            <div className={cn(
                              "w-2 h-2 rounded-full shrink-0",
                              index === 0 ? "bg-primary animate-pulse" : "bg-muted-foreground/40"
                            )} />
                            <code className="text-xs font-bold text-foreground truncate">
                              {model.id}
                            </code>
                          </div>
                          {model.name && model.name !== model.id && (
                            <p className="text-[11px] text-primary/80 font-medium mb-1 truncate">{model.name}</p>
                          )}
                          <p className="text-[11px] text-muted-foreground line-clamp-2 leading-relaxed">
                            {model.description || (isEn ? 'No description' : '无描述')}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center justify-between mt-2 pt-2 border-t border-border/50">
                        <div className="flex items-center gap-1.5">
                          {model.inputTypes?.includes('TEXT') && (
                            <Badge variant="secondary" className="text-[10px] px-1.5 h-5 bg-blue-500/10 text-blue-600 dark:text-blue-400 border-0">
                              <FileText className="h-3 w-3 mr-0.5" />Text
                            </Badge>
                          )}
                          {model.inputTypes?.includes('IMAGE') && (
                            <Badge variant="secondary" className="text-[10px] px-1.5 h-5 bg-purple-500/10 text-purple-600 dark:text-purple-400 border-0">
                              <Image className="h-3 w-3 mr-0.5" />Image
                            </Badge>
                          )}
                          {model.rateMultiplier !== undefined && (
                            <Badge variant="secondary" className="text-[10px] px-1.5 h-5 bg-amber-500/10 text-amber-600 dark:text-amber-400 border-0">
                              <Zap className="h-3 w-3 mr-0.5" />{model.rateMultiplier}x
                            </Badge>
                          )}
                        </div>
                        <div className="flex items-center gap-1 text-[10px] text-muted-foreground font-mono">
                          <Hash className="h-3 w-3" />
                          <span className="text-green-600 dark:text-green-400">
                            {model.maxInputTokens ? (model.maxInputTokens >= 1000000 ? `${(model.maxInputTokens / 1000000).toFixed(0)}M` : `${(model.maxInputTokens / 1000).toFixed(0)}K`) : '-'}
                          </span>
                          <span>/</span>
                          <span className="text-orange-600 dark:text-orange-400">
                            {model.maxOutputTokens ? (model.maxOutputTokens >= 1000000 ? `${(model.maxOutputTokens / 1000000).toFixed(0)}M` : `${(model.maxOutputTokens / 1000).toFixed(0)}K`) : '-'}
                          </span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </section>
        </div>
      </div>
    </div>,
    document.body
  )
}
