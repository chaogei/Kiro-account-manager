import { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import { UserPlus, Mail, Key, Loader2, CheckCircle2, XCircle, Trash2, Play, Square, Clock, RotateCcw, RefreshCw, Download, Upload, Settings2, Link2, AtSign, Shuffle, Info, Pause, AlertTriangle, ShieldAlert, Gauge, Activity, CalendarClock, Timer } from 'lucide-react'
import { useTranslation } from '@/hooks/useTranslation'
import { useAccountsStore } from '@/store/accounts'
import { useTaskStore } from '@/store/tasks'
import { createRateLimiter, type RateLimiter, type RateLimiterSnapshot } from '@/store/rateLimiter'
import { useWebhookStore } from '@/store/webhooks'
import { Card, CardContent, CardHeader, CardTitle, Button, Input, Label, Progress, Badge, Switch } from '../ui'
import { cn } from '@/lib/utils'
import { appendSubscriptionLink, updateSubscriptionLink } from './SubscriptionPage'
import { generateNextDotVariant, countSameRootVariants, totalVariantCount, splitEmail } from '@/lib/dotVariants'

// 失败错误码归类：用于失败重试队列的过滤
type ErrCategory =
  | 'risk_control' | 'proxy_chain' | 'strict_proxy' | 'proxy_whitelist'
  | 'eof' | 'otp_timeout' | 'network' | 'email_used'
  | 'rate_limit' | 'auth' | 'suspended' | 'unknown'

interface ErrorDiagnosis {
  category: ErrCategory
  title: string
  reasons: string[]
  suggestions: string[]
}

/**
 * 把失败原因翻译成"普通话"的诊断 + 建议，覆盖批量注册里最常见的几类失败。
 * 优先级：风控 > 代理白名单 > 代理链 > 严格代理 > EOF > OTP超时 > 网络 > 邮箱已用 > 限流 > 鉴权 > suspended > unknown
 */
function diagnoseRegError(err: string | undefined): ErrorDiagnosis {
  const e = (err || '').toLowerCase()
  if (!e) {
    return { category: 'unknown', title: '未知错误', reasons: ['未捕获到具体错误信息'], suggestions: ['查看完整日志'] }
  }
  // AWS 风控
  if (e.includes('aws-risk-control') || e.includes('风控') || e.includes('请稍后再试') || e.includes('try again later')) {
    return {
      category: 'risk_control',
      title: 'AWS 风控触发',
      reasons: ['注册请求被 AWS 安全策略拦截', '常见诱因：同 IP 短时注册多账号、行为节奏机械化、邮箱域名被关联'],
      suggestions: ['启用代理池 + 每号唯一 session（每号一个 IP）', '降低速率（限速 10/分钟或更低）', '邮箱用多域名轮换', '若用 bestproxy 类住宅代理，确保来源 IP 非大陆']
    }
  }
  // bestproxy 610 / IP 白名单类
  if (e.includes('610') || e.includes('whitelist') || (e.includes('connect') && e.includes('http 4'))) {
    return {
      category: 'proxy_whitelist',
      title: '代理认证 / 白名单失败',
      reasons: ['目标代理拒绝认证（账密错或来源 IP 不在白名单）', 'bestproxy 的 610 = 来源 IP 未授权'],
      suggestions: ['在代理后台把当前出口 IP 加入白名单', '或改用账密直连模式 + 确保来源是允许地区', '配合"上游中转代理"用非大陆中转']
    }
  }
  // 代理链失败
  if (e.includes('proxychain') || e.includes('代理链') || e.includes('上游中转')) {
    return {
      category: 'proxy_chain',
      title: '代理链建立失败',
      reasons: ['"上游中转 → 目标代理"链路握手未通过'],
      suggestions: ['到「代理池」页面点「诊断」定位哪一层挂了', '确认上游中转端口（如 socks5://127.0.0.1:7890）已在跑', '若目标代理要求白名单，确保中转出口 IP 已加白']
    }
  }
  // 严格代理（无可用代理拒绝裸奔）
  if (e.includes('严格代理') || e.includes('strict') && e.includes('proxy')) {
    return {
      category: 'strict_proxy',
      title: '严格代理模式拦截',
      reasons: ['代理池启用了"绝不裸奔直连"，但当前无可用代理'],
      suggestions: ['到代理池验活，确认至少 1 条 alive', '检查代理是否被自动停用', '临时可手动启用所有代理 / 关掉"失败自动停用"']
    }
  }
  // EOF / status=0 网络抖动
  if (e.includes('eof') || (e.includes('status=0') && e.includes('failed to do request')) || e.includes('connection reset')) {
    return {
      category: 'eof',
      title: '网络瞬时断开（EOF）',
      reasons: ['TLS 连接在握手或传输中被对端 RST/关闭', '常见于代理不稳定 / 高并发挤压 / 中间网络抖动'],
      suggestions: ['降低并发数', '换代理 / 加上游中转', '已内置重试，偶发可忽略；连续大量则更换出口']
    }
  }
  // OTP 超时
  if ((e.includes('timeout') || e.includes('超时')) && (e.includes('otp') || e.includes('验证码') || e.includes('code'))) {
    return {
      category: 'otp_timeout',
      title: '等待验证码超时',
      reasons: ['临时邮箱未在期限内收到 AWS 验证邮件', '可能 AWS 没发（风控拦截）/ 邮件落到垃圾 / 临时邮箱服务延迟'],
      suggestions: ['确认临时邮箱服务可用', '该邮箱域名可能被 AWS 标黑，换域名重试', '若反复出现，多半是 AWS 静默风控，需换 IP/换节奏']
    }
  }
  // 一般网络
  if (e.includes('timeout') || e.includes('超时') || e.includes('etimedout') || e.includes('fetch failed') || e.includes('econnreset') || e.includes('econnrefused') || e.includes('enotfound') || e.includes('network')) {
    return {
      category: 'network',
      title: '网络错误',
      reasons: ['连接 / DNS / 超时类失败'],
      suggestions: ['检查本机网络与代理可达性', '降低并发再试']
    }
  }
  // 邮箱已被注册
  if (e.includes('已注册') || (e.includes('email') && (e.includes('already') || e.includes('exists') || e.includes('used') || e.includes('已存在') || e.includes('已被')))) {
    return {
      category: 'email_used',
      title: '邮箱已被注册',
      reasons: ['该邮箱地址 AWS 侧已存在'],
      suggestions: ['前缀生成器近期已增强随机性（中间名/双姓），再跑一次几乎不会撞', '使用多域名进一步降低冲突']
    }
  }
  // 限流
  if (e.includes('rate') || e.includes('limit') || e.includes('too many') || e.includes('限流') || e.includes('429')) {
    return {
      category: 'rate_limit',
      title: '触发限流',
      reasons: ['短时请求次数超出 AWS 接受范围'],
      suggestions: ['降低 maxPerMinute 与并发', '启用风控自动暂停']
    }
  }
  // suspended
  if (e.includes('suspended')) {
    return {
      category: 'suspended',
      title: '账号已被停用',
      reasons: ['注册流程跑完但 AWS 在最后一步把账号标为 suspended', '通常是风控级判定（域名/IP/指纹综合）'],
      suggestions: ['换出口 IP / 换邮箱域名 / 降低速率', '可看作"软风控"信号，应立刻放慢']
    }
  }
  // 鉴权
  if (e.includes('unauthorized') || e.includes('401') || e.includes('403')) {
    return {
      category: 'auth',
      title: '鉴权失败',
      reasons: ['上游接口返回 401/403'],
      suggestions: ['检查凭据 / 看接口侧响应体']
    }
  }
  return { category: 'unknown', title: '其他错误', reasons: [err || ''], suggestions: ['查看完整日志定位'] }
}

/** 旧 API 兼容：现有 retryFailed 等用 classifyError 做筛选 */
function classifyError(err: string | undefined): 'network' | 'otp_timeout' | 'email_used' | 'rate_limit' | 'auth' | 'risk_control' | 'unknown' {
  const cat = diagnoseRegError(err).category
  if (cat === 'risk_control') return 'risk_control'
  if (cat === 'otp_timeout') return 'otp_timeout'
  if (cat === 'email_used') return 'email_used'
  if (cat === 'rate_limit') return 'rate_limit'
  if (cat === 'auth') return 'auth'
  if (cat === 'eof' || cat === 'network' || cat === 'proxy_chain' || cat === 'proxy_whitelist' || cat === 'strict_proxy') return 'network'
  return 'unknown'
}

// 随机 session 值（字母数字），用于代理「会话粘性」——同值保持同一出口 IP
function randomSession(len = 8): string {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
  let s = ''
  for (let i = 0; i < len; i++) s += chars[Math.floor(Math.random() * chars.length)]
  return s
}

/**
 * 为代理 URL 注入「每账号唯一 session」，让同一账号整个注册流程走同一出口 IP、不同账号用不同 IP。
 * 1) url 含 {session} 占位符 → 替换为随机值（通用，适配任意服务商）；
 * 2) 参数化用户名（bestproxy 等，含 _area-/_life-/_city-/_state- 等）且未写 _session- → 自动补一个；
 * 其余情况（普通代理、已写 session）原样返回，不干扰。
 */
function injectProxySession(url: string): string {
  if (!url) return url
  const session = randomSession()
  if (url.includes('{session}')) {
    return url.replace(/\{session\}/g, session)
  }
  const m = url.match(/^(\w+:\/\/)([^@/]+)@(.+)$/)
  if (m) {
    const [, scheme, userinfo, hostpart] = m
    const ci = userinfo.indexOf(':')
    const username = ci >= 0 ? userinfo.slice(0, ci) : userinfo
    const password = ci >= 0 ? userinfo.slice(ci + 1) : ''
    const isParamStyle = /_(area|life|city|state|session|region|country)-/i.test(username)
    if (isParamStyle && !/_session-/i.test(username)) {
      const newUser = `${username}_session-${session}`
      return `${scheme}${newUser}${ci >= 0 ? ':' + password : ''}@${hostpart}`
    }
  }
  return url
}

type RegMode = 'manual' | 'outlook' | 'tempmail' | 'proton' | 'gptmail' | 'mixed'
type AutoEmailSource = 'outlook' | 'tempmail' | 'proton' | 'gptmail'
/**
 * Phase 状态机：
 * - idle：未开始
 * - initializing：OIDC 设备授权初始化
 * - email：等待用户输入邮箱
 * - otp：等待用户输入验证码
 * - running：注册流程进行中（Verify/Password/Token 由日志关键字推断）
 * - done：核心注册流程完成（含 Token），未启用任何后处理时即为最终态
 * - importing：正在自动导入账号
 * - fetching-link：正在获取 Pro 订阅链接
 * - finalized：包含所有后处理在内的最终完成
 */
type Phase = 'idle' | 'initializing' | 'email' | 'otp' | 'running' | 'done' | 'importing' | 'fetching-link' | 'finalized'

interface FingerprintSnapshot {
  chromeVer: string
  ua: string
  gpuVendor: string
  gpuModel: string
  canvasHash: number
  screen: { width: number; height: number }
  proxyUrl?: string
  exitIP?: string
}

interface RegResult {
  status: 'success' | 'failed'
  email: string
  password?: string
  error?: string
  clientId?: string
  clientSecret?: string
  refreshToken?: string
  accessToken?: string
  region?: string
  provider?: string
  verify?: Record<string, unknown>
  fingerprint?: FingerprintSnapshot
}

type BatchItemStatus = 'pending' | 'running' | 'retrying' | 'success' | 'failed' | 'imported' | 'import_failed'

interface HistoryItem {
  id: string
  time: number
  email: string
  status: 'success' | 'failed'
  error?: string
  password?: string
  result?: RegResult
  imported: boolean
  subscriptionUrl?: string
}

type RegStepName =
  | 'init' | 'proxy-chain-ready' | 'tls-ready' | 'exit-ip'
  | 'oidc' | 'device' | 'email-created'
  | 'portal' | 'workflow-init' | 'submit-email'
  | 'signup' | 'send-otp' | 'waiting-otp' | 'otp-received'
  | 'create-identity' | 'set-password' | 'sso-workflow' | 'sso-token'
  | 'verify-alive' | 'done'

/** step → 简短中文标签，给 UI 显示用 */
const STEP_LABEL_CN: Record<RegStepName, string> = {
  'init': '初始化',
  'proxy-chain-ready': '代理链就绪',
  'tls-ready': 'TLS 就绪',
  'exit-ip': '探出口 IP',
  'oidc': 'OIDC',
  'device': '设备授权',
  'email-created': '邮箱已创建',
  'portal': 'Portal',
  'workflow-init': '工作流',
  'submit-email': '提交邮箱',
  'signup': 'Signup',
  'send-otp': '发送验证码',
  'waiting-otp': '等验证码',
  'otp-received': '验证码到',
  'create-identity': '建身份',
  'set-password': '设密码',
  'sso-workflow': 'SSO 工作流',
  'sso-token': '取 Token',
  'verify-alive': '验活',
  'done': '完成'
}

interface BatchItem {
  id: string
  index: number
  status: BatchItemStatus
  email: string
  error?: string
  retryCount: number
  /** 实时进度：当前 step、起步时间、当前 step 起步时间、出口 IP */
  currentStep?: RegStepName
  startedAt?: number
  stepStartedAt?: number
  exitIp?: string
}

function fmtMs(ms: number): string {
  if (ms < 1000) return `${ms}ms`
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`
  const m = Math.floor(ms / 60_000)
  const s = Math.floor((ms % 60_000) / 1000)
  return `${m}m${s.toString().padStart(2, '0')}s`
}

/** 单行批量任务的展示：状态图标 + 邮箱 + 当前步骤 + 总耗时 + 出口 IP / 错误 + 失败诊断展开。
 * 拆为子组件可减少父组件重渲染时的工作量，并配合 batchClock 让总耗时随秒滚动。
 */
function BatchItemRow({
  item,
  t,
  batchClock
}: {
  item: BatchItem
  t: (k: string) => string
  batchClock: number
}): React.ReactNode {
  const isActive = item.status === 'running' || item.status === 'retrying'
  const now = isActive ? batchClock : (item.stepStartedAt || item.startedAt || 0)
  const totalMs = item.startedAt ? Math.max(0, now - item.startedAt) : undefined
  const stepLabel = item.currentStep ? STEP_LABEL_CN[item.currentStep] : ''
  const [diagOpen, setDiagOpen] = useState(false)
  const isFailed = item.status === 'failed' || item.status === 'import_failed'
  const diag = isFailed && item.error ? diagnoseRegError(item.error) : null

  return (
    <div className="border-b last:border-b-0 text-xs hover:bg-muted/50 transition-colors">
      <div className="flex items-center justify-between px-3 py-1.5">
        <div className="flex items-center gap-2 min-w-0 flex-1">
          <span className="text-muted-foreground w-6 text-right shrink-0">#{item.index}</span>
          {item.status === 'pending' && <span className="text-muted-foreground shrink-0">—</span>}
          {item.status === 'running' && <Loader2 className="h-3 w-3 animate-spin text-primary shrink-0" />}
          {item.status === 'retrying' && <RefreshCw className="h-3 w-3 animate-spin text-yellow-500 shrink-0" />}
          {item.status === 'success' && <CheckCircle2 className="h-3 w-3 text-green-500 shrink-0" />}
          {item.status === 'imported' && <Download className="h-3 w-3 text-green-600 shrink-0" />}
          {item.status === 'failed' && <XCircle className="h-3 w-3 text-red-500 shrink-0" />}
          {item.status === 'import_failed' && <XCircle className="h-3 w-3 text-orange-500 shrink-0" />}
          <span className="font-mono truncate">{item.email || <span className="text-muted-foreground italic">待生成</span>}</span>
          {isActive && stepLabel && (
            <Badge variant="outline" className="h-4 px-1.5 text-[10px] font-normal shrink-0">{stepLabel}</Badge>
          )}
          {item.exitIp && (
            <span className="text-[10px] text-muted-foreground font-mono shrink-0 hidden sm:inline">IP {item.exitIp}</span>
          )}
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {totalMs !== undefined && (
            <span className="text-[10px] text-muted-foreground font-mono tabular-nums">{fmtMs(totalMs)}</span>
          )}
          <span className={cn('text-xs whitespace-nowrap',
            (item.status === 'success' || item.status === 'imported') && 'text-green-600',
            (item.status === 'failed' || item.status === 'import_failed') && 'text-red-500',
            item.status === 'retrying' && 'text-yellow-600',
            (item.status === 'pending' || item.status === 'running') && 'text-muted-foreground'
          )}>
            {item.status === 'pending' ? '' :
             item.status === 'running' ? '' :
             item.status === 'retrying' ? `${t('register.batchItemRetrying')} (${item.retryCount})` :
             item.status === 'success' ? t('register.batchItemSuccess') :
             item.status === 'imported' ? t('register.batchItemImported') :
             item.status === 'import_failed' ? t('register.batchItemImportFailed') :
             diag ? diag.title : (item.error || t('register.batchItemFailed'))}
          </span>
          {diag && (
            <button
              onClick={() => setDiagOpen((v) => !v)}
              className="ml-1 text-[10px] px-1.5 py-0.5 rounded border border-border bg-background hover:bg-muted transition-colors text-muted-foreground hover:text-foreground"
              title="查看原因与建议"
            >
              {diagOpen ? '收起' : '诊断'}
            </button>
          )}
        </div>
      </div>
      {diag && diagOpen && (
        <div className="px-3 pb-2 pl-12 pr-3 space-y-1.5">
          <div className="rounded-md border border-red-500/30 bg-red-500/5 px-3 py-2 space-y-1.5">
            <div className="font-medium text-red-700 dark:text-red-400 text-[11px]">{diag.title}</div>
            {diag.reasons.length > 0 && (
              <div className="text-[11px] text-foreground/80">
                <div className="text-muted-foreground">可能原因：</div>
                <ul className="list-disc pl-4 space-y-0.5">
                  {diag.reasons.map((r, i) => <li key={i}>{r}</li>)}
                </ul>
              </div>
            )}
            {diag.suggestions.length > 0 && (
              <div className="text-[11px] text-foreground/80">
                <div className="text-muted-foreground">建议：</div>
                <ul className="list-disc pl-4 space-y-0.5">
                  {diag.suggestions.map((s, i) => <li key={i}>{s}</li>)}
                </ul>
              </div>
            )}
            {item.error && (
              <div className="text-[10px] text-muted-foreground font-mono break-all pt-1 border-t border-red-500/20">
                原始：{item.error}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

/**
 * 注册进度的核心 6 步：OIDC → Email → Verify → Password → Token → Done
 * 后处理可选追加：Import（自动导入开启时）、ProLink（自动获取 Pro 链接开启时）
 */
const CORE_STEPS = ['OIDC', 'Email', 'Verify', 'Password', 'Token', 'Done'] as const

/**
 * 根据用户开关动态构建步骤列表
 * @param hasImport 是否启用了自动导入
 * @param hasProLink 是否启用了自动获取 Pro 链接
 */
function buildManualSteps(hasImport: boolean, hasProLink: boolean): readonly string[] {
  const extras: string[] = []
  if (hasImport) extras.push('Import')
  if (hasProLink) extras.push('ProLink')
  if (extras.length === 0) return CORE_STEPS
  // 在 Done 之前插入额外步骤；'Done' 永远在最后
  return [...CORE_STEPS.slice(0, -1), ...extras, 'Done']
}

/**
 * 将 phase + 最近日志推断到当前步骤索引（基于动态步骤数组）
 * @param phase 后端发出的注册阶段（含后处理阶段）
 * @param lastLog 最近一条日志（用于在 running 阶段细分到 Verify/Password/Token）
 * @param steps 通过 buildManualSteps 构造的动态步骤数组
 */
function phaseToStep(phase: Phase, lastLog: string | undefined, steps: readonly string[]): number {
  // 步骤索引辅助：找具体步骤名在动态数组中的位置
  const idxOf = (name: string): number => steps.indexOf(name)
  const lastIdx = steps.length - 1

  switch (phase) {
    case 'idle': return -1
    case 'initializing': return idxOf('OIDC')
    case 'email': return idxOf('Email')
    case 'otp': return idxOf('Verify')
    case 'done': return idxOf('Done')  // 核心流程完成（未启用后处理时即最终态）
    case 'importing': {
      const i = idxOf('Import')
      return i >= 0 ? i : idxOf('Done')
    }
    case 'fetching-link': {
      const i = idxOf('ProLink')
      return i >= 0 ? i : idxOf('Done')
    }
    case 'finalized': return lastIdx
    case 'running': {
      if (!lastLog) return Math.max(0, idxOf('Email'))
      const log = lastLog.toLowerCase()
      // 自动模式 OTP 提交时也走 running，这里识别后处理消息
      if (log.includes('正在获取 pro') || log.includes('pro link') || log.includes('fetching pro')) {
        const i = idxOf('ProLink')
        if (i >= 0) return i
      }
      if (log.includes('正在导入') || log.includes('importing') || log.includes('已导入')) {
        const i = idxOf('Import')
        if (i >= 0) return i
      }
      // [13] SSO Token / [12.5] complete-signup / 验活成功
      if (log.includes('sso') || log.includes('token') || log.includes('验活') || log.includes('complete') || log.includes('end-of-workflow')) return idxOf('Token')
      // [12] 设置密码 / SetPassword / 加密公钥
      if (log.includes('密码') || log.includes('password') || log.includes('加密公钥')) return idxOf('Password')
      // [9] OTP / [10] verify-email / signup verify
      if (log.includes('验证码') || log.includes('otp') || log.includes('verify')) return idxOf('Verify')
      // [7-8] Signup / SignupInit / Profile
      if (log.includes('signup') || log.includes('profile') || log.includes('注册初始化')) return idxOf('Verify')
      // [6] 提交邮箱 / SubmitEmail
      if (log.includes('提交邮箱') || log.includes('submit') || log.includes('邮箱')) return idxOf('Email')
      return Math.max(0, idxOf('Email'))
    }
  }
}

const STORAGE_KEY = 'kiro-register-config'
const HISTORY_KEY = 'kiro-register-history'
/** 已知占用邮箱黑名单：注册失败为 email_used 时加入，下次自动跳过 */
const EMAIL_BLACKLIST_KEY = 'kiro-register-email-blacklist'
/** 注册策略模板：完整 RegisterConfig 命名快照，便于一键切换场景 */
const TEMPLATES_KEY = 'kiro-register-templates'

interface RegisterTemplate {
  id: string
  name: string
  config: RegisterConfig
  createdAt: number
}

function loadTemplates(): RegisterTemplate[] {
  try {
    const raw = localStorage.getItem(TEMPLATES_KEY)
    return raw ? JSON.parse(raw) as RegisterTemplate[] : []
  } catch { return [] }
}

function saveTemplates(items: RegisterTemplate[]): void {
  try { localStorage.setItem(TEMPLATES_KEY, JSON.stringify(items)) } catch { /* ignore */ }
}

function loadEmailBlacklist(): Set<string> {
  try {
    const raw = localStorage.getItem(EMAIL_BLACKLIST_KEY)
    if (!raw) return new Set()
    const arr = JSON.parse(raw) as string[]
    return new Set(arr.map((e) => e.toLowerCase()))
  } catch {
    return new Set()
  }
}

function saveEmailBlacklist(set: Set<string>): void {
  try {
    // 限制最多 5000 条，避免无限增长
    const arr = Array.from(set).slice(-5000)
    localStorage.setItem(EMAIL_BLACKLIST_KEY, JSON.stringify(arr))
  } catch { /* ignore */ }
}

function clearEmailBlacklist(): void {
  try { localStorage.removeItem(EMAIL_BLACKLIST_KEY) } catch { /* ignore */ }
}

// 模块级状态：组件卸载后仍保留（同一会话内）
let _logs: string[] = []
let _phase: Phase = 'idle'
let _result: RegResult | null = null
let _batchRunning = false
let _batchDone = 0
let _batchSuccess = 0
let _batchFail = 0
let _batchItems: BatchItem[] = []
// Proton 登录态缓存到模块级：切换页面回来不丢失显示（真实登录态持久化在 persist:proton session）
let _protonLoggedIn = false
/**
 * 模块级映射：taskId(后端) → batchItem.id(前端)，用于把 step 事件路由到对应行。
 * 必须放模块级 — 之前用 useRef 会在切换页面 unmount 时丢失，导致重新挂载后
 * 仍在跑的任务的 step/IP/耗时不再更新（页面回来后看起来"信息没保存"）。
 */
const _taskIdToItemId = new Map<string, string>()

/**
 * 模块级 step 事件订阅：注册一次后永不取消。
 * 旧实现把订阅放 useEffect，切到其它页面 unmount 时被 cleanup 取消，
 * 期间发生的所有 step 事件全部丢失，切回来后 UI 信息缺失。
 */
let _stepListenerRegistered = false
function ensureStepListenerRegistered(): void {
  if (_stepListenerRegistered) return
  _stepListenerRegistered = true
  window.api.onRegistrationStep(({ taskId, event }) => {
    if (!taskId) return
    const itemId = _taskIdToItemId.get(taskId)
    if (!itemId) return
    const now = event.ts || Date.now()
    // 写模块级数据 + 通知挂载中的 React 组件刷新（用 _refSetBatchItems）
    _batchItems = _batchItems.map((it) => {
      if (it.id !== itemId) return it
      return {
        ...it,
        currentStep: event.name as RegStepName,
        startedAt: it.startedAt ?? now,
        stepStartedAt: now,
        email: event.email || it.email,
        exitIp: event.exitIp || it.exitIp
      }
    })
    _refSetBatchItems?.([..._batchItems])
  })
}

/**
 * 模块级 log 订阅同理：切页面期间发生的日志也不会丢。
 * 行为对齐 addLog：加时间戳前缀。
 */
let _logListenerRegistered = false
function ensureLogListenerRegistered(): void {
  if (_logListenerRegistered) return
  _logListenerRegistered = true
  window.api.onRegistrationLog((msg) => {
    const next = [..._logs, `[${new Date().toLocaleTimeString()}] ${msg}`]
    if (next.length > 500) next.splice(0, next.length - 500)
    _logs = next
    _refSetLogs?.(next)
  })
}

// 模块级 React setter refs：异步代码跨组件生命周期调用最新 setter
let _refSetPhase: ((v: Phase) => void) | null = null
let _refSetResult: ((v: RegResult | null) => void) | null = null
let _refSetLogs: ((v: string[]) => void) | null = null
let _refSetBatchRunning: ((v: boolean) => void) | null = null
let _refSetBatchDone: ((v: number) => void) | null = null
let _refSetBatchSuccess: ((v: number) => void) | null = null
let _refSetBatchFail: ((v: number) => void) | null = null
let _refSetBatchItems: ((v: BatchItem[]) => void) | null = null
let _refSetHistory: ((v: HistoryItem[] | ((prev: HistoryItem[]) => HistoryItem[])) => void) | null = null

function loadHistory(): HistoryItem[] {
  try {
    const raw = localStorage.getItem(HISTORY_KEY)
    return raw ? JSON.parse(raw) : []
  } catch {
    return []
  }
}

function saveHistory(items: HistoryItem[]): void {
  try { localStorage.setItem(HISTORY_KEY, JSON.stringify(items.slice(0, 100))) } catch { /* ignore */ }
}

/** 订阅计划类型（对应 Kiro 后端 qSubscriptionType）*/
export type ProPlanType = 'Q_DEVELOPER_STANDALONE_PRO' | 'Q_DEVELOPER_STANDALONE_PRO_PLUS' | 'Q_DEVELOPER_STANDALONE_POWER'

interface RegisterConfig {
  mode: RegMode
  outlookData: string
  fullName: string
  batchCount: number
  batchInterval: number
  batchAutoImport: boolean
  batchRetries: number
  batchConcurrency: number
  autoFetchProLink: boolean
  proPlanType: ProPlanType
  tempMailEmail: string
  tempMailEpin: string
  tempMailDomain: string
  /** Proton 母邮箱（点号别名母号，如 evanbartellchae@protonmail.com）*/
  protonBaseEmail: string
  /** GPTmail (mail.chatgpt.org.uk) — 支持两种模式：私有域名直收（inbox 留空）或 CF 转发（填 inbox）；
   *   私有域名设了密码时填 privatePassword */
  gptMailBaseURL: string
  gptMailInboxEmail: string
  gptMailDomain: string
  gptMailPrefix: string
  gptMailPrivatePassword: string
  /** 手动模式 — 母邮箱（收验证码的真实邮箱）*/
  manualParentEmail: string
  /** 手动模式 — 启用匿名邮箱（点号变体）*/
  manualAnonymousEmail: boolean
  /** 混合模式 — 启用的邮箱源 */
  mixedEnabledSources?: AutoEmailSource[]
}

function loadConfig(): Partial<RegisterConfig> {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    return raw ? JSON.parse(raw) : {}
  } catch {
    return {}
  }
}

function saveConfig(cfg: RegisterConfig): void {
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(cfg)) } catch { /* ignore */ }
}

export function RegisterPage(): React.JSX.Element {
  const { t } = useTranslation()
  const isEn = t('common.unknown') === 'Unknown'
  const saved = useRef(loadConfig()).current

  const [mode, setMode] = useState<RegMode>(saved.mode || 'manual')
  const [phase, _setPhase] = useState<Phase>(_phase)
  const [logs, setLogs] = useState<string[]>(_logs)
  const [result, _setResult] = useState<RegResult | null>(_result)
  const [imported, setImported] = useState(false)

  const setPhase = useCallback((p: Phase) => { _phase = p; _refSetPhase?.(p) }, [])
  const setResult = useCallback((r: RegResult | null) => { _result = r; _refSetResult?.(r) }, [])

  // 手动模式
  const [email, setEmail] = useState('')
  const [fullName, setFullName] = useState(saved.fullName || '')
  const [otp, setOtp] = useState('')
  const [parentEmail, setParentEmail] = useState(saved.manualParentEmail || '')
  const [anonymousEmail, setAnonymousEmail] = useState(saved.manualAnonymousEmail ?? false)

  // Outlook 配置
  const [outlookData, setOutlookData] = useState(saved.outlookData || '')

  // TempMail.Plus 配置
  const [tempMailEmail, setTempMailEmail] = useState(saved.tempMailEmail || '')
  const [tempMailEpin, setTempMailEpin] = useState(saved.tempMailEpin || '')
  const [tempMailDomain, setTempMailDomain] = useState(saved.tempMailDomain || '')

  // Proton 配置（点号别名，webview 借壳官方网页取码，需先登录一次）
  const [protonBaseEmail, setProtonBaseEmail] = useState(saved.protonBaseEmail || '')
  // 初始值取模块级缓存：切到别的页面再回来仍保持登录态显示
  const [protonLoggedIn, _setProtonLoggedIn] = useState(_protonLoggedIn)
  const setProtonLoggedIn = useCallback((v: boolean): void => { _protonLoggedIn = v; _setProtonLoggedIn(v) }, [])
  const [protonChecking, setProtonChecking] = useState(false)

  // GPTmail (mail.chatgpt.org.uk) 配置 —— 同时支持两种模式：
  //   A. 私有域名直收：MX 解析到 GPTmail；inboxEmail 留空；私有域名设了密码就填 privatePassword
  //   B. CF Email Routing 转发：inboxEmail 填固定 GPTmail 邮箱
  const [gptMailBaseURL, setGptMailBaseURL] = useState(saved.gptMailBaseURL || '')
  const [gptMailInboxEmail, setGptMailInboxEmail] = useState(saved.gptMailInboxEmail || '')
  const [gptMailDomain, setGptMailDomain] = useState(saved.gptMailDomain || '')
  const [gptMailPrefix, setGptMailPrefix] = useState(saved.gptMailPrefix || '')
  const [gptMailPrivatePassword, setGptMailPrivatePassword] = useState(saved.gptMailPrivatePassword || '')

  const logContainerRef = useRef<HTMLDivElement>(null)
  const { addAccount, accounts } = useAccountsStore()

  /** 从代理池取下一个可用代理（如果启用），返回 proxy + upstreamProxy 供注册配置注入 */
  const getRegistrationProxy = useCallback((): { proxy: string; upstreamProxy: string; proxyId: string; label: string } | null => {
    const { pickNextProxy, proxyPoolConfig } = useAccountsStore.getState()
    const entry = pickNextProxy()
    if (!entry) return null
    const masked = entry.url.replace(/:([^:@/]+)@/, ':***@')
    return {
      proxy: entry.url,
      upstreamProxy: proxyPoolConfig.upstreamProxy || '',
      proxyId: entry.id,
      label: masked
    }
  }, [])

  const addLog = useCallback((msg: string) => {
    const next = [..._logs, `[${new Date().toLocaleTimeString()}] ${msg}`]
    _logs = next
    _refSetLogs?.(next)
  }, [])

  useEffect(() => {
    const el = logContainerRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [logs])

  // 注册一次性的 log / step IPC 监听器：模块级注册，永不取消，
  // 避免切到其它页面时丢失中间的事件（之前用 useEffect 在 unmount 时取消会丢事件）
  useEffect(() => {
    ensureLogListenerRegistered()
    ensureStepListenerRegistered()
  }, [])

  // 页面挂载时检测注册流程状态
  useEffect(() => {
    window.api.registrationStatus().then((res) => {
      if (res.inProgress && _phase === 'idle') {
        // 后端有流程但前端无状态（应用重启场景），取消残留
        window.api.registrationCancel()
      }
    })
  }, [])

  const reset = (): void => {
    _phase = 'idle'
    _logs = []
    _result = null
    setPhase('idle')
    setLogs([])
    setResult(null)
    setImported(false)
    setOtp('')
  }

  // ============ 手动模式 ============

  /** 收集本地已使用过的邮箱集合（帐号库存 + 注册历史 + 已知占用黑名单）*/
  const collectUsedEmails = useCallback((): Set<string> => {
    const used = new Set<string>()
    for (const acc of accounts.values()) {
      if (acc.email) used.add(acc.email.toLowerCase())
    }
    // 注册历史（包括未导入账号的历史记录）
    for (const item of loadHistory()) {
      if (item.email) used.add(item.email.toLowerCase())
    }
    // 已知占用邮箱黑名单
    for (const e of loadEmailBlacklist()) {
      used.add(e)
    }
    return used
  }, [accounts])

  // Proton 点号变体分配：会话级已分配集合，避免并发/连续注册生成重复变体
  const protonAllocatedRef = useRef<Set<string>>(new Set())
  /** 生成下一个未使用的 Proton 点号变体地址；母邮箱未填或变体用尽返回 null */
  const generateProtonEmail = useCallback((): string | null => {
    const base = protonBaseEmail.trim()
    if (!base || !splitEmail(base)) return null
    const used = new Set(collectUsedEmails())
    for (const e of protonAllocatedRef.current) used.add(e.toLowerCase())
    const result = generateNextDotVariant(base, used)
    if (result.variant) protonAllocatedRef.current.add(result.variant.toLowerCase())
    return result.variant
  }, [protonBaseEmail, collectUsedEmails])

  const startManual = async (): Promise<void> => {
    // 1. 预生成邮箱：开启匿名时从母邮箱生成点号变体；否则使用母邮箱本身（如果填了）
    let preEmail = ''
    if (anonymousEmail) {
      const parent = parentEmail.trim()
      if (!parent || !splitEmail(parent)) {
        addLog(t('register.logAnonymousNoParent'))
        return
      }
      const result = generateNextDotVariant(parent, collectUsedEmails())
      if (!result.variant) {
        addLog(t('register.logAnonymousExhausted'))
        return
      }
      preEmail = result.variant
      setEmail(preEmail)
      addLog(t('register.logAnonymousGenerated').replace('{email}', preEmail).replace('{dots}', String(result.dotCount)))
    } else if (parentEmail.trim()) {
      preEmail = parentEmail.trim()
      setEmail(preEmail)
    }

    setPhase('initializing')
    _logs = []; setLogs([])
    setResult(null)
    setImported(false)
    addLog(t('register.logManualInit'))

    const config: Record<string, string> = {}
    if (fullName.trim()) config.fullName = fullName.trim()

    // 代理池注入：如果代理池启用且有可用代理，自动取一个并传入 config
    const proxyInfo = getRegistrationProxy()
    if (proxyInfo) {
      config.proxy = injectProxySession(proxyInfo.proxy)
      config.upstreamProxy = proxyInfo.upstreamProxy
      addLog(`[Proxy] ${isEn ? 'Using proxy pool' : '使用代理池'}: ${config.proxy.replace(/:([^:@/]+)@/, ':***@')}`)
    }

    const res = await window.api.registrationManualPhase1(config)
    if (!res.success) {
      addLog(`${t('register.logInitFailed')} ${res.error}`)
      setPhase('idle')
      return
    }
    addLog(t('register.logInitDone'))
    setPhase('email')

    // 2. 如果预填了邮箱，自动提交 phase2跳过手动输入阶段
    if (preEmail) {
      setPhase('running')
      addLog(`${t('register.logSubmitEmail')} ${preEmail}`)
      const phase2Res = await window.api.registrationManualPhase2(preEmail, fullName.trim() || undefined)
      if (phase2Res.success) {
        addLog(t('register.logOtpSent'))
        setPhase('otp')
      } else {
        addLog(`${t('register.logFailed')} ${phase2Res.error}`)
        setPhase('idle')
      }
    }
  }

  const submitEmail = async (): Promise<void> => {
    if (!email.trim()) return
    setPhase('running')
    addLog(`${t('register.logSubmitEmail')} ${email}`)

    const res = await window.api.registrationManualPhase2(email.trim(), fullName.trim() || undefined)
    if (res.success) {
      addLog(t('register.logOtpSent'))
      setPhase('otp')
    } else {
      addLog(`${t('register.logFailed')} ${res.error}`)
      setPhase('idle')
    }
  }

  const submitOTP = async (): Promise<void> => {
    if (!otp.trim()) return
    setPhase('running')
    addLog(`${t('register.logSubmitOtp')} ${otp}`)

    const res = await window.api.registrationManualPhase3(otp.trim())
    if (res.success) {
      const regResult = res.result as RegResult
      setResult(regResult)
      setPhase('done')
      addHistory({ email: regResult.email, status: regResult.status, password: regResult.password, result: regResult })
      const isSuccess = regResult.status === 'success'
      const needImport = batchAutoImport && isSuccess
      const needProLink = autoFetchProLink && isSuccess

      if (needImport) {
        setPhase('importing')
        const ok = await autoImportResult(regResult)
        if (ok) {
          setImported(true)
          addLog(t('register.logImported'))
          setHistory((prev) => {
            const idx = prev.findIndex((h) => h.email === regResult.email && !h.imported)
            if (idx >= 0) { const u = [...prev]; u[idx] = { ...u[idx], imported: true }; return u }
            return prev
          })
        }
      }
      if (needProLink) {
        setPhase('fetching-link')
        await fetchProSubscriptionUrl(regResult, regResult.email)
      }
      // 后处理全部完成 → finalized；未启用任何后处理时保持 done（语义等价）
      if (needImport || needProLink) {
        setPhase('finalized')
      }
    } else {
      addLog(`${t('register.logFailed')} ${res.error}`)
      setPhase('idle')
    }
  }

  // ============ 自动模式 (MoEmail / Outlook) ============

  const startAuto = async (): Promise<void> => {
    setPhase('running')
    _logs = []; setLogs([])
    setResult(null)
    setImported(false)
    const modeLabel = mode === 'tempmail' ? 'TempMail.Plus' : mode === 'proton' ? 'Proton' : mode === 'gptmail' ? 'GPTmail' : 'Outlook'
    addLog(t('register.logAutoStart').replace('{mode}', modeLabel))

    const config: Record<string, unknown> = {}
    if (mode === 'outlook') {
      config.useOutlook = true
      config.outlookData = outlookData
    } else if (mode === 'tempmail') {
      config.useTempMailPlus = true
      config.tempMailPlusEmail = tempMailEmail
      config.tempMailPlusEpin = tempMailEpin
      config.tempMailPlusDomain = tempMailDomain
    } else if (mode === 'proton') {
      const variant = generateProtonEmail()
      if (!variant) {
        addLog(isEn ? '[Proton] Base email not set or all dot-variants used up' : '[Proton] 未配置母邮箱或点号变体已用尽')
        setPhase('idle')
        return
      }
      config.useProton = true
      config.protonEmail = variant
      addLog(`[Proton] ${isEn ? 'Using dot-variant' : '使用点号变体'}: ${variant}`)
    } else if (mode === 'gptmail') {
      if (!gptMailDomain.trim()) {
        addLog(isEn ? '[GPTmail] Domain not configured' : '[GPTmail] 未配置域名')
        setPhase('idle')
        return
      }
      config.useGptMail = true
      config.gptMailBaseURL = gptMailBaseURL.trim()
      config.gptMailInboxEmail = gptMailInboxEmail.trim()  // 留空 → 私有域名直收；填了 → CF 转发
      config.gptMailDomain = gptMailDomain
      config.gptMailPrefix = gptMailPrefix.trim()
      config.gptMailPrivatePassword = gptMailPrivatePassword  // 私有域名设了密码才填
    }

    // 代理池注入
    const proxyInfo = getRegistrationProxy()
    if (proxyInfo) {
      config.proxy = injectProxySession(proxyInfo.proxy)
      config.upstreamProxy = proxyInfo.upstreamProxy
      addLog(`[Proxy] ${isEn ? 'Using proxy pool' : '使用代理池'}: ${String(config.proxy).replace(/:([^:@/]+)@/, ':***@')}`)
    }

    const res = await window.api.registrationStartAuto(config as Parameters<typeof window.api.registrationStartAuto>[0])
    if (!res.success) {
      addLog(`${t('register.logStartFailed')} ${res.error}`)
      setPhase('idle')
    }
  }

  // ============ 取消 ============

  const cancel = async (): Promise<void> => {
    await window.api.registrationCancel()
    addLog(t('register.logCancelled'))
    setPhase('idle')
  }

  // ============ 导入账号 ============

  const importAccount = async (): Promise<void> => {
    if (!result || result.status !== 'success' || !result.refreshToken) return

    try {
      const verifyResult = await window.api.verifyAccountCredentials({
        refreshToken: result.refreshToken,
        clientId: result.clientId!,
        clientSecret: result.clientSecret!,
        region: result.region || 'us-east-1',
        authMethod: 'IdC',
        provider: 'BuilderId'
      })

      const now = Date.now()
      const defaultUsage = { current: 0, limit: 0, percentUsed: 0, lastUpdated: now }

      if (verifyResult.success && verifyResult.data) {
        const expiresAt = verifyResult.data.expiresIn
          ? now + verifyResult.data.expiresIn * 1000
          : now + 3600000
        const usage = verifyResult.data.usage
          ? {
              ...verifyResult.data.usage,
              percentUsed: verifyResult.data.usage.limit > 0
                ? Math.round((verifyResult.data.usage.current / verifyResult.data.usage.limit) * 100)
                : 0,
              lastUpdated: now
            }
          : defaultUsage

        addAccount({
          email: verifyResult.data.email || result.email,
          idp: 'BuilderId',
          status: 'active',
          credentials: {
            refreshToken: result.refreshToken,
            clientId: result.clientId!,
            clientSecret: result.clientSecret!,
            accessToken: verifyResult.data.accessToken || result.accessToken || '',
            csrfToken: '',
            region: result.region || 'us-east-1',
            authMethod: 'IdC' as const,
            provider: 'BuilderId' as const,
            expiresAt
          },
          subscription: {
            type: (verifyResult.data.subscriptionType as 'Free' | 'Pro' | 'Pro_Plus' | 'Enterprise' | 'Teams') || 'Free',
            title: verifyResult.data.subscriptionTitle || 'Free Tier'
          },
          usage,
          tags: [],
          lastUsedAt: now
        })
        setImported(true)
        addLog(t('register.logImported'))
      } else {
        addLog(`${t('register.logVerifyFailed')} ${verifyResult.error}`)
        addAccount({
          email: result.email,
          idp: 'BuilderId',
          status: 'active',
          credentials: {
            refreshToken: result.refreshToken,
            clientId: result.clientId!,
            clientSecret: result.clientSecret!,
            accessToken: result.accessToken || '',
            csrfToken: '',
            region: result.region || 'us-east-1',
            authMethod: 'IdC' as const,
            provider: 'BuilderId' as const,
            expiresAt: now + 3600000
          },
          subscription: { type: 'Free', title: 'Free Tier' },
          usage: defaultUsage,
          tags: [],
          lastUsedAt: now
        })
        setImported(true)
        addLog(t('register.logDirectImport'))
      }
    } catch (err) {
      addLog(`${t('register.logImportFailed')} ${err instanceof Error ? err.message : String(err)}`)
    }
  }

  // 'isRunning' 表示注册流程主线进行中（不含 idle/email/otp 等待用户输入态、也不含完成态）
  const isRunning = phase === 'initializing' || phase === 'running' || phase === 'importing' || phase === 'fetching-link'
  // manualSteps / currentStep 在下方"批量注册"区块的 state 定义之后计算

  // ============ 批量注册 ============

  const [batchCount, setBatchCount] = useState(saved.batchCount ?? 1)
  const [batchInterval, setBatchInterval] = useState(saved.batchInterval ?? 5)
  const [batchRunning, _setBatchRunning] = useState(_batchRunning)
  const [batchDone, _setBatchDone] = useState(_batchDone)
  const [batchSuccess, _setBatchSuccess] = useState(_batchSuccess)
  const [batchFail, _setBatchFail] = useState(_batchFail)
  const [batchAutoImport, setBatchAutoImport] = useState(saved.batchAutoImport ?? true)
  const [batchRetries, setBatchRetries] = useState(saved.batchRetries ?? 1)
  const [batchConcurrency, setBatchConcurrency] = useState(saved.batchConcurrency ?? 1)
  const [autoFetchProLink, setAutoFetchProLink] = useState(saved.autoFetchProLink ?? false)
  const [proPlanType, setProPlanType] = useState<ProPlanType>(saved.proPlanType ?? 'Q_DEVELOPER_STANDALONE_PRO')
  const [batchItems, _setBatchItems] = useState<BatchItem[]>(_batchItems)

  // taskId → batchItem.id 映射：直接引用模块级 Map，组件 unmount/remount 不影响
  const taskIdToItemId = useRef(_taskIdToItemId)

  /** 1Hz 心跳，让运行中任务的"总耗时"实时跳动（仅 batchRunning 时启用，省电） */
  const [batchClock, setBatchClock] = useState(Date.now())
  useEffect(() => {
    if (!batchRunning) return
    const id = setInterval(() => setBatchClock(Date.now()), 1000)
    return () => clearInterval(id)
  }, [batchRunning])

  // 动态构建注册步骤（根据是否启用自动导入 / Pro 链接）
  const manualSteps = useMemo(
    () => buildManualSteps(batchAutoImport, autoFetchProLink),
    [batchAutoImport, autoFetchProLink]
  )
  const lastLogText = logs.length > 0 ? logs[logs.length - 1] : undefined
  const currentStep = phaseToStep(phase, lastLogText, manualSteps)

  const setBatchRunning = (v: boolean) => { _batchRunning = v; _refSetBatchRunning?.(v) }
  const setBatchDone = (v: number | ((p: number) => number)) => {
    const next = typeof v === 'function' ? v(_batchDone) : v; _batchDone = next; _refSetBatchDone?.(next)
  }
  const setBatchSuccess = (v: number | ((p: number) => number)) => {
    const next = typeof v === 'function' ? v(_batchSuccess) : v; _batchSuccess = next; _refSetBatchSuccess?.(next)
  }
  const setBatchFail = (v: number | ((p: number) => number)) => {
    const next = typeof v === 'function' ? v(_batchFail) : v; _batchFail = next; _refSetBatchFail?.(next)
  }
  const setBatchItems = (v: BatchItem[] | ((p: BatchItem[]) => BatchItem[])) => {
    const next = typeof v === 'function' ? v(_batchItems) : v; _batchItems = next; _refSetBatchItems?.(next)
  }
  const batchAbort = useRef(false)
  // 暂停状态：仅暂停"启动新任务"，已并发执行的会跑完
  const batchPause = useRef(false)
  const [isPaused, setIsPaused] = useState(false)
  // 当前批量任务在任务中心的 ID（用于更新进度）
  const currentTaskCenterId = useRef<string | null>(null)

  // ============ 注册策略模板 ============
  const [templates, setTemplates] = useState<RegisterTemplate[]>(loadTemplates)
  const [showTemplatesMenu, setShowTemplatesMenu] = useState(false)

  const collectCurrentConfig = useCallback((): RegisterConfig => {
    // mixedEnabledSources 在本组件内声明在更下方，避免 hoisting 限制：从 localStorage 读取最新值
    let mixed: AutoEmailSource[] = ['outlook', 'tempmail']
    try {
      const raw = localStorage.getItem('kiro-register-mixed-sources')
      if (raw) {
        const arr = JSON.parse(raw) as string[]
        mixed = arr.filter((x): x is AutoEmailSource => x === 'outlook' || x === 'tempmail' || x === 'proton' || x === 'gptmail')
        if (mixed.length === 0) mixed = ['outlook', 'tempmail']
      }
    } catch { /* ignore */ }
    return {
      mode,
      outlookData,
      fullName,
      batchCount,
      batchInterval,
      batchAutoImport,
      batchRetries,
      batchConcurrency,
      autoFetchProLink,
      proPlanType,
      tempMailEmail,
      tempMailEpin,
      tempMailDomain,
      protonBaseEmail,
      gptMailBaseURL,
      gptMailInboxEmail,
      gptMailDomain,
      gptMailPrefix,
      gptMailPrivatePassword,
      manualParentEmail: parentEmail,
      manualAnonymousEmail: anonymousEmail,
      mixedEnabledSources: mixed
    }
  }, [mode, outlookData, fullName, batchCount, batchInterval, batchAutoImport, batchRetries, batchConcurrency, autoFetchProLink, proPlanType, tempMailEmail, tempMailEpin, tempMailDomain, protonBaseEmail, gptMailBaseURL, gptMailInboxEmail, gptMailDomain, gptMailPrefix, gptMailPrivatePassword, parentEmail, anonymousEmail])

  const applyTemplate = useCallback((tpl: RegisterTemplate) => {
    const c = tpl.config
    // 兼容老模板：mode === 'moemail' 时回退到 outlook
    setMode((c.mode === ('moemail' as RegMode) ? 'outlook' : c.mode) as RegMode)
    setOutlookData(c.outlookData || '')
    setFullName(c.fullName || '')
    setBatchCount(c.batchCount ?? 1)
    setBatchInterval(c.batchInterval ?? 5)
    setBatchAutoImport(c.batchAutoImport ?? true)
    setBatchRetries(c.batchRetries ?? 1)
    setBatchConcurrency(c.batchConcurrency ?? 1)
    setAutoFetchProLink(c.autoFetchProLink ?? false)
    setProPlanType(c.proPlanType ?? 'Q_DEVELOPER_STANDALONE_PRO')
    setTempMailEmail(c.tempMailEmail || '')
    setTempMailEpin(c.tempMailEpin || '')
    setTempMailDomain(c.tempMailDomain || '')
    setProtonBaseEmail(c.protonBaseEmail || '')
    setGptMailBaseURL(c.gptMailBaseURL || '')
    setGptMailInboxEmail(c.gptMailInboxEmail || '')
    setGptMailDomain(c.gptMailDomain || '')
    setGptMailPrefix(c.gptMailPrefix || '')
    setGptMailPrivatePassword(c.gptMailPrivatePassword || '')
    setParentEmail(c.manualParentEmail || '')
    setAnonymousEmail(c.manualAnonymousEmail ?? false)
    if (c.mixedEnabledSources) setMixedEnabledSources(c.mixedEnabledSources)
    addLog(`[Template] 已应用模板：${tpl.name}`)
    setShowTemplatesMenu(false)
  }, [addLog])

  const saveCurrentAsTemplate = useCallback(() => {
    const name = prompt('为当前配置保存为模板，请输入模板名称：')?.trim()
    if (!name) return
    const tpl: RegisterTemplate = {
      id: crypto.randomUUID(),
      name,
      config: collectCurrentConfig(),
      createdAt: Date.now()
    }
    const next = [tpl, ...templates]
    setTemplates(next)
    saveTemplates(next)
    addLog(`[Template] 已保存模板：${name}`)
  }, [collectCurrentConfig, templates, addLog])

  const removeTemplate = useCallback((id: string) => {
    if (!confirm('确定删除这个模板？')) return
    const next = templates.filter((t) => t.id !== id)
    setTemplates(next)
    saveTemplates(next)
  }, [templates])

  // ============ 定时任务 + 每日配额 ============
  // 每日已注册成功数（按本地日期聚合，跨日自动重置）
  const dailyQuotaKey = useMemo(() => {
    const d = new Date()
    return `kiro-register-quota-${d.getFullYear()}-${d.getMonth() + 1}-${d.getDate()}`
  }, [])
  const [dailyQuotaUsed, setDailyQuotaUsedState] = useState<number>(() => {
    try { return parseInt(localStorage.getItem(dailyQuotaKey) || '0', 10) || 0 } catch { return 0 }
  })
  const incrementDailyQuota = useCallback((n: number) => {
    setDailyQuotaUsedState((prev) => {
      const next = prev + n
      try { localStorage.setItem(dailyQuotaKey, String(next)) } catch { /* ignore */ }
      return next
    })
  }, [dailyQuotaKey])

  const [dailyQuotaLimit, setDailyQuotaLimit] = useState<number>(() => {
    try { return parseInt(localStorage.getItem('kiro-register-dailyquota-limit') || '0', 10) || 0 } catch { return 0 }
  })
  const [scheduleEnabled, setScheduleEnabled] = useState<boolean>(() => {
    try { return localStorage.getItem('kiro-register-schedule-enabled') === '1' } catch { return false }
  })
  const [scheduleTime, setScheduleTime] = useState<string>(() => {
    try { return localStorage.getItem('kiro-register-schedule-time') || '03:00' } catch { return '03:00' }
  })
  /** C6: 星期掩码（位 0=周日 ... 位 6=周六），默认每天（127） */
  const [scheduleWeekMask, setScheduleWeekMask] = useState<number>(() => {
    try { return parseInt(localStorage.getItem('kiro-register-schedule-week-mask') || '127', 10) } catch { return 127 }
  })

  useEffect(() => { try { localStorage.setItem('kiro-register-dailyquota-limit', String(dailyQuotaLimit)) } catch { /* ignore */ } }, [dailyQuotaLimit])
  useEffect(() => { try { localStorage.setItem('kiro-register-schedule-enabled', scheduleEnabled ? '1' : '0') } catch { /* ignore */ } }, [scheduleEnabled])
  useEffect(() => { try { localStorage.setItem('kiro-register-schedule-time', scheduleTime) } catch { /* ignore */ } }, [scheduleTime])
  useEffect(() => { try { localStorage.setItem('kiro-register-schedule-week-mask', String(scheduleWeekMask)) } catch { /* ignore */ } }, [scheduleWeekMask])

  // 定时任务：每分钟检查一次是否到点（含星期过滤）
  const scheduleTriggered = useRef<string>('')  // 标记今日是否已触发，防止重复
  useEffect(() => {
    if (!scheduleEnabled) return
    const tick = (): void => {
      if (batchRunning) return
      const now = new Date()
      const todayKey = `${now.getFullYear()}-${now.getMonth() + 1}-${now.getDate()}`
      if (scheduleTriggered.current === todayKey) return
      // C6: 星期掩码过滤（位 0=周日 ... 位 6=周六）
      const dow = now.getDay()
      if (!(scheduleWeekMask & (1 << dow))) return
      const [hh, mm] = scheduleTime.split(':').map((s) => parseInt(s, 10))
      if (now.getHours() === hh && now.getMinutes() === mm) {
        scheduleTriggered.current = todayKey
        addLog(`[Schedule] 到达定时启动时间 ${scheduleTime}，自动开始批量注册`)
        void startBatch()
      }
    }
    const timer = setInterval(tick, 60_000)
    tick()
    return () => clearInterval(timer)
    // 故意忽略 startBatch 依赖（它依赖太多 state，引用每次都变化；scheduleTriggered 防止重入）
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scheduleEnabled, scheduleTime, scheduleWeekMask, batchRunning])

  // ============ 限速 + 风控 ============
  // 持久化用户的限速配置
  const [rateLimitEnabled, setRateLimitEnabled] = useState<boolean>(() => {
    try { const v = localStorage.getItem('kiro-register-ratelimit-enabled'); return v === null ? true : v === '1' } catch { return true }
  })
  const [maxPerMinute, setMaxPerMinute] = useState<number>(() => {
    try { return parseInt(localStorage.getItem('kiro-register-ratelimit-max') || '10', 10) || 10 } catch { return 10 }
  })
  const [burstSize, setBurstSize] = useState<number>(() => {
    try { return parseInt(localStorage.getItem('kiro-register-ratelimit-burst') || '3', 10) || 3 } catch { return 3 }
  })
  const [backoffBaseSec, setBackoffBaseSec] = useState<number>(() => {
    try { return parseInt(localStorage.getItem('kiro-register-backoff-base-sec') || '8', 10) || 8 } catch { return 8 }
  })
  const [backoffMaxSec, setBackoffMaxSec] = useState<number>(() => {
    try { return parseInt(localStorage.getItem('kiro-register-backoff-max-sec') || '120', 10) || 120 } catch { return 120 }
  })
  const [autoBackoff, setAutoBackoff] = useState<boolean>(() => {
    try { return localStorage.getItem('kiro-register-autobackoff') !== '0' } catch { return true }
  })
  // 风控触发后自动暂停（B3）
  const [autoPauseOnRisk, setAutoPauseOnRisk] = useState<boolean>(() => {
    try { return localStorage.getItem('kiro-register-autopause-risk') === '1' } catch { return false }
  })
  useEffect(() => { try { localStorage.setItem('kiro-register-ratelimit-enabled', rateLimitEnabled ? '1' : '0') } catch { /* ignore */ } }, [rateLimitEnabled])
  useEffect(() => { try { localStorage.setItem('kiro-register-ratelimit-max', String(maxPerMinute)) } catch { /* ignore */ } }, [maxPerMinute])
  useEffect(() => { try { localStorage.setItem('kiro-register-ratelimit-burst', String(burstSize)) } catch { /* ignore */ } }, [burstSize])
  useEffect(() => { try { localStorage.setItem('kiro-register-backoff-base-sec', String(backoffBaseSec)) } catch { /* ignore */ } }, [backoffBaseSec])
  useEffect(() => { try { localStorage.setItem('kiro-register-backoff-max-sec', String(backoffMaxSec)) } catch { /* ignore */ } }, [backoffMaxSec])
  useEffect(() => { try { localStorage.setItem('kiro-register-autobackoff', autoBackoff ? '1' : '0') } catch { /* ignore */ } }, [autoBackoff])
  useEffect(() => { try { localStorage.setItem('kiro-register-autopause-risk', autoPauseOnRisk ? '1' : '0') } catch { /* ignore */ } }, [autoPauseOnRisk])

  // 限速器实例（单例 ref）
  const rateLimiterRef = useRef<RateLimiter | null>(null)
  // 限速器快照（每秒刷新一次到 React state）
  const [rateSnapshot, setRateSnapshot] = useState<RateLimiterSnapshot | null>(null)
  // 跟踪上次风控状态，避免持续触发 webhook
  const lastRiskWarningRef = useRef(false)
  useEffect(() => {
    if (!batchRunning) {
      setRateSnapshot(null)
      lastRiskWarningRef.current = false
      return
    }
    const timer = setInterval(() => {
      if (rateLimiterRef.current) {
        const snap = rateLimiterRef.current.snapshot()
        setRateSnapshot(snap)
        // 风控信号上升沿：从未警告 → 警告，触发 webhook + 可能自动暂停
        if (snap.riskWarning && !lastRiskWarningRef.current) {
          lastRiskWarningRef.current = true
          // 自动暂停
          if (autoPauseOnRisk && !batchPause.current) {
            batchPause.current = true
            setIsPaused(true)
            if (currentTaskCenterId.current) {
              useTaskStore.getState().updateTask(currentTaskCenterId.current, { status: 'paused' })
            }
            addLog(`[RiskControl] 风控触发，自动暂停（成功率 ${Math.round(snap.successRate * 100)}%）`)
          }
          void useWebhookStore.getState().triggerEvent('risk-warning', {
            title: '风控信号触发',
            message: `批量注册成功率降至 ${Math.round(snap.successRate * 100)}%${autoPauseOnRisk ? '，已自动暂停' : '，建议暂停检查'}`,
            level: 'warn',
            fields: {
              成功率: `${Math.round(snap.successRate * 100)}%`,
              连续失败: snap.consecutiveFailures,
              吞吐: `${snap.throughputPerMinute}/min`,
              动作: autoPauseOnRisk ? '已自动暂停' : '请手动检查'
            }
          })
        } else if (!snap.riskWarning && lastRiskWarningRef.current) {
          // 风控恢复
          lastRiskWarningRef.current = false
        }
      }
    }, 1000)
    return () => clearInterval(timer)
  }, [batchRunning])

  // 自动保存配置到 localStorage
  useEffect(() => {
    saveConfig({ mode, outlookData, fullName, batchCount, batchInterval, batchAutoImport, batchRetries, batchConcurrency, autoFetchProLink, proPlanType, tempMailEmail, tempMailEpin, tempMailDomain, protonBaseEmail, gptMailBaseURL, gptMailInboxEmail, gptMailDomain, gptMailPrefix, gptMailPrivatePassword, manualParentEmail: parentEmail, manualAnonymousEmail: anonymousEmail })
  }, [mode, outlookData, fullName, batchCount, batchInterval, batchAutoImport, batchRetries, batchConcurrency, autoFetchProLink, proPlanType, tempMailEmail, tempMailEpin, tempMailDomain, protonBaseEmail, gptMailBaseURL, gptMailInboxEmail, gptMailDomain, gptMailPrefix, gptMailPrivatePassword, parentEmail, anonymousEmail])

  // 匿名邮箱预览计算 — 以 anonymousEmail/parentEmail/accounts 为依赖实时冷算下一个变体
  const anonymousPreview = useMemo(() => {
    if (!anonymousEmail) return null
    const parent = parentEmail.trim()
    if (!parent) return { error: 'empty' as const }
    const split = splitEmail(parent)
    if (!split) return { error: 'invalid' as const }
    const used = new Set<string>()
    for (const acc of accounts.values()) {
      if (acc.email) used.add(acc.email.toLowerCase())
    }
    for (const item of loadHistory()) {
      if (item.email) used.add(item.email.toLowerCase())
    }
    const result = generateNextDotVariant(parent, used)
    const sameRootCount = countSameRootVariants(parent, used)
    const localLen = split[0].replace(/\./g, '').length
    // 上限估算到 5 个点，足以应付绝大多数场景（避免大二项式造成 UI 误导）
    const totalCapacity = totalVariantCount(localLen, 5)
    return { ...result, sameRootCount, totalCapacity, localLen, error: null as null | 'empty' | 'invalid' }
  }, [anonymousEmail, parentEmail, accounts])

  // ============ 注册历史 ============

  const [history, _setHistory] = useState<HistoryItem[]>(loadHistory)

  const setHistory = useCallback((updater: HistoryItem[] | ((prev: HistoryItem[]) => HistoryItem[])) => {
    _refSetHistory?.((prev) => {
      const next = typeof updater === 'function' ? updater(prev) : updater
      saveHistory(next)
      return next
    })
  }, [])

  const addHistory = useCallback((item: Omit<HistoryItem, 'id' | 'time' | 'imported'>) => {
    setHistory((prev) => [{
      ...item,
      id: crypto.randomUUID(),
      time: Date.now(),
      imported: false
    }, ...prev])
  }, [setHistory])

  // 注册模块级 setter refs，确保异步代码跨组件生命周期调用最新 setter
  useEffect(() => {
    _refSetPhase = _setPhase
    _refSetResult = _setResult
    _refSetLogs = setLogs
    _refSetBatchRunning = _setBatchRunning
    _refSetBatchDone = _setBatchDone
    _refSetBatchSuccess = _setBatchSuccess
    _refSetBatchFail = _setBatchFail
    _refSetBatchItems = _setBatchItems
    _refSetHistory = _setHistory
    // 组件重新挂载时同步模块级状态到 React state
    _setPhase(_phase)
    _setResult(_result)
    setLogs([..._logs])
    _setBatchRunning(_batchRunning)
    _setBatchDone(_batchDone)
    _setBatchSuccess(_batchSuccess)
    _setBatchFail(_batchFail)
    _setBatchItems([..._batchItems])
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  // 自动导入单个成功结果
  const autoImportResult = useCallback(async (regResult: RegResult): Promise<boolean> => {
    if (!regResult.refreshToken || !regResult.clientId || !regResult.clientSecret) return false
    const now = Date.now()
    const defaultUsage = { current: 0, limit: 0, percentUsed: 0, lastUpdated: now }

    // 快速路径：后端 verifyAlive 已返回完整信息（verify.alive=true），直接用它导入
    // 避免重新调 verifyAccountCredentials 花 30-60 秒（网络请求冗余）
    const v = regResult.verify as Record<string, unknown> | undefined
    if (v && v.alive) {
      const sub = String(v.subscription || 'KIRO FREE')
      const creditUsed = Number(v.credit_used) || 0
      const creditLimit = Number(v.credit_limit) || 0
      const subType = sub.includes('PRO_PLUS') ? 'Pro_Plus' as const
        : sub.includes('PRO') ? 'Pro' as const
        : sub.includes('POWER') ? 'Pro_Plus' as const
        : 'Free' as const
      addAccount({
        email: String(v.email || regResult.email),
        password: regResult.password,
        idp: 'BuilderId',
        status: 'active',
        credentials: {
          refreshToken: regResult.refreshToken,
          clientId: regResult.clientId,
          clientSecret: regResult.clientSecret,
          accessToken: regResult.accessToken || '',
          csrfToken: '',
          region: regResult.region || 'us-east-1',
          authMethod: 'IdC' as const,
          provider: 'BuilderId' as const,
          expiresAt: now + 3600000
        },
        subscription: { type: subType, title: sub },
        usage: creditLimit > 0
          ? { current: creditUsed, limit: creditLimit, percentUsed: Math.round((creditUsed / creditLimit) * 100), lastUpdated: now }
          : defaultUsage,
        tags: [],
        lastUsedAt: now
      })
      return true
    }

    // 降级路径：后端 verify 信息缺失时走网络验证（兜底）
    try {
      const verifyResult = await window.api.verifyAccountCredentials({
        refreshToken: regResult.refreshToken,
        clientId: regResult.clientId,
        clientSecret: regResult.clientSecret,
        region: regResult.region || 'us-east-1',
        authMethod: 'IdC',
        provider: 'BuilderId'
      })

      if (verifyResult.success && verifyResult.data) {
        const expiresAt = verifyResult.data.expiresIn ? now + verifyResult.data.expiresIn * 1000 : now + 3600000
        const usage = verifyResult.data.usage
          ? { ...verifyResult.data.usage, percentUsed: verifyResult.data.usage.limit > 0 ? Math.round((verifyResult.data.usage.current / verifyResult.data.usage.limit) * 100) : 0, lastUpdated: now }
          : defaultUsage
        addAccount({
          email: verifyResult.data.email || regResult.email, password: regResult.password, idp: 'BuilderId', status: 'active',
          credentials: { refreshToken: regResult.refreshToken, clientId: regResult.clientId, clientSecret: regResult.clientSecret, accessToken: verifyResult.data.accessToken || regResult.accessToken || '', csrfToken: '', region: regResult.region || 'us-east-1', authMethod: 'IdC' as const, provider: 'BuilderId' as const, expiresAt },
          subscription: { type: (verifyResult.data.subscriptionType as 'Free' | 'Pro' | 'Pro_Plus' | 'Enterprise' | 'Teams') || 'Free', title: verifyResult.data.subscriptionTitle || 'Free Tier' },
          usage, tags: [], lastUsedAt: now
        })
      } else {
        addAccount({
          email: regResult.email, password: regResult.password, idp: 'BuilderId', status: 'active',
          credentials: { refreshToken: regResult.refreshToken, clientId: regResult.clientId, clientSecret: regResult.clientSecret, accessToken: regResult.accessToken || '', csrfToken: '', region: regResult.region || 'us-east-1', authMethod: 'IdC' as const, provider: 'BuilderId' as const, expiresAt: now + 3600000 },
          subscription: { type: 'Free', title: 'Free Tier' }, usage: defaultUsage, tags: [], lastUsedAt: now
        })
      }
      return true
    } catch {
      return false
    }
  }, [addAccount])

  // 获取 Pro 订阅链接并写入订阅页面链接列表
  const fetchProSubscriptionUrl = useCallback(async (regResult: RegResult, email: string): Promise<string | undefined> => {
    const accessToken = regResult.accessToken
    if (!accessToken) return undefined
    const linkId = crypto.randomUUID()
    appendSubscriptionLink({ accountId: linkId, email, status: 'loading' })
    try {
      addLog(`[Pro Link] ${email}: ${t('register.fetchingProLink')} (${proPlanType.replace('Q_DEVELOPER_STANDALONE_', '')})...`)
      const result = await window.api.accountGetSubscriptionUrl(
        accessToken,
        proPlanType,
        regResult.region || 'us-east-1',
        undefined,
        undefined,
        'BuilderId',
        'IdC',
        undefined
      )
      if (result.success && result.url) {
        addLog(`[Pro Link] ${email}: ${result.url}`)
        updateSubscriptionLink(linkId, { status: 'success', url: result.url })
        return result.url
      }
      const errMsg = result.error || 'Failed to get link'
      addLog(`[Pro Link] ${email}: ${errMsg}`)
      updateSubscriptionLink(linkId, { status: 'error', error: errMsg })
      return undefined
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : String(err)
      addLog(`[Pro Link] ${email}: ${errMsg}`)
      updateSubscriptionLink(linkId, { status: 'error', error: errMsg })
      return undefined
    }
  }, [addLog, t])

  // 监听注册完成 - 同时记录到历史 + 自动导入
  const onRegComplete = useCallback(async (res: RegResult) => {
    setResult(res)
    setPhase('done')
    if (res.status === 'success') {
      addLog(`${t('register.logRegSuccess')} ${res.email}`)
      addHistory({ email: res.email, status: 'success', password: res.password, result: res })
      // 触发 Webhook
      void useWebhookStore.getState().triggerEvent('register-success', {
        title: '账号注册成功',
        message: `新账号 ${res.email} 注册完成`,
        level: 'success',
        fields: { 邮箱: res.email, 模式: mode }
      })
      // 与手动模式 submitOTP 状态机保持一致：后处理期间推进 phase，
      // 避免后处理仍在跑时 phase 提前变 'done' 导致"新注册"按钮提前出现 + reset 竞态
      const needImport = batchAutoImport
      const needProLink = autoFetchProLink
      if (needImport) {
        setPhase('importing')
        const ok = await autoImportResult(res)
        if (ok) {
          setImported(true)
          addLog(t('register.logImported'))
          setHistory((prev) => {
            const idx = prev.findIndex((h) => h.email === res.email && !h.imported)
            if (idx >= 0) { const u = [...prev]; u[idx] = { ...u[idx], imported: true }; return u }
            return prev
          })
        }
      }
      if (needProLink) {
        setPhase('fetching-link')
        await fetchProSubscriptionUrl(res, res.email)
      }
      // 后处理全部完成 → finalized；未启用任何后处理时保持 done（语义等价）
      if (needImport || needProLink) {
        setPhase('finalized')
      }
    } else {
      addLog(`${t('register.logRegFailed')} ${res.error}`)
      addHistory({ email: res.email, status: res.status, error: res.error, password: res.password, result: res })
      // 单次模式失败补偿：邮箱已占用时加入黑名单（与批量 runSingleWithRetry 逻辑对齐），
      // 下次 generateProtonEmail / 匿名变体经 collectUsedEmails 自动跳过
      if (res.email && classifyError(res.error) === 'email_used') {
        const set = loadEmailBlacklist()
        set.add(res.email.toLowerCase())
        saveEmailBlacklist(set)
        addLog(`[Precheck] 邮箱 ${res.email} 已加入占用黑名单`)
      }
      // 触发 Webhook
      void useWebhookStore.getState().triggerEvent('register-failed', {
        title: '账号注册失败',
        message: `${res.email || '(未知邮箱)'} 注册失败`,
        level: 'error',
        fields: { 邮箱: res.email || '-', 错误: res.error || '-', 模式: mode }
      })
    }
  }, [addLog, addHistory, t, batchAutoImport, autoImportResult, autoFetchProLink, fetchProSubscriptionUrl, mode])

  // 覆盖原有的 onRegistrationComplete 监听
  useEffect(() => {
    const unsub = window.api.onRegistrationComplete(onRegComplete)
    return () => unsub()
  }, [onRegComplete])

  // 混合模式：启用的子源 + 权重 + 累积调度状态
  const [mixedEnabledSources, setMixedEnabledSources] = useState<AutoEmailSource[]>(() => {
    try {
      const raw = localStorage.getItem('kiro-register-mixed-sources')
      if (raw) {
        // 兼容老数据：过滤掉已废弃的 moemail
        const arr = JSON.parse(raw) as string[]
        const valid = arr.filter((x): x is AutoEmailSource => x === 'outlook' || x === 'tempmail' || x === 'proton' || x === 'gptmail')
        return valid.length > 0 ? valid : ['outlook', 'tempmail']
      }
    } catch { /* ignore */ }
    return ['outlook', 'tempmail']
  })
  /** 每个源的权重（默认 1） — 加权轮询 */
  const [mixedWeights, setMixedWeights] = useState<Record<AutoEmailSource, number>>(() => {
    try {
      const raw = localStorage.getItem('kiro-register-mixed-weights')
      if (raw) {
        const parsed = JSON.parse(raw) as Record<string, number>
        return { outlook: parsed.outlook ?? 1, tempmail: parsed.tempmail ?? 1, proton: parsed.proton ?? 1, gptmail: parsed.gptmail ?? 1 }
      }
    } catch { /* ignore */ }
    return { outlook: 1, tempmail: 1, proton: 1, gptmail: 1 }
  })
  useEffect(() => {
    try { localStorage.setItem('kiro-register-mixed-sources', JSON.stringify(mixedEnabledSources)) } catch { /* ignore */ }
  }, [mixedEnabledSources])
  useEffect(() => {
    try { localStorage.setItem('kiro-register-mixed-weights', JSON.stringify(mixedWeights)) } catch { /* ignore */ }
  }, [mixedWeights])

  // 加权轮询调度：维护各源的"信用"分数，每次选信用最高的，扣除后累积
  // 这是 Smooth Weighted Round-Robin 算法（nginx 用的同款）
  const mixedCredits = useRef<Record<AutoEmailSource, number>>({ outlook: 0, tempmail: 0, proton: 0, gptmail: 0 })

  /** 在混合模式下按加权轮询挑选下一个有效子源 */
  const pickNextSource = useCallback((): AutoEmailSource | null => {
    const candidates = mixedEnabledSources.filter((src) => {
      // 子源必须填了对应的配置
      if (src === 'outlook') return !!outlookData.trim()
      if (src === 'tempmail') return !!(tempMailDomain.trim() && tempMailEmail.trim() && tempMailEpin.trim())
      if (src === 'proton') return !!protonBaseEmail.trim()
      // GPTmail：只要有域名就 OK（inboxEmail 留空 = 私有直收模式）
      if (src === 'gptmail') return !!gptMailDomain.trim()
      return false
    })
    if (candidates.length === 0) return null
    if (candidates.length === 1) return candidates[0]

    // SWRR：每次给所有候选 credit += weight，挑选 credit 最高的，然后该项 credit -= totalWeight
    let totalWeight = 0
    for (const c of candidates) totalWeight += Math.max(0, mixedWeights[c] || 0)
    if (totalWeight === 0) totalWeight = candidates.length // 兜底：全 0 权重时退化为简单轮询

    let best: AutoEmailSource | null = null
    let bestCredit = -Infinity
    for (const c of candidates) {
      const w = Math.max(0, mixedWeights[c] || 0) || 1
      mixedCredits.current[c] = (mixedCredits.current[c] || 0) + w
      if (mixedCredits.current[c] > bestCredit) {
        best = c
        bestCredit = mixedCredits.current[c]
      }
    }
    if (best) {
      mixedCredits.current[best] -= totalWeight
    }
    return best
  }, [mixedEnabledSources, mixedWeights, outlookData, tempMailDomain, tempMailEmail, tempMailEpin, protonBaseEmail, gptMailDomain, gptMailInboxEmail])

  // 构建自动模式配置
  const buildAutoConfig = useCallback((): Parameters<typeof window.api.registrationStartAuto>[0] => {
    const config: Record<string, unknown> = {}

    // 混合模式：每次调用挑一个子源
    const effectiveMode: AutoEmailSource | null = mode === 'mixed'
      ? pickNextSource()
      : (mode === 'manual' ? null : (mode as AutoEmailSource))

    if (effectiveMode === 'tempmail') {
      config.useTempMailPlus = true
      config.tempMailPlusEmail = tempMailEmail
      config.tempMailPlusEpin = tempMailEpin
      config.tempMailPlusDomain = tempMailDomain
    } else if (effectiveMode === 'outlook') {
      config.useOutlook = true
      config.outlookData = outlookData
    } else if (effectiveMode === 'proton') {
      config.useProton = true
      const variant = generateProtonEmail()
      if (variant) config.protonEmail = variant
    } else if (effectiveMode === 'gptmail') {
      config.useGptMail = true
      config.gptMailBaseURL = gptMailBaseURL.trim()
      config.gptMailInboxEmail = gptMailInboxEmail.trim()
      config.gptMailDomain = gptMailDomain
      config.gptMailPrefix = gptMailPrefix.trim()
      config.gptMailPrivatePassword = gptMailPrivatePassword
    }
    return config as Parameters<typeof window.api.registrationStartAuto>[0]
  }, [mode, pickNextSource, outlookData, tempMailEmail, tempMailEpin, tempMailDomain, generateProtonEmail, gptMailBaseURL, gptMailInboxEmail, gptMailDomain, gptMailPrefix, gptMailPrivatePassword])

  // 代理池：注册时为每个任务自动挑选一个出口代理（启用后生效）
  const { proxyPool, proxyPoolConfig, pickNextProxy, reportProxyResult } = useAccountsStore()

  /**
   * Outlook 单行池：批量启动时 shuffle 一次，每个 task 独占一行避免并发抢占。
   * 之前的 bug：所有 task 共享同一份 outlookData，主进程用 Math.random() 挑选 → 并发任务可能撞同一个邮箱。
   */
  const outlookPoolRef = useRef<string[]>([])

  // 执行单次注册（含重试）— 每次都重新 buildAutoConfig，让 mixed 模式权重正确生效
  const runSingleWithRetry = useCallback(async (
    itemId: string,
    taskId: string,
    maxRetries: number
  ): Promise<{ success: boolean; result?: RegResult }> => {
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      // 暂停时阻塞等待恢复；停止时立即退出 —— 让暂停/停止对"重试"也即时生效
      while (batchPause.current && !batchAbort.current) {
        await new Promise((r) => setTimeout(r, 300))
      }
      if (batchAbort.current) return { success: false }

      if (attempt > 0) {
        setBatchItems((prev) => prev.map((it) =>
          it.id === itemId ? { ...it, status: 'retrying' as BatchItemStatus, retryCount: attempt } : it
        ))
        addLog(t('register.batchRetrying').replace('{current}', String(attempt)).replace('{max}', String(maxRetries)))
        // 可中断的重试等待（每 100ms 检查一次 abort，最多 3s）
        for (let w = 0; w < 30 && !batchAbort.current; w++) {
          await new Promise((r) => setTimeout(r, 100))
        }
        if (batchAbort.current) return { success: false }
      } else {
        setBatchItems((prev) => prev.map((it) =>
          it.id === itemId ? { ...it, status: 'running' as BatchItemStatus } : it
        ))
      }

      // 每次都重新 build：混合模式下每个 task / 每次重试都独立挑源（权重正确生效）
      const config = buildAutoConfig()
      const enrichedConfig: Record<string, unknown> = { ...config, taskId }

      // Outlook 模式：从 shuffle 后的池里取单行（不同 task 不会抢同一个邮箱）
      // 池空时回退到完整列表（主进程 random pick，兼容兜底）
      if (config.useOutlook && outlookPoolRef.current.length > 0) {
        const line = outlookPoolRef.current.shift()
        if (line) {
          enrichedConfig.outlookData = line
          addLog(`[Outlook] 分配邮箱: ${line.split('----')[0]}`)
        }
      }

      // 从代理池挑一个代理（仅在启用时）；每次重试也重新挑，让失效代理自动回避
      let pickedProxy: ReturnType<typeof pickNextProxy> = null
      if (proxyPoolConfig.enabled) {
        // 严格代理模式：代理池启用就绝不允许裸奔直连（暴露本机真实 IP 给 AWS 是大忌）
        if (proxyPool.size === 0) {
          addLog('[Proxy] 代理池已启用但池中无任何代理，已中止注册（请先在「代理池」页面添加代理）')
          return { success: false, result: { status: 'failed', email: '', error: '代理池已启用但池为空' } as RegResult }
        }
        pickedProxy = pickNextProxy()
        if (!pickedProxy) {
          addLog('[Proxy] 代理池已启用但当前无可用代理（全部 dead/disabled），已中止注册以防裸奔直连')
          return { success: false, result: { status: 'failed', email: '', error: '代理池无可用代理' } as RegResult }
        }
        const proxyUrl = injectProxySession(pickedProxy.url)
        enrichedConfig.proxy = proxyUrl
        enrichedConfig.strictProxy = true
        if (proxyPoolConfig.upstreamProxy && proxyPoolConfig.upstreamProxy.trim()) {
          enrichedConfig.upstreamProxy = proxyPoolConfig.upstreamProxy.trim()
        }
        const sessionTag = proxyUrl !== pickedProxy.url ? ' (session 已注入)' : ''
        addLog(`[Proxy] Using ${pickedProxy.protocol}://${pickedProxy.host}:${pickedProxy.port}${sessionTag}`)
      }

      const res = await window.api.registrationStartAuto(enrichedConfig as typeof config)

      // 上报代理使用结果
      if (pickedProxy) {
        const ok = res.success && (res.result as RegResult | undefined)?.status === 'success'
        const emailUsed = (res.result as RegResult | undefined)?.email
        const errMsg = res.error || (res.result as RegResult | undefined)?.error
        reportProxyResult(pickedProxy.id, ok, emailUsed, errMsg)
      }

      if (res.success && res.result) {
        const regResult = res.result as RegResult
        if (regResult.status === 'success') {
          return { success: true, result: regResult }
        }
        if (attempt === maxRetries) {
          return { success: false, result: regResult }
        }
      } else if (!res.success) {
        if (attempt === maxRetries) return { success: false }
      }
    }
    return { success: false }
  }, [addLog, t, proxyPool, proxyPoolConfig.enabled, pickNextProxy, reportProxyResult, buildAutoConfig])

  // 处理单个批量注册任务完成
  const handleBatchOutcome = async (
    itemId: string,
    outcome: { success: boolean; result?: RegResult }
  ): Promise<void> => {
    if (outcome.success && outcome.result) {
      setBatchSuccess((p) => p + 1)
      // 每日配额计数（仅成功才扣减）
      if (dailyQuotaLimit > 0) incrementDailyQuota(1)
      setBatchItems((prev) => prev.map((it) =>
        it.id === itemId ? { ...it, status: 'success', email: outcome.result!.email } : it
      ))
      addHistory({ email: outcome.result.email, status: 'success', password: outcome.result.password, result: outcome.result })

      if (batchAutoImport) {
        const imported = await autoImportResult(outcome.result)
        setBatchItems((prev) => prev.map((it) =>
          it.id === itemId ? { ...it, status: imported ? 'imported' : 'import_failed' } : it
        ))
        if (imported) {
          addLog(t('register.logImported'))
          setHistory((prev) => {
            const idx = prev.findIndex((h) => h.email === outcome.result!.email && !h.imported)
            if (idx >= 0) {
              const updated = [...prev]
              updated[idx] = { ...updated[idx], imported: true }
              return updated
            }
            return prev
          })
        }
      }
      if (autoFetchProLink) {
        await fetchProSubscriptionUrl(outcome.result, outcome.result.email)
      }
    } else {
      setBatchFail((p) => p + 1)
      const errEmail = outcome.result?.email || ''
      const errMsg = outcome.result?.error || 'unknown'
      setBatchItems((prev) => prev.map((it) =>
        it.id === itemId ? { ...it, status: 'failed', email: errEmail, error: errMsg } : it
      ))
      if (outcome.result) {
        addHistory({ email: errEmail, status: 'failed', error: errMsg })
      }
      const errCategory = classifyError(errMsg)
      // 经验型预校验：邮箱已占用错误加入黑名单
      if (errEmail && errCategory === 'email_used') {
        const set = loadEmailBlacklist()
        set.add(errEmail.toLowerCase())
        saveEmailBlacklist(set)
        addLog(`[Precheck] 邮箱 ${errEmail} 已加入占用黑名单`)
      }
      // AWS 风控触发：立即暂停（如启用自动暂停）
      if (errCategory === 'risk_control' && autoPauseOnRisk && !batchPause.current) {
        batchPause.current = true
        setIsPaused(true)
        if (currentTaskCenterId.current) {
          useTaskStore.getState().updateTask(currentTaskCenterId.current, { status: 'paused' })
        }
        addLog(`[RiskControl] 检测到 AWS 风控（${errEmail || '账号'}），自动暂停批量注册`)
        void useWebhookStore.getState().triggerEvent('risk-warning', {
          title: 'AWS 风控触发，已自动暂停',
          message: `账号 ${errEmail || '(创建中)'} 触发 AWS 风控限流。建议启用代理池 + 验活，或换 IP 后再恢复。`,
          level: 'error',
          fields: { 邮箱: errEmail || '-', 错误: errMsg }
        })
      }
    }
    setBatchDone((p) => p + 1)
  }

  // 批量注册主逻辑（支持并发 + 暂停/恢复 + 任务中心进度上报）
  // 第二个参数 retryItems 用于"从失败重试队列"启动：仅重跑指定 items 而非创建新 N 个
  const startBatch = async (retryItems?: BatchItem[]): Promise<void> => {
    if (mode === 'manual') return

    // 每日配额检查
    if (dailyQuotaLimit > 0) {
      const remainingQuota = Math.max(0, dailyQuotaLimit - dailyQuotaUsed)
      if (remainingQuota === 0) {
        addLog(`[Quota] 今日配额已满 (${dailyQuotaUsed}/${dailyQuotaLimit})，跳过启动`)
        alert(`今日注册配额已用完 (${dailyQuotaUsed}/${dailyQuotaLimit})`)
        return
      }
      const want = retryItems ? retryItems.length : batchCount
      if (want > remainingQuota) {
        addLog(`[Quota] 本次申请 ${want} 个，今日剩余配额 ${remainingQuota}，自动缩减到 ${remainingQuota}`)
        if (!retryItems) {
          setBatchCount(remainingQuota)
        }
      }
    }

    setBatchRunning(true)
    batchAbort.current = false
    batchPause.current = false
    setIsPaused(false)

    let items: BatchItem[]
    if (retryItems && retryItems.length > 0) {
      // 仅重置传入项的状态
      items = retryItems.map((it) => ({ ...it, status: 'pending' as BatchItemStatus, error: undefined, retryCount: 0 }))
      // 合并回完整列表，保持其它成功项可见
      const ids = new Set(items.map((i) => i.id))
      setBatchItems((prev) => [
        ...prev.filter((it) => !ids.has(it.id)),
        ...items
      ])
      // 重试模式下统计仅重置失败计数
      setBatchFail(0)
      setBatchDone((prev) => Math.max(0, prev - items.length))
    } else {
      setBatchDone(0)
      setBatchSuccess(0)
      setBatchFail(0)
      items = Array.from({ length: batchCount }, (_, i) => ({
        id: crypto.randomUUID(),
        index: i + 1,
        status: 'pending' as BatchItemStatus,
        email: '',
        retryCount: 0
      }))
      setBatchItems(items)
    }

    const concurrency = Math.max(1, batchConcurrency)
    const totalCount = items.length

    // 初始化 Outlook 单行池（avoid 并发抢占）—— 仅当 outlook / mixed 启用且填了 outlookData
    const needsOutlook = mode === 'outlook' || (mode === 'mixed' && mixedEnabledSources.includes('outlook'))
    if (needsOutlook && outlookData.trim()) {
      const lines = outlookData.split('\n').map((s) => s.trim()).filter((s) => s.includes('----'))
      // Fisher-Yates shuffle
      for (let i = lines.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1))
        ;[lines[i], lines[j]] = [lines[j], lines[i]]
      }
      outlookPoolRef.current = lines
      if (lines.length < totalCount) {
        addLog(`[Outlook] 警告：邮箱池仅 ${lines.length} 个，本批 ${totalCount} 个任务，超出部分将随机复用（可能撞号）`)
      } else {
        addLog(`[Outlook] 邮箱池已就绪 (${lines.length} 个，shuffle 后分配)`)
      }
    } else {
      outlookPoolRef.current = []
    }

    setPhase('running')

    // 初始化限速器（如启用）
    if (rateLimitEnabled) {
      const cfg = {
        maxPerMinute,
        burst: burstSize,
        backoffBaseMs: backoffBaseSec * 1000,
        backoffMaxMs: backoffMaxSec * 1000,
        consecutiveFailureThreshold: autoBackoff ? 5 : 999999  // 关闭自动退避时通过大阈值禁用
      }
      if (!rateLimiterRef.current) {
        rateLimiterRef.current = createRateLimiter(cfg)
      } else {
        rateLimiterRef.current.updateConfig(cfg)
        rateLimiterRef.current.reset()
      }
      addLog(`[RateLimit] 已启用：${maxPerMinute}/分钟 burst=${burstSize} 退避 ${backoffBaseSec}~${backoffMaxSec}s，自动退避：${autoBackoff ? '开' : '关'}`)
    } else {
      rateLimiterRef.current = null
    }

    // 在任务中心创建任务条目
    const taskCenter = useTaskStore.getState()
    const taskCenterId = taskCenter.createTask({
      kind: 'register-batch',
      title: retryItems ? `重试 ${totalCount} 个失败任务` : `批量注册 ${totalCount} 个账号`,
      subtitle: `${mode === 'outlook' ? 'Outlook' : mode === 'tempmail' ? 'TempMail.Plus' : mode === 'proton' ? 'Proton' : mode === 'gptmail' ? 'GPTmail' : mode === 'mixed' ? 'Mixed' : 'Manual'}，并发 ${concurrency}${proxyPoolConfig.enabled ? ' + 代理池' : ''}${rateLimitEnabled ? ` + ${maxPerMinute}/分钟` : ''}`,
      total: totalCount,
      onPause: () => {
        batchPause.current = true
        setIsPaused(true)
        useTaskStore.getState().updateTask(taskCenterId, { status: 'paused' })
      },
      onResume: () => {
        batchPause.current = false
        setIsPaused(false)
        useTaskStore.getState().updateTask(taskCenterId, { status: 'running' })
      },
      onCancel: () => {
        batchAbort.current = true
        window.api.registrationCancel()
      }
    })
    currentTaskCenterId.current = taskCenterId

    // 并发池执行
    const executing = new Set<Promise<void>>()
    let launched = 0

    for (let i = 0; i < items.length; i++) {
      if (batchAbort.current) {
        addLog(t('register.batchStopped').replace('{done}', String(launched)).replace('{total}', String(totalCount)))
        break
      }

      // 暂停：等待恢复
      while (batchPause.current && !batchAbort.current) {
        await new Promise((r) => setTimeout(r, 500))
      }
      if (batchAbort.current) break

      // 限速：等待令牌（含退避）
      if (rateLimiterRef.current) {
        await rateLimiterRef.current.waitForSlot({ get aborted() { return batchAbort.current } })
        if (batchAbort.current) break
      }

      const itemId = items[i].id
      const taskId = `batch-${itemId.slice(0, 8)}`
      taskIdToItemId.current.set(taskId, itemId)
      addLog(`--- Batch ${i + 1}/${totalCount} ---`)
      launched++

      const task = (async () => {
        const outcome = await runSingleWithRetry(itemId, taskId, batchRetries)
        taskIdToItemId.current.delete(taskId)
        await handleBatchOutcome(itemId, outcome)
        // 上报限速器结果（用于动态退避 + 风控判定）
        if (rateLimiterRef.current) {
          rateLimiterRef.current.reportResult(outcome.success)
        }
        // 上报任务中心进度
        useTaskStore.getState().updateTask(taskCenterId, {
          done: _batchDone,
          successCount: _batchSuccess,
          failedCount: _batchFail,
          progress: Math.round((_batchDone / totalCount) * 100)
        })
      })()

      const tracked = task.finally(() => executing.delete(tracked))
      executing.add(tracked)

      // 控制并发数：池满时等待空位
      if (executing.size >= concurrency) {
        await Promise.race(executing)
      }

      // 每次启动任务后等待间隔（0 则不等待）
      if (i < items.length - 1 && !batchAbort.current && batchInterval > 0) {
        await new Promise((r) => setTimeout(r, batchInterval * 1000))
      }
    }

    // 等待所有正在执行的任务完成
    await Promise.all(executing)

    setBatchRunning(false)
    setIsPaused(false)
    setPhase('idle')
    addLog(t('register.batchCompleted'))

    // 完成任务中心条目
    useTaskStore.getState().completeTask(taskCenterId, {
      successCount: _batchSuccess,
      failedCount: _batchFail
    })
    currentTaskCenterId.current = null

    // 触发 Webhook 通知
    void useWebhookStore.getState().triggerEvent('batch-completed', {
      title: `批量注册${retryItems ? '重试' : ''}完成`,
      message: `共 ${totalCount} 个任务，成功 ${_batchSuccess}，失败 ${_batchFail}`,
      level: _batchFail === 0 ? 'success' : (_batchSuccess === 0 ? 'error' : 'warn'),
      fields: {
        模式: mode === 'outlook' ? 'Outlook' : mode === 'tempmail' ? 'TempMail.Plus' : mode === 'proton' ? 'Proton' : mode === 'gptmail' ? 'GPTmail' : mode === 'mixed' ? 'Mixed' : 'Manual',
        并发: concurrency,
        成功: _batchSuccess,
        失败: _batchFail,
        总数: totalCount
      }
    })
  }

  /** 暂停 / 恢复批量注册 */
  const togglePauseBatch = (): void => {
    if (!batchRunning) return
    if (batchPause.current) {
      batchPause.current = false
      setIsPaused(false)
      if (currentTaskCenterId.current) {
        useTaskStore.getState().updateTask(currentTaskCenterId.current, { status: 'running' })
      }
    } else {
      batchPause.current = true
      setIsPaused(true)
      if (currentTaskCenterId.current) {
        useTaskStore.getState().updateTask(currentTaskCenterId.current, { status: 'paused' })
      }
    }
  }

  const stopBatch = (): void => {
    batchAbort.current = true
    // 同时解除暂停，避免暂停态下主循环 / 重试循环卡在 while 等待
    batchPause.current = false
    setIsPaused(false)
    addLog(isEn ? '[Batch] Stopping, aborting in-flight requests...' : '[Batch] 正在停止，已中止在途请求...')
    // 取消后端所有在途注册（中断当前正在跑的 registrationStartAuto）
    window.api.registrationCancel()
    if (currentTaskCenterId.current) {
      useTaskStore.getState().cancelTask(currentTaskCenterId.current)
      currentTaskCenterId.current = null
    }
  }

  /** 从失败列表中按筛选条件重试 */
  const retryFailed = (filter?: 'network' | 'otp_timeout' | 'rate_limit' | 'all'): void => {
    const failedItems = _batchItems.filter((it) => {
      if (it.status !== 'failed' && it.status !== 'import_failed') return false
      if (!filter || filter === 'all') return true
      return classifyError(it.error) === filter
    })
    if (failedItems.length === 0) {
      addLog(`[Retry] 没有匹配的失败任务可重试`)
      return
    }
    addLog(`[Retry] 重试 ${failedItems.length} 个失败任务（筛选: ${filter || 'all'}）`)
    void startBatch(failedItems)
  }

  // 导入历史中的账号
  const importHistoryItem = async (item: HistoryItem): Promise<void> => {
    if (!item.result || item.result.status !== 'success' || !item.result.refreshToken) return
    const r = item.result

    try {
      const verifyResult = await window.api.verifyAccountCredentials({
        refreshToken: r.refreshToken!,
        clientId: r.clientId!,
        clientSecret: r.clientSecret!,
        region: r.region || 'us-east-1',
        authMethod: 'IdC',
        provider: 'BuilderId'
      })

      const now = Date.now()
      const defaultUsage = { current: 0, limit: 0, percentUsed: 0, lastUpdated: now }

      if (verifyResult.success && verifyResult.data) {
        const expiresAt = verifyResult.data.expiresIn ? now + verifyResult.data.expiresIn * 1000 : now + 3600000
        const usage = verifyResult.data.usage
          ? { ...verifyResult.data.usage, percentUsed: verifyResult.data.usage.limit > 0 ? Math.round((verifyResult.data.usage.current / verifyResult.data.usage.limit) * 100) : 0, lastUpdated: now }
          : defaultUsage

        addAccount({
          email: verifyResult.data.email || r.email,
          idp: 'BuilderId', status: 'active',
          credentials: { refreshToken: r.refreshToken!, clientId: r.clientId!, clientSecret: r.clientSecret!, accessToken: verifyResult.data.accessToken || r.accessToken || '', csrfToken: '', region: r.region || 'us-east-1', authMethod: 'IdC' as const, provider: 'BuilderId' as const, expiresAt },
          subscription: { type: (verifyResult.data.subscriptionType as 'Free' | 'Pro' | 'Pro_Plus' | 'Enterprise' | 'Teams') || 'Free', title: verifyResult.data.subscriptionTitle || 'Free Tier' },
          usage, tags: [], lastUsedAt: now
        })
      } else {
        addAccount({
          email: r.email, idp: 'BuilderId', status: 'active',
          credentials: { refreshToken: r.refreshToken!, clientId: r.clientId!, clientSecret: r.clientSecret!, accessToken: r.accessToken || '', csrfToken: '', region: r.region || 'us-east-1', authMethod: 'IdC' as const, provider: 'BuilderId' as const, expiresAt: now + 3600000 },
          subscription: { type: 'Free', title: 'Free Tier' }, usage: defaultUsage, tags: [], lastUsedAt: now
        })
      }

      setHistory((prev) => prev.map((h) => h.id === item.id ? { ...h, imported: true } : h))
    } catch { /* ignore */ }
  }

  return (
    <div className="flex-1 p-6 space-y-6 overflow-auto">
      {/* Header */}
      <div className="page-hero p-6">
        <div className="absolute top-0 right-0 w-32 h-32 bg-gradient-to-br from-primary/20 to-transparent rounded-full blur-2xl" />
        <div className="absolute bottom-0 left-0 w-24 h-24 bg-gradient-to-tr from-primary/20 to-transparent rounded-full blur-2xl" />
        <div className="relative flex items-center gap-4">
          <div className="p-3 rounded-xl bg-primary/10">
            <UserPlus className="h-7 w-7 text-primary" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-primary">{t('register.title')}</h1>
            <p className="text-sm text-muted-foreground">{isEn ? 'Register new Kiro accounts automatically or manually' : '自动或手动注册新的 Kiro 账号'}</p>
          </div>
        </div>
      </div>

      {/* 模式选择 + 配置 */}
      <Card className="hover-lift">
        <CardHeader className="pb-3">
          <CardTitle className="text-base flex items-center gap-2">
            <Settings2 className="h-4 w-4 text-primary" />
            {t('register.mode')}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-1 p-1 bg-muted rounded-lg w-fit">
            {([
              ['manual', t('register.manual')],
              ['outlook', 'Outlook'],
              ['tempmail', t('register.tempmail')],
              ['proton', 'Proton'],
              ['gptmail', 'GPTmail'],
              ['mixed', isEn ? 'Mixed' : '混合']
            ] as [RegMode, string][]).map(([m, label]) => (
              <button
                key={m}
                onClick={() => setMode(m)}
                disabled={isRunning || batchRunning}
                className={cn(
                  'px-4 py-1.5 rounded-md text-sm font-medium transition-colors disabled:opacity-50',
                  mode === m
                    ? 'bg-background shadow text-foreground'
                    : 'text-muted-foreground hover:text-foreground'
                )}
              >
                {label}
              </button>
            ))}
          </div>


          {/* 自动导入开关 */}
          <div className="flex items-center gap-3">
            <Switch
              checked={batchAutoImport}
              onCheckedChange={setBatchAutoImport}
              disabled={isRunning || batchRunning}
            />
            <div className="flex items-center gap-2">
              <Download className="h-4 w-4 text-muted-foreground" />
              <span className="text-sm">{t('register.batchAutoImport')}</span>
              <span className="text-xs text-muted-foreground">— {t('register.batchAutoImportDesc')}</span>
            </div>
          </div>

          {/* 自动获取 Pro 订阅链接开关 + 计划选择 */}
          <div className="flex flex-col gap-2">
            <div className="flex items-center gap-3">
              <Switch
                checked={autoFetchProLink}
                onCheckedChange={setAutoFetchProLink}
                disabled={isRunning || batchRunning}
              />
              <div className="flex items-center gap-2">
                <Link2 className="h-4 w-4 text-muted-foreground" />
                <span className="text-sm">{t('register.autoFetchProLink')}</span>
                <span className="text-xs text-muted-foreground">— {t('register.autoFetchProLinkDesc')}</span>
              </div>
            </div>

            {/* 计划类型选择（仅开关开启时显示）*/}
            {autoFetchProLink && (
              <div className="ml-11 flex items-center gap-2">
                <span className="text-xs text-muted-foreground">{isEn ? 'Plan:' : '计划:'}</span>
                {([
                  { value: 'Q_DEVELOPER_STANDALONE_PRO' as ProPlanType, label: 'Pro', color: 'bg-blue-500' },
                  { value: 'Q_DEVELOPER_STANDALONE_PRO_PLUS' as ProPlanType, label: 'Pro+', color: 'bg-purple-500' },
                  { value: 'Q_DEVELOPER_STANDALONE_POWER' as ProPlanType, label: 'Power', color: 'bg-amber-500' }
                ]).map(opt => (
                  <button
                    key={opt.value}
                    type="button"
                    onClick={() => setProPlanType(opt.value)}
                    disabled={isRunning || batchRunning}
                    className={`px-3 h-7 rounded-md text-xs font-medium transition-all flex items-center gap-1.5 border ${
                      proPlanType === opt.value
                        ? `${opt.color} text-white border-transparent shadow-sm`
                        : 'bg-background border-border text-muted-foreground hover:text-foreground hover:border-primary/40'
                    } disabled:opacity-50 disabled:cursor-not-allowed`}
                  >
                    {proPlanType === opt.value && <span className="w-1.5 h-1.5 rounded-full bg-white" />}
                    {opt.label}
                  </button>
                ))}
                <span className="text-[10px] text-muted-foreground ml-1 italic">
                  {isEn ? '(Plan ID will be sent to Kiro API)' : '(计划 ID 会作为订阅类型发送)'}
                </span>
              </div>
            )}
          </div>

          {/* Outlook 配置（独立模式 或 混合模式启用了 outlook 时显示） */}
          {(mode === 'outlook' || (mode === 'mixed' && mixedEnabledSources.includes('outlook'))) && (
            <div className="p-4 bg-muted/30 rounded-lg border border-dashed space-y-1.5">
              <Label>{t('register.outlookAccounts')} ({t('register.outlookFormat')})</Label>
              <textarea
                value={outlookData}
                onChange={(e) => setOutlookData(e.target.value)}
                placeholder={t('register.outlookPlaceholder')}
                rows={3}
                disabled={isRunning || batchRunning}
                className="w-full px-3 py-2 bg-background border rounded-lg text-sm font-mono disabled:opacity-50 resize-none"
              />
            </div>
          )}

          {/* 混合模式配置：勾选要参与轮询的子源 + 权重 */}
          {mode === 'mixed' && (
            <div className="p-4 bg-muted/30 rounded-lg border border-dashed space-y-3">
              <Label>{isEn ? 'Enabled email sources (Weighted Round-Robin)' : '启用的邮箱源（加权轮询）'}</Label>
              <div className="space-y-2">
                {(['outlook', 'tempmail', 'proton', 'gptmail'] as AutoEmailSource[]).map((src) => {
                  const enabled = mixedEnabledSources.includes(src)
                  const label = src === 'outlook' ? 'Outlook' : src === 'tempmail' ? 'TempMail.Plus' : src === 'proton' ? 'Proton' : 'GPTmail'
                  const configured = src === 'outlook' ? !!outlookData.trim()
                    : src === 'proton' ? !!protonBaseEmail.trim()
                    : src === 'gptmail' ? !!gptMailDomain.trim()
                    : !!(tempMailDomain.trim() && tempMailEmail.trim() && tempMailEpin.trim())
                  return (
                    <div key={src} className="flex items-center gap-2">
                      <button
                        onClick={() => {
                          setMixedEnabledSources((prev) =>
                            enabled ? prev.filter((s) => s !== src) : [...prev, src]
                          )
                        }}
                        disabled={isRunning || batchRunning}
                        className={cn(
                          'flex-1 px-3 py-2 rounded-md border text-sm transition-colors flex items-center gap-2',
                          enabled
                            ? 'border-primary bg-primary/10 text-primary font-medium'
                            : 'border-border hover:border-primary/50',
                          !configured && 'opacity-60'
                        )}
                        title={!configured ? '该源尚未配置，会被跳过' : ''}
                      >
                        {enabled
                          ? <CheckCircle2 className="h-4 w-4" />
                          : <Square className="h-4 w-4" />
                        }
                        {label}
                        {!configured && <span className="text-[10px] text-amber-500 ml-auto">{isEn ? 'not configured' : '未配置'}</span>}
                      </button>
                      {enabled && configured && (
                        <div className="flex items-center gap-1 text-xs">
                          <span className="text-muted-foreground">{isEn ? 'Weight:' : '权重:'}</span>
                          <Input
                            type="number" min={0} max={100}
                            value={mixedWeights[src] || 0}
                            onChange={(e) => {
                              const v = parseInt(e.target.value, 10)
                              if (!isNaN(v) && v >= 0) {
                                setMixedWeights((prev) => ({ ...prev, [src]: v }))
                              }
                            }}
                            disabled={isRunning || batchRunning}
                            className="h-8 w-16 text-xs text-center"
                          />
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
              <p className="text-xs text-muted-foreground">
                {isEn
                  ? 'Smooth Weighted Round-Robin: e.g. moemail=4 + tempmail=1 means 80% / 20%. Set 0 to disable.'
                  : '平滑加权轮询：例如 moemail=4 + tempmail=1 表示 80% / 20%。权重为 0 等于不参与。'
                }
              </p>
              {mixedEnabledSources.length === 0 && (
                <p className="text-xs text-amber-500">
                  {isEn ? 'Please enable at least one source.' : '请至少启用一个源'}
                </p>
              )}
            </div>
          )}

          {/* TempMail.Plus 配置（独立模式 或 混合模式启用了 tempmail 时显示） */}
          {(mode === 'tempmail' || (mode === 'mixed' && mixedEnabledSources.includes('tempmail'))) && (
            <div className="p-4 bg-muted/30 rounded-lg border border-dashed space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="space-y-1.5">
                  <Label>{t('register.tempMailDomain')}</Label>
                  <Input
                    value={tempMailDomain}
                    onChange={(e) => setTempMailDomain(e.target.value)}
                    placeholder="example.com  domain2.com  domain3.com"
                    disabled={isRunning || batchRunning}
                    className="font-mono text-xs"
                  />
                  {tempMailDomain.trim() && (() => {
                    const list = tempMailDomain.split(/[\s,;]+/).filter(Boolean)
                    return list.length > 1
                      ? <p className="text-[11px] text-muted-foreground">域名池 {list.length} 个，每个账号随机挑一个，降低单域名关联</p>
                      : <p className="text-[11px] text-muted-foreground">填多个域名（空格/逗号分隔）可启用域名轮换</p>
                  })()}
                </div>
                <div className="space-y-1.5">
                  <Label>{t('register.tempMailEmail')}</Label>
                  <Input
                    value={tempMailEmail}
                    onChange={(e) => setTempMailEmail(e.target.value)}
                    placeholder={t('register.tempMailEmailPlaceholder')}
                    disabled={isRunning || batchRunning}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label>{t('register.tempMailEpin')}</Label>
                  <Input
                    type="password"
                    value={tempMailEpin}
                    onChange={(e) => setTempMailEpin(e.target.value)}
                    disabled={isRunning || batchRunning}
                  />
                </div>
              </div>
              <p className="text-xs text-muted-foreground">{t('register.tempMailDesc')}</p>
            </div>
          )}

          {/* Proton 配置（独立模式 或 混合模式启用了 proton 时显示） */}
          {(mode === 'proton' || (mode === 'mixed' && mixedEnabledSources.includes('proton'))) && (
            <div className="p-4 bg-muted/30 rounded-lg border border-dashed space-y-3">
              <div className="space-y-1.5">
                <Label>{isEn ? 'Proton base email (dot-alias parent)' : 'Proton 母邮箱（点号别名母号）'}</Label>
                <Input
                  type="email"
                  value={protonBaseEmail}
                  onChange={(e) => setProtonBaseEmail(e.target.value)}
                  placeholder="evanbartellchae@protonmail.com"
                  disabled={isRunning || batchRunning}
                  autoComplete="off"
                  spellCheck={false}
                  className="font-mono text-xs"
                />
                {protonBaseEmail.trim() && (() => {
                  const split = splitEmail(protonBaseEmail.trim())
                  if (!split) return <p className="text-[11px] text-destructive">{isEn ? 'Invalid email' : '邮箱格式无效'}</p>
                  const localLen = split[0].replace(/\./g, '').length
                  const capacity = totalVariantCount(localLen, 5)
                  return <p className="text-[11px] text-muted-foreground">{isEn ? `Auto-generates dot-variants of the local part, ~${capacity.toLocaleString()} available` : `自动生成用户名点号变体，约 ${capacity.toLocaleString()} 个可用`}</p>
                })()}
              </div>
              <div className="flex items-center gap-2 flex-wrap">
                <button
                  type="button"
                  disabled={protonChecking}
                  onClick={async () => {
                    setProtonChecking(true)
                    try {
                      const r = await window.api.protonOpenLogin()
                      setProtonLoggedIn(r.loggedIn)
                      addLog(r.loggedIn
                        ? (isEn ? '[Proton] Already logged in' : '[Proton] 已登录')
                        : (isEn ? '[Proton] Please complete login in the popup window' : '[Proton] 请在弹出的窗口中完成登录'))
                    } catch (err) {
                      addLog(`[Proton] ${err instanceof Error ? err.message : String(err)}`)
                    } finally {
                      setProtonChecking(false)
                    }
                  }}
                  className="px-3 py-1.5 rounded-md border border-primary bg-primary/10 text-primary text-sm font-medium transition-colors hover:bg-primary/20 disabled:opacity-50"
                >
                  {protonChecking ? (isEn ? 'Opening...' : '打开中...') : (isEn ? 'Login Proton' : '登录 Proton')}
                </button>
                <button
                  type="button"
                  disabled={protonChecking}
                  onClick={async () => {
                    setProtonChecking(true)
                    try {
                      const r = await window.api.protonLoginStatus(undefined, protonBaseEmail.trim() || undefined)
                      setProtonLoggedIn(r.loggedIn)
                      if (!r.loggedIn) {
                        addLog(isEn ? '[Proton] Not logged in' : '[Proton] 未登录')
                      } else if (r.emailMatch === false) {
                        addLog(`[Proton] ${isEn ? 'Logged in as' : '已登录'} ${r.currentEmail || '???'}, ${isEn ? 'but does not match configured email' : '但与配置的母邮箱不匹配'}: ${protonBaseEmail}. ${isEn ? 'Please logout and re-login.' : '请退出后重新登录。'}`)
                      } else if (r.currentEmail) {
                        addLog(`[Proton] ${isEn ? 'Logged in as' : '已登录'} ${r.currentEmail}${r.emailMatch ? ` (${isEn ? 'email matches' : '邮箱一致'})` : ''}`)
                      } else {
                        addLog(`[Proton] ${isEn ? 'Logged in (could not read account email, please verify manually)' : '已登录（未能读取账户邮箱，请手动确认）'}`)
                      }
                    } finally {
                      setProtonChecking(false)
                    }
                  }}
                  className="px-3 py-1.5 rounded-md border border-border text-sm transition-colors hover:border-primary/50 disabled:opacity-50"
                >
                  {isEn ? 'Check status' : '检查登录态'}
                </button>
                <span className={cn('text-xs', protonLoggedIn ? 'text-green-500' : 'text-muted-foreground')}>
                  {protonLoggedIn ? (isEn ? '● Logged in' : '● 已登录') : (isEn ? '○ Not logged in' : '○ 未登录')}
                </span>
                <button
                  type="button"
                  disabled={protonChecking || !protonLoggedIn}
                  onClick={async () => {
                    setProtonChecking(true)
                    try {
                      await window.api.protonClose()
                      setProtonLoggedIn(false)
                      addLog(isEn ? '[Proton] Logged out, please re-login with the correct account' : '[Proton] 已退出，请重新登录正确的账户')
                    } finally {
                      setProtonChecking(false)
                    }
                  }}
                  className="px-3 py-1.5 rounded-md border border-destructive/30 text-destructive text-sm transition-colors hover:bg-destructive/10 disabled:opacity-50"
                >
                  {isEn ? 'Logout' : '退出登录'}
                </button>
              </div>
              <p className="text-xs text-muted-foreground leading-snug">
                {isEn
                  ? 'Reads codes via the official Proton web page (login once, session persists). Each account uses a dot-variant of the base email (e.g. evanbar.tellcha.e@), all landing in the same inbox. Recommended concurrency: 1.'
                  : '借壳 Proton 官方网页取码（登录一次，会话持久化）。每个账号使用母邮箱的点号变体（如 evanbar.tellcha.e@），全部进同一收件箱。建议并发设为 1。'}
              </p>
            </div>
          )}

          {/* GPTmail 配置（独立模式 或 混合模式启用了 gptmail 时显示）
              支持两种模式：
                A. 私有域名直收（接收邮箱留空）—— MX 直接解析到 GPTmail，无需 CF
                B. CF 转发（填接收邮箱）—— 跟 TempMail.Plus 玩法一致 */}
          {(mode === 'gptmail' || (mode === 'mixed' && mixedEnabledSources.includes('gptmail'))) && (() => {
            const isPrivateMode = !gptMailInboxEmail.trim()
            return (
            <div className="p-4 bg-muted/30 rounded-lg border border-dashed space-y-4">
              {/* 模式状态标签 */}
              <div className="flex items-center gap-2 text-xs">
                <span className="text-muted-foreground">{isEn ? 'Current mode:' : '当前模式：'}</span>
                <span className={cn(
                  'px-2 py-0.5 rounded-full font-medium',
                  isPrivateMode ? 'bg-primary/10 text-primary' : 'bg-amber-500/10 text-amber-600'
                )}>
                  {isPrivateMode
                    ? (isEn ? 'A · Private direct (MX → GPTmail)' : 'A · 私有域名直收（MX → GPTmail）')
                    : (isEn ? 'B · CF Email Routing forward' : 'B · CF Email Routing 转发')}
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <Label>{isEn ? 'Your domain pool' : '自建域名池'} <span className="text-destructive">*</span></Label>
                  <Input
                    value={gptMailDomain}
                    onChange={(e) => setGptMailDomain(e.target.value)}
                    placeholder="example.com  domain2.com"
                    disabled={isRunning || batchRunning}
                    className="font-mono text-xs"
                  />
                  {gptMailDomain.trim() && (() => {
                    const list = gptMailDomain.split(/[\s,;]+/).filter(Boolean)
                    return list.length > 1
                      ? <p className="text-[11px] text-muted-foreground">{isEn ? `Domain pool: ${list.length}, randomized per account` : `域名池 ${list.length} 个，每个账号随机挑一个（降低关联）`}</p>
                      : <p className="text-[11px] text-muted-foreground">{isEn ? 'Multiple domains (space/comma separated) enable rotation' : '填多个域名（空格/逗号分隔）可启用域名轮换'}</p>
                  })()}
                </div>

                <div className="space-y-1.5">
                  <Label>{isEn ? 'GPTmail inbox (optional, for CF forwarding)' : 'GPTmail 接收邮箱（可选，CF 转发用）'}</Label>
                  <Input
                    type="email"
                    value={gptMailInboxEmail}
                    onChange={(e) => setGptMailInboxEmail(e.target.value)}
                    placeholder={isEn ? 'leave empty for private direct' : '留空 = 私有域名直收'}
                    disabled={isRunning || batchRunning}
                    autoComplete="off"
                    spellCheck={false}
                    className="font-mono text-xs"
                  />
                  <p className="text-[11px] text-muted-foreground leading-snug">
                    {isEn
                      ? 'Empty: register prefix@yourdomain directly as the inbox (MX must point to GPTmail). Filled: CF Email Routing forwards *@yourdomain to this inbox.'
                      : '留空：prefix@yourdomain 本身就是 inbox（域名 MX 必须解析到 GPTmail）。填了：CF Email Routing 把 *@yourdomain 转发到此邮箱。'}
                  </p>
                </div>

                <div className="space-y-1.5">
                  <Label>{isEn ? 'Private domain password (optional)' : '私有域名密码（可选）'}</Label>
                  <Input
                    type="password"
                    value={gptMailPrivatePassword}
                    onChange={(e) => setGptMailPrivatePassword(e.target.value)}
                    placeholder={isEn ? 'only for private domains with password' : '仅在 GPTmail 设了私密密码时填'}
                    disabled={isRunning || batchRunning}
                    autoComplete="off"
                    className="font-mono text-xs"
                  />
                  <p className="text-[11px] text-muted-foreground leading-snug">
                    {isEn
                      ? 'If you added your domain as "Private" on GPTmail, fill the password here. Auto-unlocks the inbox before polling.'
                      : '如果你在 GPTmail 把域名添加为"私密域名"并设了密码，填这里。轮询前会自动解锁 inbox。'}
                  </p>
                </div>
                <div className="space-y-1.5">
                  <Label>{isEn ? 'Fixed prefix (optional)' : '固定前缀（可选）'}</Label>
                  <Input
                    value={gptMailPrefix}
                    onChange={(e) => setGptMailPrefix(e.target.value)}
                    placeholder={isEn ? 'leave empty for random' : '留空则自动生成随机前缀'}
                    disabled={isRunning || batchRunning}
                    className="font-mono text-xs"
                  />
                </div>
                <div className="space-y-1.5 md:col-span-2">
                  <Label>{isEn ? 'Custom Base URL (optional)' : '自定义 BaseURL（可选）'}</Label>
                  <Input
                    value={gptMailBaseURL}
                    onChange={(e) => setGptMailBaseURL(e.target.value)}
                    placeholder="https://mail.chatgpt.org.uk"
                    disabled={isRunning || batchRunning}
                    className="font-mono text-xs"
                  />
                  <p className="text-[11px] text-muted-foreground">{isEn ? 'Defaults to https://mail.chatgpt.org.uk; change for self-hosted' : '默认 https://mail.chatgpt.org.uk，私有部署可改'}</p>
                </div>
              </div>

              {/* 模式说明 */}
              <div className="p-2.5 bg-background/60 rounded border-l-2 border-primary/60 text-xs leading-relaxed text-muted-foreground space-y-1">
                {isPrivateMode ? (
                  <>
                    <p className="font-medium text-foreground">{isEn ? 'Mode A · Private direct (recommended):' : '模式 A · 私有域名直收（推荐）：'}</p>
                    <ol className="list-decimal pl-5 space-y-0.5">
                      <li>{isEn ? 'Add your domain on mail.chatgpt.org.uk (it gives you MX records)' : '在 mail.chatgpt.org.uk 添加私有/公开域名（页面会给出 MX 解析记录）'}</li>
                      <li>{isEn ? 'Point your domain MX to GPTmail at your DNS provider' : '在 DNS 提供商把你的域名 MX 指向 GPTmail'}</li>
                      <li>{isEn ? 'Each registration uses prefix@yourdomain as both register email and inbox' : '每次注册用 prefix@你的域名 作为注册邮箱（同时也是 inbox）'}</li>
                      <li>{isEn ? 'GPTmail receives directly, we poll the API and extract the code' : 'GPTmail 直接收信 → 我们轮询 API 提取验证码'}</li>
                    </ol>
                  </>
                ) : (
                  <>
                    <p className="font-medium text-foreground">{isEn ? 'Mode B · Cloudflare Email Routing forward:' : '模式 B · Cloudflare Email Routing 转发：'}</p>
                    <ol className="list-decimal pl-5 space-y-0.5">
                      <li>{isEn ? 'Register a receiving inbox on mail.chatgpt.org.uk (e.g. abc@msn-mail-free-9224.dynv6.net)' : '在 mail.chatgpt.org.uk 注册一个接收邮箱（如 abc@msn-mail-free-9224.dynv6.net）'}</li>
                      <li>{isEn ? 'In Cloudflare Email Routing, set catch-all *@yourdomain → that inbox' : '在 Cloudflare Email Routing 把 *@你的域名 catch-all 转发到该邮箱'}</li>
                      <li>{isEn ? 'Each registration uses prefix@yourdomain' : '每次注册用 prefix@你的域名'}</li>
                      <li>{isEn ? 'AWS sends OTP → CF forwards to GPTmail → we poll GPTmail API and extract the code' : 'AWS 发送验证码 → CF 转发到 GPTmail → 我们轮询 GPTmail API 提取验证码'}</li>
                    </ol>
                  </>
                )}
              </div>
            </div>
            )
          })()}
        </CardContent>
      </Card>

      {/* 手动模式母邮箱输入 + 匿名邮箱开关（仅 phase=idle） */}
      {mode === 'manual' && phase === 'idle' && !batchRunning && (
        <Card className="hover-lift">
          <CardHeader className="pb-3">
            <CardTitle className="text-base flex items-center gap-2">
              <AtSign className="h-4 w-4 text-primary" />
              {t('register.parentEmailSection')}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <Label htmlFor="parentEmail" className="text-xs">{t('register.parentEmailLabel')}</Label>
                <Input
                  id="parentEmail"
                  type="email"
                  value={parentEmail}
                  onChange={(e) => setParentEmail(e.target.value)}
                  placeholder={t('register.parentEmailPlaceholder')}
                  autoComplete="off"
                  spellCheck={false}
                />
                <p className="text-[11px] text-muted-foreground leading-snug">{t('register.parentEmailHint')}</p>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="fullNameIdle" className="text-xs">{t('register.fullNameRandom')}</Label>
                <Input
                  id="fullNameIdle"
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder={t('register.fullNamePlaceholder')}
                />
              </div>
            </div>

            <div className="flex items-start gap-3 pt-1">
              <Switch
                id="anonymousEmail"
                checked={anonymousEmail}
                onCheckedChange={setAnonymousEmail}
              />
              <div className="flex-1 space-y-0.5">
                <Label htmlFor="anonymousEmail" className="cursor-pointer text-sm flex items-center gap-1.5">
                  <Shuffle className="h-3.5 w-3.5 text-primary" />
                  {t('register.anonymousEmailLabel')}
                </Label>
                <p className="text-[11px] text-muted-foreground leading-snug">{t('register.anonymousEmailHint')}</p>
              </div>
            </div>

            {/* 预览面板 */}
            {anonymousEmail && (
              <div className="text-xs">
                {anonymousPreview?.error === 'empty' && (
                  <div className="flex items-center gap-1.5 text-warning">
                    <Info className="h-3.5 w-3.5" />
                    <span>{t('register.anonymousNoParent')}</span>
                  </div>
                )}
                {anonymousPreview?.error === 'invalid' && (
                  <div className="flex items-center gap-1.5 text-destructive">
                    <Info className="h-3.5 w-3.5" />
                    <span>{t('register.anonymousInvalid')}</span>
                  </div>
                )}
                {anonymousPreview && !anonymousPreview.error && anonymousPreview.variant && (
                  <div className="bg-primary/[0.06] border border-primary/20 rounded-md p-2.5 space-y-1.5">
                    <div className="flex items-center justify-between flex-wrap gap-2">
                      <span className="text-muted-foreground flex items-center gap-1"><Shuffle className="h-3 w-3" /> {t('register.nextVariant')}:</span>
                      <code className="bg-background px-2 py-0.5 rounded font-mono text-foreground border">
                        {anonymousPreview.variant}
                      </code>
                    </div>
                    <div className="flex items-center justify-between text-[11px] text-muted-foreground gap-2">
                      <span>{t('register.dotCount')}: <strong className="text-foreground">{anonymousPreview.dotCount}</strong></span>
                      <span>{t('register.sameRoot')}: <strong className="text-foreground">{anonymousPreview.sameRootCount}</strong> / ~{anonymousPreview.totalCapacity}</span>
                    </div>
                  </div>
                )}
                {anonymousPreview && !anonymousPreview.error && !anonymousPreview.variant && (
                  <div className="flex items-center gap-1.5 text-warning">
                    <Info className="h-3.5 w-3.5" />
                    <span>{t('register.anonymousExhausted')}</span>
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* 手动模式进度步骤条（动态步骤：6-8 步，根据开关启用 Import / ProLink） */}
      {mode === 'manual' && phase !== 'idle' && (
        <div className="bg-card border rounded-xl p-4">
          <div className="flex items-center justify-between">
            {manualSteps.map((step, i) => {
              const isLast = i === manualSteps.length - 1
              const isDone = i < currentStep
              const isCurrent = i === currentStep
              // 区分核心步骤 vs 后处理步骤（用不同颜色）
              const isExtra = step === 'Import' || step === 'ProLink'
              return (
                <div key={step} className={cn('flex items-center', isLast ? '' : 'flex-1 min-w-0')}>
                  <div
                    className={cn(
                      'flex items-center justify-center w-8 h-8 rounded-full text-xs font-bold transition-all flex-shrink-0',
                      isDone && (isExtra
                        ? 'bg-cyan-500 text-white shadow-sm shadow-cyan-500/30'
                        : 'bg-green-500 text-white shadow-sm shadow-green-500/30'),
                      isCurrent && 'bg-primary text-primary-foreground animate-pulse shadow-sm shadow-primary/30',
                      !isDone && !isCurrent && 'bg-muted text-muted-foreground'
                    )}
                  >
                    {isDone ? <CheckCircle2 className="h-4 w-4" /> : i + 1}
                  </div>
                  <span
                    className={cn(
                      'ml-1.5 text-xs font-medium whitespace-nowrap',
                      (isDone || isCurrent) ? 'text-foreground' : 'text-muted-foreground'
                    )}
                  >
                    {step}
                  </span>
                  {!isLast && (
                    <div
                      className={cn(
                        'flex-1 h-0.5 mx-2 transition-colors',
                        isDone
                          ? (isExtra ? 'bg-cyan-500' : 'bg-green-500')
                          : 'bg-muted'
                      )}
                    />
                  )}
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* 操作区 */}
      <Card className="hover-lift">
        <CardContent className="pt-5 space-y-4">
          {/* 手动模式 email/otp 输入 */}
          {mode === 'manual' && phase === 'email' && (
            <div className="space-y-4 p-4 bg-muted/30 rounded-lg border border-dashed">
              <div className="space-y-1.5">
                <Label>{t('register.emailLabel')}</Label>
                <Input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder={t('register.emailPlaceholder')}
                  onKeyDown={(e) => e.key === 'Enter' && submitEmail()}
                />
              </div>
              <div className="space-y-1.5">
                <Label>{t('register.fullNameRandom')}</Label>
                <Input
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder={t('register.fullNamePlaceholder')}
                />
              </div>
              <Button onClick={submitEmail} size="sm">
                <Mail className="h-4 w-4 mr-2" />
                {t('register.submitEmail')}
              </Button>
            </div>
          )}

          {mode === 'manual' && phase === 'otp' && (
            <div className="space-y-4 p-4 bg-muted/30 rounded-lg border border-dashed">
              <div className="space-y-1.5">
                <Label>{t('register.otpLabel')}</Label>
                <Input
                  value={otp}
                  onChange={(e) => setOtp(e.target.value)}
                  placeholder="123456"
                  maxLength={6}
                  className="font-mono text-lg tracking-widest"
                  onKeyDown={(e) => e.key === 'Enter' && submitOTP()}
                />
                <p className="text-xs text-muted-foreground">
                  {t('register.otpSentTo')} {email}
                </p>
              </div>
              <Button onClick={submitOTP} size="sm">
                <Key className="h-4 w-4 mr-2" />
                {t('register.submitOtp')}
              </Button>
            </div>
          )}

          {/* 按钮 */}
          <div className="flex gap-3">
            {phase === 'idle' && !batchRunning && (
              <Button
                onClick={mode === 'manual' ? startManual : startAuto}
                disabled={
                  (mode === 'outlook' && !outlookData.trim()) ||
                  (mode === 'tempmail' && (!tempMailDomain.trim() || !tempMailEmail.trim() || !tempMailEpin.trim())) ||
                  (mode === 'gptmail' && !gptMailDomain.trim()) ||
                  (mode === 'proton' && !protonBaseEmail.trim()) ||
                  (mode === 'mixed' && pickNextSource() == null)
                }
              >
                <Play className="h-4 w-4 mr-2" />
                {t('register.startRegistration')}
              </Button>
            )}

            {(isRunning || batchRunning || phase === 'email' || phase === 'otp') && (
              <Button variant="destructive" onClick={batchRunning ? stopBatch : cancel}>
                <Square className="h-4 w-4 mr-2" />
                {t('register.cancel')}
              </Button>
            )}

            {(phase === 'done' || phase === 'finalized') && !batchRunning && (
              <Button variant="outline" onClick={reset}>
                <RotateCcw className="h-4 w-4 mr-2" />
                {t('register.newRegistration')}
              </Button>
            )}
          </div>

          {isRunning && (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin text-primary" />
              {t('register.processing')}
            </div>
          )}
        </CardContent>
      </Card>

      {/* 日志（紧跟"开始注册"卡片，方便观察进度，不再放到页面最底部） */}
      {logs.length > 0 && (
        <Card className="overflow-hidden">
          <CardHeader className="py-3 border-b">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm">{t('register.log')}</CardTitle>
              <Button variant="ghost" size="sm" onClick={() => { _logs = []; setLogs([]) }}>
                <Trash2 className="h-3.5 w-3.5" />
              </Button>
            </div>
          </CardHeader>
          <CardContent className="p-0">
            <div ref={logContainerRef} className="h-48 overflow-y-auto p-3 font-mono text-xs space-y-0.5 bg-muted/20">
              {logs.map((line, i) => (
                <div key={i} className="text-muted-foreground leading-relaxed">{line}</div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* 批量注册 (非手动模式) */}
      {mode !== 'manual' && (
        <Card className="hover-lift">
          <CardHeader className="pb-3 flex flex-row items-center justify-between">
            <CardTitle className="text-base flex items-center gap-2">
              <Play className="h-4 w-4 text-primary" />
              {t('register.batchTitle')}
            </CardTitle>
            {/* 策略模板 */}
            <div className="relative">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setShowTemplatesMenu(!showTemplatesMenu)}
                disabled={batchRunning}
              >
                <Settings2 className="h-4 w-4 mr-1" />
                {isEn ? 'Templates' : '模板'} ({templates.length})
              </Button>
              {showTemplatesMenu && (
                <div className="absolute right-0 top-full mt-2 z-50 min-w-[280px] max-h-[400px] overflow-y-auto bg-popover border rounded-lg shadow-lg p-2">
                  <div className="flex items-center justify-between mb-2 px-2">
                    <span className="text-xs font-medium uppercase text-muted-foreground">{isEn ? 'Strategy Templates' : '策略模板'}</span>
                    <div className="flex items-center gap-1">
                      <Button size="sm" variant="ghost" onClick={saveCurrentAsTemplate} className="h-7 text-xs">
                        <Download className="h-3 w-3 mr-1" />
                        {isEn ? 'Save current' : '保存当前'}
                      </Button>
                      {/* C8: 导入/导出 */}
                      <button
                        type="button"
                        onClick={() => {
                          const blob = new Blob([JSON.stringify(templates, null, 2)], { type: 'application/json' })
                          const url = URL.createObjectURL(blob)
                          const a = document.createElement('a')
                          a.href = url
                          a.download = `kiro-register-templates-${new Date().toISOString().slice(0, 10)}.json`
                          a.click()
                          setTimeout(() => URL.revokeObjectURL(url), 1000)
                        }}
                        title={isEn ? 'Export all templates' : '导出全部模板'}
                        className="p-1 rounded hover:bg-muted text-muted-foreground"
                      >
                        <Download className="h-3 w-3" />
                      </button>
                      <label className="p-1 rounded hover:bg-muted text-muted-foreground cursor-pointer" title={isEn ? 'Import templates' : '导入模板'}>
                        <input
                          type="file"
                          accept="application/json,.json"
                          className="hidden"
                          onChange={async (e) => {
                            const file = e.target.files?.[0]
                            if (!file) return
                            try {
                              const text = await file.text()
                              const arr = JSON.parse(text) as RegisterTemplate[]
                              if (!Array.isArray(arr)) throw new Error('文件格式无效')
                              const merged = [...arr, ...templates]
                              // 按 ID 去重，新文件优先
                              const seen = new Set<string>()
                              const dedup: RegisterTemplate[] = []
                              for (const t of merged) {
                                if (seen.has(t.id)) continue
                                seen.add(t.id)
                                dedup.push(t)
                              }
                              setTemplates(dedup)
                              saveTemplates(dedup)
                              addLog(`[Template] 已导入 ${arr.length} 个模板`)
                            } catch (err) {
                              alert(`导入失败：${err instanceof Error ? err.message : String(err)}`)
                            }
                            e.currentTarget.value = ''
                          }}
                        />
                        <Upload className="h-3 w-3" />
                      </label>
                    </div>
                  </div>
                  <div className="border-t mb-1" />
                  {templates.length === 0 ? (
                    <div className="py-6 text-center text-xs text-muted-foreground">
                      {isEn ? 'No templates yet. Click "Save current" to save the current config as a template.' : '尚无模板。点击「保存当前」把当前配置保存为模板。'}
                    </div>
                  ) : (
                    templates.map((tpl) => (
                      <div
                        key={tpl.id}
                        className="flex items-center justify-between gap-2 px-2 py-1.5 hover:bg-muted rounded transition-colors"
                      >
                        <button
                          onClick={() => applyTemplate(tpl)}
                          className="flex-1 text-left min-w-0"
                        >
                          <div className="text-sm truncate">{tpl.name}</div>
                          <div className="text-[10px] text-muted-foreground">
                            {tpl.config.mode} · {isEn ? 'count' : '批量'} {tpl.config.batchCount} · {isEn ? 'conc.' : '并发'} {tpl.config.batchConcurrency}
                          </div>
                        </button>
                        <button
                          onClick={() => removeTemplate(tpl.id)}
                          className="p-1 rounded hover:bg-destructive/10 text-destructive"
                          title={isEn ? 'Delete' : '删除'}
                        >
                          <Trash2 className="h-3 w-3" />
                        </button>
                      </div>
                    ))
                  )}
                </div>
              )}
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* 配置行 */}
            <div className="flex flex-wrap items-end gap-4">
              <div className="space-y-1">
                <Label className="text-xs">{t('register.batchCount')}</Label>
                <Input
                  type="number" min={1} max={100}
                  value={batchCount}
                  onChange={(e) => { const v = parseInt(e.target.value); if (!isNaN(v) && v >= 1) setBatchCount(v) }}
                  onBlur={() => { if (batchCount < 1) setBatchCount(1) }}
                  disabled={batchRunning}
                  className="w-24"
                />
              </div>
              <div className="space-y-1">
                <Label className="text-xs">{t('register.batchInterval')}</Label>
                <Input
                  type="number" min={0} max={300}
                  value={batchInterval}
                  onChange={(e) => { const v = parseInt(e.target.value); if (!isNaN(v) && v >= 0) setBatchInterval(v) }}
                  disabled={batchRunning}
                  className="w-24"
                />
              </div>
              <div className="space-y-1">
                <Label className="text-xs">{t('register.batchRetries')}</Label>
                <Input
                  type="number" min={0} max={10}
                  value={batchRetries}
                  onChange={(e) => { const v = parseInt(e.target.value); if (!isNaN(v) && v >= 0) setBatchRetries(v) }}
                  disabled={batchRunning}
                  className="w-24"
                />
              </div>
              <div className="space-y-1">
                <Label className="text-xs">{t('register.batchConcurrency')}</Label>
                <Input
                  type="number" min={1} max={100}
                  value={batchConcurrency}
                  onChange={(e) => { const v = parseInt(e.target.value); if (!isNaN(v) && v >= 1) setBatchConcurrency(v) }}
                  onBlur={() => { if (batchConcurrency < 1) setBatchConcurrency(1) }}
                  disabled={batchRunning}
                  className="w-24"
                />
              </div>
              <Button
                variant={batchRunning ? 'destructive' : 'default'}
                onClick={batchRunning ? stopBatch : () => void startBatch()}
                disabled={
                  (!batchRunning && isRunning) ||
                  (mode === 'outlook' && !outlookData.trim()) ||
                  (mode === 'tempmail' && (!tempMailDomain.trim() || !tempMailEmail.trim() || !tempMailEpin.trim())) ||
                  (mode === 'gptmail' && !gptMailDomain.trim()) ||
                  (mode === 'proton' && !protonBaseEmail.trim()) ||
                  (mode === 'mixed' && pickNextSource() == null)
                }
              >
                {batchRunning ? <><Square className="h-4 w-4 mr-2" />{t('register.batchStop')}</> : <><Play className="h-4 w-4 mr-2" />{t('register.batchStart')}</>}
              </Button>
              {batchRunning && (
                <Button variant="outline" onClick={togglePauseBatch} title={isPaused ? '恢复' : '暂停'}>
                  {isPaused ? <><Play className="h-4 w-4 mr-2" />{isEn ? 'Resume' : '恢复'}</> : <><Pause className="h-4 w-4 mr-2" />{isEn ? 'Pause' : '暂停'}</>}
                </Button>
              )}
            </div>

            {/* 定时任务 + 每日配额 */}
            <div className="flex items-center gap-4 flex-wrap p-3 rounded-lg bg-muted/30 border border-dashed">
              <div className="flex items-center gap-2">
                <Switch checked={scheduleEnabled} onCheckedChange={setScheduleEnabled} disabled={batchRunning} />
                <Label className="text-sm cursor-pointer flex items-center gap-1.5">
                  <CalendarClock className="h-4 w-4 text-primary" />
                  定时启动
                </Label>
              </div>
              {scheduleEnabled && (
                <>
                  <div className="flex items-center gap-1.5 text-xs">
                    <Input
                      type="time"
                      value={scheduleTime}
                      onChange={(e) => setScheduleTime(e.target.value)}
                      disabled={batchRunning}
                      className="h-8 w-28 text-xs"
                    />
                  </div>
                  {/* C6: 星期选择 */}
                  <div className="flex items-center gap-1 text-xs">
                    {(isEn ? ['Su', 'Mo', 'Tu', 'We', 'Th', 'Fr', 'Sa'] : ['日', '一', '二', '三', '四', '五', '六']).map((label, i) => {
                      const checked = !!(scheduleWeekMask & (1 << i))
                      return (
                        <button
                          key={i}
                          type="button"
                          onClick={() => setScheduleWeekMask(scheduleWeekMask ^ (1 << i))}
                          disabled={batchRunning}
                          className={cn(
                            'w-7 h-7 rounded text-[10px] border transition-colors',
                            checked
                              ? 'border-primary bg-primary/10 text-primary font-medium'
                              : 'border-border text-muted-foreground hover:border-primary/50'
                          )}
                        >
                          {label}
                        </button>
                      )
                    })}
                    <button
                      type="button"
                      onClick={() => setScheduleWeekMask(scheduleWeekMask === 127 ? 0b0111110 : 127)}
                      disabled={batchRunning}
                      className="text-[10px] text-primary hover:underline ml-1"
                      title={isEn ? 'Toggle: all / weekdays only' : '切换：全选 / 仅工作日'}
                    >
                      {scheduleWeekMask === 127 ? (isEn ? 'Weekdays' : '工作日') : (isEn ? 'Daily' : '每天')}
                    </button>
                  </div>
                </>
              )}
              <div className="w-px h-6 bg-border" />
              <div className="flex items-center gap-1.5 text-xs">
                <Timer className="h-4 w-4 text-primary" />
                <span className="text-muted-foreground">{isEn ? 'Daily quota:' : '每日配额:'}</span>
                <Input
                  type="number" min={0} max={9999}
                  value={dailyQuotaLimit}
                  onChange={(e) => { const v = parseInt(e.target.value, 10); if (!isNaN(v) && v >= 0) setDailyQuotaLimit(v) }}
                  disabled={batchRunning}
                  className="h-8 w-20 text-xs text-center"
                />
                <span className="text-muted-foreground">{isEn ? '/day' : '个/天'}</span>
                {dailyQuotaLimit > 0 && (
                  <>
                    <Badge
                      variant="outline"
                      className={cn(
                        'text-[10px]',
                        dailyQuotaUsed >= dailyQuotaLimit
                          ? 'text-red-600 border-red-200'
                          : dailyQuotaUsed >= dailyQuotaLimit * 0.8
                            ? 'text-amber-600 border-amber-200'
                            : 'text-muted-foreground'
                      )}
                    >
                      {isEn ? 'Today' : '今日'}: {dailyQuotaUsed} / {dailyQuotaLimit}
                    </Badge>
                    <button
                      type="button"
                      onClick={() => {
                        if (confirm(isEn ? `Reset today's used quota (currently ${dailyQuotaUsed})?` : `重置今日已用配额（当前 ${dailyQuotaUsed}）？`)) {
                          setDailyQuotaUsedState(0)
                          try { localStorage.setItem(dailyQuotaKey, '0') } catch { /* ignore */ }
                          addLog(isEn ? '[Quota] Today\'s quota counter reset' : '[Quota] 已重置今日配额计数')
                        }
                      }}
                      className="text-[10px] text-muted-foreground hover:text-foreground underline"
                      title={isEn ? "Manually reset today's used quota" : '手动重置今日已用配额'}
                    >
                      {isEn ? 'Reset' : '重置'}
                    </button>
                  </>
                )}
                {dailyQuotaLimit === 0 && (
                  <span className="text-[10px] text-muted-foreground italic">{isEn ? '(0 = unlimited)' : '（0 = 不限制）'}</span>
                )}
              </div>
            </div>

            {/* 限速 + 退避配置 */}
            <div className="flex items-center gap-4 flex-wrap p-3 rounded-lg bg-muted/30 border border-dashed">
              <div className="flex items-center gap-2">
                <Switch checked={rateLimitEnabled} onCheckedChange={setRateLimitEnabled} disabled={batchRunning} />
                <Label className="text-sm cursor-pointer flex items-center gap-1.5">
                  <Gauge className="h-4 w-4 text-primary" />
                  {isEn ? 'Rate limit' : '限速'}
                </Label>
              </div>
              {rateLimitEnabled && (
                <>
                  <div className="flex items-center gap-1.5 text-xs">
                    <span className="text-muted-foreground">{isEn ? 'Max launch rate:' : '最大启动速率:'}</span>
                    <Input
                      type="number" min={1} max={300}
                      value={maxPerMinute}
                      onChange={(e) => { const v = parseInt(e.target.value, 10); if (!isNaN(v) && v >= 1) setMaxPerMinute(v) }}
                      disabled={batchRunning}
                      className="w-20 h-8 text-xs text-center"
                    />
                    <span className="text-muted-foreground">{isEn ? '/ min' : '/ 分钟'}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Switch checked={autoBackoff} onCheckedChange={setAutoBackoff} disabled={batchRunning} />
                    <Label className="text-xs cursor-pointer">
                      {isEn ? 'Auto backoff on consecutive failures (exponential)' : '连续失败自动退避（指数）'}
                    </Label>
                  </div>
                  <div className="flex items-center gap-2">
                    <Switch checked={autoPauseOnRisk} onCheckedChange={setAutoPauseOnRisk} disabled={batchRunning} />
                    <Label className="text-xs cursor-pointer flex items-center gap-1">
                      <ShieldAlert className="h-3 w-3 text-amber-500" />
                      {isEn ? 'Auto pause on risk control' : '风控触发自动暂停'}
                    </Label>
                  </div>
                  {/* C3: 高级配置 */}
                  <div className="w-full flex items-center gap-3 text-xs flex-wrap pt-2 border-t border-dashed">
                    <span className="text-muted-foreground">{isEn ? 'Advanced:' : '高级:'}</span>
                    <div className="flex items-center gap-1">
                      <span className="text-muted-foreground">{isEn ? 'Burst cap' : '突发上限'}</span>
                      <Input
                        type="number" min={1} max={100}
                        value={burstSize}
                        onChange={(e) => { const v = parseInt(e.target.value, 10); if (!isNaN(v) && v >= 1) setBurstSize(v) }}
                        disabled={batchRunning}
                        className="w-16 h-7 text-xs text-center"
                      />
                    </div>
                    <div className="flex items-center gap-1">
                      <span className="text-muted-foreground">{isEn ? 'Backoff start' : '退避起始'}</span>
                      <Input
                        type="number" min={1} max={300}
                        value={backoffBaseSec}
                        onChange={(e) => { const v = parseInt(e.target.value, 10); if (!isNaN(v) && v >= 1) setBackoffBaseSec(v) }}
                        disabled={batchRunning}
                        className="w-16 h-7 text-xs text-center"
                      />
                      <span className="text-muted-foreground">{isEn ? 'sec' : '秒'}</span>
                    </div>
                    <div className="flex items-center gap-1">
                      <span className="text-muted-foreground">{isEn ? 'Backoff cap' : '退避上限'}</span>
                      <Input
                        type="number" min={1} max={3600}
                        value={backoffMaxSec}
                        onChange={(e) => { const v = parseInt(e.target.value, 10); if (!isNaN(v) && v >= 1) setBackoffMaxSec(v) }}
                        disabled={batchRunning}
                        className="w-20 h-7 text-xs text-center"
                      />
                      <span className="text-muted-foreground">{isEn ? 'sec' : '秒'}</span>
                    </div>
                  </div>
                </>
              )}
              {!rateLimitEnabled && (
                <span className="text-xs text-muted-foreground">
                  {isEn
                    ? 'When enabled, a token bucket paces launches and auto-extends intervals on consecutive failures to avoid risk control.'
                    : '开启后会以令牌桶控制启动节奏，连续失败时自动延长间隔，防风控'}
                </span>
              )}
            </div>

            {/* 运行中：实时速率 + 风控信号 */}
            {batchRunning && rateSnapshot && (
              <div className={cn(
                'p-3 rounded-lg border space-y-2 transition-colors',
                rateSnapshot.riskWarning
                  ? 'bg-red-50 dark:bg-red-950/20 border-red-300 dark:border-red-800'
                  : (rateSnapshot.backoffRemainingMs > 0
                    ? 'bg-amber-50 dark:bg-amber-950/20 border-amber-300 dark:border-amber-800'
                    : 'bg-blue-50 dark:bg-blue-950/20 border-blue-200 dark:border-blue-800')
              )}>
                <div className="flex items-center gap-2">
                  {rateSnapshot.riskWarning ? (
                    <>
                      <ShieldAlert className="h-4 w-4 text-red-500 animate-pulse" />
                      <span className="text-sm font-medium text-red-600 dark:text-red-400">
                        {isEn ? 'Risk warning: success rate too low' : '风控警告：成功率过低'} ({Math.round(rateSnapshot.successRate * 100)}%)
                      </span>
                    </>
                  ) : rateSnapshot.backoffRemainingMs > 0 ? (
                    <>
                      <Clock className="h-4 w-4 text-amber-500" />
                      <span className="text-sm font-medium text-amber-600 dark:text-amber-400">
                        {isEn ? `Backing off: resuming in ${Math.ceil(rateSnapshot.backoffRemainingMs / 1000)}s` : `退避中：等待 ${Math.ceil(rateSnapshot.backoffRemainingMs / 1000)}s 后恢复`}
                      </span>
                    </>
                  ) : (
                    <>
                      <Activity className="h-4 w-4 text-blue-500" />
                      <span className="text-sm font-medium text-blue-600 dark:text-blue-400">{isEn ? 'Running' : '运行中'}</span>
                    </>
                  )}
                </div>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs">
                  <div className="flex items-center gap-1.5">
                    <span className="text-muted-foreground">{isEn ? 'Throughput:' : '吞吐:'}</span>
                    <span className="font-mono tabular-nums">{rateSnapshot.throughputPerMinute}/min</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="text-muted-foreground">{isEn ? 'Success rate:' : '成功率:'}</span>
                    <span className={cn(
                      'font-mono tabular-nums font-medium',
                      rateSnapshot.successRate >= 0.8 ? 'text-green-600' :
                      rateSnapshot.successRate >= 0.5 ? 'text-amber-600' : 'text-red-600'
                    )}>{Math.round(rateSnapshot.successRate * 100)}%</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="text-muted-foreground">{isEn ? 'Window:' : '窗口:'}</span>
                    <span className="font-mono tabular-nums">
                      <span className="text-green-600">✓{rateSnapshot.windowSuccess}</span>
                      <span className="text-muted-foreground mx-0.5">/</span>
                      <span className="text-red-500">✗{rateSnapshot.windowFailed}</span>
                    </span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="text-muted-foreground">{isEn ? 'Consec. fails:' : '连续失败:'}</span>
                    <span className={cn(
                      'font-mono tabular-nums',
                      rateSnapshot.consecutiveFailures >= 3 ? 'text-red-600 font-medium' : ''
                    )}>{rateSnapshot.consecutiveFailures}</span>
                  </div>
                </div>
              </div>
            )}

            {/* 失败重试面板（仅有失败时显示） */}
            {!batchRunning && batchFail > 0 && batchItems.some(it => it.status === 'failed' || it.status === 'import_failed') && (() => {
              // 按错误类型分桶
              const buckets: Record<string, number> = { network: 0, otp_timeout: 0, email_used: 0, rate_limit: 0, risk_control: 0, auth: 0, unknown: 0 }
              for (const it of batchItems) {
                if (it.status !== 'failed' && it.status !== 'import_failed') continue
                const k = classifyError(it.error)
                buckets[k] = (buckets[k] || 0) + 1
              }
              const labels: Record<string, string> = isEn ? {
                network: 'Network error',
                otp_timeout: 'OTP timeout',
                email_used: 'Email in use',
                rate_limit: 'Rate limited',
                risk_control: 'AWS risk control',
                auth: 'Auth error',
                unknown: 'Other/Unknown'
              } : {
                network: '网络错误',
                otp_timeout: '验证码超时',
                email_used: '邮箱已占用',
                rate_limit: '限流',
                risk_control: 'AWS 风控',
                auth: '认证错误',
                unknown: '其它/未知'
              }
              return (
                <div className="p-3 bg-amber-50 dark:bg-amber-950/20 border border-amber-200 dark:border-amber-800 rounded-lg space-y-2">
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4 text-amber-600" />
                    <span className="text-sm font-medium">{isEn ? `${batchFail} tasks failed` : `${batchFail} 个任务失败`}</span>
                    <Button size="sm" variant="default" className="ml-auto" onClick={() => retryFailed('all')}>
                      <RefreshCw className="h-3.5 w-3.5 mr-1" />
                      {isEn ? 'Retry all' : '全部重试'}
                    </Button>
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {Object.entries(buckets).filter(([, c]) => c > 0).map(([k, c]) => (
                      <button
                        key={k}
                        type="button"
                        onClick={() => retryFailed(k as 'network' | 'otp_timeout' | 'rate_limit' | 'all')}
                        className="px-2 py-0.5 rounded text-[10px] bg-amber-100 dark:bg-amber-900/40 text-amber-900 dark:text-amber-100 hover:bg-amber-200 dark:hover:bg-amber-900/60 transition-colors"
                        title={isEn ? 'Click to retry this category' : '点击重试该类失败'}
                      >
                        {labels[k]} ({c})
                      </button>
                    ))}
                  </div>
                </div>
              )
            })()}

            {/* 进度 + 每项状态 */}
            {(batchRunning || batchDone > 0) && (
              <div className="space-y-3">
                <div className="flex items-center gap-4 text-sm">
                  <span className="font-medium">{t('register.batchProgress')}: {batchDone}/{batchCount}</span>
                  <Badge variant="outline" className="text-green-600 border-green-200 bg-green-50 dark:bg-green-950/30">{t('register.batchSuccess')}: {batchSuccess}</Badge>
                  <Badge variant="outline" className="text-red-600 border-red-200 bg-red-50 dark:bg-red-950/30">{t('register.batchFail')}: {batchFail}</Badge>
                </div>
                <Progress value={batchCount > 0 ? (batchDone / batchCount) * 100 : 0} className="h-2" />

                {/* 每项状态列表 */}
                {batchItems.length > 0 && (
                  <div className="max-h-60 overflow-y-auto border rounded-lg bg-muted/20">
                    {batchItems.map((item) => <BatchItemRow key={item.id} item={item} t={t} batchClock={batchClock} />)}
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* 结果 */}
      {result && (
        <Card className={cn('border shadow-sm',
          result.status === 'success' ? 'bg-green-50 dark:bg-green-950/20 border-green-200 dark:border-green-800' : 'bg-red-50 dark:bg-red-950/20 border-red-200 dark:border-red-800'
        )}>
          <CardContent className="pt-5 space-y-3">
            <div className="flex items-center gap-2">
              {result.status === 'success' ? (
                <div className="p-1.5 rounded-full bg-green-100 dark:bg-green-900/50">
                  <CheckCircle2 className="h-5 w-5 text-green-600" />
                </div>
              ) : (
                <div className="p-1.5 rounded-full bg-red-100 dark:bg-red-900/50">
                  <XCircle className="h-5 w-5 text-red-600" />
                </div>
              )}
              <h3 className="text-lg font-semibold">
                {result.status === 'success' ? t('register.success') : t('register.failed')}
              </h3>
            </div>

            {result.status === 'success' && (
              <>
                <div className="grid grid-cols-2 gap-3 text-sm p-3 bg-background/50 rounded-lg">
                  <div><span className="text-muted-foreground">{t('register.emailField')}</span> <span className="font-mono font-medium">{result.email}</span></div>
                  <div><span className="text-muted-foreground">{t('register.passwordField')}</span> <span className="font-mono font-medium">{result.password}</span></div>
                </div>
                <Button
                  onClick={importAccount}
                  disabled={imported}
                  variant={imported ? 'outline' : 'default'}
                  className={imported ? 'text-green-600 border-green-300' : ''}
                  size="sm"
                >
                  {imported ? (
                    <><CheckCircle2 className="h-4 w-4 mr-2" />{t('register.imported')}</>
                  ) : (
                    <><UserPlus className="h-4 w-4 mr-2" />{t('register.importToManager')}</>
                  )}
                </Button>
              </>
            )}

            {result.status === 'failed' && (
              <p className="text-sm text-red-600 dark:text-red-400">{result.error}</p>
            )}
          </CardContent>
        </Card>
      )}

      {/* 注册结果分析报表（视觉升级版） */}
      {history.length >= 5 && <RegisterAnalyticsReport history={history} />}

      {/* 占用邮箱黑名单管理 */}
      <EmailBlacklistManager />

      {/* 注册历史 */}
      {history.length > 0 && (
        <Card className="overflow-hidden">
          <CardHeader className="py-3 border-b">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm flex items-center gap-2">
                <Clock className="h-4 w-4 text-primary" />
                {t('register.historyTitle')} ({history.length})
              </CardTitle>
              <Button variant="ghost" size="sm" onClick={() => setHistory([])}>
                <Trash2 className="h-3.5 w-3.5 mr-1" />
                {t('register.historyClear')}
              </Button>
            </div>
          </CardHeader>
          <CardContent className="p-0">
            <div className="max-h-48 overflow-y-auto">
              {history.map((item) => {
                const fp = item.result?.fingerprint
                return (
                  <div key={item.id} className="flex items-center justify-between px-4 py-2.5 border-b last:border-b-0 hover:bg-muted/50 transition-colors">
                    <div className="flex items-center gap-3 flex-1 min-w-0">
                      {item.status === 'success' ? <CheckCircle2 className="h-4 w-4 text-green-500 flex-shrink-0" /> : <XCircle className="h-4 w-4 text-red-500 flex-shrink-0" />}
                      <span className="font-mono text-xs truncate">{item.email}</span>
                      <span className="text-xs text-muted-foreground flex-shrink-0">{new Date(item.time).toLocaleTimeString()}</span>
                      {/* 指纹摘要徽章（B7） */}
                      {fp && (
                        <span
                          className="text-[9px] text-muted-foreground bg-muted px-1.5 py-0.5 rounded font-mono flex-shrink-0 cursor-help"
                          title={`Chrome ${fp.chromeVer}\nUA: ${fp.ua}\nGPU: ${fp.gpuVendor} ${fp.gpuModel}\nCanvas: ${fp.canvasHash}\nScreen: ${fp.screen.width}x${fp.screen.height}\nProxy: ${fp.proxyUrl || '(direct)'}\nExit IP: ${fp.exitIP || 'N/A'}`}
                        >
                          🔒 {fp.chromeVer.split('.')[0]}・{fp.screen.width}×{fp.screen.height}{fp.exitIP ? `・${fp.exitIP}` : ''}
                        </span>
                      )}
                    </div>
                    {item.status === 'success' && item.result?.refreshToken && (
                      <Badge
                        variant="outline"
                        className={cn('cursor-pointer text-xs', item.imported ? 'text-green-600 border-green-200' : 'text-primary border-primary/30 hover:bg-primary/10')}
                        onClick={() => !item.imported && importHistoryItem(item)}
                      >
                        {item.imported ? t('register.imported') : t('register.historyImport')}
                      </Badge>
                    )}
                  </div>
                )
              })}
            </div>
          </CardContent>
        </Card>
      )}

    </div>
  )
}

// ============ 注册结果分析报表（视觉升级版） ============

interface RegisterAnalyticsProps {
  history: HistoryItem[]
}

function RegisterAnalyticsReport({ history }: RegisterAnalyticsProps): React.ReactNode {
  const { t } = useTranslation()
  const isEn = t('common.unknown') === 'Unknown'
  const analytics = useMemo(() => {
    const total = history.length
    let success = 0, failed = 0
    const byMode: Record<string, { success: number; failed: number }> = {}
    const byHour: Record<number, { success: number; failed: number }> = {}
    const byDay: Record<string, { success: number; failed: number }> = {}  // 7 日趋势
    const errorBuckets: Record<string, number> = {}

    const now = Date.now()
    // 准备最近 7 天的桶（含今天）
    const sevenDays: string[] = []
    for (let i = 6; i >= 0; i--) {
      const d = new Date(now - i * 86400000)
      const key = `${d.getMonth() + 1}/${d.getDate()}`
      sevenDays.push(key)
      byDay[key] = { success: 0, failed: 0 }
    }

    for (const h of history) {
      if (h.status === 'success') success++; else failed++
      const m = (h.result as { provider?: string } | undefined)?.provider || 'BuilderId'
      if (!byMode[m]) byMode[m] = { success: 0, failed: 0 }
      if (h.status === 'success') byMode[m].success++; else byMode[m].failed++
      const dt = new Date(h.time)
      const hr = dt.getHours()
      if (!byHour[hr]) byHour[hr] = { success: 0, failed: 0 }
      if (h.status === 'success') byHour[hr].success++; else byHour[hr].failed++
      // 日桶（7 天内）
      const dayKey = `${dt.getMonth() + 1}/${dt.getDate()}`
      if (byDay[dayKey]) {
        if (h.status === 'success') byDay[dayKey].success++; else byDay[dayKey].failed++
      }
      if (h.status === 'failed') {
        const cat = classifyError(h.error)
        errorBuckets[cat] = (errorBuckets[cat] || 0) + 1
      }
    }
    const successRate = total > 0 ? success / total : 0
    const peakHours = Object.entries(byHour)
      .filter(([, v]) => v.success + v.failed >= 2)  // 至少 2 个样本
      .sort((a, b) => {
        const ar = a[1].success / (a[1].success + a[1].failed)
        const br = b[1].success / (b[1].success + b[1].failed)
        return br - ar
      })
      .slice(0, 3)
    const topErrors = Object.entries(errorBuckets).sort((a, b) => b[1] - a[1])

    return { total, success, failed, successRate, byMode, byHour, byDay, sevenDays, peakHours, topErrors }
  }, [history])

  const handleExportCSV = useCallback((): void => {
    const lines = ['time,email,status,error,password']
    for (const h of history) {
      const csvEsc = (v: string | undefined): string => {
        if (!v) return ''
        const escaped = v.replace(/"/g, '""')
        return /[,"\n]/.test(escaped) ? `"${escaped}"` : escaped
      }
      lines.push([
        new Date(h.time).toISOString(),
        csvEsc(h.email),
        h.status,
        csvEsc(h.error),
        csvEsc(h.password)
      ].join(','))
    }
    const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `register-history-${new Date().toISOString().slice(0, 10)}.csv`
    a.click()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
  }, [history])

  const errorLabels: Record<string, { label: string; color: string }> = {
    network: { label: isEn ? 'Network error' : '网络错误', color: 'bg-blue-500' },
    otp_timeout: { label: isEn ? 'OTP timeout' : '验证码超时', color: 'bg-amber-500' },
    email_used: { label: isEn ? 'Email in use' : '邮箱已占用', color: 'bg-slate-500' },
    rate_limit: { label: isEn ? 'Rate limited' : '限流', color: 'bg-orange-500' },
    risk_control: { label: isEn ? 'AWS risk control' : 'AWS 风控', color: 'bg-red-500' },
    auth: { label: isEn ? 'Auth error' : '认证错误', color: 'bg-purple-500' },
    unknown: { label: isEn ? 'Other/Unknown' : '其它/未知', color: 'bg-gray-500' }
  }

  const successColor = analytics.successRate >= 0.85 ? '#22c55e'
    : analytics.successRate >= 0.6 ? '#f59e0b' : '#ef4444'

  // SVG 圆环图参数
  const ringRadius = 36
  const ringStroke = 8
  const ringCircum = 2 * Math.PI * ringRadius
  const ringOffset = ringCircum * (1 - analytics.successRate)

  return (
    <Card className="hover-lift overflow-hidden">
      <CardHeader className="pb-2 bg-gradient-to-br from-primary/5 to-transparent">
        <CardTitle className="text-sm flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-primary/10">
            <Activity className="h-4 w-4 text-primary" />
          </div>
          <span>{isEn ? 'Registration Analytics' : '注册结果分析报表'}</span>
          <Badge variant="outline" className="text-[10px] ml-auto">
            {isEn ? 'Samples' : '样本'} {analytics.total}
          </Badge>
          <Button
            size="sm"
            variant="ghost"
            className="h-6 text-[10px] -mr-1"
            onClick={handleExportCSV}
          >
            <Download className="h-3 w-3 mr-1" />
            CSV
          </Button>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4 pt-4">
        {/* 顶部：圆环图 + 关键指标 */}
        <div className="grid grid-cols-1 md:grid-cols-[140px_1fr] gap-4 items-center">
          {/* 圆环图 */}
          <div className="relative flex items-center justify-center">
            <svg width="120" height="120" viewBox="0 0 100 100">
              {/* 底圈 */}
              <circle
                cx="50" cy="50" r={ringRadius}
                fill="none"
                stroke="currentColor"
                strokeWidth={ringStroke}
                opacity="0.1"
              />
              {/* 成功率圈 */}
              <circle
                cx="50" cy="50" r={ringRadius}
                fill="none"
                stroke={successColor}
                strokeWidth={ringStroke}
                strokeLinecap="round"
                strokeDasharray={ringCircum}
                strokeDashoffset={ringOffset}
                transform="rotate(-90 50 50)"
                className="transition-all duration-700"
              />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <div className="text-2xl font-bold tabular-nums" style={{ color: successColor }}>
                {Math.round(analytics.successRate * 100)}%
              </div>
              <div className="text-[10px] text-muted-foreground">{isEn ? 'Success rate' : '成功率'}</div>
            </div>
          </div>

          {/* 关键指标 */}
          <div className="grid grid-cols-2 gap-2">
            <div className="p-3 rounded-lg bg-green-500/5 border border-green-500/20">
              <div className="flex items-center justify-between">
                <span className="text-[10px] text-muted-foreground">{isEn ? 'Success' : '成功'}</span>
                <CheckCircle2 className="h-3 w-3 text-green-500" />
              </div>
              <div className="text-xl font-bold tabular-nums text-green-600 mt-0.5">{analytics.success}</div>
            </div>
            <div className="p-3 rounded-lg bg-red-500/5 border border-red-500/20">
              <div className="flex items-center justify-between">
                <span className="text-[10px] text-muted-foreground">{isEn ? 'Failed' : '失败'}</span>
                <XCircle className="h-3 w-3 text-red-500" />
              </div>
              <div className="text-xl font-bold tabular-nums text-red-600 mt-0.5">{analytics.failed}</div>
            </div>
            <div className="p-3 rounded-lg bg-blue-500/5 border border-blue-500/20 col-span-2">
              <div className="flex items-center justify-between mb-1">
                <span className="text-[10px] text-muted-foreground flex items-center gap-1">
                  <Clock className="h-3 w-3" />
                  {isEn ? 'Top 3 success hours' : '高成功率时段 TOP3'}
                </span>
              </div>
              {analytics.peakHours.length === 0 ? (
                <p className="text-xs text-muted-foreground">{isEn ? 'Not enough data' : '样本不足'}</p>
              ) : (
                <div className="flex gap-2">
                  {analytics.peakHours.map(([h, v]) => {
                    const sr = Math.round(v.success / (v.success + v.failed) * 100)
                    return (
                      <div key={h} className="flex-1 text-center">
                        <div className="text-sm font-bold font-mono">{h.padStart(2, '0')}:00</div>
                        <div className="text-[10px] text-green-600 font-mono">{sr}%</div>
                      </div>
                    )
                  })}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* 24 小时分布（SVG 平滑曲线 + 渐变填充） */}
        <div>
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-medium">{isEn ? '24-hour distribution' : '24 小时分布'}</span>
            <div className="flex items-center gap-3 text-[10px] text-muted-foreground">
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-green-500" /> {isEn ? 'Success' : '成功'}
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-red-500" /> {isEn ? 'Failed' : '失败'}
              </span>
            </div>
          </div>
          <HourDistributionChart byHour={analytics.byHour} />
        </div>

        {/* 7 日趋势 */}
        <div>
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-medium">{isEn ? '7-day trend' : '7 日趋势'}</span>
            <span className="text-[10px] text-muted-foreground">{isEn ? 'Registrations' : '注册数'}</span>
          </div>
          <SevenDayChart sevenDays={analytics.sevenDays} byDay={analytics.byDay} />
        </div>

        {/* 失败原因分布（精致版） */}
        {analytics.topErrors.length > 0 && (
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-medium">{isEn ? 'Failure reasons' : '失败原因分布'}</span>
              <span className="text-[10px] text-muted-foreground">{isEn ? `${analytics.failed} failures total` : `共 ${analytics.failed} 次失败`}</span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              {analytics.topErrors.map(([cat, count]) => {
                const meta = errorLabels[cat] || { label: cat, color: 'bg-gray-500' }
                const pct = Math.round((count / analytics.failed) * 100)
                return (
                  <div key={cat} className="p-2 rounded-lg border bg-card hover:bg-muted/30 transition-colors">
                    <div className="flex items-center gap-2 mb-1">
                      <div className={cn('w-2 h-2 rounded-full', meta.color)} />
                      <span className="text-xs font-medium flex-1 truncate">{meta.label}</span>
                      <span className="text-xs font-mono tabular-nums text-muted-foreground">{count}</span>
                    </div>
                    <div className="h-1.5 bg-muted rounded-full overflow-hidden">
                      <div className={cn('h-full transition-all', meta.color)} style={{ width: `${pct}%` }} />
                    </div>
                    <div className="text-right text-[10px] text-muted-foreground tabular-nums mt-0.5">{pct}%</div>
                  </div>
                )
              })}
            </div>
          </div>
        )}

        {/* 登录方式对比 */}
        {Object.keys(analytics.byMode).length > 1 && (
          <div>
            <div className="text-xs font-medium mb-2">{isEn ? 'Mode comparison' : '登录方式对比'}</div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
              {Object.entries(analytics.byMode).map(([m, v]) => {
                const tot = v.success + v.failed
                const sr = tot > 0 ? Math.round(v.success / tot * 100) : 0
                const srColor = sr >= 80 ? 'text-green-600' : sr >= 50 ? 'text-amber-600' : 'text-red-600'
                const srBg = sr >= 80 ? 'bg-green-500' : sr >= 50 ? 'bg-amber-500' : 'bg-red-500'
                return (
                  <div key={m} className="p-3 rounded-lg border bg-card">
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="text-xs font-medium">{m}</span>
                      <span className={cn('text-xs font-mono tabular-nums font-bold', srColor)}>{sr}%</span>
                    </div>
                    <div className="h-1 bg-muted rounded-full overflow-hidden">
                      <div className={cn('h-full', srBg)} style={{ width: `${sr}%` }} />
                    </div>
                    <div className="text-[10px] text-muted-foreground mt-1">
                      ✓{v.success} / ✗{v.failed} ({isEn ? 'total' : '共'} {tot})
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

/** 24 小时分布 SVG 图（平滑曲线 + 渐变填充） */
function HourDistributionChart({ byHour }: { byHour: Record<number, { success: number; failed: number }> }): React.ReactNode {
  const width = 720, height = 100, padTop = 8, padBottom = 18, padX = 12
  const innerH = height - padTop - padBottom
  const stepX = (width - padX * 2) / 23  // 24 个点

  // 计算最大值
  let maxVal = 0
  for (let h = 0; h < 24; h++) {
    const v = byHour[h] || { success: 0, failed: 0 }
    maxVal = Math.max(maxVal, v.success + v.failed)
  }
  if (maxVal === 0) maxVal = 1

  const pointAt = (h: number, count: number): [number, number] => {
    const x = padX + h * stepX
    const y = padTop + innerH - (count / maxVal) * innerH
    return [x, y]
  }

  // 生成两条平滑路径
  const buildPath = (key: 'success' | 'failed'): { line: string; area: string } => {
    const points: [number, number][] = []
    for (let h = 0; h < 24; h++) {
      const v = byHour[h] || { success: 0, failed: 0 }
      points.push(pointAt(h, v[key]))
    }
    // 平滑曲线（Catmull-Rom 转 Bezier）
    let line = `M${points[0][0]},${points[0][1]}`
    for (let i = 0; i < points.length - 1; i++) {
      const p0 = points[i === 0 ? i : i - 1]
      const p1 = points[i]
      const p2 = points[i + 1]
      const p3 = points[i + 2 < points.length ? i + 2 : i + 1]
      const cp1x = p1[0] + (p2[0] - p0[0]) / 6
      const cp1y = p1[1] + (p2[1] - p0[1]) / 6
      const cp2x = p2[0] - (p3[0] - p1[0]) / 6
      const cp2y = p2[1] - (p3[1] - p1[1]) / 6
      line += ` C${cp1x},${cp1y} ${cp2x},${cp2y} ${p2[0]},${p2[1]}`
    }
    // 闭合下方区域
    const area = line + ` L${padX + 23 * stepX},${padTop + innerH} L${padX},${padTop + innerH} Z`
    return { line, area }
  }

  const succ = buildPath('success')
  const fail = buildPath('failed')

  return (
    <svg width="100%" viewBox={`0 0 ${width} ${height}`} className="overflow-visible" preserveAspectRatio="none">
      <defs>
        <linearGradient id="succGradient" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="rgb(34 197 94)" stopOpacity="0.35" />
          <stop offset="100%" stopColor="rgb(34 197 94)" stopOpacity="0" />
        </linearGradient>
        <linearGradient id="failGradient" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="rgb(239 68 68)" stopOpacity="0.3" />
          <stop offset="100%" stopColor="rgb(239 68 68)" stopOpacity="0" />
        </linearGradient>
      </defs>

      {/* 网格 */}
      {[0.25, 0.5, 0.75].map((p) => (
        <line
          key={p}
          x1={padX} x2={width - padX}
          y1={padTop + innerH * p} y2={padTop + innerH * p}
          stroke="currentColor" strokeOpacity="0.06" strokeDasharray="2,3"
        />
      ))}

      {/* 失败区域和线 */}
      <path d={fail.area} fill="url(#failGradient)" />
      <path d={fail.line} fill="none" stroke="rgb(239 68 68)" strokeWidth="1.5" opacity="0.8" />

      {/* 成功区域和线 */}
      <path d={succ.area} fill="url(#succGradient)" />
      <path d={succ.line} fill="none" stroke="rgb(34 197 94)" strokeWidth="2" />

      {/* 数据点 */}
      {Array.from({ length: 24 }).map((_, h) => {
        const v = byHour[h] || { success: 0, failed: 0 }
        if (v.success === 0 && v.failed === 0) return null
        return (
          <g key={h}>
            {v.success > 0 && (() => {
              const [x, y] = pointAt(h, v.success)
              return <circle cx={x} cy={y} r="2.5" fill="rgb(34 197 94)" />
            })()}
            {v.failed > 0 && (() => {
              const [x, y] = pointAt(h, v.failed)
              return <circle cx={x} cy={y} r="2" fill="rgb(239 68 68)" />
            })()}
          </g>
        )
      })}

      {/* X 轴刻度 */}
      {[0, 6, 12, 18, 23].map((h) => {
        const x = padX + h * stepX
        return (
          <g key={h}>
            <line x1={x} x2={x} y1={padTop + innerH} y2={padTop + innerH + 3} stroke="currentColor" opacity="0.3" />
            <text x={x} y={height - 4} fontSize="9" fill="currentColor" opacity="0.5" textAnchor="middle">
              {h.toString().padStart(2, '0')}:00
            </text>
          </g>
        )
      })}
    </svg>
  )
}

/** 7 日趋势柱状图（叠加 + 渐变） */
function SevenDayChart({ sevenDays, byDay }: {
  sevenDays: string[]
  byDay: Record<string, { success: number; failed: number }>
}): React.ReactNode {
  const width = 720, height = 80, padTop = 8, padBottom = 18, padX = 16
  const innerH = height - padTop - padBottom
  const barW = (width - padX * 2) / sevenDays.length * 0.6
  const gap = (width - padX * 2) / sevenDays.length

  let maxTotal = 0
  for (const k of sevenDays) {
    const v = byDay[k] || { success: 0, failed: 0 }
    maxTotal = Math.max(maxTotal, v.success + v.failed)
  }
  if (maxTotal === 0) maxTotal = 1

  return (
    <svg width="100%" viewBox={`0 0 ${width} ${height}`} className="overflow-visible" preserveAspectRatio="none">
      <defs>
        <linearGradient id="barSuccGrad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="rgb(34 197 94)" stopOpacity="1" />
          <stop offset="100%" stopColor="rgb(34 197 94)" stopOpacity="0.6" />
        </linearGradient>
        <linearGradient id="barFailGrad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="rgb(239 68 68)" stopOpacity="1" />
          <stop offset="100%" stopColor="rgb(239 68 68)" stopOpacity="0.6" />
        </linearGradient>
      </defs>

      {/* 网格 */}
      {[0.5].map((p) => (
        <line
          key={p}
          x1={padX} x2={width - padX}
          y1={padTop + innerH * p} y2={padTop + innerH * p}
          stroke="currentColor" strokeOpacity="0.06" strokeDasharray="2,3"
        />
      ))}

      {sevenDays.map((day, i) => {
        const v = byDay[day] || { success: 0, failed: 0 }
        const total = v.success + v.failed
        const totalH = (total / maxTotal) * innerH
        const succH = total > 0 ? (v.success / total) * totalH : 0
        const failH = total > 0 ? (v.failed / total) * totalH : 0
        const x = padX + i * gap + (gap - barW) / 2
        const yBase = padTop + innerH

        return (
          <g key={day}>
            {/* 失败（上面） */}
            {v.failed > 0 && (
              <rect
                x={x} y={yBase - totalH}
                width={barW} height={failH}
                fill="url(#barFailGrad)"
                rx="2"
              />
            )}
            {/* 成功（下面） */}
            {v.success > 0 && (
              <rect
                x={x} y={yBase - succH}
                width={barW} height={succH}
                fill="url(#barSuccGrad)"
                rx="2"
              />
            )}
            {/* 总数标签 */}
            {total > 0 && (
              <text
                x={x + barW / 2}
                y={yBase - totalH - 3}
                fontSize="9"
                fill="currentColor"
                opacity="0.6"
                textAnchor="middle"
              >
                {total}
              </text>
            )}
            {/* X 轴标签 */}
            <text
              x={x + barW / 2}
              y={height - 4}
              fontSize="10"
              fill="currentColor"
              opacity={i === sevenDays.length - 1 ? 1 : 0.5}
              fontWeight={i === sevenDays.length - 1 ? 'bold' : 'normal'}
              textAnchor="middle"
            >
              {day}
            </text>
          </g>
        )
      })}
    </svg>
  )
}

/**
 * 占用邮箱黑名单管理（A5 边缘修复）
 * 用户可以查看 / 搜索 / 删除单个 / 清空黑名单中的邮箱
 */
function EmailBlacklistManager(): React.ReactNode {
  const { t } = useTranslation()
  const isEn = t('common.unknown') === 'Unknown'
  const [expanded, setExpanded] = useState(false)
  const [items, setItems] = useState<string[]>(() => Array.from(loadEmailBlacklist()))
  const [filter, setFilter] = useState('')

  const refresh = useCallback((): void => {
    setItems(Array.from(loadEmailBlacklist()))
  }, [])

  const removeOne = useCallback((email: string): void => {
    const set = loadEmailBlacklist()
    set.delete(email.toLowerCase())
    saveEmailBlacklist(set)
    refresh()
  }, [refresh])

  const clearAll = useCallback((): void => {
    if (!confirm(isEn ? `Clear all ${items.length} emails from blacklist?` : `确定清空黑名单中的 ${items.length} 个邮箱？`)) return
    clearEmailBlacklist()
    refresh()
  }, [items.length, refresh, isEn])

  const filtered = useMemo(() => {
    if (!filter.trim()) return items
    const q = filter.toLowerCase()
    return items.filter((e) => e.includes(q))
  }, [items, filter])

  if (items.length === 0 && !expanded) return null

  return (
    <Card className="hover-lift">
      <CardHeader className="pb-2">
        <button
          type="button"
          onClick={() => { setExpanded(!expanded); if (!expanded) refresh() }}
          className="w-full flex items-center justify-between"
        >
          <CardTitle className="text-sm flex items-center gap-2">
            <XCircle className="h-4 w-4 text-amber-500" />
            {isEn ? 'Used-email blacklist' : '占用邮箱黑名单'}
            <Badge variant="outline" className="text-[10px]">{items.length}</Badge>
          </CardTitle>
          <span className="text-xs text-muted-foreground">{expanded ? (isEn ? '▼ Collapse' : '▼ 收起') : (isEn ? '▶ Expand' : '▶ 展开')}</span>
        </button>
      </CardHeader>
      {expanded && (
        <CardContent className="space-y-2">
          <div className="flex items-center gap-2">
            <Input
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder={isEn ? 'Search email...' : '搜索邮箱...'}
              className="h-8 text-xs max-w-xs"
            />
            <Button size="sm" variant="ghost" onClick={refresh}>
              <RefreshCw className="h-3.5 w-3.5 mr-1" /> {isEn ? 'Refresh' : '刷新'}
            </Button>
            <Button
              size="sm"
              variant="ghost"
              className="text-destructive ml-auto"
              onClick={clearAll}
              disabled={items.length === 0}
            >
              <Trash2 className="h-3.5 w-3.5 mr-1" /> {isEn ? 'Clear all' : '全部清空'}
            </Button>
          </div>

          {items.length === 0 ? (
            <div className="py-6 text-center text-xs text-muted-foreground">
              {isEn ? 'Blacklist is empty' : '黑名单为空'}
            </div>
          ) : filtered.length === 0 ? (
            <div className="py-4 text-center text-xs text-muted-foreground">
              {isEn ? 'No matches' : '无匹配项'}
            </div>
          ) : (
            <div className="max-h-60 overflow-y-auto border rounded">
              {filtered.map((email) => (
                <div
                  key={email}
                  className="flex items-center justify-between gap-2 px-2 py-1 border-b last:border-b-0 hover:bg-muted/40 text-xs"
                >
                  <span className="font-mono truncate flex-1" title={email}>{email}</span>
                  <button
                    onClick={() => removeOne(email)}
                    className="p-1 rounded hover:bg-destructive/10 text-destructive"
                    title={isEn ? 'Remove from blacklist' : '从黑名单移除'}
                  >
                    <Trash2 className="h-3 w-3" />
                  </button>
                </div>
              ))}
            </div>
          )}

          <p className="text-[10px] text-muted-foreground italic">
            黑名单基于注册失败时的「email_used」错误自动添加。被加入的邮箱在后续批量注册时会被跳过。
            如果 Kiro 释放了过期邮箱，可在此手动移除让它重新参与注册。
          </p>
        </CardContent>
      )}
    </Card>
  )
}
