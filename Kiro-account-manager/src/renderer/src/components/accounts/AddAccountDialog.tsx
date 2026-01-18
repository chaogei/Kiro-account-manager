import { useState, useEffect, useRef } from 'react'
import { Button, Card, CardContent, CardHeader, CardTitle, Input, Label } from '../ui'
import { useAccountsStore } from '@/store/accounts'
import { useTranslation } from '@/hooks/useTranslation'
import type { SubscriptionType } from '@/types/account'
import { X, Loader2, Download, Copy, Check, ExternalLink, Info, EyeOff } from 'lucide-react'

interface AddAccountDialogProps {
  isOpen: boolean
  onClose: () => void
}

interface BonusData {
  code: string
  name: string
  current: number
  limit: number
  expiresAt?: string
}

interface VerifiedData {
  email: string
  userId: string
  accessToken: string
  refreshToken: string
  expiresIn?: number
  subscriptionType: string
  subscriptionTitle: string
  subscription?: {
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
    bonuses?: BonusData[]
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

type ImportMode = 'oidc' | 'sso' | 'login'
type LoginType = 'builderid' | 'google' | 'github' | 'iamsso'

export function AddAccountDialog({ isOpen, onClose }: AddAccountDialogProps): React.ReactNode {
  const { addAccount, accounts, batchImportConcurrency, loginPrivateMode } = useAccountsStore()

  // 检查账户是否已存在（同邮箱+同provider 或 同userId 才算重复）
  const isAccountExists = (email: string, userId: string, provider?: string): boolean => {
    return Array.from(accounts.values()).some(acc => {
      // userId 相同则重复
      if (acc.userId === userId) return true
      // email 相同且 provider 相同则重复（允许同邮箱不同登录方式）
      if (acc.email === email && acc.credentials.provider === provider) return true
      return false
    })
  }

  // 导入模式
  const [importMode, setImportMode] = useState<ImportMode>('login')

  // OIDC 凭证输入
  const [refreshToken, setRefreshToken] = useState('')
  const [clientId, setClientId] = useState('')
  const [clientSecret, setClientSecret] = useState('')
  const [region, setRegion] = useState('us-east-1')
  const [authMethod, setAuthMethod] = useState<'IdC' | 'social'>('IdC')
  const [provider, setProvider] = useState('BuilderId')  // 'BuilderId', 'Enterprise', 'Github', 'Google'

  // SSO Token 导入
  const [ssoToken, setSsoToken] = useState('')
  const [batchImportResult, setBatchImportResult] = useState<{ total: number; success: number; failed: number; errors: string[] } | null>(null)

  // OIDC 批量导入
  const [oidcImportMode, setOidcImportMode] = useState<'single' | 'batch'>('single')
  const [oidcBatchData, setOidcBatchData] = useState('')
  const [oidcBatchImportResult, setOidcBatchImportResult] = useState<{ total: number; success: number; failed: number; errors: string[] } | null>(null)

  // 验证后的数据（保留用于条件渲染）
  const [verifiedData, setVerifiedData] = useState<VerifiedData | null>(null)

  // 状态
  const [isVerifying, setIsVerifying] = useState(false)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const { t } = useTranslation()
  const isEn = t('common.unknown') === 'Unknown'

  // 登录相关状态
  const [loginType, setLoginType] = useState<LoginType>('builderid')
  const [isLoggingIn, setIsLoggingIn] = useState(false)
  const [usePrivateMode, setUsePrivateMode] = useState(loginPrivateMode) // 临时隐私模式开关，默认跟随全局设置
  const [builderIdLoginData, setBuilderIdLoginData] = useState<{
    userCode: string
    verificationUri: string
    expiresIn: number
    interval: number
  } | null>(null)
  const [copied, setCopied] = useState(false)
  const pollIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null)
  
  // IAM SSO 登录相关状态
  const [ssoStartUrl, setSsoStartUrl] = useState('')
  const [iamSsoLoginData, setIamSsoLoginData] = useState<{
    userCode: string
    verificationUri: string
    expiresIn: number
    interval: number
  } | null>(null)

  // 清理轮询
  useEffect(() => {
    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current)
      }
    }
  }, [])

  // 监听 Social Auth 回调
  useEffect(() => {
    if (!isLoggingIn || loginType === 'builderid') return

    const unsubscribe = window.api.onSocialAuthCallback(async (data) => {
      console.log('[AddAccountDialog] Social auth callback:', data)
      
      if (data.error) {
        setError(`登录失败: ${data.error}`)
        setIsLoggingIn(false)
        return
      }

      if (data.code && data.state) {
        try {
          const result = await window.api.exchangeSocialToken(data.code, data.state)
          if (result.success) {
            await handleLoginSuccess({
              accessToken: result.accessToken!,
              refreshToken: result.refreshToken!,
              authMethod: 'social',
              provider: result.provider
            })
          } else {
            setError(result.error || 'Token 交换失败')
          }
        } catch (e) {
          setError(e instanceof Error ? e.message : '登录失败')
        } finally {
          setIsLoggingIn(false)
        }
      }
    })

    return () => unsubscribe()
  }, [isLoggingIn, loginType])

  // 处理登录成功
  const handleLoginSuccess = async (tokenData: {
    accessToken: string
    refreshToken: string
    clientId?: string
    clientSecret?: string
    region?: string
    authMethod?: string
    provider?: string
  }) => {
    console.log('[AddAccountDialog] Login successful, verifying credentials...')
    
    try {
      // 验证凭证并获取账号信息
      const result = await window.api.verifyAccountCredentials({
        refreshToken: tokenData.refreshToken,
        clientId: tokenData.clientId || '',
        clientSecret: tokenData.clientSecret || '',
        region: tokenData.region || 'us-east-1',
        authMethod: tokenData.authMethod,
        provider: tokenData.provider
      })

      if (result.success && result.data) {
        const { email, userId } = result.data
        const providerName = tokenData.provider || 'BuilderId'
        
        // 检查账户是否已存在
        if (isAccountExists(email, userId, providerName)) {
          setError(isEn ? 'This account already exists' : '该账号已存在，无需重复添加')
          return
        }
        
        // 添加账号
        const now = Date.now()
        addAccount({
          email,
          userId,
          nickname: email ? email.split('@')[0] : undefined,
          idp: providerName as 'BuilderId' | 'Google' | 'Github',
          credentials: {
            accessToken: result.data.accessToken,
            csrfToken: '',
            refreshToken: result.data.refreshToken,
            clientId: tokenData.clientId || '',
            clientSecret: tokenData.clientSecret || '',
            region: tokenData.region || 'us-east-1',
            expiresAt: result.data.expiresIn ? now + result.data.expiresIn * 1000 : now + 3600 * 1000,
            authMethod: tokenData.authMethod as 'IdC' | 'social',
            provider: (tokenData.provider || 'BuilderId') as 'BuilderId' | 'Github' | 'Google'
          },
          subscription: {
            type: result.data.subscriptionType as SubscriptionType,
            title: result.data.subscriptionTitle,
            rawType: result.data.subscription?.rawType,
            daysRemaining: result.data.daysRemaining,
            expiresAt: result.data.expiresAt,
            managementTarget: result.data.subscription?.managementTarget,
            upgradeCapability: result.data.subscription?.upgradeCapability,
            overageCapability: result.data.subscription?.overageCapability
          },
          usage: {
            current: result.data.usage.current,
            limit: result.data.usage.limit,
            percentUsed: result.data.usage.limit > 0 
              ? result.data.usage.current / result.data.usage.limit 
              : 0,
            lastUpdated: now,
            baseLimit: result.data.usage.baseLimit,
            baseCurrent: result.data.usage.baseCurrent,
            freeTrialLimit: result.data.usage.freeTrialLimit,
            freeTrialCurrent: result.data.usage.freeTrialCurrent,
            freeTrialExpiry: result.data.usage.freeTrialExpiry,
            bonuses: result.data.usage.bonuses,
            nextResetDate: result.data.usage.nextResetDate,
            resourceDetail: result.data.usage.resourceDetail
          },
          groupId: undefined,
          tags: [],
          status: 'active',
          lastUsedAt: now
        })

        resetForm()
        onClose()
      } else {
        setError(result.error || '验证失败')
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : '添加账号失败')
    }
  }

  // 启动 Builder ID 登录
  const handleStartBuilderIdLogin = async () => {
    setIsLoggingIn(true)
    setError(null)
    setBuilderIdLoginData(null)

    try {
      const result = await window.api.startBuilderIdLogin(region)
      
      if (result.success && result.userCode && result.verificationUri) {
        setBuilderIdLoginData({
          userCode: result.userCode,
          verificationUri: result.verificationUri,
          expiresIn: result.expiresIn || 600,
          interval: result.interval || 5
        })

        // 打开浏览器
        window.api.openExternal(result.verificationUri)

        // 开始轮询
        startPolling(result.interval || 5)
      } else {
        setError(result.error || '启动登录失败')
        setIsLoggingIn(false)
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : '启动登录失败')
      setIsLoggingIn(false)
    }
  }

  // 启动 IAM SSO 登录
  const handleStartIamSsoLogin = async () => {
    if (!ssoStartUrl.trim()) {
      setError(isEn ? 'Please enter SSO Start URL' : '请输入 SSO Start URL')
      return
    }
    
    setIsLoggingIn(true)
    setError(null)
    setIamSsoLoginData(null)

    try {
      const result = await window.api.startIamSsoLogin(ssoStartUrl.trim(), region)
      
      if (result.success && result.userCode && result.verificationUri) {
        setIamSsoLoginData({
          userCode: result.userCode,
          verificationUri: result.verificationUri,
          expiresIn: result.expiresIn || 600,
          interval: result.interval || 5
        })

        // 打开浏览器
        window.api.openExternal(result.verificationUri)

        // 开始轮询
        startIamSsoPolling(result.interval || 5)
      } else {
        setError(result.error || (isEn ? 'Failed to start login' : '启动登录失败'))
        setIsLoggingIn(false)
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : (isEn ? 'Failed to start login' : '启动登录失败'))
      setIsLoggingIn(false)
    }
  }

  // 开始轮询 IAM SSO 授权
  const startIamSsoPolling = (interval: number) => {
    if (pollIntervalRef.current) {
      clearInterval(pollIntervalRef.current)
    }

    pollIntervalRef.current = setInterval(async () => {
      try {
        const result = await window.api.pollIamSsoAuth(region)
        
        if (!result.success) {
          setError(result.error || (isEn ? 'Authorization failed' : '授权失败'))
          setIsLoggingIn(false)
          setIamSsoLoginData(null)
          if (pollIntervalRef.current) {
            clearInterval(pollIntervalRef.current)
            pollIntervalRef.current = null
          }
          return
        }

        if (result.completed) {
          if (pollIntervalRef.current) {
            clearInterval(pollIntervalRef.current)
            pollIntervalRef.current = null
          }
          
          await handleLoginSuccess({
            accessToken: result.accessToken!,
            refreshToken: result.refreshToken!,
            clientId: result.clientId,
            clientSecret: result.clientSecret,
            region: result.region,
            authMethod: 'IdC',
            provider: 'IAM_SSO'
          })
          
          setIsLoggingIn(false)
          setIamSsoLoginData(null)
        }
        // 如果是 pending 或 slow_down，继续轮询
      } catch (e) {
        console.error('[AddAccountDialog] IAM SSO Poll error:', e)
      }
    }, interval * 1000)
  }

  // 开始轮询 Builder ID 授权
  const startPolling = (interval: number) => {
    if (pollIntervalRef.current) {
      clearInterval(pollIntervalRef.current)
    }

    pollIntervalRef.current = setInterval(async () => {
      try {
        const result = await window.api.pollBuilderIdAuth(region)
        
        if (!result.success) {
          setError(result.error || '授权失败')
          setIsLoggingIn(false)
          setBuilderIdLoginData(null)
          if (pollIntervalRef.current) {
            clearInterval(pollIntervalRef.current)
            pollIntervalRef.current = null
          }
          return
        }

        if (result.completed) {
          if (pollIntervalRef.current) {
            clearInterval(pollIntervalRef.current)
            pollIntervalRef.current = null
          }
          
          await handleLoginSuccess({
            accessToken: result.accessToken!,
            refreshToken: result.refreshToken!,
            clientId: result.clientId,
            clientSecret: result.clientSecret,
            region: result.region,
            authMethod: 'IdC',
            provider: 'BuilderId'
          })
          
          setIsLoggingIn(false)
          setBuilderIdLoginData(null)
        }
        // 如果是 pending 或 slow_down，继续轮询
      } catch (e) {
        console.error('[AddAccountDialog] Poll error:', e)
      }
    }, interval * 1000)
  }

  // 取消登录
  const handleCancelLogin = async () => {
    if (pollIntervalRef.current) {
      clearInterval(pollIntervalRef.current)
      pollIntervalRef.current = null
    }

    if (loginType === 'builderid') {
      await window.api.cancelBuilderIdLogin()
    } else if (loginType === 'iamsso') {
      await window.api.cancelIamSsoLogin()
    } else {
      await window.api.cancelSocialLogin()
    }

    setIsLoggingIn(false)
    setBuilderIdLoginData(null)
    setIamSsoLoginData(null)
    setError(null)
  }

  // 启动 Social Auth 登录 (Google/GitHub)
  const handleStartSocialLogin = async (socialProvider: 'Google' | 'Github') => {
    setIsLoggingIn(true)
    setError(null)

    try {
      const result = await window.api.startSocialLogin(socialProvider, usePrivateMode)
      
      if (!result.success) {
        setError(result.error || '启动登录失败')
        setIsLoggingIn(false)
      }
      // 成功后等待回调
    } catch (e) {
      setError(e instanceof Error ? e.message : '启动登录失败')
      setIsLoggingIn(false)
    }
  }

  // 复制 user_code
  const handleCopyUserCode = async () => {
    if (builderIdLoginData?.userCode) {
      await navigator.clipboard.writeText(builderIdLoginData.userCode)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }

  // 从本地配置导入
  const handleImportFromLocal = async () => {
    try {
      const result = await window.api.loadKiroCredentials()
      if (result.success && result.data) {
        setRefreshToken(result.data.refreshToken)
        setClientId(result.data.clientId)
        setClientSecret(result.data.clientSecret)
        setRegion(result.data.region)
        setAuthMethod(result.data.authMethod as 'IdC' | 'social' || 'IdC')
        setProvider(result.data.provider || 'BuilderId')
        setError(null)
      } else {
        setError(result.error || '导入失败')
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : '导入失败')
    }
  }

  // 从 SSO Token 导入并添加账号（支持批量）
  const handleSsoImport = async () => {
    if (!ssoToken.trim()) {
      setError('请输入 x-amz-sso_authn 的值')
      return
    }

    // 解析多个 Token（每行一个）
    const tokens = ssoToken
      .split('\n')
      .map(t => t.trim())
      .filter(t => t.length > 0)

    if (tokens.length === 0) {
      setError('请输入至少一个 Token')
      return
    }

    setIsVerifying(true)
    setError(null)
    setBatchImportResult(null)

    const importResult = { total: tokens.length, success: 0, failed: 0, errors: [] as string[], failedIndices: [] as number[] }

    // 单个 Token 导入函数
    const importSingleToken = async (token: string, index: number): Promise<void> => {
      try {
        const result = await window.api.importFromSsoToken(token, region)
        
        if (result.success && result.data) {
          const { email, userId } = result.data
          
          // 检查账户是否已存在（已存在的也从输入框中移除）
          if (email && userId && isAccountExists(email, userId, 'BuilderId')) {
            importResult.errors.push(`#${index + 1}: ${email} ${isEn ? 'already exists' : '已存在'}`)
            return
          }
          
          // 添加账号
          const now = Date.now()
          addAccount({
            email: email || '',
            userId: userId || '',
            nickname: email ? email.split('@')[0] : undefined,
            idp: 'BuilderId',
            credentials: {
              accessToken: result.data.accessToken,
              csrfToken: '',
              refreshToken: result.data.refreshToken,
              clientId: result.data.clientId,
              clientSecret: result.data.clientSecret,
              region: result.data.region,
              expiresAt: result.data.expiresIn ? now + result.data.expiresIn * 1000 : now + 3600 * 1000
            },
            subscription: {
              type: (result.data.subscriptionType || 'Free') as SubscriptionType,
              title: result.data.subscriptionTitle || 'KIRO',
              daysRemaining: result.data.daysRemaining,
              managementTarget: result.data.subscription?.managementTarget,
              upgradeCapability: result.data.subscription?.upgradeCapability,
              overageCapability: result.data.subscription?.overageCapability
            },
            usage: {
              current: result.data.usage?.current || 0,
              limit: result.data.usage?.limit || 0,
              percentUsed: (result.data.usage?.limit || 0) > 0 
                ? (result.data.usage?.current || 0) / (result.data.usage?.limit || 1) 
                : 0,
              lastUpdated: now,
              baseLimit: result.data.usage?.baseLimit,
              baseCurrent: result.data.usage?.baseCurrent,
              freeTrialLimit: result.data.usage?.freeTrialLimit,
              freeTrialCurrent: result.data.usage?.freeTrialCurrent,
              freeTrialExpiry: result.data.usage?.freeTrialExpiry,
              bonuses: result.data.usage?.bonuses,
              nextResetDate: result.data.usage?.nextResetDate,
              resourceDetail: result.data.usage?.resourceDetail
            },
            groupId: undefined,
            tags: [],
            status: 'active',
            lastUsedAt: now
          })
          
          importResult.success++
        } else {
          importResult.failed++
          importResult.failedIndices.push(index)
          importResult.errors.push(`#${index + 1}: ${result.error?.message || '导入失败'}`)
        }
      } catch (e) {
        importResult.failed++
        importResult.failedIndices.push(index)
        importResult.errors.push(`#${index + 1}: ${e instanceof Error ? e.message : '导入失败'}`)
      }
    }

    try {
      // 并发控制：使用配置的并发数，避免 API 限流
      const BATCH_SIZE = batchImportConcurrency
      for (let i = 0; i < tokens.length; i += BATCH_SIZE) {
        const batch = tokens.slice(i, i + BATCH_SIZE)
        await Promise.allSettled(
          batch.map((token, batchIndex) => importSingleToken(token, i + batchIndex))
        )
        // 批次间添加短暂延迟
        if (i + BATCH_SIZE < tokens.length) {
          await new Promise(resolve => setTimeout(resolve, 100))
        }
      }
      
      setBatchImportResult(importResult)
      
      // 如果全部成功，关闭弹窗
      if (importResult.failed === 0) {
        resetForm()
        onClose()
      } else {
        // 保留失败的 Token 在输入框中
        const failedTokens = importResult.failedIndices.map(i => tokens[i])
        if (failedTokens.length > 0) {
          setSsoToken(failedTokens.join('\n'))
        }
        if (importResult.success > 0) {
          setError(`成功导入 ${importResult.success} 个，失败 ${importResult.failed} 个`)
        } else {
          setError(`全部导入失败 (${importResult.failed} 个)`)
        }
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'SSO 导入失败')
    } finally {
      setIsVerifying(false)
    }
  }

  // OIDC 批量导入
  const handleOidcBatchAdd = async () => {
    if (!oidcBatchData.trim()) {
      setError('请输入凭证数据')
      return
    }

    // 解析 JSON 数据
    let credentials: Array<{
      refreshToken: string
      clientId?: string
      clientSecret?: string
      region?: string
      authMethod?: 'IdC' | 'social'
      provider?: string
    }>

    try {
      const parsed = JSON.parse(oidcBatchData.trim())
      credentials = Array.isArray(parsed) ? parsed : [parsed]
    } catch {
      setError('JSON 格式错误，请检查输入')
      return
    }

    if (credentials.length === 0) {
      setError('请输入至少一个凭证')
      return
    }

    setIsSubmitting(true)
    setError(null)
    setOidcBatchImportResult(null)

    const importResult = { total: credentials.length, success: 0, failed: 0, errors: [] as string[], failedIndices: [] as number[] }

    // 单个凭证导入函数
    const importSingleCredential = async (cred: typeof credentials[0], index: number): Promise<void> => {
      try {
        if (!cred.refreshToken) {
          importResult.failed++
          importResult.failedIndices.push(index)
          importResult.errors.push(`#${index + 1}: 缺少 refreshToken`)
          return
        }

        // 根据 provider 自动确定 authMethod
        const credProvider = cred.provider || 'BuilderId'
        const credAuthMethod = cred.authMethod || ((credProvider === 'BuilderId' || credProvider === 'Enterprise') ? 'IdC' : 'social')

        const result = await window.api.verifyAccountCredentials({
          refreshToken: cred.refreshToken,
          clientId: cred.clientId || '',
          clientSecret: cred.clientSecret || '',
          region: cred.region || 'us-east-1',
          authMethod: credAuthMethod,
          provider: credProvider
        })

        if (result.success && result.data) {
          const { email, userId } = result.data
          const provider = (cred.provider || 'BuilderId') as 'BuilderId' | 'Enterprise' | 'Github' | 'Google'
          
          if (isAccountExists(email, userId, provider)) {
            // 已存在的不记入失败，也从输入框中移除
            importResult.errors.push(`#${index + 1}: ${email} ${isEn ? 'already exists' : '已存在'}`)
            return
          }
          
          // 根据 provider 确定 idp 和 authMethod
          const idpMap: Record<string, 'BuilderId' | 'Enterprise' | 'Github' | 'Google'> = {
            'BuilderId': 'BuilderId',
            'Enterprise': 'Enterprise',
            'Github': 'Github',
            'Google': 'Google'
          }
          const idp = idpMap[provider] || 'BuilderId'
          // GitHub 和 Google 使用 social 认证方式，BuilderId 和 Enterprise 使用 IdC
          const authMethod = cred.authMethod || ((provider === 'BuilderId' || provider === 'Enterprise') ? 'IdC' : 'social')
          
          const now = Date.now()
          addAccount({
            email,
            userId,
            nickname: email ? email.split('@')[0] : undefined,
            idp,
            credentials: {
              accessToken: result.data.accessToken,
              csrfToken: '',
              refreshToken: result.data.refreshToken,
              clientId: cred.clientId || '',
              clientSecret: cred.clientSecret || '',
              region: cred.region || 'us-east-1',
              expiresAt: result.data.expiresIn ? now + result.data.expiresIn * 1000 : now + 3600 * 1000,
              authMethod,
              provider
            },
            subscription: {
              type: result.data.subscriptionType as SubscriptionType,
              title: result.data.subscriptionTitle,
              daysRemaining: result.data.daysRemaining,
              expiresAt: result.data.expiresAt,
              managementTarget: result.data.subscription?.managementTarget,
              upgradeCapability: result.data.subscription?.upgradeCapability,
              overageCapability: result.data.subscription?.overageCapability
            },
            usage: {
              current: result.data.usage.current,
              limit: result.data.usage.limit,
              percentUsed: result.data.usage.limit > 0 
                ? result.data.usage.current / result.data.usage.limit 
                : 0,
              lastUpdated: now,
              baseLimit: result.data.usage.baseLimit,
              baseCurrent: result.data.usage.baseCurrent,
              freeTrialLimit: result.data.usage.freeTrialLimit,
              freeTrialCurrent: result.data.usage.freeTrialCurrent,
              freeTrialExpiry: result.data.usage.freeTrialExpiry,
              bonuses: result.data.usage.bonuses,
              nextResetDate: result.data.usage.nextResetDate,
              resourceDetail: result.data.usage.resourceDetail
            },
            groupId: undefined,
            tags: [],
            status: 'active',
            lastUsedAt: now
          })
          
          importResult.success++
        } else {
          importResult.failed++
          importResult.failedIndices.push(index)
          const err = result.error as { message?: string } | string | undefined
          const errorMsg = typeof err === 'object' ? (err?.message || '验证失败') : (err || '验证失败')
          importResult.errors.push(`#${index + 1}: ${errorMsg}`)
        }
      } catch (e) {
        importResult.failed++
        importResult.failedIndices.push(index)
        importResult.errors.push(`#${index + 1}: ${e instanceof Error ? e.message : '导入失败'}`)
      }
    }

    try {
      // 并发控制：使用配置的并发数，避免 API 限流
      const BATCH_SIZE = batchImportConcurrency
      for (let i = 0; i < credentials.length; i += BATCH_SIZE) {
        const batch = credentials.slice(i, i + BATCH_SIZE)
        await Promise.allSettled(
          batch.map((cred, batchIndex) => importSingleCredential(cred, i + batchIndex))
        )
        // 批次间添加短暂延迟，进一步避免限流
        if (i + BATCH_SIZE < credentials.length) {
          await new Promise(resolve => setTimeout(resolve, 100))
        }
      }
      
      setOidcBatchImportResult(importResult)
      
      if (importResult.failed === 0) {
        resetForm()
        onClose()
      } else {
        // 保留失败的凭证在输入框中
        const failedCredentials = importResult.failedIndices.map(i => credentials[i])
        if (failedCredentials.length > 0) {
          setOidcBatchData(JSON.stringify(failedCredentials, null, 2))
        }
        if (importResult.success > 0) {
          setError(`成功导入 ${importResult.success} 个，失败 ${importResult.failed} 个`)
        } else {
          setError(`全部导入失败 (${importResult.failed} 个)`)
        }
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'OIDC 批量导入失败')
    } finally {
      setIsSubmitting(false)
    }
  }

  // OIDC 凭证添加账号（验证并添加）
  const handleOidcAdd = async () => {
    if (!refreshToken) {
      setError('请填写 Refresh Token')
      return
    }
    // 社交登录不需要 clientId 和 clientSecret
    if (authMethod !== 'social' && (!clientId || !clientSecret)) {
      setError('请填写 Client ID 和 Client Secret')
      return
    }

    setIsSubmitting(true)
    setError(null)

    try {
      const result = await window.api.verifyAccountCredentials({
        refreshToken,
        clientId,
        clientSecret,
        region,
        authMethod,
        provider
      })

      if (result.success && result.data) {
        const { email, userId } = result.data
        const providerName = provider || 'BuilderId'
        
        // 检查账户是否已存在
        if (isAccountExists(email, userId, providerName)) {
          setError(isEn ? 'This account already exists' : '该账号已存在，无需重复添加')
          return
        }
        
        // 直接添加账号
        const now = Date.now()
        addAccount({
          email,
          userId,
          nickname: email ? email.split('@')[0] : undefined,
          idp: providerName as 'BuilderId' | 'Github' | 'Google',
          credentials: {
            accessToken: result.data.accessToken,
            csrfToken: '',
            refreshToken: result.data.refreshToken,
            clientId,
            clientSecret,
            region,
            expiresAt: result.data.expiresIn ? now + result.data.expiresIn * 1000 : now + 3600 * 1000,
            authMethod,
            provider: (provider || 'BuilderId') as 'BuilderId' | 'Github' | 'Google'
          },
          subscription: {
            type: result.data.subscriptionType as SubscriptionType,
            title: result.data.subscriptionTitle,
            daysRemaining: result.data.daysRemaining,
            expiresAt: result.data.expiresAt,
            managementTarget: result.data.subscription?.managementTarget,
            upgradeCapability: result.data.subscription?.upgradeCapability,
            overageCapability: result.data.subscription?.overageCapability
          },
          usage: {
            current: result.data.usage.current,
            limit: result.data.usage.limit,
            percentUsed: result.data.usage.limit > 0 
              ? result.data.usage.current / result.data.usage.limit 
              : 0,
            lastUpdated: now,
            baseLimit: result.data.usage.baseLimit,
            baseCurrent: result.data.usage.baseCurrent,
            freeTrialLimit: result.data.usage.freeTrialLimit,
            freeTrialCurrent: result.data.usage.freeTrialCurrent,
            freeTrialExpiry: result.data.usage.freeTrialExpiry,
            bonuses: result.data.usage.bonuses,
            nextResetDate: result.data.usage.nextResetDate,
            resourceDetail: result.data.usage.resourceDetail
          },
          groupId: undefined,
          tags: [],
          status: 'active',
          lastUsedAt: now
        })

        resetForm()
        onClose()
      } else {
        setError(result.error || '验证失败')
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : '添加失败')
    } finally {
      setIsSubmitting(false)
    }
  }

  const resetForm = () => {
    setImportMode('login')
    setRefreshToken('')
    setClientId('')
    setClientSecret('')
    setRegion('us-east-1')
    setAuthMethod('IdC')
    setProvider('BuilderId')
    setSsoToken('')
    setVerifiedData(null)
    setError(null)
    // 清理登录状态
    setLoginType('builderid')
    setIsLoggingIn(false)
    setBuilderIdLoginData(null)
    setCopied(false)
    if (pollIntervalRef.current) {
      clearInterval(pollIntervalRef.current)
      pollIntervalRef.current = null
    }
  }

  if (!isOpen) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/50" onClick={onClose} />

      <Card className="relative w-full max-w-lg max-h-[90vh] overflow-auto z-10">
        <CardHeader className="pb-4 border-b">
          <div className="flex flex-row items-center justify-between">
            <CardTitle className="text-xl font-bold">{isEn ? 'Add Account' : '添加账号'}</CardTitle>
            <Button variant="ghost" size="icon" className="h-8 w-8 rounded-full hover:bg-muted" onClick={onClose}>
              <X className="h-4 w-4" />
            </Button>
          </div>
          <p className="text-sm text-muted-foreground mt-1">{isEn ? 'Choose a method to add your Kiro account' : '选择一种方式来添加您的 Kiro 账号'}</p>
        </CardHeader>

        <CardContent className="space-y-6 pt-6">
          {/* 导入模式切换 */}
          <div className="grid grid-cols-3 gap-1 p-1 bg-muted/50 rounded-xl border">
            <button
              className={`py-2 px-3 text-sm rounded-lg transition-all duration-200 font-medium ${
                importMode === 'login' 
                  ? 'bg-background text-foreground shadow-sm ring-1 ring-black/5' 
                  : 'text-muted-foreground hover:text-foreground hover:bg-background/50'
              }`}
              onClick={() => { setImportMode('login'); setError(null) }}
              disabled={!!verifiedData || isLoggingIn}
            >
              {isEn ? 'Login' : '在线登录'}
            </button>
            <button
              className={`py-2 px-3 text-sm rounded-lg transition-all duration-200 font-medium ${
                importMode === 'oidc' 
                  ? 'bg-background text-foreground shadow-sm ring-1 ring-black/5' 
                  : 'text-muted-foreground hover:text-foreground hover:bg-background/50'
              }`}
              onClick={() => { setImportMode('oidc'); setError(null) }}
              disabled={!!verifiedData || isLoggingIn}
            >
              {isEn ? 'OIDC Token' : 'OIDC 凭证'}
            </button>
            <button
              className={`py-2 px-3 text-sm rounded-lg transition-all duration-200 font-medium ${
                importMode === 'sso' 
                  ? 'bg-background text-foreground shadow-sm ring-1 ring-black/5' 
                  : 'text-muted-foreground hover:text-foreground hover:bg-background/50'
              }`}
              onClick={() => { setImportMode('sso'); setError(null) }}
              disabled={!!verifiedData || isLoggingIn}
            >
              SSO Token
            </button>
          </div>

          {/* 登录模式 */}
          {importMode === 'login' && !verifiedData && (
            <div className="space-y-4">
              {/* 登录中状态 - Builder ID */}
              {isLoggingIn && builderIdLoginData && (
                <div className="space-y-4">
                  <div className="p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg text-center">
                    <p className="text-sm text-blue-700 dark:text-blue-300 mb-2">
                      {isEn ? 'Complete login in browser and enter this code:' : '请在浏览器中完成登录，并输入以下代码：'}
                    </p>
                    <div className="flex items-center justify-center gap-2">
                      <code className="text-2xl font-bold tracking-widest bg-white dark:bg-gray-800 px-4 py-2 rounded border">
                        {builderIdLoginData.userCode}
                      </code>
                      <Button 
                        variant="outline" 
                        size="icon"
                        onClick={handleCopyUserCode}
                        title={isEn ? 'Copy code' : '复制代码'}
                      >
                        {copied ? <Check className="h-4 w-4 text-green-500" /> : <Copy className="h-4 w-4" />}
                      </Button>
                    </div>
                    <div className="mt-3 flex items-center justify-center gap-2 text-xs text-muted-foreground">
                      <Loader2 className="h-3 w-3 animate-spin" />
                      {isEn ? 'Waiting for authorization...' : '等待授权中...'}
                    </div>
                  </div>
                  
                  <div className="flex gap-2">
                    <Button 
                      variant="outline" 
                      className="flex-1"
                      onClick={() => window.api.openExternal(builderIdLoginData.verificationUri)}
                    >
                      <ExternalLink className="h-4 w-4 mr-2" />
                      {isEn ? 'Open Browser' : '重新打开浏览器'}
                    </Button>
                    <Button 
                      variant="destructive" 
                      className="flex-1"
                      onClick={handleCancelLogin}
                    >
                      {isEn ? 'Cancel' : '取消登录'}
                    </Button>
                  </div>
                </div>
              )}

              {/* 登录中状态 - Social Auth */}
              {isLoggingIn && !builderIdLoginData && (
                <div className="space-y-4">
                  <div className="p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg text-center">
                    <Loader2 className="h-8 w-8 animate-spin mx-auto mb-2 text-blue-500" />
                    <p className="text-sm text-blue-700 dark:text-blue-300">
                      {isEn ? 'Complete login in browser...' : '请在浏览器中完成登录...'}
                    </p>
                    <p className="text-xs text-muted-foreground mt-1">
                      {isEn ? 'Will auto return after login' : '登录完成后会自动返回'}
                    </p>
                  </div>
                  
                  <Button 
                    variant="destructive" 
                    className="w-full"
                    onClick={handleCancelLogin}
                  >
                    {isEn ? 'Cancel' : '取消登录'}
                  </Button>
                </div>
              )}

              {/* 未登录状态 - 显示登录选项 */}
              {!isLoggingIn && (
                <div className="space-y-4 py-2">
                  <div className="text-center mb-6">
                    <div className="w-12 h-12 bg-primary/10 rounded-full flex items-center justify-center mx-auto mb-3">
                      <Check className="w-6 h-6 text-primary" />
                    </div>
                    <h3 className="text-lg font-semibold">{isEn ? 'Choose Login Method' : '选择登录方式'}</h3>
                    <p className="text-sm text-muted-foreground mt-1">
                      {isEn ? 'Multiple quick login options' : '支持多种方式快捷登录'}
                    </p>
                  </div>

                  {/* 隐私模式选项 */}
                  <div className="px-2">
                    <button
                      type="button"
                      onClick={() => setUsePrivateMode(!usePrivateMode)}
                      className={`w-full flex items-center justify-between px-4 py-3 rounded-xl border transition-all duration-200 ${
                        usePrivateMode 
                          ? 'bg-primary/5 border-primary/30 hover:bg-primary/10' 
                          : 'bg-muted/30 border-transparent hover:bg-muted/50'
                      }`}
                    >
                      <div className="flex items-center gap-3">
                        <div className={`w-8 h-8 rounded-full flex items-center justify-center transition-colors ${
                          usePrivateMode ? 'bg-primary/20' : 'bg-muted'
                        }`}>
                          <EyeOff className={`w-4 h-4 ${usePrivateMode ? 'text-primary' : 'text-muted-foreground'}`} />
                        </div>
                        <span className={`text-sm font-medium ${usePrivateMode ? 'text-foreground' : 'text-muted-foreground'}`}>
                          {isEn ? 'Private/Incognito Mode' : '隐私/无痕模式'}
                        </span>
                      </div>
                      <div className={`w-10 h-6 rounded-full p-1 transition-colors ${
                        usePrivateMode ? 'bg-primary' : 'bg-muted-foreground/30'
                      }`}>
                        <div className={`w-4 h-4 rounded-full bg-white shadow-sm transition-transform ${
                          usePrivateMode ? 'translate-x-4' : 'translate-x-0'
                        }`} />
                      </div>
                    </button>
                  </div>
                  
                  <div className="space-y-3 px-2">
                    {/* Google */}
                    <button 
                      className="group w-full h-14 flex items-center px-4 gap-4 bg-white dark:bg-slate-900 hover:bg-slate-50 dark:hover:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl transition-all duration-200 hover:shadow-md hover:border-primary/30"
                      onClick={() => {
                        setLoginType('google')
                        handleStartSocialLogin('Google')
                      }}
                    >
                      <div className="w-8 h-8 flex items-center justify-center bg-white rounded-full shadow-sm border p-1.5 group-hover:scale-110 transition-transform">
                        <svg viewBox="0 0 24 24" className="w-full h-full">
                          <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                          <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                          <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                          <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
                        </svg>
                      </div>
                      <div className="flex flex-col items-start">
                        <span className="text-sm font-semibold text-foreground">{isEn ? 'Google Account' : 'Google 账号'}</span>
                        <span className="text-xs text-muted-foreground">{isEn ? 'Quick login with Google' : '使用 Google 账号快捷登录'}</span>
                      </div>
                    </button>

                    {/* GitHub */}
                    <button 
                      className="group w-full h-14 flex items-center px-4 gap-4 bg-white dark:bg-slate-900 hover:bg-slate-50 dark:hover:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl transition-all duration-200 hover:shadow-md hover:border-primary/30"
                      onClick={() => {
                        setLoginType('github')
                        handleStartSocialLogin('Github')
                      }}
                    >
                      <div className="w-8 h-8 flex items-center justify-center bg-white rounded-full shadow-sm border p-1.5 group-hover:scale-110 transition-transform">
                        <svg viewBox="0 0 24 24" fill="#24292f" className="w-full h-full">
                          <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
                        </svg>
                      </div>
                      <div className="flex flex-col items-start">
                        <span className="text-sm font-semibold text-foreground">{isEn ? 'GitHub Account' : 'GitHub 账号'}</span>
                        <span className="text-xs text-muted-foreground">{isEn ? 'Quick login with GitHub' : '使用 GitHub 账号快捷登录'}</span>
                      </div>
                    </button>

                    {/* AWS Builder ID */}
                    <button 
                      className="group w-full h-14 flex items-center px-4 gap-4 bg-white dark:bg-slate-900 hover:bg-slate-50 dark:hover:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl transition-all duration-200 hover:shadow-md hover:border-primary/30"
                      onClick={() => {
                        setLoginType('builderid')
                        handleStartBuilderIdLogin()
                      }}
                    >
                      <div className="w-8 h-8 flex items-center justify-center bg-white rounded-full shadow-sm border p-1.5 group-hover:scale-110 transition-transform">
                        <svg viewBox="0 0 24 24" fill="#232f3e" className="w-full h-full">
                          <text x="0" y="17" fontSize="12" fontWeight="bold" fontFamily="Arial">aws</text>
                        </svg>
                      </div>
                      <div className="flex flex-col items-start">
                        <span className="text-sm font-semibold text-foreground">AWS Builder ID</span>
                        <span className="text-xs text-muted-foreground">{isEn ? 'Login with AWS Builder ID' : '使用 AWS Builder ID 登录'}</span>
                      </div>
                    </button>

                    {/* IAM Identity Center (Organization) */}
                    <button 
                      className="group w-full h-14 flex items-center px-4 gap-4 bg-white dark:bg-slate-900 hover:bg-slate-50 dark:hover:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl transition-all duration-200 hover:shadow-md hover:border-primary/30"
                      onClick={() => {
                        setLoginType('iamsso')
                      }}
                    >
                      <div className="w-8 h-8 flex items-center justify-center bg-white rounded-full shadow-sm border p-1.5 group-hover:scale-110 transition-transform">
                        <svg viewBox="0 0 24 24" fill="#232f3e" className="w-full h-full">
                          <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8zm-1-13h2v6h-2zm0 8h2v2h-2z"/>
                        </svg>
                      </div>
                      <div className="flex flex-col items-start">
                        <span className="text-sm font-semibold text-foreground">{isEn ? 'Organization Identity' : '组织身份'}</span>
                        <span className="text-xs text-muted-foreground">{isEn ? 'IAM Identity Center SSO' : 'IAM Identity Center SSO'}</span>
                      </div>
                    </button>
                  </div>

                  {/* IAM SSO 输入框 */}
                  {loginType === 'iamsso' && !iamSsoLoginData && (
                    <div className="space-y-4 p-4 bg-slate-50 dark:bg-slate-800/50 rounded-xl border border-slate-200 dark:border-slate-700">
                      <div className="space-y-2">
                        <Label htmlFor="ssoStartUrl" className="text-sm font-medium">{isEn ? 'SSO Start URL' : 'SSO Start URL'}</Label>
                        <Input
                          id="ssoStartUrl"
                          type="url"
                          placeholder="https://your-org.awsapps.com/start"
                          value={ssoStartUrl}
                          onChange={(e) => setSsoStartUrl(e.target.value)}
                          className="font-mono text-sm"
                        />
                        <p className="text-xs text-muted-foreground">
                          {isEn ? 'Get this from your organization admin' : '从您的组织管理员处获取'}
                        </p>
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="ssoRegion" className="text-sm font-medium">{isEn ? 'SSO Region' : 'SSO 区域'}</Label>
                        <select
                          id="ssoRegion"
                          value={region}
                          onChange={(e) => setRegion(e.target.value)}
                          className="w-full h-10 px-3 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-sm"
                        >
                          <optgroup label="US">
                            <option value="us-east-1">US East (N. Virginia)</option>
                            <option value="us-east-2">US East (Ohio)</option>
                            <option value="us-west-1">US West (N. California)</option>
                            <option value="us-west-2">US West (Oregon)</option>
                          </optgroup>
                          <optgroup label="Europe">
                            <option value="eu-west-1">Europe (Ireland)</option>
                            <option value="eu-west-2">Europe (London)</option>
                            <option value="eu-west-3">Europe (Paris)</option>
                            <option value="eu-central-1">Europe (Frankfurt)</option>
                            <option value="eu-north-1">Europe (Stockholm)</option>
                            <option value="eu-south-1">Europe (Milan)</option>
                          </optgroup>
                          <optgroup label="Asia Pacific">
                            <option value="ap-northeast-1">Asia Pacific (Tokyo)</option>
                            <option value="ap-northeast-2">Asia Pacific (Seoul)</option>
                            <option value="ap-northeast-3">Asia Pacific (Osaka)</option>
                            <option value="ap-southeast-1">Asia Pacific (Singapore)</option>
                            <option value="ap-southeast-2">Asia Pacific (Sydney)</option>
                            <option value="ap-south-1">Asia Pacific (Mumbai)</option>
                            <option value="ap-east-1">Asia Pacific (Hong Kong)</option>
                          </optgroup>
                          <optgroup label="Other">
                            <option value="ca-central-1">Canada (Central)</option>
                            <option value="sa-east-1">South America (São Paulo)</option>
                            <option value="me-south-1">Middle East (Bahrain)</option>
                            <option value="af-south-1">Africa (Cape Town)</option>
                          </optgroup>
                        </select>
                      </div>
                      <Button 
                        className="w-full"
                        onClick={handleStartIamSsoLogin}
                        disabled={!ssoStartUrl.trim() || isLoggingIn}
                      >
                        {isLoggingIn ? (isEn ? 'Starting...' : '启动中...') : (isEn ? 'Start Login' : '开始登录')}
                      </Button>
                    </div>
                  )}

                  {/* IAM SSO 授权中 */}
                  {loginType === 'iamsso' && iamSsoLoginData && (
                    <div className="space-y-4 p-4 bg-slate-50 dark:bg-slate-800/50 rounded-xl border border-slate-200 dark:border-slate-700">
                      <div className="text-center space-y-2">
                        <p className="text-sm font-medium">{isEn ? 'Enter this code in browser:' : '在浏览器中输入此代码:'}</p>
                        <div className="flex items-center justify-center gap-2">
                          <code className="px-4 py-2 bg-primary/10 text-primary font-mono text-2xl font-bold rounded-lg">
                            {iamSsoLoginData.userCode}
                          </code>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => {
                              navigator.clipboard.writeText(iamSsoLoginData.userCode)
                              setCopied(true)
                              setTimeout(() => setCopied(false), 2000)
                            }}
                          >
                            {copied ? <Check className="w-4 h-4 text-green-500" /> : <Copy className="w-4 h-4" />}
                          </Button>
                        </div>
                      </div>
                      <div className="flex items-center justify-center gap-2 text-sm text-muted-foreground">
                        <Loader2 className="w-4 h-4 animate-spin" />
                        <span>{isEn ? 'Waiting for authorization...' : '等待授权中...'}</span>
                      </div>
                      <Button 
                        variant="destructive" 
                        className="w-full"
                        onClick={handleCancelLogin}
                      >
                        {isEn ? 'Cancel' : '取消登录'}
                      </Button>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* SSO Token 导入模式 */}
          {importMode === 'sso' && !verifiedData && (
            <div className="space-y-5">
              <div className="p-4 bg-blue-50/50 dark:bg-blue-900/10 rounded-xl border border-blue-100 dark:border-blue-900/20">
                <div className="flex items-start gap-3">
                   <div className="p-2 bg-blue-100 dark:bg-blue-900/30 rounded-lg text-blue-600 dark:text-blue-400">
                      <Info className="w-4 h-4" />
                   </div>
                   <div className="flex-1">
                      <p className="text-sm font-semibold text-blue-700 dark:text-blue-300 mb-1.5">{isEn ? 'How to get Token?' : '如何获取 Token?'}</p>
                      <ol className="text-xs text-blue-600/90 dark:text-blue-400/90 list-decimal list-inside space-y-1.5">
                        <li>{isEn ? 'Visit and login:' : '在浏览器中访问并登录:'} <a href="https://view.awsapps.com/start/#/device?user_code=PQCF-FCCN/start/#/device?user_code=PQCF-FCCN" target="_blank" className="underline hover:text-blue-800 font-medium">view.awsapps.com/start/#/device?user_code=PQCF-FCCN</a></li>
                        <li>{isEn ? 'Press F12 → Application → Cookies' : '按 F12 打开开发者工具 → Application → Cookies'}</li>
                        <li>{isEn ? 'Find and copy' : '找到并复制'} <code className="px-1 py-0.5 bg-blue-100 dark:bg-blue-900/40 rounded font-mono text-[10px]">x-amz-sso_authn</code> {isEn ? 'value' : '的值'}</li>
                      </ol>
                   </div>
                </div>
              </div>
              
              <div className="space-y-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium flex items-center gap-1">
                    x-amz-sso_authn <span className="text-destructive">*</span>
                    <span className="text-xs text-muted-foreground font-normal ml-2">{isEn ? 'Supports batch import, one per line' : '支持批量导入，每行一个 Token'}</span>
                  </label>
                  <textarea
                    className="w-full min-h-[120px] px-3 py-2.5 text-sm rounded-xl border border-input bg-background/50 ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 resize-none font-mono"
                    placeholder={isEn ? 'Paste Token content, one per line&#10;eyJlbmMiOiJBMjU2...&#10;eyJlbmMiOiJBMjU2...' : '粘贴 Token 内容，每行一个&#10;eyJlbmMiOiJBMjU2...&#10;eyJlbmMiOiJBMjU2...'}
                    value={ssoToken}
                    onChange={(e) => { setSsoToken(e.target.value); setBatchImportResult(null) }}
                  />
                  {ssoToken.trim() && (
                    <p className="text-xs text-muted-foreground">
                      {isEn ? `Entered ${ssoToken.split('\n').filter(t => t.trim()).length} tokens` : `已输入 ${ssoToken.split('\n').filter(t => t.trim()).length} 个 Token`}
                    </p>
                  )}
                </div>

                <div className="space-y-2">
                  <label className="text-sm font-medium">AWS Region</label>
                  <select
                    className="w-full h-10 px-3 py-2 text-sm rounded-xl border border-input bg-background/50 ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2"
                    value={region}
                    onChange={(e) => setRegion(e.target.value)}
                  >
                    <option value="us-east-1">us-east-1 (N. Virginia)</option>
                    <option value="us-west-2">us-west-2 (Oregon)</option>
                    <option value="eu-west-1">eu-west-1 (Ireland)</option>
                  </select>
                </div>
              </div>

              {/* 批量导入结果 */}
              {batchImportResult && (
                <div className={`p-3 rounded-lg text-sm ${batchImportResult.failed > 0 ? 'bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800' : 'bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800'}`}>
                  <p className={`font-medium ${batchImportResult.failed > 0 ? 'text-amber-700 dark:text-amber-300' : 'text-green-700 dark:text-green-300'}`}>
                    {isEn ? `Result: ${batchImportResult.success}/${batchImportResult.total} succeeded` : `导入结果: 成功 ${batchImportResult.success}/${batchImportResult.total}`}
                  </p>
                  {batchImportResult.errors.length > 0 && (
                    <ul className="mt-2 text-xs text-amber-600 dark:text-amber-400 space-y-0.5 max-h-20 overflow-y-auto">
                      {batchImportResult.errors.map((err, i) => (
                        <li key={i}>{err}</li>
                      ))}
                    </ul>
                  )}
                </div>
              )}

              <Button 
                type="button" 
                className="w-full h-11 text-sm font-medium rounded-xl shadow-sm"
                onClick={handleSsoImport}
                disabled={isVerifying || !ssoToken.trim()}
              >
                {isVerifying ? (
                  <>
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    {isEn ? `Importing ${ssoToken.split('\n').filter(t => t.trim()).length} accounts...` : `正在并发导入 ${ssoToken.split('\n').filter(t => t.trim()).length} 个账号...`}
                  </>
                ) : (
                  ssoToken.split('\n').filter(t => t.trim()).length > 1 
                    ? (isEn ? `Batch import ${ssoToken.split('\n').filter(t => t.trim()).length} accounts` : `批量导入 ${ssoToken.split('\n').filter(t => t.trim()).length} 个账号`)
                    : (isEn ? 'Import & Verify' : '导入并验证')
                )}
              </Button>
            </div>
          )}

          {/* OIDC 凭证输入模式 */}
          {importMode === 'oidc' && !verifiedData && (
            <div className="space-y-5">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold">{isEn ? 'Enter OIDC Token' : '输入 OIDC 凭证'}</h3>
                <div className="flex items-center gap-2">
                  {/* 单个/批量 切换 */}
                  <div className="flex bg-muted/50 rounded-lg p-0.5">
                    <button
                      className={`px-2.5 py-1 text-xs rounded-md transition-all ${oidcImportMode === 'single' ? 'bg-background shadow-sm font-medium' : 'text-muted-foreground hover:text-foreground'}`}
                      onClick={() => { setOidcImportMode('single'); setOidcBatchImportResult(null) }}
                    >
                      {isEn ? 'Single' : '单个'}
                    </button>
                    <button
                      className={`px-2.5 py-1 text-xs rounded-md transition-all ${oidcImportMode === 'batch' ? 'bg-background shadow-sm font-medium' : 'text-muted-foreground hover:text-foreground'}`}
                      onClick={() => { setOidcImportMode('batch'); setOidcBatchImportResult(null) }}
                    >
                      {isEn ? 'Batch' : '批量'}
                    </button>
                  </div>
                  {oidcImportMode === 'single' && (
                    <Button 
                      type="button" 
                      variant="outline" 
                      size="sm"
                      className="h-7 rounded-lg text-xs"
                      onClick={handleImportFromLocal}
                    >
                      <Download className="h-3 w-3 mr-1" />
                      {isEn ? 'Import' : '本地导入'}
                    </Button>
                  )}
                </div>
              </div>

              {/* 单个导入模式 */}
              {oidcImportMode === 'single' && (
                <>
                  <div className="space-y-4">
                    {/* 登录类型选择 */}
                    <div className="space-y-2">
                      <label className="text-sm font-medium">{isEn ? 'Login Type' : '登录类型'}</label>
                      <div className="flex gap-2">
                        <button
                          type="button"
                          className={`flex-1 h-9 px-3 text-sm rounded-lg border transition-all ${authMethod === 'IdC' && provider === 'BuilderId' ? 'bg-primary text-primary-foreground border-primary' : 'bg-background border-input hover:bg-muted'}`}
                          onClick={() => {
                            setAuthMethod('IdC')
                            setProvider('BuilderId')
                          }}
                        >
                          Builder ID
                        </button>
                        <button
                          type="button"
                          className={`flex-1 h-9 px-3 text-sm rounded-lg border transition-all ${authMethod === 'IdC' && provider === 'Enterprise' ? 'bg-primary text-primary-foreground border-primary' : 'bg-background border-input hover:bg-muted'}`}
                          onClick={() => {
                            setAuthMethod('IdC')
                            setProvider('Enterprise')
                          }}
                        >
                          {isEn ? 'Organization' : '组织身份'}
                        </button>
                        <button
                          type="button"
                          className={`flex-1 h-9 px-3 text-sm rounded-lg border transition-all ${authMethod === 'social' ? 'bg-primary text-primary-foreground border-primary' : 'bg-background border-input hover:bg-muted'}`}
                          onClick={() => {
                            setAuthMethod('social')
                            setProvider('Google')
                          }}
                        >
                          Social
                        </button>
                      </div>
                      {authMethod === 'social' && (
                        <div className="space-y-2">
                          <div className="flex gap-2">
                            <button
                              type="button"
                              className={`flex-1 h-8 px-3 text-xs rounded-lg border transition-all ${provider === 'Google' ? 'bg-primary/20 text-primary border-primary/50' : 'bg-background border-input hover:bg-muted'}`}
                              onClick={() => setProvider('Google')}
                            >
                              Google
                            </button>
                            <button
                              type="button"
                              className={`flex-1 h-8 px-3 text-xs rounded-lg border transition-all ${provider === 'Github' ? 'bg-primary/20 text-primary border-primary/50' : 'bg-background border-input hover:bg-muted'}`}
                              onClick={() => setProvider('Github')}
                            >
                              GitHub
                            </button>
                          </div>
                          <p className="text-xs text-muted-foreground">
                            {isEn ? 'Social login does not require Client ID and Secret' : '社交登录不需要 Client ID 和 Client Secret'}
                          </p>
                        </div>
                      )}
                      {authMethod === 'IdC' && provider === 'Enterprise' && (
                        <p className="text-xs text-muted-foreground">
                          {isEn ? 'Organization identity (IAM Identity Center SSO)' : '组织身份（IAM Identity Center SSO）'}
                        </p>
                      )}
                    </div>

                    <div className="space-y-2">
                      <label className="text-sm font-medium">
                        Refresh Token <span className="text-destructive">*</span>
                      </label>
                      <textarea
                        className="w-full min-h-[80px] px-3 py-2.5 text-sm rounded-xl border border-input bg-background/50 ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 resize-none font-mono"
                        placeholder={isEn ? 'Paste Refresh Token...' : '粘贴 Refresh Token...'}
                        value={refreshToken}
                        onChange={(e) => setRefreshToken(e.target.value)}
                      />
                    </div>

                    {/* IdC 登录需要 Client ID、Client Secret 和 Region */}
                    {authMethod !== 'social' && (
                      <>
                        <div className="grid grid-cols-2 gap-4">
                          <div className="space-y-2">
                            <label className="text-sm font-medium">
                              Client ID <span className="text-destructive">*</span>
                            </label>
                            <input
                              type="text"
                              className="w-full h-10 px-3 py-2 text-sm rounded-xl border border-input bg-background/50 ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2 font-mono"
                              placeholder="Client ID"
                              value={clientId}
                              onChange={(e) => setClientId(e.target.value)}
                            />
                          </div>

                          <div className="space-y-2">
                            <label className="text-sm font-medium">
                              Client Secret <span className="text-destructive">*</span>
                            </label>
                            <input
                              type="password"
                              className="w-full h-10 px-3 py-2 text-sm rounded-xl border border-input bg-background/50 ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2 font-mono"
                              placeholder="Client Secret"
                              value={clientSecret}
                              onChange={(e) => setClientSecret(e.target.value)}
                            />
                          </div>
                        </div>

                        <div className="space-y-2">
                          <label className="text-sm font-medium">AWS Region</label>
                          <select
                            className="w-full h-10 px-3 py-2 text-sm rounded-xl border border-input bg-background/50 ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2"
                            value={region}
                            onChange={(e) => setRegion(e.target.value)}
                          >
                            <option value="us-east-1">us-east-1 (N. Virginia)</option>
                            <option value="us-west-2">us-west-2 (Oregon)</option>
                            <option value="eu-west-1">eu-west-1 (Ireland)</option>
                          </select>
                        </div>
                      </>
                    )}
                  </div>
                </>
              )}

              {/* 批量导入模式 */}
              {oidcImportMode === 'batch' && (
                <>
                  <div className="p-3 bg-blue-50/50 dark:bg-blue-900/10 rounded-xl border border-blue-100 dark:border-blue-900/20">
                    <p className="text-xs text-blue-600 dark:text-blue-400">
                      {isEn ? 'JSON array format. Required:' : '支持 JSON 数组格式。必填:'} <code className="px-1 bg-blue-100 dark:bg-blue-900/40 rounded">refreshToken</code>.
                      {isEn ? 'Optional:' : '可选:'} <code className="px-1 bg-blue-100 dark:bg-blue-900/40 rounded">provider</code> (BuilderId/Enterprise/Github/Google),
                      <code className="px-1 bg-blue-100 dark:bg-blue-900/40 rounded">clientId</code>,
                      <code className="px-1 bg-blue-100 dark:bg-blue-900/40 rounded">clientSecret</code>
                    </p>
                  </div>

                  <div className="space-y-2">
                    <label className="text-sm font-medium flex items-center gap-2">
                      {isEn ? 'JSON Credentials' : 'JSON 凭证数据'} <span className="text-destructive">*</span>
                    </label>
                    <textarea
                      className="w-full min-h-[180px] px-3 py-2.5 text-sm rounded-xl border border-input bg-background/50 ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 resize-none font-mono text-xs"
                      placeholder={`[
  {
    "refreshToken": "xxx",
    "clientId": "xxx",
    "clientSecret": "xxx",
    "provider": "BuilderId"
  },
  {
    "refreshToken": "yyy",
    "clientId": "yyy",
    "clientSecret": "yyy",
    "provider": "Enterprise"
  },
  {
    "refreshToken": "zzz",
    "provider": "Github"
  },
  {
    "refreshToken": "aaa",
    "provider": "Google"
  }
]`}
                      value={oidcBatchData}
                      onChange={(e) => { setOidcBatchData(e.target.value); setOidcBatchImportResult(null) }}
                    />
                    {oidcBatchData.trim() && (() => {
                      try {
                        const parsed = JSON.parse(oidcBatchData.trim())
                        const count = Array.isArray(parsed) ? parsed.length : 1
                        return <p className="text-xs text-muted-foreground">{isEn ? `Entered ${count} credentials` : `已输入 ${count} 个凭证`}</p>
                      } catch {
                        return <p className="text-xs text-destructive">{isEn ? 'Invalid JSON format' : 'JSON 格式错误'}</p>
                      }
                    })()}
                  </div>

                  {/* 批量导入结果 */}
                  {oidcBatchImportResult && (
                    <div className={`p-3 rounded-lg text-sm ${oidcBatchImportResult.failed > 0 ? 'bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800' : 'bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800'}`}>
                      <p className={`font-medium ${oidcBatchImportResult.failed > 0 ? 'text-amber-700 dark:text-amber-300' : 'text-green-700 dark:text-green-300'}`}>
                        {isEn ? `Result: ${oidcBatchImportResult.success}/${oidcBatchImportResult.total} succeeded` : `导入结果: 成功 ${oidcBatchImportResult.success}/${oidcBatchImportResult.total}`}
                      </p>
                      {oidcBatchImportResult.errors.length > 0 && (
                        <ul className="mt-2 text-xs text-amber-600 dark:text-amber-400 space-y-0.5 max-h-20 overflow-y-auto">
                          {oidcBatchImportResult.errors.map((err, i) => (
                            <li key={i}>{err}</li>
                          ))}
                        </ul>
                      )}
                    </div>
                  )}
                </>
              )}
            </div>
          )}

          {/* 错误信息 */}
          {error && (
            <div className="p-3 bg-destructive/10 text-destructive rounded-xl text-sm flex items-center gap-2 animate-in fade-in slide-in-from-top-2">
              <div className="w-1.5 h-1.5 rounded-full bg-destructive shrink-0" />
              {error}
            </div>
          )}

          {/* 提交按钮 - 只在 OIDC 模式显示 */}
          {importMode === 'oidc' && (
            <div className="flex justify-end gap-3 pt-4 border-t">
              <Button type="button" variant="outline" onClick={onClose} className="rounded-xl h-10 px-6">
                {isEn ? 'Cancel' : '取消'}
              </Button>
              {oidcImportMode === 'single' ? (
                <Button 
                  onClick={handleOidcAdd} 
                  disabled={isSubmitting || !refreshToken || (authMethod !== 'social' && (!clientId || !clientSecret))}
                  className="rounded-xl h-10 px-6"
                >
                  {isSubmitting && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                  {isEn ? 'Add Account' : '确认添加'}
                </Button>
              ) : (
                <Button 
                  onClick={handleOidcBatchAdd} 
                  disabled={isSubmitting || !oidcBatchData.trim()}
                  className="rounded-xl h-10 px-6"
                >
                  {isSubmitting ? (
                    <>
                      <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                      {isEn ? 'Importing...' : '正在并发导入...'}
                    </>
                  ) : (
                    (() => {
                      try {
                        const parsed = JSON.parse(oidcBatchData.trim())
                        const count = Array.isArray(parsed) ? parsed.length : 1
                        return isEn ? `Batch import ${count} accounts` : `批量导入 ${count} 个账号`
                      } catch {
                        return isEn ? 'Batch Import' : '批量导入'
                      }
                    })()
                  )}
                </Button>
              )}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
