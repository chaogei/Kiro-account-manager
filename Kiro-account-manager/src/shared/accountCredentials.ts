export interface AccountCredentialUpdate {
  id: string
  accessToken?: string
  refreshToken?: string
  expiresAt?: number
  profileArn?: string
}

interface CredentialAccount {
  credentials?: {
    accessToken?: string
    refreshToken?: string
    expiresAt?: number
    profileArn?: string
  }
  profileArn?: string
  status?: string
  lastError?: string
  usage?: { current?: number; limit?: number; percentUsed?: number; lastUpdated?: number }
  subscription?: object
  lastCheckedAt?: number
  email?: string
  userId?: string
}

export interface BackgroundAccountUpdate extends AccountCredentialUpdate {
  expiresIn?: number
  usage?: CredentialAccount['usage']
  subscription?: object
  status?: string
  errorMessage?: string
  userInfo?: { email?: string; userId?: string }
}

/** Persist official results even when no renderer is listening. */
export function applyBackgroundAccountUpdate<T extends CredentialAccount>(
  account: T,
  update: BackgroundAccountUpdate,
  now = Date.now()
): T {
  const next = applyAccountCredentialUpdate(account, {
    ...update,
    expiresAt: update.expiresIn ? now + update.expiresIn * 1000 : undefined
  })
  const result = { ...next, lastCheckedAt: now }
  if (update.usage) {
    const usage = { ...account.usage, ...update.usage, lastUpdated: now }
    usage.percentUsed = usage.limit ? (usage.current || 0) / usage.limit : 0
    result.usage = usage
  }
  if (update.subscription) {
    const subscription = update.subscription as { subscriptionManagementTarget?: string }
    result.subscription = {
      ...account.subscription,
      ...update.subscription,
      ...(subscription.subscriptionManagementTarget
        ? { managementTarget: subscription.subscriptionManagementTarget }
        : {})
    }
  }
  if (update.userInfo?.email) result.email = update.userInfo.email
  if (update.userInfo?.userId) result.userId = update.userInfo.userId
  if (update.status) result.status = update.status
  if (update.errorMessage) result.lastError = update.errorMessage
  else if (update.status === 'active') result.lastError = undefined
  return result
}

export interface AccountDataSnapshot {
  accounts?: Record<string, CredentialAccount>
}

function isExpiredCredentialError(error?: string): boolean {
  if (!error) return false
  // A refresh fixes stale authentication, not suspension, quota or network errors.
  if (/suspend|封禁|\b423\b/i.test(error)) return false
  return /token expired|token.*已过期|bearer token.*invalid|invalid token/i.test(error)
}

/** Apply token-only and profile-only events without discarding unrelated credentials. */
export function applyAccountCredentialUpdate<T extends CredentialAccount>(
  account: T,
  update: AccountCredentialUpdate
): T {
  if (update.expiresAt !== undefined && update.expiresAt < (account.credentials?.expiresAt || 0))
    return account

  const credentials = { ...account.credentials }
  if (update.accessToken) credentials.accessToken = update.accessToken
  if (update.refreshToken) credentials.refreshToken = update.refreshToken
  if (update.expiresAt !== undefined) credentials.expiresAt = update.expiresAt
  if (update.profileArn) credentials.profileArn = update.profileArn

  const next = { ...account, credentials }
  if (update.profileArn) next.profileArn = update.profileArn
  if (update.accessToken && isExpiredCredentialError(account.lastError)) {
    next.status = 'active'
    next.lastError = undefined
  }
  return next
}

/** Keep account edits/deletions, but don't let an old renderer save roll back a refresh. */
export function preserveNewerAccountCredentials<T extends AccountDataSnapshot>(
  incoming: T,
  persisted?: AccountDataSnapshot | null
): T {
  if (!incoming?.accounts || !persisted?.accounts) return incoming
  const accounts = { ...incoming.accounts }
  for (const [id, account] of Object.entries(accounts)) {
    const saved = persisted.accounts[id]
    if ((saved?.usage?.lastUpdated || 0) > (account.usage?.lastUpdated || 0)) {
      accounts[id] = { ...account, usage: saved.usage, subscription: saved.subscription }
    }
    if (
      !saved ||
      !saved.credentials?.accessToken ||
      (saved.credentials.expiresAt || 0) <= (account.credentials?.expiresAt || 0)
    )
      continue
    accounts[id] = applyAccountCredentialUpdate(accounts[id], {
      id,
      ...saved.credentials,
      profileArn: saved.profileArn || saved.credentials.profileArn
    })
  }
  return { ...incoming, accounts }
}
