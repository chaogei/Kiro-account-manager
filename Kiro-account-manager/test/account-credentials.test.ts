import assert from 'node:assert/strict'
import { test } from 'node:test'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  applyAccountCredentialUpdate,
  preserveNewerAccountCredentials
} from '../src/shared/accountCredentials.ts'

const original = {
  nickname: 'Original',
  status: 'error',
  lastError: 'HTTP 403: The bearer token included in the request is invalid.',
  credentials: {
    accessToken: 'expired-access',
    refreshToken: 'old-refresh',
    expiresAt: 100,
    clientId: 'keep-client',
    clientSecret: 'keep-secret',
    region: 'us-east-1'
  }
}
const refresh = {
  id: 'account',
  accessToken: 'new-access',
  refreshToken: 'rotated-refresh',
  expiresAt: 200
}

test('token-only refresh updates the global account state without a profile ARN', () => {
  const updated = applyAccountCredentialUpdate(original, refresh)
  assert.equal(updated.credentials.accessToken, 'new-access')
  assert.equal(updated.credentials.refreshToken, 'rotated-refresh')
  assert.equal(updated.status, 'active')
  assert.equal(updated.lastError, undefined)
  assert.equal(updated.credentials.clientSecret, 'keep-secret')
  assert.equal(original.credentials.accessToken, 'expired-access')
})

test('a refresh survives an old renderer save and a restart', () => {
  const directory = mkdtempSync(join(tmpdir(), 'kiro-credentials-'))
  try {
    const file = join(directory, 'accounts.json')
    const snapshot = { language: 'en', accounts: { account: original } }
    const refreshed = {
      ...snapshot,
      accounts: { account: applyAccountCredentialUpdate(original, refresh) }
    }
    writeFileSync(file, JSON.stringify(refreshed))
    // A still-mounted page changes a nickname using its pre-refresh snapshot.
    const staleSave = {
      ...snapshot,
      language: 'zh',
      accounts: {
        account: { ...original, nickname: 'Edited while refreshing' }
      }
    }
    const saved = preserveNewerAccountCredentials(staleSave, JSON.parse(readFileSync(file, 'utf8')))
    writeFileSync(file, JSON.stringify(saved))
    // Closing can send the original snapshot again; it must not roll credentials back.
    const onQuit = preserveNewerAccountCredentials(saved, JSON.parse(readFileSync(file, 'utf8')))
    writeFileSync(file, JSON.stringify(onQuit))
    const restarted = JSON.parse(readFileSync(file, 'utf8'))
    assert.equal(restarted.accounts.account.credentials.accessToken, 'new-access')
    assert.equal(restarted.accounts.account.credentials.refreshToken, 'rotated-refresh')
    assert.equal(restarted.accounts.account.credentials.expiresAt, 200)
    assert.equal(restarted.accounts.account.status, 'active')
    assert.equal(restarted.accounts.account.nickname, 'Edited while refreshing')
    assert.equal(restarted.language, 'zh')
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
})

test('missing optional refresh token keeps the existing refresh token', () => {
  const updated = applyAccountCredentialUpdate(original, {
    id: 'account',
    accessToken: 'new-access',
    expiresAt: 200
  })
  assert.equal(updated.credentials.refreshToken, 'old-refresh')
})

test('profile-only updates preserve tokens and authentication errors', () => {
  const updated = applyAccountCredentialUpdate(original, {
    id: 'account',
    profileArn: 'profile-arn'
  })
  assert.equal(updated.profileArn, 'profile-arn')
  assert.equal(updated.credentials.profileArn, 'profile-arn')
  assert.equal(updated.credentials.accessToken, 'expired-access')
  assert.equal(updated.lastError, original.lastError)
})

test('out-of-order token events cannot replace a newer token pair', () => {
  const current = applyAccountCredentialUpdate(original, refresh)
  assert.equal(
    applyAccountCredentialUpdate(current, {
      ...refresh,
      accessToken: 'older-access',
      expiresAt: 150
    }),
    current
  )
})

test('successful refresh does not clear suspension, quota or network errors', () => {
  for (const error of [
    'AccountSuspendedException',
    'TEMPORARILY_SUSPENDED: invalid token',
    'HTTP 429 quota exceeded',
    'fetch failed'
  ]) {
    const updated = applyAccountCredentialUpdate({ ...original, lastError: error }, refresh)
    assert.equal(updated.status, 'error')
    assert.equal(updated.lastError, error)
  }
})

test('old renderer saves cannot recreate deleted accounts or erase unrelated edits', () => {
  const persisted = { accounts: { account: applyAccountCredentialUpdate(original, refresh) } }
  const incoming = { accounts: {}, language: 'zh' }
  assert.deepEqual(preserveNewerAccountCredentials(incoming, persisted), incoming)
})

test('newer or equal-expiry incoming credentials are retained', () => {
  const current = { accounts: { account: applyAccountCredentialUpdate(original, refresh) } }
  const incoming = {
    accounts: {
      account: applyAccountCredentialUpdate(original, {
        ...refresh,
        accessToken: 'manual-login',
        expiresAt: 300
      })
    }
  }
  assert.equal(
    preserveNewerAccountCredentials(incoming, current).accounts.account.credentials.accessToken,
    'manual-login'
  )
  assert.deepEqual(preserveNewerAccountCredentials(current, current), current)
})
