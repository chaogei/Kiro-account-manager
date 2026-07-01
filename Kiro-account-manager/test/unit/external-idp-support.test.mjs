/* eslint-disable @typescript-eslint/explicit-function-return-type */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'

const read = (path) => readFileSync(new URL(`../../${path}`, import.meta.url), 'utf8')

test('main process refreshes ExternalIdp credentials with their token endpoint', () => {
  const source = read('src/main/index.ts')

  assert.match(source, /function refreshExternalIdpToken|async function refreshExternalIdpToken/)
  assert.match(source, /authMethod === 'external_idp'[\s\S]*refreshExternalIdpToken/)
  assert.match(source, /tokenEndpoint/)
  assert.match(source, /grant_type:\s*['"]refresh_token/)
})

test('local Kiro import reads IDE ExternalIdp profile metadata', () => {
  const source = read('src/main/index.ts')

  assert.match(source, /readKiroIdeProfileArn/)
  assert.match(source, /kiro\.kiroagent/)
  assert.match(source, /profile\.json/)
  assert.match(source, /arn:aws:codewhisperer:/)
})

test('account model carries ExternalIdp metadata required by proxy refresh', () => {
  const source = read('src/renderer/src/types/account.ts')

  assert.match(source, /external_idp/)
  assert.match(source, /ExternalIdp/)
  assert.match(source, /tokenEndpoint/)
  assert.match(source, /issuerUrl/)
  assert.match(source, /scopes/)
})

test('local ExternalIdp import is idempotent across refresh token rotation', () => {
  const source = read('src/renderer/src/store/accounts.ts')

  assert.match(source, /localSsoSyncInFlight/)
  assert.match(source, /findMatchingAccountId/)
  assert.match(source, /mergeDuplicateAccounts/)
  assert.match(source, /client-issuer/)
  assert.match(source, /Updated existing local SSO account/)
})

test('OIDC batch import normalizes Kiro ExternalIdp export JSON', () => {
  const source = read('src/renderer/src/components/accounts/AddAccountDialog.tsx')

  assert.match(source, /kiro_auth_token_raw/)
  assert.match(source, /kiro_profile_raw/)
  assert.match(source, /refresh_token/)
  assert.match(source, /profileArn/)
  assert.match(source, /tokenEndpoint/)
})

test('proxy Kiro API sends ExternalIdp token type header', () => {
  const source = read('src/main/proxy/kiroApi.ts')

  assert.match(source, /provider === 'ExternalIdp'/)
  assert.match(source, /TokenType/)
  assert.match(source, /EXTERNAL_IDP/)
})
