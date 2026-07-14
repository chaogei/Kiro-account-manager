# kiro-cli ≥2.12 account switch (fix notes)

This document describes fixes applied so **Kiro Account Manager** can switch credentials into **kiro-cli 2.12** (IDE + CLI), including Google social accounts.

## Problem

- Switching accounts updated **Kiro IDE** (`~/.aws/sso/cache/kiro-auth-token.json`) but not **kiro-cli**, or wrote a schema kiro-cli rejects.
- Google/social accounts: IDE worked, CLI showed **Not logged in** or chat **dispatch failure**.
- Domain / IdC accounts were easier to get working; social needed extra fields and careful refresh ordering.

## Root causes

1. **Different stores**  
   - IDE: camelCase JSON on disk  
   - CLI (macOS): `~/Library/Application Support/kiro-cli/data.sqlite3` table `auth_kv`

2. **Social token schema** (`kirocli:social:token`) must include:
   - `provider`: `Google` or `Github` (casing matters for reliability)
   - `profile_arn`: e.g. `arn:aws:codewhisperer:us-east-1:699475941385:profile/EHGA3GRVQMUK`
   - plus `access_token`, `refresh_token`, `expires_at`

3. **IdC token schema** (`kirocli:odic:token` / `device-registration`) needs `oauth_flow` and `client_secret_expires_at` (RFC3339 with timezone).

4. **Mis-classification of social accounts**  
   Strict `provider === 'Google'` missed `google` / `authMethod === 'social'`, so Gmail was written as IdC/odic.

5. **Double refresh when Switch Target = Both**  
   IDE refresh rotates the refresh token; CLI then refreshed with the old token → dead CLI session / dispatch failure.  
   Fix: pass live tokens from IDE to CLI and **`skipRefresh: true`** on the CLI path for Both.

6. **Silent CLI errors** when Both: UI showed Active if only IDE succeeded.

## Changes (this fork/clone)

| Area | Change |
|------|--------|
| `switch-account-cli` | Correct social vs IdC detection; write required fields; clear competing auth keys; optional `skipRefresh` |
| `writeKiroAuthTokenFile` | After social IDE write, **auto-sync** same tokens into CLI `auth_kv` |
| Renderer switch (card/list/auto) | Live token pair across IDE→CLI; report CLI failures; default `switchTarget` = `both` |

## Verification

After switching to a Google account (app built from this tree):

```bash
kiro-cli whoami
# expect: Logged in with Google / correct email

kiro-cli chat --no-interactive "hi"
# expect: reply + Credits (not "dispatch failure" / "Not logged in")
```

Note: the **new** full-screen TUI (bare `kiro-cli` without `--classic`) can still show `dispatch failure` even when non-interactive chat works. Prefer:

```bash
kiro-cli chat --classic --agent yolo -a
```

## Related local tag

- `v1.7.7-cli-domain-ok` — baseline where domain/IdC CLI switch was verified before further Google fixes.
