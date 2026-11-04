# 修复：「切号目标」对 Kiro CLI 不生效

> 对应上游 issue：[chaogei/Kiro-account-manager#125](https://github.com/chaogei/Kiro-account-manager/issues/125)
> （`missing field 'oauth_flow' at line 1 column 645`）
> 相关未合并 PR：#118 / #121（思路参考，未直接采用）
> 参考实现：`kiro-ide-auth-to-cli.py`（IDE → CLI 凭证同步脚本）

## 现象

设置里的「切号目标」选择 **Kiro CLI** 或 **两者 (IDE + CLI)** 后切换账号：

- Kiro IDE 正常切到新账号；
- Kiro CLI 仍然是旧账号 / 未登录；
- 应用 UI 显示切换成功，日志里也有 `[Switch CLI] Account switched successfully in ...`。

## 根因（4 个叠加问题）

### 1. macOS 数据库路径写错（直接原因）

Kiro CLI（Rust `dirs` crate）在 macOS 上读取：

```
~/Library/Application Support/kiro-cli/data.sqlite3
```

而旧实现对所有非 Windows 平台都写：

```
~/.local/share/kiro-cli/data.sqlite3
```

于是 App 在 macOS 上写了一个 CLI 根本不会读的“私有数据库”，并创建目录/文件、报告成功。
Kiro CLI 的真实数据库从未被更新。

### 2. `auth_kv` 记录 schema 不完整（修完路径就会暴露）

kiro-cli 用 Rust serde 反序列化 `auth_kv` 里的 JSON，必填字段缺失会直接报错退出。
旧实现写出的记录：

```jsonc
// kirocli:odic:token
{ "access_token": "…", "refresh_token": "…", "expires_at": "…", "region": "us-east-1", "profile_arn": "…" }
// kirocli:odic:device-registration
{ "client_id": "…", "client_secret": "…", "region": "us-east-1" }
```

kiro-cli 2.x 实际需要（以本机 CLI 自己写出的记录为准）：

```jsonc
// kirocli:odic:token（BuilderIdToken）
{
  "access_token": "…", "expires_at": "<RFC3339>", "refresh_token": "…",
  "region": "us-east-1",
  "start_url": "https://<instance>.awsapps.com/start",  // Enterprise 必须是账号自己的 SSO Start URL
  "oauth_flow": "Pkce",
  "scopes": ["codewhisperer:completions", "codewhisperer:analysis", "codewhisperer:conversations"]
  // telemetry_generation 可选，CLI 会自愈
}
// kirocli:odic:device-registration（DeviceRegistration）
{
  "client_id": "…", "client_secret": "…",
  "client_secret_expires_at": "<RFC3339>",
  "region": "us-east-1", "oauth_flow": "Pkce", "scopes": [...]
}
```

缺 `oauth_flow` → `missing field 'oauth_flow'`（issue #125）；
缺 registration 的 `client_secret_expires_at` → **加载 token 时**就报
`missing field 'client_secret_expires_at'`，CLI 直接视为未登录（实测）。

### 3. rotating refreshToken 被丢弃 / both 模式二次 refresh

旧 CLI handler 里 refresh 后只更新 `accessToken`，**没有保存新的 `refreshToken`**；
而 `both` 模式下 renderer 先调 IDE 切号（refresh 并轮换 RT），再调 CLI 切号时
用的是切换前捕获的旧 RT 二次 refresh，最终写进 CLI 的可能是被轮换掉的旧 token。

### 4. CLI 写入失败在 both 模式下被吞掉

`if (!result.success && switchTarget === 'cli')` —— 只有「仅 CLI」时才会报错，
`both` 模式下 CLI 写失败/没生效，UI 仍然显示成功。

## 修复内容

| 文件 | 变更 |
| --- | --- |
| `src/main/kiroCliAuth.ts`（新增） | 纯 Node 依赖的 kiro-cli 凭证层：按平台解析 `data.sqlite3` 路径；生成 kiro-cli 兼容的 token/registration/social 记录（`start_url` 从 clientSecret JWT 的 `initiateLoginUri` 推导，`client_secret_expires_at` 从 JWT `expirationTimestamp` 推导）；`node:sqlite` 参数化写入 + `sqlite3` CLI 兜底；不存在的 CLI 数据库给出可读错误而不是乱写 |
| `src/main/index.ts` | 合并 `switch-account` / `switch-account-cli`：按 `target`（ide/cli/both）**只 refresh 一次**，写 IDE 和/或 CLI，失败显式返回错误并回传 rotated credentials |
| `src/preload/index.ts`、`index.d.ts` | `switchAccount` 增加 `target` / `cliDbPath` 类型；移除已废弃的 `switchAccountCli` |
| `src/renderer/.../AccountCard.tsx`、`AccountListRow.tsx`、`store/accounts.ts` | 单次 IPC 调用；success/failure 都把 rotated token 落回 store；both 模式 CLI 失败会提示用户；auto-switch 改为 await 并同步错误 |
| `test/cli-switch/kiroCliAuth.test.ts`（新增） | 17 个 node:test 用例：三平台路径、social/IdC 判定、start_url/client_secret 过期时间推导、token/registration 必填字段、竞争 key 清理、SQLite 写入 round-trip、CLI 未初始化错误 |

## 验证

### 单元测试

```bash
cd Kiro-account-manager
node --disable-warning=MODULE_TYPELESS_PACKAGE_JSON --test test/cli-switch/
# → 17 pass / 0 fail
npm run typecheck   # → exit 0
```

### 真实 kiro-cli 2.36.0 离线对照（沙箱 HOME + 假 token，不触碰真实凭证）

| 沙箱 DB 里的记录 | `kiro-cli whoami` |
| --- | --- |
| 空 `auth_kv`（对照组） | `Not logged in` (exit 1) |
| 旧 App 写出的记录（缺 `oauth_flow`） | `Not logged in` (exit 1) ← 这就是用户看到的 bug |
| 新 `buildKiroCliAuthRecords()` 生成的记录 | `Logged in with IAM Identity Center (https://…awsapps.com/start)` (exit 0) |

### 行为变化

- `切号目标 = Kiro CLI`：只写 CLI 数据库，不动 IDE token 文件；
- `切号目标 = 两者`：一次 refresh，同时写 IDE + CLI；CLI 写失败会在 UI 报错，不再静默成功；
- 默认值仍是 `ide`，IDE-only 行为不变；
- refresh 失败不写任何客户端（避免写“半坏”凭证）；
- 旧的 `~/.local/share/kiro-cli/data.sqlite3`（历史 bug 产物）不再写入，可手动删除。

## 已知限制 / 后续可做

1. **App 发起的 refresh 已同步 CLI（本次新增）**：成功切到 CLI 的账号会被 main 进程记录
   （`kiroCliTrackedAuth`，持久化在 electron-store 的 `kiroCliTracking`，App 重启后恢复）。
   之后这些路径轮换 token 时会把新 token 一并写回 kiro-cli 数据库（仅当切号目标仍含 CLI
   且刷新的正是该账号，best-effort，失败只记日志）：
   - 主动续期（proactive renewal）；
   - 手动刷新（`refresh-account-token`）；
   - 后台批量刷新（`background-batch-refresh`）；
   - IDE 自己 refresh 写入 token 文件后的反向同步（fs.watch）。
   仍未覆盖：反向代理自己的内存内刷新（不落盘）；以及 CLI 自己 refresh 后 App store 里
   可能留下旧 RT（共享 registration 的双 rotator 问题）。
2. **两个 rotator 共存**：IDE 与 CLI 共享同一 client registration / refresh token 族，
   两边各自 refresh 时仍可能出现竞争；本次修复保证「切号」这一步一致。
3. CLI 自己还会把 profile/start-url 缓存到 `state` 表；本次只按参考脚本的 scope 更新 `auth_kv`，
   跨账号的 profile 选择依赖 CLI 自身的 ListAvailableProfiles 自愈（离线无法验证）。
4. social（Google/Github）路径按未合并 PR #121 的字段实现（`provider`、`profile_arn`），
   本机没有 social 账号，未做真机验证。
5. Windows / Linux 路径按 Rust `dirs` crate 语义实现（`%LOCALAPPDATA%\kiro-cli`、
   `$XDG_DATA_HOME/kiro-cli`），本机（macOS）无法实测这两个平台；路径解析有单测覆盖。
   Windows 目录名 `kiro-cli` 与 CLI 官方 Windows 构建内 `paths.rs` 的 `"kiro-cli"` 字面量一致
   （NTFS 大小写不敏感，参考脚本的 `Kiro-Cli` 也能命中同一目录）。
