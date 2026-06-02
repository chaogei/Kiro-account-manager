# Kiro 账户管理器

<p align="center">
  <img src="Kiro-account-manager/resources/icon.png" width="128" height="128" alt="Kiro Logo">
</p>

<p align="center">
  <strong>QQ 交流群: 653516618</strong>
</p>

<p align="center">
  <img src="Kiro-account-manager/src/renderer/src/assets/交流群.png" width="200" alt="QQ 交流群">
</p>

<p align="center">
  <strong>一个功能强大的 Kiro IDE 多账号管理工具</strong>
</p>

<p align="center">
  支持多账号快速切换、自动 Token 刷新、分组标签管理、机器码管理等功能
</p>

<p align="center">
  <a href="README.md">English</a> | <strong>简体中文</strong>
</p>

---

## ✨ 功能特性

### 🔐 多账号管理
- 支持添加、编辑、删除多个 Kiro 账号
- 一键快速切换当前使用的账号
- 支持 Builder ID 和 Social（Google/GitHub）登录方式
- 批量导入导出账号数据

### 🔄 自动刷新
- Token 过期前自动刷新，保持登录状态
- Token 刷新后自动更新账户用量、订阅等信息
- 开启自动换号时，定期检查所有账户余额

### 📁 分组与标签
- 通过分组和标签灵活组织管理账号
- 多选账户批量设置分组/标签
- 一个账户只能属于一个分组，但可以有多个标签

### 🔑 机器码管理
- 修改设备标识符，防止账号关联封禁
- 切换账号时自动更换机器码
- 为每个账户分配唯一绑定的机器码
- 支持备份和恢复原始机器码

### 🔄 自动换号
- 余额不足时自动切换到其他可用账号
- 可配置余额阈值和检查间隔

### 🎨 个性化设置
- 21 种主题颜色可选（按色系分组显示）
- 深色/浅色模式切换
- 隐私模式隐藏敏感信息

### 🌐 代理支持
- 支持 HTTP/HTTPS/SOCKS5 代理
- 所有网络请求通过代理服务器

### 🔄 自动更新检测
- 自动检测 GitHub 最新版本
- 显示更新内容和下载文件列表
- 一键跳转到下载页面

---

## 📸 界面预览

### 主页
显示账号统计、当前使用账号详情、订阅信息和额度明细。

![主页](Kiro-account-manager/resources/主页.png)

### 账户管理
管理所有账号，支持搜索、筛选、批量操作，一键切换账号。

![账户管理](Kiro-account-manager/resources/账户管理.png)

### 机器码管理
管理设备标识符，防止账号关联封禁，支持备份恢复。

![机器码管理](Kiro-account-manager/resources/机器码管理.png)

### 设置
配置主题颜色、隐私模式、自动刷新、代理等选项。

![设置](Kiro-account-manager/resources/设置.png)

### API 反代服务
提供 OpenAI 和 Claude 兼容的 API 端点，支持多账号轮询、Token 自动刷新、请求重试等功能。

![API 反代服务](Kiro-account-manager/resources/API%20反代服务.png)

### Kiro IDE 设置
同步 Kiro IDE 设置，编辑 MCP 服务器，管理用户规则（Steering）。

![Kiro 设置](Kiro-account-manager/resources/Kiro%20设置.png)

### 关于
查看版本信息、功能列表、技术栈和作者信息。

![关于](Kiro-account-manager/resources/关于.png)

---

## 📥 安装说明

### Windows
直接运行安装程序 `.exe` 文件即可。

### macOS
由于应用未进行 Apple 代码签名，首次打开时 macOS 会提示"已损坏，无法打开"。请按以下步骤解决：

**方法一：终端命令（推荐）**
```bash
xattr -cr /Applications/Kiro\ Account\ Manager.app
```

**方法二：右键打开**
1. 在 Finder 中找到应用
2. 按住 `Control` 键点击应用（或右键点击）
3. 选择「打开」
4. 在弹出对话框中点击「打开」

### Linux
- **AppImage**：添加执行权限后直接运行
  ```bash
  chmod +x kiro-account-manager-*.AppImage
  ./kiro-account-manager-*.AppImage
  ```
- **deb**：使用 `dpkg -i` 安装
- **snap**：使用 `snap install` 安装

---

## 📖 使用说明

### 添加账号

1. 点击「账户管理」进入账号列表页面
2. 点击右上角「+ 添加账号」按钮
3. 输入账号的 SSO Token 或 OIDC 凭证
4. 点击确认完成添加

### 切换账号

1. 在账户管理页面找到目标账号
2. 点击账号卡片上的电源图标即可切换
3. 切换后 Kiro IDE 将使用新账号

### 批量设置分组/标签

1. 在账户管理页面勾选多个账号
2. 点击「分组」或「标签」按钮
3. 在下拉菜单中选择要添加或移除的分组/标签

### 机器码管理

1. 点击左侧「机器码」进入管理页面
2. 首次使用会自动备份原始机器码
3. 点击「随机生成并应用」可更换新机器码
4. 如需恢复，点击「恢复原始」即可

> ⚠️ **注意**：修改机器码需要管理员权限，请以管理员身份运行应用

### 导入导出

- **导出**：设置 → 数据管理 → 导出，支持 JSON、TXT、CSV、剪贴板多种格式
- **导入**：设置 → 数据管理 → 导入，从 JSON 文件恢复账号数据

---

## 🛠️ 技术栈

- **框架**: Electron + React + TypeScript
- **状态管理**: Zustand
- **样式**: Tailwind CSS
- **构建工具**: Vite
- **图标**: Lucide React

---

## 💻 开发指南

### 环境要求

- Node.js >= 18
- npm >= 9

### 安装依赖

```bash
npm install
```

### 开发模式

```bash
npm run dev
```

### 构建应用

```bash
# Windows
npm run build:win

# macOS
npm run build:mac

# Linux
npm run build:linux
```

### 构建多架构版本

```bash
# Windows 64位
npx electron-builder --win --x64

# Windows 32位
npx electron-builder --win --ia32

# Windows ARM64
npx electron-builder --win --arm64

# macOS Intel
npx electron-builder --mac --x64

# macOS Apple Silicon
npx electron-builder --mac --arm64

# Linux 64位
npx electron-builder --linux --x64

# Linux ARM64
npx electron-builder --linux --arm64
```

---

## 🚀 自动构建 (GitHub Actions)

项目配置了 GitHub Actions 工作流，支持自动构建所有平台和架构：

### 支持的平台

| 平台 | 架构 | 格式 |
|------|------|------|
| Windows | x64, ia32, arm64 | exe, zip |
| macOS | x64, arm64 | dmg, zip |
| Linux | x64, arm64, armv7l | AppImage, deb, snap |

### 触发方式

1. **推送标签**: 推送 `v*` 格式的标签时自动构建并发布
   ```bash
   git tag v1.1.0
   git push origin v1.1.0
   ```

2. **手动触发**: 在 GitHub Actions 页面手动运行工作流

---

## 📋 更新日志


### v1.7.2 (2026-6-2) — 批量订阅链接增强 + 卡密解析修复 + 添加/导入分组归属

> 本版本聚焦批量订阅「获取链接」界面的批量导入与快选分批打开、卡密/凭证解析的边界字符修复（解决导入验证 401），以及添加 / 批量 / 导入账号时可归入指定分组。

#### 🔗 批量订阅 · 获取链接

- **新增**: 链接批量导入 — 弹窗粘贴多行文本，自动从每行提取 URL（支持纯 URL，或「邮箱<分隔符>URL」，分隔符兼容 空格 / 逗号 / Tab / 竖线 / ----），按 URL 去重后以「成功」状态进入列表，可与现有链接一样单个 / 多选打开、复制、导出
- **新增**: 快选「前 N 个」 — 从列表顶部一键选中前 N 个可用链接（默认 10，数量跨页面记忆），便于分批打开
- **新增**: 快选「下一批」 — 基于游标从上次位置继续选 N 个，到末尾循环，配合「打开选中」可分批打开、避免一次开太多浏览器窗口

#### 🎫 卡密 / 凭证解析（边界字符修复）

- **修复**: 🔥 **卡密导入验证 401（Bad credentials）** — RefreshToken / ClientSecret 为 base64url(JWT)，当字段值以 `-` 结尾时会与 `----` 分隔符相邻形成 5+ 个连续 `-`，旧的 `split('----')` 只吃前 4 个，导致 ClientSecret 末尾 `-` 丢失（JWT 损坏）、provider 变成 `-BuilderId` → authMethod 被误判为 social → 刷新走错端点报 401
- **新增**: 统一解析函数 `splitCredentialLine` — 用 `/-{4,}/` 整体匹配分隔符，把多出的 (N-4) 个 `-` 归还前一字段，保证 JWT 完整、provider 正确；应用于 OIDC 批量导入、TXT 文件卡密导入、Outlook 邮箱解析
- **修复**: TXT 文件卡密导入此前硬编码 `idp=BuilderId` 且未读第 6 字段 — 现改为读取登录方式并按 ClientId / Secret 推断，与弹窗批量导入逻辑一致

#### 🗂️ 添加 / 批量 / 导入 · 分组归属

- **新增**: 添加账号弹窗顶部新增「添加到分组」下拉 — 覆盖 登录 / OIDC 单个 / OIDC 批量 / SSO 全部方式；打开弹窗时默认选中「当前打开的分组」，可改选任意分组或「默认（未分组）」
- **新增**: 文件导入（CSV / TXT / 卡密）归入「当前打开的分组」，导入完成提示显示分组名；JSON 完整备份导入保留原分组结构
- **修复**: 原先添加账号写死 `groupId: undefined` 导致新账号永远进「未分组」，现按所选分组归类


### v1.7.1 (2026-6-1) — Proton 注册取码稳定性 / 速度优化 + 社交登录卡密修复

> 本版本聚焦 Proton 邮箱注册流程的验证码自动获取（准确率 + 速度 + 日志可见性）、Proton 登录态与代理体验，以及 GitHub/Google 社交登录账号的卡密导入导出修复。

#### 🎫 卡密导入 / 导出（社交登录修复）

- **修复**: 🔥 **GitHub / Google 社交登录账号卡密批量导入失败** — 旧逻辑导入时硬编码 `provider=BuilderId`(IdC)，而社交账号没有 ClientId / Secret，被验证接口 `authMethod !== 'social' && (!clientId || !clientSecret)` 直接拒绝（提示"请填写 Client ID 和 Client Secret"）
- **新增**: 卡密导出格式新增**第 6 字段「登录方式(idp)」** — `邮箱----密码----RefreshToken----ClientId----ClientSecret----登录方式`，导入时可精确还原 social(Github/Google) / IdC(BuilderId/Enterprise)
- **新增**: 旧 5 字段卡密兼容 — 无第 6 字段时按 ClientId / Secret 是否为空推断：都空 → social（默认 Google），有 → IdC(BuilderId)。社交账号刷新只需 RefreshToken，推断后即可验证通过
#### 📧 Proton 验证码自动获取（注册流程）

- **修复**: 取码时误点邮件行内的星标按钮 — 表现为"邮件已到却一直在点星标/取消、读不到码"。改为精确点击邮件主题文本（避开 button / checkbox）打开邮件
- **修复**: 验证码被其它邮件干扰 — AWS 同时下发的「Response Required: Your Kiro Account」（收件人相同但无验证码）会把验证码邮件挤到第二封。现按发件人 `no-reply@signin.aws` 精确筛选，并读取前两封候选，避免误判"已打开当前邮件但无码"而卡死
- **新增**: 收件人原样精确匹配 — 用邮件头收件人地址（保留点号）区分同一母号不同点号变体的旧验证码，杜绝取到历史码
- **优化**: 取码速度 — 点开邮件后由固定 2.2s 死等改为轮询渲染就绪（出现 6 位码 / 收件人+正文齐备即继续，通常 ~0.5s 命中）；Proton 取码是本地 DOM 轮询、无网络限流，轮询间隔从沿用的 3s 收紧到 ≤1s。验证码到达 → 读到延迟约从 4s 降到 1.5s
- **新增**: 取码全过程日志接入注册页面日志面板 — 发件人筛选、收件人精确匹配、"最新邮件收件人非当前地址，等待中"等状态实时可见

#### 🔐 Proton 登录态 + 代理

- **修复**: 切换页面后返回，Proton 登录状态显示变回"未登录" — 改用模块级缓存跨组件卸载/挂载保持登录态展示
- **优化**: Proton 取码窗口默认走「设置页全局代理」（`process.env.HTTPS_PROXY`），而非系统代理或注册代理池；窗口复用时也刷新 session 代理，设置变更后下次取码即生效




### v1.7.0 (2026-5-28) — 安全加固 + 全功能扩展大版本

> 本版本包含 70+ 项改进，覆盖反代安全加固、批量注册并发隔离、SOCKS 代理、任务中心、Webhook 通知、报表分析、一键诊断、配置导入导出、性能优化等多个方向。

#### 🛡️ 反代安全加固（21 项）

**P0 紧急安全**
- **修复**: `readBody` 加入请求体大小上限（默认 10MB），Content-Length 提前拒绝 + 流式累加超限断连，触发 HTTP 413（防 DoS）
- **修复**: 检测到 host=`0.0.0.0`/`::` 且未配置 API Key 时拒绝启动；UI 显示红色警告，需显式 `allowExternalWithoutApiKey` 才能裸跑
- **修复**: API Key 比较改用 `crypto.timingSafeEqual`，杜绝时序攻击逐字猜 Key
- **修复**: 错误响应 500 类只返回通用消息 "Internal server error"；自动脱敏 Bearer/access_token/JWT/系统路径
- **修复**: `/admin/config` GET 屏蔽 `apiKeys[].key` 明文，仅返回 `xxxx***last4`

**P1 运维与可观测**
- **新增**: IP 白名单 / 黑名单（支持单 IP + IPv4/IPv6 CIDR）
- **新增**: 反代关键事件接入 Webhook（封号 / 全员配额耗尽，5 分钟去重）
- **新增**: `/admin/config` POST 字段白名单校验，禁止远程修改 port/host/apiKeys/tls 等敏感字段
- **新增**: 按 API Key / IP 的请求频率限制（滑动窗口，每分钟可配）
- **新增**: 会话粘性（按 conversation_id 路由到同账号，保 prompt cache + 防风控）
- **新增**: keep-alive / headers 空闲超时（默认 65s/60s 可调）
- **新增**: TLS 自签证书一键生成（2 年有效期 + SAN 覆盖 localhost/127.0.0.1/::1/用户 host）
- **新增**: stop() 优雅停止（5 秒优雅期 → activeRequests.abort → socket.destroy）
- **新增**: 日志 sanitize（移除 Bearer/access_token/JWT/系统路径片段）

**P2 高级特性**
- **新增**: Prometheus `/metrics` 端点（8 个核心指标：requests/tokens/credits/accounts/uptime）
- **新增**: 反代审计日志（滚动 200 条 + `/admin/audit` GET + `enableAuditLog` 开关）
- **新增**: API Key 绑账号白名单（`apiKeyAccountBindings`：apiKey id → 允许的账号 id 数组）
- **新增**: HTTP + HTTPS 双端口（启用 TLS 时通过 `fallbackPort` 同时监听 HTTP）
- **新增**: `recentRequests` 上限可配置（默认 100，最多 10000）
- **新增**: port/host/tls 变更标记需重启 + UI 一键重启按钮
- **新增**: 流式响应 socket-level backpressure 监控

**新文件**: `src/main/proxy/selfSignedCert.ts`、`ProxySecurityPanel.tsx`
**新 IPC**: `proxySelfSignedCertInfo` / `proxySelfSignedCertRegenerate` / `proxyNeedsRestart` / `proxyRestart` / `proxyAuditLog` / `onProxyWebhookTrigger`

#### 🌐 多协议代理支持

- **新增**: SOCKS5 / SOCKS5h / SOCKS4 / SOCKS4a 代理支持（基于 `socks` 库 + undici 自定义 Agent + TLS 升级）
- **新增**: 账号-代理 N:1 绑定（反代分桶，多账号共用 1 个 IP 降低风控关联）
- **新增**: 账号的所有请求（含 token 刷新、background 检查、Kiro API）统一走绑定代理
- **新增**: 代理池高级搜索（9 字段全文：host / port / protocol / user / label / email / url / tags / source）
- **新增**: 代理池多维筛选（协议 / 启用状态 / 延迟范围 / 最后验证时间）+ 匹配数实时显示

#### 🚀 批量注册重大升级

**并发隔离修复**
- **修复**: Outlook 批量并发邮箱抢占（前端预 shuffle outlookData + 每 task 独占一行；主进程兼容单行/多行）
- **修复**: Mixed 模式源选择只生效一次（每 task 独立 `buildAutoConfig`，权重轮询真正生效）
- **修复**: 注册历史"直连"误报（`resolvedProxyUrl()` 含系统/环境变量代理）

**功能扩展**
- **新增**: 限速器（token bucket）+ 指数退避 + 成功率监控
- **新增**: 失败重试队列（按错误类型：network / otp_timeout / email_used / rate_limit / auth / risk_control）
- **新增**: AWS 风控自动识别（"TEMPORARILY_SUSPENDED" / "请稍后再试"）+ 自动暂停批量
- **新增**: 邮箱预校验黑名单（占用邮箱自动加入，跳过节省时间）
- **新增**: 混合邮箱源加权轮询（SWRR / nginx 同款算法）
- **新增**: 每日注册配额 + cron 定时启动
- **新增**: 注册策略模板（保存/应用/导入/导出）
- **新增**: 6-8 步动态进度条（根据 `batchAutoImport` 和 `autoFetchProLink` 自动增减）
- **修复**: 注册过程中文乱码错误（tlsclientwrapper Latin-1 → UTF-8 重解码）
- **移除**: MoEmail 注册功能（无用）

#### 📊 任务中心 + Webhook 通知

- **新增**: 统一任务中心（`useTaskStore`，标题栏入口 + 抽屉式 UI）
- **新增**: 任务状态机：running / paused / success / failed / cancelled
- **新增**: 任务中心持久化（完成的任务保存到 localStorage）
- **新增**: 全部取消按钮 / 进度条 / 子任务详情
- **新增**: Webhook 通知（钉钉 / Telegram / Discord / Slack / Generic JSON）
- **新增**: Webhook 重试（3 次指数退避）+ 限流（20 条/分钟/webhook）
- **新增**: 反代关键事件 → Webhook（封号 / 全员配额耗尽）

#### 🩺 一键诊断

- **新增**: 诊断页面（网络 / Kiro API / 邮箱服务 / 代理 / 自定义端点连通性）
- **新增**: 自定义探测 URL（替代 MoEmail，可填任意 HTTP/HTTPS 端点）
- **新增**: 通过代理执行诊断 + 报告导出（剪贴板）
- **新增**: 老 MoEmail 配置自动迁移到新探测 URL key

#### 🔧 订阅管理

- **新增**: 批量订阅预检（资格检查 + 报告）
- **新增**: 订阅取消 / 降级 / 续期入口
- **新增**: 订阅链接有效期检测（HTTP HEAD 探测 + generatedAt 时间戳）
- **新增**: 管理订阅 Tab（批量打开门户 + 一键关闭超额计费）
- **新增**: 订阅账号虚拟列表（@tanstack/react-virtual）

#### 📈 报表分析

- **新增**: 注册结果分析报表（成功/失败圆环 + 24h 平滑曲线 + 7 日趋势）
- **新增**: 错误分类统计（OTP 超时 / 网络 / 邮箱占用 / 限流 / 风控）
- **新增**: CSV 导出

#### 📦 配置导入导出

- **新增**: 一键导出全量配置（账号 / 代理池 / Webhook / 策略模板）
- **新增**: AES-GCM 加密导出（KCFG 格式，PBKDF2-SHA256 派生密钥）
- **新增**: 跨设备配置同步

#### ⚡ 性能优化（防卡顿）

**I/O 与持久化**
- **优化**: `saveToStorage` 500ms 防抖 + `flushSaveImmediately` 强制刷新接口
- **优化**: `createBackup` 5 分钟节流（之前每次保存都备份）
- **优化**: `ProxyLogStore` 异步 `fs.promises.writeFile` + 30 秒节流 + maxLogs 100 万 → 5 万
- **优化**: `proxy-account-suspended` IPC 只更新内存快照，延迟落盘
- **优化**: SSO 账号 `queueMicrotask` 异步加载（不阻塞 loadFromStorage）

**渲染与计算**
- **优化**: `getFilteredAccounts` / `getStats` / `activeAccount` 模块级 memoization
- **优化**: `applyBackgroundRefreshResults` / `applyBackgroundCheckResults` 批量合并（120ms buffer）
- **优化**: `importAccounts` / `importFromExportData` 单 set 调用
- **优化**: `updateTrayInfo` 400ms 防抖
- **优化**: `AccountToolbar` 选中状态 `useMemo` + `useCallback`
- **优化**: 代理池 / 账号 / 订阅列表使用虚拟列表（`@tanstack/react-virtual`，仅渲染可视区域）

#### 🐛 关键 Bug 修复

- **修复**: `Invalid URL protocol`（Windows 注册表 ProxyServer 多协议字符串解析，仅取 HTTP/HTTPS）
- **修复**: `tls-client-wrapper` DLL 改用 `userData/tls-client/` 永久存储（之前在 `%TEMP%` 会被系统清理）
- **修复**: 网络请求 Latin-1 字符串响应转 UTF-8（中文错误正确显示）
- **修复**: `proxyServer.stop()` socket 强制 destroy 太早导致响应截断
- **修复**: 多个内存泄漏（限流桶 / 会话粘性条目 5 分钟自动清理）

#### 🆕 新页面

- **`ProxyPoolPage`** — 代理池管理 + 高级搜索 + 账号绑定 + 定时验活
- **`WebhooksPage`** — Webhook 配置 + 测试 + 事件订阅
- **`DiagnosePage`** — 一键诊断（网络 / API / 邮箱 / 代理 / 自定义）
- **`ConfigSyncPage`** — 配置导入导出 + AES-GCM 加密

#### 🔧 主题与 UI

- **新增**: 任务中心按钮（标题栏）+ 全局进度展示
- **新增**: 反代"安全与可观测设置 (v1.8)"卡片（折叠式，统一新配置入口）
- **优化**: 失败错误码本地化显示
- **优化**: 危险绑定（0.0.0.0）自动弹红色警告 + 风险确认开关

#### 🔄 ProxyAccount 数据模型扩展

- 新增 `proxyUrl` 字段（账号绑定的出口代理）
- 新增 `machineId` 字段（账户绑定的设备 ID）

#### 📋 ProxyConfig 新增字段（14 项）

`maxRequestBodyBytes` / `allowedIPs` / `deniedIPs` / `allowExternalWithoutApiKey` / `rateLimitPerKeyPerMinute` / `sessionAffinityEnabled` / `keepAliveTimeoutMs` / `headersTimeoutMs` / `recentRequestsLimit` / `enableMetrics` / `apiKeyAccountBindings` / `fallbackPort` / `enableAuditLog` / `apiKeyGroupBindings`(deprecated)


### v1.6.9 (2026-5-24)

#### UI 全面主题适配
- **重构**: 所有弹窗/卡片硬编码颜色统一替换为主题/语义令牌 — `text-green-500/600` → `text-success`、`text-red-500/600` → `text-destructive`、`text-amber/orange-500/600` → `text-warning`、`bg-blue-50/...` 等装饰色 → `bg-primary/[0.04~0.15]`
- **影响范围**: AccountDetailDialog、AccountCard、AccountListRow、ModelsDialog、AccountSelectDialog、ProxyLogsDialog、ProxyDetailedLogsDialog、ApiKeyUsageDialog、ClientConfigDialog、EditAccountDialog、SteeringEditor、AddAccountDialog、ApiKeyManager、ProxyPanel 等 14+ 组件
- **重构**: `_helpers.ts` 的 `getStatusBadgeClass` 状态色全部 token 化，支持自动深色模式适配
- **优化**: 切换主题色后所有弹窗/卡片立即跟随，不再有"主题切换部分元素不变"的问题

#### 账户卡片纯色背景
- **新增**: `--card-solid` CSS 变量（浅色模式 `#FFFFFF` / 深色模式 `#1A2236`）— 账户卡片专用不透明背景
- **新增**: `.bg-solid-card` utility class，配合双 class 选择器（`.glass-card.bg-solid-card`）覆盖玻璃态半透明背景，禁用 `backdrop-filter`
- **修复**: 主题色（橙色等）透过 72% 半透明 `bg-card` 渗入账户数据区导致"被蒙一层主题色"的问题
- **保留**: 其他玻璃态（dialog/popover/toolbar/sidebar/KIRO 配额卡）仍用 `bg-card` 半透明，玻璃质感不变

#### 列表/卡片视图视觉优化
- **重构**: 标签 chip 从实色填充改为半透明描边样式（12% 标签色背景 + 标签色文字 + 30% 标签色边框），视觉柔和不刺眼
- **重构**: `generateRowGlowStyle` 单标签场景去掉横向背景渐变，只保留左边 3px 色带；多标签保留垂直渐变左边带
- **修复**: 卡片/列表行选中态被多标签 inline style（`box-shadow`/`background`）覆盖导致选中无视觉反馈 — 改用绝对定位独立覆盖层（`absolute inset-0 ring-2 ring-inset ring-primary/60 bg-primary/[0.08] z-10`），与 inline style 隔离
- **优化**: 选中状态强化为 `ring-2 ring-primary/60` + `bg-primary/[0.08]` + 主色阴影

#### 分组功能改造（独立视图切换）
- **新增**: `useAccountsStore` 增加 `activeGroupTab` state（`'all' | 'ungrouped' | <groupId>`），localStorage 持久化 — 取代原"多选筛选"逻辑
- **新增**: `getFilteredAccounts()` 开头优先按 `activeGroupTab` 互斥过滤账号
- **重构**: 工具栏"分组"按钮改为三合一菜单 — 切换视图 / 批量移动 / 管理分组
  - 按钮文字动态显示当前 Tab 名 + 颜色圆点 + 计数
  - 下拉菜单 2 列网格紧凑布局，节省垂直空间
  - 用户分组列表只列一次（合并切换视图区和批量移动区）
  - 选中账户时 hover tile 显示行尾 ⇄ 快捷按钮，点击批量移动到该组
- **移除**: `AccountFilter.tsx` 中的分组 chip 多选区（避免与 Tab 双重控制冲突）
- **修复**: 下拉菜单被卡片遮挡 — `<header>` 加 `relative z-20` 抬升 stacking context（`.glass-toolbar` 的 backdrop-filter 创建了独立 z 层，需显式提升）

#### 账号管理工具栏紧凑化
- **重构**: 6 个工具栏按钮（标签/隐私/筛选/检查/删除/刷新）改为纯图标 + tooltip 模式（`size="icon" h-8 w-8`），节省约 280px 宽度
- **优化**: 标签按钮选中状态用主色小圆点（6px）替代 `ChevronDown`，更克制
- **优化**: 删除按钮 hover 变 `bg-destructive/10` 红色警示
- **优化**: tooltip 动态显示选中数量（如"删除选中的 5 个账号"），disabled 时提示"请先选中"
- **新增**: 独立"清除选中" X 按钮（仅多选时显示），hover 红色提示
- **保留**: 分组按钮（含当前 Tab 名）+ 全选按钮（含计数）保留文字（信息价值高）

#### 注册页 Pro 计划自定义选择
- **新增**: `ProPlanType` 类型 — Pro / Pro+ / Power 三种计划，对应 Kiro 后端 `Q_DEVELOPER_STANDALONE_{PRO|PRO_PLUS|POWER}` qSubscriptionType
- **新增**: 注册页"自动获取 Pro 订阅链接"开关下方加三选一 chip 按钮（蓝/紫/金业务色），localStorage 持久化
- **重构**: `fetchProSubscriptionUrl` 使用用户选择的计划类型替代硬编码 PRO

#### 反代功能增强
- **修复**: 多账号模式下"已过期 token 账号永远不刷新"bug — `accountPool.isAccountAvailable` 仅在**无 refreshToken**时才视为不可用，有 refreshToken 的过期账号让 `proxyServer.getAvailableAccount` 触发 `refreshToken`；刷新失败通过 `markNeedsRefresh` 自动隔离，形成闭环
- **新增**: `ProxyConfig` 增加 `multiAccountSelectionMode: 'all' | 'groups'` 和 `multiAccountGroupIds: string[]` 字段
- **新增**: 多账号轮询新增"轮询范围"配置 — 全部账号 / 指定分组（chip 多选含"未分组"特殊选项）
- **新增**: `syncAccounts` 在多账号 + groups 模式下按选中分组过滤要同步的账号
- **新增**: 反代页面 UI 加"轮询范围"切换 + 分组 chip（用户分组色 + 计数）+ 实时账号数预览
- **同步**: preload IPC 类型同步（`multiAccountSelectionMode` / `multiAccountGroupIds` / `accountSelectionStrategy`）

#### 反代页面 UI 紧凑化
- **重构**: 基础配置 + API Key 合并为 1 行 12 列网格 — 端口(2) + 监听(3) + API Key(7)
- **重构**: API Key 操作按钮（sk-xxx 格式选择 / 随机生成 / 复制 / 管理）全部 `icon-only h-7 w-7` 移到 Label 行右侧
- **重构**: 高级配置从 2 列改为 3 列布局，所有 description `<p>` 标签移到 Label 的 `title` tooltip（节省 30-40% 纵向空间）
- **重构**: Token Buffer 开关 + 数字输入合并为 `col-span-3` 一行（`[启用裁剪 160px][数字输入 flex-1]`）
- **优化**: 模式开关行从 `flex-wrap` 改为 `grid-cols-3`，3 个开关（额度切换/记录日志/流式日志）共一行
- **修复**: `sk-xxx` 下拉框 `h-6` 被 Select 内部 `py-2` 撑超导致内容被切 — 用 Tailwind 任意属性选择器 `[&>button]:h-7 [&>button]:py-0 [&>button]:px-2.5` 强制覆盖
- **优化**: 高级配置标题加 `Settings2` 图标 + `uppercase tracking-wider` 小型化

#### Bug 修复
- **修复**: `AccountManager.tsx` 文件末尾多余 `}` 闭合括号导致 TypeScript 语法错误
- **优化**: `AccountFilter.tsx` 清理未使用的 `groups` 解构变量

### v1.6.8 (2026-5-23)

#### Token 计量精度重构
- **新增**: `tokenCounter.ts` 独立模块 — 封装 `js-tiktoken` 的 `cl100k_base` 编码器与 `getModelContextLength` 函数，统一处理所有 token 计算逻辑
- **新增**: 多级精度链路 — Kiro 后端 `tokenUsage` 真实值 > `contextUsageEvent` 百分比反推（`modelCtx × percentage / 100`）> `tiktoken` 精算 > 字符系数兜底（input 0.42、output 0.4）
- **优化**: 输入 token 估算精度从 ~30% 偏差降至 ~5%（Sonnet 4.5 实测 17871 → 19608，与官方 12.7% contextUsage 完美对齐）
- **优化**: 输出 token 统计改为累积 `assistantResponseEvent` / `codeEvent` 文本后用 tiktoken 精算，不再依赖输出字符长度
- **新增**: `getModelContextLength` 三级查找链 — Kiro `fetchKiroModels` 返回的真实 `maxInputTokens` 缓存优先 → 模糊匹配（`claude-sonnet-4.5` ↔ `claude-sonnet-4-5-20251001`）→ 关键词兜底（sonnet/haiku/opus/gpt-4 等）
- **新增**: AmazonQ CLI 端点 `CodeEvent` 解析支持 — 修复该端点流式输出代码内容丢失的问题
- **优化**: `parseEventStream` 签名扩展，接收 `modelId` 与 `payloadStr` 参数，端到端贯通模型上下文供 contextUsage 反推使用
- **修复**: `kiroApi.ts` 中重复定义的 `modelContextWindowCache` 移除，统一从 `tokenCounter.ts` 导入并 re-export 保持向后兼容

#### Token Buffer Reserve 开关化（默认关闭）
- **变更**: ⚠️ **`tokenBufferReserve` 行为变更** — v1.6.7 强制启用预留 50K，v1.6.8 改为可选开关，**默认关闭**，开启时默认值降为 20K
- **新增**: `enableTokenBufferReserve` 独立开关 — `ProxyConfig` 新增字段，前端 UI 加内嵌 Switch 控件
- **行为**: 关闭时 `trimHistoryByTokens` **完全跳过**，超出 context window 由 Kiro 后端直接返回 `CONTENT_LENGTH_EXCEEDS_THRESHOLD` 错误，反代原样转发给客户端
- **行为**: 开启时 effective limit = `model.maxInputTokens - tokenBufferReserve`（200K → 180K, 1M → 980K，取值范围 5K~150K）
- **UI**: 数字输入框 disable 条件追加 `!enableTokenBufferReserve` — 开关关闭时输入框自动置灰；运行中所有相关控件锁定
- **兼容**: 存量配置中 50K 等历史值会保留（仍在 5K~150K 区间），但因开关默认 false 不会立即触发裁剪，用户需手动开启

#### 代理 URL 容错
- **新增**: `normalizeProxyUrl` 工具函数 — 自动规范化用户输入的非标准代理 URL（如 `http:127.0.0.1:7890` 缺 `//`、`127.0.0.1:7890` 缺协议、首尾空格等）统一补齐为标准 `http://host:port` 格式
- **优化**: 环境变量（`HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY`）、Electron `session.setProxy`、前端 UI 三处统一使用规范化后的 URL，避免代理失效或重复设置
- **优化**: IPC `set-proxy` 返回 `normalizedUrl` 给前端 store，自动回写到 UI 输入框显示规范化结果

#### 功能精简
- **移除**: 「自动继续轮数 / 服务端工具自动继续」完整功能链路 — 14 处引用清零（前端 UI 控件、`ProxyConfig` 字段、IPC `proxyStart`/`proxyUpdateConfig` 类型签名、后端 OpenAI `handleOpenAIStream` 与 Claude `handleClaudeStream` 流式 auto-continue 触发分支）
- **行为**: 流式工具调用走完后直接返回 `tool_calls` / `tool_use` 给客户端，由客户端决定后续动作，不再有服务端「伪造继续」的递归调用路径
- **理由**: 该功能与主流 API 客户端（Cline / Roo / Cursor / Claude Code）的工具执行循环冲突，且与 `clientDrivenToolExecution=true`（推荐配置）互斥，长期不被使用

#### Bug 修复
- **修复**: 🔥 `electron-builder` 构建报错 `ENOENT: no such file or directory, rename 'electron.exe' -> 'kiro-account-manager.exe'` — 根因为 npmmirror 镜像下载的 `electron-v38.7.2-win32-x64.zip` 不完整导致 Electron 二进制损坏，改用 BITS 从 `cdn.npmmirror.com/binaries/electron/` 下载完整 zip 解决
- **修复**: 注册流程 `app.js` 下载触发 `RangeError: init["status"] must be in the range of 200 to 599, inclusive.` — `tlsclientwrapper` 在网络错误时返回 `status=0/undefined`，触发 `new Response()` 校验异常。改用 `undici fetch` 直接获取静态资源 `app.js`，绕过 tls-client 避免污染其全局状态
- **修复**: 启用代理后 OIDC 注册失败 `failed to build client out of request input: failed to modify existing client: no tls client for modification check` — `app.js` 下载失败连带污染了 tls-client DLL 全局状态，后续 `SessionClient` 初始化失败。`app.js` 改用 undici 后该问题自动消除
- **修复**: 前端 `setProxy` 改为 async 函数 — 等待 IPC 返回规范化后的 URL 并回写 store 显示，避免 UI 与实际生效值不一致

### v1.6.7 (2026-5-23)

#### 账号封禁处理 (核心新功能)
- **新增**: 完整的 TEMPORARILY_SUSPENDED 检测链路 — 反代识别 Kiro 后端风控错误（`403 + reason:"TEMPORARILY_SUSPENDED"`）、`AccountSuspendedException`（CodeWhisperer）、`423 Locked` 三类响应
- **新增**: `ProxyAccount` 增加 `suspendedAt` / `suspendReason` / `suspendMessage` 字段，跟踪长期封禁状态（区分于临时 `errorCount` 冷却）
- **新增**: `AccountPool` 增加 `isSuspended` / `markSuspended` / `clearSuspended` 三个方法 — 被封禁账号在 `isAccountAvailable` 中永久跳过，直到手动解封或调用 `reset()`
- **新增**: `onAccountSuspended` 事件 + IPC `proxy-account-suspended` — 完整桥接 proxy server → main → preload → renderer store → UI
- **新增**: 封禁状态持久化到 `store.accountData[id].lastError` 和 `status='error'`，应用重启后仍然可见
- **新增**: 检测到当前账号被封禁时自动切换到下一可用账号（多账号模式和单账号 + 自动切换模式均生效）
- **改进**: 统一 `isBannedAccountError` 函数 — `store/accounts.ts` / `AccountSelectDialog` / `AccountCard` 三处全部识别 `temporarily_suspended` / `temporarily suspended` / `User ID is suspended` 模式并显示封禁标记
- **新增**: 手动解封 UI — `AccountCard` 封禁详情弹窗新增「重置封禁状态」按钮，调用 IPC `proxy-clear-account-suspended` → 同时清除反代池 suspended 标记 + 清除 `store.accountData[id].lastError` + 设置 `status='active'`
- **修复**: `accountPool.addAccount` 之前总是强制设置 `isAvailable=true`，会静默丢失账号重新 add 时带的 suspended 状态（如 `proxy-sync-accounts` 后）。现在 `addAccount` 尊重传入的 `suspendedAt` 字段，保留 `isAvailable=false`，从持久化数据重新加入的被封账号仍被正确跳过。

#### 局域网访问修复 (Issue #75)
- **修复**: 🔥 **从 1.5.0 升级到 1.6.x 后无法通过局域网访问反代** — 根因：默认 `host` 是 `127.0.0.1`（仅 loopback），且 UI 的「外网」Switch 在反代运行时被 `disabled`，用户无法切换必须停服
- **修复**: 反代面板的「外网」Switch 现在运行中也可点击 — 切换时自动 stop + start 反代，~300ms 内新 host 生效
- **改进**: 服务地址显示从 `http://0.0.0.0:5580` 改为 `http://localhost:5580`（前者不是有效的客户端目标地址），复制按钮也使用人类可读形式
- **改进**: Host 字段下方新增动态提示 — loopback 模式提示如何开启外网访问；外网模式警告需设置 API Key 并放行防火墙端口
- **改进**: 开启外网模式时，服务地址下方额外显示 `局域网设备请使用 http://<本机IP>:<端口>`

#### UI 优化
- **新增**: 🎨 **高级 SaaS 玻璃态全面重设计** — 致敬 Linear / Raycast / Vercel 风格的设计系统重构：
  - **设计令牌**：背景 `#f4f7fb`、主色 `#5B8CFF`、紫辅 `#8B5CF6`、成功色 `#22C55E`、半透明白边框 `rgba(255,255,255,0.4)`
  - **磨砂玻璃系统**：新增 `.glass-card` / `.glass-card-strong` / `.glass-card-subtle` / `.glass-sidebar` / `.glass-toolbar` 工具类，`backdrop-filter: blur(24px) saturate(180%)`
  - **悬浮侧边栏**：圆角 24px、玻璃背景、framer-motion spring 宽度动画、激活态采用 layoutId 形变药丸（主色 → 紫辅渐变）
  - **环境光背景**：双径向渐变（蓝 + 紫）配合 22s/26s 浮动 keyframes，80px 柔光，深色模式自动降透明度
  - **Card 默认**：`<Card>` 默认 glass variant + `rounded-2xl` (24px)，支持 `variant=glass/glass-strong/glass-subtle/solid/elevated` 与 `interactive` 属性（hover 浮起 -2px + 阴影增强）
  - **页面 Hero 统一**：8 个页面（首页/账号/设置/反代/K-Proxy/Kiro设置/订阅/注册/关于/机器码）全部使用 `.page-hero` 工具类，24px 圆角玻璃页头
  - **透明工具栏**：AccountManager 顶部 header 改用 `glass-toolbar`（16px blur + 半透明 + 仅底边线）
  - **页面切换**：`AnimatePresence` + `motion.div` 包裹页面，路由切换时 fade + 8px Y 轴 spring 过渡
  - **深色模式**：深海军蓝 `#0a0e1a` 背景配合调优后的玻璃面板，弱光环境下可读性更佳
  - **依赖**：新增 `framer-motion ^11.x` 支持声明式动画
- **修复（玻璃态打磨）**：页面滚动失效回归 — `motion.div` 包装器加上 `h-full flex flex-col`，确保子页面的 `flex-1 overflow-auto` 重新生效
- **优化（玻璃态打磨）**：
  - `HomePage` / `SettingsPage` / `AboutPage` / `RegisterPage` / `KiroSettingsPage` / `ProxyPanel` 中所有 33 处 `<Card className="border-0 shadow-sm hover:shadow-md transition-shadow duration-200">` 全部替换为 `hover-lift` — Card 默认 glass variant 完全显现
  - 4 个手写 div 风格的 Dialog 容器（`UpdateDialog` / `CloseConfirmDialog` / `AccountDetailDialog` / `ProxyDetailedLogsDialog`）从 `bg-background rounded-xl border` 换为 `glass-card-strong rounded-2xl` + 遮罩 backdrop-blur
  - `Button` 组件全面翻新：默认 `rounded-xl`、`transition-all 200ms`，`default`/`destructive` variants 加 hover `-translate-y-px` + 主色辉光环；新增 `gradient` variant（主题渐变背景 + breathe-glow 呼吸动画）；新增 `cta` size（h-12 rounded-2xl，用于主 Call-to-Action）
  - **21 个主题色全部配套定义 active-pill 渐变对** — 每个主题独立定义 `--gradient-from` / `--gradient-to`（紫/翠/橙/玫瑰/青/琥珀/水鸭/靖/青柠/粉/灰/晴空/紫罗兰/洋红/红/黄/绿/暖灰/中性灰 + default）。Sidebar 的 `motion.span layoutId="sidebar-active-pill"` 读取 CSS var，激活药丸跟随主题色谐和渐变（如翠绿主题 → 翠→青青渐变，不再固定蓝→紫）
  - `gradient-bg-primary` 和 `gradient-border` 工具类改用 `var(--gradient-from/-to)`，所有渐变按钮/边框自动跟随主题切换
- **优化（玻璃质感精修）**：
  - **玻璃阴影 4 层合成**：顶部 1px 白色高光（inset）+ 1px slate-900 @ 4% 外描边 + 0 8px 32px @ 12% 远阴影 + 0 2px 6px @ 5% 近阴影 — 让卡片在浅色背景上有真实的「磨砂亚克力」实物感（之前纯半透明在白底上视觉无差）
  - **页面光晕渗透**：`main` 容器加 `.page-surface`（双色 18%/14% 蓝紫径向 blob，60px blur），让玻璃卡片有色彩可折射 — 之前白底白卡视觉无对比
  - **AccountCard 重构**：移除多余的 `border` + `hover:shadow-lg` 覆盖（被 glass 系统覆盖）；非 active/非封禁卡片改用 `hover-lift` 工具类（translateY -2px + 增强阴影）；流光边框与封禁红边保留
  - **AccountToolbar 输入框**：搜索框、视图切换组按钮改用 `bg-[var(--glass-bg-subtle)] backdrop-blur-md` + rounded-xl + 大焦点环；AccountFilter 中 number input 同处理
- **新增**: 账号管理页新增**列表视图** — 工具栏增加「卡片/列表」切换按钮，选择持久化到 `localStorage('accounts_viewMode')`。紧凑列表行同行显示邮箱 + 状态 + 订阅 + 标签 + 额度进度 + 快捷操作，密度是卡片的 ~5 倍（适合管理 100+ 账号）
- **修复**: 系统日志页面的「显示数量」默认值从「全部」改为「5K」，并持久化到 `localStorage('systemLogs_displayLimit')` — 之前用户修改后切页或重启会重置为「全部」，在日志量大时冷启渲染特别慢

#### Token 维度历史裁剪
- **新增**: `tokenBufferReserve` 配置（替代之前的 `maxInputTokensThreshold`）— 根据 `ListAvailableModels` 返回的真实 `contextWindow` 自适应裁剪
- **变更**: 每次请求的有效裁剪阈值 = `model.maxInputTokens - tokenBufferReserve`，默认预留 `50000` 适配所有模型（200K 模型 → 150K 阈值，1M 模型 → 950K 阈值）
- **新增**: 预留 token 覆盖 `system` + `tools` + 当前消息 + 输出额度 + 估算偏差，无论 byte 维度的 payload size 多大都能避免 `CONTENT_LENGTH_EXCEEDS_THRESHOLD` 错误
- **新增**: 模型 context 缓存从 `fetchKiroModels` 同步到裁剪逻辑，Kiro 新增模型可自动获取正确上下文窗口

#### 弹窗玻璃态系统重构
- **重构**: 17 个 dialog 统一使用 `.glass-card-strong` — `Card` 重写为 90% 半透白底（`rgba(255,255,255,0.90)` / 深色 `rgba(20,25,40,0.90)`）+ `backdrop-filter: blur(20px) saturate(160%)` 真实磨砂玻璃 + 三层合成深阴影（1px 微外描边 + 0 24px 64px 远阴影 + 0 8px 24px 近接触影）让弹窗有强浮起感
- **统一**: dialog 背景遮罩从原 `bg-black/40 backdrop-blur-sm` / `bg-black/50` 改为 `bg-slate-900/[0.12] dark:bg-black/50 backdrop-blur-xl`，浅色 12% slate 极淡蒙板 + 强模糊（24px）— 背景虚化但不拉灰 dialog 采样
- **统一**: 所有 dialog 右上角关闭按钮（×）统一红色 hover — `hover:bg-red-500 hover:text-white transition-colors`，覆盖 `AccountDetailDialog` / `EditAccountDialog` / `AddAccountDialog` / `TagManageDialog` / `GroupManageDialog` / `ExportDialog` / `AccountCard` 封禁+订阅 / `ApiKeyUsageDialog` / `AccountSelectDialog` / `UpdateDialog` 等 15+ 个 dialog，与 TitleBar 危险关闭保持一致语义
- **改进**: `--glass-bg-strong` token 从纯白实色改为 90% 半透 + `backdrop-filter` 真正生效，dialog 不再是不透明白卡片而是带玻璃质感

#### 主题底色 & 氛围光优化
- **设计**: 浅色主背景从 `#f4f7fb` → `#EEF2F8` 冰白蓝调（参考 F1 清新蓝），减少「AI 配色」死白感
- **设计**: 深色主背景从 `#0a0e1a` → `#0B1220` 深空蓝（参考 E1），改为蓝调而非中性灰黑
- **新增**: `body` 三段渐变 — 浅色顶部 `#E5EBF5` → 中部 `#EEF2F8` → 底部 `#F2F5FA` 模拟天光过渡；深色顶部 `#0F1729` → 中部 `#0B1220` → 底部 `#060A14` 夜空深邃感
- **新增**: body 渐变顶/底用 `color-mix(in srgb, var(--gradient-from) 10%, ...)` 染上主题色，**主题切换时整个底色跟随**（之前主题只影响按钮，不影响背景氛围）
- **改进**: ambient blob 颜色从硬编码 `rgba(91,140,255,0.55)` 蓝紫改为 `color-mix(var(--gradient-from) 38%, transparent)` — 切换主题后呼吸光晕也跟随主题色相，蓝/紫/绿/橙/金各主题视觉氛围独立
- **改进**: titlebar 浅色玻璃从 `rgba(255,255,255,0.75) → rgba(244,247,251,0.65)` 改为 `rgba(255,255,255,0.78) → rgba(229,235,245,0.65)`；深色从中性深灰改为深空蓝调 `rgba(22,30,48,0.85) → rgba(11,18,32,0.75)`
- **修复**: App 根 `<div>` 去除 `bg-background` 实色 class — 之前覆盖 body 渐变，导致渐变背景看不见

#### 主题色扩展 — 新增 11 个高级主题（共 32 种）
- **新增**: 「奢华配色」分组 4 个 — `gold` 奢华金 `#C9A227` / `navy` 海军蓝 `#1E40AF` / `wine` 酒红 `#9F1239` / `champagne` 香槟 `#B89968`，适合金融、商务、奢侈品风格场景
- **新增**: 「莫兰迪色系」分组 4 个 — `dustyblue` 烟雾蓝 `#64748B` / `terracotta` 陶土橙 `#B45434` / `sage` 鼠尾草 `#6B8E5A` / `mauve` 烟紫 `#8E7CC3`，高级灰调降饱和，长时间使用不疲劳
- **新增**: 「自然深色」分组 3 个 — `coral` 珊瑚粉 `#F87171` / `forest` 森林绿 `#166534` / `ocean` 深海青 `#155E75`，沉静自然质感
- **改进**: 每个新主题配套深色模式独立色值（如 `forest` 浅色 `#166534` 深色 `#4ADE80`），保证 WCAG 对比度
- **同步**: `accounts.ts` 主题切换时移除列表加入 11 个新类；`zh.ts` / `en.ts` / `AboutPage.tsx` 中 "21 种主题" → "32 种主题"

#### 额度统计进度条增强
- **新增**: 进度条上方右侧增加**实时百分比药丸** — 按使用率分级变色：< 50% 绿、50-80% 黄、80-100% 橙、> 100% 红
- **新增**: 超额时进度条采用**双段视觉化** — 基础段（0-100% 填满，按使用率分级颜色）+ 右侧叠加深红条纹超额段（`animate-pulse` + 45° `repeating-linear-gradient` 斜纹），超额段视觉宽度按相对超额比例计算（最多 60% 避免完全遮盖）
- **新增**: 超额时进度条下方追加**红色警示横幅** — 显示「⚠️ 已超额 +X.XX%」+「超额积分：Y 积分」，使用 `bg-red-500/10` + `border-red-500/30` 区域强调
- **改进**: 百分比和超额比例都跟随 `usagePrecision` 设置（开启时 2 位小数，关闭时 1 位）

### v1.6.6 (2026-5-17)

#### E2E 测试套件
- **新增**: 完整 E2E 兼容性测试套件 `test/e2e-fullsuite/` (**30 个用例, 29/30 通过**) — 覆盖 Claude Code / OpenCode 真实抓包请求 + 边界/错误路径
- **新增**: 基础协议覆盖 (CASE 01-16): probe、流式/非流式、system array、工具 (snake/Pascal/MCP-schema)、多轮 tool_result+text 回归、thinking signature、Claude Code Skill 复刻、12KB 大 description、OpenAI 流式/工具调用、opencode reasoning/multi-turn/promptCacheKey
- **新增**: 错误路径覆盖 (CASE 17-21): 无 token / 错 token (401)、非法 JSON (400)、未知模型兜底、客户端 abort 清理
- **新增**: 特殊端点 (CASE 22-24): `/v1/messages/count_tokens`、`/v1/models`、`/v1/responses` (OpenAI Responses API)
- **新增**: 多模态/字段 (CASE 25-28): image base64、`tool_choice=any/none`、`stop_sequences`
- **新增**: Admin/路由 (CASE 29-30): admin/stats 请求计数追踪、admin/config apiKeys 可读
- **新增**: 零依赖 runner (`node test/e2e-fullsuite/run.mjs`)，支持 `--only <id|tag>` 过滤、JSON 报告 (`last-report.json`)
- **新增**: `npm run test:e2e` 和 `npm run test:e2e:only` 脚本；完整文档见 `docs/E2E-TESTING.md`
- **说明**: 默认模型 `claude-sonnet-4.5` (可改为 `claude-opus-4.7` 等)；CASE 01 probe 断言已放宽 (Kiro 反代无 probe-intercept)

#### 日志优化
- **优化**: 所有 API 日志（CBOR/REST）显示账号邮箱，方便识别来源
- **优化**: API 响应日志拆分为一行摘要 + 可展开 JSON 详情（点击 ⓘ 查看）
- **优化**: 日志中移除 token 明文（安全），改为 `token=N字符` 长度指示
- **优化**: 冗余多行日志合并 — `[IPC]`、`[Kiro API]`、`[Kiro REST API]` 每次请求/响应各 1 行
- **优化**: `[KiroPayload]` 和 `[KiroAPI] Request to` 结构化数据放入可展开详情
- **移除**: `[REST->Unified] Converting response` 重复日志、`Using K-Proxy agent` 噪音日志

#### 账号池策略
- **新增**: 账号选择策略可配置 — `round-robin`（轮询，默认，负载均衡）或 `sticky`（粘滞，保留 prompt cache）；多账号轮询开关旁有 UI 切换
- **修复**: 🔥 多账号"轮询"实际没轮询 — `recordSuccess` 总是把 `currentIndex` 固定在成功账号，导致连续成功请求一直粘在同一账号，直到失败才切换。默认改为真正的 round-robin（`currentIndex = (success + 1) % len`）。原 sticky 行为保留为可选项，适合需要 prompt cache 复用的场景。

#### UI 提示
- **新增**: 可用模型对话框新增可关闭的 IP 限制提示 — 订阅 Pro/Pro Max 但看不到高级模型？很可能是国内 IP 被限制；提示开启 VPN/代理或切换到美国/欧洲住宅 IP。通过 `localStorage('models_dialog_ip_tip_dismissed')` 持久化关闭状态。

#### 日志查看器增强
- **优化**: 反代详细日志弹窗 — 分页改为虚拟滚动 + 智能自动跟随 + 「回到底部」浮动按钮
- **优化**: 系统日志页面 — 新增时间范围筛选（1h/6h/1d/7d）、分类下拉、显示条数选择器（5K–100K）
- **优化**: 系统日志拉取数量跟随用户选择的显示条数，不再固定 3000
- **优化**: 两个日志页面统一交互体验：向上滚动暂停跟随、底部状态指示、新日志数 badge

#### 高级配置
- **新增**: Payload 大小限制可在高级设置中配置（256KB–10240KB，默认 1536KB/1.5MB）
- **变更**: Payload 截断阈值从 380KB 提升到 1.5MB — 支持 200K+ token 大上下文模型，避免误截断
- **变更**: 工具结果截断长度从 2000 提升到 4000 字符

#### Bug 修复
- **修复**: 🔥 **多轮 thinking / Claude Code Skill 502** — `history.assistantResponseMessage.reasoningContent` 被 Kiro 后端 schema 拒绝触发 `400 Improperly formed request`。现在 history 中丢弃 thinking blocks（当前消息的 thinking 仍通过 `additionalModelRequestFields.thinking={type:'adaptive'}` 控制）。Anthropic 和 OpenAI 转换器双路径都修复。E2E CASE-08/09 暴露并验证。
- **修复**: 缓存 token 双重计费 — `input_tokens` 现在扣除 `cache_read` + `cache_creation`，符合 Anthropic 官方规范（之前会让客户端账单显示虚高）
- **修复**: 未知模型兜底 — `mapModelId` 完全未识别的模型名现在兜底到 `MODEL_ID_MAP.default` (claude-sonnet-4.5)，保留 `claude-{sonnet|haiku|opus}-{ver}` 格式的向前兼容透传。之前用户拼错 model 名会触发上游 `400 Improperly formed request`。E2E CASE-20 暴露并验证。
- **修复**: 非流式路径统计字段缺失 — `/v1/responses`（流式 + 非流式）、`/v1/chat/completions` 非流式、`/v1/messages` 非流式 4 处的 `recordRequest` 和 `onResponse` 事件都漏传 `credits` / `responseTime` / `cacheReadTokens` / `reasoningTokens`，导致前端日志表「Credits」「耗时」列对非流式请求显示 `-`。4 处全部补齐完整事件载荷与持久化字段。

### v1.6.5 (2026-5-15)

#### Prompt Cache 模拟器
- **新增**: 完整的 prompt cache 模拟 — 追踪 `cache_control` 断点，按账号计算 `cache_read_input_tokens` 和 `cache_creation_input_tokens`，在 API 响应中返回真实缓存 usage
- **新增**: 反代面板显示缓存命中率百分比 badge
- **新增**: 三级检测：工具 → system → 消息块，支持 `ephemeral` TTL（5分钟/1小时）

#### 前端面板增强
- **新增**: 第二行统计卡片 — 总 Tokens、输入/输出、缓存命中率、推理 Tokens、成功率、Credits
- **新增**: 大数字自动缩写（如 `206.3M`、`1096K`），hover 显示完整数值
- **新增**: 日志表新增列 — 缓存读取（绿色）、响应耗时
- **新增**: 侧边栏新增系统日志页面 — 完整控制台输出、虚拟滚动、级别筛选、搜索、自动跟随

#### 系统日志页面
- **新增**: 独立日志页面，显示所有系统输出（反代、API、账号、后台任务）
- **新增**: Console 拦截器，`console.log/warn/error` 全部进入日志存储
- **新增**: 虚拟滚动（`@tanstack/react-virtual`）— 10 万条以上不卡顿
- **新增**: 智能自动滚动 — 在底部自动跟随，向上滚动暂停，浮动「回到底部」按钮显示新日志数
- **新增**: 级别筛选按钮组（ALL/DEBUG/INFO/WARN/ERROR），每个级别显示彩色计数
- **新增**: Grid 对齐列、分类颜色编码（Kiro=蓝、ProxyServer=紫、KiroAPI=青）
- **新增**: 点击展开数据详情（JSON 格式化），流式事件聚合为单条摘要

#### Bug 修复
- **修复**: `tool_result content block N requires text` — 空/null 工具结果规范化为 `"(no output)"`，不再抛 400
- **修复**: Thinking 参数发送给非 Claude 模型导致 400 — 现在仅对 Claude 4+ 模型发送（`modelSupportsThinkingParam()`）
- **修复**: 流式事件日志刷屏 — 开启 `logStreamEvents` 时聚合为单条请求摘要
- **新增**: 隐藏模型 ID 加入模型列表 — `simple-task`、`CLAUDE_SONNET_4_20250514_V1_0`、`CLAUDE_HAIKU_4_5_20251001_V1_0`、`CLAUDE_3_7_SONNET_20250219_V1_0`

### v1.6.4 (2026-5-14)

#### API 反代
- **修复**: Claude Code 的 `thinking` 参数不再触发 `400 REQUEST_BODY_INVALID` — 所有 thinking 请求统一映射为 Kiro 枚举 `{ type: "adaptive" }`（Kiro schema 仅接受 `["adaptive", "disabled"]`）
- **修复**: `context_management`、`effort`、`anthropic_beta` 不再注入 `additionalModelRequestFields` — Kiro schema 不允许额外属性，仅 `thinking` 可用
- **修复**: System prompt 不再以 `--- SYSTEM PROMPT ---` 文本标记嵌入用户消息（被 Claude 模型识别为 prompt injection）— 改用 Kiro 官方 Human/AI pair 注入方式，与官方 IDE 行为一致
- **修复**: CodeWhisperer 模型 ID 解析不再把 `claude-opus-4.7` 错误映射到 Sonnet 模型 — 匹配逻辑新增模型家族互斥（opus/sonnet/haiku 不可交叉匹配）
- **修复**: 模型匹配不再搜索 description 文本，降低新模型未在 `ListAvailableModels` 中时的误匹配
- **修复**: Token 估算修正 — 输入（JSON payload）使用 0.3 token/字符，输出（自然语言）使用 0.4 token/字符，并提供 CJK 感知的 `estimateTokens()` 辅助函数
- **变更**: AmazonQ CLI 端点 origin 更新为 `AI_EDITOR`

#### 会话稳定性与防封
- **新增**: `conversationId` 稳定化 — 同一客户端会话的多轮请求复用同一个 `conversationId`（与官方 Kiro IDE 行为一致）
- **新增**: 三级会话检测：HTTP Header（`X-Claude-Code-Session-Id`、`x-opencode-session`、`x-session-affinity`）→ Body 字段（`conversation_id`、`thread_id`、`session_id`）→ History 指纹兜底
- **新增**: API Key 隔离 — 不同 API Key 自动获得独立的会话命名空间
- **新增**: `/admin/cache/clear` 端点 — 手动清除 conversationId 映射和模型缓存

#### Claude Code 兼容性
- **新增**: `redacted_thinking` 加密思考块支持 — Kiro `ReasoningContentEvent.redactedContent` 解码并转换为 Anthropic `redacted_thinking` 内容块（请求输入和响应输出双向支持）
- **新增**: Payload 大小限制器 — 当 payload 超过 380KB 时，从最旧的大型工具结果开始截断为 2000 字符（保留截断标记），防止 Kiro API 拒绝长会话
- **新增**: OpenAI 兼容的 `thinking` 参数也映射到 Kiro `additionalModelRequestFields`

### v1.6.2 (2026-5-13)

#### 账号切换
- **修复**: 切换 Google/GitHub 社交登录账号后 Kiro IDE 不再报 `Invalid token` 错误
- **修复**: 切号前先刷新 Token，确保写入 `kiro-auth-token.json` 的 `accessToken` 始终有效
- **修复**: `profileArn` 始终写入 token 文件，未存储时根据 provider 自动推导（Google/GitHub → 社交 profile，BuilderId → Builder profile）
- **修复**: 社交登录的 token 文件格式与官方 Kiro IDE 完全一致（不再多余写入 `region`、`clientIdHash` 字段）
- **修复**: Kiro CLI 切号同步支持切号前刷新 Token、写入 `profileArn`，并正确区分 social 和 IdC 登录
- **修复**: CLI 的 `isSocial` 判断不再把 BuilderId 错误归类为社交登录

#### 一键客户端配置
- **修复**: 一键配置客户端优先从代理服务加载模型（与"查看模型"一致），代理未启动时回退到账号直连
- **修复**: Claude Code 配置现在写入 `ANTHROPIC_DEFAULT_HAIKU_MODEL`、`ANTHROPIC_DEFAULT_OPUS_MODEL`、`ANTHROPIC_DEFAULT_SONNET_MODEL` 字段，匹配完整官方配置格式
- **修复**: 隐藏模型（如 `claude-3.7-sonnet`）现在也会出现在一键配置的模型列表中

#### 代理与网络
- **新增**: 系统代理自动检测 — Windows（注册表 `Internet Settings`）和 macOS（`scutil --proxy`），30 秒缓存
- **修复**: 所有出站连接统一代理优先级：用户手动设置代理 → 系统代理 → 直连
- **修复**: 注册模块（MoEmail、TempMail.Plus、Outlook OAuth、TLS 客户端）不再使用独立的代理输入框，自动跟随全局代理设置
- **修复**: 反代服务的图片下载也支持系统代理回退

#### 注册功能
- **新增**: 注册成功后自动获取 Kiro Pro 订阅链接 — 注册页面开关控制，结果展示在批量订阅页面「获取链接」标签
- **优化**: 并发注册日志隔离 — 每个批量任务日志自动加 `[#taskId]` 前缀，避免多线程日志混乱
- **优化**: 注册日志事件携带结构化 `{ message, taskId }`，便于过滤
- **修复**: `refreshAppJSConfig` 使用 Promise 锁防止并发 worker 竞争下载 app.js
- **移除**: 注册页面的独立代理输入框（统一使用全局代理设置）

### v1.6.1 (2026-5-12)

#### API 反代兼容性
- **修复**: OpenCode 会话压缩请求携带历史工具调用时，不再触发 Kiro API `400 Improperly formed request`
- **修复**: 原生 history 模式补齐官方 Kiro 风格的会话清洗流程，包括工具结果重定位、孤儿工具结果移除、缺失工具结果补齐、消息交替和最终校验
- **修复**: 当当前请求没有匹配的工具定义时，历史工具调用/工具结果会转为普通文本，保留压缩上下文，同时避免 Kiro 后端工具 schema 校验失败
- **修复**: AmazonQ CLI 端点 `/SendMessageStreaming` 使用正确的 `CLI` origin，并移除无效的 `amazonq-cli` 自动回退到 IDE 协议端点策略
- **优化**: Kiro 请求诊断日志新增当前工具结果数、历史消息数、历史工具调用/结果数量，便于排查 payload 结构问题

#### 一键客户端配置
- **修复**: 新安装后添加首个账号再打开一键配置客户端时，不再因账号模型接口返回空列表而显示“暂无模型”
- **修复**: 账号模型加载现在会向 `ListAvailableModels` 传递完整账号身份字段（`machineId`、`provider`、`authMethod`、`accountId`）
- **修复**: 一键配置客户端在账号级模型加载成功但模型列表为空时，会继续回退到反代模型加载链路
- **修复**: 账号详情页模型列表同步使用完整账号身份字段，提升新添加账号的模型加载一致性

#### 账号刷新与状态
- **修复**: `fetch failed` 等网络错误、Token 过期、刷新失败和 `UnauthorizedException` 不再计入封号统计
- **修复**: 自动刷新只跳过明确暂停/封禁信号（`AccountSuspendedException`、`AccountSuspended` 或 HTTP `423`）的账号，临时网络/Token 错误后续仍可重试
- **修复**: 账号卡片、账号选择弹窗、封禁筛选和封号统计统一使用更严格的暂停/封禁识别逻辑
- **修复**: 普通 HTTP `403` 在账号状态检查中不再被当作封号信号

### v1.6.0 (2026-5-12)

#### 反代 API 增强
- **新增**: Gemini v1beta API 兼容（`/v1beta/models`、`/v1beta/models/{model}:generateContent`、`/v1beta/models/{model}:streamGenerateContent`）
- **新增**: 一键配置客户端支持 6 种：Claude Code、OpenCode、Codex CLI、Gemini CLI、Hermes、OpenClaw
- **新增**: AmazonQ CLI 端点隔离 — `amazonq-cli` 首选端点仅使用 SendMessageStreaming，失败不回退
- **新增**: 智能账号轮换 — 断路器 + 粘滞行为 + 指数退避 + 概率重试（参考 Kiro Gateway 架构）
- **新增**: 错误分类系统 — `FATAL`（请求问题，直接返回）vs `RECOVERABLE`（账号问题，切换下一个）
- **新增**: 主动配额过滤 — 已耗尽账号在选择前即被排除，不再等 429 才发现
- **新增**: `onPoolEmpty` 懒加载回调 — 代理收到首个请求时自动从 store 加载账号（修复 Mac 冷启动 503）
- **新增**: 冷启动账号池同步重试机制（5 次重试，2s/4s/6s/8s/10s 间隔）
- **新增**: 模型能力标签 — 模型列表显示 Thinking/Caching/Effort 等能力（从 ListAvailableModels 解析）
- **新增**: 隐藏模型支持 — Claude 3.7 Sonnet 等未在官方列表中但后端支持的模型
- **优化**: 请求头/UA/版本号完全匹配官方 Kiro IDE 0.12.155 抢包（SDK 1.0.34、动态 OS/Node 指纹）
- **优化**: 请求体新增 agentContinuationId/agentTaskType 字段，匹配官方协议
- **优化**: 所有出站请求统一走应用级 HTTP 代理（包括 Token 刷新、SSO 登录、图片下载等）
- **优化**: machineId 空值兆底（SHA-256 哈希）、Token 刷新随机 jitter（0-3s）、IDC UA 动态 OS
- **优化**: K-Proxy MITM 新增 body 中 machineId 替换 + telemetry 域名 kiro.dev 拦截
- **优化**: 工具调用 token 估算覆盖全部出口（工具名 + 参数 JSON）
- **优化**: 503 错误信息包含配额详情（`All accounts quota exhausted (X/Y exhausted, Z in cooldown)`）
- **优化**: 扩展配额错误检测模式（402、429、ThrottlingException、ServiceQuotaExceededException、rate limit、limit exceeded）
- **新增**: 流式日志开关 — 默认关闭，开启后显示每个流式事件的详细 JSON（assistantResponseEvent/toolUseEvent 等）
- **优化**: Thinking 模式简化 — 移除旧的 `<thinking>` 标签检测，直接透传原生 reasoningContentEvent 为 OpenAI `reasoning_content` / Claude thinking block
- **新增**: `additionalModelRequestFields` 支持 — 客户端发送 `thinking` 参数时透传给 Kiro API

#### 账号切换
- **新增**: Kiro CLI 切号支持 — 写入凭证到 `~/.local/share/kiro-cli/data.sqlite3` SQLite 数据库
- **新增**: 设置中可选择切号目标：「Kiro IDE」/「Kiro CLI」/「两者 (IDE + CLI)」（默认 IDE）
- **新增**: 手动切号和自动切号均遵循 `switchTarget` 设置
- **新增**: CLI 切号使用 Read-Merge-Write 策略，保留未知字段，清理过期优先级 key

#### 订阅与超额
- **新增**: 批量超额设置页面 —「一键超额」（仅未开启）和「全部设置」（所有已订阅）按钮
- **新增**: 账号超额状态总览表（订阅类型、超额能力、超额状态）
- **修复**: `overageStatus` 字段检测 — 正确将 REST API 的 `"ENABLED"`/`"DISABLED"` 字符串映射为布尔值
- **修复**: 批量检查和批量刷新现在会返回 `resourceDetail` 和 `overageCapability` 给前端

#### UI & 交互
- **新增**: 注册页面全面重设计 — 使用 Card/Button/Input/Label/Progress/Badge/Switch 组件库
- **新增**: 订阅页面 Header 重设计 — 渐变色横幅风格
- **新增**: 两个页面均支持主题色切换和深色模式
- **修复**: 批量注册进度/历史切页后不再丢失（模块级 React setter refs）
- **修复**: Windows 开发终端中文乱码（dev 脚本前置 `chcp 65001`）

#### 账号注册
- **新增**: 账号注册功能（手动 / MoEmail / Outlook / 自建域名 模式）
- **新增**: 自建域名模式 — 用户提供域名（配置 catch-all 转发到 TempMail.Plus），系统自动生成随机英文人名邮箱前缀注册
- **新增**: 并发批量注册 — 可配置并发数（1-10 个任务同时执行）
- **新增**: 批量注册，支持自动导入、失败重试、每项状态跟踪
- **新增**: 手动模式步骤进度指示器
- **新增**: 所有模式注册成功后自动验活并导入账号
- **新增**: 会话级注册状态持久化（日志、阶段、历史切换页面后保留）
- **新增**: 手动模式支持中途取消注册
- **新增**: 注册页面完整 i18n 支持（中/英）

#### Bug 修复
- **修复**: 模型别名映射改为精确匹配，`claude-opus-4.7` 等动态模型不再被降级
- **修复**: 代理测试页加载真实 `/v1/models` 结果，避免选择不可用的静态别名
- **修复**: 未知模型 ID 原样透传，不再重映射到静态 Claude 默认值
- **修复**: 代理默认端点顺序改为 AmazonQ 优先，CodeWhisperer 备用
- **修复**: 反代流式请求通过应用级 HTTP 代理路由
- **修复**: CodeWhisperer 请求解析短别名为 `ListAvailableModels` 官方 ID
- **修复**: CodeWhisperer 请求包含 `x-amzn-kiro-agent-mode` 头
- **修复**: 解决注册页面白屏问题（TDZ 错误）
- **修复**: 解决手动模式注册后账号被重复导入
- **修复**: TLS 指纹升级到 `chrome_144`
- **修复**: 修正 `tlsclientwrapper` API 调用方式 — body 为第2参数、options 为第3参数

### v1.5.0 (2025-02-06)
- 🌐 **API 区域路由修复**: 修复 EU 账号调用 ListAvailableModels/fetchSubscriptionToken/fetchAvailableSubscriptions 时 403 错误，所有 API 调用根据账号区域路由到正确端点（eu-* → eu-central-1，其他 → us-east-1）
- 🔄 **区域 Fallback 机制**: 主端点返回 403 时自动尝试另一个区域端点，确保所有区域（ap-*、ca-*、sa-*、me-*、af-*）账号都能正常调用
- 🔄 **Stale 状态修复**: 修复 GetUserInfo 返回 Stale 状态时被误判为错误的问题，Stale 现在视为正常状态
- 📋 **模型列表增强**: fetchKiroModels 现在传递 profileArn 参数并支持分页，与官方插件一致，返回完整模型列表
- ⚙️ **Kiro 设置页更新**: Model Selection 改为下拉框动态获取当前账号可用模型（fallback 到文本输入）；新增 Trusted Tools 配置项；描述文本全部与官方 IDE 对齐
- ⚙️ **设置页模型获取优化**: 使用当前激活账号（isActive）而非 store 中第一个账号获取模型列表
- 🔧 **反代模型获取修复**: getAvailableModels 改用 getAvailableAccount() 替代 getNextAccount()，关闭轮询后指定账号能被正确使用
- 🔄 **CBOR → REST 自动 Fallback**: Enterprise/IdC 账号 CBOR API 失败时自动降级到 REST API（与官方 IDE 一致）
- 💾 **磁盘写入优化**: 新增 debouncedStoreSet 防抖机制，将每次请求多次 store.set() 合并为每 5 秒批量写入；托盘菜单更新加 3 秒防抖；退出前 flushStoreWrites() 确保数据不丢失
- 🔧 **PowerShell 多路径探测**: 优化管理员权限检测和提权重启，自动探测多个 PowerShell 路径（PS7/System32/SysWOW64/PATH），兼容更多 Windows 环境
- 🐧 **Linux deb 包修复**: 添加 afterInstall 脚本，自动修复 chrome-sandbox SUID 权限和安装路径空格问题，解决 sandbox/execvp 启动失败

### v1.4.9 (2025-02-02)
- 🗺️ **AWS Region 扩展**: OIDC 和在线登录的 AWS Region 从 3 个扩展到 21 个区域，分组显示（US/Europe/Asia Pacific/Other）
- 🗺️ **AWS Region 自定义输入**: 新增自定义输入框，支持手动输入未列出的区域（如 cn-north-1）
- 🔀 **模型映射功能**: 新增模型映射管理，支持替换、别名、负载均衡三种映射模式
- 🎯 **模型映射规则**: 支持通配符 * 匹配、权重配置、按 API Key 配置不同规则
- 📋 **官方模型列表**: 模型映射自动获取 Kiro 官方模型列表，方便选择目标模型
- 📝 **模型映射说明**: 源/目标模型添加 UI 说明，明确各字段用途
- 💻 **Win11 机器码优化**: 三重备用方案获取机器码（reg query → PowerShell → WMIC）
- 🔐 **管理员权限检测**: 优化检测逻辑（PowerShell WindowsPrincipal → net session）
- 🌙 **深色模式修复**: 修复机器码页面深色模式下显示区域的背景色问题

### v1.4.8 (2025-01-29)
- 📊 **请求日志模型列**: 请求日志表格和最近请求预览区域新增模型列
- 🧠 **思考标签转换**: 检测普通响应中的 &lt;thinking&gt; 标签并根据配置转换格式
- 📜 **详细日志排序**: 修复详细日志排序，最新日志现在显示在最前面
- 📈 **API Key 用量详情**: 新增用量详情对话框，包含历史记录、按模型统计、每日统计图表
- 🗂️ **API Key 管理优化**: 弹窗宽度从 600px 增加到 800px，改善显示效果
- 🧠 **思考内容输出格式**: 新增下拉框选择 reasoning_content / &lt;thinking&gt; / &lt;think&gt; 三种格式

### v1.4.7 (2025-01-29)
- 📊 **请求日志 Token 详情**: 请求日志表格新增输入/输出 tokens 列
- 📊 **最近请求增强**: 最近请求预览区域也显示输入/输出 tokens
- 📐 **日志弹窗宽度**: 请求日志弹窗宽度从 700px 增加到 900px
- 🎯 **工具栏布局优化**: 账户管理工具栏两排按钮右对齐，缩小按钮间距
- 💰 **试用/奖励额度显示**: 修复 REST API 的 freeTrialInfo 和 bonuses 额度显示，统一时间戳格式
- 🔧 **机器码页面修复**: 修复复制/刷新按钮点击无响应的问题
- ✅ **复制反馈**: 机器码页面复制按钮现在显示“已复制”反馈
- 🔄 **刷新动画**: 机器码刷新按钮现在显示旋转动画

### v1.4.6 (2025-01-28)
- 🔑 **多 API Key 管理**: 支持创建多个 API Key，可选格式（sk-xxx / PROXY_KEY / KEY:TOKEN）
- 💰 **Credits 额度限制**: 为每个 API Key 设置独立的 Credits 使用额度上限
- 📊 **API Key 用量统计**: 记录每个 API Key 的请求数、Credits、Tokens 使用情况
- 🚫 **超额自动拒绝**: 超出 Credits 额度后返回 429 错误，阻止继续调用
- 🧠 **模型思考模式**: 为每个模型单独配置是否默认启用扩展思考模式 (Extended Thinking)
- ⏰ **时间精确显示**: API Key 创建时间和最后使用时间精确到秒
- 🔧 **K-Proxy 集成**: 新增 K-Proxy 代理服务支持，实现设备指纹管理和请求代理
- 🆔 **设备 ID 管理**: 支持账户绑定设备 ID，可导入/导出设备 ID 映射
- 🔄 **API 类型切换**: 支持 REST API (GetUsageLimits) 和 CBOR API (GetUsage) 双模式切换
- 🌐 **代理请求支持**: Kiro API 请求支持通过 K-Proxy 代理发送，使用 undici 库
- 📊 **用量查询增强**: 统一用量查询接口，自动适配不同 API 类型
- ⌨️ **全局快捷键**: 新增显示主窗口快捷键，支持自定义配置和按键录制
- 🍎 **macOS 关机修复**: 修复关机时应用阻塞问题，添加 3 秒超时强制退出
- 🍎 **macOS Dock 优化**: 点击 Dock 图标直接显示主窗口（像微信一样）

### v1.4.5 (2025-01-21)
- 🐛 **企业账号判重修复**: 修复企业认证账号（无邮箱）被误判为重复的问题，改用 userId 判断
- 🎨 **订阅标签颜色**: 详情页订阅标签颜色现在与卡片一致（PRO+ 紫色、POWER 金色、PRO 蓝色）
- 🔧 **Enterprise 身份修复**: 修复 Enterprise 账号刷新后身份提供商变为 Internal 的问题
- ⚡ **日志性能优化**: 使用 useMemo 缓存日志过滤结果，优化搜索逻辑，解决大量日志时卡顿问题
- 📐 **详情页布局**: 修复长账号名称/别名导致换行的问题，超长文本自动截断
- 📋 **邮箱快捷复制**: 点击账户卡片邮箱可直接复制到剪贴板，显示“已复制”提示
- 🔍 **筛选功能增强**: IDP 筛选添加 Enterprise 选项，新增封禁账号筛选
- 🎨 **筛选器配色**: 订阅类型筛选按钮添加彩色配色（FREE 灰色、PRO 蓝色、PRO+ 紫色、POWER 金色）
- 🐛 **订阅解析修复**: 修复 PRO+/POWER 订阅类型未正确识别的问题

### v1.4.4 (2025-01-21)
- 📊 **会话统计**: 新增本次服务运行期间的请求统计，服务重启后重新计数
- 🎯 **托盘菜单增强**: 托盘菜单显示总计/本次请求统计、订阅类型、已用/总额度，支持语言切换
- 🔄 **额度耗尽自动切换**: 单账号模式下检测到 402 额度不足错误时自动切换到下一个可用账号
-  **反代面板布局**: 统计卡片改为一行六列紧凑布局
- 🔄 **状态指示器**: 运行状态标签添加动态呼吸灯效果
- 🎨 **页面宽度统一**: API 反代页面宽度与其他页面保持一致
- 🌐 **界面翻译**: 关闭确认对话框和详细日志界面添加英文翻译支持
- 📄 **日志分页**: 详细日志支持分页显示，支持跳转页码，避免大量日志卡顿
- 🔍 **请求详情**: 日志条目支持展开查看请求详情（模型、内容长度、工具数、历史长度等）
- ⏰ **完整时间格式**: 日志时间改为完整格式 YYYY-MM-DD HH:mm:ss.ms
- 📋 **日志过滤**: 新增时间范围过滤（1h/6h/12h/1d/3d/7d/30d/180d/1y）和显示条数限制（5000-100万）
- 💾 **设置持久化**: 时间范围、显示条数、每页数量设置自动保存
- 📦 **日志存储扩容**: 后端日志存储上限从 1 万提升到 100 万条
- 🐛 **进度条修复**: 修复账号选择对话框中额度用完后进度条不显示满的问题

### v1.4.3 (2025-01-20)
- 📋 **详细日志查看器**: 新增反代服务器详细日志页面，类似控制台输出，支持实时查看所有事件
- 💾 **日志持久化**: 所有反代日志持久化保存到 `proxy-logs.json`，直到用户手动清除
- 🎨 **日志界面美化**: 美观的日志界面，支持搜索、按级别/类别过滤、自动滚动、导出和清空功能
- 🎯 **主题色适配**: 日志界面和下拉框颜色跟随用户选择的主题色变化
- 🔧 **自定义下拉框**: 将原生 select 替换为美化的自定义下拉框组件，支持图标和选中状态
- 🧠 **执行导向指令**: 自动注入执行导向指令到系统提示，防止 AI 目标漂移
- 📊 **扩展 Token 信息**: 新增 Cache Tokens（读/写）和 Reasoning Tokens 统计
- 📈 **完整 Usage 返回**: OpenAI/Claude 流式响应现在返回完整的 usage 信息
- 🔗 **API 端点布局优化**: API 端点列表改为三列布局（方法/路径/说明），POST 橙色、GET 绿色
- 🔄 **统一日志路由**: kiroApi 和 proxyServer 的日志统一通过 proxyLogger 路由到 UI
- 🐛 **日志存储修复**: 修复请求日志和详细日志使用相同文件路径导致数据丢失的问题
- 🐛 **Invalid Date 修复**: 修复加载旧日志时出现 "Invalid Date.NaN" 的问题

### v1.4.2 (2025-01-20)
- 🔄 **原生 History 支持**: 根据 Kiro 官方实现重构，使用原生 history 字段替代文本嵌入方式
- 🧹 **消息清理逻辑**: 实现 sanitizeConversation 确保消息交替、工具调用匹配等
- 🔧 **API 兼容性修复**: 修复之前因消息格式不正确导致的 400 错误

### v1.4.1 (2025-01-19)
- 💰 **Credits 显示**: 使用 Credits 替代 Tokens 显示用量
- 📊 **累计 Credits 统计**: 新增累计 Credits 统计并支持持久化
- 🔄 **清空 Credits**: 新增清空总计 Credits 按钮
- 🔍 **错误详情弹窗**: 请求日志中点击错误状态可查看错误详情
- 🔁 **自动继续轮数**: 工具调用后自动发送"继续"消息，避免流式响应中断
- 🚫 **禁用工具调用**: 新增开关移除 tools 参数，AI 直接回答不调用工具

### v1.4.0 (2025-01-19)
- 🔧 **API 400 错误修复**: 修复 Kiro API 不支持 toolResults 和 history 字段导致的请求失败，改为文本嵌入方式
- 🔄 **多账号轮询开关修复**: 修复关闭多账号轮询后仍然切换账号的问题
- 👤 **指定账号功能**: 关闭多账号轮询时可指定使用特定账号
- 🎯 **账号选择弹窗**: 新增账号选择对话框，显示邮箱、订阅类型、使用量进度条、账号状态
- 🔍 **账号搜索**: 账号选择弹窗支持按邮箱、ID、订阅类型搜索
- 🚫 **封禁状态显示**: 账号选择弹窗正确显示已封禁/错误/过期状态
- 💾 **代理配置持久化修复**: 修复端口、监听地址、API Key、首选端点、最大重试次数等配置重启后丢失的问题
- 🎨 **订阅颜色统一**: 账号选择弹窗的订阅类型颜色与账户卡片保持一致

### v1.3.9 (2025-01-19)
- � **Enterprise 登录修复**: 修复 IAM Identity Center SSO 登录，使用 Authorization Code Grant with PKCE 流程
- �🔧 **Enterprise 切号修复**: 修复 Enterprise 账户切号失败问题，使用正确的 startUrl 计算 clientIdHash
- 🚪 **退出登录按钮**: 当前使用的账号显示退出登录按钮，点击清除 SSO 缓存
- 🌙 **深色模式按钮修复**: 登录方式按钮正确支持深色模式，使用主题感知背景色
- 👤 **账户显示优化**: 没有邮箱的账户优先显示昵称，无昵称则显示 userId
- 🏷️ **Enterprise 标签更新**: 登录界面将"组织身份"改为"Enterprise"，保持一致性

### v1.3.8 (2025-01-18)
- 🏢 **IAM Identity Center SSO 登录**: 新增组织身份登录支持，通过 IAM Identity Center SSO 认证
- 🔗 **SSO Start URL 输入**: 用户可输入组织的 SSO Start URL 进行认证
- 🌍 **AWS Region 选择**: 支持 20+ 个 AWS 区域选择（美国、欧洲、亚太等）
- 🏷️ **Enterprise Provider 支持**: OIDC 凭证导入支持 `Enterprise` 身份提供商类型
- 📦 **批量导入增强**: 批量导入 JSON 示例包含 Enterprise provider 示例
- 🔄 **一键切号兼容**: 账户切换完全支持 Enterprise/IAM_SSO 身份类型
- 📊 **统计功能增强**: 账户统计支持 Enterprise 和 IAM_SSO 身份类型
- 📌 **托盘图标优化**: 托盘菜单图标改用外部 PNG 文件，支持自定义替换
- 🔄 **托盘状态同步**: 在软件界面启动/停止代理服务时，托盘状态实时同步更新
- 📝 **关闭确认对话框**: 自定义关闭确认对话框，支持记住用户选择

### v1.3.7 (2025-01-17)
- 📊 **账户可用模型**: 账户详情页新增可用模型列表，显示该账户支持的模型
- ⚡ **模型消耗倍率**: 模型列表显示消耗倍率 (rateMultiplier)，如 1.3x credit
- 🚫 **封禁详情弹窗**: 点击"已封禁"标签可查看详细封禁信息和申诉链接
- ✅ **按钮点击反馈**: API Key 复制和随机生成按钮添加点击成功反馈
- 🎨 **模型列表美化**: 优化代理可用模型弹窗的双列网格布局样式
- 🎯 **订阅流程重构**: 点击订阅标签统一先获取可用订阅列表，然后显示订阅计划页面
- 👤 **首次用户支持**: 正确处理首次用户订阅流程，使用 `qSubscriptionType` 参数创建订阅令牌
- 💳 **管理账单按钮**: 所有账户左下角都显示"管理账单"按钮，不管是否有订阅
- 📋 **链接自动复制**: 选择订阅计划后，支付链接自动复制到剪贴板
- ✅ **复制成功提示**: 显示绿色提示"链接已复制到剪贴板！"，800ms 后自动关闭弹窗
- ❌ **错误提示**: 订阅相关操作失败时，在弹窗中显示红色错误提示信息
- 🔧 **API 修复**: 统一使用正确的 `x-amzn-codewhisperer-optout-preference` 请求头
- 🌐 **API 反代 Claude Code 兼容**: 新增 `/anthropic/v1/messages`、`/v1/messages/count_tokens`、`/api/event_logging/batch` 端点
- 💾 **反代配置持久化**: 端口和 host 更改时自动保存配置
- 🔒 **CORS 头增强**: 添加 Claude Code 需要的更多请求头支持
- 📏 **工具描述长度限制**: 自动截断超过 10240 bytes 的工具描述
- 📝 **内容非空检查**: 确保发送给 Kiro API 的消息内容非空

### v1.3.6 (2025-01-17)
- 🔑 **API Key 持久化**: API Key 输入后可持久化保存，重启软件后保留
- 👁️ **API Key 显示/隐藏**: API Key 输入框支持点击切换显示/隐藏
- 🚀 **自启动修复**: 修复"随软件启动"功能不生效的问题
- 📋 **API Key 复制**: API Key 输入后可一键复制

### v1.3.5 (2025-01-17)
- 🌐 **API 反代页面多语言**: API 反代服务页面支持中英文切换
- 📋 **请求日志展示**: API 反代服务页面新增最近请求日志展示面板
- 💾 **日志持久化**: 请求日志持久化保存，重启后保留
- 📊 **日志弹窗**: 支持弹窗查看全部日志，支持导出和清空
- 🔄 **动态获取模型**: 从 Kiro API 获取模型并与预设模型合并
- 🔄 **刷新模型**: 新增手动刷新模型缓存按钮
- 🚀 **自动启动**: API 反代服务支持随软件启动自动运行
- 🔄 **异常重启**: 开启自动启动时，服务异常关闭会自动重启
- 🌐 **外网开关**: 快速切换本地访问 (127.0.0.1) 或外网访问 (0.0.0.0)
- 📊 **Token 统计修复**: 修复请求日志中 Token 数量不显示的问题
- 🔐 **复制 Access Token**: 编辑账号和复制凭证时可复制 Access Token

### v1.3.4 (2025-01-16)
- 🐛 **多账号激活状态修复**: 修复部分设备切换账号时多个账号同时显示“当前使用”的问题
- ✨ **流光边框效果**: 当前使用的账号卡片添加动态流光边框效果
- 💬 **QQ 交流群**: README 添加 QQ 交流群信息
- 🚀 **API 反代服务增强**:
  - Token 自动刷新（请求前检测过期）
  - 请求重试机制（401/403/429/5xx 智能处理）
  - IDC 认证支持 + 首选端点配置
  - Agentic 模式检测 + Thinking 模式支持
  - 系统提示注入 + 图像处理
  - 使用量统计增强 + 管理 API 端点
- 🎨 **API 反代页面美化**: 界面样式与其他页面保持一致，跟随主题色
- 📖 **使用说明文档**: 新增 API 反代服务使用指南
- 🐛 **正常账号统计修复**: 修复首页“正常账号”统计数据与实际不符的问题

### v1.3.3 (2025-01-15)
- 🍎 **macOS 机器码修复**: 修复修改机器码后刷新仍显示原始机器码的问题
- 🍎 **macOS 权限修复**: macOS 上不再错误提示"需要管理员权限"
- 🔗 **Kiro IDE 同步**: macOS 修改机器码时自动同步到 Kiro IDE 的 machineid 文件
- 🔒 **登录隐私模式**: 在线登录时可选择使用浏览器隐私/无痕模式打开
- ⚙️ **全局设置**: 设置页面新增"登录隐私模式"开关
- 🔄 **临时切换**: 登录对话框支持临时切换隐私模式（默认跟随全局设置）
- 🌐 **自动检测浏览器**: 自动检测系统默认浏览器并使用对应的隐私模式参数
- 💻 **多浏览器支持**: 支持 Chrome、Edge、Firefox、Brave、Opera 的隐私模式

### v1.3.2 (2025-01-02)
- 🔄 **自动刷新定时器修复**: 修复 Token 未过期时自动刷新定时器不检查账户信息的问题
- 🔄 **后台刷新更新修复**: 修复后台刷新结果不更新账户面板数据的问题
- 📊 **批量检查修复**: 修复批量检查账户信息不更新使用量进度条和订阅到期时间的问题
- 🎯 **百分比精度**: 使用率百分比显示现在也受"使用量精度"设置控制

### v1.3.1 (2025-01-01)
- � **检查账户按钮修复**: 修复点击"检查账户信息"按钮无视觉反馈的问题
- 🔄 **自动刷新同步修复**: 修复"同步检测账户信息"设置在自动刷新时不生效的问题
- 📊 **使用量精度设置**: 新增使用量显示精度切换（整数/小数）
- 🔢 **精确使用量数据**: 后端现在保存精确的小数使用量数据（如 1.22 而非 1）
- ⚙️ **GitHub Actions 优化**: 移除 tag 触发条件，改为仅支持手动触发；发布默认不再是草稿
- 🐛 **导入修复**: 修复同邮箱不同提供商（GitHub/Google）账号无法导入的问题

### v1.3.0 (2025-12-30)
- 🌐 **多语言支持**: 完整的中英文双语界面
- 🌐 **语言设置**: 支持自动检测系统语言或手动选择
- 🐧 **Linux 修复**: 修复安装路径包含空格导致启动失败的问题
- 🐧 **Linux 修复**: 修复机器码权限提升在 Wayland 环境下失败的问题
- 🍎 **macOS 修复**: 修复 DMG 无法打开的签名问题
- 🔧 **编辑账号优化**: 社交登录账号（Google/GitHub）编辑时只显示 Refresh Token
- ⚙️ **自动刷新设置**: 新增"同步检测账户信息"开关，可单独控制是否在刷新时检测用量和封禁状态

### v1.2.9 (2025-12-17)
- 🔍 **批量检查修复**: 批量检查现在和单个检查效果一致，能正确检测封禁状态
- 📤 **导出格式增强**: TXT 和剪贴板导出在勾选「包含凭证」时可直接用于导入
- 🏢 **Teams 订阅支持**: 新增 Teams 订阅类型识别
- 🎨 **机器码页面美化**: 全新设计的机器码管理页面，新增统计卡片和优化布局
- 🎯 **主题色统一**: 机器码管理页面颜色跟随用户选择的主题色变化

### v1.2.5 (2025-12-09)
- 🎨 **主题系统升级**: 主题颜色从 13 个增加到 21 个，按色系分组显示
- 📊 **额度统计**: 主页新增总额度统计卡片，实时汇总所有账号用量
- 💾 **多格式导出**: 支持 JSON、TXT、CSV、剪贴板等多种导出格式
- 🔧 **机器码优化**: 新增搜索功能和最后修改时间显示
- 🐛 **修复**: 修复部分主题颜色切换无效的问题

### v1.1.0
- 新增机器码管理功能
- 新增批量设置分组/标签功能
- 优化自动刷新，同步更新账户信息
- 新增 13 种主题颜色
- 界面优化和 Bug 修复

### v1.0.0
- 初始版本发布
- 支持多账号管理和切换
- 支持自动 Token 刷新
- 支持分组和标签管理
- 支持隐私模式和代理设置

---

## 📄 许可证

本项目基于 [AGPL-3.0 License](LICENSE) 开源。

---

## 👨‍💻 作者

- **GitHub**: [chaogei](https://github.com/chaogei)
- **项目主页**: [Kiro-account-manager](https://github.com/chaogei/Kiro-account-manager)

---

## 🙏 致谢

感谢所有使用和支持本项目的用户！

如果这个项目对你有帮助，欢迎 Star ⭐ 支持一下！
