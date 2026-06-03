# 本地 Skills 管理界面需求文档

## 1. 背景

当前项目是 Electron + React 桌面应用：

- 主进程集中在 `src/main/index.ts`，通过 `ipcMain.handle` 暴露本地文件、系统配置和账号能力。
- 预加载层通过 `src/preload/index.ts` / `src/preload/index.d.ts` 将 IPC 能力桥接到 `window.api`。
- 渲染层页面集中在 `src/renderer/src/components/pages`，侧边栏页面枚举在 `src/renderer/src/components/layout/Sidebar.tsx`，页面路由在 `src/renderer/src/App.tsx`。
- 持久化方式分两类：
  - 重要、跨进程、需要主进程访问的数据使用 `electron-store`，当前 store 名为 `kiro-accounts`，带 `encryptionKey`。
  - 纯渲染进程 UI 状态或轻量配置使用 `localStorage` / Zustand。

本需求新增一个“本地 Skills 管理”界面，用于管理本机不同 AI agent 已安装的 skills，并复用 `vercel-labs/skills` npm 包的能力模型。

## 2. 上游 skills 包能力分析

源码来源：`https://github.com/vercel-labs/skills`。

已确认上游包提供以下核心能力：

- `agents.ts`
  - 内置 50+ agents 配置。
  - 每个 agent 包含 `name`、`displayName`、项目级 `skillsDir`、全局级 `globalSkillsDir` 和安装探测逻辑。
  - Codex 全局路径为 `~/.codex/skills`；Claude Code 全局路径为 `~/.claude/skills`；Kiro CLI 全局路径为 `~/.kiro/skills`。
  - 一批 agent 使用通用项目目录 `.agents/skills`。
- `installer.ts`
  - 支持 `installSkillForAgent`、`installRemoteSkillForAgent`、`installWellKnownSkillForAgent`。
  - 默认 `symlink` 模式：先写入 canonical 目录 `.agents/skills/<skill>` 或 `~/.agents/skills/<skill>`，再为 agent-specific 目录建立软链。
  - `copy` 模式可直接复制到 agent 目录。
  - 提供 `listInstalledSkills`，可列出 project/global skills、所属 agents、canonicalPath。
- `list.ts`
  - CLI 的 `skills list` 默认列项目级，`-g` 列全局级，可按 agent 过滤，可 JSON 输出。
- `remove.ts`
  - 支持按 skill、按 agent、按 scope 删除。
  - 删除时会清理 canonical 目录与 agent-specific 目录；若 canonical 仍被其他 agent 使用，则保留。
  - 全局删除会清理全局 lock；项目级删除源码当前未显式清理 `skills-lock.json`，界面实现需要补齐。
- `update.ts`
  - 支持按 global/project/both 更新，按 skill 名过滤。
  - 可自动检查 GitHub tree hash，识别可更新、上游已删除、无法自动检查的 skill。
  - 本地路径、Git URL、well-known 或缺少 `skillFolderHash/skillPath` 的记录可能无法自动检查，只能提示用户刷新/重装。
- lock 文件
  - 全局 lock：`~/.agents/.skill-lock.json` 或 `$XDG_STATE_HOME/skills/.skill-lock.json`，版本 3。
  - 项目 lock：`skills-lock.json`，版本 1。
  - lock 记录 source、sourceType、ref、skillPath、hash 等，用于更新和来源追踪。

## 3. 目标

新增“Skills 管理”页面，提供本机全局 skills 的可视化管理：

- 按本地已安装 agents 展示。
- 每个 agent 以 Tab 呈现，Tab 标题显示该 agent 下 skills 数量。
- 支持单个 skill 的检查更新、同步、全量同步、删除、自动更新配置。
- 支持 agent 维度的搜索、批量删除、批量更新、批量同步、从其他 agent 全量同步。
- 支持跨 agent 的安装和默认自动更新开关。
- 删除 skill 后清理本应用保存的该 skill 配置；下次同名 skill 重新安装时不复用历史配置。
- skill 更新不清理该 skill 配置。

## 4. 范围

### 4.1 本期范围

- 管理全局 skills，即 agent 的 `globalSkillsDir`。
- 发现本地已安装 agents，并展示每个 agent 的 skills 列表。
- 读取并合并 skills 包 lock 信息，展示来源、更新时间、可更新状态。
- 提供基础操作和批量操作。
- 在本应用 `electron-store` 中保存 UI/策略配置。

### 4.2 暂不纳入

- 项目级 skills 管理。
- skill 内容编辑器。
- skill marketplace 浏览页的完整搜索体验。
- 定时后台自动更新任务。
  - 本期只做自动更新开关配置与手动触发；后续可接入启动时检查或定时任务。

## 5. 用户界面需求

### 5.1 页面入口

- 在侧边栏新增页面：`Skills 管理`。
- 建议图标：`Sparkles`、`Boxes` 或 `Puzzle` 类 lucide 图标。
- 页面文件建议：`src/renderer/src/components/pages/SkillsPage.tsx`。

### 5.2 顶部全局操作区

顶部固定展示：

- `安装` 按钮
  - 打开安装弹窗。
  - 输入源支持 GitHub shorthand、GitHub URL、Git URL、本地路径。
  - 可选择目标 agents，默认选中当前已安装 agents。
  - 可选择安装模式：默认 `symlink`，可选 `copy`。
- `开启默认更新` Switch
  - 控制新安装 skill 的默认 `autoUpdate`。
  - 不批量修改已安装 skill，除非用户明确选择“应用到现有 skills”。
- `刷新` 按钮
  - 重新扫描 agents、skills、lock 和本应用配置。

### 5.3 Agent Tabs

- 仅展示本机已安装的 agents。
- 每个 Tab 标题格式：`Codex (14)`。
- 数量为该 agent 全局目录下有效 skill 数量。
- 如果某个 agent 已安装但 skills 目录不存在，Tab 仍展示，数量为 0。
- Universal/canonical 目录的 skill 需要按实际可被 agent 使用的结果归属到对应 agent，避免重复计数。

### 5.4 Agent 操作区

每个 agent Tab 内顶部展示：

- 搜索框
  - 支持按 skill name、description、source、路径模糊搜索。
- 批量删除
  - 对当前选中 skills 执行。
  - 删除前二次确认。
- 批量更新
  - 对当前选中 skills 执行检查并更新。
  - 对无法自动更新的 skill 展示原因。
- 批量同步
  - 将当前选中 skills 同步到指定目标 agents。
  - 不允许选择当前 agent 作为目标。
- 从 agent 全量同步
  - 选择来源 agent。
  - 将来源 agent 的全部 skills 同步到当前 agent。
  - 已存在同名 skill 时默认跳过；可选覆盖。

### 5.5 Skill 列表

列表建议字段：

- 选择框。
- 名称。
- 描述。
- 来源 source。
- 当前路径。
- 安装方式：canonical、symlink、copy、unknown。
- 更新状态：
  - 未检查。
  - 已是最新。
  - 可更新。
  - 无法检查。
  - 检查失败。
- 自动更新 Switch。
- 操作按钮：
  - 检查更新。
  - 同步到。
  - 全量同步。
  - 删除。

交互要求：

- 删除是高风险操作，必须二次确认，并说明会清理本应用内该 skill 的自动更新配置。
- 更新不清理配置。
- 同步到其他 agent 后，同名 skill 的 per-skill 配置应按“目标 agent + skill”维度初始化，不继承来源 agent 的覆盖配置；如果目标已有配置则保留。

## 6. 数据模型

### 6.1 数据来源

页面展示数据来自三部分合并：

- 文件系统扫描结果：
  - agent 是否安装。
  - agent skills 目录。
  - `SKILL.md` frontmatter 中的 name、description、metadata。
- skills 包 lock：
  - 全局 lock 记录 source、sourceType、ref、skillPath、skillFolderHash、installedAt、updatedAt、pluginName。
- 本应用配置：
  - 默认自动更新开关。
  - 每个 agent/skill 的自动更新开关。
  - 最近检查状态缓存。
  - UI 偏好，如最近选中的 agent、搜索关键词可选保存。

### 6.2 electron-store 配置建议

新增 key：`skillsManagerConfig`。

```ts
interface SkillsManagerConfig {
  version: 1
  defaultAutoUpdate: boolean
  skillConfigs: Record<string, SkillManagerSkillConfig>
  lastSelectedAgent?: string
}

interface SkillManagerSkillConfig {
  agent: string
  skillName: string
  autoUpdate?: boolean
  createdAt: number
  updatedAt: number
}
```

`skillConfigs` 的 key 建议使用 `${agent}:${normalizedSkillName}`。

### 6.3 删除配置清理规则

- 删除某个 agent 下的 skill 后：
  - 删除 `skillsManagerConfig.skillConfigs[agent:skillName]`。
  - 如果执行“从所有 agents 删除”或“全量删除”，需要删除所有 `${anyAgent}:${skillName}` 配置。
  - 如果上游 lock 中存在该 skill 且已被真正删除，也同步清理 lock。
- 同名 skill 下次重新安装：
  - 不复用旧配置，因为旧配置已删除。
  - 使用当前 `defaultAutoUpdate` 初始化。
- 更新 skill：
  - 保留 `skillConfigs`。
  - 仅刷新最近检查结果、更新时间等运行态信息。

## 7. IPC/API 草案

建议新增主进程模块：`src/main/ipc/skillsManager.ts`。

预加载层新增：

```ts
skillsListAgents: () => Promise<SkillsAgentsResult>
skillsRefresh: () => Promise<SkillsAgentsResult>
skillsInstall: (input: SkillsInstallInput) => Promise<SkillsOperationResult>
skillsCheckUpdate: (input: { agent: string; skillName: string }) => Promise<SkillsUpdateCheckResult>
skillsUpdate: (input: { agent: string; skillNames: string[] }) => Promise<SkillsOperationResult>
skillsDelete: (input: { agent: string; skillNames: string[]; allAgents?: boolean }) => Promise<SkillsOperationResult>
skillsSync: (input: { sourceAgent: string; skillNames: string[]; targetAgents: string[]; overwrite?: boolean }) => Promise<SkillsOperationResult>
skillsGetConfig: () => Promise<SkillsManagerConfig>
skillsSaveConfig: (patch: Partial<SkillsManagerConfig>) => Promise<SkillsOperationResult>
skillsSetSkillAutoUpdate: (input: { agent: string; skillName: string; enabled: boolean }) => Promise<SkillsOperationResult>
```

### 7.1 返回结构草案

```ts
interface SkillsAgentView {
  id: string
  displayName: string
  installed: boolean
  globalSkillsDir?: string
  count: number
  skills: SkillsSkillView[]
}

interface SkillsSkillView {
  name: string
  description: string
  agent: string
  source?: string
  sourceType?: string
  ref?: string
  path: string
  canonicalPath?: string
  installedAt?: string
  updatedAt?: string
  pluginName?: string
  autoUpdate: boolean
  updateStatus?: 'unknown' | 'latest' | 'available' | 'unsupported' | 'failed'
  updateReason?: string
}
```

## 8. 操作语义

### 8.1 安装

- 调用 skills 包的 add/install 能力。
- 默认 scope 为 global。
- 默认安装到已安装 agents。
- 如果用户选择“所有 agents”，可传 `agent: ['*']` 或逐个 agent 执行。
- 安装成功后为每个目标 agent 初始化配置：
  - `autoUpdate = defaultAutoUpdate`。

### 8.2 检查更新

- 优先读取 lock。
- 有 `skillFolderHash` 和 `skillPath` 的 GitHub 来源可自动检查。
- 不支持自动检查时显示原因：
  - 本地路径。
  - Git URL。
  - well-known skill。
  - 私有或已删除 repo。
  - 缺少版本追踪字段。
- 检查更新不修改 skill 文件。

### 8.3 更新

- 只更新用户指定 skill。
- 更新成功后保留本应用配置。
- 更新失败时保留原 skill。
- 对上游已删除的 skill，不自动删除，除非用户确认。

### 8.4 同步到

- 将当前 skill 同步到目标 agents。
- 如果源 skill 是 canonical/symlink 模式：
  - 优先复用 canonical 目录。
  - 为目标 agent 建立 symlink。
- 如果 symlink 失败：
  - fallback copy，并在结果中提示。
- 如果目标已有同名 skill：
  - 默认跳过。
  - 用户选择覆盖时才替换。

### 8.5 全量同步

分两种语义：

- skill 行内“全量同步”
  - 将该 skill 同步到所有已安装 agents。
- agent 操作区“从 agent 全量同步”
  - 将来源 agent 的全部 skills 同步到当前 agent。

### 8.6 删除

- 删除当前 agent 下选中 skills。
- 行内删除默认只删除当前 agent。
- 提供“从所有 agents 删除”选项。
- 删除完成后必须清理本应用配置。
- 若删除的是最后一个使用该 canonical skill 的 agent，则删除 canonical 目录和 lock 记录。

## 9. 状态与异常

需要覆盖以下状态：

- agent 未安装。
- agent 已安装但 skills 目录不存在。
- skills 目录无权限读取。
- skill 缺失 `SKILL.md`。
- `SKILL.md` frontmatter 缺少 name/description。
- 软链损坏。
- canonical 目录存在但 agent-specific 链接缺失。
- lock 存在但 skill 文件已被手动删除。
- skill 文件存在但 lock 缺失，更新状态显示“无法检查：缺少版本追踪”。
- GitHub API rate limit 或网络失败。

## 10. 与当前项目的兼容策略

- 数据存储：
  - `skillsManagerConfig` 使用主进程 `electron-store`，与现有账号/代理配置风格一致。
  - 不建议用 `localStorage` 保存自动更新配置，因为删除清理需要主进程在文件操作后原子更新。
- IPC：
  - 避免把文件系统操作放到 renderer。
  - 所有安装、同步、删除、更新均由主进程执行。
- UI：
  - 使用现有 `Button`、`Switch`、`Input`、`Card`、`Badge` 等组件。
  - 表格/列表风格参考 `AccountManager` 和 `ConfigSyncPage`，保持页面密度。
- 依赖：
  - 若 npm 包对外导出库函数，优先直接依赖并调用。
  - 若只稳定支持 CLI，可在主进程封装 CLI 调用，但需要结构化解析输出；这会降低可靠性。

## 11. 待确认问题

- 本期是否只管理全局 skills？当前文档按“全局”定义；项目级可作为二期。
- 安装来源是否需要支持 skills.sh 搜索？还是先只支持用户输入 source。
- 自动更新开关本期是否需要真正后台执行？当前建议本期只存配置，后续再接启动时/定时检查。
- “同步到其他 agent”时，同名 skill 默认跳过还是默认覆盖？当前建议默认跳过。
- 是否需要支持打开 skill 所在目录或查看 `SKILL.md`？这对排查很有用，但不在原始需求内。

## 12. 验收标准

- 页面能列出本机已安装 agents，并且每个 Tab 数量正确。
- 每个 Tab 能展示该 agent 的 skills 列表并支持搜索。
- 单个 skill 可检查更新、同步到指定 agents、同步到所有 agents、删除、切换自动更新。
- agent 维度可批量删除、批量更新、批量同步、从其他 agent 全量同步。
- 顶部可安装 skill，并可设置默认自动更新。
- 删除 skill 后，对应 `skillsManagerConfig.skillConfigs` 被清理。
- 更新 skill 后，对应配置仍保留。
- 同名 skill 删除后再安装，使用当前默认配置，不复用旧配置。
- 对缺 lock、私有源、本地路径、网络失败等情况有明确状态提示。
