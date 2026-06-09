# MCP 管理整体设计

## 1. 背景与结论

本项目已经有 `Skills 管理`，其核心是“规范 skill 目录 + 投影到各 agent”。MCP 不能完全照搬目录投影，因为不同 agent 的 MCP 配置入口、字段名、传输协议表达都不一致。

结论：

- MCP 应使用“规范 MCP 配置 + agent adapter 转换写入”的模式。
- 页面上的新增、编辑、删除、同步都作用于规范配置，然后同步写入所有本机已安装且支持 MCP 的 agent。
- APP 启动时自动检查并修复缺失 agent 配置；页面提供“同步”按钮，触发同一套修复逻辑。
- Kiro 需要特殊处理：规范配置中可以是 HTTP/SSE，但写入 Kiro 时转换为 `npx -y mcp-remote <url>`；从 Kiro 读取时识别该命令并反向还原为 HTTP/SSE。

## 2. Agent MCP 注册方式梳理

不是所有 agent 都使用相同配置文件。

| Agent                     | 全局配置建议                                          | 配置结构                     | HTTP 支持处理                                                     | 备注                                                        |
| ------------------------- | ----------------------------------------------------- | ---------------------------- | ----------------------------------------------------------------- | ----------------------------------------------------------- |
| Codex                     | `~/.codex/config.toml`                                | TOML: `[mcp_servers.<name>]` | 可按 Codex 支持写 `url`，或兼容期写 stdio                         | 与 Skills 的 `codexHome` 保持一致，注意 TOML 保留其它配置   |
| Claude Code               | `~/.claude.json` user scope；项目级 `.mcp.json`       | JSON: `mcpServers`           | 原生支持 `type: "http"` / `url`                                   | 本功能做本机全局同步，优先 user scope                       |
| Kiro IDE                  | `~/.kiro/settings/mcp.json`                           | JSON: `mcpServers`           | 本项目按“不支持 HTTP”处理，写为 `npx mcp-remote`                  | 现有 Kiro 设置页已读写该文件                                |
| Kiro CLI                  | `~/.kiro/settings/mcp.json` 或 `~/.kiro/mcp.json`     | JSON: `mcpServers`           | 同 Kiro IDE                                                       | 当前项目已有 IDE 路径，首期复用 `~/.kiro/settings/mcp.json` |
| Cursor                    | `~/.cursor/mcp.json`                                  | JSON: `mcpServers`           | 原生支持 URL                                                      | 配置格式接近 Claude/Cline                                   |
| Cline                     | `~/.cline/mcp.json` 或扩展 raw config                 | JSON: `mcpServers`           | 原生支持 URL                                                      | CLI 文档给出 `~/.cline/mcp.json`                            |
| Gemini CLI                | `~/.gemini/settings.json`                             | JSON: `mcpServers`           | `httpUrl`/`url`                                                   | 与 Qwen Code 接近                                           |
| Qwen Code                 | `~/.qwen/settings.json`                               | JSON: `mcpServers`           | `httpUrl`/`url`                                                   | 项目级 `.qwen/settings.json` 暂不纳入                       |
| OpenCode                  | `~/.config/opencode/opencode.json` 或 `opencode.json` | JSON: `mcp`                  | `type: "remote"` / `url`；本地为 `type: "local"` + `command` 数组 | 字段名与主流 `mcpServers` 不同                              |
| VS Code / GitHub Copilot  | user profile 或 `.vscode/mcp.json`                    | JSON: `servers`              | 原生支持 URL                                                      | 字段为 `servers`，不是 `mcpServers`                         |
| Continue                  | `~/.continue/mcpServers/*.json`                       | 目录导入 JSON                | 可复用 Claude/Cursor JSON                                         | 首期可选支持，adapter 写单文件更稳                          |
| Windsurf / Roo / Goose 等 | 配置路径和版本差异较大                                | 多为 JSON                    | 需按实际 adapter 补齐                                             | 先只展示“待支持/未配置”，避免误写                           |

资料来源：

- Kiro MCP IDE 配置说明：`https://kiro.dev/docs/mcp/configuration/`
- Kiro Web MCP 说明中提到当前只支持 local MCP：`https://kiro.dev/docs/autonomous-agent/sandbox/mcp/`
- Codex MCP 配置：`https://www.mintlify.com/openai/codex/configuration/mcp-servers`
- Claude Code MCP scopes：`https://code.claude.com/docs/en/mcp`
- Cursor MCP：`https://docs.cursor.com/context/model-context-protocol`
- Gemini CLI MCP：`https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/mcp-server.md`
- Qwen Code MCP：`https://qwenlm.github.io/qwen-code-docs/en/developers/tools/mcp-server/`
- Cline MCP：`https://docs.cline.bot/mcp/configuring-mcp-servers`
- OpenCode MCP：`https://thdxr.dev.opencode.ai/docs/mcp-servers`
- VS Code MCP config：`https://code.visualstudio.com/docs/copilot/reference/mcp-configuration`
- Continue MCP：`https://docs.continue.dev/customize/deep-dives/mcp`

## 3. 设计目标

- 增加独立的 `MCP 管理` 页面，参考 `src/renderer/src/components/pages/skill` 的页面结构。
- 支持新增、编辑、删除、启用/禁用、同步。
- 所有 MCP 操作默认同步到所有本机已安装且支持 MCP 的 agent。
- 启动时自动检查：如果规范配置中存在 MCP，但某些 agent 缺失或配置不一致，则自动注册/修复。
- 页面同步按钮不需要用户选择源 agent，自动以规范配置为准完成同步。
- 编辑 HTTP MCP 时，Kiro 和其它 agent 之间要能正反向转换。
- 不破坏 agent 原有配置：只管理本应用写入或已被用户纳入管理的 MCP entry，保留其它未知配置。

## 4. 核心模型

新增主进程目录：`src/main/mcp`。

建议类型：

```ts
export type McpTransport = 'stdio' | 'http' | 'sse'

export interface ManagedMcpServer {
  name: string
  title?: string
  description?: string
  transport: McpTransport
  command?: string
  args?: string[]
  cwd?: string
  env?: Record<string, string>
  url?: string
  headers?: Record<string, string>
  disabled?: boolean
  autoApprove?: string[]
  disabledTools?: string[]
  timeout?: number
  source?: 'manual' | 'imported' | 'kiro-settings'
  createdAt: number
  updatedAt: number
}

export interface McpManagerConfig {
  version: 1
  servers: Record<string, ManagedMcpServer>
  managedKeys: string[]
  lastSelectedAgent?: string
  autoSyncOnStartup: boolean
  lastSyncAt?: string
}
```

持久化 key：`mcpManagerConfig`，存入现有 `electron-store`。

命名规范：

- `name` 为跨 agent 的主键。
- 使用 `normalizeMcpName(name)` 做 key，规则类似 `normalizeSkillName`。
- 重命名视为“删除旧名 + 新增新名”，对所有 agent 同步。

## 5. Adapter 架构

每个 agent 一个 adapter，统一接口：

```ts
export interface McpAgentAdapter {
  id: string
  displayName: string
  detect(): boolean
  getConfigPath(): string
  read(): Promise<McpAgentConfigReadResult>
  writeServer(server: ManagedMcpServer): Promise<McpWriteResult>
  deleteServer(name: string): Promise<McpWriteResult>
  toNative(server: ManagedMcpServer): unknown
  fromNative(name: string, value: unknown): ManagedMcpServer | null
}
```

公共能力：

- `jsonConfigAdapter`：处理 `mcpServers` JSON。
- `settingsJsonAdapter`：处理 `settings.json` 中的 `mcpServers`。
- `tomlConfigAdapter`：处理 Codex TOML。
- `opencodeAdapter`：处理 `mcp` 字段。
- `vscodeAdapter`：处理 `servers` 字段。
- `kiroAdapter`：基于 JSON adapter，但覆盖 HTTP/SSE 转换。

写入策略：

- 读文件，不存在则创建。
- JSON 写入保留未知字段，只改目标 server entry。
- TOML 写入应使用 TOML parser/stringifier；不要手写字符串拼接。
- 写入前做 `.bak` 可选备份，失败时回滚。
- 所有 adapter 写入结果统一返回 `success/error/configPath/nativeServer`。

## 6. Kiro `mcp-remote` 正反向转换

规范 HTTP：

```ts
{
  name: 'linear',
  transport: 'http',
  url: 'https://mcp.linear.app/mcp',
  headers: { Authorization: 'Bearer ${LINEAR_API_KEY}' }
}
```

写入 Kiro：

```json
{
  "mcpServers": {
    "linear": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://mcp.linear.app/mcp"],
      "env": {
        "LINEAR_API_KEY": "${LINEAR_API_KEY}"
      },
      "disabled": false
    }
  }
}
```

转换规则：

- `transport: "http"` 或 `"sse"` 且 `url` 存在时，Kiro 写为 stdio。
- `command` 固定 `npx`，`args` 固定前缀 `["-y", "mcp-remote", url]`。
- `headers` 不能直接表达到 Kiro stdio，需要两种方案：
  - 首期：提示 headers 不会被 Kiro 直接同步，只同步 URL 和 env。
  - 后续：支持 `mcp-remote` headers 参数，若确认当前版本参数格式后再加入。
- 从 Kiro 读取时，如果 `command === "npx"` 且 args 包含 `mcp-remote`，取其后的第一个 URL 还原为 `transport: "http"`。
- 如果用户在 Kiro 手写其它 stdio MCP，则保持 `transport: "stdio"`，不强行还原。

## 7. 同步模式

以规范配置为源，不以某个 agent 为源。

### 7.1 启动自动同步

在 `app.whenReady()` 后执行：

1. 读取 `mcpManagerConfig`。
2. 探测本机已安装 agent。
3. 对支持 MCP 的 agent 调用 adapter.read。
4. 对 `config.servers` 中每个 server 生成 native 配置。
5. 如果 agent 缺失该 server 或 native 配置不一致，则写入。
6. 记录 `lastSyncAt` 和 per-agent 结果。

为了避免启动卡 UI：

- 在主进程后台执行。
- 失败只记录日志，不阻塞应用打开。
- 渲染层可监听 `mcp:sync-completed` 事件刷新页面。

### 7.2 页面同步按钮

按钮行为：

- 调用 `mcp:sync`。
- 后端执行同启动同步一致的逻辑。
- 返回每个 server 在每个 agent 的状态：`created`、`updated`、`skipped`、`failed`。

### 7.3 编辑/删除同步

编辑：

1. 更新规范配置。
2. 对所有支持 MCP agent 写入转换后的 native 配置。
3. 任一 agent 失败不回滚规范配置，但结果要展示失败 agent，页面标记“部分同步失败”。

删除：

1. 从规范配置删除。
2. 对所有支持 MCP agent 删除同名 server。
3. 清理 `managedKeys`。
4. 不删除未知名字或非托管 entry。

## 8. IPC/API 草案

预加载层参考 Skills：

```ts
mcpList: () => Promise<McpListResult>
mcpGetConfig: () => Promise<McpManagerConfig>
mcpSaveServer: (input: { server: ManagedMcpServer; oldName?: string }) =>
  Promise<McpOperationResult>
mcpDeleteServer: (input: { name: string }) => Promise<McpOperationResult>
mcpSync: () => Promise<McpSyncResult>
mcpImportFromAgents: (input: { agents?: string[]; overwrite?: boolean }) =>
  Promise<McpOperationResult>
mcpSetAutoSync: (input: { enabled: boolean }) => Promise<McpOperationResult>
```

`mcpList` 返回：

```ts
interface McpListResult {
  servers: ManagedMcpServer[]
  agents: Array<{
    id: string
    displayName: string
    installed: boolean
    supported: boolean
    configPath?: string
    count: number
    servers: Array<{
      name: string
      managed: boolean
      synced: boolean
      nativeTransport: string
      configPath: string
      warning?: string
    }>
  }>
  config: McpManagerConfig
}
```

## 9. 页面设计

新增：

- `src/renderer/src/components/pages/mcp/index.tsx`
- `src/renderer/src/components/pages/mcp/useMcpManager.ts`
- `src/renderer/src/components/pages/mcp/EditModal.tsx`
- `src/renderer/src/components/pages/mcp/SyncResultModal.tsx`
- `src/renderer/src/components/pages/mcp/types.ts`

入口：

- `Sidebar.tsx` 新增 `mcp` page，图标建议 `Plug` 或 `Network`。
- `App.tsx` 和 `pages/index.ts` 接入。
- i18n 增加 `nav.mcp`。

页面结构参考 Skills：

- 顶部标题：`MCP 管理`
- 操作区：
  - `添加`
  - `同步`
  - `导入已有配置`
  - `刷新`
  - `启动自动同步` Switch
- 主表：
  - 名称
  - 传输类型：stdio/http/sse
  - 命令或 URL
  - 同步状态：全部已同步 / 部分缺失 / 部分失败
  - 已注册 agents
  - 禁用状态
  - 操作：编辑、删除、查看原生配置
- Agent Tabs：
  - 展示每个 agent 的实际 MCP 列表和配置路径。
  - 用于排查某个 agent 未同步或转换后的 native 配置。

编辑弹窗：

- Server Name
- Transport segmented control：`STDIO` / `HTTP` / `SSE`
- STDIO 字段：command、args、cwd、env
- HTTP/SSE 字段：url、headers、env
- 高级字段：timeout、autoApprove、disabledTools、disabled
- Kiro 兼容提示：当存在 headers 且 Kiro 已安装，提示 Kiro 转换限制。

## 10. 与现有 Kiro 设置页关系

现有 `KiroSettingsPage` 仍保留 MCP 区块，用于 Kiro 单配置查看/编辑。

新增 MCP 管理页是跨 agent 的统一入口：

- Kiro 设置页编辑后，可通过 MCP 管理页“导入已有配置”纳入统一管理。
- MCP 管理页编辑托管 server 后，会写回 Kiro 配置。
- 后续可把 Kiro 设置页的 MCP 操作按钮引导到 MCP 管理页，减少两套编辑入口冲突。

## 11. 实施顺序

1. 抽离 MCP 类型与 adapter 基础设施。
2. 支持 JSON `mcpServers` adapter：Kiro、Cursor、Cline。
3. 实现 Kiro `mcp-remote` 转换。
4. 支持 Codex TOML adapter。
5. 支持 Gemini/Qwen settings adapter。
6. 接 IPC 和 preload 类型。
7. 接启动自动同步。
8. 新增页面，复用 Skills 的 hook + table + modal 风格。
9. 添加单元测试：转换、读写保留未知字段、同步缺失修复、删除清理。

## 12. 测试重点

- Kiro HTTP 写入为 `npx -y mcp-remote <url>`。
- Kiro `npx mcp-remote` 能反向读取为 HTTP。
- JSON adapter 写入不会删除其它配置字段。
- Codex TOML 写入不会破坏已有 model、sandbox、profiles 配置。
- 删除只删除同名托管 MCP，不误删其它用户配置。
- 启动自动同步在 agent 配置文件不存在时能创建目录和文件。
- 某个 agent 写入失败时，其它 agent 仍完成同步，并返回部分失败。
