# Kiro 账户管理器 v1.3.8 更新说明

发布日期：2025-01-18

## 🏢 IAM Identity Center SSO 登录

### 新增组织身份登录
- **登录入口**：添加账户对话框新增"组织身份"登录按钮
- **SSO Start URL**：支持输入组织的 SSO Start URL 进行认证
- **设备授权流程**：采用 AWS IAM Identity Center 设备授权流程

### AWS Region 支持
支持 20+ 个 AWS 区域，按地区分组：

| 地区 | 支持的 Region |
|------|--------------|
| 美国 | us-east-1, us-east-2, us-west-1, us-west-2 |
| 欧洲 | eu-west-1, eu-west-2, eu-west-3, eu-central-1, eu-north-1, eu-south-1 |
| 亚太 | ap-northeast-1, ap-northeast-2, ap-northeast-3, ap-southeast-1, ap-southeast-2, ap-south-1, ap-east-1 |
| 其他 | ca-central-1, sa-east-1, me-south-1, af-south-1 |

## 🏷️ Enterprise Provider 支持

### OIDC 凭证导入
- **单个导入**：登录类型新增三个选项：Builder ID | 组织身份 | Social
- **批量导入**：支持 `provider: "Enterprise"` 字段

### 支持的 Provider 类型

| Provider | 说明 | authMethod |
|----------|------|------------|
| `BuilderId` | AWS Builder ID | IdC |
| `Enterprise` | 组织身份 (IAM SSO) | IdC |
| `Google` | Google 登录 | social |
| `Github` | GitHub 登录 | social |

### 批量导入 JSON 示例
```json
[
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
]
```

## 🔄 一键切号兼容性

### 账户切换支持
- 完全兼容 Enterprise 和 IAM_SSO 身份类型
- 切换账户时正确传递 provider 信息

## 📊 统计功能增强

### 账户统计
- `byIdp` 统计新增 `Enterprise` 和 `IAM_SSO` 类型
- 账户卡片正确显示身份提供商标签

## 📌 系统托盘增强

### 托盘图标优化
- **外部图标支持**：托盘菜单图标改用外部 PNG 文件，支持自定义替换
- **图标缓存**：图标加载后缓存，提升菜单响应速度
- **新增图标**：用量、请求数等信息现有专属图标

### 托盘状态同步
- **界面操作同步**：在软件界面启动/停止代理服务时，托盘状态实时同步更新

### 关闭确认对话框
- **自定义对话框**：关闭窗口时显示自定义确认对话框
- **记住选择**：支持记住用户的关闭操作选择

## 📝 代码变更

### 类型定义 (account.ts)
- `IdpType` 新增 `Enterprise` 和 `IAM_SSO`
- `AccountCredentials.provider` 支持新类型

### 主进程 (index.ts)
- 新增 `start-iam-sso-login` IPC handler
- 新增 `poll-iam-sso-auth` IPC handler
- 新增 `cancel-iam-sso-login` IPC handler
- `currentLoginState.type` 支持 `'iamsso'`

### Preload API (index.ts, index.d.ts)
- 新增 `startIamSsoLogin(startUrl, region)` 方法
- 新增 `pollIamSsoAuth(region)` 方法
- 新增 `cancelIamSsoLogin()` 方法

### 添加账户对话框 (AddAccountDialog.tsx)
- `LoginType` 新增 `'iamsso'`
- 新增 SSO Start URL 输入框
- 新增 AWS Region 下拉选择
- 登录类型按钮：Builder ID | 组织身份 | Social
- 批量导入 JSON 示例更新

### 账户存储 (accounts.ts)
- `byIdp` 统计支持 Enterprise 和 IAM_SSO

---

**完整更新列表**:
- 🏢 IAM Identity Center SSO 登录
- 🔗 SSO Start URL 输入
- 🌍 20+ AWS Region 选择
- 🏷️ Enterprise Provider 支持
- 📦 批量导入增强
- 🔄 一键切号兼容
- 📊 统计功能增强
- 📌 托盘图标优化
- 🔄 托盘状态同步
- 📝 关闭确认对话框
