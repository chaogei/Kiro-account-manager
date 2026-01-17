# Kiro 账户管理器 v1.3.7 更新说明

发布日期：2025-01-18

## 🎯 订阅管理功能优化

### 订阅流程重构
- **统一订阅入口**：点击订阅标签统一先获取可用订阅列表，然后显示订阅计划页面
- **首次用户支持**：正确处理首次用户订阅流程，使用 `qSubscriptionType` 参数创建订阅令牌
- **管理账单按钮**：所有账户左下角都显示"管理账单"按钮，不管是否有订阅

### 用户体验优化
- **链接自动复制**：选择订阅计划后，支付链接自动复制到剪贴板
- **复制成功提示**：显示绿色提示"链接已复制到剪贴板！"，800ms 后自动关闭弹窗并打开链接
- **错误提示**：订阅相关操作失败时，在弹窗中显示红色错误提示信息

## 🌐 API 反代服务改进

### Claude Code 兼容性
- **新增端点**：`/anthropic/v1/messages` - Claude Code 兼容
- **新增端点**：`/v1/messages/count_tokens` - Token 计数
- **新增端点**：`/api/event_logging/batch` - 遥测支持

### 配置与稳定性
- **配置持久化**：端口和 host 更改时自动保存配置
- **CORS 头增强**：添加 Claude Code 需要的更多请求头支持

### API 兼容性
- **工具描述长度限制**：自动截断超过 10240 bytes 的工具描述
- **内容非空检查**：确保发送给 Kiro API 的消息内容非空

## 🔧 技术修复

### API 调用优化
- **修复 Header**：统一使用正确的 `x-amzn-codewhisperer-optout-preference: OPTIN` 请求头
- **修复订阅类型参数**：`CreateSubscriptionToken` API 使用 `qSubscriptionType`

## 📝 代码变更

### AccountCard.tsx
- 新增 `subscriptionError` 和 `subscriptionSuccess` 状态
- 重构订阅相关函数

### ProxyPanel.tsx
- 端口、host 更改时自动保存配置
- 更新 API 端点说明列表

### proxyServer.ts
- 添加新路由支持和 `handleCountTokens` 方法
- 增强 CORS 头配置

### translator.ts
- 添加工具描述长度限制和内容非空检查

### kiroApi.ts
- 修复请求头格式
