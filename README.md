# Kiro Account Manager

<p align="center">
  <img src="Kiro-account-manager/resources/icon.png" width="128" height="128" alt="Kiro Logo">
</p>

<p align="center">
  <strong>QQ Group: 653516618</strong>
</p>

<p align="center">
  <img src="Kiro-account-manager/src/renderer/src/assets/交流群.png" width="200" alt="QQ Group">
</p>

<p align="center">
  <strong>A powerful multi-account management tool for Kiro IDE</strong>
</p>

<p align="center">
  Quick account switching, auto token refresh, group/tag management, machine ID management and more
</p>

<p align="center">
  <strong>English</strong> | <a href="README_CN.md">简体中文</a>
</p>

---

## ✨ Features

### 🔐 Multi-Account Management
- Add, edit, and delete multiple Kiro accounts
- One-click quick account switching
- Support Builder ID, IAM Identity Center (SSO) and Social (Google/GitHub) login methods
- Batch import/export account data

### 🔄 Auto Refresh
- Auto refresh tokens before expiration
- Auto update account usage and subscription info after refresh
- Periodically check all account balances when auto-switch is enabled

### 📁 Groups & Tags
- Flexibly organize accounts with groups and tags
- Batch set groups/tags for multiple accounts
- One account can only belong to one group, but can have multiple tags

### 🔑 Machine ID Management
- Modify device identifier to prevent account association bans
- Auto switch machine ID when switching accounts
- Assign unique bound machine ID to each account
- Backup and restore original machine ID

### 🔄 Auto Account Switch
- Auto switch to available account when balance is low
- Configurable balance threshold and check interval

### 🎨 Personalization
- 21 theme colors available (grouped by color family)
- Dark/Light mode toggle
- Privacy mode to hide sensitive information

### 🌐 Proxy Support
- Support HTTP/HTTPS/SOCKS5 proxy
- All network requests through proxy server

### 🔄 Auto Update Detection
- Auto detect latest version from GitHub
- Show update content and download file list
- One-click to download page

---

## 📸 Screenshots

### Home
Shows account statistics, current account details, subscription info and quota breakdown.

![Home](Kiro-account-manager/resources/主页.png)

### Account Management
Manage all accounts, search, filter, batch operations, one-click switch.

![Account Management](Kiro-account-manager/resources/账户管理.png)

### Machine ID Management
Manage device identifier, prevent account association bans, backup and restore.

![Machine ID Management](Kiro-account-manager/resources/机器码管理.png)

### Settings
Configure theme colors, privacy mode, auto refresh, proxy and more.

![Settings](Kiro-account-manager/resources/设置.png)

### API Proxy Service
Provides OpenAI and Claude compatible API endpoints with multi-account rotation, auto token refresh, request retry and more.

![API Proxy Service](Kiro-account-manager/resources/API%20反代服务.png)

### Kiro IDE Settings
Sync Kiro IDE settings, edit MCP servers, manage user rules (Steering).

![Kiro Settings](Kiro-account-manager/resources/Kiro%20设置.png)

### About
View version info, feature list, tech stack and author info.

![About](Kiro-account-manager/resources/关于.png)

---

## 📥 Installation

### Windows
Simply run the `.exe` installer.

### macOS
Since the app is not code-signed by Apple, macOS will show "damaged and can't be opened" on first launch. Please follow these steps:

**Method 1: Terminal Command (Recommended)**
```bash
xattr -cr /Applications/Kiro\ Account\ Manager.app
```

**Method 2: Right-click Open**
1. Find the app in Finder
2. Hold `Control` and click the app (or right-click)
3. Select "Open"
4. Click "Open" in the dialog

### Linux
- **AppImage**: Add execute permission and run directly
  ```bash
  chmod +x kiro-account-manager-*.AppImage
  ./kiro-account-manager-*.AppImage
  ```
- **deb**: Install with `dpkg -i`
- **snap**: Install with `snap install`

---

## 📖 Usage Guide

### Add Account

1. Click "Account Management" to enter account list page
2. Click "+ Add Account" button in the top right
3. Enter SSO Token or OIDC credentials
4. Click confirm to complete

### Switch Account

1. Find the target account in Account Management page
2. Click the power icon on the account card to switch
3. Kiro IDE will use the new account after switching

### Batch Set Groups/Tags

1. Select multiple accounts in Account Management page
2. Click "Group" or "Tag" button
3. Select groups/tags to add or remove in the dropdown menu

### Machine ID Management

1. Click "Machine ID" on the left sidebar
2. Original machine ID will be auto backed up on first use
3. Click "Generate Random & Apply" to change machine ID
4. Click "Restore Original" to restore if needed

> ⚠️ **Note**: Modifying machine ID requires admin privileges, please run the app as administrator

### Import/Export

- **Export**: Settings → Data Management → Export, supports JSON, TXT, CSV, Clipboard formats
- **Import**: Settings → Data Management → Import, restore account data from JSON file

---

## 🛠️ Tech Stack

- **Framework**: Electron + React + TypeScript
- **State Management**: Zustand
- **Styling**: Tailwind CSS
- **Build Tool**: Vite
- **Icons**: Lucide React

---

## 💻 Development Guide

### Requirements

- Node.js >= 18
- npm >= 9

### Install Dependencies

```bash
npm install
```

### Development Mode

```bash
npm run dev
```

### Build Application

```bash
# Windows
npm run build:win

# macOS
npm run build:mac

# Linux
npm run build:linux
```

### Build Multi-Architecture

```bash
# Windows 64-bit
npx electron-builder --win --x64

# Windows 32-bit
npx electron-builder --win --ia32

# Windows ARM64
npx electron-builder --win --arm64

# macOS Intel
npx electron-builder --mac --x64

# macOS Apple Silicon
npx electron-builder --mac --arm64

# Linux 64-bit
npx electron-builder --linux --x64

# Linux ARM64
npx electron-builder --linux --arm64
```

---

## 🚀 Auto Build (GitHub Actions)

The project is configured with GitHub Actions workflow for auto building all platforms and architectures:

### Supported Platforms

| Platform | Architecture | Format |
|----------|--------------|--------|
| Windows | x64, ia32, arm64 | exe, zip |
| macOS | x64, arm64 | dmg, zip |
| Linux | x64, arm64, armv7l | AppImage, deb, snap |

### Trigger Methods

1. **Push Tag**: Auto build and release when pushing `v*` format tags
   ```bash
   git tag v1.1.0
   git push origin v1.1.0
   ```

2. **Manual Trigger**: Manually run workflow in GitHub Actions page

---

## 📋 Changelog

### v1.4.9 (2025-02-02)
- 🗺️ **AWS Region Expansion**: OIDC and online login AWS Regions expanded from 3 to 21, grouped by US/Europe/Asia Pacific/Other
- 🗺️ **AWS Region Custom Input**: Added custom input field for manual entry of unlisted regions (e.g., cn-north-1)
- 🔀 **Model Mapping Feature**: New model mapping management with replace, alias, and load balance modes
- 🎯 **Model Mapping Rules**: Support wildcard * matching, weight configuration, and per-API-Key rule settings
- � **Official Model List**: Model mapping auto-fetches Kiro official models for easy target selection
- 📝 **Model Mapping UI**: Added source/target model field descriptions for clarity
- �💻 **Win11 Machine ID Optimization**: Triple fallback for machine ID retrieval (reg query → PowerShell → WMIC)
- 🔐 **Admin Privilege Detection**: Enhanced detection (PowerShell WindowsPrincipal → net session)
- 🌙 **Dark Mode Fix**: Fixed machine ID page display area background color in dark mode

### v1.4.8 (2025-01-29)
- 📊 **Request Logs Model Column**: Added model column to request logs table and recent requests preview
- 🧠 **Thinking Tag Conversion**: Detect &lt;thinking&gt; tags in regular responses and convert based on config
- 📜 **Detailed Logs Sorting**: Fixed detailed logs sorting, newest logs now appear first
- 📈 **API Key Usage Details**: New usage details dialog with history, model stats, and daily charts
- 🗂️ **API Key Manager Optimization**: Dialog width increased from 600px to 800px for better display
- 🧠 **Thinking Output Format**: Added dropdown to select reasoning_content / &lt;thinking&gt; / &lt;think&gt; formats

### v1.4.7 (2025-01-29)
- 📊 **Request Logs Token Detail**: Added Input/Output tokens columns to request logs table
- 📊 **Recent Requests Enhancement**: Recent requests preview also shows Input/Output tokens
- 📐 **Logs Dialog Width**: Increased request logs dialog width from 700px to 900px
- 🎯 **Toolbar Layout Optimization**: Account management toolbar buttons right-aligned with reduced spacing
- 💰 **Trial/Bonus Quota Display**: Fixed REST API freeTrialInfo and bonuses display with unified timestamp format
- 🔧 **Machine ID Page Fix**: Fixed copy/refresh buttons not responding to clicks
- ✅ **Copy Feedback**: Machine ID page copy button now shows "Copied!" feedback
- 🔄 **Refresh Animation**: Machine ID refresh button now shows spinning animation

### v1.4.6 (2025-01-28)
- 🔑 **Multi API Key Management**: Support creating multiple API Keys with selectable formats (sk-xxx / PROXY_KEY / KEY:TOKEN)
- 💰 **Credits Limit**: Set independent Credits usage limit for each API Key
- 📊 **API Key Usage Stats**: Track requests, Credits, and Tokens usage for each API Key
- 🚫 **Auto-Reject on Quota Exceeded**: Returns 429 error when Credits limit exceeded
- 🧠 **Model Thinking Mode**: Configure Extended Thinking mode default setting for each model
- ⏰ **Precise Timestamps**: API Key creation time and last used time shown with seconds
- 🔧 **K-Proxy Integration**: Added K-Proxy service support for device fingerprint management and request proxying
- 🆔 **Device ID Management**: Support account-bound device IDs with import/export for device ID mappings
- 🔄 **API Type Switch**: Support both REST API (GetUsageLimits) and CBOR API (GetUsage) modes
- 🌐 **Proxy Request Support**: Kiro API requests can be sent through K-Proxy using undici library
- 📊 **Usage Query Enhancement**: Unified usage query interface with automatic API type adaptation
- ⌨️ **Global Shortcut**: Added show window shortcut with customizable key binding and key recording
- 🍎 **macOS Shutdown Fix**: Fixed app blocking shutdown, added 3s timeout for force quit
- 🍎 **macOS Dock Optimization**: Click Dock icon to show main window directly (like WeChat)

### v1.4.5 (2025-01-21)
- 🐛 **Enterprise Account Dedup Fix**: Fixed enterprise accounts (no email) being incorrectly flagged as duplicates, now uses userId for checking
- 🎨 **Subscription Badge Color**: Detail page subscription badge color now matches card (PRO+ purple, POWER gold, PRO blue)
- 🔧 **Enterprise Identity Fix**: Fixed Enterprise account provider changing to Internal after refresh
- ⚡ **Log Performance**: Use useMemo to cache filtered logs, optimize search logic, fix lag with large log volumes
- 📐 **Detail Page Layout**: Fixed long account name/nickname causing layout wrap, auto-truncate long text
- 📋 **Quick Copy Email**: Click account card email to copy to clipboard with "Copied!" feedback
- 🔍 **Filter Enhancement**: Added Enterprise to IDP filter, added banned account filter
- 🎨 **Filter Colors**: Subscription filter buttons now have colored styling (FREE gray, PRO blue, PRO+ purple, POWER gold)
- 🐛 **Subscription Parse Fix**: Fixed PRO+/POWER subscription types not being correctly identified

### v1.4.4 (2025-01-21)
- 📊 **Session Statistics**: Added request statistics for current service session, resets on service restart
- 🎯 **Tray Menu Enhanced**: Tray menu shows total/session stats, subscription type, used/total credits, and supports language switching
- 🔄 **Auto-Switch on Quota Exhausted**: In single-account mode, auto-switch to next available account when 402 quota error detected
- 📐 **Proxy Panel Layout**: Stats cards changed to compact 6-column single-row layout
- 🔄 **Status Indicator**: Running status badge now has animated ping effect
- 🎨 **Page Width Unified**: API proxy page width now matches other pages
- 🌐 **UI Translation**: Added English translation for close confirm dialog and detailed logs interface
- 📄 **Log Pagination**: Detailed logs support pagination with page jump feature to prevent lag
- 🔍 **Request Details**: Log entries can be expanded to view request details (model, content length, tools count, history length, etc.)
- ⏰ **Full Timestamp Format**: Log timestamps now show full format YYYY-MM-DD HH:mm:ss.ms
- 📋 **Log Filtering**: Added time range filter (1h/6h/12h/1d/3d/7d/30d/180d/1y) and display limit (5000-1M entries)
- 💾 **Settings Persistence**: Time range, display limit, and page size settings auto-saved
- 📦 **Log Storage Expansion**: Backend log storage limit increased from 10K to 1M entries
- 🐛 **Progress Bar Fix**: Fixed account selection dialog progress bar not showing full when quota exhausted

### v1.4.3 (2025-01-20)
- 📋 **Detailed Logs Viewer**: New detailed logs page for proxy server, similar to console output, supports real-time event viewing
- 💾 **Log Persistence**: All proxy logs are persistently saved to `proxy-logs.json` until manually cleared
- 🎨 **Logs UI Enhancement**: Beautiful logs interface with search, filter by level/category, auto-scroll, export and clear functions
- 🎯 **Theme Adaptive**: Logs interface and dropdown colors follow user selected theme
- 🔧 **Custom Dropdown**: Replaced native select with styled custom dropdown component with icons and selected state
- 🧠 **Execution-Oriented Directive**: Auto-inject execution-oriented directive into system prompt to prevent AI goal drifting
- 📊 **Extended Token Info**: Added Cache Tokens (read/write) and Reasoning Tokens statistics
- 📈 **Complete Usage Response**: OpenAI/Claude streaming responses now return complete usage information
- 🔗 **API Endpoints Layout**: API endpoints list now uses 3-column layout (method/path/description), POST in orange, GET in green
- 🔄 **Unified Log Routing**: Logs from kiroApi and proxyServer are now routed through proxyLogger to UI
- 🐛 **Log Storage Fix**: Fixed request logs and detailed logs using same file path causing data loss
- 🐛 **Invalid Date Fix**: Fixed "Invalid Date.NaN" issue when loading old logs

### v1.4.2 (2025-01-20)
- 🔄 **Native History Support**: Refactored based on Kiro official implementation, using native history field instead of text embedding
- 🧹 **Message Sanitization**: Implemented sanitizeConversation to ensure message alternation, tool call matching, etc.
- 🔧 **API Compatibility Fix**: Fixed 400 errors caused by incorrect message format

### v1.4.1 (2025-01-19)
- 💰 **Credits Display**: Replaced Tokens with Credits usage display
- 📊 **Total Credits Stats**: Added cumulative Credits statistics with persistence
- 🔄 **Reset Credits**: Added button to reset total Credits count
- 🔍 **Error Details Popup**: Click error badge in request logs to view error details
- 🔁 **Auto Continue Rounds**: Auto-send "Continue" after tool calls to prevent stream interruption
- 🚫 **Disable Tool Calls**: New toggle to remove tools parameter, AI responds directly without tools

### v1.4.0 (2025-01-19)
- 🔧 **API 400 Error Fix**: Fixed Kiro API not supporting toolResults and history fields, now embedded as text
- 🔄 **Multi-Account Toggle Fix**: Fixed issue where accounts still switched when multi-account polling was disabled
- 👤 **Specify Account Feature**: Can now specify which account to use when multi-account polling is disabled
- 🎯 **Account Select Dialog**: New account selection dialog showing email, subscription type, usage progress bar, and status
- 🔍 **Account Search**: Account selection dialog supports searching by email, ID, or subscription type
- 🚫 **Banned Status Display**: Account selection dialog correctly shows banned/error/expired status
- 💾 **Proxy Config Persistence Fix**: Fixed port, host, API Key, preferred endpoint, max retries not persisting after restart
- 🎨 **Subscription Color Consistency**: Account selection dialog subscription colors now match account cards

### v1.3.9 (2025-01-19)
- 🔐 **Enterprise Login Fix**: Fixed IAM Identity Center SSO login using Authorization Code Grant with PKCE flow
- 🔧 **Enterprise Switch Fix**: Fixed account switching for Enterprise accounts by using correct startUrl to calculate clientIdHash
- 🚪 **Logout Button**: Active account now shows logout button instead of switch button, clears SSO cache on click
- 🌙 **Dark Mode Button Fix**: Login method buttons now properly support dark mode with theme-aware background colors
- 👤 **Account Display Optimization**: Accounts without email now display nickname or userId as fallback
- 🏷️ **Enterprise Label Update**: Changed "组织身份" to "Enterprise" in login UI for consistency

### v1.3.8 (2025-01-18)
- 🏢 **IAM Identity Center SSO Login**: Added organization identity login support via IAM Identity Center SSO
- 🔗 **SSO Start URL Input**: Users can input their organization's SSO Start URL for authentication
- 🌍 **AWS Region Selection**: Support 20+ AWS regions for SSO login (US, Europe, Asia Pacific, etc.)
- 🏷️ **Enterprise Provider Support**: OIDC credential import now supports `Enterprise` provider type
- 📦 **Batch Import Enhancement**: Batch import JSON example now includes Enterprise provider
- 🔄 **One-Click Switch Compatibility**: Account switching fully supports Enterprise/IAM_SSO provider types
- 📊 **Statistics Enhancement**: Account statistics now track Enterprise and IAM_SSO identity types
- 📌 **Tray Icon Enhancement**: Tray menu icons now use external PNG files, support custom replacement
- 🔄 **Tray Status Sync**: Tray status updates in real-time when starting/stopping proxy from UI
- 📝 **Close Confirm Dialog**: Custom close confirmation dialog with "Remember my choice" option

### v1.3.7 (2025-01-17)
- 📊 **Account Available Models**: Added available models list in account detail page
- ⚡ **Model Rate Multiplier**: Model list now displays rate multiplier (e.g., 1.3x credit)
- 🚫 **Ban Details Dialog**: Click "Banned" label to view detailed ban info and support link
- ✅ **Button Click Feedback**: Added success feedback for API Key copy and generate buttons
- 🎨 **Models List UI**: Improved dual-column grid layout for proxy models dialog
- 🎯 **Subscription Flow Refactor**: Clicking subscription label now fetches available subscriptions first, then displays plan selection page
- 👤 **First-time User Support**: Properly handle first-time user subscription flow using `qSubscriptionType` parameter
- 💳 **Manage Billing Button**: All accounts now show "Manage Billing" button regardless of subscription status
- 📋 **Auto Copy Link**: Payment link is automatically copied to clipboard when selecting a subscription plan
- ✅ **Copy Success Toast**: Shows green "Link copied to clipboard!" message, auto-closes dialog after 800ms
- ❌ **Error Messages**: Shows red error message in dialog when subscription operations fail
- 🔧 **API Fix**: Fixed to use correct `x-amzn-codewhisperer-optout-preference` request header
- 🌐 **API Proxy Claude Code Support**: Added `/anthropic/v1/messages`, `/v1/messages/count_tokens`, `/api/event_logging/batch` endpoints
- 💾 **Proxy Config Persistence**: Port and host changes are now automatically saved
- 🔒 **Enhanced CORS Headers**: Added more request headers support for Claude Code compatibility
- 📏 **Tool Description Length Limit**: Auto-truncate tool descriptions exceeding 10240 bytes
- 📝 **Content Non-empty Check**: Ensure message content sent to Kiro API is non-empty

### v1.3.6 (2025-01-17)
- 🔑 **API Key Persistence**: API Key is now persisted and preserved after app restart
- 👁️ **API Key Show/Hide**: Added toggle to show/hide API Key in input field
- 🚀 **Auto Start Fix**: Fixed "Auto Start" feature not working properly
- 📋 **API Key Copy**: One-click copy button for API Key

### v1.3.5 (2025-01-17)
- 🌐 **API Proxy Page i18n**: API Proxy Service page now supports English/Chinese language switching
- 📋 **Request Logs Display**: Added recent request logs display panel in API Proxy Service page
- 💾 **Log Persistence**: Request logs are now persisted to file and preserved after restart
- 📊 **Logs Dialog**: View all logs in a popup dialog with export and clear functions
- 🔄 **Dynamic Model Fetching**: Fetch models from Kiro API and merge with preset models
- 🔄 **Refresh Models**: Added button to manually refresh model cache
- 🚀 **Auto Start**: API Proxy Service can now auto-start when application launches
- 🔄 **Auto Restart**: Auto restart proxy service when it crashes unexpectedly (if auto-start enabled)
- 🌐 **Public Access Switch**: Quick toggle to switch between local (127.0.0.1) and public (0.0.0.0) access
- 📊 **Token Usage Fix**: Fixed token count not displaying in request logs
- 🔐 **Copy Access Token**: Can now copy Access Token when editing account or copying credentials

### v1.3.4 (2025-01-16)
- 🐛 **Multi-Account Active State Fix**: Fixed the issue where multiple accounts showed "Active" status simultaneously on some devices
- ✨ **Glow Border Effect**: Added animated glow border effect for the currently active account card
- 💬 **QQ Group**: Added QQ group information to README
- 🚀 **API Proxy Service Enhancement**:
  - Auto token refresh before expiry
  - Request retry mechanism (smart handling for 401/403/429/5xx)
  - IDC authentication support + preferred endpoint config
  - Agentic mode detection + Thinking mode support
  - System prompt injection + image processing
  - Enhanced usage statistics + management API endpoints
- 🎨 **API Proxy Page UI Update**: Consistent styling with other pages, follows theme color
- 📖 **Usage Guide**: Added API proxy service usage guide documentation
- 🐛 **Active Account Stats Fix**: Fixed "Active Accounts" count mismatch on homepage

### v1.3.3 (2025-01-15)
- 🍎 **macOS Machine ID Fix**: Fixed the issue where modified machine ID still showed the original ID after refresh
- 🍎 **macOS Permission Fix**: macOS no longer incorrectly prompts "Admin privileges required"
- 🔗 **Kiro IDE Sync**: macOS now automatically syncs machine ID to Kiro IDE's machineid file
- 🔒 **Login Private Mode**: Option to open browser in incognito/private mode when logging in online
- ⚙️ **Global Setting**: Added "Login Private Mode" toggle in settings page
- 🔄 **Temporary Toggle**: Login dialog supports temporary private mode toggle (defaults to global setting)
- 🌐 **Auto Browser Detection**: Automatically detects system default browser and uses corresponding private mode arguments
- 💻 **Multi-Browser Support**: Supports private mode for Chrome, Edge, Firefox, Brave, Opera

### v1.3.2 (2025-01-02)
- 🔄 **Auto Refresh Timer Fix**: Fixed the issue where auto refresh timer did not check account info when token is not expired
- 🔄 **Background Refresh Update Fix**: Fixed the issue where background refresh results were not updating account panel data
- 📊 **Batch Check Fix**: Fixed the issue where batch account check was not updating usage progress bar and subscription expiry time
- 🎯 **Percentage Precision**: Usage percentage display is now also controlled by "Usage Precision" setting

### v1.3.1 (2025-01-01)
- 🔧 **Check Account Button Fix**: Fixed the issue where clicking "Check Account Info" button had no visual feedback
- 🔄 **Auto Refresh Sync Fix**: Fixed the issue where "Sync Account Info" setting was not working during auto refresh
- 📊 **Usage Precision Setting**: Added option to toggle between integer and decimal display for usage values
- 🔢 **Precise Usage Data**: Backend now saves precise decimal usage data (e.g., 1.22 instead of 1)
- ⚙️ **GitHub Actions Optimization**: Removed tag trigger, now only supports manual trigger; release is no longer draft by default
- 🐛 **Import Fix**: Fixed the issue where accounts with same email but different providers (GitHub/Google) could not be imported

### v1.3.0 (2025-12-30)
- 🌐 **Multi-Language Support**: Full English/Chinese bilingual interface
- 🌐 **Language Settings**: Auto-detect system language or manual selection
- 🐧 **Linux Fix**: Fixed launch failure when installation path contains spaces
- 🐧 **Linux Fix**: Fixed machine ID privilege escalation failure on Wayland
- 🍎 **macOS Fix**: Fixed DMG signing issue
- 🔧 **Edit Account Optimization**: Social login accounts (Google/GitHub) now only show Refresh Token when editing
- ⚙️ **Auto Refresh Settings**: Added "Sync Account Info" toggle to control whether to detect usage and ban status during refresh

### v1.2.9 (2025-12-17)
- 🔍 **Batch Check Fix**: Batch check now works same as single check, correctly detecting ban status
- 📤 **Export Enhancement**: TXT and Clipboard export with "Include Credentials" can be directly used for import
- 🏢 **Teams Subscription**: Added Teams subscription type recognition
- 🎨 **Machine ID Page**: Redesigned page with new statistics cards and optimized layout
- 🎯 **Theme Color Unity**: Machine ID page colors follow user selected theme

### v1.2.5 (2025-12-09)
- 🎨 **Theme System Upgrade**: Theme colors increased from 13 to 21, grouped by color family
- 📊 **Quota Statistics**: Added total quota statistics card on home page
- 💾 **Multi-Format Export**: Support JSON, TXT, CSV, Clipboard formats
- 🔧 **Machine ID Optimization**: Added search function and last modified time display
- 🐛 **Fix**: Fixed some theme color switching issues

### v1.1.0
- Added machine ID management
- Added batch set groups/tags
- Optimized auto refresh, sync update account info
- Added 13 theme colors
- UI optimization and bug fixes

### v1.0.0
- Initial release
- Multi-account management and switching
- Auto token refresh
- Groups and tags management
- Privacy mode and proxy settings

---

## 📄 License

This project is licensed under the [AGPL-3.0 License](LICENSE).

---

## 👨‍💻 Author

- **GitHub**: [chaogei](https://github.com/chaogei)
- **Project Homepage**: [Kiro-account-manager](https://github.com/chaogei/Kiro-account-manager)

---

## 🙏 Acknowledgments

Thanks to all users who use and support this project!

If this project helps you, please give it a Star ⭐!
