# Kiro Account Manager

<p align="center">
  <img src="Kiro-account-manager/resources/icon.png" width="128" height="128" alt="Kiro Logo">
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
- Support Builder ID and Social (Google/GitHub) login methods
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
