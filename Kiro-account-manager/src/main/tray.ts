// 系统托盘模块
import { Tray, Menu, nativeImage, app, BrowserWindow, dialog, MenuItemConstructorOptions, NativeImage } from 'electron'
import { join } from 'path'

// 托盘实例
let tray: Tray | null = null

// 菜单图标缓存
const menuIcons: Map<string, NativeImage> = new Map()

// 获取托盘图标目录路径
function getTrayIconDir(): string {
  // 开发环境和生产环境路径不同
  if (app.isPackaged) {
    // asarUnpack 会将 resources 解包到 app.asar.unpacked 目录
    return join(process.resourcesPath, 'app.asar.unpacked', 'resources', '托盘图标')
  }
  return join(__dirname, '../../resources/托盘图标')
}

// 图标名称到文件名的映射
const ICON_FILE_MAP: Record<string, string> = {
  // 应用图标
  'app': 'icon.png',
  // 状态图标
  'status-running': '运行状态.png',
  'status-stopped': '停止状态.png',
  // 菜单图标
  'mail': '当前账户.png',
  'refresh': '刷新.png',
  'switchAccount': '切换.png',
  'copy': '复制.png',
  'window': '弹出窗口.png',
  'logout': '退出.png',
  'play': '播放.png',
  'stop': '停止状态.png',
  'check': '已勾选.png',
  'warning': '警告.png',
  'usage': '用量.png',
  'requests': '请求.png'
}

// 从文件加载图标
function loadIconFromFile(iconKey: string): NativeImage {
  const cached = menuIcons.get(iconKey)
  if (cached) return cached
  
  const fileName = ICON_FILE_MAP[iconKey]
  if (!fileName) {
    console.warn(`[Tray] Unknown icon key: ${iconKey}`)
    return nativeImage.createEmpty()
  }
  
  const iconPath = join(getTrayIconDir(), fileName)
  try {
    const icon = nativeImage.createFromPath(iconPath)
    // 调整大小为 16x16 以适合菜单
    const resized = icon.resize({ width: 16, height: 16 })
    menuIcons.set(iconKey, resized)
    return resized
  } catch (error) {
    console.error(`[Tray] Failed to load icon: ${iconPath}`, error)
    return nativeImage.createEmpty()
  }
}

// 获取状态图标
function getStatusIcon(running: boolean): NativeImage {
  return loadIconFromFile(running ? 'status-running' : 'status-stopped')
}

// 获取菜单图标
function getMenuIcon(name: string): NativeImage {
  return loadIconFromFile(name)
}

// 当前账户信息（用于托盘菜单显示）
interface TrayAccountInfo {
  id: string
  email: string
  idp: string
  status: string
  subscription?: string
  usage?: {
    usedCredits: number
    totalCredits: number
    totalRequests: number
    successRequests: number
    failedRequests: number
  }
}

let currentAccount: TrayAccountInfo | null = null
let accountList: TrayAccountInfo[] = []
let currentLanguage: 'en' | 'zh' = 'zh'

// 回调函数
interface TrayCallbacks {
  onShowWindow: () => void
  onQuit: () => void
  onRefreshAccount: () => Promise<void>
  onSwitchAccount: () => Promise<void>
  onToggleProxy: () => Promise<void>
  getProxyStatus: () => { running: boolean; port: number }
  getCurrentAccount: () => TrayAccountInfo | null
  getAccountList: () => TrayAccountInfo[]
  getProxyStats: () => { totalRequests: number; successRequests: number; failedRequests: number }
  getSessionStats: () => { totalRequests: number; successRequests: number; failedRequests: number; startTime: number }
}

let callbacks: TrayCallbacks | null = null

// 获取托盘图标路径
function getTrayIconPath(): string {
  // 根据平台选择合适的图标
  if (process.platform === 'win32') {
    // Windows 使用 ico 文件
    if (app.isPackaged) {
      return join(process.resourcesPath, 'app.asar.unpacked', 'resources', 'icon.ico')
    }
    return join(__dirname, '../../resources/icon.ico')
  } else if (process.platform === 'darwin') {
    // macOS 使用 Template 图标（自动适应深色/浅色模式）
    if (app.isPackaged) {
      return join(process.resourcesPath, 'app.asar.unpacked', 'resources', 'icon.png')
    }
    return join(__dirname, '../../resources/icon.png')
  } else {
    // Linux 使用 png 文件
    if (app.isPackaged) {
      return join(process.resourcesPath, 'app.asar.unpacked', 'resources', 'icon.png')
    }
    return join(__dirname, '../../resources/icon.png')
  }
}

// 构建托盘菜单
function buildTrayMenu(): Menu {
  const menuTemplate: MenuItemConstructorOptions[] = []

  const isEn = currentLanguage === 'en'
  
  // 应用标题
  menuTemplate.push({
    label: `Kiro ${isEn ? 'Account Manager' : '账号管理器'} v${app.getVersion()}`,
    icon: getMenuIcon('app'),
    enabled: false
  })
  menuTemplate.push({ type: 'separator' })

  // 代理服务状态
  if (callbacks) {
    const proxyStatus = callbacks.getProxyStatus()
    menuTemplate.push({
      label: proxyStatus.running 
        ? (isEn ? `Proxy Running (Port ${proxyStatus.port})` : `代理服务运行中 (端口 ${proxyStatus.port})`) 
        : (isEn ? 'Proxy Stopped' : '代理服务已停止'),
      icon: getStatusIcon(proxyStatus.running),
      enabled: false
    })
    menuTemplate.push({
      label: proxyStatus.running ? (isEn ? 'Stop Proxy' : '停止代理服务') : (isEn ? 'Start Proxy' : '启动代理服务'),
      icon: getMenuIcon(proxyStatus.running ? 'stop' : 'play'),
      click: async () => {
        await callbacks?.onToggleProxy()
        updateTrayMenu()
      }
    })
    menuTemplate.push({ type: 'separator' })
  }

  // 当前账户信息
  const account = callbacks?.getCurrentAccount() || currentAccount
  if (account) {
    menuTemplate.push({
      label: isEn ? 'Current Account' : '当前账户',
      icon: getMenuIcon('mail'),
      enabled: false
    })
    menuTemplate.push({
      label: `   ${account.email}`,
      enabled: false
    })
    menuTemplate.push({
      label: isEn 
        ? `   Identity: ${account.idp} | ${account.subscription || 'Unknown'} | ${account.status === 'active' ? 'Active' : account.status}`
        : `   身份: ${account.idp} | ${account.subscription || '未知'} | ${account.status === 'active' ? '活跃' : account.status}`,
      icon: getMenuIcon(account.status === 'active' ? 'check' : 'warning'),
      enabled: false
    })
    
    if (account.usage) {
      menuTemplate.push({
        label: isEn 
          ? `   Usage: ${account.usage.usedCredits} / ${account.usage.totalCredits} Credits`
          : `   用量: ${account.usage.usedCredits} / ${account.usage.totalCredits} Credits`,
        icon: getMenuIcon('usage'),
        enabled: false
      })
    }
    // 从主进程获取实时统计数据（总计和会话）
    const proxyStats = callbacks?.getProxyStats() || { totalRequests: 0, successRequests: 0, failedRequests: 0 }
    const sessionStats = callbacks?.getSessionStats() || { totalRequests: 0, successRequests: 0, failedRequests: 0, startTime: 0 }
    menuTemplate.push({
      label: isEn 
        ? `   Total: ${proxyStats.totalRequests} (✓${proxyStats.successRequests} ✗${proxyStats.failedRequests})`
        : `   总计: ${proxyStats.totalRequests} (成功${proxyStats.successRequests} 失败${proxyStats.failedRequests})`,
      icon: getMenuIcon('requests'),
      enabled: false
    })
    menuTemplate.push({
      label: isEn 
        ? `   Session: ${sessionStats.totalRequests} (✓${sessionStats.successRequests} ✗${sessionStats.failedRequests})`
        : `   本次: ${sessionStats.totalRequests} (成功${sessionStats.successRequests} 失败${sessionStats.failedRequests})`,
      icon: getMenuIcon('requests'),
      enabled: false
    })
    menuTemplate.push({ type: 'separator' })
  } else {
    menuTemplate.push({
      label: isEn ? 'No Active Account' : '暂无活跃账户',
      icon: getMenuIcon('mail'),
      enabled: false
    })
    menuTemplate.push({ type: 'separator' })
  }

  // 账户操作
  menuTemplate.push({
    label: isEn ? 'Refresh Account Info' : '刷新账户信息',
    icon: getMenuIcon('refresh'),
    click: async () => {
      await callbacks?.onRefreshAccount()
      updateTrayMenu()
    }
  })

  const accounts = callbacks?.getAccountList() || accountList
  const activeAccounts = accounts.filter(a => a.status === 'active')
  menuTemplate.push({
    label: isEn ? `Switch to Next Account (${activeAccounts.length} available)` : `切换到下一个账户 (${activeAccounts.length} 个可用)`,
    icon: getMenuIcon('switchAccount'),
    enabled: activeAccounts.length > 1,
    click: async () => {
      await callbacks?.onSwitchAccount()
      updateTrayMenu()
    }
  })

  menuTemplate.push({ type: 'separator' })

  // 快捷操作
  menuTemplate.push({
    label: isEn ? 'Copy Proxy Address' : '复制代理地址',
    icon: getMenuIcon('copy'),
    click: () => {
      const { clipboard } = require('electron')
      const proxyStatus = callbacks?.getProxyStatus()
      if (proxyStatus?.running) {
        clipboard.writeText(`http://127.0.0.1:${proxyStatus.port}`)
      }
    },
    enabled: callbacks?.getProxyStatus()?.running ?? false
  })

  menuTemplate.push({ type: 'separator' })

  // 显示主窗口
  menuTemplate.push({
    label: isEn ? 'Show Main Window' : '显示主窗口',
    icon: getMenuIcon('window'),
    click: () => {
      callbacks?.onShowWindow()
    }
  })

  // 退出应用
  menuTemplate.push({
    label: isEn ? 'Exit' : '退出程序',
    icon: getMenuIcon('logout'),
    click: () => {
      callbacks?.onQuit()
    }
  })

  return Menu.buildFromTemplate(menuTemplate)
}

// 更新托盘菜单
export function updateTrayMenu(): void {
  if (tray) {
    tray.setContextMenu(buildTrayMenu())
  }
}

// 更新当前账户信息
export function updateCurrentAccount(account: TrayAccountInfo | null): void {
  currentAccount = account
  updateTrayMenu()
}

// 更新账户列表
export function updateAccountList(accounts: TrayAccountInfo[]): void {
  accountList = accounts
  updateTrayMenu()
}

// 更新语言设置
export function updateTrayLanguage(language: 'en' | 'zh'): void {
  currentLanguage = language
  updateTrayMenu()
}

// 设置托盘提示
export function setTrayTooltip(tooltip: string): void {
  if (tray) {
    tray.setToolTip(tooltip)
  }
}

// 创建托盘
export function createTray(cbs: TrayCallbacks): Tray | null {
  if (tray) {
    return tray
  }

  callbacks = cbs

  try {
    const iconPath = getTrayIconPath()
    let icon = nativeImage.createFromPath(iconPath)
    
    // macOS 需要设置为 Template 图标
    if (process.platform === 'darwin') {
      icon = icon.resize({ width: 16, height: 16 })
      icon.setTemplateImage(true)
    } else if (process.platform === 'win32') {
      // Windows 图标大小调整
      icon = icon.resize({ width: 16, height: 16 })
    }

    tray = new Tray(icon)
    tray.setToolTip(currentLanguage === 'en' ? 'Kiro Account Manager' : 'Kiro 账号管理器')
    tray.setContextMenu(buildTrayMenu())

    // 双击托盘图标显示主窗口
    tray.on('double-click', () => {
      callbacks?.onShowWindow()
    })

    // Windows 和 Linux: 单击右键显示菜单，单击左键显示窗口
    if (process.platform !== 'darwin') {
      tray.on('click', () => {
        callbacks?.onShowWindow()
      })
    }

    console.log('[Tray] System tray created successfully')
    return tray
  } catch (error) {
    console.error('[Tray] Failed to create system tray:', error)
    return null
  }
}

// 销毁托盘
export function destroyTray(): void {
  if (tray) {
    tray.destroy()
    tray = null
    callbacks = null
    console.log('[Tray] System tray destroyed')
  }
}

// 获取托盘实例
export function getTray(): Tray | null {
  return tray
}

// 显示关闭确认对话框
export async function showCloseConfirmDialog(mainWindow: BrowserWindow): Promise<'minimize' | 'quit' | 'cancel'> {
  const isEn = currentLanguage === 'en'
  const result = await dialog.showMessageBox(mainWindow, {
    type: 'question',
    buttons: [
      isEn ? 'Minimize to Tray' : '最小化到托盘',
      isEn ? 'Quit' : '退出程序',
      isEn ? 'Cancel' : '取消'
    ],
    defaultId: 0,
    cancelId: 2,
    title: isEn ? 'Close Window' : '关闭窗口',
    message: isEn
      ? 'Would you like to minimize to the system tray or quit the application?'
      : '您想要最小化到系统托盘还是退出程序？',
    detail: isEn
      ? 'When minimized to tray, the app will continue running in the background. Click the tray icon to reopen the window.'
      : '最小化到托盘后，程序将在后台继续运行，您可以通过点击托盘图标重新打开窗口。',
    checkboxLabel: isEn ? 'Remember my choice' : '记住我的选择',
    checkboxChecked: false
  })

  const actions: ('minimize' | 'quit' | 'cancel')[] = ['minimize', 'quit', 'cancel']
  return actions[result.response]
}

// 托盘设置类型
export interface TraySettings {
  enabled: boolean
  closeAction: 'ask' | 'minimize' | 'quit'
  showNotifications: boolean
  minimizeOnStart: boolean
}

// 默认托盘设置
export const defaultTraySettings: TraySettings = {
  enabled: true,
  closeAction: 'ask',
  showNotifications: true,
  minimizeOnStart: false
}
