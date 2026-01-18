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
    return join(process.resourcesPath, 'resources', '托盘图标')
  }
  return join(__dirname, '../../resources/托盘图标')
}

// 图标名称到文件名的映射
const ICON_FILE_MAP: Record<string, string> = {
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
  usage?: {
    inputTokens: number
    outputTokens: number
    totalRequests: number
  }
}

let currentAccount: TrayAccountInfo | null = null
let accountList: TrayAccountInfo[] = []

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
}

let callbacks: TrayCallbacks | null = null

// 获取托盘图标路径
function getTrayIconPath(): string {
  // 根据平台选择合适的图标
  if (process.platform === 'win32') {
    // Windows 使用 ico 文件
    return join(__dirname, '../../build/icon.ico')
  } else if (process.platform === 'darwin') {
    // macOS 使用 Template 图标（自动适应深色/浅色模式）
    return join(__dirname, '../../build/icon.png')
  } else {
    // Linux 使用 png 文件
    return join(__dirname, '../../build/icon.png')
  }
}

// 格式化 Token 用量
function formatTokens(tokens: number): string {
  if (tokens >= 1000000) {
    return `${(tokens / 1000000).toFixed(2)}M`
  } else if (tokens >= 1000) {
    return `${(tokens / 1000).toFixed(1)}K`
  }
  return tokens.toString()
}

// 构建托盘菜单
function buildTrayMenu(): Menu {
  const menuTemplate: MenuItemConstructorOptions[] = []

  // 应用标题
  menuTemplate.push({
    label: `Kiro 账号管理器 v${app.getVersion()}`,
    enabled: false
  })
  menuTemplate.push({ type: 'separator' })

  // 代理服务状态
  if (callbacks) {
    const proxyStatus = callbacks.getProxyStatus()
    menuTemplate.push({
      label: proxyStatus.running 
        ? `代理服务运行中 (端口 ${proxyStatus.port})` 
        : '代理服务已停止',
      icon: getStatusIcon(proxyStatus.running),
      enabled: false
    })
    menuTemplate.push({
      label: proxyStatus.running ? '停止代理服务' : '启动代理服务',
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
      label: '当前账户',
      icon: getMenuIcon('mail'),
      enabled: false
    })
    menuTemplate.push({
      label: `   ${account.email}`,
      enabled: false
    })
    menuTemplate.push({
      label: `   身份: ${account.idp} | 状态: ${account.status === 'active' ? '活跃' : account.status}`,
      icon: getMenuIcon(account.status === 'active' ? 'check' : 'warning'),
      enabled: false
    })
    
    if (account.usage) {
      menuTemplate.push({
        label: `   用量: ${formatTokens(account.usage.inputTokens)} 输入 / ${formatTokens(account.usage.outputTokens)} 输出`,
        icon: getMenuIcon('usage'),
        enabled: false
      })
      menuTemplate.push({
        label: `   请求数: ${account.usage.totalRequests}`,
        icon: getMenuIcon('requests'),
        enabled: false
      })
    }
    menuTemplate.push({ type: 'separator' })
  } else {
    menuTemplate.push({
      label: '暂无活跃账户',
      icon: getMenuIcon('mail'),
      enabled: false
    })
    menuTemplate.push({ type: 'separator' })
  }

  // 账户操作
  menuTemplate.push({
    label: '刷新账户信息',
    icon: getMenuIcon('refresh'),
    click: async () => {
      await callbacks?.onRefreshAccount()
      updateTrayMenu()
    }
  })

  const accounts = callbacks?.getAccountList() || accountList
  const activeAccounts = accounts.filter(a => a.status === 'active')
  menuTemplate.push({
    label: `切换到下一个账户 (${activeAccounts.length} 个可用)`,
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
    label: '复制代理地址',
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
    label: '显示主窗口',
    icon: getMenuIcon('window'),
    click: () => {
      callbacks?.onShowWindow()
    }
  })

  // 退出应用
  menuTemplate.push({
    label: '退出程序',
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
    tray.setToolTip('Kiro 账号管理器')
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
  const result = await dialog.showMessageBox(mainWindow, {
    type: 'question',
    buttons: ['最小化到托盘', '退出程序', '取消'],
    defaultId: 0,
    cancelId: 2,
    title: '关闭窗口',
    message: '您想要最小化到系统托盘还是退出程序？',
    detail: '最小化到托盘后，程序将在后台继续运行，您可以通过点击托盘图标重新打开窗口。',
    checkboxLabel: '记住我的选择',
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
