import { ipcMain, BrowserWindow } from 'electron'
import { Registrar, newConfig, type RegistrationConfig } from './index'
import type { RegStepEvent } from './registrar'
import { openProtonLogin, getProtonLoginStatus, closeProtonWindow } from './proton-mail-window'

// 注册池：支持多个并发注册任务
const registrarPool = new Map<string, Registrar>()
// 手动模式使用固定 key
const MANUAL_KEY = '__manual__'

export function registerIPCHandlers(getMainWindow: () => BrowserWindow | null): void {
  const sendLog = (msg: string, taskId?: string): void => {
    const win = getMainWindow()
    if (win && !win.isDestroyed()) {
      win.webContents.send('registration-log', { message: msg, taskId })
    }
  }
  const sendStep = (event: RegStepEvent, taskId?: string): void => {
    const win = getMainWindow()
    if (win && !win.isDestroyed()) {
      win.webContents.send('registration-step', { taskId, event })
    }
  }

  // 启动自动注册（支持并发：每个 taskId 独立运行）
  ipcMain.handle('registration-start-auto', async (_event, config: Partial<RegistrationConfig> & { taskId?: string }) => {
    const taskId = config.taskId || `auto-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`
    const logPrefix = config.taskId ? `[#${config.taskId.slice(0, 12)}] ` : ''

    const cfg = newConfig(config)
    cfg.manualMode = false
    const registrar = new Registrar(
      cfg,
      (msg) => sendLog(`${logPrefix}${msg}`, config.taskId),
      (event) => sendStep(event, config.taskId)
    )
    registrarPool.set(taskId, registrar)

    try {
      const result = await registrar.run()
      // run() 内部 finally 已调用 cleanup()，无需再次 destroy
      registrarPool.delete(taskId)
      // 仅单次注册（无 taskId）发送 complete 事件
      if (!config.taskId) {
        const win = getMainWindow()
        if (win && !win.isDestroyed()) {
          win.webContents.send('registration-complete', result)
        }
      }
      return { success: true, result }
    } catch (err) {
      // run() 内部 finally 已调用 cleanup()，无需再次 destroy
      registrarPool.delete(taskId)
      const errMsg = err instanceof Error ? err.message : String(err)
      return { success: false, error: errMsg }
    }
  })

  // 手动模式 Phase1: OIDC + Device
  ipcMain.handle('registration-manual-phase1', async (_event, config: Partial<RegistrationConfig>) => {
    if (registrarPool.has(MANUAL_KEY)) {
      return { success: false, error: '已有手动注册流程正在进行' }
    }

    const cfg = newConfig(config)
    cfg.manualMode = true
    const registrar = new Registrar(cfg, sendLog, (event) => sendStep(event))
    registrarPool.set(MANUAL_KEY, registrar)

    const result = await registrar.runManualPhase1()
    if (!result.success) {
      await registrar.destroy()
      registrarPool.delete(MANUAL_KEY)
    }
    return result
  })

  // 手动模式 Phase2: 设置邮箱 -> 发送 OTP
  ipcMain.handle('registration-manual-phase2', async (_event, email: string, fullName?: string) => {
    const registrar = registrarPool.get(MANUAL_KEY)
    if (!registrar) {
      return { success: false, error: '无进行中的注册流程' }
    }
    const result = await registrar.runManualPhase2(email, fullName)
    if (!result.success) {
      await registrar.destroy()
      registrarPool.delete(MANUAL_KEY)
    }
    return result
  })

  // 手动模式 Phase3: 验证码 -> 完成注册
  // 注意：不发送 registration-complete 事件，前端 submitOTP 通过 invoke 返回值直接处理
  ipcMain.handle('registration-manual-phase3', async (_event, otp: string) => {
    const registrar = registrarPool.get(MANUAL_KEY)
    if (!registrar) {
      return { success: false, error: '无进行中的注册流程' }
    }
    const result = await registrar.runManualPhase3(otp)
    await registrar.destroy()
    registrarPool.delete(MANUAL_KEY)
    return { success: true, result }
  })

  // 取消注册（支持指定 taskId 或取消全部）
  ipcMain.handle('registration-cancel', async (_event, taskId?: string) => {
    if (taskId) {
      const registrar = registrarPool.get(taskId)
      if (registrar) {
        registrar.abort()
        await registrar.destroy()
        registrarPool.delete(taskId)
      }
    } else {
      // 取消全部
      const tasks = Array.from(registrarPool.entries())
      for (const [id, registrar] of tasks) {
        registrar.abort()
        await registrar.destroy()
        registrarPool.delete(id)
      }
    }
    return { success: true }
  })

  // 获取注册状态
  ipcMain.handle('registration-status', async () => {
    return { inProgress: registrarPool.size > 0, count: registrarPool.size }
  })

  // ===== Proton 邮箱取码源 =====

  // 打开 Proton 登录窗口（首次需用户手动登录，之后 session 持久化复用）
  ipcMain.handle('proton-open-login', async (_event, proxy?: string) => {
    return openProtonLogin(proxy)
  })

  // 查询 Proton 登录态（不弹窗）
  ipcMain.handle('proton-login-status', async (_event, proxy?: string, expectedEmail?: string) => {
    return getProtonLoginStatus(proxy, expectedEmail)
  })

  // 关闭 Proton 窗口（保留登录态）
  ipcMain.handle('proton-close', async () => {
    closeProtonWindow()
    return { success: true }
  })
}
