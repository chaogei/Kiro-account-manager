import { ipcMain } from 'electron'
import {
  checkSkillUpdate,
  defaultSkillsManagerConfig,
  deleteSkills,
  installSkills,
  listSkillsState,
  normalizeSkillsManagerConfig,
  saveSkillsConfigPatch,
  setSkillAutoUpdate,
  syncSkills,
  updateSkills,
  type SkillsManagerConfig
} from './service'

interface StoreLike {
  get: (key: string, defaultValue?: unknown) => unknown
  set: (key: string, value: unknown) => void
}

const STORE_KEY = 'skillsManagerConfig'

export function registerSkillsManagerIpcHandlers(getStore: () => StoreLike | null): void {
  const readConfig = (): SkillsManagerConfig => {
    const store = getStore()
    return normalizeSkillsManagerConfig(store?.get(STORE_KEY, defaultSkillsManagerConfig()))
  }

  const saveConfig = (config: SkillsManagerConfig): void => {
    const store = getStore()
    if (!store) return
    store.set(STORE_KEY, normalizeSkillsManagerConfig(config))
  }

  ipcMain.handle('skills:list', async () => {
    return listSkillsState(readConfig())
  })

  ipcMain.handle('skills:get-config', async () => {
    return readConfig()
  })

  ipcMain.handle('skills:save-config', async (_event, patch: Partial<SkillsManagerConfig>) => {
    try {
      const config = await saveSkillsConfigPatch(patch, readConfig(), saveConfig)
      return { success: true, config }
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : String(error) }
    }
  })

  ipcMain.handle('skills:set-auto-update', async (_event, input: { agent: string; skillName: string; enabled: boolean }) => {
    try {
      return await setSkillAutoUpdate(input, readConfig(), saveConfig)
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : String(error) }
    }
  })

  ipcMain.handle('skills:install', async (_event, input) => {
    try {
      return await installSkills(input, readConfig(), saveConfig)
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : String(error) }
    }
  })

  ipcMain.handle('skills:check-update', async (_event, input: { agent: string; skillName: string }) => {
    try {
      return await checkSkillUpdate(input, readConfig())
    } catch (error) {
      return { success: false, status: 'failed', reason: error instanceof Error ? error.message : String(error) }
    }
  })

  ipcMain.handle('skills:update', async (_event, input: { agent: string; skillNames: string[] }) => {
    try {
      return await updateSkills(input, readConfig())
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : String(error) }
    }
  })

  ipcMain.handle('skills:delete', async (_event, input: { agent: string; skillNames: string[]; allAgents?: boolean }) => {
    try {
      return await deleteSkills(input, readConfig(), saveConfig)
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : String(error) }
    }
  })

  ipcMain.handle('skills:sync', async (_event, input: { sourceAgent: string; skillNames: string[]; targetAgents: string[]; overwrite?: boolean }) => {
    try {
      return await syncSkills(input, readConfig(), saveConfig)
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : String(error) }
    }
  })
}
