import { spawn } from 'child_process'
import { home } from './agents'
import type { SkillsOperationResult } from './types'

export function runNpxSkills(args: string[]): Promise<SkillsOperationResult> {
  return new Promise((resolveResult) => {
    const child = spawn(process.platform === 'win32' ? 'npx.cmd' : 'npx', ['skills', ...args], {
      cwd: home,
      env: { ...process.env, DISABLE_TELEMETRY: '1' }
    })
    let output = ''
    child.stdout.on('data', (data) => {
      output += String(data)
    })
    child.stderr.on('data', (data) => {
      output += String(data)
    })
    child.on('error', (error) => resolveResult({ success: false, error: error.message }))
    child.on('close', (code) => {
      resolveResult({
        success: code === 0,
        message: output.trim(),
        error: code === 0 ? undefined : output.trim() || `npx skills exited with ${code}`
      })
    })
  })
}
