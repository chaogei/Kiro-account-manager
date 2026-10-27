/** Share the usage polling deadline between renderer requests and the main timer. */
export function isUsageSyncDue(
  settings: {
    autoRefreshEnabled?: boolean
    autoRefreshSyncInfo?: boolean
    autoRefreshInterval?: number
  },
  lastSyncAt: number,
  now: number
): boolean {
  if (settings.autoRefreshEnabled === false || settings.autoRefreshSyncInfo === false) return false
  const interval = Math.max(1, settings.autoRefreshInterval || 5) * 60_000
  return now - lastSyncAt >= interval
}

export function selectionChanged(saved?: string[], live?: string[]): boolean {
  return JSON.stringify(saved || []) !== JSON.stringify(live || [])
}
