import { CheckCircle2, AlertTriangle, Folder, GitBranch, Github, Gitlab } from 'lucide-react'
import { getSourceProvider } from './source'
import type { SkillUpdateStatus, SkillsSkillView } from './types'

export function SourceIcon({ skill }: { skill: SkillsSkillView }): React.ReactNode {
  const sourceProvider = getSourceProvider(skill)
  if (sourceProvider === 'github') return <Github className="h-3.5 w-3.5 text-muted-foreground" />
  if (sourceProvider === 'gitlab') return <Gitlab className="h-3.5 w-3.5 text-orange-500" />
  if (sourceProvider === 'git') return <GitBranch className="h-3.5 w-3.5 text-muted-foreground" />
  return <Folder className="h-3.5 w-3.5 text-muted-foreground" />
}

export function StatusIcon({ status }: { status: SkillUpdateStatus }): React.ReactNode {
  return status === 'latest' ? (
    <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" />
  ) : (
    <AlertTriangle className="h-3.5 w-3.5 text-amber-500" />
  )
}
