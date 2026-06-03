import type { SkillsSkillView } from './types'

export function getSourceProvider(skill: SkillsSkillView): 'github' | 'gitlab' | 'git' | 'local' {
  const sourceType = skill.sourceType?.trim()
  if (!sourceType) return 'local'

  const normalizedSourceType = sourceType.toLowerCase()
  const sourceText = `${skill.source || ''} ${skill.sourceUrl || ''}`.toLowerCase()
  if (normalizedSourceType.includes('gitlab') || sourceText.includes('gitlab')) return 'gitlab'
  if (normalizedSourceType.includes('github') || sourceText.includes('github')) return 'github'
  if (normalizedSourceType === 'git') return 'git'
  return 'local'
}
