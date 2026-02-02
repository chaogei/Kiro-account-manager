import { useState, useEffect } from 'react'
import { X, Plus, Trash2, GripVertical, Shuffle, ArrowRight, Tag, Settings2, Loader2, ChevronDown, ChevronUp } from 'lucide-react'
import { Button, Card, CardContent, CardHeader, CardTitle, Badge, Input, Label, Switch } from '../ui'
import { cn } from '@/lib/utils'

interface ModelMappingRule {
  id: string
  name: string
  enabled: boolean
  type: 'replace' | 'alias' | 'loadbalance'
  sourceModel: string
  targetModels: string[]
  weights?: number[]
  priority: number
  apiKeyIds?: string[]
}

interface ApiKey {
  id: string
  name: string
}

interface ModelInfo {
  id: string
  name: string
}

interface ModelMappingDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  isEn: boolean
  mappings: ModelMappingRule[]
  onMappingsChange: (mappings: ModelMappingRule[]) => void
  apiKeys: ApiKey[]
  availableModels: ModelInfo[]
}

export function ModelMappingDialog({
  open,
  onOpenChange,
  isEn,
  mappings,
  onMappingsChange,
  apiKeys,
  availableModels
}: ModelMappingDialogProps) {
  const [localMappings, setLocalMappings] = useState<ModelMappingRule[]>(mappings)
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (open) {
      setLocalMappings(mappings)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open])

  const generateId = () => `mapping_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`

  const addRule = () => {
    const newRule: ModelMappingRule = {
      id: generateId(),
      name: isEn ? 'New Rule' : '新规则',
      enabled: true,
      type: 'replace',
      sourceModel: '',
      targetModels: [''],
      priority: localMappings.length,
      apiKeyIds: []
    }
    setLocalMappings([...localMappings, newRule])
    setExpandedId(newRule.id)
  }

  const updateRule = (id: string, updates: Partial<ModelMappingRule>) => {
    setLocalMappings(localMappings.map(rule => 
      rule.id === id ? { ...rule, ...updates } : rule
    ))
  }

  const deleteRule = (id: string) => {
    setLocalMappings(localMappings.filter(rule => rule.id !== id))
    if (expandedId === id) setExpandedId(null)
  }

  const moveRule = (id: string, direction: 'up' | 'down') => {
    const index = localMappings.findIndex(r => r.id === id)
    if ((direction === 'up' && index === 0) || (direction === 'down' && index === localMappings.length - 1)) return
    
    const newMappings = [...localMappings]
    const newIndex = direction === 'up' ? index - 1 : index + 1
    ;[newMappings[index], newMappings[newIndex]] = [newMappings[newIndex], newMappings[index]]
    newMappings.forEach((r, i) => r.priority = i)
    setLocalMappings(newMappings)
  }

  const addTargetModel = (ruleId: string) => {
    const rule = localMappings.find(r => r.id === ruleId)
    if (rule) {
      updateRule(ruleId, { 
        targetModels: [...rule.targetModels, ''],
        weights: rule.weights ? [...rule.weights, 1] : undefined
      })
    }
  }

  const updateTargetModel = (ruleId: string, index: number, value: string) => {
    const rule = localMappings.find(r => r.id === ruleId)
    if (rule) {
      const newTargets = [...rule.targetModels]
      newTargets[index] = value
      updateRule(ruleId, { targetModels: newTargets })
    }
  }

  const removeTargetModel = (ruleId: string, index: number) => {
    const rule = localMappings.find(r => r.id === ruleId)
    if (rule && rule.targetModels.length > 1) {
      const newTargets = rule.targetModels.filter((_, i) => i !== index)
      const newWeights = rule.weights ? rule.weights.filter((_, i) => i !== index) : undefined
      updateRule(ruleId, { targetModels: newTargets, weights: newWeights })
    }
  }

  const updateWeight = (ruleId: string, index: number, value: number) => {
    const rule = localMappings.find(r => r.id === ruleId)
    if (rule) {
      const newWeights = rule.weights ? [...rule.weights] : rule.targetModels.map(() => 1)
      newWeights[index] = value
      updateRule(ruleId, { weights: newWeights })
    }
  }

  const toggleApiKey = (ruleId: string, keyId: string) => {
    const rule = localMappings.find(r => r.id === ruleId)
    if (rule) {
      const currentKeys = rule.apiKeyIds || []
      const newKeys = currentKeys.includes(keyId)
        ? currentKeys.filter(k => k !== keyId)
        : [...currentKeys, keyId]
      updateRule(ruleId, { apiKeyIds: newKeys })
    }
  }

  const handleSave = async () => {
    setLoading(true)
    try {
      onMappingsChange(localMappings)
      onOpenChange(false)
    } finally {
      setLoading(false)
    }
  }

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'replace': return <ArrowRight className="h-4 w-4" />
      case 'alias': return <Tag className="h-4 w-4" />
      case 'loadbalance': return <Shuffle className="h-4 w-4" />
      default: return <Settings2 className="h-4 w-4" />
    }
  }

  const getTypeLabel = (type: string) => {
    switch (type) {
      case 'replace': return isEn ? 'Replace' : '替换'
      case 'alias': return isEn ? 'Alias' : '别名'
      case 'loadbalance': return isEn ? 'Load Balance' : '负载均衡'
      default: return type
    }
  }

  const getTypeColor = (type: string) => {
    switch (type) {
      case 'replace': return 'bg-blue-500/10 text-blue-600 dark:text-blue-400'
      case 'alias': return 'bg-purple-500/10 text-purple-600 dark:text-purple-400'
      case 'loadbalance': return 'bg-green-500/10 text-green-600 dark:text-green-400'
      default: return 'bg-muted'
    }
  }

  if (!open) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={() => onOpenChange(false)} />
      <Card className="relative w-[900px] max-h-[85vh] shadow-2xl border overflow-hidden animate-in fade-in zoom-in-95 duration-200 bg-gradient-to-br from-background to-muted/20">
        <CardHeader className="pb-4 border-b sticky top-0 bg-background/95 backdrop-blur z-10">
          <div className="flex items-center justify-between">
            <CardTitle className="text-xl flex items-center gap-3">
              <div className="p-2 rounded-xl bg-primary/10">
                <Shuffle className="h-6 w-6 text-primary" />
              </div>
              <div>
                <span className="font-bold">{isEn ? 'Model Mapping' : '模型映射'}</span>
                <div className="flex items-center gap-2 mt-1">
                  <Badge className="bg-primary/10 text-primary border-primary/20 font-semibold">
                    {localMappings.length} {isEn ? 'rules' : '条规则'}
                  </Badge>
                </div>
              </div>
            </CardTitle>
            <div className="flex items-center gap-2">
              <Button 
                variant="outline" 
                size="sm" 
                onClick={addRule}
                className="rounded-lg"
              >
                <Plus className="h-4 w-4 mr-1" />
                {isEn ? 'Add Rule' : '添加规则'}
              </Button>
              <Button variant="ghost" size="icon" className="h-9 w-9 rounded-lg hover:bg-destructive/10 hover:text-destructive" onClick={() => onOpenChange(false)}>
                <X className="h-5 w-5" />
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent className="p-4">
          <div className="max-h-[calc(85vh-180px)] overflow-y-auto pr-2 space-y-3">
            {localMappings.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
                <div className="p-4 rounded-full bg-muted mb-4">
                  <Shuffle className="h-8 w-8" />
                </div>
                <p className="font-medium">{isEn ? 'No mapping rules' : '暂无映射规则'}</p>
                <p className="text-sm mt-1">{isEn ? 'Click "Add Rule" to create one' : '点击"添加规则"创建新规则'}</p>
              </div>
            ) : (
              localMappings.map((rule, index) => (
                <div 
                  key={rule.id}
                  className={cn(
                    "border rounded-xl overflow-hidden transition-all",
                    rule.enabled ? "bg-background" : "bg-muted/30 opacity-60",
                    expandedId === rule.id ? "ring-2 ring-primary/30" : ""
                  )}
                >
                  {/* 规则头部 */}
                  <div 
                    className="flex items-center gap-3 p-3 cursor-pointer hover:bg-muted/30"
                    onClick={() => setExpandedId(expandedId === rule.id ? null : rule.id)}
                  >
                    <GripVertical className="h-4 w-4 text-muted-foreground" />
                    <div onClick={(e) => e.stopPropagation()}>
                      <Switch 
                        checked={rule.enabled}
                        onCheckedChange={(checked) => {
                          updateRule(rule.id, { enabled: checked })
                        }}
                      />
                    </div>
                    <Badge className={cn("px-2 py-0.5", getTypeColor(rule.type))}>
                      {getTypeIcon(rule.type)}
                      <span className="ml-1">{getTypeLabel(rule.type)}</span>
                    </Badge>
                    <div className="flex-1 min-w-0">
                      <span className="font-medium truncate">{rule.name}</span>
                      <span className="text-muted-foreground mx-2">:</span>
                      <code className="text-sm bg-muted px-1.5 py-0.5 rounded">{rule.sourceModel || '...'}</code>
                      <ArrowRight className="inline h-4 w-4 mx-2 text-muted-foreground" />
                      <code className="text-sm bg-muted px-1.5 py-0.5 rounded">
                        {rule.targetModels.filter(t => t).join(', ') || '...'}
                      </code>
                    </div>
                    <div className="flex items-center gap-1">
                      <Button 
                        variant="ghost" 
                        size="icon" 
                        className="h-7 w-7"
                        onClick={(e) => { e.stopPropagation(); moveRule(rule.id, 'up') }}
                        disabled={index === 0}
                      >
                        <ChevronUp className="h-4 w-4" />
                      </Button>
                      <Button 
                        variant="ghost" 
                        size="icon" 
                        className="h-7 w-7"
                        onClick={(e) => { e.stopPropagation(); moveRule(rule.id, 'down') }}
                        disabled={index === localMappings.length - 1}
                      >
                        <ChevronDown className="h-4 w-4" />
                      </Button>
                      <Button 
                        variant="ghost" 
                        size="icon" 
                        className="h-7 w-7 hover:bg-destructive/10 hover:text-destructive"
                        onClick={(e) => { e.stopPropagation(); deleteRule(rule.id) }}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>

                  {/* 展开的编辑区域 */}
                  {expandedId === rule.id && (
                    <div className="border-t p-4 space-y-4 bg-muted/10">
                      <div className="grid grid-cols-2 gap-4">
                        <div className="space-y-2">
                          <Label>{isEn ? 'Rule Name' : '规则名称'}</Label>
                          <Input 
                            value={rule.name}
                            onChange={(e) => updateRule(rule.id, { name: e.target.value })}
                            placeholder={isEn ? 'Enter rule name' : '输入规则名称'}
                          />
                        </div>
                        <div className="space-y-2">
                          <Label>{isEn ? 'Mapping Type' : '映射类型'}</Label>
                          <select
                            className="w-full h-10 px-3 py-2 text-sm rounded-xl border border-input bg-background ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2"
                            value={rule.type}
                            onChange={(e) => updateRule(rule.id, { type: e.target.value as ModelMappingRule['type'] })}
                          >
                            <option value="replace">{isEn ? 'Replace - Direct model replacement' : '替换 - 直接替换模型'}</option>
                            <option value="alias">{isEn ? 'Alias - Create model alias' : '别名 - 创建模型别名'}</option>
                            <option value="loadbalance">{isEn ? 'Load Balance - Random selection' : '负载均衡 - 随机选择'}</option>
                          </select>
                        </div>
                      </div>

                      <div className="space-y-2">
                        <div>
                          <Label>{isEn ? 'Source Model' : '源模型'}</Label>
                          <p className="text-xs text-muted-foreground mt-0.5">
                            {isEn ? 'The model name in user request (e.g., gpt-4, claude-*, my-alias). Supports * wildcard.' : '用户请求时使用的模型名（如 gpt-4, claude-*, my-alias）。支持 * 通配符。'}
                          </p>
                        </div>
                        <div className="flex gap-2">
                          <Input 
                            value={rule.sourceModel}
                            onChange={(e) => updateRule(rule.id, { sourceModel: e.target.value })}
                            placeholder={isEn ? 'e.g., claude-*, gpt-4, my-alias' : '例如: claude-*, gpt-4, my-alias'}
                            className="flex-1"
                          />
                          {availableModels.length > 0 && (
                            <select
                              className="h-10 px-3 text-sm rounded-xl border border-input bg-background"
                              value=""
                              onChange={(e) => {
                                if (e.target.value) updateRule(rule.id, { sourceModel: e.target.value })
                              }}
                            >
                              <option value="">{isEn ? 'Select model' : '选择模型'}</option>
                              {availableModels.map(m => (
                                <option key={m.id} value={m.id}>{m.id}</option>
                              ))}
                            </select>
                          )}
                        </div>
                      </div>

                      <div className="space-y-2">
                        <div className="flex items-center justify-between">
                          <div>
                            <Label>{isEn ? 'Target Models' : '目标模型'}</Label>
                            <p className="text-xs text-muted-foreground mt-0.5">
                              {isEn ? 'The actual Kiro model to call. Select from the dropdown for official models.' : '实际调用的 Kiro 模型。从下拉框选择官方模型。'}
                            </p>
                          </div>
                          <Button 
                            variant="outline" 
                            size="sm" 
                            onClick={() => addTargetModel(rule.id)}
                            className="h-7 text-xs"
                          >
                            <Plus className="h-3 w-3 mr-1" />
                            {isEn ? 'Add' : '添加'}
                          </Button>
                        </div>
                        <div className="space-y-2">
                          {rule.targetModels.map((target, targetIndex) => (
                            <div key={targetIndex} className="flex items-center gap-2">
                              <Input 
                                value={target}
                                onChange={(e) => updateTargetModel(rule.id, targetIndex, e.target.value)}
                                placeholder={isEn ? 'Target model name' : '目标模型名'}
                                className="flex-1"
                              />
                              {availableModels.length > 0 && (
                                <select
                                  className="h-10 px-3 text-sm rounded-xl border border-input bg-background"
                                  value=""
                                  onChange={(e) => {
                                    if (e.target.value) updateTargetModel(rule.id, targetIndex, e.target.value)
                                  }}
                                >
                                  <option value="">{isEn ? 'Select' : '选择'}</option>
                                  {availableModels.map(m => (
                                    <option key={m.id} value={m.id}>{m.id}</option>
                                  ))}
                                </select>
                              )}
                              {rule.type === 'loadbalance' && (
                                <div className="flex items-center gap-1">
                                  <Label className="text-xs whitespace-nowrap">{isEn ? 'Weight' : '权重'}</Label>
                                  <Input 
                                    type="number"
                                    min={1}
                                    value={rule.weights?.[targetIndex] ?? 1}
                                    onChange={(e) => updateWeight(rule.id, targetIndex, parseInt(e.target.value) || 1)}
                                    className="w-16"
                                  />
                                </div>
                              )}
                              {rule.targetModels.length > 1 && (
                                <Button 
                                  variant="ghost" 
                                  size="icon" 
                                  className="h-8 w-8 hover:bg-destructive/10 hover:text-destructive"
                                  onClick={() => removeTargetModel(rule.id, targetIndex)}
                                >
                                  <Trash2 className="h-4 w-4" />
                                </Button>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>

                      {apiKeys.length > 0 && (
                        <div className="space-y-2">
                          <Label>{isEn ? 'Apply to API Keys (empty = all keys)' : '适用 API Key（空 = 所有 Key）'}</Label>
                          <div className="flex flex-wrap gap-2">
                            {apiKeys.map(key => (
                              <Badge 
                                key={key.id}
                                variant={rule.apiKeyIds?.includes(key.id) ? "default" : "outline"}
                                className="cursor-pointer hover:bg-primary/20"
                                onClick={() => toggleApiKey(rule.id, key.id)}
                              >
                                {key.name}
                              </Badge>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>

          {/* 底部操作栏 */}
          <div className="flex justify-end gap-2 pt-4 border-t mt-4">
            <Button variant="outline" onClick={() => onOpenChange(false)}>
              {isEn ? 'Cancel' : '取消'}
            </Button>
            <Button onClick={handleSave} disabled={loading}>
              {loading && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              {isEn ? 'Save' : '保存'}
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
