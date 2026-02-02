import { useState, useEffect } from 'react'
import { X, RefreshCw, Loader2, Cpu, FileText, Image, Hash, Sparkles, Zap, Shuffle } from 'lucide-react'
import { Button, Card, CardContent, CardHeader, CardTitle, Badge } from '../ui'
import { cn } from '@/lib/utils'

interface ModelInfo {
  id: string
  name: string
  description: string
  inputTypes?: string[]
  maxInputTokens?: number | null
  maxOutputTokens?: number | null
  rateMultiplier?: number
  rateUnit?: string
}

interface ModelsDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  isEn: boolean
  onOpenModelMapping?: () => void
  mappingCount?: number
}

export function ModelsDialog({
  open,
  onOpenChange,
  isEn,
  onOpenModelMapping,
  mappingCount = 0
}: ModelsDialogProps) {
  const [models, setModels] = useState<ModelInfo[]>([])
  const [loading, setLoading] = useState(false)
  const [fromCache, setFromCache] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const fetchModels = async () => {
    setLoading(true)
    setError(null)
    try {
      const result = await window.api.proxyGetModels()
      if (result.success) {
        setModels(result.models)
        setFromCache(result.fromCache || false)
      } else {
        setError(result.error || 'Failed to fetch models')
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (open) {
      fetchModels()
    }
  }, [open])

  if (!open) return null

  const formatTokens = (tokens: number | null | undefined) => {
    if (tokens === null || tokens === undefined) return '-'
    if (tokens >= 1000000) return `${(tokens / 1000000).toFixed(1)}M`
    if (tokens >= 1000) return `${(tokens / 1000).toFixed(0)}K`
    return tokens.toString()
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={() => onOpenChange(false)} />
      <Card className="relative w-[850px] max-h-[85vh] shadow-2xl border overflow-hidden animate-in fade-in zoom-in-95 duration-200 bg-gradient-to-br from-background to-muted/20">
        <CardHeader className="pb-4 border-b sticky top-0 bg-background/95 backdrop-blur z-10">
          <div className="flex items-center justify-between">
            <CardTitle className="text-xl flex items-center gap-3">
              <div className="p-2 rounded-xl bg-primary/10">
                <Cpu className="h-6 w-6 text-primary" />
              </div>
              <div>
                <span className="font-bold">{isEn ? 'Available Models' : '可用模型'}</span>
                <div className="flex items-center gap-2 mt-1">
                  <Badge className="bg-primary/10 text-primary border-primary/20 font-semibold">
                    {models.length} {isEn ? 'models' : '个模型'}
                  </Badge>
                  {fromCache && (
                    <Badge variant="secondary" className="text-xs bg-amber-500/10 text-amber-600 dark:text-amber-400 border-0">
                      <Sparkles className="h-3 w-3 mr-1" />
                      {isEn ? 'Cached' : '缓存'}
                    </Badge>
                  )}
                </div>
              </div>
            </CardTitle>
            <div className="flex items-center gap-2">
              {onOpenModelMapping && (
                <Button 
                  variant="outline" 
                  size="sm" 
                  onClick={onOpenModelMapping}
                  className="rounded-lg"
                >
                  <Shuffle className="h-4 w-4" />
                  <span className="ml-1.5">{isEn ? 'Mapping' : '映射'}</span>
                  {mappingCount > 0 && (
                    <Badge className="ml-1.5 h-5 px-1.5 bg-primary/20 text-primary text-xs">
                      {mappingCount}
                    </Badge>
                  )}
                </Button>
              )}
              <Button 
                variant="outline" 
                size="sm" 
                onClick={fetchModels}
                disabled={loading}
                className="rounded-lg"
              >
                {loading ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <RefreshCw className="h-4 w-4" />
                )}
                <span className="ml-1.5">{isEn ? 'Refresh' : '刷新'}</span>
              </Button>
              <Button variant="ghost" size="icon" className="h-9 w-9 rounded-lg hover:bg-destructive/10 hover:text-destructive" onClick={() => onOpenChange(false)}>
                <X className="h-5 w-5" />
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent className="p-4">
          <div className="max-h-[calc(85vh-140px)] overflow-y-auto pr-2">
            {loading && models.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
                <div className="p-4 rounded-full bg-primary/10 mb-4">
                  <Loader2 className="h-8 w-8 animate-spin text-primary" />
                </div>
                <p className="font-medium">{isEn ? 'Loading models...' : '加载模型中...'}</p>
              </div>
            ) : error ? (
              <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
                <div className="p-4 rounded-full bg-red-500/10 mb-4">
                  <X className="h-8 w-8 text-red-500" />
                </div>
                <p className="text-red-500 font-medium">{error}</p>
                <p className="text-sm mt-2">{isEn ? 'Make sure proxy is running and has synced accounts' : '请确保代理服务已启动且已同步账号'}</p>
              </div>
            ) : models.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
                <div className="p-4 rounded-full bg-muted mb-4">
                  <Cpu className="h-8 w-8" />
                </div>
                <p className="font-medium">{isEn ? 'No models available' : '暂无可用模型'}</p>
              </div>
            ) : (
              <div className="grid grid-cols-2 gap-3">
                {models.map((model, index) => (
                  <div 
                    key={model.id} 
                    className={cn(
                      "group p-3 rounded-xl border hover:shadow-md hover:border-primary/30 transition-all duration-200",
                      index === 0 ? "border-primary/40 bg-primary/10" : "bg-background"
                    )}
                  >
                    <div className="flex items-start gap-2 mb-2">
                      <div className={cn(
                        "w-2 h-2 rounded-full mt-1.5 shrink-0",
                        index === 0 ? "bg-primary" : "bg-muted-foreground/30"
                      )} />
                      <div className="flex-1 min-w-0">
                        <code className="text-sm font-bold text-foreground">{model.id}</code>
                        {model.name && model.name !== model.id && (
                          <p className="text-[11px] text-primary/70 font-medium truncate">{model.name}</p>
                        )}
                      </div>
                    </div>
                    <p className="text-[11px] text-muted-foreground line-clamp-2 mb-2 pl-4">
                      {model.description || (isEn ? 'No description' : '无描述')}
                    </p>
                    <div className="flex items-center justify-between pt-2 border-t border-border/50">
                      <div className="flex items-center gap-2">
                        <div className="flex items-center gap-1">
                          {model.inputTypes?.includes('TEXT') && (
                            <Badge variant="secondary" className="text-[10px] px-1.5 h-5 bg-blue-500/10 text-blue-600 dark:text-blue-400 border-0">
                              <FileText className="h-3 w-3" />
                            </Badge>
                          )}
                          {model.inputTypes?.includes('IMAGE') && (
                            <Badge variant="secondary" className="text-[10px] px-1.5 h-5 bg-purple-500/10 text-purple-600 dark:text-purple-400 border-0">
                              <Image className="h-3 w-3" />
                            </Badge>
                          )}
                        </div>
                        {model.rateMultiplier !== undefined && (
                          <Badge variant="secondary" className="text-[10px] px-1.5 h-5 bg-amber-500/10 text-amber-600 dark:text-amber-400 border-0">
                            <Zap className="h-3 w-3 mr-0.5" />
                            {model.rateMultiplier}x {model.rateUnit || 'credit'}
                          </Badge>
                        )}
                      </div>
                      <div className="flex items-center gap-1 text-[11px] font-mono text-muted-foreground">
                        <Hash className="h-3 w-3" />
                        <span className="text-green-600 dark:text-green-400">{formatTokens(model.maxInputTokens)}</span>
                        <span>/</span>
                        <span className="text-orange-600 dark:text-orange-400">{formatTokens(model.maxOutputTokens)}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
