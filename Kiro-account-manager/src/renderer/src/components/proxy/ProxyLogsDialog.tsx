import { useState } from 'react'
import { X, Trash2, Download, AlertCircle, RotateCcw } from 'lucide-react'
import { Button, Card, CardContent, CardHeader, CardTitle, Badge } from '../ui'

interface LogEntry {
  time: string
  path: string
  model?: string
  status: number
  tokens?: number
  inputTokens?: number
  outputTokens?: number
  cacheReadTokens?: number
  reasoningTokens?: number
  credits?: number
  responseTime?: number
  error?: string
}

interface ProxyLogsDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  logs: LogEntry[]
  totalCredits: number // 累计总 credits（所有请求）
  totalTokens: number // 累计总 tokens（所有请求）
  onClearLogs: () => void
  onResetCredits?: () => void
  onResetTokens?: () => void
  isEn: boolean
}

export function ProxyLogsDialog({
  open,
  onOpenChange,
  logs,
  totalCredits,
  totalTokens,
  onClearLogs,
  onResetCredits,
  onResetTokens,
  isEn
}: ProxyLogsDialogProps) {
  const [expandedError, setExpandedError] = useState<number | null>(null)
  
  if (!open) return null

  const handleExport = () => {
    const formatCell = (value: string | number | undefined) => String(value ?? '').replace(/[\t\r\n]+/g, ' ')
    const content = logs.map(log => {
      const credits = log.credits ? `${log.credits.toFixed(6)} credits` : ''
      return [
        log.time,
        log.path,
        log.model,
        log.status,
        credits,
        log.error
      ].map(formatCell).join('\t')
    }).join('\n')
    const blob = new Blob([content], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `proxy-logs-${new Date().toISOString().slice(0, 10)}.txt`
    a.click()
    URL.revokeObjectURL(url)
  }

  const successCount = logs.filter(l => l.status < 400).length
  const errorCount = logs.filter(l => l.status >= 400).length
  const recentCredits = logs.reduce((sum, l) => sum + (l.credits || 0), 0)
  const recentTokens = logs.reduce((sum, l) => sum + (l.tokens || 0), 0)

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/50" onClick={() => onOpenChange(false)} />
      <Card className="relative w-[900px] max-h-[80vh] shadow-2xl border-0 overflow-hidden animate-in fade-in zoom-in-95 duration-200 glass-card-strong">
        <CardHeader className="pb-3 border-b sticky top-0 z-10">
          <div className="flex items-center justify-between">
            <CardTitle className="text-lg">{isEn ? 'Request Logs' : '请求日志'}</CardTitle>
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" onClick={handleExport} disabled={logs.length === 0}>
                <Download className="h-4 w-4 mr-1" />
                {isEn ? 'Export' : '导出'}
              </Button>
              <Button variant="outline" size="sm" onClick={onClearLogs} disabled={logs.length === 0}>
                <Trash2 className="h-4 w-4 mr-1" />
                {isEn ? 'Clear' : '清空'}
              </Button>
              <Button variant="ghost" size="icon" className="h-8 w-8 rounded-lg hover:bg-red-500 hover:text-white transition-colors" onClick={() => onOpenChange(false)}>
                <X className="h-4 w-4" />
              </Button>
            </div>
          </div>
          <div className="flex flex-wrap gap-x-4 gap-y-1 mt-2 text-sm">
            <span>{isEn ? 'Total' : '总计'}: <Badge variant="secondary">{logs.length}</Badge></span>
            <span>{isEn ? 'Success' : '成功'}: <Badge className="bg-success/20 text-success">{successCount}</Badge></span>
            <span>{isEn ? 'Error' : '错误'}: <Badge className="bg-destructive/20 text-destructive">{errorCount}</Badge></span>
            <span className="text-muted-foreground">|</span>
            <span>Tokens {isEn ? 'Recent' : '最近'}: <Badge variant="outline">{recentTokens.toLocaleString()}</Badge></span>
            <span className="flex items-center gap-1">
              Tokens {isEn ? 'Total' : '总计'}: <Badge variant="secondary">{totalTokens.toLocaleString()}</Badge>
              {onResetTokens && (
                <Button variant="ghost" size="icon" className="h-5 w-5" onClick={onResetTokens} title={isEn ? 'Reset total' : '重置总计'}>
                  <RotateCcw className="h-3 w-3" />
                </Button>
              )}
            </span>
            <span className="text-muted-foreground">|</span>
            <span>Credits {isEn ? 'Recent' : '最近'}: <Badge variant="outline">{recentCredits.toFixed(4)}</Badge></span>
            <span className="flex items-center gap-1">
              Credits {isEn ? 'Total' : '总计'}: <Badge variant="secondary">{totalCredits.toFixed(4)}</Badge>
              {onResetCredits && (
                <Button variant="ghost" size="icon" className="h-5 w-5" onClick={onResetCredits} title={isEn ? 'Reset total' : '重置总计'}>
                  <RotateCcw className="h-3 w-3" />
                </Button>
              )}
            </span>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <div className="max-h-[calc(80vh-120px)] overflow-y-auto">
            {logs.length === 0 ? (
              <div className="flex items-center justify-center h-32 text-muted-foreground">
                {isEn ? 'No logs yet' : '暂无日志'}
              </div>
            ) : (
              <table className="w-full text-sm">
                <thead className="bg-muted/50 sticky top-0">
                  <tr>
                    <th className="text-left p-2 font-medium">{isEn ? 'Time' : '时间'}</th>
                    <th className="text-left p-2 font-medium">{isEn ? 'Path' : '路径'}</th>
                    <th className="text-left p-2 font-medium">{isEn ? 'Model' : '模型'}</th>
                    <th className="text-center p-2 font-medium">{isEn ? 'Status' : '状态'}</th>
                    <th className="text-center p-2 font-medium">{isEn ? 'In' : '输入'}</th>
                    <th className="text-center p-2 font-medium">{isEn ? 'Out' : '输出'}</th>
                    <th className="text-center p-2 font-medium">Cache</th>
                    <th className="text-right p-2 font-medium">Credits</th>
                    <th className="text-right p-2 font-medium">{isEn ? 'Time' : '耗时'}</th>
                  </tr>
                </thead>
                <tbody className="font-mono">
                  {logs.map((log, idx) => (
                    <tr key={idx} className="border-b border-muted/30 hover:bg-muted/30">
                      <td className="p-2 text-muted-foreground whitespace-nowrap">{log.time}</td>
                      <td className="p-2 truncate max-w-[200px]" title={log.path}>{log.path}</td>
                      <td className="p-2 truncate max-w-[150px] text-muted-foreground" title={log.model}>{log.model ? log.model.replace('anthropic.', '').replace('-v1:0', '') : '-'}</td>
                      <td className="p-2 text-center relative">
                        {log.status >= 400 && log.error ? (
                          <div className="relative inline-block">
                            <Badge 
                              className="bg-destructive/20 text-destructive cursor-pointer hover:bg-destructive/30 transition-colors"
                              onClick={() => setExpandedError(expandedError === idx ? null : idx)}
                            >
                              <AlertCircle className="h-3 w-3 mr-1" />
                              {log.status}
                            </Badge>
                            {expandedError === idx && (
                              <div className="absolute z-50 top-full left-1/2 -translate-x-1/2 mt-2 w-80 bg-background border border-destructive/30 rounded-lg shadow-xl p-3 text-left">
                                <div className="absolute -top-2 left-1/2 -translate-x-1/2 w-3 h-3 bg-background border-l border-t border-destructive/30 rotate-45"></div>
                                <div className="text-xs font-sans">
                                  <div className="font-medium text-destructive mb-2 flex items-center gap-1">
                                    <AlertCircle className="h-3 w-3" />
                                    {isEn ? 'Error Details' : '错误详情'}
                                  </div>
                                  <pre className="whitespace-pre-wrap break-all bg-destructive/10 p-2 rounded text-destructive text-xs max-h-40 overflow-y-auto">{log.error}</pre>
                                </div>
                              </div>
                            )}
                          </div>
                        ) : (
                          <Badge className={log.status >= 400 ? 'bg-destructive/20 text-destructive' : 'bg-success/20 text-success'}>
                            {log.status}
                          </Badge>
                        )}
                      </td>
                      <td className="p-2 text-center text-muted-foreground">{log.inputTokens ? log.inputTokens.toLocaleString() : '-'}</td>
                      <td className="p-2 text-center text-muted-foreground">{log.outputTokens ? log.outputTokens.toLocaleString() : '-'}</td>
                      <td className="p-2 text-center text-success">{log.cacheReadTokens ? log.cacheReadTokens.toLocaleString() : '-'}</td>
                      <td className="p-2 text-right text-muted-foreground">{log.credits ? log.credits.toFixed(6) : '-'}</td>
                      <td className="p-2 text-right text-muted-foreground">{log.responseTime ? `${(log.responseTime / 1000).toFixed(1)}s` : '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

