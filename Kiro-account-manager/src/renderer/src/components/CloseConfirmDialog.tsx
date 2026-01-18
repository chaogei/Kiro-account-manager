import { useState, useEffect } from 'react'
import { createPortal } from 'react-dom'
import { X, Minimize2, LogOut, XCircle, Check } from 'lucide-react'
import { Button } from '@/components/ui/button'

export function CloseConfirmDialog() {
  const [open, setOpen] = useState(false)
  const [rememberChoice, setRememberChoice] = useState(false)

  useEffect(() => {
    const unsubscribe = window.api.onShowCloseConfirmDialog(() => {
      setOpen(true)
      setRememberChoice(false)
    })
    return () => unsubscribe()
  }, [])

  const handleAction = (action: 'minimize' | 'quit' | 'cancel') => {
    window.api.sendCloseConfirmResponse(action, rememberChoice)
    setOpen(false)
  }

  if (!open) return null

  return createPortal(
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/50" onClick={() => handleAction('cancel')} />
      
      <div className="relative bg-background rounded-xl shadow-2xl w-full max-w-md m-4 animate-in zoom-in-95 duration-200 border overflow-hidden">
        {/* 头部 */}
        <div className="bg-gradient-to-r from-blue-500/10 to-purple-500/10 p-6 border-b">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 rounded-xl bg-primary/20 flex items-center justify-center">
                <XCircle className="h-6 w-6 text-primary" />
              </div>
              <div>
                <h2 className="text-lg font-bold">关闭窗口</h2>
                <p className="text-sm text-muted-foreground">请选择关闭行为</p>
              </div>
            </div>
            <button
              onClick={() => handleAction('cancel')}
              className="p-2 hover:bg-muted rounded-lg transition-colors"
            >
              <X className="h-5 w-5" />
            </button>
          </div>
        </div>

        {/* 内容 */}
        <div className="p-6 space-y-4">
          <p className="text-sm text-muted-foreground">
            您想要最小化到系统托盘还是退出程序？
          </p>
          
          <p className="text-xs text-muted-foreground bg-muted/50 rounded-lg p-3">
            最小化到托盘后，程序将在后台继续运行，代理服务保持可用。您可以通过点击托盘图标重新打开窗口。
          </p>

          {/* 操作按钮 */}
          <div className="space-y-2">
            <Button 
              variant="outline" 
              className="w-full justify-start gap-3 h-12"
              onClick={() => handleAction('minimize')}
            >
              <div className="w-8 h-8 rounded-lg bg-blue-500/10 flex items-center justify-center">
                <Minimize2 className="h-4 w-4 text-blue-500" />
              </div>
              <div className="text-left">
                <div className="font-medium">最小化到托盘</div>
                <div className="text-xs text-muted-foreground">在后台继续运行</div>
              </div>
            </Button>
            
            <Button 
              variant="outline" 
              className="w-full justify-start gap-3 h-12"
              onClick={() => handleAction('quit')}
            >
              <div className="w-8 h-8 rounded-lg bg-red-500/10 flex items-center justify-center">
                <LogOut className="h-4 w-4 text-red-500" />
              </div>
              <div className="text-left">
                <div className="font-medium">退出程序</div>
                <div className="text-xs text-muted-foreground">完全关闭应用</div>
              </div>
            </Button>
          </div>

          {/* 记住选择 */}
          <div className="flex items-center gap-2 pt-2">
            <button
              type="button"
              onClick={() => setRememberChoice(!rememberChoice)}
              className={`w-4 h-4 rounded border flex items-center justify-center transition-colors ${
                rememberChoice 
                  ? 'bg-primary border-primary' 
                  : 'border-muted-foreground/50 hover:border-primary'
              }`}
            >
              {rememberChoice && <Check className="h-3 w-3 text-primary-foreground" />}
            </button>
            <button
              type="button"
              onClick={() => setRememberChoice(!rememberChoice)}
              className="text-sm text-muted-foreground cursor-pointer select-none"
            >
              记住我的选择
            </button>
          </div>

          {/* 取消按钮 */}
          <Button 
            variant="ghost" 
            className="w-full"
            onClick={() => handleAction('cancel')}
          >
            取消
          </Button>
        </div>
      </div>
    </div>,
    document.body
  )
}
