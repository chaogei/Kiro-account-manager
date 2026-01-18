import { useState, useEffect, useCallback } from 'react'
import { AccountManager } from './components/accounts'
import { Sidebar, type PageType } from './components/layout'
import { HomePage, AboutPage, SettingsPage, MachineIdPage, KiroSettingsPage, ProxyPage } from './components/pages'
import { UpdateDialog } from './components/UpdateDialog'
import { CloseConfirmDialog } from './components/CloseConfirmDialog'
import { useAccountsStore } from './store/accounts'

function App(): React.JSX.Element {
  const [currentPage, setCurrentPage] = useState<PageType>('home')
  const [sidebarCollapsed, setSidebarCollapsed] = useState(true)
  
  const { 
    loadFromStorage, 
    startAutoTokenRefresh, 
    stopAutoTokenRefresh, 
    handleBackgroundRefreshResult, 
    handleBackgroundCheckResult,
    accounts,
    activeAccountId,
    setActiveAccount,
    checkAndRefreshExpiringTokens
  } = useAccountsStore()

  // 切换到下一个可用账户
  const switchToNextAccount = useCallback(() => {
    const activeAccounts = Array.from(accounts.values()).filter(acc => acc.status === 'active')
    if (activeAccounts.length <= 1) return

    const currentIndex = activeAccounts.findIndex(acc => acc.id === activeAccountId)
    const nextIndex = (currentIndex + 1) % activeAccounts.length
    setActiveAccount(activeAccounts[nextIndex].id)
  }, [accounts, activeAccountId, setActiveAccount])

  // 更新托盘账户信息
  const updateTrayInfo = useCallback(() => {
    // 更新账户列表
    const accountList = Array.from(accounts.values()).map(acc => ({
      id: acc.id,
      email: acc.email || 'Unknown',
      idp: acc.idp || 'Unknown',
      status: acc.status
    }))
    window.api.updateTrayAccountList(accountList)

    // 更新当前账户
    if (activeAccountId) {
      const activeAccount = accounts.get(activeAccountId)
      if (activeAccount) {
        window.api.updateTrayAccount({
          id: activeAccount.id,
          email: activeAccount.email || 'Unknown',
          idp: activeAccount.idp || 'Unknown',
          status: activeAccount.status,
          usage: activeAccount.usage ? {
            inputTokens: activeAccount.usage.current || 0,
            outputTokens: activeAccount.usage.limit || 0,
            totalRequests: Math.round(activeAccount.usage.percentUsed * 100)
          } : undefined
        })
      } else {
        window.api.updateTrayAccount(null)
      }
    } else {
      window.api.updateTrayAccount(null)
    }
  }, [accounts, activeAccountId])
  
  // 应用启动时加载数据并启动自动刷新
  useEffect(() => {
    loadFromStorage().then(() => {
      startAutoTokenRefresh()
    })
    
    return () => {
      stopAutoTokenRefresh()
    }
  }, [loadFromStorage, startAutoTokenRefresh, stopAutoTokenRefresh])

  // 账户变化时更新托盘信息
  useEffect(() => {
    updateTrayInfo()
  }, [updateTrayInfo])

  // 监听托盘刷新账户事件
  useEffect(() => {
    const unsubscribe = window.api.onTrayRefreshAccount(() => {
      checkAndRefreshExpiringTokens()
      updateTrayInfo()
    })
    return () => {
      unsubscribe()
    }
  }, [checkAndRefreshExpiringTokens, updateTrayInfo])

  // 监听托盘切换账户事件
  useEffect(() => {
    const unsubscribe = window.api.onTraySwitchAccount(() => {
      switchToNextAccount()
    })
    return () => {
      unsubscribe()
    }
  }, [switchToNextAccount])

  // 监听后台刷新结果
  useEffect(() => {
    const unsubscribe = window.api.onBackgroundRefreshResult((data) => {
      handleBackgroundRefreshResult(data)
    })
    return () => {
      unsubscribe()
    }
  }, [handleBackgroundRefreshResult])

  // 监听后台检查结果
  useEffect(() => {
    const unsubscribe = window.api.onBackgroundCheckResult((data) => {
      handleBackgroundCheckResult(data)
    })
    return () => {
      unsubscribe()
    }
  }, [handleBackgroundCheckResult])

  const renderPage = () => {
    switch (currentPage) {
      case 'home':
        return <HomePage />
      case 'accounts':
        return <AccountManager />
      case 'machineId':
        return <MachineIdPage />
      case 'kiroSettings':
        return <KiroSettingsPage />
      case 'proxy':
        return <ProxyPage />
      case 'settings':
        return <SettingsPage />
      case 'about':
        return <AboutPage />
      default:
        return <HomePage />
    }
  }

  return (
    <div className="h-screen bg-background flex">
      <Sidebar
        currentPage={currentPage}
        onPageChange={setCurrentPage}
        collapsed={sidebarCollapsed}
        onToggleCollapse={() => setSidebarCollapsed(!sidebarCollapsed)}
      />
      <main className="flex-1 overflow-auto">
        {renderPage()}
      </main>
      <UpdateDialog />
      <CloseConfirmDialog />
    </div>
  )
}

export default App
