import { useState, useEffect } from 'react'
import { AccountManager } from './components/accounts'
import { Sidebar, type PageType } from './components/layout'
import { HomePage, AboutPage, SettingsPage, MachineIdPage, KiroSettingsPage } from './components/pages'
import { UpdateDialog } from './components/UpdateDialog'
import { useAccountsStore } from './store/accounts'

function App(): React.JSX.Element {
  const [currentPage, setCurrentPage] = useState<PageType>('home')
  const [sidebarCollapsed, setSidebarCollapsed] = useState(true)
  
  const { loadFromStorage, startAutoTokenRefresh, stopAutoTokenRefresh, handleBackgroundRefreshResult, handleBackgroundCheckResult } = useAccountsStore()
  
  // 应用启动时加载数据并启动自动刷新
  useEffect(() => {
    loadFromStorage().then(() => {
      startAutoTokenRefresh()
    })
    
    return () => {
      stopAutoTokenRefresh()
    }
  }, [loadFromStorage, startAutoTokenRefresh, stopAutoTokenRefresh])

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
    </div>
  )
}

export default App
