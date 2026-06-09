import {
  Home,
  Users,
  Settings,
  Info,
  ChevronRight,
  Fingerprint,
  Sparkles,
  Server,
  Shield,
  UserPlus,
  CreditCard,
  ScrollText,
  Network,
  Bell,
  Stethoscope,
  Archive,
  Puzzle,
  Plug
} from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'
import { cn } from '@/lib/utils'
import kiroLogo from '@/assets/kiro-high-resolution-logo-transparent.png'
import kiroLogoSmall from '@/assets/Kiro Logo.svg'
import { useAccountsStore } from '@/store/accounts'
import { useTranslation } from '@/hooks/useTranslation'

export type PageType =
  | 'home'
  | 'accounts'
  | 'machineId'
  | 'kiroSettings'
  | 'skills'
  | 'mcp'
  | 'proxy'
  | 'kproxy'
  | 'proxyPool'
  | 'register'
  | 'subscription'
  | 'webhooks'
  | 'diagnose'
  | 'configSync'
  | 'logs'
  | 'settings'
  | 'about'

interface SidebarProps {
  currentPage: PageType
  onPageChange: (page: PageType) => void
  collapsed: boolean
  onToggleCollapse: () => void
}

const menuItemsConfig: { id: PageType; labelKey: string; icon: React.ElementType }[] = [
  { id: 'home', labelKey: 'nav.home', icon: Home },
  { id: 'accounts', labelKey: 'nav.accounts', icon: Users },
  { id: 'machineId', labelKey: 'nav.machineId', icon: Fingerprint },
  { id: 'kiroSettings', labelKey: 'nav.kiroSettings', icon: Sparkles },
  { id: 'skills', labelKey: 'nav.skills', icon: Puzzle },
  { id: 'mcp', labelKey: 'nav.mcp', icon: Plug },
  { id: 'proxy', labelKey: 'nav.proxy', icon: Server },
  { id: 'kproxy', labelKey: 'nav.kproxy', icon: Shield },
  { id: 'proxyPool', labelKey: 'nav.proxyPool', icon: Network },
  { id: 'register', labelKey: 'nav.register', icon: UserPlus },
  { id: 'subscription', labelKey: 'nav.subscription', icon: CreditCard },
  { id: 'webhooks', labelKey: 'nav.webhooks', icon: Bell },
  { id: 'diagnose', labelKey: 'nav.diagnose', icon: Stethoscope },
  { id: 'configSync', labelKey: 'nav.configSync', icon: Archive },
  { id: 'logs', labelKey: 'nav.logs', icon: ScrollText },
  { id: 'settings', labelKey: 'nav.settings', icon: Settings },
  { id: 'about', labelKey: 'nav.about', icon: Info }
]

export function Sidebar({
  currentPage,
  onPageChange,
  collapsed,
  onToggleCollapse
}: SidebarProps): React.ReactNode {
  const { darkMode } = useAccountsStore()
  const { t } = useTranslation()
  const isEn = t('common.unknown') === 'Unknown'

  return (
    <motion.aside
      initial={false}
      animate={{ width: collapsed ? 64 : 224 }}
      transition={{ type: 'spring', stiffness: 320, damping: 30 }}
      className="glass-sidebar rounded-3xl flex flex-col overflow-hidden shrink-0"
    >
      {/* Logo */}
      <div className="h-14 flex items-center justify-center px-3 gap-2 overflow-hidden border-b border-white/10 dark:border-white/5">
        <AnimatePresence mode="wait" initial={false}>
          {collapsed ? (
            <motion.img
              key="logo-small"
              src={kiroLogoSmall}
              alt="Kiro"
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.8 }}
              transition={{ duration: 0.2 }}
              className={cn('h-10 w-10 object-contain', darkMode && 'invert brightness-0')}
            />
          ) : (
            <motion.div
              key="logo-full"
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -10 }}
              transition={{ duration: 0.2 }}
              className="flex items-center gap-2"
            >
              <img
                src={kiroLogo}
                alt="Kiro"
                className={cn('h-7 w-auto shrink-0', darkMode && 'invert brightness-0')}
              />
              <span className="font-semibold text-foreground whitespace-nowrap text-sm">
                {isEn ? 'Account Manager' : '账户管理器'}
              </span>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Menu Items */}
      <nav className="flex-1 py-3 px-2 space-y-1 overflow-y-auto">
        {menuItemsConfig.map((item) => {
          const Icon = item.icon
          const isActive = currentPage === item.id
          const label = t(item.labelKey)
          return (
            <button
              key={item.id}
              onClick={() => onPageChange(item.id)}
              className={cn(
                'group relative w-full flex items-center rounded-xl text-sm font-medium transition-all overflow-hidden focus:outline-none focus-visible:ring-2 focus-visible:ring-primary/50',
                isActive
                  ? 'text-primary-foreground shadow-[0_4px_16px_rgba(91,140,255,0.35)]'
                  : 'text-muted-foreground hover:text-foreground hover:bg-white/40 dark:hover:bg-white/5',
                collapsed ? 'justify-center p-2.5' : 'gap-3 px-3 py-2.5'
              )}
              title={collapsed ? label : undefined}
            >
              {/* 激活态：渐变背景（主题色随动） */}
              {isActive && (
                <motion.span
                  layoutId="sidebar-active-pill"
                  className="absolute inset-0 rounded-xl"
                  style={{
                    background: 'linear-gradient(135deg, var(--gradient-from), var(--gradient-to))'
                  }}
                  transition={{ type: 'spring', stiffness: 380, damping: 32 }}
                />
              )}
              <Icon
                className={cn('h-5 w-5 shrink-0 relative z-10', isActive ? 'text-white' : '')}
              />
              <AnimatePresence initial={false}>
                {!collapsed && (
                  <motion.span
                    key="label"
                    initial={{ opacity: 0, x: -8 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -8 }}
                    transition={{ duration: 0.15 }}
                    className={cn('whitespace-nowrap relative z-10', isActive && 'text-white')}
                  >
                    {label}
                  </motion.span>
                )}
              </AnimatePresence>
            </button>
          )
        })}
      </nav>

      {/* Collapse Toggle */}
      <div className="p-2 border-t border-white/10 dark:border-white/5">
        <button
          onClick={onToggleCollapse}
          className="group w-full flex items-center justify-center gap-2 px-3 py-2 rounded-xl text-sm text-muted-foreground hover:text-primary hover:bg-white/40 dark:hover:bg-white/5 transition-all overflow-hidden focus:outline-none focus-visible:ring-2 focus-visible:ring-primary/50"
          title={collapsed ? (isEn ? 'Expand' : '展开侧边栏') : isEn ? 'Collapse' : '收起侧边栏'}
        >
          <motion.div
            animate={{ rotate: collapsed ? 0 : 180 }}
            transition={{ duration: 0.3, ease: [0.4, 0, 0.2, 1] }}
            className="shrink-0"
          >
            <ChevronRight className="h-4 w-4" />
          </motion.div>
          <AnimatePresence initial={false}>
            {!collapsed && (
              <motion.span
                key="collapse-label"
                initial={{ opacity: 0, width: 0 }}
                animate={{ opacity: 1, width: 'auto' }}
                exit={{ opacity: 0, width: 0 }}
                transition={{ duration: 0.15 }}
                className="whitespace-nowrap overflow-hidden"
              >
                {isEn ? 'Collapse' : '收起'}
              </motion.span>
            )}
          </AnimatePresence>
        </button>
      </div>
    </motion.aside>
  )
}
