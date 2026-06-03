import { type PropsWithChildren, useEffect, useMemo, useState } from 'react'
import { App as AntdApp, ConfigProvider, theme as antdTheme } from 'antd'

function readCssVar(name: string, fallback: string): string {
  if (typeof window === 'undefined') return fallback
  const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim()
  return value || fallback
}

export function AntdThemeProvider({ children }: PropsWithChildren): React.ReactNode {
  const [themeVersion, setThemeVersion] = useState(0)

  useEffect(() => {
    const root = document.documentElement
    const observer = new MutationObserver(() => {
      setThemeVersion((value) => value + 1)
    })

    observer.observe(root, {
      attributes: true,
      attributeFilter: ['class', 'style']
    })

    return () => observer.disconnect()
  }, [])

  const themeConfig = useMemo(() => {
    const isDark = document.documentElement.classList.contains('dark')

    return {
      cssVar: { key: 'kiro-account-manager' },
      algorithm: isDark ? antdTheme.darkAlgorithm : antdTheme.defaultAlgorithm,
      token: {
        colorFill: readCssVar(
          '--glass-bg-strong',
          isDark ? 'rgba(20, 25, 40, 0.9)' : 'rgba(255, 255, 255, 0.9)'
        ),
        colorBgLayout: readCssVar('--color-background', isDark ? '#0B1220' : '#EEF2F8'),
        colorPrimary: readCssVar('--color-primary', isDark ? '#7BA3FF' : '#5B8CFF'),
        colorSuccess: readCssVar('--color-success', '#22C55E'),
        colorWarning: readCssVar('--color-warning', '#F59E0B'),
        colorError: readCssVar('--color-destructive', '#EF4444'),
        colorText: readCssVar('--color-foreground', isDark ? '#F1F5F9' : '#0F172A'),
        colorTextSecondary: readCssVar('--color-muted-foreground', '#64748B'),
        colorBgBase: readCssVar('--color-background', isDark ? '#0B1220' : '#EEF2F8'),
        colorBgContainer: readCssVar('--glass-bg', isDark ? 'rgba(20, 25, 40, 0.65)' : 'rgba(255, 255, 255, 0.55)'),
        colorBgElevated: readCssVar('--color-popover', isDark ? 'rgba(20, 25, 40, 0.95)' : 'rgba(255, 255, 255, 0.95)'),
        colorBorder: readCssVar('--color-border', isDark ? 'rgba(255,255,255,0.08)' : 'rgba(255,255,255,0.4)'),
        colorBorderSecondary: readCssVar('--glass-border', isDark ? 'rgba(255,255,255,0.08)' : 'rgba(255,255,255,0.4)'),
        colorFillSecondary: readCssVar(
          '--glass-bg-strong',
          isDark ? 'rgba(20, 25, 40, 0.9)' : 'rgba(255, 255, 255, 0.9)'
        ),
        colorFillTertiary: readCssVar('--glass-bg', isDark ? 'rgba(20, 25, 40, 0.65)' : 'rgba(255, 255, 255, 0.55)'),
        colorFillAlter: readCssVar('--color-muted', isDark ? 'rgba(40, 45, 60, 0.5)' : 'rgba(241, 245, 249, 0.7)'),
        fontFamily:
          '"SF Pro Display","SF Pro Text","PingFang SC","Microsoft YaHei","Helvetica Neue",sans-serif'
      },
      components: {
        Layout: {
          headerBg: 'transparent',
          bodyBg: 'transparent',
          siderBg: 'transparent'
        },
        Card: {
          bodyPadding: 16,
          headerHeight: 48
        },
        Table: {
          headerBg: 'transparent',
          bodySortBg: 'transparent',
          headerSortActiveBg: 'transparent',
          headerSortHoverBg: 'transparent',
          rowHoverBg: isDark ? 'rgba(255,255,255,0.04)' : 'rgba(255,255,255,0.5)',
          headerSplitColor: 'transparent'
        },
        Input: {
          activeBg: readCssVar('--glass-bg-strong', isDark ? 'rgba(20, 25, 40, 0.9)' : 'rgba(255, 255, 255, 0.9)'),
          hoverBg: readCssVar('--glass-bg-strong', isDark ? 'rgba(20, 25, 40, 0.9)' : 'rgba(255, 255, 255, 0.9)'),
          addonBg: readCssVar('--glass-bg', isDark ? 'rgba(20, 25, 40, 0.65)' : 'rgba(255, 255, 255, 0.55)'),
          hoverBorderColor: readCssVar(
            '--color-primary',
            isDark ? '#7BA3FF' : '#5B8CFF'
          ),
          activeBorderColor: readCssVar(
            '--color-primary',
            isDark ? '#7BA3FF' : '#5B8CFF'
          ),
          activeShadow: isDark
            ? '0 0 0 2px rgba(123, 163, 255, 0.3)'
            : '0 0 0 2px rgba(91, 140, 255, 0.3)'
        },
        Select: {
          selectorBg: readCssVar('--glass-bg', isDark ? 'rgba(20, 25, 40, 0.65)' : 'rgba(255, 255, 255, 0.55)'),
          optionActiveBg: readCssVar('--color-muted', isDark ? 'rgba(40, 45, 60, 0.5)' : 'rgba(241, 245, 249, 0.7)'),
          optionSelectedBg: readCssVar('--color-muted', isDark ? 'rgba(40, 45, 60, 0.5)' : 'rgba(241, 245, 249, 0.7)'),
          hoverBorderColor: readCssVar('--color-primary', isDark ? '#7BA3FF' : '#5B8CFF'),
          activeBorderColor: readCssVar('--color-primary', isDark ? '#7BA3FF' : '#5B8CFF'),
          activeOutlineColor: 'transparent',
          multipleItemBg: readCssVar('--glass-bg-subtle', isDark ? 'rgba(20, 25, 40, 0.45)' : 'rgba(255, 255, 255, 0.35)'),
          clearBg: readCssVar('--glass-bg', isDark ? 'rgba(20, 25, 40, 0.65)' : 'rgba(255, 255, 255, 0.55)')
        },
        Tabs: {
          cardBg: 'transparent',
          itemSelectedColor: readCssVar('--color-primary', isDark ? '#7BA3FF' : '#5B8CFF'),
          itemColor: readCssVar('--color-muted-foreground', '#64748B')
        },
        Modal: {
          contentBg: readCssVar('--color-background', isDark ? '#0B1220' : '#EEF2F8'),
          headerBg: readCssVar('--color-background', isDark ? '#0B1220' : '#EEF2F8'),
          footerBg: readCssVar('--color-background', isDark ? '#0B1220' : '#EEF2F8'),
          titleColor: readCssVar('--color-foreground', isDark ? '#F1F5F9' : '#0F172A'),
          modalFooterBorderColorSplit: readCssVar(
            '--color-border',
            isDark ? 'rgba(255,255,255,0.08)' : 'rgba(255,255,255,0.4)'
          )
        }
      }
    }
  }, [themeVersion])

  return (
    <ConfigProvider theme={themeConfig}>
      <AntdApp>{children}</AntdApp>
    </ConfigProvider>
  )
}
