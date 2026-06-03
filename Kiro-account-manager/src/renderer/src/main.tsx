import './styles/globals.css'

import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App'
import { AntdThemeProvider } from './theme/AntdThemeProvider'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <AntdThemeProvider>
      <App />
    </AntdThemeProvider>
  </StrictMode>
)
