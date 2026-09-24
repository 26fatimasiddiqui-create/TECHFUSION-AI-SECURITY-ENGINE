import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'
import { ThemeProvider } from './context/ThemeContext'
import { ModeProvider } from './context/ModeContext'
import { ErrorBoundary } from './components/common/ErrorBoundary'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <ErrorBoundary>
      <ThemeProvider>
        <ModeProvider>
          <App />
        </ModeProvider>
      </ThemeProvider>
    </ErrorBoundary>
  </StrictMode>,
)

