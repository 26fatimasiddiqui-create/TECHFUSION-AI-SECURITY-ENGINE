import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'
import { ThemeProvider } from './context/ThemeContext'
import { ModeProvider } from './context/ModeContext'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <ThemeProvider>
      <ModeProvider>
        <App />
      </ModeProvider>
    </ThemeProvider>
  </StrictMode>,
)
