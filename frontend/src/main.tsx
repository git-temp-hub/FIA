import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import { ThemeProvider } from './theme/ThemeProvider.tsx'
import { ToastProvider } from './components/ui/ToastProvider.tsx'
import UploadProvider from './upload/UploadProvider.tsx'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ThemeProvider>
      <ToastProvider>
        {/* Above the router so an in-flight upload survives navigation. */}
        <UploadProvider>
          <App />
        </UploadProvider>
      </ToastProvider>
    </ThemeProvider>
  </StrictMode>,
)
