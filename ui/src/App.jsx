import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import CommandBar from './components/shell/CommandBar'
import RailNav from './components/shell/RailNav'
import TokenGate from './components/shell/TokenGate'
import ScanPage from './pages/ScanPage'
import FindingsPage from './pages/FindingsPage'
import FilesPage from './pages/FilesPage'
import ScansPage from './pages/ScansPage'
import LogsPage from './pages/LogsPage'
import { ScanProvider } from './context/ScanContext'
import { ThemeProvider } from './context/ThemeContext'
import { ToastProvider } from './context/ToastContext'
import './index.css'
import './styles/tokens.css'
import './styles/aegis.css'

function Page({ children }) {
  return <main className="ag-page">{children}</main>
}

export default function App() {
  return (
    <ThemeProvider>
      <ToastProvider>
      <ScanProvider>
        <BrowserRouter>
          <div className="ag-app">
            <TokenGate />
            <CommandBar />
            <RailNav />
            <Routes>
              <Route path="/" element={<Navigate to="/dashboard" replace />} />
              <Route path="/dashboard" element={<ScanPage />} />
              <Route path="/findings" element={<Page><FindingsPage /></Page>} />
              <Route path="/files" element={<Page><FilesPage /></Page>} />
              <Route path="/scans" element={<Page><ScansPage /></Page>} />
              <Route path="/logs" element={<Page><LogsPage /></Page>} />
              <Route path="*" element={<Navigate to="/dashboard" replace />} />
            </Routes>
          </div>
        </BrowserRouter>
      </ScanProvider>
      </ToastProvider>
    </ThemeProvider>
  )
}
