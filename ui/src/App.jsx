import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Sidebar from './components/Sidebar'
import TopBar from './components/TopBar'
import DashboardPage from './pages/DashboardPage'
import FindingsPage from './pages/FindingsPage'
import FilesPage from './pages/FilesPage'
import ScansPage from './pages/ScansPage'
import LogsPage from './pages/LogsPage'
import { ScanProvider } from './context/ScanContext'
import { ThemeProvider } from './context/ThemeContext'
import './index.css'

export default function App() {
  return (
    <ThemeProvider>
      <ScanProvider>
        <BrowserRouter>
          <div className="app-shell">
            <Sidebar />
            <div className="main-content">
              <TopBar />
              <div className="page-body">
                <Routes>
                  <Route path="/" element={<Navigate to="/dashboard" replace />} />
                  <Route path="/dashboard" element={<DashboardPage />} />
                  <Route path="/findings" element={<FindingsPage />} />
                  <Route path="/files" element={<FilesPage />} />
                  <Route path="/scans" element={<ScansPage />} />
                  <Route path="/logs" element={<LogsPage />} />
                  <Route path="*" element={<Navigate to="/dashboard" replace />} />
                </Routes>
              </div>
            </div>
          </div>
        </BrowserRouter>
      </ScanProvider>
    </ThemeProvider>
  )
}
