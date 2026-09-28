import { createContext, useContext, useState, useCallback, useEffect, useMemo } from 'react'

const ScanContext = createContext(null)

let _logSeq = 0
function makeLog(level, message) {
  return { id: `${Date.now()}-${_logSeq++}`, ts: new Date(), level, message }
}

function pyLevelToLogLevel(pyLevel) {
  if (pyLevel === 'error' || pyLevel === 'critical') return 'err'
  if (pyLevel === 'warning') return 'warn'
  return 'info'
}

export function ScanProvider({ children }) {
  const [scanResult, setScanResult] = useState(null)
  const [scanning, setScanning] = useState(false)
  const [progress, setProgress] = useState({ phase: '', file: '', pct: 0, found: 0 })
  const [logs, setLogs] = useState([])
  const [history, setHistory] = useState([])
  const [targetPath, setTargetPath] = useState('.')
  const [options, setOptions] = useState({
    staticOnly: true,
    deep: false,
    generatePatches: false,
    privacy: 'standard',
    apiKey: '',
  })

  const fetchHistory = useCallback(async () => {
    try {
      const res = await fetch('/api/history?limit=20')
      if (res.ok) {
        const data = await res.json()
        setHistory(data)
        if (data && data.length > 0 && targetPath === '.') {
          const latest = data[0]
          setTargetPath(latest.target_path || '.')
        }
      }
    } catch {}
  }, [targetPath])

  useEffect(() => {
    fetchHistory()
  }, [fetchHistory])

  const startScan = useCallback(async () => {
    setScanning(true)
    setProgress({ phase: 'Initializing scanner...', file: '', pct: 5, found: 0 })
    setLogs([makeLog('info', 'Scan requested — connecting to pipeline…')])

    const forceLocalOnly = options.privacy === 'strict'
    const isStaticOnly = forceLocalOnly || (options.staticOnly && !options.deep && !options.generatePatches)
    const shouldGeneratePatches = forceLocalOnly ? false : options.generatePatches

    const params = new URLSearchParams({
      path: targetPath,
      static_only: String(isStaticOnly),
      deep: String(options.deep),
      generate_patches: String(shouldGeneratePatches),
      privacy: options.privacy,
      api_key: options.apiKey,
    })

    try {
      const es = new EventSource(`/api/scan/stream?${params}`)

      es.addEventListener('progress', (e) => {
        const d = JSON.parse(e.data)
        setProgress(d)
        const text = d.file ? `${d.phase} — ${d.file}` : d.phase
        setLogs((prev) => [...prev, makeLog('info', text)])
      })

      // Real backend log records (provider rate limits/failover, static-tool
      // errors, etc.) forwarded live from Python's logging module — see
      // scanner/server/app.py's _SSELogHandler.
      es.addEventListener('log', (e) => {
        const d = JSON.parse(e.data)
        setLogs((prev) => [...prev, makeLog(pyLevelToLogLevel(d.level), d.message)])
      })

      es.addEventListener('complete', (e) => {
        const result = JSON.parse(e.data)
        setScanResult(result)
        setScanning(false)
        setProgress({ phase: 'Complete', file: '', pct: 100, found: result.findings?.length ?? 0 })
        setLogs((prev) => [...prev, makeLog('ok', `Scan complete — ${result.findings?.length ?? 0} findings, score ${result.security_score != null ? Math.round(result.security_score) : '—'}/100`)])
        es.close()
        fetchHistory()
      })

      es.addEventListener('error', () => {
        es.close()
        setLogs((prev) => [...prev, makeLog('warn', 'Stream interrupted — falling back to a single-shot scan request…')])
        // Fallback to sync POST scan endpoint
        fetch('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            path: targetPath,
            static_only: isStaticOnly,
            deep: options.deep,
            generate_patches: shouldGeneratePatches,
            privacy: options.privacy,
            api_key: options.apiKey,
          })
        })
          .then(r => r.json())
          .then(result => {
            if (!result.error) {
              setScanResult(result)
              setProgress({ phase: 'Complete', file: '', pct: 100, found: result.findings?.length ?? 0 })
              setLogs((prev) => [...prev, makeLog('ok', `Scan complete — ${result.findings?.length ?? 0} findings, score ${result.security_score != null ? Math.round(result.security_score) : '—'}/100`)])
            } else {
              setLogs((prev) => [...prev, makeLog('err', result.error)])
            }
          })
          .catch(() => setLogs((prev) => [...prev, makeLog('err', 'Fallback scan request failed.')]))
          .finally(() => {
            setScanning(false)
            fetchHistory()
          })
      })
    } catch {
      setScanning(false)
    }
  }, [targetPath, options, fetchHistory])

  const value = useMemo(() => ({
    scanResult, setScanResult,
    scanning, progress,
    logs,
    history, fetchHistory,
    targetPath, setTargetPath,
    options, setOptions,
    startScan,
  }), [scanResult, scanning, progress, logs, history, fetchHistory, targetPath, options, startScan])

  return (
    <ScanContext.Provider value={value}>
      {children}
    </ScanContext.Provider>
  )
}

export const useScan = () => useContext(ScanContext)
