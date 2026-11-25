import { createContext, useContext, useState, useCallback, useEffect, useMemo, useRef } from 'react'
import { ApiError, authHeaders, loadToken, readSse, saveToken, toApiError } from '../lib/api'
import { zipFiles } from '../lib/upload'
import { useLocalState } from '../lib/useLocalState'
import { mergePreview } from '../lib/liveHits'

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

const LOCAL_CONFIG = {
  mode: 'local',
  auth_required: false,
  features: { path: true, upload: false, git: false, llm: true, history: true },
  limits: {},
}

const isAbort = (err) => err?.name === 'AbortError'

export function ScanProvider({ children }) {
  const [config, setConfig] = useState(null) // null while /api/config is loading
  const [token, setTokenState] = useState(loadToken)
  const [authError, setAuthError] = useState('')
  const [scanResult, setScanResult] = useState(null)
  const [scanning, setScanning] = useState(false)
  const [progress, setProgress] = useState({ phase: '', file: '', pct: 0, found: 0 })
  const [logs, setLogs] = useState([])
  const [history, setHistory] = useState([])
  const [historyStatus, setHistoryStatus] = useState('loading') // loading | ready | error
  const [scanError, setScanError] = useState(null)
  const [selectedId, setSelectedId] = useState(null)
  // Preliminary findings streamed as each static tool finishes: { byPath: {path: {worst, count}}, total, tool }.
  const [liveHits, setLiveHits] = useState(null)
  const [liveFiles, setLiveFiles] = useState(null) // { files: [{path, lines}], total } streamed once the scanner has crawled the target
  // Timestamped progress/log events for the timeline. t is ms since the scan was requested.
  // Recorded client-side from the stream; the API exposes no phase timings of its own.
  const [recording, setRecording] = useState({ events: [], durationMs: 0, live: false, startedAt: 0 })
  const startedAtRef = useRef(0)
  const abortRef = useRef(null)
  const uploadRef = useRef({ source: null, id: null }) // reuse an upload for re-scans of the same selection
  const nowMs = () => performance.now() - startedAtRef.current
  const record = useCallback((ev) => {
    setRecording((r) => ({ ...r, events: [...r.events, { t: performance.now() - startedAtRef.current, ...ev }] }))
  }, [])
  const [targetPath, setTargetPath] = useState('.')
  const [source, setSource] = useState({ kind: 'folder', folder: null, gitUrl: '' }) // hosted mode input
  const [options, setOptions] = useState({
    staticOnly: true,
    deep: false,
    generatePatches: false,
    privacy: 'standard',
    apiKey: '',
  })

  const hosted = config?.mode === 'hosted'
  const needsToken = !!config?.auth_required && !token

  const setToken = useCallback((value) => {
    saveToken(value)
    setTokenState(value)
  }, [])

  // ---- server capabilities (local vs hosted) ----
  useEffect(() => {
    let cancelled = false
    fetch('/api/config')
      .then((res) => (res.ok ? res.json() : Promise.reject(new Error(`config ${res.status}`))))
      .then((data) => {
        if (!cancelled) setConfig({ ...LOCAL_CONFIG, ...data, features: { ...LOCAL_CONFIG.features, history: data.mode !== 'hosted', ...data.features } })
      })
      .catch(() => {
        if (!cancelled) setConfig(LOCAL_CONFIG)
      })
    return () => { cancelled = true }
  }, [])

  const fetchHistory = useCallback(async () => {
    if (!config) return
    if (!config.features.history) {
      setHistory([])
      setHistoryStatus('ready')
      return
    }
    try {
      const res = await fetch('/api/history?limit=20', { headers: authHeaders(token) })
      if (!res.ok) throw new Error(`history ${res.status}`)
      const data = await res.json()
      setHistory(data)
      setHistoryStatus('ready')
      if (data && data.length > 0 && targetPath === '.') {
        setTargetPath(data[0].target_path || '.')
      }
    } catch {
      setHistoryStatus('error')
    }
  }, [config, token, targetPath])

  useEffect(() => {
    if (config && !needsToken) fetchHistory()
  }, [config, needsToken, fetchHistory])

  const finishWithResult = useCallback((result) => {
    setScanResult(result)
    setScanning(false)
    setRecording((r) => ({ ...r, durationMs: nowMs(), live: false }))
    setProgress({ phase: 'Complete', file: '', pct: 100, found: result.findings?.length ?? 0 })
    setLogs((prev) => [...prev, makeLog('ok', `Scan complete — ${result.findings?.length ?? 0} findings, score ${result.security_score != null ? Math.round(result.security_score) : '—'}/100`)])
    fetchHistory()
  }, [fetchHistory])

  const finishWithError = useCallback((message) => {
    setScanError(message)
    setScanning(false)
    setRecording((r) => ({ ...r, durationMs: nowMs(), live: false }))
    setLogs((prev) => [...prev, makeLog('err', message)])
  }, [])

  /** Hosted mode: zip the chosen folder in the browser and upload it (or reuse the previous upload). */
  const prepareUpload = useCallback(async (signal, force) => {
    const folder = source.folder
    if (!folder?.files?.length) throw new ApiError(400, 'Choose a folder to scan first.')
    if (!force && uploadRef.current.source === folder && uploadRef.current.id) return uploadRef.current.id

    setProgress({ phase: 'Preparing folder', file: '', pct: 2, found: 0 })
    record({ kind: 'progress', level: 'info', phase: 'Preparing folder', pct: 2, found: 0, message: 'Preparing folder' })
    setLogs((prev) => [...prev, makeLog('info', `Preparing ${folder.files.length} files from ${folder.name}`)])
    const blob = await zipFiles(folder.files)
    const limit = (config?.limits?.max_upload_mb ?? 50) * 1024 * 1024
    if (blob.size > limit) {
      throw new ApiError(413, `The zipped folder is larger than ${Math.round(limit / 1048576)} MB. Leave out large or generated folders and try again.`)
    }

    setProgress({ phase: 'Uploading folder', file: '', pct: 4, found: 0 })
    record({ kind: 'progress', level: 'info', phase: 'Uploading folder', pct: 4, found: 0, message: 'Uploading folder' })
    const res = await fetch('/api/upload', {
      method: 'POST',
      headers: { 'Content-Type': 'application/zip', 'X-Upload-Name': encodeURIComponent(folder.name), ...authHeaders(token) },
      body: blob,
      signal,
    })
    if (!res.ok) throw await toApiError(res)
    const data = await res.json()
    uploadRef.current = { source: folder, id: data.upload_id }
    return data.upload_id
  }, [source, config, token, record])

  const buildBody = useCallback(async (signal, forceUpload = false) => {
    if (!hosted) {
      const forceLocalOnly = options.privacy === 'strict'
      return {
        path: targetPath,
        static_only: forceLocalOnly || (options.staticOnly && !options.deep && !options.generatePatches),
        deep: options.deep,
        generate_patches: forceLocalOnly ? false : options.generatePatches,
        privacy: options.privacy,
        api_key: options.apiKey,
      }
    }
    if (source.kind === 'git') {
      if (!source.gitUrl.trim()) throw new ApiError(400, 'Enter a Git URL to scan.')
      return { git_url: source.gitUrl.trim() }
    }
    return { upload_id: await prepareUpload(signal, forceUpload) }
  }, [hosted, options, targetPath, source, prepareUpload])

  const startScan = useCallback(async () => {
    if (!config || needsToken) return
    abortRef.current?.abort()
    const controller = new AbortController()
    abortRef.current = controller
    const { signal } = controller

    setScanning(true)
    setScanError(null)
    setSelectedId(null)
    setLiveFiles(null)
    setLiveHits(null)
    startedAtRef.current = performance.now()
    setRecording({ events: [], durationMs: 0, live: true, startedAt: startedAtRef.current })
    setProgress({ phase: 'Initializing scanner...', file: '', pct: 1, found: 0 })
    setLogs([makeLog('info', 'Scan requested — connecting to pipeline…')])

    let completed = false
    const onEvent = (name, d) => {
      if (name === 'progress') {
        setProgress(d)
        record({ kind: 'progress', level: 'info', phase: d.phase, pct: d.pct, found: d.found, message: d.phase })
        setLogs((prev) => [...prev, makeLog('info', d.file ? `${d.phase} — ${d.file}` : d.phase)])
      } else if (name === 'files') {
        setLiveFiles(d)
      } else if (name === 'preview') {
        setLiveHits((prev) => mergePreview(prev, d))
      } else if (name === 'log') {
        // Backend log records (provider rate limits, tool errors, ...), see scanner/server/app.py.
        record({ kind: 'log', level: pyLevelToLogLevel(d.level), message: d.message })
        setLogs((prev) => [...prev, makeLog(pyLevelToLogLevel(d.level), d.message)])
      } else if (name === 'complete') {
        completed = true
        finishWithResult(d)
      } else if (name === 'error') {
        completed = true
        finishWithError(d.error || 'The scan did not finish.')
      }
    }

    const streamOnce = async (forceUpload) => {
      const body = await buildBody(signal, forceUpload)
      const res = await fetch('/api/scan/stream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...authHeaders(token) },
        body: JSON.stringify(body),
        signal,
      })
      if (!res.ok) throw await toApiError(res)
      await readSse(res, onEvent)
      return body
    }

    try {
      let body
      try {
        body = await streamOnce(false)
      } catch (err) {
        // The upload expired between scans: upload the same folder again once.
        if (hosted && err instanceof ApiError && err.status === 404 && source.kind === 'folder') {
          uploadRef.current = { source: null, id: null }
          body = await streamOnce(true)
        } else {
          throw err
        }
      }
      if (!completed && !hosted) {
        // Stream ended without a result: fall back to the single-shot request, as before.
        setLogs((prev) => [...prev, makeLog('warn', 'Stream interrupted — falling back to a single-shot scan request…')])
        const res = await fetch('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', ...authHeaders(token) },
          body: JSON.stringify(body),
          signal,
        })
        const result = await res.json()
        if (result.error) finishWithError(result.error)
        else finishWithResult(result)
      } else if (!completed) {
        finishWithError('The connection ended before the scan finished. Try again.')
      }
    } catch (err) {
      if (isAbort(err)) return
      if (err instanceof ApiError && err.status === 401) {
        setToken('')
        setAuthError('The access token was not accepted. Enter it again.')
        finishWithError(err.message)
      } else if (err instanceof ApiError) {
        finishWithError(err.message)
      } else {
        finishWithError('Could not reach the scan server.')
      }
    }
  }, [config, needsToken, token, hosted, source, buildBody, record, finishWithResult, finishWithError, setToken])

  /** Stop the running scan. Closing the stream tells the server to stop at its next step. */
  const cancelScan = useCallback(() => {
    if (!abortRef.current) return
    abortRef.current.abort()
    abortRef.current = null
    setScanning(false)
    setRecording((r) => ({ ...r, durationMs: nowMs(), live: false }))
    setProgress({ phase: 'Cancelled', file: '', pct: 0, found: 0 })
    setLogs((prev) => [...prev, makeLog('warn', 'Scan cancelled. The server stops at its next step; a long step such as Semgrep finishes first.')])
  }, [])

  useEffect(() => () => abortRef.current?.abort(), [])

  const log = useCallback((level, message) => setLogs((prev) => [...prev, makeLog(level, message)]), [])
  const local = useLocalState({
    enabled: !!config && !hosted && !needsToken && config.features.history !== false,
    token, scanResult, setScanResult, scanning, history, log,
  })

  const value = useMemo(() => ({
    ...local,
    config, hosted, needsToken, token, setToken, authError, setAuthError,
    scanResult, setScanResult,
    scanning, progress,
    logs,
    history, fetchHistory, historyStatus,
    scanError, selectedId, setSelectedId, recording, liveFiles, liveHits,
    targetPath, setTargetPath,
    source, setSource,
    options, setOptions,
    startScan, cancelScan,
  }), [local, config, hosted, needsToken, token, setToken, authError, scanResult, scanning, progress, logs, history, fetchHistory, historyStatus, scanError, selectedId, recording, liveFiles, liveHits, targetPath, source, options, startScan, cancelScan])

  return (
    <ScanContext.Provider value={value}>
      {children}
    </ScanContext.Provider>
  )
}

export const useScan = () => useContext(ScanContext)
