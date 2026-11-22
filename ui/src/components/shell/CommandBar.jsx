import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { useScan } from '../../context/ScanContext'
import { useTheme } from '../../context/ThemeContext'
import SourcePicker from './SourcePicker'

function ThemeSwitch() {
  const { theme, setTheme } = useTheme()
  return (
    <div className="ag-seg" role="group" aria-label="Colour theme">
      <button type="button" aria-pressed={theme === 'day'} onClick={() => setTheme('day')}>Day</button>
      <button type="button" aria-pressed={theme === 'night'} onClick={() => setTheme('night')}>Night</button>
    </div>
  )
}

/** Less common options that the old top bar exposed: patch generation and the Groq key. */
function MoreOptions() {
  const { options, setOptions } = useScan()
  const [open, setOpen] = useState(false)
  const ref = useRef(null)

  useEffect(() => {
    if (!open) return undefined
    const onDown = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false) }
    const onKey = (e) => { if (e.key === 'Escape') setOpen(false) }
    document.addEventListener('pointerdown', onDown)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('pointerdown', onDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  return (
    <div className="ag-opts" ref={ref}>
      <button type="button" className="ag-btn ag-btn--ghost" aria-expanded={open} aria-controls="ag-more-opts" onClick={() => setOpen((o) => !o)}>
        More
      </button>
      {open && (
        <div className="ag-opts-panel" id="ag-more-opts" role="group" aria-label="More scan options">
          <label className="ag-check" style={{ padding: 0 }}>
            <input
              type="checkbox"
              checked={options.generatePatches}
              onChange={(e) => setOptions((o) => ({ ...o, generatePatches: e.target.checked }))}
            />
            Generate fix patches
          </label>
          <label className="ag-field">
            Groq API key, optional
            <input
              className="ag-input ag-mono"
              type="password"
              autoComplete="off"
              value={options.apiKey || ''}
              placeholder="gsk_..."
              onChange={(e) => setOptions((o) => ({ ...o, apiKey: e.target.value }))}
            />
          </label>
        </div>
      )}
    </div>
  )
}

export default function CommandBar() {
  const { config, hosted, scanning, scanResult, progress, scanError, startScan, targetPath, setTargetPath, options, setOptions } = useScan()
  const showScanOptions = !hosted || !!config?.features?.llm

  let status = 'Idle'
  if (!config) status = 'Connecting'
  else if (scanning) status = (progress.phase ? `Scanning: ${progress.phase}` : 'Scanning')
  else if (scanError) status = 'Scan failed'
  else if (scanResult) status = 'Scan ready'

  return (
    <header className="ag-cmd">
      <Link className="ag-brand" to="/dashboard" aria-label="AegisScan, scan view">
        <svg className="ag-brand-mark" viewBox="0 0 64 64" aria-hidden="true" focusable="false">
          <g fill="none" stroke="currentColor" strokeWidth="3.5" strokeLinejoin="round" strokeLinecap="round">
            <path d="M32 4 L55 12 V32 C55 46 45 55 32 60 C19 55 9 46 9 32 V12 Z" fill="currentColor" fillOpacity=".15" />
            <path d="M32 38 L46 44 L32 51 L18 44 Z" fill="currentColor" />
            <path d="M32 38 V20" />
            <path d="M32 12 L37 17 L32 22 L27 17 Z" fill="currentColor" />
          </g>
        </svg>
      </Link>
      <span className="ag-name">AegisScan</span>
      {hosted ? (
        <SourcePicker />
      ) : (
        <>
          <label className="visually-hidden" htmlFor="ag-target">Scan target</label>
          <input
            id="ag-target"
            className="ag-input ag-path"
            value={targetPath}
            spellCheck={false}
            placeholder="Directory to scan"
            onChange={(e) => setTargetPath(e.target.value)}
          />
        </>
      )}
      {showScanOptions && (
        <>
          <label className="ag-check">
            <input
              type="checkbox"
              checked={options.deep}
              onChange={(e) => setOptions((o) => ({ ...o, deep: e.target.checked, staticOnly: e.target.checked ? false : o.staticOnly }))}
            />
            Deep
          </label>
          <label className="ag-check">
            <input
              type="checkbox"
              checked={options.staticOnly && !options.deep}
              onChange={(e) => setOptions((o) => ({ ...o, staticOnly: e.target.checked, deep: e.target.checked ? false : o.deep }))}
            />
            Static only
          </label>
          <label className="visually-hidden" htmlFor="ag-privacy">Privacy level</label>
          <select
            id="ag-privacy"
            className="ag-input"
            value={options.privacy}
            onChange={(e) => setOptions((o) => ({ ...o, privacy: e.target.value }))}
          >
            <option value="standard">Privacy standard</option>
            <option value="redact">Privacy redact</option>
            <option value="strict">Privacy strict</option>
          </select>
          {!hosted && <MoreOptions />}
        </>
      )}
      <button type="button" className="ag-btn ag-btn--primary" onClick={startScan} disabled={scanning || !config}>
        {scanning ? 'Scanning' : 'Run scan'}
      </button>
      <div className="ag-cmd-end">
        <span className="ag-status" role="status">{status}</span>
        <ThemeSwitch />
      </div>
    </header>
  )
}
