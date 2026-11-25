import { useEffect, useRef, useState } from 'react'
import { useScan } from '../../context/ScanContext'
import { useToast } from '../../context/ToastContext'
import { exportResult } from '../../lib/api'

const FORMATS = [
  { id: 'html', label: 'HTML report', note: 'Self-contained page to share or archive' },
  { id: 'sarif', label: 'SARIF', note: 'For GitHub code scanning and IDEs' },
  { id: 'json', label: 'JSON', note: 'The full scan result' },
]

/** Download the current result in a report format. Rendered by the server from the result in the page. */
export default function ExportMenu() {
  const { scanResult, scanning, token } = useScan()
  const { toast } = useToast()
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState('')
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

  if (!scanResult || scanning) return null

  const run = async (fmt) => {
    setBusy(fmt.id)
    try {
      const name = await exportResult(fmt.id, scanResult, token)
      toast(`Saved ${name}`)
      setOpen(false)
    } catch (err) {
      toast(err?.message || 'The export failed.', 'err')
    } finally {
      setBusy('')
    }
  }

  return (
    <div className="ag-opts" ref={ref}>
      <button type="button" className="ag-btn" aria-expanded={open} aria-controls="ag-export" onClick={() => setOpen((o) => !o)}>
        Export
      </button>
      {open && (
        <div className="ag-opts-panel ag-export" id="ag-export" role="group" aria-label="Export the scan result">
          {FORMATS.map((f) => (
            <button key={f.id} type="button" className="ag-export-item" disabled={!!busy} onClick={() => run(f)}>
              <span>{f.label}</span>
              <span className="ag-muted">{busy === f.id ? 'Preparing' : f.note}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
