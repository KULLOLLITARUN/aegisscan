import { useEffect, useRef } from 'react'
import Evidence from '../inspector/Evidence'

const FOCUSABLE = 'button:not([disabled]), [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'

/** Right-docked modal showing one finding (same Evidence view as the inspector). Esc closes; focus is trapped and restored. */
export default function FindingDialog({ finding, result, onClose }) {
  const box = useRef(null)
  const closeBtn = useRef(null)

  useEffect(() => {
    const opener = document.activeElement
    closeBtn.current?.focus()
    const onKey = (e) => {
      if (e.key === 'Escape') {
        onClose()
        return
      }
      if (e.key !== 'Tab' || !box.current) return
      const items = [...box.current.querySelectorAll(FOCUSABLE)]
      if (!items.length) return
      const first = items[0]
      const last = items[items.length - 1]
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus() }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus() }
    }
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('keydown', onKey)
      if (opener && opener.focus) opener.focus()
    }
  }, [onClose])

  return (
    <>
      <div className="ag-scrim" onClick={onClose} />
      <div ref={box} className="ag-dialog" role="dialog" aria-modal="true" aria-label={`Finding: ${finding.issue_type}`}>
        <div className="ag-dialog-head">
          <button ref={closeBtn} type="button" className="ag-btn ag-btn--sm" onClick={onClose}>Close</button>
        </div>
        <Evidence finding={finding} result={result} scanning={false} />
      </div>
    </>
  )
}
