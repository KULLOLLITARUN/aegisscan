import { useEffect, useRef } from 'react'
import { Link } from 'react-router-dom'
import { useScan } from '../context/ScanContext'

const LEVEL_CLASS = { ok: 'ev-ok', warn: 'ev-warn', info: 'ev-info', err: 'ev-err' }

function fmtTime(d) {
  return d instanceof Date
    ? d.toLocaleTimeString('en-GB', { hour12: false })
    : ''
}

/**
 * Real-time pipeline + LLM provider activity feed.
 * Sourced entirely from ScanContext.logs — real SSE progress events plus
 * Python log records forwarded live by scanner/server/app.py's _SSELogHandler
 * (provider rate limits, failovers, static-tool errors). Nothing here is
 * simulated; if it's quiet, nothing has happened yet.
 */
export default function LiveActivity({ maxHeight = 196, showFooter = true }) {
  const { logs, scanning } = useScan()
  const scrollRef = useRef(null)

  useEffect(() => {
    const el = scrollRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [logs])

  return (
    <div style={{ display: 'flex', flexDirection: 'column', flex: 1, minHeight: 0 }}>
      <div ref={scrollRef} className="console mono" style={{ maxHeight, flex: showFooter ? undefined : 1 }}>
        {!logs.length ? (
          <div style={{ color: 'var(--console-ts)' }}>No activity yet — run a scan to see live pipeline &amp; LLM events.</div>
        ) : (
          logs.map((l) => (
            <div key={l.id}>
              <span className="ts">{fmtTime(l.ts)}</span>
              <span className={LEVEL_CLASS[l.level] || 'ev-info'}></span>
              <span className="msg">{l.message}</span>
            </div>
          ))
        )}
      </div>
      {showFooter && (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: 11, fontSize: 10.5, color: 'var(--text-muted)' }}>
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, color: scanning ? 'var(--high)' : 'var(--low)', fontWeight: 600 }}>
            <span className="live-dot" style={{ background: scanning ? 'var(--high)' : 'var(--low)' }} />
            {scanning ? 'scan in progress' : 'watching for next scan'}
          </span>
          <Link to="/logs" style={{ color: 'var(--accent)', fontWeight: 600 }}>View full log →</Link>
        </div>
      )}
    </div>
  )
}
