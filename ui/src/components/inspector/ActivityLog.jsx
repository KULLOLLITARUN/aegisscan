import { useEffect, useRef } from 'react'

const clock = (d) => (d instanceof Date ? d.toLocaleTimeString('en-GB', { hour12: false }) : '')

/** The SSE log stream: progress lines plus backend log records, in arrival order. */
export default function ActivityLog({ logs, scanning, nowSeconds }) {
  const ref = useRef(null)
  useEffect(() => {
    if (scanning && ref.current) ref.current.scrollTop = ref.current.scrollHeight
  }, [logs, scanning])

  if (!logs.length) {
    return (
      <div className="ag-state">
        <h3>No activity yet</h3>
        <p>Run a scan to stream pipeline and provider events here as they happen.</p>
      </div>
    )
  }

  // Highlight the entry that was current at the replay time (relative to the first event).
  const t0 = logs[0].ts instanceof Date ? logs[0].ts.getTime() : 0
  let nowIdx = -1
  if (!scanning && nowSeconds != null) {
    logs.forEach((l, i) => { if ((l.ts.getTime() - t0) / 1000 <= nowSeconds) nowIdx = i })
  }

  return (
    <div ref={ref} className="ag-log" role="log" aria-live="off" aria-label="Scan activity">
      {logs.map((l, i) => (
        <div key={l.id} className={i === nowIdx ? 'now' : ''} aria-current={i === nowIdx ? 'true' : undefined}>
          <span className="ts">{clock(l.ts)}</span>
          <span className={l.level}>{l.level}</span>
          <span>{l.message}</span>
        </div>
      ))}
    </div>
  )
}
