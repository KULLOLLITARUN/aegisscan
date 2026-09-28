import { useScan } from '../context/ScanContext'
import LiveActivity from '../components/LiveActivity'

export default function LogsPage() {
  const { logs, scanning } = useScan()
  const counts = logs.reduce((acc, l) => { acc[l.level] = (acc[l.level] || 0) + 1; return acc }, {})

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div>
        <h1 style={{ fontSize: 22, fontWeight: 700, letterSpacing: '-0.01em' }} className="display">Live Log</h1>
        <p style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 3 }}>
          {logs.length ? `${logs.length} events this session` : 'No events yet'}
          {counts.warn ? ` · ${counts.warn} warning${counts.warn === 1 ? '' : 's'}` : ''}
          {counts.err ? ` · ${counts.err} error${counts.err === 1 ? '' : 's'}` : ''}
          {scanning ? ' · scan in progress' : ''}
        </p>
      </div>

      <div className="card" style={{ display: 'flex', flexDirection: 'column', flex: 1 }}>
        <LiveActivity maxHeight={560} showFooter={false} />
      </div>
    </div>
  )
}
