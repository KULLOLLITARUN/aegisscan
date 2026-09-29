import { useScan } from '../context/ScanContext'

function Wrap({ embedded, children }) {
  return embedded ? <>{children}</> : <div className="card">{children}</div>
}

export default function ScanSummary({ embedded = false }) {
  const { scanResult, options } = useScan()

  if (!scanResult) {
    return (
      <Wrap embedded={embedded}>
        {!embedded && <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 12 }}>Scan Summary</div>}
        <div style={{ fontSize: 12, color: 'var(--text-muted)', textAlign: 'center', padding: '20px 0' }}>
          No scan data yet
        </div>
      </Wrap>
    )
  }

  // scanResult.static_tools_run is populated by main.py's run() — see scanner/models/scan.py.
  const rows = [
    ['Files Scanned',    scanResult.files_analyzed?.toLocaleString() ?? '—'],
    ['Files Discovered', scanResult.files_discovered?.toLocaleString() ?? '—'],
    ['Total Findings',   scanResult.total_findings?.toLocaleString() ?? scanResult.findings?.length ?? '—'],
    ['Scan Duration',    scanResult.scan_duration_seconds ? `${scanResult.scan_duration_seconds.toFixed(2)}s` : '—'],
    ['Static Tools',     (scanResult.static_tools_run?.length ? scanResult.static_tools_run : ['bandit']).join(', ')],
    ['LLM Provider',     scanResult.llm_provider ?? 'static-only'],
    // The backend doesn't echo privacy mode back on ScanResult — this reflects
    // what was requested for the last scan, from the client's own options.
    ['Privacy Mode',     options?.privacy ?? 'standard'],
    ['Languages',        Object.keys(scanResult.language_breakdown ?? {}).join(', ') || '—'],
  ]

  return (
    <Wrap embedded={embedded}>
      {!embedded && <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 14 }}>Scan Summary</div>}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
        {rows.map(([label, value]) => (
          <div key={label} style={{
            display: 'flex', justifyContent: 'space-between', alignItems: 'center',
            padding: '7px 0', borderBottom: '1px solid var(--border)',
          }}>
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{label}</span>
            <span className="mono" style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-primary)', textAlign: 'right' }}>
              {value}
            </span>
          </div>
        ))}
      </div>
    </Wrap>
  )
}
