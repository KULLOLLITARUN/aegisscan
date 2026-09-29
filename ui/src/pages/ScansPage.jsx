import { useEffect } from 'react'
import { useScan } from '../context/ScanContext'

function scoreVar(score) {
  if (score == null) return '--text-muted'
  if (score >= 90) return '--low'
  if (score >= 75) return '--info'
  if (score >= 55) return '--medium'
  if (score >= 30) return '--high'
  return '--critical'
}

export default function ScansPage() {
  const { history, fetchHistory } = useScan()

  useEffect(() => { fetchHistory() }, [fetchHistory])

  const fmt = (ts) => ts ? new Date(ts).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' }) : '—'

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div>
        <h1 className="display" style={{ fontSize: 21, fontWeight: 600, letterSpacing: '0.005em' }}>Scan History</h1>
        <p style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 3 }}>
          {history.length} scans recorded in SQLite database
        </p>
      </div>

      <div className="card">
        {!history.length ? (
          <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)', fontSize: 13 }}>
            No scans recorded yet. Run a scan to see history.
          </div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Scan ID</th>
                <th>Date</th>
                <th>Status</th>
                <th>Files</th>
                <th>Findings</th>
                <th>Security Score</th>
                <th>Opt. Score</th>
                <th>Duration</th>
              </tr>
            </thead>
            <tbody>
              {history.map((h) => (
                <tr key={h.scan_id} style={{ cursor: 'default' }}>
                  <td><span className="mono" style={{ color: 'var(--accent)', fontSize: 11 }}>{h.scan_id?.substring(0, 13)}</span></td>
                  <td style={{ color: 'var(--text-muted)', fontSize: 11 }}>{fmt(h.timestamp)}</td>
                  <td>
                    <span className="sev-badge" data-sev="low" style={{ textTransform: 'none' }}>Completed</span>
                  </td>
                  <td className="mono" style={{ fontSize: 11 }}>{h.files_analyzed ?? '—'}</td>
                  <td style={{ fontWeight: 600 }}>{h.total_findings}</td>
                  <td>
                    <span className="display" style={{ fontWeight: 600, color: `var(${scoreVar(h.security_score)})` }}>
                      {h.security_score != null ? Math.round(h.security_score) : '—'}
                    </span>
                    <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>/100</span>
                  </td>
                  <td>
                    <span className="display" style={{ fontWeight: 600, color: `var(${scoreVar(h.optimization_score)})` }}>
                      {h.optimization_score != null ? Math.round(h.optimization_score) : '—'}
                    </span>
                    <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>/100</span>
                  </td>
                  <td className="mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                    {h.duration_seconds != null ? `${h.duration_seconds.toFixed(1)}s` : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
