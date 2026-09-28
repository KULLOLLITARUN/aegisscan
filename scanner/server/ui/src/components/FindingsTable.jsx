import { useScan } from '../context/ScanContext'
import FindingDrawer from './FindingDrawer'
import { useState } from 'react'
import { normSeverity, normCategory } from '../constants'

export default function FindingsTable({ findings: propFindings, limit, showTitle = true }) {
  const { scanResult } = useScan()
  const [selected, setSelected] = useState(null)
  const allFindings = propFindings ?? scanResult?.findings ?? []
  const findings = limit ? allFindings.slice(0, limit) : allFindings

  return (
    <>
      {showTitle && (
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
          <div className="display" style={{ fontSize: 13.5, fontWeight: 600 }}>
            {limit ? `Top ${limit} Critical / High Findings` : `Findings (${findings.length})`}
          </div>
          {limit && allFindings.length > limit && (
            <a href="/findings" style={{ fontSize: 12, color: 'var(--accent)', fontWeight: 600 }}>
              View All Findings →
            </a>
          )}
        </div>
      )}

      {!findings.length ? (
        <div style={{ fontSize: 12, color: 'var(--text-muted)', padding: '20px 0', textAlign: 'center' }}>
          No findings to display
        </div>
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Title</th>
              <th>Category</th>
              <th>File</th>
              <th>Line</th>
              <th>Severity</th>
              <th>Confidence</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f, i) => {
              const fname = f.file_path?.split(/[/\\]/).pop() ?? '—'
              return (
                <tr key={f.id || f.finding_id || i} onClick={() => setSelected(f)}>
                  <td>
                    <span className="mono" style={{ color: 'var(--accent)', fontSize: 11 }}>
                      F-{String(i).padStart(6, '0')}
                    </span>
                  </td>
                  <td style={{ fontWeight: 500, maxWidth: 200 }}>
                    <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', display: 'block' }}>
                      {f.issue_type}
                    </span>
                  </td>
                  <td><span className="cat-tag" data-cat={normCategory(f.category)}>{f.category || '—'}</span></td>
                  <td>
                    <span className="mono" style={{ fontSize: 11, color: 'var(--text-dim)' }}>{fname}</span>
                  </td>
                  <td className="mono" style={{ fontSize: 11 }}>{f.line_start}</td>
                  <td><span className="sev-badge" data-sev={normSeverity(f.severity)}>{f.severity}</span></td>
                  <td>
                    <div className="conf-meter">
                      <div className="track"><div className="fill" style={{ width: `${(f.confidence || 0) * 100}%` }} /></div>
                      <span className="pct mono">{((f.confidence || 0) * 100).toFixed(0)}%</span>
                    </div>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      )}

      {selected && <FindingDrawer finding={selected} onClose={() => setSelected(null)} />}
    </>
  )
}
