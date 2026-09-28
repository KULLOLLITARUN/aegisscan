import { useState } from 'react'
import { useScan } from '../context/ScanContext'
import FindingDrawer from '../components/FindingDrawer'
import { SEVERITIES, normSeverity, normCategory } from '../constants'

function topSeverity(fs) {
  for (const s of SEVERITIES) if (fs.some(f => normSeverity(f.severity) === s)) return s
  return 'info'
}

export default function FilesPage() {
  const { scanResult } = useScan()
  const [selectedFile, setSelectedFile] = useState(null)
  const [selectedFinding, setSelectedFinding] = useState(null)
  const findings = scanResult?.findings ?? []

  const fileMap = {}
  findings.forEach(f => {
    const key = f.file_path || 'unknown'
    if (!fileMap[key]) fileMap[key] = []
    fileMap[key].push(f)
  })

  const files = Object.entries(fileMap).sort((a, b) => b[1].length - a[1].length)
  const selected = selectedFile ? fileMap[selectedFile] ?? [] : []

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div>
        <h1 className="display" style={{ fontSize: 21, fontWeight: 600, letterSpacing: '0.005em' }}>Files</h1>
        <p style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 3 }}>
          {files.length} files with findings
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '280px 1fr', gap: 16 }}>
        {/* File tree */}
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          <div style={{ padding: '12px 14px', borderBottom: '1px solid var(--border)', fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            Project Files
          </div>
          <div style={{ overflow: 'auto', maxHeight: 600 }}>
            {!files.length ? (
              <div style={{ padding: '20px 14px', fontSize: 12, color: 'var(--text-muted)' }}>No scan data</div>
            ) : files.map(([path, fs]) => {
              const fname = path.split(/[/\\]/).pop()
              const sev = topSeverity(fs)
              const isSelected = selectedFile === path
              return (
                <button key={path} type="button" onClick={() => setSelectedFile(path)} style={{
                  width: '100%', textAlign: 'left', border: 'none',
                  padding: '9px 14px', cursor: 'pointer', fontSize: 12,
                  display: 'flex', alignItems: 'center', gap: 9,
                  background: isSelected ? 'var(--accent-dim)' : 'transparent',
                  borderLeft: isSelected ? '2px solid var(--accent)' : '2px solid transparent',
                  color: 'inherit', fontFamily: 'inherit',
                }}>
                  <span className="diamond" style={{ background: `var(--${sev})`, flexShrink: 0 }} />
                  <span className="mono" style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: isSelected ? 'var(--accent)' : 'var(--text-primary)' }}>
                    {fname}
                  </span>
                  <span className="sev-badge" data-sev={sev} style={{ padding: '1px 7px' }}>{fs.length}</span>
                </button>
              )
            })}
          </div>
        </div>

        {/* Right panel */}
        <div className="card">
          {!selectedFile ? (
            <div style={{ textAlign: 'center', padding: '60px 24px', color: 'var(--text-muted)', fontSize: 13 }}>
              ← Select a file from the tree
            </div>
          ) : (
            <>
              <div style={{ marginBottom: 16 }}>
                <div className="mono" style={{ fontSize: 12, color: 'var(--accent)', marginBottom: 4 }}>{selectedFile}</div>
                <div style={{ display: 'flex', gap: 16, fontSize: 11, color: 'var(--text-muted)' }}>
                  <span>Findings: <strong style={{ color: 'var(--text-primary)' }}>{selected.length}</strong></span>
                  <span>Language: <strong style={{ color: 'var(--text-primary)' }}>{selected[0]?.language || 'Python'}</strong></span>
                </div>
              </div>

              <table className="data-table">
                <thead>
                  <tr><th>Line</th><th>Issue</th><th>Category</th><th>Severity</th><th>Confidence</th></tr>
                </thead>
                <tbody>
                  {selected.map((f, i) => (
                    <tr key={f.id || f.finding_id || i} onClick={() => setSelectedFinding(f)}>
                      <td className="mono" style={{ fontSize: 11, color: 'var(--accent)' }}>{f.line_start}</td>
                      <td style={{ fontWeight: 500 }}>{f.issue_type}</td>
                      <td><span className="cat-tag" data-cat={normCategory(f.category)}>{f.category}</span></td>
                      <td><span className="sev-badge" data-sev={normSeverity(f.severity)}>{f.severity}</span></td>
                      <td className="mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>{((f.confidence || 0) * 100).toFixed(0)}%</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
        </div>
      </div>

      {selectedFinding && <FindingDrawer finding={selectedFinding} onClose={() => setSelectedFinding(null)} />}
    </div>
  )
}
