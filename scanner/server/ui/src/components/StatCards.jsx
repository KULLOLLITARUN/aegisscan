import { useScan } from '../context/ScanContext'
import { SEVERITIES, SEVERITY_LABEL, normSeverity } from '../constants'

function StatCard({ level, count }) {
  const varName = `--${level}`
  return (
    <div className="stat-card" style={{ flex: 1, minWidth: 150, borderColor: count > 0 ? `var(${varName})` : 'var(--border)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 11 }}>
        <span className="diamond" style={{ background: `var(${varName})`, opacity: count > 0 ? 1 : 0.4 }} />
        <span style={{ fontSize: 10.5, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-dim)' }}>
          {SEVERITY_LABEL[level]}
        </span>
      </div>

      <div style={{ display: 'flex', alignItems: 'baseline', gap: 9 }}>
        <div className="display" style={{ fontSize: 28, fontWeight: 600, lineHeight: 1, color: count > 0 ? 'var(--text-primary)' : 'var(--text-muted)' }}>
          {count}
        </div>
        <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
          {count === 1 ? 'finding' : 'findings'}
        </div>
      </div>
    </div>
  )
}

export default function StatCards() {
  const { scanResult } = useScan()
  const findings = scanResult?.findings ?? []

  const count = (sev) => findings.filter(f => normSeverity(f.severity) === sev).length

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 12 }}>
      {SEVERITIES.map(level => (
        <StatCard key={level} level={level} count={count(level)} />
      ))}
    </div>
  )
}
