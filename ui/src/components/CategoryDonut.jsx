import { useScan } from '../context/ScanContext'
import { CATEGORY_LABEL, normCategory } from '../constants'

const R = 15.9
const CIRC = 2 * Math.PI * R

export default function CategoryDonut() {
  const { scanResult } = useScan()
  const findings = scanResult?.findings ?? []

  const counts = {}
  findings.forEach(f => {
    const cat = normCategory(f.category)
    counts[cat] = (counts[cat] || 0) + 1
  })

  const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1])
  const total = findings.length

  let cumulative = 0
  const segments = sorted.map(([cat, value]) => {
    const len = (value / total) * CIRC
    const seg = { cat, value, dash: len, offset: CIRC / 4 - cumulative }
    cumulative += len
    return seg
  })

  return (
    <div className="card" style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <div>
          <div className="display" style={{ fontSize: 13.5, fontWeight: 600, letterSpacing: '0.01em' }}>Findings by Category</div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>Vulnerability domain breakdown</div>
        </div>
      </div>

      {!sorted.length ? (
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: 120, color: 'var(--text-muted)', fontSize: 12, textAlign: 'center' }}>
          Run a scan to see category metrics
        </div>
      ) : (
        <div style={{ display: 'flex', alignItems: 'center', gap: 20, flex: 1 }}>
          <svg width="104" height="104" viewBox="0 0 42 42" style={{ flexShrink: 0 }}>
            <circle cx="21" cy="21" r={R} fill="none" stroke="var(--bg-card-3)" strokeWidth="6" />
            {segments.map(s => (
              <circle key={s.cat} cx="21" cy="21" r={R} fill="none" stroke={`var(--cat-${s.cat})`} strokeWidth="6"
                strokeDasharray={`${s.dash} ${CIRC - s.dash}`} strokeDashoffset={s.offset} strokeLinecap="round" />
            ))}
            <text x="21" y="19.5" textAnchor="middle" fontSize="7.5" fontWeight="700" fill="var(--text-primary)" fontFamily="'Chakra Petch', sans-serif">{total}</text>
            <text x="21" y="26" textAnchor="middle" fontSize="3.2" fill="var(--text-muted)" fontFamily="'IBM Plex Sans', sans-serif" fontWeight="500">total</text>
          </svg>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10, flex: 1, minWidth: 0 }}>
            {sorted.map(([cat, value]) => {
              const pct = ((value / total) * 100).toFixed(0)
              return (
                <div key={cat} style={{ display: 'flex', alignItems: 'center', gap: 9, fontSize: 12 }}>
                  <span className="diamond" style={{ background: `var(--cat-${cat})` }} />
                  <span style={{ color: 'var(--text-dim)', fontWeight: 500, flex: 1 }}>{CATEGORY_LABEL[cat]}</span>
                  <span className="mono" style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{value}</span>
                  <span style={{ color: 'var(--text-muted)', fontSize: 10.5, width: 32, textAlign: 'right' }}>{pct}%</span>
                </div>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}
