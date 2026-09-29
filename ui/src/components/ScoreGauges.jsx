import { useScan } from '../context/ScanContext'
import { SEVERITY_LABEL, normSeverity } from '../constants'

// Mirrors scanner/scoring/calculator.py's score_label() bands exactly, mapped
// to theme tokens instead of fixed hex so it adapts across light/dark.
function scoreBand(score) {
  if (score == null) return { label: 'Pending', var: '--text-muted' }
  if (score >= 90) return { label: 'Excellent', var: '--low' }
  if (score >= 75) return { label: 'Good', var: '--info' }
  if (score >= 55) return { label: 'Fair', var: '--medium' }
  if (score >= 30) return { label: 'Poor', var: '--high' }
  return { label: 'Critical', var: '--critical' }
}

function verdictText(scanResult) {
  const findings = scanResult?.findings ?? []
  if (!scanResult) return "Run a scan to see your workspace's security posture."
  const critical = findings.filter(f => normSeverity(f.severity) === 'critical')
  const high = findings.filter(f => normSeverity(f.severity) === 'high')
  const urgent = [...critical, ...high]
  if (!urgent.length) {
    return findings.length
      ? `No ${SEVERITY_LABEL.critical.toLowerCase()} or ${SEVERITY_LABEL.high.toLowerCase()}-severity findings out of ${findings.length} total - remaining issues are lower priority.`
      : 'No findings on the last scan.'
  }
  const topTypes = [...new Set(urgent.map(f => f.issue_type).filter(Boolean))].slice(0, 2)
  const urgentSummary = [
    critical.length ? `${critical.length} ${SEVERITY_LABEL.critical.toLowerCase()}` : '',
    high.length ? `${high.length} ${SEVERITY_LABEL.high.toLowerCase()}` : '',
  ].filter(Boolean).join(' and ')
  const noun = urgent.length === 1 ? 'finding requires' : 'findings require'
  const lastRun = (scanResult.llm_provider ?? scanResult.llm_provider_used) ? 'AI reasoning pass included.' : 'Static analysis only - no LLM pass on this run.'
  const topTypesSuffix = topTypes.length ? ` - ${topTypes.join(', ')}` : ''
  return `${urgentSummary} ${noun} attention${topTypesSuffix}. ${lastRun}`
}

function HeroGauge({ score }) {
  const cx = 104, cy = 104, r = 80
  const circ = Math.PI * r
  const pct = score != null ? Math.max(0, Math.min(score, 100)) / 100 : 0
  const filled = circ * pct
  const band = scoreBand(score)

  const theta = (180 - pct * 180) * (Math.PI / 180)
  const px = cx + r * Math.cos(theta)
  const py = cy - r * Math.sin(theta)

  const ticks = [180, 135, 90, 45, 0].map((deg) => {
    const t = deg * (Math.PI / 180)
    return {
      deg,
      x1: cx + 72 * Math.cos(t), y1: cy - 72 * Math.sin(t),
      x2: cx + 82 * Math.cos(t), y2: cy - 82 * Math.sin(t),
    }
  })

  return (
    <div style={{ flexShrink: 0, position: 'relative', width: 208 }}>
      <svg viewBox="0 0 208 128" width="208" height="128">
        <g stroke="var(--border)" strokeWidth="2">
          {ticks.map((t) => <line key={t.deg} x1={t.x1} y1={t.y1} x2={t.x2} y2={t.y2} />)}
        </g>
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="var(--bg-card-3)" strokeWidth="11"
          strokeDasharray={`${circ} ${circ}`} strokeLinecap="round" transform={`rotate(-180 ${cx} ${cy})`} />
        <circle cx={cx} cy={cy} r={r} fill="none" stroke={`var(${band.var})`} strokeWidth="11"
          strokeDasharray={`${filled} ${circ - filled}`} strokeLinecap="round"
          transform={`rotate(-180 ${cx} ${cy})`} style={{ transition: 'stroke-dasharray 0.8s ease' }} />
        {score != null && (
          <circle cx={px} cy={py} r="4.5" fill={`var(${band.var})`} stroke="var(--bg-card)" strokeWidth="2" />
        )}
      </svg>
      <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'flex-end', paddingBottom: 8 }}>
        <div className="display" style={{ fontSize: 44, fontWeight: 700, lineHeight: 1, color: `var(${band.var})` }}>
          {score != null ? Math.round(score) : '—'}
        </div>
        <div style={{ fontSize: 11.5, fontWeight: 700, letterSpacing: '0.06em', textTransform: 'uppercase', color: `var(${band.var})`, marginTop: 2 }}>
          {band.label}
        </div>
      </div>
    </div>
  )
}

function OptRing({ score }) {
  const r = 16
  const circ = 2 * Math.PI * r
  const pct = score != null ? Math.max(0, Math.min(score, 100)) / 100 : 0
  const band = scoreBand(score)
  return (
    <svg width="40" height="40" viewBox="0 0 40 40">
      <circle cx="20" cy="20" r={r} fill="none" stroke="var(--bg-card-3)" strokeWidth="4" />
      <circle cx="20" cy="20" r={r} fill="none" stroke={`var(${band.var})`} strokeWidth="4"
        strokeDasharray={`${circ * pct} ${circ}`} strokeLinecap="round"
        transform="rotate(-90 20 20)" style={{ transition: 'stroke-dasharray 0.8s ease' }} />
    </svg>
  )
}

export default function ScoreGauges() {
  const { scanResult, scanning, progress } = useScan()
  const secScore = scanResult?.security_score
  const optScore = scanResult?.optimization_score
  const optBand = scoreBand(optScore)

  return (
    <div className="card facet-tr" style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 4 }}>
        <div>
          <div className="display" style={{ fontSize: 13.5, fontWeight: 600, letterSpacing: '0.01em' }}>Security Score</div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>Weighted across severity &amp; confidence</div>
        </div>
      </div>

      {scanning && (
        <div style={{ margin: '10px 0' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, marginBottom: 6 }}>
            <span style={{ color: 'var(--text-muted)' }}>{progress.phase}</span>
            <span style={{ color: 'var(--accent)', fontWeight: 700 }}>{progress.pct}%</span>
          </div>
          <div style={{ width: '100%', height: 5, background: 'var(--bg-card-3)', borderRadius: 3, overflow: 'hidden' }}>
            <div className="progress-bar-fill" style={{ width: `${progress.pct}%` }} />
          </div>
        </div>
      )}

      <div style={{ display: 'flex', alignItems: 'center', gap: 26, flex: 1, marginTop: 8 }}>
        <HeroGauge score={secScore} />
        <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div style={{ fontSize: 13, color: 'var(--text-dim)', lineHeight: 1.65 }}>
            {verdictText(scanResult)}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, paddingTop: 12, borderTop: '1px solid var(--border)' }}>
            <OptRing score={optScore} />
            <div>
              <div style={{ fontSize: 10.5, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Optimization Score</div>
              <div className="display" style={{ fontSize: 16, fontWeight: 600, color: `var(${optBand.var})` }}>
                {optScore != null ? Math.round(optScore) : '—'}
                <span style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 500, marginLeft: 6 }}>— {optBand.label}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
