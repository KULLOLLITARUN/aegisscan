import { useState } from 'react'
import StatCards from '../components/StatCards'
import ScoreGauges from '../components/ScoreGauges'
import CategoryDonut from '../components/CategoryDonut'
import ScanSummary from '../components/ScanSummary'
import FindingsTable from '../components/FindingsTable'
import LiveActivity from '../components/LiveActivity'
import { useScan } from '../context/ScanContext'
import { normSeverity } from '../constants'

function ActivityPanel() {
  const [tab, setTab] = useState('Activity')
  return (
    <div className="card" style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
        <div>
          <div className="display" style={{ fontSize: 13.5, fontWeight: 600, letterSpacing: '0.01em' }}>Live Activity</div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>Pipeline &amp; LLM provider events</div>
        </div>
        <div style={{ display: 'flex', gap: 2, background: 'var(--bg-card-3)', padding: 2, borderRadius: 3 }}>
          {['Activity', 'Summary'].map(t => (
            <button
              type="button"
              key={t}
              onClick={() => setTab(t)}
              className={tab === t ? 'display' : ''}
              style={{
                fontSize: 10.5, fontWeight: 600, padding: '3px 10px', borderRadius: 2,
                border: 'none', cursor: 'pointer',
                color: tab === t ? 'var(--text-primary)' : 'var(--text-muted)',
                background: tab === t ? 'var(--bg-card)' : 'transparent',
              }}
            >{t}</button>
          ))}
        </div>
      </div>
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0 }}>
        {tab === 'Activity' ? <LiveActivity /> : <ScanSummary embedded />}
      </div>
    </div>
  )
}

function ScoreClampBanner({ scanResult }) {
  const findings = scanResult?.findings ?? []
  if (!scanResult || scanResult.security_score !== 0 || findings.length === 0) return null

  const critical = findings.filter(f => normSeverity(f.severity) === 'critical').length
  const high = findings.filter(f => normSeverity(f.severity) === 'high').length
  const medium = findings.filter(f => normSeverity(f.severity) === 'medium').length
  const parts = [
    critical ? `${critical} critical` : '',
    high ? `${high} high` : '',
    medium ? `${medium} medium` : '',
  ].filter(Boolean).join(', ')

  return (
    <div style={{
      display: 'flex',
      alignItems: 'center',
      gap: 12,
      padding: '12px 15px',
      border: '1px solid var(--critical)',
      borderLeft: '4px solid var(--critical)',
      background: 'var(--critical-bg)',
      color: 'var(--text-primary)',
      boxShadow: 'var(--panel-shadow)',
    }}>
      <span className="diamond" style={{ background: 'var(--critical)', width: 8, height: 8 }} />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 12.5, fontWeight: 700 }}>Security score is clamped at 0/100</div>
        <div style={{ fontSize: 11.5, color: 'var(--text-dim)', marginTop: 2 }}>
          The weighted penalty from severe findings exceeds 100{parts ? ` (${parts})` : ''}. Review the critical and high findings first.
        </div>
      </div>
    </div>
  )
}

export default function DashboardPage() {
  const { scanResult, scanning, startScan } = useScan()

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: 8, gap: 20 }}>
        <div>
          <div style={{ fontSize: 10.5, fontWeight: 700, letterSpacing: '0.14em', textTransform: 'uppercase', color: 'var(--accent)', marginBottom: 5 }}>
            Executive Overview
          </div>
          <h1 className="display" style={{ fontSize: 24, fontWeight: 600, letterSpacing: '0.005em' }}>Workspace Security Posture</h1>
        </div>
        {scanResult ? (
          <div style={{ textAlign: 'right', fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.7 }}>
            Last scan <strong className="mono" style={{ color: 'var(--text-dim)', fontWeight: 600 }}>{new Date(scanResult.scan_timestamp).toLocaleString()}</strong><br />
            Duration <strong style={{ color: 'var(--text-dim)', fontWeight: 600 }}>{scanResult.scan_duration_seconds?.toFixed(2)}s</strong> · {scanResult.files_analyzed} of {scanResult.files_discovered} files analyzed
          </div>
        ) : !scanning && (
          <button type="button" className="btn btn-primary facet-tr" onClick={startScan}>
            Launch First Workspace Scan
          </button>
        )}
      </div>

      <ScoreClampBanner scanResult={scanResult} />

      {/* Hero row: score + live activity */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.15fr 0.85fr', gap: 14 }}>
        <ScoreGauges />
        <ActivityPanel />
      </div>

      {/* Severity strip */}
      <StatCards />

      {/* Category + Findings */}
      <div style={{ display: 'grid', gridTemplateColumns: '0.8fr 1.4fr', gap: 14 }}>
        <CategoryDonut />
        <div className="card">
          <FindingsTable limit={8} />
        </div>
      </div>
    </div>
  )
}
