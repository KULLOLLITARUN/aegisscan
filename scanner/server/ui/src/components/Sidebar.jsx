import { NavLink } from 'react-router-dom'
import { useScan } from '../context/ScanContext'
import { normSeverity } from '../constants'

const NAV = [
  { to: '/dashboard', label: 'Dashboard' },
  { to: '/findings',  label: 'Findings' },
  { to: '/files',     label: 'Files' },
  { to: '/scans',     label: 'Scans' },
  { to: '/logs',      label: 'Logs', badgeText: 'live' },
]

export default function Sidebar() {
  const { scanResult, logs } = useScan()
  const findings = scanResult?.findings ?? []
  const critical = findings.filter(f => normSeverity(f.severity) === 'critical').length
  const high = findings.filter(f => normSeverity(f.severity) === 'high').length
  const criticalHigh = critical + high

  return (
    <aside style={{
      position: 'fixed', top: 0, left: 0, bottom: 0,
      width: 'var(--sidebar-w)',
      background: 'var(--bg-surface)',
      borderRight: '1px solid var(--border)',
      display: 'flex', flexDirection: 'column',
      zIndex: 50,
    }}>
      {/* Brand */}
      <div style={{ padding: '20px 20px 17px', borderBottom: '1px solid var(--border)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 11 }}>
          <div className="facet-tr" style={{
            width: 32, height: 32,
            background: 'var(--accent-gradient)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 15, fontWeight: 700, color: '#fff', flexShrink: 0,
          }}>
            <span className="display" style={{ color: 'inherit' }}>Æ</span>
          </div>
          <div>
            <div className="display" style={{ fontWeight: 600, fontSize: 15.5, letterSpacing: '0.005em', color: 'var(--text-primary)' }}>AegisScan</div>
            <div style={{ fontSize: 10.5, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.03em', marginTop: 1 }}>Command Deck</div>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav style={{ padding: '16px 12px', flex: 1, overflowY: 'auto' }}>
        <div style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--text-muted)', padding: '0 10px 6px' }}>
          Workspace
        </div>
        {NAV.map(({ to, label, badgeText }) => (
          <NavLink key={to} to={to} style={({ isActive }) => ({
            display: 'flex', alignItems: 'center', gap: 11,
            padding: '8px 10px', borderRadius: 3, marginBottom: 1,
            fontSize: 13, fontWeight: isActive ? 600 : 500, textDecoration: 'none',
            color: isActive ? 'var(--text-primary)' : 'var(--text-dim)',
            background: isActive ? 'var(--accent-dim)' : 'transparent',
            borderLeft: isActive ? '2px solid var(--accent)' : '2px solid transparent',
          })}>
            {({ isActive }) => (
              <>
                <span className="diamond" style={{ background: isActive ? 'var(--accent)' : 'var(--text-muted)' }} />
                <span style={{ flex: 1 }}>{label}</span>
                {label === 'Findings' && criticalHigh > 0 && (
                  <span style={{
                    background: 'var(--critical-bg)', color: 'var(--critical)',
                    fontSize: 10, fontWeight: 700, padding: '1px 6px', borderRadius: 9,
                  }}>{criticalHigh}</span>
                )}
                {badgeText && logs.length > 0 && (
                  <span style={{
                    background: 'var(--accent-dim)', color: 'var(--accent)',
                    fontSize: 10, fontWeight: 700, padding: '1px 6px', borderRadius: 9,
                  }}>{badgeText}</span>
                )}
              </>
            )}
          </NavLink>
        ))}
      </nav>

      {/* Footer */}
      <div style={{ padding: '14px 20px 18px', borderTop: '1px solid var(--border)', fontSize: 10.5, color: 'var(--text-muted)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span className="mono">v1.0.0</span>
        <span style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
          <span className="diamond" style={{ background: 'var(--low)' }} />
          <span>Server online</span>
        </span>
      </div>
    </aside>
  )
}
