import { NavLink } from 'react-router-dom'
import { useScan } from '../../context/ScanContext'
import { normSeverity } from '../../constants'

const ITEMS = [
  { to: '/dashboard', label: 'Scan', icon: 'M3 3h8v8H3zM13 3h8v8h-8zM3 13h8v8H3zM13 13h8v8h-8z' },
  { to: '/findings', label: 'Findings', icon: 'M4 5h16M4 12h16M4 19h10', badge: true },
  { to: '/files', label: 'Files', icon: 'M3 6h7l2 2h9v11H3z' },
  { to: '/scans', label: 'History', icon: 'M12 4a8 8 0 1 0 0 16 8 8 0 0 0 0-16zM12 8v5l3 2' },
  { to: '/logs', label: 'Logs', icon: 'M4 5h16v14H4zM7 10l3 2-3 2M12 15h5', live: true },
]

export default function RailNav() {
  const { scanResult, scanning } = useScan()
  const urgent = (scanResult?.findings ?? []).filter((f) => {
    const s = normSeverity(f.severity)
    return s === 'critical' || s === 'high'
  }).length

  return (
    <nav className="ag-rail" aria-label="Primary">
      {ITEMS.map((it) => (
        <NavLink key={it.to} to={it.to}>
          <svg viewBox="0 0 24 24" aria-hidden="true"><path d={it.icon} /></svg>
          {it.label}
          {it.badge && urgent > 0 && (
            <span className="ag-badge" title={`${urgent} critical or high findings`}>
              {urgent}
              <span className="visually-hidden"> critical or high findings</span>
            </span>
          )}
          {it.live && scanning && <span className="ag-live">live</span>}
        </NavLink>
      ))}
    </nav>
  )
}
