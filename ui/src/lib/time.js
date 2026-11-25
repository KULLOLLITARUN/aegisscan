// SQLite's CURRENT_TIMESTAMP is UTC without a zone ("2026-11-24 18:44:02"): read it as UTC.
export function parseTs(ts) {
  if (!ts) return null
  const s = String(ts)
  const iso = s.includes('T') ? s : s.replace(' ', 'T')
  const d = new Date(/[zZ]$|[+-]\d\d:?\d\d$/.test(iso) ? iso : `${iso}Z`)
  return Number.isNaN(d.getTime()) ? null : d
}
