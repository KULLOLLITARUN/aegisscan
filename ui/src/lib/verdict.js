import { normSeverity } from '../constants'

const norm = (p) => String(p || '').replace(/\\/g, '/').toLowerCase().replace(/\/+$/, '')

export function scoreLabel(s) {
  if (s == null) return ''
  return s >= 90 ? 'Excellent' : s >= 75 ? 'Good' : s >= 55 ? 'Fair' : s >= 30 ? 'Poor' : 'Critical'
}

export function verdictSentence(findings) {
  const list = findings ?? []
  if (!list.length) return 'No findings in this scan.'
  const c = list.filter((f) => normSeverity(f.severity) === 'critical').length
  const h = list.filter((f) => normSeverity(f.severity) === 'high').length
  if (!c && !h) return 'No critical or high issues found.'
  const parts = `${c ? `${c} critical` : ''}${c && h ? ' and ' : ''}${h ? `${h} high` : ''}`
  return `${parts} ${c + h === 1 ? 'issue needs' : 'issues need'} fixing first.`
}

/** The most recent history row for the same target that is not the current scan. */
export function previousScan(history, result) {
  if (!result) return null
  return (
    (history ?? []).find(
      (h) => h.scan_id !== result.scan_id && norm(h.target_path) === norm(result.target_path),
    ) || null
  )
}

/** Signed score change versus the previous scan, or null when there is nothing to compare. */
export function scoreDelta(current, prev) {
  if (current == null || prev == null) return null
  return Math.round((current - prev) * 10) / 10
}
