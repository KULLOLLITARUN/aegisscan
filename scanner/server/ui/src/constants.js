// Shared vocabulary — mirrors scanner/models/finding.py exactly (Severity / Category
// enums are lowercase). Centralized here because five components previously each
// declared their own SEV_COLORS map keyed by uppercase strings ('CRITICAL', 'HIGH', …),
// which never matched the real lowercase values coming back from the API — every
// severity/category color and count silently fell back to gray. Compare and render
// through these instead of ad-hoc per-file maps.

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']

export const SEVERITY_LABEL = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
}

export const CATEGORIES = [
  'injection',
  'secrets',
  'access_control',
  'crypto',
  'performance',
  'best_practices',
  'other',
]

export const CATEGORY_LABEL = {
  injection: 'Injection',
  secrets: 'Secrets',
  access_control: 'Access Control',
  crypto: 'Crypto',
  performance: 'Performance',
  best_practices: 'Best Practices',
  other: 'Other',
}

/** Normalizes whatever the API sends (case, missing value) to a known severity key. */
export function normSeverity(sev) {
  const s = (sev || '').toLowerCase()
  return SEVERITIES.includes(s) ? s : 'info'
}

/** Normalizes whatever the API sends to a known category key. */
export function normCategory(cat) {
  const c = (cat || '').toLowerCase()
  return CATEGORIES.includes(c) ? c : 'other'
}
