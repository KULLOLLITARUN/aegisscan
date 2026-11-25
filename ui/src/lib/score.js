// Score status: one scale for every score in the UI (hero, ruler, history, trend).
// The bands match scoreLabel in lib/verdict.js. Colour is a reserved status scale (tokens --status-*),
// always shown next to its label, never on its own.

export const SCORE_STATUS = [
  { key: 'good', min: 75 },
  { key: 'warning', min: 55 },
  { key: 'serious', min: 30 },
  { key: 'critical', min: -Infinity },
]

/** 'good' | 'warning' | 'serious' | 'critical', or null when there is no score. */
export function scoreStatus(score) {
  if (score == null || Number.isNaN(Number(score))) return null
  return SCORE_STATUS.find((s) => Number(score) >= s.min).key
}

export const statusVar = (status) => (status ? `var(--status-${status})` : 'var(--muted-2)')

const one = new Intl.NumberFormat('en', { maximumFractionDigits: 1, minimumFractionDigits: 1 })
export const formatScore = (s) => (s == null ? '--' : one.format(s))
