// Timeline model built only from what the stream actually reported: progress events (phase, pct)
// and log events, each stamped client-side in ms since the scan was requested.

const phaseName = (phase) => String(phase || '').split(':')[0].trim()

/**
 * @param recording { events, durationMs }
 * @param fallbackSeconds result.scan_duration_seconds, used only for the total when no events exist
 */
export function buildTimeline(recording, fallbackSeconds = 0) {
  const events = recording?.events ?? []
  const progress = events.filter((e) => e.kind === 'progress' && phaseName(e.phase) !== 'Complete')
  const last = events.length ? events[events.length - 1].t : 0
  const totalMs = Math.max(recording?.durationMs || 0, last, (fallbackSeconds || 0) * 1000)
  const total = totalMs / 1000

  const segments = []
  for (const e of progress) {
    const name = phaseName(e.phase)
    const prev = segments[segments.length - 1]
    if (prev && prev.name === name) continue
    segments.push({ name, start: e.t / 1000, end: total })
  }
  segments.forEach((s, i) => {
    if (segments[i + 1]) s.end = segments[i + 1].start
  })
  if (segments.length && segments[0].start > 0) segments[0].start = 0

  const markers = events
    .filter((e) => e.kind === 'log' && (e.level === 'warn' || e.level === 'err'))
    .map((e) => ({ t: e.t / 1000, level: e.level, message: e.message }))

  // Reported progress (0-100) as a function of time, linearly eased between events.
  const points = [{ t: 0, pct: 0 }, ...progress.map((e) => ({ t: e.t / 1000, pct: e.pct ?? 0 })), { t: total, pct: 100 }]
  return { total, segments, markers, events, points, hasPhases: segments.length > 0 }
}

export function pctAt(points, t) {
  if (!points.length) return 100
  if (t <= points[0].t) return points[0].pct
  for (let i = 1; i < points.length; i++) {
    if (t <= points[i].t) {
      const a = points[i - 1]
      const b = points[i]
      const span = b.t - a.t
      return span <= 0 ? b.pct : a.pct + ((b.pct - a.pct) * (t - a.t)) / span
    }
  }
  return 100
}

export function segmentAt(segments, t) {
  return segments.find((s) => t >= s.start && t < s.end) || segments[segments.length - 1] || null
}
