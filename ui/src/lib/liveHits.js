import { SEVERITIES, normSeverity } from '../constants'

const rank = (s) => SEVERITIES.indexOf(normSeverity(s))

/**
 * Folds one "preview" event (a static tool's raw findings grouped by file) into the running picture of
 * what has been found so far. The numbers are preliminary: the final result is deduplicated, weighted and
 * suppressed afterwards, so it can show fewer findings.
 */
export function mergePreview(prev, event) {
  const byPath = { ...(prev?.byPath ?? {}) }
  let total = prev?.total ?? 0
  for (const f of event?.files ?? []) {
    const cur = byPath[f.path]
    const worst = cur && rank(cur.worst) <= rank(f.worst) ? cur.worst : normSeverity(f.worst)
    byPath[f.path] = { worst, count: (cur?.count ?? 0) + (f.count ?? 1) }
    total += f.count ?? 1
  }
  return { byPath, total, tool: event?.tool ?? prev?.tool ?? '' }
}
