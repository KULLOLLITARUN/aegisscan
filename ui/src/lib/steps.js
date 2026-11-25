// "LLM analysis: 22/934 chunks" repeats with a new count hundreds of times: one step, showing the latest count.
const counterKey = (ph) => ph.replace(/\d+\s*\/\s*\d+/, '#')

/** Steps the scanner has actually reported so far (from the stream), the last one still running. */
export function liveSteps(events) {
  const phases = (events || []).filter((e) => e.kind === 'progress' && e.phase).map((e) => e.phase)
  const out = []
  for (const ph of phases) {
    const last = out[out.length - 1]
    if (last === ph) continue
    if (last !== undefined && counterKey(last) === counterKey(ph) && counterKey(ph) !== ph) {
      out[out.length - 1] = ph
      continue
    }
    out.push(ph)
  }
  // "Static analysis" is superseded by "Static analysis: Bandit" and so on
  return out.filter((ph, i) => !(out[i + 1] || '').startsWith(`${ph}:`))
}
