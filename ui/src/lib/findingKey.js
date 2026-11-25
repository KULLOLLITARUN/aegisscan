import { relPath } from './paths'

/**
 * A finding's identity across scans: relative file, tool, issue type and category. No line number,
 * so an edit above a finding does not make it "new". Used for new/fixed and for triage decisions.
 */
export function findingKey(f, target) {
  return [relPath(f.file_path || '', target), f.rule_source || '', f.issue_type || '', f.category || ''].join('|')
}

/**
 * Compare two results of the same target. Count-aware: with three identical keys before and two now,
 * one is fixed. Returns { newIds: Set of current finding ids, fixed: previous findings no longer present }.
 */
export function diffResults(current, previous) {
  const counts = new Map()
  for (const f of previous?.findings ?? []) {
    const k = findingKey(f, previous.target_path)
    counts.set(k, (counts.get(k) ?? 0) + 1)
  }
  const newIds = new Set()
  for (const f of current?.findings ?? []) {
    const k = findingKey(f, current.target_path)
    const left = counts.get(k) ?? 0
    if (left > 0) counts.set(k, left - 1)
    else newIds.add(f.id)
  }
  const fixed = []
  for (const f of previous?.findings ?? []) {
    const k = findingKey(f, previous.target_path)
    const left = counts.get(k) ?? 0
    if (left > 0) {
      fixed.push(f)
      counts.set(k, left - 1)
    }
  }
  return { newIds, fixed }
}
