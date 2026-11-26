import { relPath } from './paths'

/**
 * A finding's identity across scans: relative file, tool, issue type and category. No line number,
 * so an edit above a finding does not make it "new". Used for new/fixed and for triage decisions.
 */
export function findingKey(f, target) {
  return [relPath(f.file_path || '', target), f.rule_source || '', f.issue_type || '', f.category || ''].join('|')
}

/** The flagged code with line-number prefixes (bandit adds them) and spacing removed, so it survives a move. */
function normalizedEvidence(evidence) {
  return String(evidence ?? '')
    .replace(/\r\n/g, '\n')
    .split('\n')
    .map((l) => l.replace(/^\s*\d+(?=\s|$)/, '').replace(/\s+/g, ' ').trim())
    .filter(Boolean)
    .join('\n')
}

/** FNV-1a, 32 bit, as 8 hex digits. Enough to tell apart a handful of snippets in one file. */
function fingerprint(text) {
  let h = 0x811c9dc5
  for (let i = 0; i < text.length; i += 1) {
    h ^= text.charCodeAt(i)
    h = Math.imul(h, 0x01000193)
  }
  return (h >>> 0).toString(16).padStart(8, '0')
}

/**
 * Identity of one finding for triage: findingKey plus a fingerprint of the flagged code, so marking
 * one "Try Except Pass" does not mark every other one in the file. Moving the code (an edit above it)
 * keeps the decision; changing the flagged line itself drops it. With no snippet, the line number is used.
 */
export function triageKey(f, target) {
  const code = normalizedEvidence(f.evidence)
  return `${findingKey(f, target)}|${code ? fingerprint(code) : `line${f.line_start ?? 0}`}`
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
