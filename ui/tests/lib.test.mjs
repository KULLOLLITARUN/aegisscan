// Unit tests for the UI's pure logic. Run: node --import ./tests/register.mjs --test tests/
// (Node's built-in runner, no extra dependencies.)
import { test } from 'node:test'
import assert from 'node:assert/strict'

import { parseNotes, isDownweighted } from '../src/lib/notes.js'
import { findingKey, triageKey, diffResults } from '../src/lib/findingKey.js'
import { scoreStatus, formatScore } from '../src/lib/score.js'
import { parseTs } from '../src/lib/time.js'
import { normPath, relPath } from '../src/lib/paths.js'
import { scoreLabel, verdictSentence, previousScan, scoreDelta } from '../src/lib/verdict.js'

const f = (over = {}) => ({
  id: Math.random().toString(36).slice(2),
  file_path: 'C:\\proj\\src\\app.py', rule_source: 'bandit', issue_type: 'Hashlib', category: 'crypto',
  severity: 'high', explanation: 'why', ...over,
})

// ---- notes: the scanner's bracketed prefixes become badges ----
test('parseNotes turns known prefixes into badges and keeps the rest of the text', () => {
  const r = parseNotes('[non-production path: test, example or docs code; severity lowered one level] [model remark about code quality or tooling; severity and confidence capped] Real text.')
  assert.deepEqual(r.notes.map((n) => n.key), ['nonprod', 'llm'])
  assert.equal(r.text, 'Real text.')
})

test('parseNotes leaves unknown brackets and plain text alone', () => {
  assert.deepEqual(parseNotes('[TODO] fix this'), { notes: [], text: '[TODO] fix this' })
  assert.deepEqual(parseNotes(undefined), { notes: [], text: '' })
  assert.equal(isDownweighted(f({ explanation: '[CI configuration hygiene note; severity capped at low] x' })), true)
  assert.equal(isDownweighted(f()), false)
})

// ---- finding keys and new / fixed ----
test('findingKey ignores the line number and the target prefix', () => {
  const a = findingKey(f({ line_start: 3 }), 'C:\\proj')
  const b = findingKey(f({ line_start: 90, file_path: 'C:/proj/src/app.py' }), 'C:/proj/')
  assert.equal(a, b)
  assert.equal(a, 'src/app.py|bandit|Hashlib|crypto')
})

test('triageKey tells identical issues in one file apart, and survives the code moving', () => {
  const a = f({ issue_type: 'Try Except Pass', evidence: 'try:\n    x()\nexcept:\n    pass', line_start: 10 })
  const b = f({ issue_type: 'Try Except Pass', evidence: 'try:\n    y()\nexcept:\n    pass', line_start: 40 })
  assert.notEqual(triageKey(a, 'C:/proj'), triageKey(b, 'C:/proj'))
  // same code moved down the file, with bandit-style line-number prefixes and different spacing
  const moved = { ...a, line_start: 55, evidence: '55 try:\n56     x()\n57 except:\n58     pass' }
  assert.equal(triageKey(a, 'C:/proj'), triageKey(moved, 'C:/proj'))
  assert.ok(triageKey(a, 'C:/proj').startsWith(findingKey(a, 'C:/proj') + '|'))
  assert.ok(triageKey(a, 'C:/proj').length < 600)
})

test('triageKey falls back to the line number when there is no snippet', () => {
  assert.equal(triageKey(f({ line_start: 7 }), 'C:/proj'), 'src/app.py|bandit|Hashlib|crypto|line7')
})

test('diffResults is count-aware: one of three identical findings fixed', () => {
  const prev = { target_path: 'C:/proj', findings: [f(), f(), f(), f({ issue_type: 'Gone' })] }
  const curNew = f({ issue_type: 'Brand new' })
  const cur = { target_path: 'C:/proj', findings: [f(), f(), curNew] }
  const d = diffResults(cur, prev)
  assert.deepEqual([...d.newIds], [curNew.id])
  assert.deepEqual(d.fixed.map((x) => x.issue_type).sort(), ['Gone', 'Hashlib'])
})

test('diffResults with no previous scan marks everything new and nothing fixed', () => {
  const cur = { target_path: '/p', findings: [f(), f()] }
  const d = diffResults(cur, { target_path: '/p', findings: [] })
  assert.equal(d.newIds.size, 2)
  assert.equal(d.fixed.length, 0)
})

// ---- score status ----
test('scoreStatus uses the same bands as the labels', () => {
  assert.equal(scoreStatus(95), 'good')
  assert.equal(scoreStatus(75), 'good')
  assert.equal(scoreStatus(74.9), 'warning')
  assert.equal(scoreStatus(55), 'warning')
  assert.equal(scoreStatus(30), 'serious')
  assert.equal(scoreStatus(0), 'critical')
  assert.equal(scoreStatus(null), null)
  assert.equal(scoreLabel(75), 'Good')
  assert.equal(scoreLabel(29.9), 'Critical')
  assert.equal(formatScore(7), '7.0')
  assert.equal(formatScore(null), '--')
})

// ---- time and paths ----
test('parseTs reads SQLite UTC timestamps as UTC and leaves zoned ones alone', () => {
  assert.equal(parseTs('2026-11-24 18:44:02').toISOString(), '2026-11-24T18:44:02.000Z')
  assert.equal(parseTs('2026-11-24T18:44:02+05:30').toISOString(), '2026-11-24T13:14:02.000Z')
  assert.equal(parseTs('not a date'), null)
  assert.equal(parseTs(null), null)
})

test('normPath and relPath', () => {
  assert.equal(normPath('C:\\a\\b\\\\'), 'C:/a/b')
  assert.equal(normPath('/'), '/')
  assert.equal(relPath('C:\\A\\b\\c.py', 'c:/a'), 'b/c.py')
  assert.equal(relPath('/elsewhere/x.py', '/a'), '/elsewhere/x.py')
})

// ---- verdict ----
test('verdictSentence and previousScan', () => {
  assert.equal(verdictSentence([]), 'No findings in this scan.')
  assert.equal(verdictSentence([f({ severity: 'critical' }), f({ severity: 'high' }), f({ severity: 'high' })]), '1 critical and 2 high issues need fixing first.')
  const history = [
    { scan_id: 'now', target_path: 'C:\\proj' },
    { scan_id: 'other', target_path: '/elsewhere' },
    { scan_id: 'before', target_path: 'c:/proj/' },
  ]
  assert.equal(previousScan(history, { scan_id: 'now', target_path: 'C:/proj' }).scan_id, 'before')
  assert.equal(scoreDelta(70.04, 60), 10)
  assert.equal(scoreDelta(70, null), null)
})

// ---- live scene: the floor drawn while a scan runs ----
import { buildLiveScene, MAX_LIVE_TILES } from '../src/lib/scene.js'

test('buildLiveScene lays out one tile per file, sorted so folders sit together', () => {
  const s = buildLiveScene({ files: [{ path: 'b/z.py', lines: 3 }, { path: 'a/y.py', lines: 9 }, { path: 'a/x.py', lines: 1 }], total: 3 })
  assert.deepEqual(s.tiles.map((t) => t.path), ['a/x.py', 'a/y.py', 'b/z.py'])
  assert.equal(s.live, true)
  assert.equal(s.hiddenFiles, 0)
  assert.ok(s.floorW > 0 && s.floorH > 0)
})

test('buildLiveScene samples a big project and counts what it leaves out', () => {
  const files = Array.from({ length: 1000 }, (_, i) => ({ path: `src/f${String(i).padStart(4, '0')}.py`, lines: 5 }))
  const s = buildLiveScene({ files, total: 1000 })
  assert.equal(s.tiles.length, MAX_LIVE_TILES)
  assert.equal(s.hiddenFiles, 1000 - MAX_LIVE_TILES)
  assert.equal(new Set(s.tiles.map((t) => t.id)).size, MAX_LIVE_TILES)
})

test('buildLiveScene copes with an empty or missing list', () => {
  assert.equal(buildLiveScene(null).tiles.length, 0)
  assert.equal(buildLiveScene({ files: [], total: 0 }).tiles.length, 0)
})

// ---- live preview: findings streamed as each static tool finishes ----
import { mergePreview } from '../src/lib/liveHits.js'

test('mergePreview adds counts per file and keeps the worst severity', () => {
  const a = mergePreview(null, { tool: 'Bandit', files: [{ path: 'a.py', worst: 'low', count: 2 }, { path: 'b.py', worst: 'high', count: 1 }] })
  assert.equal(a.total, 3)
  const b = mergePreview(a, { tool: 'Semgrep', files: [{ path: 'a.py', worst: 'critical', count: 1 }, { path: 'b.py', worst: 'info', count: 4 }] })
  assert.deepEqual(b.byPath['a.py'], { worst: 'critical', count: 3 })
  assert.deepEqual(b.byPath['b.py'], { worst: 'high', count: 5 })
  assert.equal(b.total, 8)
  assert.equal(b.tool, 'Semgrep')
  assert.equal(a.total, 3, 'the previous state is not changed')
})

test('buildLiveScene keeps the count of discovered files, which can exceed the analysed ones', () => {
  const s = buildLiveScene({ files: [{ path: 'a.py', lines: 1 }], total: 1, discovered: 4 })
  assert.equal(s.total, 1)
  assert.equal(s.discovered, 4)
  assert.equal(buildLiveScene({ files: [{ path: 'a.py', lines: 1 }], total: 1 }).discovered, 1)
})

// ---- live steps: repeated counters collapse to one line ----
import { liveSteps } from '../src/lib/steps.js'

test('liveSteps keeps one line for a repeating "n/total" counter, showing the latest count', () => {
  const ev = (phase) => ({ kind: 'progress', phase })
  const steps = liveSteps([ev('Chunking files'), ev('LLM analysis: 0/934 chunks'), ev('LLM analysis: 1/934 chunks'), ev('LLM analysis: 22/934 chunks')])
  assert.deepEqual(steps, ['Chunking files', 'LLM analysis: 22/934 chunks'])
})

test('liveSteps still drops "Static analysis" once a tool step follows it', () => {
  const ev = (phase) => ({ kind: 'progress', phase })
  assert.deepEqual(liveSteps([ev('Static analysis'), ev('Static analysis: Bandit'), ev('Static analysis: Bandit')]), ['Static analysis: Bandit'])
})
