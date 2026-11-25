import { SEVERITIES, normSeverity } from '../constants'
import { relPath, baseName } from './paths'

// The API carries no per-file list, so the floor is built from the files that have findings
// (real paths). Analysed files without findings are shown as a count only.
export const MAX_PINS = 48
const FLOOR_W = 560
const GAP = 12

const sevRank = (s) => SEVERITIES.indexOf(normSeverity(s))

/** Findings in display order: severity first, then confidence, then file and line. */
export function sortFindings(list) {
  return [...list].sort(
    (a, b) =>
      sevRank(a.severity) - sevRank(b.severity) ||
      (b.confidence ?? 0) - (a.confidence ?? 0) ||
      String(a.file_path).localeCompare(String(b.file_path)) ||
      (a.line_start ?? 0) - (b.line_start ?? 0),
  )
}

export function pinHeight(conf) {
  const c = Math.min(1, Math.max(0, Number(conf) || 0))
  return Math.round(30 + c * 90)
}

/**
 * Derive floor tiles and pins from a ScanResult.
 * Tile area scales with the highest line number a finding reaches in that file (a lower bound on
 * the real line count). Pins are capped at maxPins by severity, then confidence.
 */
export function buildScene(result, maxPins = MAX_PINS) {
  const findings = result?.findings ?? []
  const target = result?.target_path
  const sorted = sortFindings(findings)
  const shown = sorted.slice(0, maxPins)
  const hiddenPins = sorted.length - shown.length

  const byFile = new Map()
  for (const f of shown) {
    const key = relPath(f.file_path, target)
    if (!byFile.has(key)) byFile.set(key, { path: key, findings: [], lines: 1, worst: normSeverity(f.severity) })
    const t = byFile.get(key)
    t.findings.push(f)
    t.lines = Math.max(t.lines, f.line_end ?? f.line_start ?? 1)
  }
  const files = [...byFile.values()]
  const allFileCount = new Set(findings.map((f) => relPath(f.file_path, target))).size
  const hiddenFiles = allFileCount - files.length
  const cleanFiles = Math.max(0, (result?.files_analyzed ?? 0) - allFileCount)

  const maxLines = Math.max(1, ...files.map((t) => t.lines))
  // Shelf packing; files arrive worst-first so they sit at the front of the floor.
  let x = 0
  let y = 0
  let rowH = 0
  const tiles = files.map((t) => {
    const k = Math.sqrt(t.lines / maxLines)
    const w = Math.round(96 + 96 * k)
    const h = Math.round(72 + 56 * k)
    if (x + w > FLOOR_W && x > 0) {
      x = 0
      y += rowH + GAP
      rowH = 0
    }
    const tile = { id: t.path, label: baseName(t.path), path: t.path, x, y, w, h, worst: t.worst, lines: t.lines, count: t.findings.length }
    x += w + GAP
    rowH = Math.max(rowH, h)
    t.tile = tile
    return tile
  })
  const floorH = Math.max(160, y + rowH)

  const pins = []
  for (const t of files) {
    const tile = t.tile
    const cols = Math.max(1, Math.ceil(Math.sqrt(t.findings.length)))
    const rows = Math.ceil(t.findings.length / cols)
    const ordered = [...t.findings].sort((a, b) => (a.line_start ?? 0) - (b.line_start ?? 0))
    ordered.forEach((f, i) => {
      const col = i % cols
      const row = Math.floor(i / cols)
      pins.push({
        id: f.id,
        finding: f,
        sev: normSeverity(f.severity),
        tileId: tile.id,
        x: Math.round(tile.x + (tile.w * (col + 0.5)) / cols),
        y: Math.round(tile.y + ((tile.h * (row + 0.5)) / rows) * 0.8),
        h: pinHeight(f.confidence),
      })
    })
  }
  return { tiles, pins, floorW: FLOOR_W, floorH, hiddenPins, hiddenFiles, cleanFiles, totalFindings: findings.length }
}

export const MAX_LIVE_TILES = 240
const LIVE_FLOOR = 560 // the width a typical final floor has, so the live floor is about the same size
const LIVE_GAP = 8
const LIVE_MIN_W = 22
const LIVE_MAX_W = 110

/**
 * The floor drawn while a scan is still running: one small tile per analysed file, from the file list the
 * scanner streams once it has crawled and classified the target. Files are sorted by path so folders sit
 * together. Past MAX_LIVE_TILES the list is sampled evenly and hiddenFiles says how many are not drawn.
 */
export function buildLiveScene(files, maxTiles = MAX_LIVE_TILES) {
  const list = [...(files?.files ?? [])].sort((a, b) => String(a.path).localeCompare(String(b.path)))
  const total = Math.max(files?.total ?? 0, list.length)
  const step = list.length > maxTiles ? list.length / maxTiles : 1
  const shown = []
  for (let i = 0; i < Math.min(list.length, maxTiles); i++) shown.push(list[Math.floor(i * step)])
  const cols = Math.max(1, Math.min(24, Math.ceil(Math.sqrt(shown.length * 2.2))))
  // Tiles are as big as the target floor width allows (few files: chunky tiles; many: small ones).
  const tileW = Math.max(LIVE_MIN_W, Math.min(LIVE_MAX_W, Math.floor(LIVE_FLOOR / cols) - LIVE_GAP))
  const tileH = Math.round(tileW * 0.7)
  const cellW = tileW + LIVE_GAP
  const cellH = tileH + LIVE_GAP
  const tiles = shown.map((f, i) => {
    const path = String(f.path)
    return { id: path, label: baseName(path), path, x: (i % cols) * cellW, y: Math.floor(i / cols) * cellH, w: tileW, h: tileH, worst: null, lines: f.lines ?? 0, count: 0 }
  })
  const rows = Math.max(1, Math.ceil(shown.length / cols))
  return {
    tiles, pins: [], floorW: Math.max(160, cols * cellW - LIVE_GAP), floorH: Math.max(120, rows * cellH - LIVE_GAP),
    hiddenPins: 0, hiddenFiles: Math.max(0, total - shown.length), cleanFiles: 0, totalFindings: 0, live: true, total,
    discovered: Math.max(files?.discovered ?? total, total),
  }
}
