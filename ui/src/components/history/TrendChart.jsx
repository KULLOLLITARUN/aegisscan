import { useEffect, useMemo, useRef, useState } from 'react'
import { formatScore, scoreStatus, statusVar } from '../../lib/score'
import { scoreLabel } from '../../lib/verdict'

const H = 184
const PAD = { top: 16, right: 56, bottom: 30, left: 40 }
const GRID = [0, 50, 100]
const day = new Intl.DateTimeFormat('en-GB', { day: '2-digit', month: 'short' })
const full = new Intl.DateTimeFormat('en-GB', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' })

function useWidth(ref) {
  const [w, setW] = useState(0)
  useEffect(() => {
    const el = ref.current
    if (!el) return undefined
    const ro = new ResizeObserver(([entry]) => setW(Math.round(entry.contentRect.width)))
    ro.observe(el)
    return () => ro.disconnect()
  }, [ref])
  return w
}

/**
 * Security score over time for one target: a single 2px line, hairline grid, a ringed end marker
 * with its value, and a crosshair that snaps to the nearest scan (pointer or arrow keys).
 * The table under it on the History page is the accessible view of the same numbers.
 * `points` are oldest first: { id, ts: Date, score }.
 */
export default function TrendChart({ points, onPick }) {
  const box = useRef(null)
  const width = useWidth(box)
  const [active, setActive] = useState(null)

  const geo = useMemo(() => {
    const plotW = Math.max(0, width - PAD.left - PAD.right)
    const plotH = H - PAD.top - PAD.bottom
    const n = points.length
    const x = (i) => PAD.left + (n <= 1 ? plotW / 2 : (i / (n - 1)) * plotW)
    const y = (v) => PAD.top + (1 - v / 100) * plotH
    const d = points.map((p, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(p.score).toFixed(1)}`).join('')
    return { x, y, d, plotW }
  }, [points, width])

  if (!points.length) return null
  const last = points.length - 1
  const shown = active ?? last
  const p = points[shown]
  const status = scoreStatus(p.score)
  const markers = points.length <= 24

  const nearest = (clientX) => {
    const r = box.current.getBoundingClientRect()
    const rel = clientX - r.left
    let best = 0
    points.forEach((_, i) => { if (Math.abs(geo.x(i) - rel) < Math.abs(geo.x(best) - rel)) best = i })
    return best
  }
  const onKey = (e) => {
    const i = active ?? last
    if (e.key === 'ArrowLeft') setActive(Math.max(0, i - 1))
    else if (e.key === 'ArrowRight') setActive(Math.min(last, i + 1))
    else if (e.key === 'Home') setActive(0)
    else if (e.key === 'End') setActive(last)
    else if (e.key === 'Enter' && onPick) onPick(points[i])
    else if (e.key === 'Escape') setActive(null)
    else return
    e.preventDefault()
  }

  const tipLeft = Math.min(Math.max(geo.x(shown) - 90, 0), Math.max(0, width - 180))
  const first = points[0]
  const change = points.length > 1 ? p.score - first.score : null

  return (
    <div
      ref={box}
      className="ag-trend"
      tabIndex={0}
      role="img"
      aria-label={`Security score over ${points.length} scans, from ${formatScore(first.score)} to ${formatScore(points[last].score)}. Use the arrow keys to read each scan.`}
      onPointerMove={(e) => setActive(nearest(e.clientX))}
      onPointerLeave={() => setActive(null)}
      onClick={(e) => onPick && onPick(points[nearest(e.clientX)])}
      onKeyDown={onKey}
      onBlur={() => setActive(null)}
    >
      {width > 0 && (
        <svg width={width} height={H} aria-hidden="true">
          {GRID.map((g) => (
            <g key={g}>
              <line className="ag-trend-grid" x1={PAD.left} x2={PAD.left + geo.plotW} y1={geo.y(g)} y2={geo.y(g)} />
              <text className="ag-trend-axis" x={PAD.left - 8} y={geo.y(g)} dy="0.32em" textAnchor="end">{g}</text>
            </g>
          ))}
          <text className="ag-trend-axis" x={geo.x(0)} y={H - 8} textAnchor={points.length > 1 ? 'start' : 'middle'}>{day.format(first.ts)}</text>
          {points.length > 1 && <text className="ag-trend-axis" x={geo.x(last)} y={H - 8} textAnchor="end">{day.format(points[last].ts)}</text>}

          {active != null && <line className="ag-trend-cross" x1={geo.x(shown)} x2={geo.x(shown)} y1={PAD.top} y2={H - PAD.bottom} />}
          <path className="ag-trend-line" d={geo.d} pathLength="1" />
          {points.map((pt, i) => (markers || i === last || i === active) && (
            <circle
              key={pt.id}
              className={`ag-trend-dot${i === shown ? ' on' : ''}`}
              cx={geo.x(i)} cy={geo.y(pt.score)} r={i === shown ? 5 : 4}
              style={{ '--c': statusVar(scoreStatus(pt.score)), '--i': i }}
            />
          ))}
          <text className="ag-trend-end" x={geo.x(last) + 10} y={geo.y(points[last].score)} dy="0.32em">{formatScore(points[last].score)}</text>
        </svg>
      )}
      {active != null && (
        <div className="ag-trend-tip" style={{ left: tipLeft }} aria-hidden="true">
          <strong className="ag-num">{formatScore(p.score)}</strong>
          <span><i className="ag-dot" style={{ '--c': statusVar(status) }} />{scoreLabel(p.score)}</span>
          <span className="ag-muted">{full.format(p.ts)}</span>
          {change != null && shown !== 0 && <span className="ag-muted">{change >= 0 ? '+' : ''}{formatScore(change)} since the first scan</span>}
        </div>
      )}
    </div>
  )
}
