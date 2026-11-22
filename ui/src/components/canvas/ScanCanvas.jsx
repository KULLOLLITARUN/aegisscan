import { useEffect, useRef, useState } from 'react'
import { SEVERITY_LABEL } from '../../constants'
import { useScan } from '../../context/ScanContext'
import { useRaf, prefersReducedMotion } from '../../lib/useRaf'
import Verdict from './Verdict'
import ScanErrorBody from '../findings/ScanErrorBody'

const BASE_ROT = -32
const DEFAULT_HINT = 'Drag to turn the floor, scroll to zoom. Each tile is a file and each pin a finding. Taller means more confident.'
const SEV_LEGEND = ['critical', 'high', 'medium', 'low', 'info']

const pinLabel = (f, sev, rel) =>
  `${f.issue_type}, ${rel} line ${f.line_start}, ${SEVERITY_LABEL[sev]} severity, ${Math.round((f.confidence ?? 0) * 100)} percent confidence`

/**
 * The 3D floor-plan scan volume (CSS 3D, no WebGL). One tile per file with findings, one pin per
 * finding. Drag or arrow keys rotate, wheel or +/- zoom, selecting a finding moves the camera to it.
 */
export default function ScanCanvas({
  scene, result, scanning, error, history, historyStatus,
  selectedId, onSelect, hoverId, onHover, planeRef, visible, tilesDone, livePlane, onRun,
}) {
  const { hosted } = useScan()
  const stageRef = useRef(null)
  const sceneRef = useRef(null)
  const view = useRef({ offset: 0, zoom: 1, cam: { x: 0, y: 0, z: 1 }, camT: { x: 0, y: 0, z: 1 }, drag: null })
  const [sway, setSway] = useState(() => !prefersReducedMotion())
  const swayRef = useRef(sway)
  const t0 = useRef(performance.now())
  const reduced = useRef(prefersReducedMotion())

  useEffect(() => {
    swayRef.current = sway
  }, [sway])

  const { tiles, pins, floorW, floorH } = scene
  const selectedPin = pins.find((p) => p.id === selectedId)
  const selectedTile = selectedPin?.tileId

  // Camera target follows the selection.
  useEffect(() => {
    const v = view.current
    v.camT = selectedPin
      ? { x: (selectedPin.x - floorW / 2) * 0.6, y: (selectedPin.y - floorH / 2) * 0.6, z: 1.15 }
      : { x: 0, y: 0, z: 1 }
    if (reduced.current) v.cam = { ...v.camT }
  }, [selectedPin, floorW, floorH])

  // Wheel zoom needs a non-passive listener to stop the page from scrolling.
  useEffect(() => {
    const el = stageRef.current
    if (!el) return undefined
    const onWheel = (e) => {
      e.preventDefault()
      view.current.zoom = Math.max(0.6, Math.min(1.8, view.current.zoom * (e.deltaY < 0 ? 1.08 : 0.92)))
    }
    el.addEventListener('wheel', onWheel, { passive: false })
    return () => el.removeEventListener('wheel', onWheel)
  }, [])

  useRaf((now) => {
    const st = stageRef.current
    const sc = sceneRef.current
    if (!st || !sc) return
    const v = view.current
    const s = swayRef.current ? 12 * Math.sin((now - t0.current) / 6500) : 0
    const ease = reduced.current ? 1 : 0.08
    v.cam.x += (v.camT.x - v.cam.x) * ease
    v.cam.y += (v.camT.y - v.cam.y) * ease
    v.cam.z += (v.camT.z - v.cam.z) * ease
    const rot = BASE_ROT + s + v.offset
    const k = Math.max(0.55, Math.min(1.5, Math.min((st.clientWidth - 360) / (floorW + 80), st.clientHeight / (floorH + 250)))) * v.cam.z * v.zoom
    sc.style.setProperty('--rot', `${rot.toFixed(2)}deg`)
    sc.style.transform = `rotateX(58deg) rotateZ(${rot.toFixed(2)}deg) scale(${k.toFixed(3)}) translate3d(${(-v.cam.x).toFixed(1)}px, ${(-v.cam.y).toFixed(1)}px, 0)`
  })

  const onPointerDown = (e) => {
    if (e.target.closest('button, .ag-overlay, .ag-viewctl, .ag-score')) return
    view.current.drag = { x: e.clientX, o: view.current.offset }
    stageRef.current.setPointerCapture(e.pointerId)
  }
  const onPointerMove = (e) => {
    const d = view.current.drag
    if (d) view.current.offset = d.o + (e.clientX - d.x) * 0.35
  }
  const onPointerUp = () => { view.current.drag = null }
  const onKeyDown = (e) => {
    if (e.target !== stageRef.current) return
    const v = view.current
    if (e.key === 'ArrowLeft') v.offset -= 6
    else if (e.key === 'ArrowRight') v.offset += 6
    else if (e.key === '+' || e.key === '=') v.zoom = Math.min(1.8, v.zoom * 1.1)
    else if (e.key === '-') v.zoom = Math.max(0.6, v.zoom * 0.9)
    else return
    e.preventDefault()
  }
  const resetView = () => {
    const v = view.current
    v.offset = 0
    v.zoom = 1
    v.camT = { x: 0, y: 0, z: 1 }
    if (reduced.current) v.cam = { x: 0, y: 0, z: 1 }
    onSelect(null)
  }

  const noScan = !result && !scanning && !error
  const loading = scanning
  const hovered = hoverId ? pins.find((p) => p.id === hoverId) : null
  const fl = loading ? { w: 560, h: 270 } : { w: floorW, h: floorH }
  const files = result?.files_analyzed ?? 0
  const filesWithFindings = tiles.length + scene.hiddenFiles
  const showPins = !loading && !error

  const notes = []
  if (scene.hiddenPins > 0) notes.push(`Showing the ${pins.length} most severe of ${scene.totalFindings} findings. +${scene.hiddenPins} more are in the queue.`)
  if (scene.cleanFiles > 0) notes.push(`+${scene.cleanFiles} analysed ${scene.cleanFiles === 1 ? 'file has' : 'files have'} no findings and ${scene.cleanFiles === 1 ? 'is' : 'are'} not drawn.`)

  const stageState = error ? 'error' : loading ? 'loading' : noScan ? 'empty' : 'full'

  return (
    <section
      ref={stageRef}
      className="ag-stage"
      data-state={stageState}
      tabIndex={0}
      role="group"
      aria-label="Scan canvas: floor plan of files with findings. Drag or use the arrow keys to turn it, plus and minus to zoom."
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={onPointerUp}
      onPointerCancel={onPointerUp}
      onKeyDown={onKeyDown}
    >
      <div
        ref={sceneRef}
        className="ag-scene"
        style={{ width: fl.w, height: fl.h, margin: `${-fl.h / 2}px 0 0 ${-fl.w / 2}px` }}
      >
        <div className="ag-floor" style={{ left: -40, top: -40, width: fl.w + 80, height: fl.h + 80 }} />
        {showPins && tiles.map((t) => (
          <div
            key={t.id}
            className={`ag-tile hit${tilesDone.has(t.id) ? ' scanned' : ''}${t.id === selectedTile ? ' focus' : ''}`}
            style={{ left: t.x, top: t.y, width: t.w, height: t.h, '--sev': `var(--sev-${t.worst})` }}
            data-file={t.path}
          >
            <span title={t.path}>{t.label}</span>
          </div>
        ))}
        {showPins && pins.map((p) => (
          <div key={`m-${p.id}`} className="ag-mark" style={{ left: p.x, top: p.y, '--sev': `var(--sev-${p.sev})` }} />
        ))}
        <div
          ref={planeRef}
          className={`ag-wall${livePlane == null ? '' : ' live'}`}
          style={{ width: fl.h, '--plane': livePlane == null ? undefined : (livePlane / 100) * fl.w }}
        />
        {showPins && pins.map((p) => {
          const on = visible.has(p.id)
          const rel = p.tileId
          return (
            <div
              key={p.id}
              className={`ag-pin${on ? ' on' : ''}${p.id === selectedId ? ' sel' : ''}${p.id === hoverId ? ' hov' : ''}`}
              style={{ '--x': `${p.x}px`, '--y': `${p.y}px`, '--h': `${p.h}px`, '--sev': `var(--sev-${p.sev})` }}
            >
              <i className="ag-stem" />
              <button
                type="button"
                className={`ag-cap s-${p.sev}`}
                tabIndex={on ? 0 : -1}
                aria-label={pinLabel(p.finding, p.sev, rel)}
                aria-current={p.id === selectedId ? 'true' : undefined}
                onClick={() => onSelect(p.id)}
                onMouseEnter={() => onHover(p.id)}
                onMouseLeave={() => onHover(null)}
                onFocus={() => onHover(p.id)}
                onBlur={() => onHover(null)}
              >
                <i />
              </button>
            </div>
          )
        })}
      </div>

      <Verdict result={result} scanning={scanning} error={error} history={history} historyStatus={historyStatus} />

      <div className="ag-viewctl">
        <button type="button" className="ag-btn ag-btn--sm" aria-pressed={sway} onClick={() => setSway((s) => !s)}>
          {sway ? 'Hold view' : 'Auto sway'}
        </button>
        <button type="button" className="ag-btn ag-btn--sm ag-btn--ghost" onClick={resetView}>Reset view</button>
      </div>

      <div className="ag-phase ag-mono" role="status" aria-live="polite">
        {loading ? <span>Scanning, <b>{livePlane != null ? Math.round(livePlane) : 0}%</b></span> : null}
      </div>

      <div className="ag-hint">
        <div>
          {hovered
            ? `${SEVERITY_LABEL[hovered.sev]}: ${hovered.finding.issue_type}, ${hovered.tileId}:${hovered.finding.line_start}, ${Math.round((hovered.finding.confidence ?? 0) * 100)}% confidence`
            : DEFAULT_HINT}
        </div>
        {notes.map((n) => <div key={n}>{n}</div>)}
        {result && !loading && !error && scene.totalFindings === 0 && (
          <div>The floor is clear: {files} {files === 1 ? 'file' : 'files'} analysed, no findings.</div>
        )}
      </div>

      <div className="ag-legend" aria-label="Severity legend">
        {SEV_LEGEND.map((s) => (
          <span key={s}><i className={`ag-sq s-${s}`} />{SEVERITY_LABEL[s]}</span>
        ))}
      </div>

      {result && !loading && !error && (
        <div className="ag-titleblock ag-mono">
          <div>Target</div><div title={result.target_path}>{String(result.target_path).replace(/\\/g, '/')}</div>
          <div>Scan</div><div>{String(result.scan_id).slice(0, 8)}</div>
          <div>Files</div><div>{files} analysed, {filesWithFindings} with findings</div>
          <div>Duration</div><div>{(result.scan_duration_seconds ?? 0).toFixed(1)} s</div>
        </div>
      )}

      {(noScan || error) && (
        <div className="ag-overlay">
          {error ? (
            <div role="alert">
              <ScanErrorBody error={error} onRetry={onRun} as="h2" />
            </div>
          ) : (
            <div>
              <h2>No scan yet</h2>
              <p>
                {hosted
                  ? 'Choose a folder or enter a Git URL in the command bar, then run a scan. Code is scanned with static analysis only, never kept: uploaded folders are deleted after 30 minutes and cloned repositories right after the scan.'
                  : 'Set a target in the command bar and run a scan. The floor fills in with one tile per file that has findings.'}
              </p>
              <button type="button" className="ag-btn ag-btn--primary" onClick={onRun}>Run scan</button>
            </div>
          )}
        </div>
      )}
    </section>
  )
}
