import { useEffect, useMemo, useRef, useState, useCallback } from 'react'
import { useScan } from '../context/ScanContext'
import { buildScene } from '../lib/scene'
import { buildTimeline, pctAt } from '../lib/timeline'
import { usePlayback } from '../lib/usePlayback'
import ScanCanvas from '../components/canvas/ScanCanvas'
import Timeline from '../components/timeline/Timeline'
import Inspector from '../components/inspector/Inspector'

/** Scan view: canvas with verdict, scrubbable timeline and the docked inspector. */
export default function ScanPage() {
  const {
    scanResult, scanning, scanError, logs, history, historyStatus, recording, progress,
    selectedId, setSelectedId, startScan,
  } = useScan()
  const [tab, setTab] = useState('queue')
  const [hoverId, setHoverId] = useState(null)
  const planeRef = useRef(null)
  const trackRef = useRef(null)

  const scene = useMemo(() => buildScene(scanResult), [scanResult])

  // Live elapsed time while the scan runs (the stream gives progress, not a clock).
  const [liveSec, setLiveSec] = useState(0)
  useEffect(() => {
    if (!scanning) return undefined
    const tick = () => setLiveSec(Math.max(0, (performance.now() - recording.startedAt) / 1000))
    tick()
    const id = setInterval(tick, 250)
    return () => clearInterval(id)
  }, [scanning, recording.startedAt])

  const tl = useMemo(
    () => (scanning
      ? buildTimeline({ events: recording.events, durationMs: liveSec * 1000 })
      : buildTimeline(recording, scanResult?.scan_duration_seconds)),
    [scanning, recording, liveSec, scanResult],
  )

  const playback = usePlayback(scanning ? 0 : tl.total, scanResult?.scan_id)
  const { subscribe } = playback

  // Smooth per-frame updates go straight to CSS variables (transform and opacity only).
  useEffect(() => {
    if (scanning) return undefined
    return subscribe((t) => {
      const pct = tl.total > 0 ? pctAt(tl.points, t) : 100
      const plane = planeRef.current
      if (plane) {
        plane.style.setProperty('--plane', String((pct / 100) * scene.floorW))
        plane.style.setProperty('--wo', pct <= 0 || pct >= 100 ? '0' : '1')
      }
      if (trackRef.current) trackRef.current.style.setProperty('--p', String(tl.total > 0 ? (t / tl.total) * 100 : 0))
    })
  }, [subscribe, tl, scene.floorW, scanning])

  // What the sweep has reached at the (0.1 s resolution) replay time.
  const planeX = tl.total > 0 ? (pctAt(tl.points, playback.t) / 100) * scene.floorW : scene.floorW
  const visible = useMemo(() => new Set(scene.pins.filter((p) => p.x <= planeX).map((p) => p.id)), [scene.pins, planeX])
  const tilesDone = useMemo(() => new Set(scene.tiles.filter((t) => t.x + t.w <= planeX).map((t) => t.id)), [scene.tiles, planeX])

  const onSelect = useCallback((id) => {
    setSelectedId(id)
    if (id) setTab('evidence')
  }, [setSelectedId])

  return (
    <>
      <main className="ag-canvas">
        <ScanCanvas
          scene={scene}
          result={scanResult}
          scanning={scanning}
          error={scanError}
          history={history}
          historyStatus={historyStatus}
          selectedId={selectedId}
          onSelect={onSelect}
          hoverId={hoverId}
          onHover={setHoverId}
          planeRef={planeRef}
          visible={visible}
          tilesDone={tilesDone}
          livePlane={scanning ? progress.pct : null}
          onRun={startScan}
        />
        <Timeline
          tl={tl}
          playback={playback}
          trackRef={trackRef}
          scanning={scanning}
          liveSec={liveSec}
          hasResult={!!scanResult && !scanError}
          error={scanError}
        />
      </main>
      <Inspector
        tab={tab}
        setTab={setTab}
        result={scanResult}
        scanning={scanning}
        error={scanError}
        logs={logs}
        selectedId={selectedId}
        onSelect={onSelect}
        onHover={setHoverId}
        onRun={startScan}
        nowSeconds={scanResult && !scanError ? playback.t : null}
      />
    </>
  )
}
