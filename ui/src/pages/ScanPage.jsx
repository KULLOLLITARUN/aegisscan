import { useEffect, useMemo, useRef, useState, useCallback } from 'react'
import { useScan } from '../context/ScanContext'
import { buildScene, buildLiveScene } from '../lib/scene'
import { buildTimeline, pctAt } from '../lib/timeline'
import { usePlayback } from '../lib/usePlayback'
import ScanCanvas from '../components/canvas/ScanCanvas'
import Timeline from '../components/timeline/Timeline'
import Inspector from '../components/inspector/Inspector'
import { liveSteps } from '../lib/steps'

/** Scan view: canvas with verdict, scrubbable timeline and the docked inspector. */
export default function ScanPage() {
  const {
    scanResult, scanning, scanError, logs, history, historyStatus, recording, progress, liveFiles, liveHits,
    selectedId, setSelectedId, startScan,
  } = useScan()
  const [tab, setTab] = useState('queue')
  const [hoverId, setHoverId] = useState(null)
  const planeRef = useRef(null)
  const steps = useMemo(() => (scanning ? liveSteps(recording.events) : []), [scanning, recording.events])
  const trackRef = useRef(null)

  // Show the live activity while a scan runs; the queue is empty until it finishes.
  useEffect(() => { if (scanning) setTab('activity') }, [scanning])

  const scene = useMemo(() => buildScene(scanResult), [scanResult])
  // While scanning, the floor is the real file list the scanner streams, not the (still empty) result.
  const liveScene = useMemo(() => (scanning && liveFiles?.files?.length ? buildLiveScene(liveFiles) : null), [scanning, liveFiles])

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
  // Live: the sweep follows the scanner's real progress percentage across the floor. The scanner reports
  // progress per tool, not per file, so which tile lights when is an illustration of that progress.
  const livePlaneX = liveScene ? (Math.min(100, progress.pct) / 100) * liveScene.floorW : 0
  const tilesDone = useMemo(
    () => new Set((liveScene ? liveScene.tiles : scene.tiles).filter((t) => t.x + t.w <= (liveScene ? livePlaneX : planeX)).map((t) => t.id)),
    [liveScene, scene.tiles, planeX, livePlaneX],
  )

  const onSelect = useCallback((id) => {
    setSelectedId(id)
    if (id) setTab('evidence')
  }, [setSelectedId])

  return (
    <>
      <main className="ag-canvas">
        <ScanCanvas
          scene={scene}
          liveScene={liveScene}
          liveHits={liveHits}
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
          phase={scanning ? progress.phase : ''}
          steps={steps}
          liveSec={liveSec}
          onRun={startScan}
        />
        <Timeline
          tl={tl}
          playback={playback}
          trackRef={trackRef}
          scanning={scanning}
          liveSec={liveSec}
          liveHits={liveHits}
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
