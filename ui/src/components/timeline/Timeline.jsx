import { useRef } from 'react'
import { segmentAt } from '../../lib/timeline'
import { REPLAY_SPEED } from '../../lib/usePlayback'

const f1 = (v) => (Math.round(v * 10) / 10).toFixed(1)

/**
 * Scrubbable scan timeline. Segments and markers come from the progress and log events the stream
 * actually reported. Live: follows the scan. After a scan: replays at 4x and can be scrubbed.
 */
export default function Timeline({ tl, playback, trackRef, scanning, liveSec, hasResult, error }) {
  const scrubbing = useRef(false)
  const { t, playing, play, pause, seek } = playback

  const canScrub = hasResult && !scanning && tl.total > 0
  const total = scanning ? liveSec : tl.total

  const seekFromPointer = (e) => {
    const r = trackRef.current.getBoundingClientRect()
    seek(Math.max(0, Math.min(1, (e.clientX - r.left) / r.width)) * tl.total)
  }
  const onPointerDown = (e) => {
    if (!canScrub) return
    scrubbing.current = true
    trackRef.current.setPointerCapture(e.pointerId)
    seekFromPointer(e)
  }
  const onPointerMove = (e) => { if (scrubbing.current) seekFromPointer(e) }
  const onPointerUp = () => { scrubbing.current = false }
  const onKeyDown = (e) => {
    if (!canScrub) return
    const step = e.shiftKey ? 5 : 1
    if (e.key === 'ArrowRight' || e.key === 'ArrowUp') seek(t + step)
    else if (e.key === 'ArrowLeft' || e.key === 'ArrowDown') seek(t - step)
    else if (e.key === 'Home') seek(0)
    else if (e.key === 'End') seek(tl.total)
    else if (e.key === ' ') { if (playing) pause(); else play() }
    else return
    e.preventDefault()
  }

  let note = null
  if (error && !scanning) note = 'The scan did not finish, so there is no timeline to replay.'
  else if (!hasResult && !scanning) note = 'Run a scan to record its timeline here.'
  else if (hasResult && tl.total <= 0) note = 'No timing was recorded for this scan.'

  const seg = segmentAt(tl.segments, scanning ? total : t)
  const ticks = total > 0 ? [0, 0.25, 0.5, 0.75, 1].map((q) => q * total) : []
  const clock = scanning
    ? `+${f1(liveSec)} s, scanning`
    : hasResult && tl.total > 0 ? `+${f1(t)} s of ${f1(tl.total)} s` : '+0.0 s'
  const valueText = seg ? `${f1(t)} seconds, ${seg.name}` : `${f1(t)} seconds`

  return (
    <section className="ag-timeline" aria-label="Scan timeline">
      <div className="ag-tl-ctl">
        <button
          type="button"
          className="ag-btn ag-btn--sm"
          disabled={!canScrub}
          onClick={() => (playing ? pause() : play())}
          title={`Replays at ${REPLAY_SPEED} times real speed`}
        >
          {playing ? 'Pause replay' : t >= tl.total && canScrub ? 'Replay scan' : 'Resume replay'}
        </button>
        <span className="ag-clock ag-mono">{clock}</span>
      </div>
      <div className="ag-tl-main">
        {note ? (
          <p className="ag-tl-note" role={error ? 'alert' : undefined}>{note}</p>
        ) : (
          <>
            <div
              ref={trackRef}
              className="ag-track"
              tabIndex={canScrub ? 0 : -1}
              role="slider"
              aria-label="Scan time, drag or use the arrow keys to replay"
              aria-valuemin={0}
              aria-valuemax={Number(f1(total))}
              aria-valuenow={Number(f1(scanning ? liveSec : t))}
              aria-valuetext={scanning ? `${f1(liveSec)} seconds, scanning` : valueText}
              aria-disabled={!canScrub}
              style={scanning ? { '--p': 100 } : undefined}
              onPointerDown={onPointerDown}
              onPointerMove={onPointerMove}
              onPointerUp={onPointerUp}
              onPointerCancel={onPointerUp}
              onKeyDown={onKeyDown}
            >
              <div className="ag-done" />
              {tl.hasPhases ? tl.segments.map((s, i) => {
                const w = (s.end - s.start) / (total || 1)
                return (
                  <div key={`${s.name}-${i}`} className="ag-seg-bar" style={{ left: `${(s.start / (total || 1)) * 100}%`, width: `${w * 100}%`, '--tint': `${8 + (i % 3) * 6}%` }}>
                    {w > 0.12 ? s.name : ''}
                  </div>
                )
              }) : (
                <div className="ag-seg-bar" style={{ left: 0, width: '100%' }}>Scan, no phase detail reported</div>
              )}
              {tl.markers.map((m, i) => (
                <i key={i} className={`ag-marker${m.level === 'err' ? ' err' : ''}`} style={{ left: `${(m.t / (total || 1)) * 100}%` }} title={`${f1(m.t)} s ${m.message}`} />
              ))}
              <div className="ag-head" />
            </div>
            <div className="ag-axis ag-mono" aria-hidden="true">
              {ticks.map((v, i) => <span key={i} style={{ left: `${(v / (total || 1)) * 100}%` }}>{f1(v)} s</span>)}
            </div>
          </>
        )}
      </div>
    </section>
  )
}
