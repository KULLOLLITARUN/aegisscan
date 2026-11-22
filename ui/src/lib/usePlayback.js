import { useCallback, useEffect, useRef, useState } from 'react'
import { useRaf, prefersReducedMotion } from './useRaf'

export const REPLAY_SPEED = 4

/**
 * Replay clock for a finished scan. The exact time lives in a ref and is pushed to subscribers every
 * frame (for smooth CSS-variable updates); React state only follows at 0.1 s resolution.
 * Under prefers-reduced-motion the replay does not auto-play and starts at the end state.
 */
export function usePlayback(total, resetKey) {
  const tRef = useRef(0)
  const playRef = useRef(false)
  const totalRef = useRef(total)
  const listeners = useRef(new Set())
  const [t, setT] = useState(0)
  const [playing, setPlaying] = useState(false)

  useEffect(() => {
    totalRef.current = total
  }, [total])

  const emit = useCallback(() => {
    listeners.current.forEach((fn) => fn(tRef.current))
    const q = Math.round(tRef.current * 10) / 10
    setT((prev) => (prev === q ? prev : q))
  }, [])

  const subscribe = useCallback((fn) => {
    listeners.current.add(fn)
    fn(tRef.current)
    return () => listeners.current.delete(fn)
  }, [])

  const seek = useCallback((v) => {
    tRef.current = Math.max(0, Math.min(totalRef.current, v))
    playRef.current = false
    setPlaying(false)
    emit()
  }, [emit])

  const play = useCallback(() => {
    if (tRef.current >= totalRef.current) tRef.current = 0
    playRef.current = true
    setPlaying(true)
    emit()
  }, [emit])

  const pause = useCallback(() => {
    playRef.current = false
    setPlaying(false)
  }, [])

  // A new scan result restarts the replay (or jumps to the end state for reduced motion).
  useEffect(() => {
    const auto = !prefersReducedMotion() && totalRef.current > 0
    tRef.current = auto ? 0 : totalRef.current
    playRef.current = auto
    setPlaying(auto)
    emit()
  }, [resetKey, emit])

  useRaf((_now, dt) => {
    if (!playRef.current) return
    tRef.current = Math.min(totalRef.current, tRef.current + dt * REPLAY_SPEED)
    if (tRef.current >= totalRef.current) {
      playRef.current = false
      setPlaying(false)
    }
    emit()
  })

  return { t, playing, play, pause, seek, subscribe }
}
