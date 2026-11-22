import { useEffect, useRef } from 'react'

/**
 * Runs cb(now, dtSeconds) on every animation frame, and stops the loop entirely
 * while the tab is hidden (resuming without a time jump when it becomes visible).
 */
export function useRaf(cb) {
  const ref = useRef(cb)
  useEffect(() => {
    ref.current = cb
  })

  useEffect(() => {
    let id = 0
    let last = 0
    const loop = (now) => {
      const dt = Math.min(0.1, (now - last) / 1000)
      last = now
      ref.current(now, dt)
      id = requestAnimationFrame(loop)
    }
    const start = () => {
      if (id) return
      last = performance.now()
      id = requestAnimationFrame(loop)
    }
    const stop = () => {
      if (!id) return
      cancelAnimationFrame(id)
      id = 0
    }
    const onVisibility = () => (document.hidden ? stop() : start())
    document.addEventListener('visibilitychange', onVisibility)
    onVisibility()
    return () => {
      stop()
      document.removeEventListener('visibilitychange', onVisibility)
    }
  }, [])
}

export function prefersReducedMotion() {
  try {
    return window.matchMedia('(prefers-reduced-motion: reduce)').matches
  } catch {
    return false
  }
}
