import { useEffect, useRef } from 'react'
import { prefersReducedMotion } from '../lib/useRaf'

const nf = new Intl.NumberFormat('en', { maximumFractionDigits: 1, minimumFractionDigits: 1 })
const DURATION = 1100
const easeOut = (t) => 1 - (1 - t) ** 4

/**
 * The scan-complete reveal: the score counts up from 0 with a decelerating ease, once per result
 * (the parent keys it by scan id). The text node is written directly, so the count-up does not
 * re-render React 60 times a second. Reduced motion shows the final number at once.
 * The surrounding element carries the accessible label, so screen readers never hear the count.
 */
export default function ScoreNumber({ value }) {
  const ref = useRef(null)
  useEffect(() => {
    const el = ref.current
    if (!el) return undefined
    if (prefersReducedMotion()) {
      el.textContent = nf.format(value)
      return undefined
    }
    let raf = 0
    const t0 = performance.now()
    const tick = (now) => {
      const t = Math.min(1, (now - t0) / DURATION)
      el.textContent = nf.format(value * easeOut(t))
      if (t < 1) raf = requestAnimationFrame(tick)
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [value])
  return <span ref={ref} className="ag-scorenum" aria-hidden="true">{nf.format(value)}</span>
}
