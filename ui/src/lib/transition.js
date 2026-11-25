import { flushSync } from 'react-dom'
import { prefersReducedMotion } from './useRaf'

/**
 * Run a state change inside a View Transition (page switches, theme changes), so the browser
 * crossfades between the before and after pictures. Browsers without the API, and anyone who asks
 * for reduced motion, get the change instantly. flushSync makes React render inside the callback.
 */
export function withTransition(update) {
  if (typeof document === 'undefined' || !document.startViewTransition || prefersReducedMotion()) {
    update()
    return
  }
  document.startViewTransition(() => flushSync(update))
}

/** True for a plain left click (no modifier), the only click a link should take over. */
export const isPlainClick = (e) => e.button === 0 && !e.metaKey && !e.ctrlKey && !e.shiftKey && !e.altKey
