import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { authHeaders, toApiError } from './api'
import { diffResults, findingKey } from './findingKey'
import { parseTs } from './time'
import { normPath } from './paths'

const sameTarget = (a, b) => normPath(a).toLowerCase() === normPath(b).toLowerCase()

/**
 * What the local server keeps between page loads: the last result (restored on reload), past results
 * (opened from History), the previous scan of the same target (for new / fixed) and triage decisions.
 * Hosted mode keeps none of it, so every function here is a no-op there.
 */
export function useLocalState({ enabled, token, scanResult, setScanResult, scanning, history, log }) {
  const [diff, setDiff] = useState(null) // { prevId, newIds: Set, fixed: [] }
  const [triage, setTriageMap] = useState({}) // { findingKey: 'false_positive' | 'accepted' }
  const restored = useRef(false)

  // Restore the last kept result once, if the page opened without one.
  useEffect(() => {
    if (!enabled || restored.current || scanResult || scanning) return
    restored.current = true
    fetch('/api/last', { headers: authHeaders(token) })
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (data?.scan_id) {
          setScanResult((cur) => cur ?? data)
          log('info', 'Restored the last scan. Run a new scan to refresh it.')
        }
      })
      .catch(() => {})
  }, [enabled, token, scanResult, scanning, setScanResult, log])

  const openScan = useCallback(async (scanId) => {
    const res = await fetch(`/api/scan/${encodeURIComponent(scanId)}`, { headers: authHeaders(token) })
    if (!res.ok) throw await toApiError(res)
    const data = await res.json()
    setScanResult(data)
    return data
  }, [token, setScanResult])

  // New / fixed against the previous kept scan of the same target.
  useEffect(() => {
    setDiff(null)
    if (!enabled || !scanResult) return undefined
    const at = parseTs(scanResult.scan_timestamp)
    const prev = (history ?? []).find((h) => h.has_result && h.scan_id !== scanResult.scan_id
      && sameTarget(h.target_path, scanResult.target_path) && (!at || (parseTs(h.timestamp) ?? 0) < at))
    if (!prev) return undefined
    let cancelled = false
    fetch(`/api/scan/${encodeURIComponent(prev.scan_id)}`, { headers: authHeaders(token) })
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (!cancelled && data?.findings) setDiff({ prevId: prev.scan_id, ...diffResults(scanResult, data) })
      })
      .catch(() => {})
    return () => { cancelled = true }
  }, [enabled, scanResult, history, token])

  // Triage decisions for the current target.
  const target = scanResult?.target_path
  useEffect(() => {
    setTriageMap({})
    if (!enabled || !target) return undefined
    let cancelled = false
    fetch(`/api/triage?target=${encodeURIComponent(target)}`, { headers: authHeaders(token) })
      .then((res) => (res.ok ? res.json() : {}))
      .then((data) => { if (!cancelled) setTriageMap(data || {}) })
      .catch(() => {})
    return () => { cancelled = true }
  }, [enabled, target, token])

  const setTriage = useCallback(async (finding, status) => {
    const key = findingKey(finding, target)
    const res = await fetch('/api/triage', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders(token) },
      body: JSON.stringify({ target, key, status }),
    })
    if (!res.ok) throw await toApiError(res)
    setTriageMap(await res.json())
  }, [target, token])

  const triageOf = useCallback((f) => (enabled && target ? triage[findingKey(f, target)] ?? null : null), [enabled, target, triage])

  return useMemo(
    () => ({ openScan, diff, triageOf, setTriage, canKeep: enabled }),
    [openScan, diff, triageOf, setTriage, enabled],
  )
}
