import { useState } from 'react'
import { useScan } from '../../context/ScanContext'
import { authHeaders } from '../../lib/api'

/** Hosted mode: asks for the access token before anything else. The token is checked against the server. */
export default function TokenGate() {
  const { needsToken, setToken, authError, setAuthError } = useScan()
  const [value, setValue] = useState('')
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')

  if (!needsToken) return null

  const submit = async (e) => {
    e.preventDefault()
    const candidate = value.trim()
    if (!candidate) return
    setBusy(true)
    setMessage('')
    try {
      const res = await fetch('/api/history', { headers: authHeaders(candidate) })
      if (res.status === 401) setMessage('That token was not accepted.')
      else if (res.ok) {
        setAuthError('')
        setToken(candidate)
      } else setMessage(`The server answered with an error (${res.status}).`)
    } catch {
      setMessage('Could not reach the server.')
    } finally {
      setBusy(false)
    }
  }

  const shown = message || authError
  return (
    <>
      <div className="ag-scrim" />
      <form className="ag-gate" role="dialog" aria-modal="true" aria-labelledby="ag-gate-title" onSubmit={submit}>
        <h2 id="ag-gate-title">Enter the access token</h2>
        <p className="ag-muted">This scanner is private. Ask whoever runs it for the access token.</p>
        <label className="visually-hidden" htmlFor="ag-token">Access token</label>
        <input
          id="ag-token"
          className="ag-input ag-mono"
          type="password"
          autoComplete="off"
          autoFocus
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder="Access token"
        />
        {shown && <p className="ag-error" role="alert">{shown}</p>}
        <button type="submit" className="ag-btn ag-btn--primary" disabled={busy || !value.trim()}>
          {busy ? 'Checking' : 'Continue'}
        </button>
      </form>
    </>
  )
}
