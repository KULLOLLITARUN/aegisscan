import { describeScanError, focusTarget } from '../../lib/errors'

/** Title, server message, a fix hint when one is known, and the right action (retry, or change the target). */
export default function ScanErrorBody({ error, onRetry, as: Heading = 'h3', children }) {
  const e = describeScanError(error)
  return (
    <>
      <Heading style={{ color: 'var(--bad)' }}>{e.title}</Heading>
      <p>{e.detail}</p>
      {e.hint && <p>{e.hint}</p>}
      <div className="ag-actions">
        {e.retryable ? (
          <button type="button" className="ag-btn ag-btn--primary" onClick={onRetry}>Retry scan</button>
        ) : (
          <button type="button" className="ag-btn ag-btn--primary" onClick={focusTarget}>Change target</button>
        )}
        {children}
      </div>
    </>
  )
}
