import { useScan } from '../../context/ScanContext'
import ScanErrorBody from './ScanErrorBody'

/**
 * Shared loading / error / empty states for the list pages. Returns null when the scan has data,
 * so a page can write: const gate = usePageGate('Title'); if (gate) return gate.
 */
export function usePageGate(title, needsFindings = true) {
  const { scanResult, scanning, scanError, startScan } = useScan()

  if (scanning) {
    return (
      <div className="ag-state" role="status">
        <h2>{title}</h2>
        <p>A scan is running. Results appear here when it finishes.</p>
        {Array.from({ length: 5 }, (_, i) => <span key={i} className="ag-skel-bar" style={{ width: `${90 - i * 8}%`, height: 14 }} />)}
      </div>
    )
  }
  if (scanError) {
    return (
      <div className="ag-state err" role="alert">
        <h2>{title}</h2>
        <ScanErrorBody error={scanError} onRetry={startScan} />
      </div>
    )
  }
  if (!scanResult) {
    return (
      <div className="ag-state">
        <h2>{title}</h2>
        <h3>No scan yet</h3>
        <p>Run a scan from the command bar to fill this page.</p>
        <button type="button" className="ag-btn ag-btn--primary" onClick={startScan}>Run scan</button>
      </div>
    )
  }
  if (needsFindings && !scanResult.findings?.length) {
    return (
      <div className="ag-state">
        <h2>{title}</h2>
        <h3>No findings in this scan</h3>
        <p>Nothing was reported in {scanResult.files_analyzed} analysed {scanResult.files_analyzed === 1 ? 'file' : 'files'}.</p>
      </div>
    )
  }
  return null
}
