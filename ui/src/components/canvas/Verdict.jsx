import { scoreLabel, verdictSentence, previousScan, scoreDelta } from '../../lib/verdict'

const nf = new Intl.NumberFormat('en', { maximumFractionDigits: 1, minimumFractionDigits: 1 })

function Skeleton() {
  return (
    <div role="status" aria-label="Scan in progress, score not ready">
      <div className="ag-label">Security score</div>
      <span className="ag-skel-bar" style={{ width: 200, height: 72, marginTop: 12 }} />
      <span className="ag-skel-bar" style={{ width: '100%', height: 24, marginTop: 16 }} />
      <span className="ag-skel-bar" style={{ width: 240, height: 18, marginTop: 16 }} />
    </div>
  )
}

function DeltaLine({ result, history, historyStatus }) {
  const prev = previousScan(history, result)
  const d = scoreDelta(result.security_score, prev?.security_score)
  if (d === null) {
    const text = historyStatus === 'loading' ? 'Checking history' : historyStatus === 'error' ? 'History unavailable' : 'No earlier scan of this target'
    return <span className="ag-delta ag-mono">{text}</span>
  }
  if (d === 0) return <span className="ag-delta ag-mono">No change since last scan</span>
  return (
    <span className={`ag-delta ag-mono ${d < 0 ? 'worse' : 'better'}`}>
      {d < 0 ? 'Down' : 'Up'} {nf.format(Math.abs(d))} since last scan
    </span>
  )
}

/** The verdict block drawn on the canvas. Every number comes from the ScanResult or /api/history. */
export default function Verdict({ result, scanning, error, history, historyStatus }) {
  if (scanning) return <div className="ag-score"><Skeleton /></div>

  const has = result && result.security_score != null
  const sec = has ? result.security_score : null
  const opt = result?.optimization_score

  return (
    <div className="ag-score">
      <div className="ag-label">Security score</div>
      <div className="ag-hero" aria-label={has ? `Security score ${nf.format(sec)} out of 100` : 'No score yet'}>
        {has ? nf.format(sec) : '--'}
        <small>/ 100</small>
      </div>
      <div className="ag-ruler" aria-hidden="true">
        {has && <i style={{ '--v': Math.min(1, Math.max(0, sec / 100)) }} />}
      </div>
      <div className="ag-ruler-labels ag-mono" aria-hidden="true"><span>0</span><span>50</span><span>100</span></div>
      <p className="ag-verdict">
        {error ? 'The scan did not finish.' : result ? verdictSentence(result.findings) : 'Run a scan to see a verdict.'}
      </p>
      {result && !error && <DeltaLine result={result} history={history} historyStatus={historyStatus} />}
      <div className="ag-opt">
        <span className="ag-label">Optimization</span>
        <span />
        <span>
          <span className="ag-num">{opt != null ? nf.format(opt) : '--'}</span>{' '}
          <span className="ag-muted" style={{ fontSize: 'var(--text-sm)' }}>{scoreLabel(opt)}</span>
        </span>
      </div>
    </div>
  )
}
