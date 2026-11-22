import { scoreLabel, verdictSentence, previousScan, scoreDelta } from '../../lib/verdict'

const nf = new Intl.NumberFormat('en', { maximumFractionDigits: 1, minimumFractionDigits: 1 })

function Live({ steps, liveSec }) {
  return (
    <div role="status" aria-label="Scan in progress, score not ready">
      <div className="ag-label">Security score</div>
      <div className="ag-live-head">
        <span className="ag-hero ag-live-hero">Scanning<small className="ag-mono">{Math.floor(liveSec)} s</small></span>
        <p className="ag-live-note">The score appears when the scan finishes. Some steps, like Semgrep, can take a few minutes.</p>
      </div>
      <ol className="ag-steps ag-mono" aria-label="Scan steps so far">
        {steps.map((s, i) => {
          const active = i === steps.length - 1
          return (
            <li key={s} className={active ? 'active' : 'done'}>
              <span className="ag-step-mark" aria-hidden="true">{active ? '>' : '+'}</span>
              <span>{s}</span>
              <span className="ag-step-state">{active ? 'running' : 'done'}</span>
            </li>
          )
        })}
      </ol>
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
export default function Verdict({ result, scanning, error, history, historyStatus, steps = [], liveSec = 0 }) {
  if (scanning) return <div className="ag-score"><Live steps={steps} liveSec={liveSec} /></div>

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
