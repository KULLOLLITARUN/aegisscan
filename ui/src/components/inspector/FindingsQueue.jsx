import { useMemo, useState } from 'react'
import { SEVERITIES, SEVERITY_LABEL, normSeverity, normCategory, CATEGORY_LABEL } from '../../constants'
import { relPath } from '../../lib/paths'
import { sortFindings } from '../../lib/scene'

const ROW_CAP = 300
const SORTERS = {
  sev: sortFindings,
  conf: (l) => [...l].sort((a, b) => (b.confidence ?? 0) - (a.confidence ?? 0)),
  file: (l) => [...l].sort((a, b) => String(a.file_path).localeCompare(String(b.file_path)) || (a.line_start ?? 0) - (b.line_start ?? 0)),
}

function Skeleton() {
  return (
    <div role="status" aria-label="Loading findings">
      {Array.from({ length: 7 }, (_, i) => <div className="ag-skel" key={i}><i /><i /><i /></div>)}
    </div>
  )
}

export default function FindingsQueue({ result, scanning, error, selectedId, onSelect, onRun, onShowActivity, onHover }) {
  const [query, setQuery] = useState('')
  const [sev, setSev] = useState('all')
  const [sort, setSort] = useState('sev')

  const findings = useMemo(() => result?.findings ?? [], [result])
  const counts = useMemo(() => {
    const c = {}
    for (const f of findings) c[normSeverity(f.severity)] = (c[normSeverity(f.severity)] || 0) + 1
    return c
  }, [findings])

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase()
    const filtered = findings.filter((f) => {
      if (sev !== 'all' && normSeverity(f.severity) !== sev) return false
      if (!q) return true
      const hay = `${f.issue_type} ${f.file_path} ${f.rule_source} ${CATEGORY_LABEL[normCategory(f.category)]}`.toLowerCase()
      return hay.includes(q)
    })
    return SORTERS[sort](filtered)
  }, [findings, query, sev, sort])

  if (scanning) return <Skeleton />
  if (error) {
    return (
      <div className="ag-state err" role="alert">
        <h3>The scan did not finish</h3>
        <p>{error}</p>
        <div className="ag-actions">
          <button type="button" className="ag-btn ag-btn--primary" onClick={onRun}>Retry scan</button>
          <button type="button" className="ag-btn" onClick={onShowActivity}>View activity</button>
        </div>
      </div>
    )
  }
  if (!result) {
    return (
      <div className="ag-state">
        <h3>No scan yet</h3>
        <p>Run a scan to list its findings here, worst first.</p>
        <button type="button" className="ag-btn ag-btn--primary" onClick={onRun}>Run scan</button>
      </div>
    )
  }
  if (!findings.length) {
    return (
      <div className="ag-state">
        <h3>No findings in this scan</h3>
        <p>Nothing was reported in {result.files_analyzed} analysed {result.files_analyzed === 1 ? 'file' : 'files'}. A deep scan sends every chunk to the LLM pass.</p>
      </div>
    )
  }

  const shown = rows.slice(0, ROW_CAP)
  return (
    <>
      <div className="ag-qtools">
        <div className="ag-row">
          <label className="visually-hidden" htmlFor="ag-q">Search findings</label>
          <input id="ag-q" className="ag-input" placeholder="Search issue, file or source" autoComplete="off" value={query} onChange={(e) => setQuery(e.target.value)} />
          <label className="visually-hidden" htmlFor="ag-sort">Sort by</label>
          <select id="ag-sort" className="ag-input" value={sort} onChange={(e) => setSort(e.target.value)}>
            <option value="sev">Severity</option>
            <option value="conf">Confidence</option>
            <option value="file">File</option>
          </select>
        </div>
        <div className="ag-chips" role="group" aria-label="Filter by severity">
          <button type="button" className="ag-chip" aria-pressed={sev === 'all'} onClick={() => setSev('all')}>All<span className="ag-num">{findings.length}</span></button>
          {SEVERITIES.filter((s) => counts[s]).map((s) => (
            <button type="button" key={s} className="ag-chip" aria-pressed={sev === s} onClick={() => setSev(s)}>
              <i className={`ag-sq s-${s}`} />{SEVERITY_LABEL[s]}<span className="ag-num">{counts[s]}</span>
            </button>
          ))}
        </div>
      </div>
      {rows.length ? (
        <ol>
          {shown.map((f) => {
            const s = normSeverity(f.severity)
            return (
              <li key={f.id}>
                <button
                  type="button"
                  className="ag-qrow"
                  aria-current={f.id === selectedId ? 'true' : undefined}
                  onClick={() => onSelect(f.id)}
                  onMouseEnter={() => onHover(f.id)}
                  onMouseLeave={() => onHover(null)}
                  onFocus={() => onHover(f.id)}
                  onBlur={() => onHover(null)}
                >
                  <span className="ag-g"><i className={`ag-sq s-${s}`} /><span className="visually-hidden">{SEVERITY_LABEL[s]}</span></span>
                  <span>
                    <span className="ag-issue">{f.issue_type}</span>
                    <span className="ag-sub">
                      <span className="ag-mono ag-loc">{relPath(f.file_path, result.target_path)}:{f.line_start}</span>
                      <span>{f.rule_source}</span>
                    </span>
                  </span>
                  <span className="ag-conf ag-mono">{Math.round((f.confidence ?? 0) * 100)}%</span>
                </button>
              </li>
            )
          })}
        </ol>
      ) : (
        <div className="ag-state">
          <h3>No findings match</h3>
          <p>Try a different severity or clear the search.</p>
          <button type="button" className="ag-btn" onClick={() => { setSev('all'); setQuery('') }}>Clear filters</button>
        </div>
      )}
      <div className="ag-qfoot">
        {rows.length} of {findings.length} findings{rows.length > ROW_CAP ? `, showing the first ${ROW_CAP}. Narrow the search to see the rest.` : '.'}
      </div>
    </>
  )
}
