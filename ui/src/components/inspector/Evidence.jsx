import { useEffect, useRef, useState } from 'react'
import { SEVERITY_LABEL, CATEGORY_LABEL, normSeverity, normCategory, sourceLabel } from '../../constants'
import { relPath } from '../../lib/paths'
import { highlight, parseDiff } from './highlight.jsx'

function Code({ children }) {
  return <pre className="ag-code">{children}</pre>
}

export default function Evidence({ finding, result, scanning }) {
  const [msg, setMsg] = useState(null)
  const timer = useRef(0)
  useEffect(() => () => clearTimeout(timer.current), [])
  useEffect(() => { setMsg(null) }, [finding?.id])

  if (scanning) {
    return <div className="ag-state" role="status"><h3>Scan in progress</h3><p>Evidence is available once the scan completes.</p></div>
  }
  if (!finding) {
    return (
      <div className="ag-state">
        <h3>Select a finding</h3>
        <p>Pick a pin on the canvas or a row in the Findings tab. Its evidence, the reason it was raised and a suggested fix appear here.</p>
      </div>
    )
  }

  const sev = normSeverity(finding.severity)
  const loc = `${relPath(finding.file_path, result?.target_path)}:${finding.line_start}${finding.line_end && finding.line_end !== finding.line_start ? `-${finding.line_end}` : ''}`
  const start = Number.isFinite(finding.line_start) && finding.line_start > 0 ? finding.line_start : null
  const rawLines = String(finding.evidence ?? '').replace(/\r\n/g, '\n').split('\n')
  // Some tools (bandit) already prefix each snippet line with its line number: use those, do not number twice.
  const embedded = rawLines.some((l) => l.trim()) && rawLines.filter((l) => l.trim()).every((l) => /^\s*\d+(\s|$)/.test(l))
  const evidenceLines = rawLines
    .map((l, i) => {
      const m = embedded ? l.match(/^\s*(\d+)(?:\s(.*))?$/) : null
      return m ? { n: Number(m[1]), text: m[2] ?? '' } : { n: start ? start + i : null, text: l }
    })
    .filter((l, i, a) => !(embedded && l.text.trim() === '' && i === a.length - 1))
  const diff = finding.fix_patch ? parseDiff(finding.fix_patch) : null
  const fixText = finding.fix_patch || finding.suggested_fix || ''

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(fixText)
      setMsg({ ok: true, text: finding.fix_patch ? 'Patch copied' : 'Fix copied' })
    } catch {
      setMsg({ ok: false, text: 'Copy blocked by the browser' })
    }
    clearTimeout(timer.current)
    timer.current = setTimeout(() => setMsg(null), 2200)
  }

  return (
    <div className="ag-detail">
      <span className="ag-sevline">
        <i className={`ag-sq s-${sev}`} style={{ color: `var(--sev-${sev})` }} />
        {SEVERITY_LABEL[sev]}, {CATEGORY_LABEL[normCategory(finding.category)]}
      </span>
      <h3>{finding.issue_type}</h3>
      <div className="ag-facts">
        <div>Confidence<b>{Math.round((finding.confidence ?? 0) * 100)}%</b></div>
        <div>Location<b>{loc}</b></div>
        <div>Source<b>{sourceLabel(finding.rule_source)}</b></div>
      </div>
      {finding.explanation && <p>{finding.explanation}</p>}
      <div>
        <div className="ag-sub-h">Evidence</div>
        {finding.evidence ? (
          <Code>
            {evidenceLines.map((l, i) => (
              <span
                key={i}
                className={!embedded || (l.n >= finding.line_start && l.n <= (finding.line_end ?? finding.line_start)) ? 'hit' : undefined}
                style={{ '--sev': `var(--sev-${sev})` }}
              >
                <span className="ln">{l.n ?? ''}</span>{highlight(l.text)}
              </span>
            ))}
          </Code>
        ) : <p>No code snippet was captured for this finding.</p>}
      </div>
      <div>
        <div className="ag-sub-h">Suggested fix</div>
        {diff ? (
          <Code>
            {diff.map((l, i) => (
              <span key={i} className={l.kind === 'add' ? 'add' : l.kind === 'del' ? 'del' : ''}>
                {l.kind === 'hunk'
                  ? <span className="c">{l.text}</span>
                  : <><span className="sign">{l.kind === 'add' ? '+' : l.kind === 'del' ? '-' : ' '}</span>{highlight(l.text)}</>}
              </span>
            ))}
          </Code>
        ) : finding.suggested_fix ? (
          <Code>
            {String(finding.suggested_fix).replace(/\r\n/g, '\n').split('\n').map((l, i) => (
              <span key={i} className="add"><span className="sign">+</span>{highlight(l)}</span>
            ))}
          </Code>
        ) : <p>No fix was suggested for this finding.</p>}
      </div>
      <div className="ag-actions">
        <button type="button" className="ag-btn ag-btn--primary" onClick={copy} disabled={!fixText}>
          {finding.fix_patch || !fixText ? 'Copy patch' : 'Copy fix'}
        </button>
        <span className={`ag-confirm${msg && !msg.ok ? ' bad' : ''}`} role="status">{msg?.text}</span>
      </div>
    </div>
  )
}
