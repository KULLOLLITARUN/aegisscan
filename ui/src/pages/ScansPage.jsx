import { useEffect, useMemo, useState } from 'react'
import { useScan } from '../context/ScanContext'
import { SEVERITY_LABEL } from '../constants'
import { formatScore, scoreStatus, statusVar } from '../lib/score'
import { scoreLabel } from '../lib/verdict'
import TrendChart from '../components/history/TrendChart'
import { parseTs } from '../lib/time'
import { normPath } from '../lib/paths'
import { withTransition } from '../lib/transition'
import { useToast } from '../context/ToastContext'
import { useNavigate } from 'react-router-dom'

const when = new Intl.DateTimeFormat('en-GB', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' })
const norm = normPath
const short = (p) => norm(p).split('/').slice(-2).join('/')

function summary(status, rows, targets) {
  if (status === 'loading') return 'Loading scan history'
  if (status === 'error') return 'Scan history could not be loaded'
  const s = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`
  return `${s(rows, 'scan')} of ${s(targets, 'target')}, newest first. Click a scan to open it.`
}

function Score({ value }) {
  const st = scoreStatus(value)
  if (st == null) return <span className="ag-muted">--</span>
  return (
    <span className="ag-score-cell">
      <i className="ag-dot" style={{ '--c': statusVar(st) }} aria-hidden="true" />
      <span className="ag-num">{formatScore(value)}</span>
      <span className="ag-muted">{scoreLabel(value)}</span>
    </span>
  )
}

function Severities({ row }) {
  const parts = [['critical', row.critical_count], ['high', row.high_count]].filter(([, n]) => n > 0)
  return (
    <span className="ag-sevmini">
      <span className="ag-num">{row.total_findings}</span>
      {parts.map(([s, n]) => (
        <span key={s} className="ag-sevmini-part" title={`${n} ${SEVERITY_LABEL[s]}`}>
          <i className={`ag-sq s-${s}`} aria-hidden="true" />
          <span className="ag-num">{n}</span>
          <span className="visually-hidden">{SEVERITY_LABEL[s]}</span>
        </span>
      ))}
    </span>
  )
}

export default function ScansPage() {
  const { history, fetchHistory, historyStatus, openScan } = useScan()
  const { toast } = useToast()
  const navigate = useNavigate()
  useEffect(() => { fetchHistory() }, [fetchHistory])

  const open = async (row) => {
    if (!row.has_result) {
      toast('Only the 30 most recent scans keep their details. Run the scan again to see this one.', 'err')
      return
    }
    try {
      await openScan(row.scan_id)
      withTransition(() => navigate('/dashboard'))
    } catch (err) {
      toast(err?.message || 'Could not open that scan', 'err')
    }
  }

  const rows = useMemo(() => history.map((h) => ({ ...h, ts: parseTs(h.timestamp) })), [history])
  const targets = useMemo(() => [...new Set(rows.map((r) => norm(r.target_path)))], [rows])
  const [target, setTarget] = useState('')
  const current = target && targets.includes(target) ? target : targets[0] || ''

  const forTarget = useMemo(() => rows.filter((r) => norm(r.target_path) === current), [rows, current])
  const points = useMemo(
    () => forTarget.filter((r) => r.ts && r.security_score != null).map((r) => ({ id: r.scan_id, ts: r.ts, score: r.security_score })).reverse(),
    [forTarget],
  )
  const listed = target === '*' ? rows : forTarget

  return (
    <div className="ag-pagebody">
      <header className="ag-pagehead">
        <h1>History</h1>
        <p className="ag-muted" role="status">
          {summary(historyStatus, rows.length, targets.length)}
        </p>
      </header>

      {historyStatus === 'ready' && !rows.length && (
        <div className="ag-state">
          <h3>No scans recorded yet</h3>
          <p>Every finished local scan is recorded here with its scores, so you can follow a project over time.</p>
        </div>
      )}

      {rows.length > 0 && (
        <>
          <div className="ag-toolbar">
            <label className="ag-field-inline" htmlFor="ag-h-target">
              <span className="ag-muted">Target</span>
              <select id="ag-h-target" className="ag-input" value={target === '*' ? '*' : current} onChange={(e) => setTarget(e.target.value)}>
                {targets.map((t) => <option key={t} value={t}>{short(t)}</option>)}
                <option value="*">All targets (table only)</option>
              </select>
            </label>
          </div>

          {target !== '*' && (
            <section className="ag-box ag-trendbox" aria-labelledby="ag-trend-h">
              <div className="ag-trendhead">
                <h2 id="ag-trend-h">Security score</h2>
                <span className="ag-muted ag-mono" title={current}>{short(current)}</span>
              </div>
              {points.length >= 2
                ? <TrendChart points={points} onPick={(pt) => { const row = forTarget.find((r) => r.scan_id === pt.id); if (row) void open(row) }} />
                : <p className="ag-muted ag-trend-note">One scan of this target so far. The trend appears after the next one.</p>}
            </section>
          )}

          <div className="ag-tablewrap">
            <table className="ag-table">
              <thead>
                <tr>
                  <th scope="col">Date</th>
                  {target === '*' && <th scope="col">Target</th>}
                  <th scope="col">Findings</th>
                  <th scope="col">Security score</th>
                  <th scope="col">Optimization</th>
                  <th scope="col" className="ag-right">Files</th>
                  <th scope="col" className="ag-right">Duration</th>
                </tr>
              </thead>
              <tbody>
                {listed.map((h, i) => (
                  <tr key={h.scan_id} style={{ '--i': i }} className={h.has_result ? undefined : 'ag-row-dim'} onClick={() => void open(h)}>
                    <td className="ag-nowrap">
                      <button type="button" className="ag-link ag-mono" onClick={(e) => { e.stopPropagation(); void open(h) }}
                        title={h.has_result ? 'Open this scan' : 'Details not kept'}>
                        {h.ts ? when.format(h.ts) : '--'}
                      </button>
                    </td>
                    {target === '*' && <td className="ag-mono ag-loc" title={h.target_path}>{short(h.target_path)}</td>}
                    <td><Severities row={h} /></td>
                    <td><Score value={h.security_score} /></td>
                    <td><Score value={h.optimization_score} /></td>
                    <td className="ag-right ag-mono">{h.files_analyzed ?? '--'}</td>
                    <td className="ag-right ag-mono">{h.duration_seconds != null ? `${h.duration_seconds.toFixed(1)} s` : '--'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  )
}
