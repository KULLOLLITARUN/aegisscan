import { useMemo, useState } from 'react'
import { useScan } from '../context/ScanContext'
import { SEVERITIES, SEVERITY_LABEL, CATEGORIES, CATEGORY_LABEL, normSeverity, normCategory } from '../constants'
import { relPath } from '../lib/paths'
import { sortFindings } from '../lib/scene'
import FindingTable from '../components/findings/FindingTable'
import FindingDialog from '../components/findings/FindingDialog'
import { usePageGate } from '../components/findings/usePageGate'
import { isDownweighted } from '../lib/notes'

const PER_PAGE = 15

export default function FindingsPage() {
  const { scanResult, diff, triageOf } = useScan()
  const [onlyNew, setOnlyNew] = useState(false)
  const [hideTriaged, setHideTriaged] = useState(true)
  const [search, setSearch] = useState('')
  const [sev, setSev] = useState('all')
  const [cat, setCat] = useState('all')
  const [tool, setTool] = useState('all')
  const [hideDown, setHideDown] = useState(false)
  const [page, setPage] = useState(1)
  const [open, setOpen] = useState(null)

  const all = useMemo(() => scanResult?.findings ?? [], [scanResult])
  const cats = useMemo(() => CATEGORIES.filter((c) => all.some((f) => normCategory(f.category) === c)), [all])
  const hasLlm = useMemo(() => all.some((f) => f.rule_source === 'llm'), [all])
  const downCount = useMemo(() => all.filter(isDownweighted).length, [all])
  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    return sortFindings(all.filter((f) => {
      if (hideDown && isDownweighted(f)) return false
      if (hideTriaged && triageOf(f)) return false
      if (onlyNew && !diff?.newIds?.has(f.id)) return false
      if (tool === 'llm' && f.rule_source !== 'llm') return false
      if (tool === 'static' && f.rule_source === 'llm') return false
      if (sev !== 'all' && normSeverity(f.severity) !== sev) return false
      if (cat !== 'all' && normCategory(f.category) !== cat) return false
      if (!q) return true
      return `${f.issue_type} ${relPath(f.file_path, scanResult?.target_path)} ${f.rule_source}`.toLowerCase().includes(q)
    }))
  }, [all, search, sev, cat, tool, hideDown, hideTriaged, onlyNew, diff, triageOf, scanResult])
  const triagedCount = useMemo(() => all.filter((f) => triageOf(f)).length, [all, triageOf])

  const gate = usePageGate('Findings')
  if (gate) return gate

  const pages = Math.max(1, Math.ceil(filtered.length / PER_PAGE))
  const current = Math.min(page, pages)
  const paged = filtered.slice((current - 1) * PER_PAGE, current * PER_PAGE)
  const count = (s) => all.filter((f) => normSeverity(f.severity) === s).length
  const filtering = search || sev !== 'all' || cat !== 'all' || tool !== 'all' || hideDown || onlyNew
  const reset = (fn) => (e) => { fn(e.target.value); setPage(1) }

  return (
    <div className="ag-pagebody">
      <header className="ag-pagehead">
        <h1>Findings</h1>
        <p className="ag-muted">
          {filtered.length} of {all.length} findings, {count('critical')} critical, {count('high')} high
        </p>
      </header>

      <div className="ag-toolbar">
        <label className="visually-hidden" htmlFor="ag-f-search">Search findings</label>
        <input id="ag-f-search" className="ag-input" placeholder="Search issue, file or source" autoComplete="off" value={search} onChange={reset(setSearch)} />
        <label className="visually-hidden" htmlFor="ag-f-sev">Severity</label>
        <select id="ag-f-sev" className="ag-input" value={sev} onChange={reset(setSev)}>
          <option value="all">All severities</option>
          {SEVERITIES.filter(count).map((s) => <option key={s} value={s}>{SEVERITY_LABEL[s]}</option>)}
        </select>
        <label className="visually-hidden" htmlFor="ag-f-cat">Category</label>
        <select id="ag-f-cat" className="ag-input" value={cat} onChange={reset(setCat)}>
          <option value="all">All categories</option>
          {cats.map((c) => <option key={c} value={c}>{CATEGORY_LABEL[c]}</option>)}
        </select>
        {hasLlm && (
          <>
            <label className="visually-hidden" htmlFor="ag-f-tool">Found by</label>
            <select id="ag-f-tool" className="ag-input" value={tool} onChange={reset(setTool)}>
              <option value="all">All tools</option>
              <option value="static">Static tools only</option>
              <option value="llm">AI review only</option>
            </select>
          </>
        )}
        {downCount > 0 && (
          <label className="ag-check">
            <input type="checkbox" checked={hideDown} onChange={(e) => { setHideDown(e.target.checked); setPage(1) }} />
            Hide {downCount} down-weighted
          </label>
        )}
        {triagedCount > 0 && (
          <label className="ag-check">
            <input type="checkbox" checked={hideTriaged} onChange={(e) => { setHideTriaged(e.target.checked); setPage(1) }} />
            Hide {triagedCount} triaged
          </label>
        )}
        {diff && diff.newIds.size > 0 && (
          <label className="ag-check">
            <input type="checkbox" checked={onlyNew} onChange={(e) => { setOnlyNew(e.target.checked); setPage(1) }} />
            Only {diff.newIds.size} new since last scan
          </label>
        )}
        {filtering && (
          <button type="button" className="ag-btn ag-btn--ghost" onClick={() => { setSearch(''); setSev('all'); setCat('all'); setTool('all'); setHideDown(false); setOnlyNew(false); setPage(1) }}>
            Clear filters
          </button>
        )}
      </div>

      {filtered.length ? (
        <>
          <FindingTable findings={paged} target={scanResult.target_path} selectedId={open?.id} onSelect={setOpen} />
          {pages > 1 && (
            <nav className="ag-pager" aria-label="Findings pages">
              <button type="button" className="ag-btn ag-btn--sm" disabled={current === 1} onClick={() => setPage(current - 1)}>Previous</button>
              <span className="ag-mono" aria-live="polite">Page {current} of {pages}</span>
              <button type="button" className="ag-btn ag-btn--sm" disabled={current === pages} onClick={() => setPage(current + 1)}>Next</button>
            </nav>
          )}
        </>
      ) : (
        <div className="ag-state">
          <h3>No findings match</h3>
          <p>Try a different severity or category, or clear the search.</p>
        </div>
      )}

      {open && <FindingDialog finding={open} result={scanResult} onClose={() => setOpen(null)} />}
    </div>
  )
}
