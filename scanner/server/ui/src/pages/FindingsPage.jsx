import { useState } from 'react'
import FindingsTable from '../components/FindingsTable'
import { useScan } from '../context/ScanContext'
import { SEVERITIES, SEVERITY_LABEL, normSeverity } from '../constants'

const SEV_OPTIONS = ['All', ...SEVERITIES]

export default function FindingsPage() {
  const { scanResult } = useScan()
  const [search, setSearch] = useState('')
  const [sev, setSev] = useState('All')
  const [cat, setCat] = useState('All')
  const [page, setPage] = useState(1)
  const PER_PAGE = 15

  const allFindings = scanResult?.findings ?? []
  const cats = ['All', ...new Set(allFindings.map(f => f.category).filter(Boolean))]

  const filtered = allFindings.filter(f => {
    const matchSev = sev === 'All' || normSeverity(f.severity) === sev
    const matchCat = cat === 'All' || f.category === cat
    const matchSearch = !search || f.issue_type?.toLowerCase().includes(search.toLowerCase())
      || f.file_path?.toLowerCase().includes(search.toLowerCase())
    return matchSev && matchCat && matchSearch
  })

  const totalPages = Math.ceil(filtered.length / PER_PAGE)
  const paged = filtered.slice((page - 1) * PER_PAGE, page * PER_PAGE)

  const criticalCount = allFindings.filter(f => normSeverity(f.severity) === 'critical').length
  const highCount = allFindings.filter(f => normSeverity(f.severity) === 'high').length

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div>
        <h1 className="display" style={{ fontSize: 21, fontWeight: 600, letterSpacing: '0.005em' }}>Findings</h1>
        <p style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 3 }}>
          {filtered.length} findings · {criticalCount} critical · {highCount} high
        </p>
      </div>

      {/* Filter Bar */}
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
        <input
          value={search}
          onChange={e => { setSearch(e.target.value); setPage(1) }}
          placeholder="Search findings…"
          style={{ minWidth: 200, flex: 1 }}
        />
        <select value={sev} onChange={e => { setSev(e.target.value); setPage(1) }}>
          {SEV_OPTIONS.map(s => <option key={s} value={s}>{s === 'All' ? 'All' : SEVERITY_LABEL[s]}</option>)}
        </select>
        <select value={cat} onChange={e => { setCat(e.target.value); setPage(1) }}>
          {cats.map(c => <option key={c}>{c}</option>)}
        </select>
        {(search || sev !== 'All' || cat !== 'All') && (
          <button type="button" className="btn btn-ghost" onClick={() => { setSearch(''); setSev('All'); setCat('All'); setPage(1) }}>
            Clear
          </button>
        )}
      </div>

      {/* Table */}
      <div className="card">
        <FindingsTable findings={paged} showTitle={false} />

        {/* Pagination */}
        {totalPages > 1 && (
          <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 6, marginTop: 16 }}>
            <button type="button" className="btn btn-ghost" style={{ padding: '4px 10px', fontSize: 12 }}
              disabled={page === 1} onClick={() => setPage(p => p - 1)}>←</button>
            {Array.from({ length: Math.min(totalPages, 7) }, (_, i) => i + 1).map(p => (
              <button type="button" key={p} onClick={() => setPage(p)} className={p === page ? 'btn btn-primary' : 'btn btn-ghost'} style={{ padding: '4px 10px', fontSize: 12 }}>
                {p}
              </button>
            ))}
            <button type="button" className="btn btn-ghost" style={{ padding: '4px 10px', fontSize: 12 }}
              disabled={page === totalPages} onClick={() => setPage(p => p + 1)}>→</button>
          </div>
        )}
      </div>
    </div>
  )
}
