import { useMemo, useState } from 'react'
import { useScan } from '../context/ScanContext'
import { SEVERITIES, SEVERITY_LABEL, normSeverity } from '../constants'
import { relPath, baseName } from '../lib/paths'
import { sortFindings } from '../lib/scene'
import FindingTable from '../components/findings/FindingTable'
import FindingDialog from '../components/findings/FindingDialog'
import { usePageGate } from '../components/findings/usePageGate'

const topSeverity = (fs) => SEVERITIES.find((s) => fs.some((f) => normSeverity(f.severity) === s)) ?? 'info'

export default function FilesPage() {
  const { scanResult } = useScan()
  const [selectedFile, setSelectedFile] = useState(null)
  const [open, setOpen] = useState(null)

  const files = useMemo(() => {
    const map = new Map()
    for (const f of scanResult?.findings ?? []) {
      const key = relPath(f.file_path || 'unknown', scanResult?.target_path)
      if (!map.has(key)) map.set(key, [])
      map.get(key).push(f)
    }
    return [...map.entries()].sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]))
  }, [scanResult])

  const gate = usePageGate('Files')
  if (gate) return gate

  const selected = files.find(([p]) => p === selectedFile)?.[1] ?? []

  return (
    <div className="ag-pagebody">
      <header className="ag-pagehead">
        <h1>Files</h1>
        <p className="ag-muted">
          {files.length} {files.length === 1 ? 'file' : 'files'} with findings
          {scanResult.files_analyzed > files.length ? `, ${scanResult.files_analyzed - files.length} analysed files have none` : ''}
        </p>
      </header>

      <div className="ag-split">
        <nav className="ag-filelist" aria-label="Files with findings">
          <ul>
            {files.map(([path, fs]) => {
              const s = topSeverity(fs)
              return (
                <li key={path}>
                  <button
                    type="button"
                    className="ag-filerow"
                    aria-current={path === selectedFile ? 'true' : undefined}
                    onClick={() => setSelectedFile(path)}
                    title={path}
                  >
                    <i className={`ag-sq s-${s}`} />
                    <span className="visually-hidden">Worst severity {SEVERITY_LABEL[s]}, </span>
                    <span className="ag-mono ag-filename">{baseName(path)}</span>
                    <span className="ag-num">{fs.length}</span>
                  </button>
                </li>
              )
            })}
          </ul>
        </nav>

        <section aria-label="Findings in the selected file">
          {!selectedFile ? (
            <div className="ag-state">
              <h3>Select a file</h3>
              <p>Pick a file to list the findings in it.</p>
            </div>
          ) : (
            <>
              <p className="ag-mono ag-pathline">{selectedFile}</p>
              <FindingTable
                findings={sortFindings(selected)}
                target={scanResult.target_path}
                selectedId={open?.id}
                onSelect={setOpen}
                showFile={false}
              />
            </>
          )}
        </section>
      </div>

      {open && <FindingDialog finding={open} result={scanResult} onClose={() => setOpen(null)} />}
    </div>
  )
}
