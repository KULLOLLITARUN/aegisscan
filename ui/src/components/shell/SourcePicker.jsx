import { useRef, useState } from 'react'
import { useScan } from '../../context/ScanContext'
import { filterFolder, formatBytes } from '../../lib/upload'

/** Hosted mode: choose a folder from this computer (any drive) or paste a public Git URL. */
export default function SourcePicker() {
  const { source, setSource, config } = useScan()
  const inputRef = useRef(null)
  const [error, setError] = useState('')
  const maxFiles = config?.limits?.max_files ?? 5000
  const folder = source.folder

  const onPick = (e) => {
    const list = e.target.files
    if (!list?.length) return
    const picked = filterFolder(list)
    e.target.value = '' // allow choosing the same folder again
    if (!picked.files.length) {
      setError('No scannable files were found in that folder.')
      return
    }
    if (picked.files.length > maxFiles) {
      setError(`That folder has ${picked.files.length} scannable files and the limit is ${maxFiles}. Pick a smaller folder.`)
      return
    }
    setError('')
    setSource((s) => ({ ...s, kind: 'folder', folder: picked }))
  }

  const skipped = folder ? folder.skipped.dirs + folder.skipped.binary + folder.skipped.large : 0

  return (
    <div className="ag-source">
      <div className="ag-seg" role="group" aria-label="Where the code comes from">
        <button type="button" aria-pressed={source.kind === 'folder'} onClick={() => setSource((s) => ({ ...s, kind: 'folder' }))}>Folder</button>
        <button type="button" aria-pressed={source.kind === 'git'} onClick={() => setSource((s) => ({ ...s, kind: 'git' }))}>Git URL</button>
      </div>

      {source.kind === 'folder' ? (
        <>
          <input
            ref={inputRef}
            className="visually-hidden"
            type="file"
            webkitdirectory=""
            directory=""
            multiple
            tabIndex={-1}
            aria-hidden="true"
            onChange={onPick}
          />
          <button type="button" className="ag-btn" onClick={() => inputRef.current?.click()}>
            {folder ? 'Change folder' : 'Choose folder'}
          </button>
          <span className="ag-source-note" role={error ? 'alert' : 'status'}>
            {error || (folder
              ? `${folder.name}: ${folder.files.length} files, ${formatBytes(folder.totalBytes)}${skipped ? `, ${skipped} skipped (dependencies, build output, binaries, large files)` : ''}`
              : 'Pick a folder from any drive. It is zipped in your browser and uploaded.')}
          </span>
        </>
      ) : (
        <>
          <label className="visually-hidden" htmlFor="ag-git">Git repository URL</label>
          <input
            id="ag-git"
            className="ag-input ag-path"
            value={source.gitUrl}
            spellCheck={false}
            placeholder="https://github.com/owner/repo"
            onChange={(e) => setSource((s) => ({ ...s, gitUrl: e.target.value }))}
          />
          <span className="ag-source-note">Public repositories only.</span>
        </>
      )}
    </div>
  )
}
