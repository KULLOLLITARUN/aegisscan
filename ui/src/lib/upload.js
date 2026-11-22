import { Zip, ZipDeflate } from 'fflate'

// Folder selection for the hosted version: the browser picks a folder, this drops what a scanner
// does not need (dependencies, build output, binaries, huge files) and zips the rest in the browser.

export const SKIP_DIRS = new Set([
  'node_modules', '.git', '.hg', '.svn', 'dist', 'build', 'out', '.next', '.nuxt', '.cache', 'coverage',
  '.venv', 'venv', 'env', '__pycache__', '.pytest_cache', '.mypy_cache', '.tox', 'target', 'vendor',
  '.idea', '.vscode', '.gradle', 'bower_components', '.terraform',
])

const BINARY_EXT = new Set([
  'png', 'jpg', 'jpeg', 'gif', 'webp', 'ico', 'bmp', 'tif', 'tiff', 'svgz', 'pdf', 'zip', 'gz', 'tgz', 'bz2', '7z',
  'rar', 'jar', 'war', 'exe', 'dll', 'so', 'dylib', 'bin', 'class', 'o', 'a', 'woff', 'woff2', 'ttf', 'otf', 'eot',
  'mp3', 'mp4', 'mov', 'avi', 'mkv', 'wav', 'flac', 'sqlite', 'db', 'pyc', 'lock',
])

export const MAX_FILE_BYTES = 1_000_000

const extOf = (name) => {
  const i = name.lastIndexOf('.')
  return i === -1 ? '' : name.slice(i + 1).toLowerCase()
}

/**
 * Filters a FileList from <input webkitdirectory>.
 * Returns { files: [{ file, path }], name, totalBytes, skipped: { dirs, binary, large } }.
 */
export function filterFolder(fileList) {
  const files = []
  const skipped = { dirs: 0, binary: 0, large: 0 }
  let name = ''
  let totalBytes = 0
  for (const file of fileList) {
    const full = file.webkitRelativePath || file.name
    const parts = full.split('/')
    if (!name && parts.length > 1) name = parts[0]
    const rel = parts.length > 1 ? parts.slice(1) : parts
    if (rel.slice(0, -1).some((seg) => SKIP_DIRS.has(seg))) {
      skipped.dirs += 1
    } else if (BINARY_EXT.has(extOf(file.name))) {
      skipped.binary += 1
    } else if (file.size > MAX_FILE_BYTES) {
      skipped.large += 1
    } else {
      files.push({ file, path: rel.join('/') })
      totalBytes += file.size
    }
  }
  return { files, name: name || 'folder', totalBytes, skipped }
}

const nextTick = () => new Promise((resolve) => setTimeout(resolve, 0))

/** Zips the filtered files in the browser. onProgress(done, total) is called as files are added. */
export async function zipFiles(files, onProgress) {
  const chunks = []
  let failure = null
  const finished = new Promise((resolve, reject) => {
    const zip = new Zip((err, chunk, final) => {
      if (err) {
        failure = err
        reject(err)
        return
      }
      chunks.push(chunk)
      if (final) resolve()
    })
    ;(async () => {
      try {
        for (let i = 0; i < files.length; i += 1) {
          const { file, path } = files[i]
          const entry = new ZipDeflate(path, { level: 6 })
          zip.add(entry)
          entry.push(new Uint8Array(await file.arrayBuffer()), true)
          if (i % 25 === 24) {
            onProgress?.(i + 1, files.length)
            await nextTick()
          }
        }
        zip.end()
      } catch (err) {
        failure = err
        reject(err)
      }
    })()
  })
  await finished
  if (failure) throw failure
  onProgress?.(files.length, files.length)
  return new Blob(chunks, { type: 'application/zip' })
}

export const formatBytes = (n) => (n >= 1_048_576 ? `${(n / 1_048_576).toFixed(1)} MB` : `${Math.max(1, Math.round(n / 1024))} KB`)
