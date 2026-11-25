/** Forward-slash a path and make it relative to the scan target when it lies inside it. */
export function relPath(filePath, targetPath) {
  const f = String(filePath || '').replace(/\\/g, '/')
  const t = String(targetPath || '').replace(/\\/g, '/').replace(/\/+$/, '')
  if (t && f.toLowerCase().startsWith(t.toLowerCase() + '/')) return f.slice(t.length + 1)
  return f
}

/** Forward slashes, no trailing slash: for comparing scan targets. */
export function normPath(p) {
  let s = String(p || '').replaceAll('\\', '/')
  while (s.length > 1 && s.endsWith('/')) s = s.slice(0, -1)
  return s
}

export function baseName(p) {
  const parts = String(p).split('/')
  return parts[parts.length - 1] || p
}
