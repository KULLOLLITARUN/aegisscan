/**
 * Turns a scan error message from the server into what the UI should show.
 * The server refuses paths outside its allowed roots (scanner/server/app.py); retrying cannot help
 * there, so the UI explains the fix instead of offering a retry.
 */
export function describeScanError(message) {
  const text = String(message || 'The scan did not finish.')
  if (/outside the allowed scan roots/i.test(text)) {
    return {
      title: 'This folder is outside the allowed scan roots',
      // The server's trailing "Set AEGISSCAN_ALLOWED_ROOTS..." sentence is covered by the hint below.
      detail: `${text.split(/\.\s+Set\s/)[0].replace(/\.$/, '')}.`,
      hint:
        'Pick a folder inside the project, or restart the server with AEGISSCAN_ALLOWED_ROOTS set to a folder that contains your target. With the Windows launcher: run_aegisscan.bat --allow "D:\\path\\to\\folder".',
      retryable: false,
    }
  }
  return { title: 'The scan did not finish', detail: text, hint: null, retryable: true }
}

export function focusTarget() {
  const el = document.getElementById('ag-target')
  if (el) {
    el.focus()
    el.select?.()
  }
}
