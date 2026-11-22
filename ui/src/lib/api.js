// Small API helpers: access token storage, authorised fetch, and a reader for the scan's SSE stream.
// The stream is read with fetch (not EventSource) so it can be a POST and carry an Authorization header.

const TOKEN_KEY = 'aegis-token'

export function loadToken() {
  try {
    return sessionStorage.getItem(TOKEN_KEY) || ''
  } catch {
    return ''
  }
}

export function saveToken(token) {
  try {
    if (token) sessionStorage.setItem(TOKEN_KEY, token)
    else sessionStorage.removeItem(TOKEN_KEY)
  } catch {
    // storage unavailable: the token lives only in memory for this visit
  }
}

export function authHeaders(token) {
  return token ? { Authorization: `Bearer ${token}` } : {}
}

/** An HTTP error from the server with the message it sent. */
export class ApiError extends Error {
  constructor(status, message) {
    super(message)
    this.status = status
  }
}

/** Turns a non-OK response into an ApiError carrying the server's own message when it sent one. */
export async function toApiError(res) {
  let message = ''
  try {
    const data = await res.json()
    message = data?.error || ''
  } catch {
    // body was not JSON
  }
  if (!message) {
    message = res.status === 401 ? 'The access token was not accepted.'
      : res.status === 413 ? 'That is too large to upload.'
        : `The server answered with an error (${res.status}).`
  }
  return new ApiError(res.status, message)
}

/**
 * Reads a text/event-stream response and calls onEvent(name, data) for each event.
 * Resolves when the stream ends. Rejects (AbortError) if the signal aborts.
 */
export async function readSse(response, onEvent) {
  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  for (;;) {
    const { value, done } = await reader.read()
    if (done) break
    buffer += decoder.decode(value, { stream: true })
    let end = buffer.indexOf('\n\n')
    while (end !== -1) {
      const block = buffer.slice(0, end)
      buffer = buffer.slice(end + 2)
      let name = 'message'
      const dataLines = []
      for (const line of block.split('\n')) {
        if (line.startsWith('event:')) name = line.slice(6).trim()
        else if (line.startsWith('data:')) dataLines.push(line.slice(5).trimStart())
      }
      if (dataLines.length) {
        try {
          onEvent(name, JSON.parse(dataLines.join('\n')))
        } catch {
          // ignore a malformed event rather than aborting the scan
        }
      }
      end = buffer.indexOf('\n\n')
    }
  }
}
