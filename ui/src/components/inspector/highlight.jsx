// Small, dependency-free syntax colouring for evidence and fix snippets. Returns React nodes (no HTML strings).

const KEYWORDS = new Set([
  'def', 'class', 'return', 'import', 'from', 'as', 'if', 'elif', 'else', 'for', 'while', 'in', 'not', 'and', 'or',
  'raise', 'assert', 'try', 'except', 'finally', 'with', 'lambda', 'None', 'True', 'False', 'pass', 'yield',
  'const', 'let', 'var', 'function', 'new', 'await', 'async', 'throw', 'catch', 'null', 'true', 'false', 'typeof',
])

const TOKEN = /(#.*$|\/\/.*$)|("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`[^`]*`)|\b([A-Za-z_]+)\b/g

export function highlight(text) {
  const out = []
  let last = 0
  let i = 0
  for (const m of text.matchAll(TOKEN)) {
    if (m.index > last) out.push(text.slice(last, m.index))
    if (m[1]) out.push(<span key={i++} className="c">{m[1]}</span>)
    else if (m[2]) out.push(<span key={i++} className="s">{m[2]}</span>)
    else if (KEYWORDS.has(m[3])) out.push(<span key={i++} className="k">{m[3]}</span>)
    else out.push(m[3])
    last = m.index + m[0].length
  }
  if (last < text.length) out.push(text.slice(last))
  return out
}

/** Turns a unified diff into typed lines: add, del, ctx or hunk. */
export function parseDiff(patch) {
  return String(patch)
    .replace(/\r\n/g, '\n')
    .split('\n')
    .filter((l) => !/^(diff --git|index |--- |\+\+\+ )/.test(l))
    .map((l) => {
      if (l.startsWith('@@')) return { kind: 'hunk', text: l }
      if (l.startsWith('+')) return { kind: 'add', text: l.slice(1) }
      if (l.startsWith('-')) return { kind: 'del', text: l.slice(1) }
      return { kind: 'ctx', text: l.startsWith(' ') ? l.slice(1) : l }
    })
    .filter((l, i, a) => !(l.kind === 'ctx' && l.text === '' && i === a.length - 1))
}
