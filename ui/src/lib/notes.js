// The scanner explains why it down-weighted a finding with a bracketed prefix on the explanation
// (scanner/intelligence/context.py). Turn those prefixes into named badges and plain text.

const KINDS = [
  { key: 'nonprod', test: /^non-production path/i, label: 'Test or example code', title: 'Found in tests, examples or docs: severity lowered one level and confidence halved.' },
  { key: 'ci', test: /^CI configuration hygiene/i, label: 'CI hygiene', title: 'A note about a .github/ file: severity capped at low.' },
  { key: 'benign', test: /^likely benign/i, label: 'Likely benign', title: 'A pattern that is rarely a real vulnerability here: severity capped at low.' },
  { key: 'llm', test: /^model remark/i, label: 'AI remark', title: 'An AI code-quality remark or a finding in developer tooling: severity and confidence capped.' },
]

/** { notes: [{ key, label, title }], text } for an explanation string. Unknown prefixes stay in the text. */
export function parseNotes(explanation) {
  let text = String(explanation ?? '')
  const notes = []
  for (;;) {
    const m = /^\[([^\]]{1,160})\]\s*/.exec(text)
    if (!m) break
    const kind = KINDS.find((k) => k.test.test(m[1]))
    if (!kind) break
    if (!notes.some((n) => n.key === kind.key)) notes.push({ key: kind.key, label: kind.label, title: kind.title })
    text = text.slice(m[0].length)
  }
  return { notes, text }
}

export const isDownweighted = (finding) => parseNotes(finding?.explanation).notes.length > 0
