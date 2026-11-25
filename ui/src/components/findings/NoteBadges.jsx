import { parseNotes } from '../../lib/notes'

/** Why a finding was down-weighted, as small badges (the explanation keeps the rest of the text). */
export default function NoteBadges({ explanation, compact = false }) {
  const { notes } = parseNotes(explanation)
  if (!notes.length) return null
  return (
    <span className={`ag-notes${compact ? ' compact' : ''}`}>
      {notes.map((n) => (
        <span key={n.key} className={`ag-note n-${n.key}`} title={n.title}>
          {n.label}
          {compact && <span className="visually-hidden">. {n.title}</span>}
        </span>
      ))}
    </span>
  )
}
