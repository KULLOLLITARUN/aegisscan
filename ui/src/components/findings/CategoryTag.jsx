import { CATEGORY_LABEL, normCategory } from '../../constants'

// Categories carry a shape, not a colour: colour in this UI means severity (and score status), and
// 14 categories would need more hues than can stay distinguishable. Seven families, one icon each.
const FAMILY = {
  injection: 'input', xss: 'input', deserialization: 'input', redirect: 'input', path_traversal: 'input',
  secrets: 'key',
  crypto: 'lock',
  access_control: 'shield', network: 'shield', misconfig: 'shield',
  dependencies: 'package',
  performance: 'gauge',
  best_practices: 'note', other: 'note',
}

const ICON = {
  input: 'M2 4h8M2 8h5M9 6l3 2-3 2', // a line of input with an arrow into it
  key: 'M5 9a2.5 2.5 0 1 1 2-4l5 0 0 2-1 0 0 1.5-1.5 0 0-1.5-2.5 0',
  lock: 'M3.5 7h7v5h-7zM5 7V5a2 2 0 0 1 4 0v2',
  shield: 'M7 1.5 12 3v3.5c0 3-2.2 5-5 6-2.8-1-5-3-5-6V3z',
  package: 'M2 4.5 7 2l5 2.5v5L7 12 2 9.5zM2 4.5 7 7l5-2.5M7 7v5',
  gauge: 'M2 10a5 5 0 1 1 10 0M7 10l2.5-3.5',
  note: 'M3 2h8v10H3zM5 5h4M5 8h4',
}

export default function CategoryTag({ category }) {
  const key = normCategory(category)
  return (
    <span className="ag-cat">
      <svg viewBox="0 0 14 14" aria-hidden="true" focusable="false"><path d={ICON[FAMILY[key] ?? 'note']} /></svg>
      {CATEGORY_LABEL[key]}
    </span>
  )
}
