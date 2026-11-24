/**
 * A count that ticks up from 0 when it appears or changes. The animation is plain CSS (.ag-count);
 * the real number is also in the DOM as visually hidden text, and the animated copy is aria-hidden,
 * so screen readers read it once and nothing depends on the animation running.
 */
export default function Count({ n }) {
  return (
    <span className="ag-num">
      <span className="visually-hidden">{n}</span>
      <span key={n} className="ag-count" style={{ '--n': n }} aria-hidden="true" />
    </span>
  )
}
