import { SEVERITY_LABEL, normSeverity, sourceLabel } from '../../constants'
import CategoryTag from './CategoryTag'
import NoteBadges from './NoteBadges'
import FindingFlags from './FindingFlags'
import { relPath } from '../../lib/paths'

/**
 * Findings as a table. Severity is always shown as a shape plus its name, never colour alone.
 * The issue cell is a button so rows are reachable and operable from the keyboard.
 */
export default function FindingTable({ findings, target, selectedId, onSelect, showFile = true }) {
  return (
    <div className="ag-tablewrap">
      <table className="ag-table">
        <thead>
          <tr>
            <th scope="col">Severity</th>
            <th scope="col">Issue</th>
            <th scope="col">Category</th>
            <th scope="col">{showFile ? 'Location' : 'Line'}</th>
            <th scope="col">Source</th>
            <th scope="col" className="ag-right">Confidence</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f, i) => {
            const s = normSeverity(f.severity)
            const pct = Math.round((f.confidence ?? 0) * 100)
            return (
              <tr key={f.id} className={f.id === selectedId ? 'sel' : undefined} style={{ '--i': i }} onClick={() => onSelect(f)}>
                <td>
                  <span className="ag-sevline">
                    <i className={`ag-sq s-${s}`} />
                    {SEVERITY_LABEL[s]}
                  </span>
                </td>
                <td>
                  <button type="button" className="ag-link" onClick={(e) => { e.stopPropagation(); onSelect(f) }}>
                    {f.issue_type}
                  </button>
                  <FindingFlags finding={f} />
                  <NoteBadges explanation={f.explanation} compact />
                </td>
                <td><CategoryTag category={f.category} /></td>
                <td className="ag-mono ag-loc">{showFile ? `${relPath(f.file_path, target)}:${f.line_start}` : f.line_start}</td>
                <td>{sourceLabel(f.rule_source)}</td>
                <td className="ag-right ag-mono">{pct}%</td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
