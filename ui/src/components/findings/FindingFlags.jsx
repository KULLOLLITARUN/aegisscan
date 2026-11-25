import { useScan } from '../../context/ScanContext'
import { TRIAGE_LABEL } from '../../constants'

/** "New since the last scan" and the triage decision, as small flags beside a finding. */
export default function FindingFlags({ finding }) {
  const { diff, triageOf } = useScan()
  const isNew = diff?.newIds?.has(finding.id)
  const triage = triageOf ? triageOf(finding) : null
  if (!isNew && !triage) return null
  return (
    <span className="ag-flags">
      {isNew && <span className="ag-flag f-new" title="Not in the previous scan of this target">New</span>}
      {triage && <span className={`ag-flag f-${triage}`} title="Your triage decision">{TRIAGE_LABEL[triage]}</span>}
    </span>
  )
}
