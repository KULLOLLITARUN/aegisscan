import FindingsQueue from './FindingsQueue'
import Evidence from './Evidence'
import ActivityLog from './ActivityLog'

const TABS = [
  { id: 'queue', label: 'Findings' },
  { id: 'evidence', label: 'Evidence' },
  { id: 'activity', label: 'Activity' },
]

/** Right-docked inspector with Findings / Evidence / Activity tabs (ARIA tabs, arrow-key navigation). */
export default function Inspector({
  tab, setTab, result, scanning, error, logs, selectedId, onSelect, onHover, onRun, nowSeconds,
}) {
  const finding = result?.findings?.find((f) => f.id === selectedId) ?? null

  const onKeyDown = (e) => {
    const i = TABS.findIndex((t) => t.id === tab)
    let n = i
    if (e.key === 'ArrowRight') n = (i + 1) % TABS.length
    else if (e.key === 'ArrowLeft') n = (i + TABS.length - 1) % TABS.length
    else if (e.key === 'Home') n = 0
    else if (e.key === 'End') n = TABS.length - 1
    else return
    e.preventDefault()
    setTab(TABS[n].id)
    document.getElementById(`ag-tab-${TABS[n].id}`)?.focus()
  }

  return (
    <aside className="ag-inspector" aria-label="Inspector">
      <div className="ag-tabs" role="tablist" aria-label="Inspector sections" onKeyDown={onKeyDown}>
        {TABS.map((t) => (
          <button
            key={t.id}
            type="button"
            role="tab"
            id={`ag-tab-${t.id}`}
            aria-selected={tab === t.id}
            aria-controls={`ag-panel-${t.id}`}
            tabIndex={tab === t.id ? 0 : -1}
            onClick={() => setTab(t.id)}
          >
            {t.label}
            {t.id === 'queue' && result && <span className="ag-num">{result.findings?.length ?? 0}</span>}
          </button>
        ))}
      </div>
      <div className="ag-panel" id="ag-panel-queue" role="tabpanel" aria-labelledby="ag-tab-queue" hidden={tab !== 'queue'}>
        <FindingsQueue
          result={result} scanning={scanning} error={error} selectedId={selectedId}
          onSelect={onSelect} onHover={onHover} onRun={onRun} onShowActivity={() => setTab('activity')}
        />
      </div>
      <div className="ag-panel" id="ag-panel-evidence" role="tabpanel" aria-labelledby="ag-tab-evidence" hidden={tab !== 'evidence'}>
        <Evidence finding={finding} result={result} scanning={scanning} />
      </div>
      <div className="ag-panel" id="ag-panel-activity" role="tabpanel" aria-labelledby="ag-tab-activity" hidden={tab !== 'activity'}>
        <ActivityLog logs={logs} scanning={scanning} nowSeconds={nowSeconds} />
      </div>
    </aside>
  )
}
