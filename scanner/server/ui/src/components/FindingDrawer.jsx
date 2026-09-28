import { useState } from 'react'
import { normSeverity } from '../constants'

const TABS = ['Overview', 'Evidence', 'Explanation', 'Suggested Fix', 'History']

function renderDiff(patch) {
  if (!patch) return null
  return patch.split('\n').map((line, i) => {
    let cls = ''
    if (line.startsWith('+')) cls = 'diff-add'
    else if (line.startsWith('-')) cls = 'diff-del'
    return <div key={`${i}-${line.slice(0, 12)}`} className={cls}>{line || ' '}</div>
  })
}

export default function FindingDrawer({ finding: f, onClose }) {
  const [tab, setTab] = useState('Overview')
  const sev = normSeverity(f.severity)
  const fname = f.file_path?.split(/[/\\]/).pop() ?? '—'
  const conf = ((f.confidence || 0) * 100).toFixed(0)

  return (
    <>
      <div className="drawer-overlay" onClick={onClose} />
      <div className="drawer-panel">
        {/* Header */}
        <div style={{ padding: '20px 24px 0', borderBottom: '1px solid var(--border)', flexShrink: 0 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 12 }}>
            <button type="button" onClick={onClose} style={{
              background: 'none', border: 'none', color: 'var(--text-muted)',
              cursor: 'pointer', fontSize: 13, display: 'flex', alignItems: 'center', gap: 5,
            }}>← Back</button>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14, flexWrap: 'wrap' }}>
            <span className="display" style={{ fontWeight: 600, fontSize: 16 }}>{f.issue_type}</span>
            <span className="sev-badge" data-sev={sev}>{f.severity}</span>
            <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Confidence: {conf}%</span>
          </div>

          {/* Tabs */}
          <div style={{ display: 'flex', gap: 0 }}>
            {TABS.map(t => (
              <button type="button" key={t} onClick={() => setTab(t)} style={{
                padding: '8px 14px', fontSize: 12, fontWeight: 500,
                background: 'none', border: 'none', cursor: 'pointer',
                color: tab === t ? 'var(--accent)' : 'var(--text-muted)',
                borderBottom: tab === t ? '2px solid var(--accent)' : '2px solid transparent',
                marginBottom: -1, transition: 'all 0.12s',
              }}>{t}</button>
            ))}
          </div>
        </div>

        {/* Body */}
        <div style={{ flex: 1, padding: '20px 24px', overflowY: 'auto' }}>

          {tab === 'Overview' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                {[
                  ['Category', f.category || '—'],
                  ['Rule Source', f.rule_source || '—'],
                  ['Provider', f.provider || (f.rule_source === 'llm' ? '—' : f.rule_source) || '—'],
                  ['File', fname],
                  ['Line Range', `${f.line_start}–${f.line_end}`],
                  ['Severity', f.severity],
                ].map(([k, v]) => (
                  <div key={k} style={{ background: 'var(--bg-card-sub)', borderRadius: 'var(--radius)', padding: '10px 12px' }}>
                    <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.06em' }}>{k}</div>
                    <div style={{ fontSize: 12, fontWeight: 500 }}>{v}</div>
                  </div>
                ))}
              </div>
              <div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6, fontWeight: 600 }}>Description</div>
                <div style={{ fontSize: 13, lineHeight: 1.6, color: 'var(--text-dim)' }}>
                  {f.explanation || 'No description available for this finding.'}
                </div>
              </div>
            </div>
          )}

          {tab === 'Evidence' && (
            <div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 8, fontWeight: 600 }}>
                Evidence Code — <span className="mono">{f.file_path}</span>
              </div>
              <div className="code-block">{f.evidence || 'No evidence captured.'}</div>
            </div>
          )}

          {tab === 'Explanation' && (
            <div style={{ fontSize: 13, lineHeight: 1.7, color: 'var(--text-dim)' }}>
              {f.explanation || 'No detailed explanation available.'}
            </div>
          )}

          {tab === 'Suggested Fix' && (
            <div>
              {f.fix_patch ? (
                <>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600 }}>AI-Generated Unified Diff</div>
                    <button type="button" className="btn btn-ghost" style={{ fontSize: 11 }}
                      onClick={() => navigator.clipboard.writeText(f.fix_patch)}>
                      Copy Patch
                    </button>
                  </div>
                  <div className="code-block">{renderDiff(f.fix_patch)}</div>
                </>
              ) : (
                <div style={{ fontSize: 12, color: 'var(--text-muted)', padding: '20px 0' }}>
                  No AI patch generated. Re-run with <span className="mono">--generate-patches</span>.
                </div>
              )}
            </div>
          )}

          {tab === 'History' && (
            <div style={{ fontSize: 12, color: 'var(--text-muted)', padding: '20px 0' }}>
              Finding history tracking not yet available.
            </div>
          )}
        </div>
      </div>
    </>
  )
}
