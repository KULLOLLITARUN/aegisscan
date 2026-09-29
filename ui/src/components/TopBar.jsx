import { useState } from 'react'
import { useScan } from '../context/ScanContext'
import { useTheme } from '../context/ThemeContext'

function ThemeToggle() {
  const { toggleTheme } = useTheme()
  return (
    <button type="button" className="theme-toggle" onClick={toggleTheme} title="Toggle light / dark" aria-label="Toggle theme">
      <svg className="i-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
        <circle cx="12" cy="12" r="4.5" /><path d="M12 2.5v2.4M12 19.1v2.4M4.4 4.4l1.7 1.7M17.9 17.9l1.7 1.7M2.5 12h2.4M19.1 12h2.4M4.4 19.6l1.7-1.7M17.9 6.1l1.7-1.7" />
      </svg>
      <svg className="i-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M20 14.5A8.5 8.5 0 1 1 9.5 4a6.8 6.8 0 0 0 10.5 10.5Z" />
      </svg>
    </button>
  )
}

export default function TopBar() {
  const { scanResult, scanning, progress, startScan, targetPath, setTargetPath, options, setOptions } = useScan()
  const [showSettings, setShowSettings] = useState(false)

  const scanId = scanResult?.scan_id?.substring(0, 10) ?? '—'
  let status = 'Idle'
  let statusVar = '--text-muted'
  if (scanning) { status = 'Scanning…'; statusVar = '--high' }
  else if (scanResult) { status = 'Audit Ready'; statusVar = '--low' }

  return (
    <>
      <div style={{
        position: 'fixed', top: 0, left: 'var(--sidebar-w)', right: 0,
        height: 'var(--topbar-h)',
        background: 'var(--bg-surface)',
        borderBottom: '1px solid var(--border)',
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '0 28px', zIndex: 40,
      }}>
        {/* Left: Workspace Target */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 9, background: 'var(--bg-card-sub)', padding: '6px 13px', borderRadius: 'var(--radius)', border: '1px solid var(--border)' }}>
            <span style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-muted)' }}>Target</span>
            <input
              value={targetPath}
              onChange={(e) => setTargetPath(e.target.value)}
              style={{
                background: 'transparent', border: 'none', color: 'var(--text-primary)',
                fontSize: 12, fontFamily: "'IBM Plex Mono', monospace", minWidth: 260,
                padding: 0, outline: 'none', boxShadow: 'none',
              }}
              placeholder="Enter directory path…"
            />
          </div>

          {scanResult && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: 'var(--text-muted)' }}>
              <span>ID</span>
              <span className="mono" style={{ color: 'var(--accent)', fontWeight: 600 }}>{scanId}</span>
            </div>
          )}
        </div>

        {/* Right: Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{
            display: 'flex', alignItems: 'center', gap: 8,
            padding: '5px 13px', borderRadius: 20,
            border: `1px solid var(${statusVar})`,
            background: `var(${statusVar}-bg, transparent)`,
          }}>
            <span className={scanning ? 'live-dot' : 'diamond'} style={{ background: `var(${statusVar})` }} />
            <span style={{ fontSize: 11.5, fontWeight: 700, color: `var(${statusVar})` }}>{status}</span>
          </div>

          <ThemeToggle />

          <button
            type="button"
            className="btn btn-ghost"
            onClick={() => setShowSettings(true)}
            title="Scan Settings"
          >
            Options
          </button>

          <button
            type="button"
            className="btn btn-primary facet-tr"
            onClick={startScan}
            disabled={scanning}
          >
            {scanning ? `${progress.pct}% ${progress.phase}` : 'Run Scan'}
          </button>
        </div>
      </div>

      {/* Settings Modal */}
      {showSettings && (
        <div style={{
          position: 'fixed', inset: 0, background: 'rgba(8,9,13,0.55)', backdropFilter: 'blur(6px)',
          zIndex: 200, display: 'flex', alignItems: 'center', justifyContent: 'center',
        }} onClick={() => setShowSettings(false)}>
          <div style={{
            background: 'var(--bg-surface)', border: '1px solid var(--border)',
            borderRadius: 8, padding: 28, width: 480,
            boxShadow: '0 20px 50px rgba(0,0,0,0.35)',
            animation: 'fadeIn 0.2s ease',
          }} onClick={e => e.stopPropagation()}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
              <div className="display" style={{ fontWeight: 600, fontSize: 16, letterSpacing: '0.005em' }}>Scan Engine Profile</div>
              <button type="button" onClick={() => setShowSettings(false)} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 16 }}>✕</button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 14, marginBottom: 24 }}>
              <label style={{ display: 'flex', alignItems: 'flex-start', gap: 12, cursor: 'pointer', padding: 10, background: 'var(--bg-card-sub)', borderRadius: 'var(--radius)', border: '1px solid var(--border)' }}>
                <input type="checkbox"
                  checked={options.staticOnly}
                  onChange={e => setOptions(o => ({ ...o, staticOnly: e.target.checked }))}
                  style={{ accentColor: 'var(--accent)', marginTop: 3, width: 16, height: 16 }}
                />
                <div>
                  <div style={{ fontWeight: 600, fontSize: 13 }}>Static Analysis (Bandit / Semgrep / Gitleaks)</div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>Deterministic AST and rule matching (offline, instant)</div>
                </div>
              </label>

              <label style={{ display: 'flex', alignItems: 'flex-start', gap: 12, cursor: 'pointer', padding: 10, background: 'var(--bg-card-sub)', borderRadius: 'var(--radius)', border: '1px solid var(--border)' }}>
                <input type="checkbox"
                  checked={options.deep}
                  onChange={e => setOptions(o => ({ ...o, deep: e.target.checked }))}
                  style={{ accentColor: 'var(--accent)', marginTop: 3, width: 16, height: 16 }}
                />
                <div>
                  <div style={{ fontWeight: 600, fontSize: 13 }}>Deep LLM Reasoning Pass</div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>Audits all code chunks via Groq / Ollama AI reasoning</div>
                </div>
              </label>

              <label style={{ display: 'flex', alignItems: 'flex-start', gap: 12, cursor: 'pointer', padding: 10, background: 'var(--bg-card-sub)', borderRadius: 'var(--radius)', border: '1px solid var(--border)' }}>
                <input type="checkbox"
                  checked={options.generatePatches}
                  onChange={e => setOptions(o => ({ ...o, generatePatches: e.target.checked }))}
                  style={{ accentColor: 'var(--accent)', marginTop: 3, width: 16, height: 16 }}
                />
                <div>
                  <div style={{ fontWeight: 600, fontSize: 13 }}>Generate AI Code Fix Patches</div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>Synthesizes unified git diff patches for every detected finding</div>
                </div>
              </label>

              <div style={{ padding: 10, background: 'var(--bg-card-sub)', borderRadius: 'var(--radius)', border: '1px solid var(--border)' }}>
                <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 4 }}>Groq API Key (optional)</div>
                <input
                  type="password"
                  value={options.apiKey || ''}
                  onChange={e => setOptions(o => ({ ...o, apiKey: e.target.value }))}
                  placeholder="gsk_…"
                  style={{ width: '100%', fontFamily: "'IBM Plex Mono', monospace", fontSize: 12 }}
                />
                <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 4 }}>Enter an API key to enable live cloud AI audit &amp; patch generation</div>
              </div>

              <div style={{ padding: 10, background: 'var(--bg-card-sub)', borderRadius: 'var(--radius)', border: '1px solid var(--border)' }}>
                <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 6 }}>Telemetry Privacy Mode</div>
                <select
                  value={options.privacy}
                  onChange={e => setOptions(o => ({ ...o, privacy: e.target.value }))}
                  style={{ width: '100%' }}
                >
                  <option value="standard">Standard (full context for AI reasoning)</option>
                  <option value="redact">Redact (mask API keys &amp; credentials before sending to LLM)</option>
                  <option value="strict">Strict (local static analysis only, no remote calls)</option>
                </select>
              </div>
            </div>

            <button type="button" className="btn btn-primary" style={{ width: '100%', padding: '10px' }} onClick={() => setShowSettings(false)}>
              Save Profile Options
            </button>
          </div>
        </div>
      )}
    </>
  )
}
