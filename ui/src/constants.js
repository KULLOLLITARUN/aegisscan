// Shared vocabulary — mirrors scanner/models/finding.py exactly (Severity / Category
// enums are lowercase). Centralized here because five components previously each
// declared their own SEV_COLORS map keyed by uppercase strings ('CRITICAL', 'HIGH', …),
// which never matched the real lowercase values coming back from the API — every
// severity/category color and count silently fell back to gray. Compare and render
// through these instead of ad-hoc per-file maps.

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']

export const SEVERITY_LABEL = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
}

// Every category the scanner can emit. The static tools and bundled rules produce more than the
// LLM's seven (xss, path_traversal, ... and dependencies from OSV-Scanner); a category missing here
// is folded into "Other", which hid them from the Findings filter.
export const CATEGORIES = [
  'injection',
  'xss',
  'path_traversal',
  'redirect',
  'deserialization',
  'secrets',
  'dependencies',
  'access_control',
  'network',
  'crypto',
  'misconfig',
  'performance',
  'best_practices',
  'other',
]

export const CATEGORY_LABEL = {
  injection: 'Injection',
  xss: 'Cross-site scripting',
  path_traversal: 'Path traversal',
  redirect: 'Open redirect',
  deserialization: 'Deserialization',
  secrets: 'Secrets',
  dependencies: 'Vulnerable dependencies',
  access_control: 'Access Control',
  network: 'Network',
  crypto: 'Crypto',
  misconfig: 'Misconfiguration',
  performance: 'Performance',
  best_practices: 'Best Practices',
  other: 'Other',
}

export const TRIAGE_LABEL = { false_positive: 'False positive', accepted: 'Accepted risk' }

// `rule_source` is an internal id; show the tool's real name.
export const SOURCE_LABEL = {
  bandit: 'Bandit',
  semgrep: 'Semgrep',
  gitleaks: 'Secret scan',
  osv: 'OSV-Scanner',
  'aegis-opt': 'Optimizer',
  llm: 'AI review',
  correlated: 'Static + AI',
}

export function sourceLabel(source) {
  return SOURCE_LABEL[source] || source || 'Unknown'
}

/** Normalizes whatever the API sends (case, missing value) to a known severity key. */
export function normSeverity(sev) {
  const s = (sev || '').toLowerCase()
  return SEVERITIES.includes(s) ? s : 'info'
}

/** Normalizes whatever the API sends to a known category key. */
export function normCategory(cat) {
  const c = (cat || '').toLowerCase()
  return CATEGORIES.includes(c) ? c : 'other'
}
