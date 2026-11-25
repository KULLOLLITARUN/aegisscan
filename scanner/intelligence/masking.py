"""
Secret masking for what the scanner shows and stores.

A secret finding quotes the line it matched, and so can any other finding (a Bandit hardcoded-password
hit, a Semgrep rule that prints the line, an LLM quote). That text ends up in the dashboard, the kept
results on disk, and the HTML / SARIF / JSON exports, so the secret value itself must not be in it.
Each place that finds a secret masks the value where it is found; ``mask_findings`` is the safety net
that catches any recognisable token left in any finding before the result is built.
"""
from __future__ import annotations

from scanner.llm.redactor import mask_known_secrets
from scanner.models.finding import Finding

_TEXT_FIELDS = ("evidence", "explanation", "suggested_fix", "fix_patch")


def mask_findings(findings: list[Finding]) -> list[Finding]:
    """Return *findings* with recognisable secrets masked in their text fields (new objects only
    where something changed)."""
    out: list[Finding] = []
    for f in findings:
        changes = {}
        for name in _TEXT_FIELDS:
            value = getattr(f, name)
            if value:
                masked = mask_known_secrets(value)
                if masked != value:
                    changes[name] = masked
        out.append(f.model_copy(update=changes) if changes else f)
    return out
