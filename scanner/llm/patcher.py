"""
AI Fix Patch Generator — V8/V10

Generates unified `git diff` patches for security and optimization findings
using structured LLM reasoning with smart heuristic fallback for offline/demo mode.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanner.models.finding import Finding
    from scanner.providers.manager import ProviderManager

log = logging.getLogger(__name__)

_PATCH_SYSTEM_PROMPT = """You are a senior software security engineer.
Your task is to produce a valid, unified `git diff` patch that fixes the specified security or optimization finding in the provided code snippet.

OUTPUT CONTRACT:
- Output ONLY the unified git diff block starting with '--- a/' and '+++ b/'.
- Do not include markdown code block backticks, intro text, or explanation outside the patch.
- The patch must directly replace the vulnerable line(s) with safe, production-ready code.
"""


def _generate_fallback_patch(finding: Finding) -> str:
    """Generate a clean, realistic git diff patch when no LLM provider is connected."""
    fname = str(finding.file_path.name if hasattr(finding.file_path, 'name') else finding.file_path)
    evidence = finding.evidence.strip() or "# Vulnerable code line"
    lines = evidence.splitlines()
    first_line = lines[0] if lines else evidence

    # Smart pattern replacements for common security rules
    fixed_line = first_line
    if "subprocess" in first_line or "subprocess" in finding.issue_type.lower():
        fixed_line = first_line.replace("shell=True", "shell=False").replace("os.system", "subprocess.run")
        if "shell=True" not in first_line and "os.system" not in first_line:
            fixed_line = f"# Security remediated: validate input arguments\nimport shlex\nsubprocess.run(shlex.split(command), check=True)"
    elif "eval(" in first_line or "exec(" in first_line:
        fixed_line = first_line.replace("eval(", "ast.literal_eval(").replace("exec(", "# exec disabled\n# ")
    elif "password" in first_line.lower() or "secret" in first_line.lower() or "key" in first_line.lower():
        fixed_line = f"# Refactored: Load sensitive credential from environment\nimport os\nSECRET_KEY = os.environ.get('APP_SECRET_KEY')"
    elif "pickle" in first_line:
        fixed_line = first_line.replace("pickle.loads", "json.loads")
    else:
        fixed_line = f"# Safe Remediation:\n# {first_line}\n# Ensure input sanitization and secure parameterization"

    return f"""--- a/{fname}
+++ b/{fname}
@@ -{finding.line_start},1 +{finding.line_start},3 @@
-{first_line}
+{fixed_line}"""


def generate_patch_for_finding(finding: Finding, provider_manager: ProviderManager | None = None) -> str | None:
    """Request a unified git diff patch from active LLM provider or fallback template."""
    if not finding.evidence or not finding.evidence.strip():
        return None

    if provider_manager and provider_manager.is_available:
        prompt = (
            f"File: {finding.file_path}\n"
            f"Line range: {finding.line_start}-{finding.line_end}\n"
            f"Issue: {finding.issue_type} ({finding.category})\n"
            f"Explanation: {finding.explanation}\n\n"
            f"Vulnerable Code:\n"
            f"```python\n{finding.evidence}\n```\n\n"
            f"Generate a unified git diff patch fixing this issue."
        )

        try:
            messages = [
                {"role": "system", "content": _PATCH_SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ]
            response = provider_manager.complete(messages, max_tokens=1024, temperature=0.1)

            if response and response.content:
                cleaned = response.content.strip()
                if cleaned.startswith("```diff"):
                    cleaned = cleaned[7:]
                elif cleaned.startswith("```"):
                    cleaned = cleaned[3:]
                if cleaned.endswith("```"):
                    cleaned = cleaned[:-3]
                return cleaned.strip()
        except Exception as exc:
            log.warning("Failed to generate LLM patch for finding %s: %s", finding.id, exc)

    # Fallback heuristic patch
    return _generate_fallback_patch(finding)
