from __future__ import annotations

import json
from typing import Any

from joltprobe.checks.base import CheckResult, Status


_SEV_COLOR = {
    "CRITICAL": "#c0392b",
    "HIGH": "#e67e22",
    "MEDIUM": "#f1c40f",
    "LOW": "#3498db",
    "INFO": "#95a5a6",
}

_STATUS_COLOR = {
    "PASS": "#27ae60",
    "FAIL": "#c0392b",
    "ERROR": "#e67e22",
    "SKIP": "#95a5a6",
    "INCONCLUSIVE": "#8e44ad",
}

_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f5f6fa; color: #2c3e50; }
.container { max-width: 1100px; margin: 0 auto; padding: 2rem 1rem; }
h1 { font-size: 1.8rem; margin-bottom: 0.5rem; }
h2 { font-size: 1.3rem; margin: 2rem 0 1rem; border-bottom: 2px solid #e0e0e0; padding-bottom: 0.4rem; }
h3 { font-size: 1.1rem; margin: 1.5rem 0 0.5rem; }
.meta { background: #fff; border-radius: 8px; padding: 1.2rem 1.5rem; margin-bottom: 1.5rem; box-shadow: 0 1px 4px rgba(0,0,0,.08); }
.meta p { margin: 0.25rem 0; font-size: 0.9rem; color: #555; }
.meta code { background: #f0f0f0; padding: 0 4px; border-radius: 3px; }
.disclaimer { background: #fffbe6; border-left: 4px solid #f1c40f; padding: 0.8rem 1rem; margin-bottom: 1.5rem; font-size: 0.85rem; border-radius: 0 4px 4px 0; }
.summary-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(130px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }
.sev-card { background: #fff; border-radius: 8px; padding: 1rem; text-align: center; box-shadow: 0 1px 4px rgba(0,0,0,.08); border-top: 4px solid #ccc; }
.sev-card .count { font-size: 2rem; font-weight: 700; }
.sev-card .label { font-size: 0.75rem; text-transform: uppercase; letter-spacing: .05em; color: #666; }
table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 4px rgba(0,0,0,.08); }
th { background: #f0f0f0; text-align: left; padding: 0.7rem 1rem; font-size: 0.8rem; text-transform: uppercase; letter-spacing: .05em; }
td { padding: 0.65rem 1rem; border-top: 1px solid #f0f0f0; font-size: 0.875rem; vertical-align: top; }
tr:hover td { background: #fafafa; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.75rem; font-weight: 600; color: #fff; }
.finding { background: #fff; border-radius: 8px; padding: 1.2rem 1.5rem; margin-bottom: 1rem; box-shadow: 0 1px 4px rgba(0,0,0,.08); border-left: 5px solid #ccc; }
.finding pre { background: #2c3e50; color: #ecf0f1; padding: 1rem; border-radius: 6px; overflow-x: auto; font-size: 0.8rem; margin: 0.5rem 0; }
.finding .field-label { font-size: 0.8rem; font-weight: 600; text-transform: uppercase; color: #666; margin: 0.75rem 0 0.25rem; }
.finding .field-value { font-size: 0.9rem; }
.overall { font-size: 1.5rem; font-weight: 700; padding: 0.5rem 1.2rem; border-radius: 8px; color: #fff; display: inline-block; margin-bottom: 1rem; }
"""


def _badge(text: str, color: str) -> str:
    return f'<span class="badge" style="background:{color}">{text}</span>'


def render_html(meta: dict[str, Any], results: list[CheckResult]) -> str:
    failures = [r for r in results if r.status == Status.FAIL]
    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    counts = {s: sum(1 for r in failures if r.severity.value == s) for s in severities}
    overall = next((s for s in severities if counts[s] > 0), "PASS")
    overall_color = _SEV_COLOR.get(overall, "#27ae60") if overall != "PASS" else "#27ae60"

    rows = []
    for r in results:
        sev_badge = _badge(r.severity.value, _SEV_COLOR.get(r.severity.value, "#ccc"))
        sta_badge = _badge(r.status.value, _STATUS_COLOR.get(r.status.value, "#ccc"))
        rows.append(
            f"<tr><td><code>{r.id}</code></td><td>{sev_badge}</td>"
            f"<td>{sta_badge}</td><td>{r.name}</td></tr>"
        )

    sev_cards = ""
    for sev in severities:
        color = _SEV_COLOR[sev]
        sev_cards += (
            f'<div class="sev-card" style="border-top-color:{color}">'
            f'<div class="count" style="color:{color}">{counts[sev]}</div>'
            f'<div class="label">{sev}</div></div>'
        )

    finding_blocks = ""
    for r in failures:
        border_color = _SEV_COLOR.get(r.severity.value, "#ccc")
        evidence_html = ""
        if r.evidence:
            evidence_html = f'<div class="field-label">Evidence</div><pre>{json.dumps(r.evidence, indent=2)}</pre>'
        remediation_html = ""
        if r.remediation:
            remediation_html = f'<div class="field-label">Remediation</div><div class="field-value">{r.remediation}</div>'
        refs_html = ""
        if r.references:
            ref_items = "".join(f"<li>{ref}</li>" for ref in r.references)
            refs_html = f'<div class="field-label">References</div><ul style="padding-left:1.2rem;font-size:.875rem">{ref_items}</ul>'

        finding_blocks += (
            f'<div class="finding" style="border-left-color:{border_color}">'
            f"<h3>{_badge(r.severity.value, border_color)} &nbsp; {r.name}</h3>"
            f'<div style="color:#666;font-size:.8rem;margin:.25rem 0 .75rem"><code>{r.id}</code></div>'
            f'<div class="field-label">Description</div><div class="field-value">{r.description}</div>'
            f"{evidence_html}{remediation_html}{refs_html}</div>"
        )

    overall_label = overall if overall != "PASS" else "PASS — No Findings"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>JoltProbe Report — {meta.get('target', '')}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="container">
  <h1>JoltProbe Security Assessment Report</h1>
  <div class="meta">
    <p><strong>Target:</strong> <code>{meta.get('target', '')}</code></p>
    <p><strong>Charger ID:</strong> <code>{meta.get('charger_id', '')}</code></p>
    <p><strong>Protocol:</strong> OCPP {meta.get('version', '')}</p>
    <p><strong>Timestamp:</strong> {meta.get('timestamp', '')}</p>
  </div>
  <div class="disclaimer">
    ⚠️ This report was generated by JoltProbe. Only run against systems you own or have written authorisation to test.
  </div>

  <h2>Summary</h2>
  <div class="overall" style="background:{overall_color}">{overall_label}</div>
  <div class="summary-grid">{sev_cards}</div>

  <h2>All Checks</h2>
  <table>
    <thead><tr><th>Check ID</th><th>Severity</th><th>Status</th><th>Name</th></tr></thead>
    <tbody>{"".join(rows)}</tbody>
  </table>

  {"<h2>Findings</h2>" + finding_blocks if failures else ""}
</div>
</body>
</html>"""
