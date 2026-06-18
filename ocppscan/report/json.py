from __future__ import annotations

import json
from typing import Any

from ocppscan.checks.base import CheckResult


def render_json(meta: dict[str, Any], results: list[CheckResult]) -> str:
    counts: dict[str, int] = {}
    for r in results:
        if r.status.value == "FAIL":
            counts[r.severity.value] = counts.get(r.severity.value, 0) + 1

    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    overall = "PASS"
    for sev in severities:
        if counts.get(sev, 0) > 0:
            overall = sev
            break

    output = {
        "ocppscan_version": "0.1.0",
        "meta": meta,
        "summary": {
            "total": len(results),
            "by_status": _count_by(results, "status"),
            "findings_by_severity": counts,
            "overall_risk": overall,
        },
        "results": [r.to_dict() for r in results],
    }
    return json.dumps(output, indent=2)


def _count_by(results: list[CheckResult], attr: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for r in results:
        val = getattr(r, attr).value
        counts[val] = counts.get(val, 0) + 1
    return counts
