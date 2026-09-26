from __future__ import annotations

from joltprobe.checks.base import CheckResult, Severity, Status
from joltprobe.report.html import render_html
from joltprobe.report.markdown import _format_transcript, render_markdown

_META = {"target": "ws://x", "charger_id": "C", "version": "2.0.1", "timestamp": "now"}


def _finding(
    *,
    description: str = "d",
    evidence: dict | None = None,
    remediation: str = "",
    references: list | None = None,
    transcript: list | None = None,
) -> CheckResult:
    return CheckResult(
        id="firmware.update-url",
        name="X",
        severity=Severity.HIGH,
        status=Status.FAIL,
        description=description,
        evidence=evidence or {},
        remediation=remediation,
        references=references or [],
        transcript=transcript or [],
    )


def test_html_escapes_attacker_controlled_evidence():
    # A hostile CSMS response echoed into evidence must not become live markup.
    r = _finding(evidence={"status": "<script>alert(1)</script>"})
    html = render_html(_META, [r])
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_html_escapes_description_and_remediation():
    r = _finding(
        description="<img src=x onerror=alert(1)>",
        remediation="<b>fix</b>",
    )
    html = render_html(_META, [r])
    assert "<img src=x onerror=alert(1)>" not in html
    assert "<b>fix</b>" not in html


def test_html_escapes_transcript_frame():
    r = _finding(transcript=[{"t": 1.0, "dir": "recv", "frame": [3, "id", {"m": "<x>"}]}])
    html = render_html(_META, [r])
    assert "<x>" not in html.split("OCPP transcript")[1]


def test_markdown_transcript_collapses_newlines():
    # A frame carrying a newline + fence must not produce a bare ``` line.
    lines = _format_transcript([{"t": 1.0, "dir": "recv", "frame": "before\n```\nafter"}])
    assert all("\n" not in ln for ln in lines)
    assert all(ln.strip() != "```" for ln in lines)


def test_markdown_report_fence_not_broken_by_frame():
    r = _finding(transcript=[{"t": 1.0, "dir": "recv", "frame": "x\n```\ny"}])
    md = render_markdown(_META, [r])
    # A fence is only closed by a line that is *just* backticks. The frame's inline
    # ``` is folded into a single arrowed line, so only the renderer's own opening
    # and closing fences stand alone.
    standalone_fences = [ln for ln in md.splitlines() if ln.strip() == "```"]
    assert len(standalone_fences) == 2
