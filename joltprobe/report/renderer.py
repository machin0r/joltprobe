from __future__ import annotations

import os
from typing import Any

from joltprobe.checks.base import CheckResult
from joltprobe.report.json import render_json
from joltprobe.report.markdown import render_markdown
from joltprobe.report.html import render_html


def render_report(meta: dict[str, Any], results: list[CheckResult], output_path: str) -> None:
    ext = os.path.splitext(output_path)[1].lower()
    if ext == ".json":
        content = render_json(meta, results)
    elif ext == ".md":
        content = render_markdown(meta, results)
    elif ext in (".html", ".htm"):
        content = render_html(meta, results)
    else:
        raise ValueError(
            f"Unknown output format '{ext}'. Use .json, .md, or .html"
        )
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(content)
