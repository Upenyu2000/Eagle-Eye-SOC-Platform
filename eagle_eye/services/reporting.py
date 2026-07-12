from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from eagle_eye.models import AnalysisResult


def export_analysis(result: AnalysisResult, destination: str | Path) -> Path:
    path = Path(destination)
    payload: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "module": result.module,
        "summary": result.summary,
        "findings": [finding.to_dict() for finding in result.findings],
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    return path


def export_phishing_markdown(result: AnalysisResult, indicators: list[dict[str, str]], destination: str | Path) -> Path:
    path = Path(destination)
    lines = [
        "# Phishing Incident Analysis",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        "",
        "## Executive summary",
        "",
        f"Eagle Eye identified {len(result.findings)} finding(s) and {len(indicators)} indicator(s).",
        "",
        "## Header and authentication summary",
        "",
    ]
    for key, value in result.summary.items():
        lines.append(f"- **{key.replace('_', ' ').title()}:** {value}")
    lines.extend(["", "## Findings", ""])
    for finding in result.findings:
        lines.extend([
            f"### {finding.title}",
            "",
            f"**Severity:** {finding.severity.upper()}",
            "",
            finding.description,
            "",
            f"**Recommendation:** {finding.recommendation or 'Analyst review required.'}",
            "",
        ])
    lines.extend(["## Indicators", "", "| Type | Defanged indicator |", "|---|---|"])
    for indicator in indicators:
        lines.append(f"| {indicator['type']} | `{indicator['defanged']}` |")
    lines.extend([
        "",
        "## Analyst notes",
        "",
        "Document scope, user interaction, containment actions, recovery and residual risk here.",
    ])
    path.write_text("\n".join(lines), encoding="utf-8")
    return path
