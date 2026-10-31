"""Append-only JSON Lines audit trail — the evidence artifact for access reviews."""

from __future__ import annotations

import json
from pathlib import Path

from .http import redact
from .models import RunReport


def write_audit(report: RunReport, path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(redact(report.to_dict()), default=str) + "\n")
    return p
