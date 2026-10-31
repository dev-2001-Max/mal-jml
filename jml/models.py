from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any


def utcnow() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


@dataclass
class Joiner:
    first_name: str
    last_name: str
    email: str
    okta_group: str = "engineering"
    vault_group: str = "Engineering"


@dataclass
class Leaver:
    email: str
    deactivate: bool = False  # suspend (reversible) by default; deactivate is terminal


@dataclass
class StepResult:
    system: str
    action: str
    ok: bool
    detail: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    at: str = field(default_factory=utcnow)


@dataclass
class RunReport:
    flow: str
    subject: str
    mode: dict[str, str]
    run_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    started_at: str = field(default_factory=utcnow)
    finished_at: str | None = None
    steps: list[StepResult] = field(default_factory=list)

    @property
    def failures(self) -> list[StepResult]:
        return [s for s in self.steps if not s.ok]

    @property
    def ok(self) -> bool:
        return not self.failures

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["ok"] = self.ok
        return d
