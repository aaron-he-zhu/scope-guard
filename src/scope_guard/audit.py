"""Lightweight audit log for scope-guard decisions."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from scope_guard.checker import CheckResult


@dataclass
class AuditEntry:
    timestamp: str
    tool: str
    target: str
    verdict: str
    risk_level: str
    scope_violation: bool
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "tool": self.tool,
            "target": self.target,
            "verdict": self.verdict,
            "risk_level": self.risk_level,
            "scope_violation": self.scope_violation,
            "reason": self.reason,
        }


class AuditLog:
    """Append-only audit log stored as JSONL."""

    def __init__(self, path: Path) -> None:
        self.path = path

    @classmethod
    def default(cls) -> AuditLog:
        return cls(Path.cwd() / ".claude" / "scope-guard-audit.jsonl")

    def record(self, result: CheckResult) -> None:
        entry = AuditEntry(
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            tool=result.tool,
            target=result.target,
            verdict=result.verdict.value,
            risk_level=result.risk_level.value,
            scope_violation=result.scope_violation,
            reason=result.reason,
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a") as f:
            f.write(json.dumps(entry.to_dict(), ensure_ascii=False) + "\n")

    def read(self, limit: int = 50) -> list[AuditEntry]:
        if not self.path.exists():
            return []
        entries: list[AuditEntry] = []
        for line in self.path.read_text().strip().split("\n"):
            if not line:
                continue
            try:
                d = json.loads(line)
                entries.append(AuditEntry(**d))
            except (json.JSONDecodeError, TypeError):
                continue  # skip malformed lines
        return entries[-limit:]

    def summary(self) -> dict[str, Any]:
        entries = self.read(limit=9999)
        if not entries:
            return {"total": 0}
        verdicts = {"allow": 0, "warn": 0, "block": 0}
        scope_violations = 0
        for e in entries:
            verdicts[e.verdict] = verdicts.get(e.verdict, 0) + 1
            if e.scope_violation:
                scope_violations += 1
        return {
            "total": len(entries),
            "verdicts": verdicts,
            "scope_violations": scope_violations,
        }
