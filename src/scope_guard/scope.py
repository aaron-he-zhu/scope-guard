"""Scope boundary: the core data structure that defines what an agent is allowed to do."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

from scope_guard.risk import RiskLevel


@dataclass
class Assumption:
    text: str
    verified: bool = False
    verification_method: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"text": self.text, "verified": self.verified}
        if self.verification_method:
            d["verification_method"] = self.verification_method
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Assumption:
        return cls(
            text=d["text"],
            verified=d.get("verified", False),
            verification_method=d.get("verification_method"),
        )


@dataclass
class ScopeBoundary:
    """Defines the boundary of what an agent may do for a given task."""

    files_in_scope: list[str] = field(default_factory=list)
    dirs_in_scope: list[str] = field(default_factory=list)
    assumptions: list[Assumption] = field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.LOW
    approval_required: bool = False
    task_summary: str = ""
    created_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%S%z"))
    revisions: list[dict[str, Any]] = field(default_factory=list)

    # --- persistence ---

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False) + "\n")

    @classmethod
    def load(cls, path: str | Path) -> ScopeBoundary:
        path = Path(path)
        if not path.exists():
            return cls()
        data = json.loads(path.read_text())
        return cls.from_dict(data)

    # --- serialisation ---

    def to_dict(self) -> dict[str, Any]:
        return {
            "files_in_scope": self.files_in_scope,
            "dirs_in_scope": self.dirs_in_scope,
            "assumptions": [a.to_dict() for a in self.assumptions],
            "risk_level": self.risk_level.value,
            "approval_required": self.approval_required,
            "task_summary": self.task_summary,
            "created_at": self.created_at,
            "revisions": self.revisions,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ScopeBoundary:
        return cls(
            files_in_scope=d.get("files_in_scope", []),
            dirs_in_scope=d.get("dirs_in_scope", []),
            assumptions=[Assumption.from_dict(a) for a in d.get("assumptions", [])],
            risk_level=RiskLevel(d.get("risk_level", "low")),
            approval_required=d.get("approval_required", False),
            task_summary=d.get("task_summary", ""),
            created_at=d.get("created_at", ""),
            revisions=d.get("revisions", []),
        )

    # --- scope operations ---

    def is_file_in_scope(self, file_path: str) -> bool:
        """Check if a file path falls within the declared scope."""
        normalised = _normalise(file_path)
        for f in self.files_in_scope:
            if _normalise(f) == normalised:
                return True
        for d in self.dirs_in_scope:
            nd = _normalise(d)
            if not nd.endswith("/"):
                nd += "/"
            if normalised.startswith(nd):
                return True
        return False

    def expand_scope(self, files: list[str] | None = None, dirs: list[str] | None = None, reason: str = "") -> None:
        """Expand the scope boundary and record the revision."""
        revision: dict[str, Any] = {
            "action": "expand",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "reason": reason,
            "added_files": files or [],
            "added_dirs": dirs or [],
        }
        for f in files or []:
            nf = _normalise(f)
            if nf not in [_normalise(x) for x in self.files_in_scope]:
                self.files_in_scope.append(f)
        for d in dirs or []:
            nd = _normalise(d)
            if nd not in [_normalise(x) for x in self.dirs_in_scope]:
                self.dirs_in_scope.append(d)
        self.revisions.append(revision)

    def merge(self, other: ScopeBoundary) -> ScopeBoundary:
        """Return a new ScopeBoundary that is the union of self and other."""
        merged_files = list(dict.fromkeys(self.files_in_scope + other.files_in_scope))
        merged_dirs = list(dict.fromkeys(self.dirs_in_scope + other.dirs_in_scope))
        merged_assumptions = self.assumptions + [
            a for a in other.assumptions if a.text not in {x.text for x in self.assumptions}
        ]
        higher_risk = max(self.risk_level, other.risk_level, key=lambda r: ["low", "medium", "high"].index(r.value))
        return ScopeBoundary(
            files_in_scope=merged_files,
            dirs_in_scope=merged_dirs,
            assumptions=merged_assumptions,
            risk_level=higher_risk,
            approval_required=self.approval_required or other.approval_required,
            task_summary=self.task_summary or other.task_summary,
        )

    @property
    def is_empty(self) -> bool:
        return not self.files_in_scope and not self.dirs_in_scope


def _normalise(p: str) -> str:
    """Normalise a file path for comparison.

    Uses os.path.normpath to collapse '..' and '.' segments for all paths,
    preventing path-traversal bypasses like 'src/auth/../../etc/passwd'.
    """
    import os
    cleaned = p.strip().rstrip("/")
    if Path(cleaned).is_absolute():
        return str(Path(cleaned).resolve())
    return os.path.normpath(cleaned)
