"""Rule-based risk assessment engine."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class RiskRule:
    name: str
    tool: str  # tool name to match, or "*" for any
    pattern: str  # regex to match against the serialised params
    risk: RiskLevel
    description: str = ""

    def matches(self, tool_name: str, params_str: str) -> bool:
        if self.tool != "*" and self.tool.lower() != tool_name.lower():
            return False
        return bool(re.search(self.pattern, params_str, re.IGNORECASE))


class RiskEngine:
    """Evaluate the risk level of a tool call based on configurable rules."""

    def __init__(self, rules: list[RiskRule] | None = None) -> None:
        self.rules: list[RiskRule] = rules or []

    # --- loading ---

    @classmethod
    def from_yaml(cls, path: str | Path) -> RiskEngine:
        path = Path(path)
        data = yaml.safe_load(path.read_text())
        rules = []
        for entry in data.get("rules", []):
            rules.append(
                RiskRule(
                    name=entry["name"],
                    tool=entry.get("tool", "*"),
                    pattern=entry["pattern"],
                    risk=RiskLevel(entry["risk"]),
                    description=entry.get("description", ""),
                )
            )
        return cls(rules=rules)

    @classmethod
    def default(cls) -> RiskEngine:
        default_path = Path(__file__).parent / "rules" / "default.yaml"
        if default_path.exists():
            return cls.from_yaml(default_path)
        return cls(rules=_builtin_rules())

    # --- assessment ---

    def assess(self, tool_name: str, params: dict[str, Any] | str) -> RiskLevel:
        """Return the highest risk level matched by any rule."""
        if isinstance(params, dict):
            import json
            params_str = json.dumps(params, default=str)
        else:
            params_str = str(params)

        highest = RiskLevel.LOW
        for rule in self.rules:
            if rule.matches(tool_name, params_str):
                if _risk_ord(rule.risk) > _risk_ord(highest):
                    highest = rule.risk
        return highest

    def matching_rules(self, tool_name: str, params: dict[str, Any] | str) -> list[RiskRule]:
        """Return all rules that match the given tool call."""
        if isinstance(params, dict):
            import json
            params_str = json.dumps(params, default=str)
        else:
            params_str = str(params)
        return [r for r in self.rules if r.matches(tool_name, params_str)]


def _risk_ord(r: RiskLevel) -> int:
    return {"low": 0, "medium": 1, "high": 2}[r.value]


def _builtin_rules() -> list[RiskRule]:
    """Hardcoded fallback rules when no YAML is available."""
    return [
        # --- HIGH risk ---
        RiskRule(
            name="destructive_bash",
            tool="Bash",
            pattern=r"\b(rm\s+-rf|rm\s+-r|rmdir|drop\s+table|drop\s+database|truncate\s+table)\b",
            risk=RiskLevel.HIGH,
            description="Destructive shell commands",
        ),
        RiskRule(
            name="force_push",
            tool="Bash",
            pattern=r"git\s+push\s+.*--force",
            risk=RiskLevel.HIGH,
            description="Force push to remote",
        ),
        RiskRule(
            name="git_reset_hard",
            tool="Bash",
            pattern=r"git\s+reset\s+--hard",
            risk=RiskLevel.HIGH,
            description="Hard reset discards changes",
        ),
        RiskRule(
            name="sensitive_file_edit",
            tool="*",
            pattern=r"\.(env|pem|key|secret|credentials|password)([\"'\s}]|$)",
            risk=RiskLevel.HIGH,
            description="Editing sensitive/secret files",
        ),
        RiskRule(
            name="network_send",
            tool="Bash",
            pattern=r"\b(curl\s+.*-X\s*(POST|PUT|DELETE|PATCH)|wget\s+.*--post|npm\s+publish|docker\s+push)\b",
            risk=RiskLevel.HIGH,
            description="Network operations that send data",
        ),
        # --- MEDIUM risk ---
        RiskRule(
            name="file_overwrite",
            tool="Write",
            pattern=r".",  # any Write call is at least medium (overwrites file)
            risk=RiskLevel.MEDIUM,
            description="Overwriting a file",
        ),
        RiskRule(
            name="network_read",
            tool="Bash",
            pattern=r"\b(curl|wget|http|fetch)\b",
            risk=RiskLevel.MEDIUM,
            description="Network read operations",
        ),
        RiskRule(
            name="package_install",
            tool="Bash",
            pattern=r"\b(pip\s+install|npm\s+install|yarn\s+add|apt\s+install|brew\s+install)\b",
            risk=RiskLevel.MEDIUM,
            description="Installing packages",
        ),
        RiskRule(
            name="git_destructive",
            tool="Bash",
            pattern=r"git\s+(checkout\s+--\s|restore\s|clean\s+-f|branch\s+-D)",
            risk=RiskLevel.MEDIUM,
            description="Potentially destructive git operations",
        ),
    ]
