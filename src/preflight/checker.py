"""ScopeChecker — the core engine that decides allow / warn / block for every tool call."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from preflight.risk import RiskEngine, RiskLevel
from preflight.scope import ScopeBoundary


class CheckVerdict(str, Enum):
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"


@dataclass
class CheckResult:
    verdict: CheckVerdict
    tool: str
    target: str
    reason: str
    risk_level: RiskLevel
    scope_violation: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "tool": self.tool,
            "target": self.target,
            "reason": self.reason,
            "risk_level": self.risk_level.value,
            "scope_violation": self.scope_violation,
        }


# Tools that read but don't modify — always allow.
_READ_ONLY_TOOLS = frozenset({
    "Read", "Glob", "Grep", "WebSearch", "WebFetch",
    "TodoWrite", "AskUserQuestion",
})

# Tools where we extract a file path to check scope.
_FILE_PATH_TOOLS = frozenset({
    "Edit", "Write", "NotebookEdit",
})


class ScopeChecker:
    """Evaluate a tool call against a ScopeBoundary and risk rules."""

    def __init__(
        self,
        boundary: ScopeBoundary,
        risk_engine: RiskEngine | None = None,
    ) -> None:
        self.boundary = boundary
        self.risk_engine = risk_engine or RiskEngine.default()

    # --- main entry ---

    def check(self, tool_name: str, params: dict[str, Any]) -> CheckResult:
        # 1. Read-only tools are always allowed.
        if tool_name in _READ_ONLY_TOOLS:
            return CheckResult(
                verdict=CheckVerdict.ALLOW,
                tool=tool_name,
                target="",
                reason="read-only tool",
                risk_level=RiskLevel.LOW,
            )

        # 2. If no scope boundary is set, fall back to risk-only check.
        if self.boundary.is_empty:
            risk = self.risk_engine.assess(tool_name, params)
            return self._risk_only_result(tool_name, params, risk)

        # 3. File-path tools: check scope + risk.
        if tool_name in _FILE_PATH_TOOLS:
            return self._check_file_tool(tool_name, params)

        # 4. Bash: check risk, and optionally check scope via file refs in command.
        if tool_name == "Bash":
            return self._check_bash(tool_name, params)

        # 5. Everything else: risk-only.
        risk = self.risk_engine.assess(tool_name, params)
        return self._risk_only_result(tool_name, params, risk)

    # --- internal ---

    def _check_file_tool(self, tool_name: str, params: dict[str, Any]) -> CheckResult:
        file_path = params.get("file_path", params.get("notebook_path", ""))
        risk = self.risk_engine.assess(tool_name, params)

        if not file_path:
            return CheckResult(
                verdict=CheckVerdict.WARN,
                tool=tool_name,
                target="",
                reason="no file path detected — cannot verify scope",
                risk_level=risk,
            )

        in_scope = self.boundary.is_file_in_scope(file_path)

        if in_scope:
            verdict = self._verdict_for_risk(risk)
            return CheckResult(
                verdict=verdict,
                tool=tool_name,
                target=file_path,
                reason="in scope" if verdict == CheckVerdict.ALLOW else f"in scope but {risk.value} risk",
                risk_level=risk,
            )

        # Out of scope — at minimum warn, block if high risk.
        verdict = CheckVerdict.BLOCK if risk == RiskLevel.HIGH else CheckVerdict.WARN
        return CheckResult(
            verdict=verdict,
            tool=tool_name,
            target=file_path,
            reason=f"out of scope ({file_path})",
            risk_level=risk,
            scope_violation=True,
        )

    def _check_bash(self, tool_name: str, params: dict[str, Any]) -> CheckResult:
        command = params.get("command", "")
        risk = self.risk_engine.assess(tool_name, params)

        if risk == RiskLevel.HIGH:
            return CheckResult(
                verdict=CheckVerdict.BLOCK,
                tool=tool_name,
                target=command[:120],
                reason="high-risk shell command",
                risk_level=risk,
            )

        if risk == RiskLevel.MEDIUM:
            return CheckResult(
                verdict=CheckVerdict.WARN,
                tool=tool_name,
                target=command[:120],
                reason="medium-risk shell command",
                risk_level=risk,
            )

        return CheckResult(
            verdict=CheckVerdict.ALLOW,
            tool=tool_name,
            target=command[:120],
            reason="low-risk shell command",
            risk_level=risk,
        )

    def _risk_only_result(self, tool_name: str, params: dict[str, Any], risk: RiskLevel) -> CheckResult:
        verdict = self._verdict_for_risk(risk)
        target = _extract_target(tool_name, params)
        return CheckResult(
            verdict=verdict,
            tool=tool_name,
            target=target,
            reason=f"{risk.value} risk",
            risk_level=risk,
        )

    @staticmethod
    def _verdict_for_risk(risk: RiskLevel) -> CheckVerdict:
        if risk == RiskLevel.HIGH:
            return CheckVerdict.BLOCK
        if risk == RiskLevel.MEDIUM:
            return CheckVerdict.WARN
        return CheckVerdict.ALLOW


def _extract_target(tool_name: str, params: dict[str, Any]) -> str:
    """Best-effort extraction of the target from params."""
    for key in ("file_path", "notebook_path", "command", "pattern", "url", "query"):
        if key in params:
            return str(params[key])[:120]
    return ""


# ---------------------------------------------------------------------------
# Hook entry point: called by pre_tool_use.sh / Claude Code hooks
# ---------------------------------------------------------------------------

def hook_main() -> None:
    """Read a tool call from stdin (JSON), check it, print verdict to stdout.

    Exit codes:
        0 — allow (tool may proceed)
        1 — warn  (tool proceeds but user sees warning)
        2 — block (tool is prevented, user must confirm)
    """
    raw = sys.stdin.read()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        # Safety tool must fail closed — block on unparseable input.
        print(json.dumps({"verdict": "block", "reason": "unparsable input"}))
        sys.exit(2)

    tool_name = payload.get("tool_name", payload.get("tool", ""))
    params = payload.get("tool_input", payload.get("params", {}))

    # Load scope boundary from the conventional location.
    scope_path = Path.cwd() / ".claude" / "scope-boundary.json"
    boundary = ScopeBoundary.load(scope_path)
    engine = RiskEngine.default()
    checker = ScopeChecker(boundary, engine)
    result = checker.check(tool_name, params)

    # Write audit log.
    try:
        from preflight.audit import AuditLog
        audit = AuditLog.default()
        audit.record(result)
    except Exception as exc:
        print(f"[preflight] audit write failed: {exc}", file=sys.stderr)

    print(json.dumps(result.to_dict()))

    exit_code = {"allow": 0, "warn": 1, "block": 2}[result.verdict.value]
    sys.exit(exit_code)


if __name__ == "__main__":
    hook_main()
