"""Scope Guard — safety guardrail for agentic AI systems."""

from scope_guard.scope import ScopeBoundary, Assumption
from scope_guard.risk import RiskEngine, RiskLevel
from scope_guard.checker import ScopeChecker, CheckResult, CheckVerdict

__version__ = "0.1.0"

__all__ = [
    "ScopeBoundary",
    "Assumption",
    "RiskEngine",
    "RiskLevel",
    "ScopeChecker",
    "CheckResult",
    "CheckVerdict",
]
