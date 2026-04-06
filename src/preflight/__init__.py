"""Preflight — scope guard for agentic AI systems."""

from preflight.scope import ScopeBoundary, Assumption
from preflight.risk import RiskEngine, RiskLevel
from preflight.checker import ScopeChecker, CheckResult, CheckVerdict

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
