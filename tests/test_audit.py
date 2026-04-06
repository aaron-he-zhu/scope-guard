"""Tests for AuditLog."""

import tempfile
from pathlib import Path

from scope_guard.audit import AuditLog
from scope_guard.checker import CheckResult, CheckVerdict
from scope_guard.risk import RiskLevel


class TestAuditLog:
    def test_record_and_read(self):
        with tempfile.TemporaryDirectory() as td:
            log = AuditLog(Path(td) / "audit.jsonl")

            result = CheckResult(
                verdict=CheckVerdict.WARN,
                tool="Edit",
                target="src/api.py",
                reason="out of scope",
                risk_level=RiskLevel.MEDIUM,
                scope_violation=True,
            )
            log.record(result)

            entries = log.read()
            assert len(entries) == 1
            assert entries[0].tool == "Edit"
            assert entries[0].verdict == "warn"
            assert entries[0].scope_violation is True

    def test_multiple_records(self):
        with tempfile.TemporaryDirectory() as td:
            log = AuditLog(Path(td) / "audit.jsonl")

            for i in range(5):
                log.record(CheckResult(
                    verdict=CheckVerdict.ALLOW,
                    tool="Read",
                    target=f"file{i}.py",
                    reason="ok",
                    risk_level=RiskLevel.LOW,
                ))

            entries = log.read()
            assert len(entries) == 5

    def test_summary(self):
        with tempfile.TemporaryDirectory() as td:
            log = AuditLog(Path(td) / "audit.jsonl")

            log.record(CheckResult(CheckVerdict.ALLOW, "Read", "", "ok", RiskLevel.LOW))
            log.record(CheckResult(CheckVerdict.WARN, "Edit", "x.py", "scope", RiskLevel.MEDIUM, True))
            log.record(CheckResult(CheckVerdict.BLOCK, "Bash", "rm -rf", "danger", RiskLevel.HIGH))

            s = log.summary()
            assert s["total"] == 3
            assert s["verdicts"]["allow"] == 1
            assert s["verdicts"]["warn"] == 1
            assert s["verdicts"]["block"] == 1
            assert s["scope_violations"] == 1

    def test_empty_log(self):
        with tempfile.TemporaryDirectory() as td:
            log = AuditLog(Path(td) / "nonexistent.jsonl")
            assert log.read() == []
            s = log.summary()
            assert s["total"] == 0

    def test_read_limit(self):
        with tempfile.TemporaryDirectory() as td:
            log = AuditLog(Path(td) / "audit.jsonl")
            for i in range(20):
                log.record(CheckResult(CheckVerdict.ALLOW, "Read", f"f{i}", "ok", RiskLevel.LOW))
            entries = log.read(limit=5)
            assert len(entries) == 5
            # Should return the last 5
            assert entries[-1].target == "f19"
