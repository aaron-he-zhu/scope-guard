"""Tests for ScopeBoundary."""

import json
import tempfile
from pathlib import Path

from scope_guard.scope import ScopeBoundary, Assumption, RiskLevel


class TestScopeBoundary:
    def test_empty_scope(self):
        sb = ScopeBoundary()
        assert sb.is_empty
        assert sb.risk_level == RiskLevel.LOW
        assert not sb.approval_required

    def test_file_in_scope_exact(self):
        sb = ScopeBoundary(files_in_scope=["src/auth/login.py", "src/auth/session.py"])
        assert sb.is_file_in_scope("src/auth/login.py")
        assert not sb.is_file_in_scope("src/api/routes.py")

    def test_file_in_scope_via_dir(self):
        sb = ScopeBoundary(dirs_in_scope=["src/auth"])
        assert sb.is_file_in_scope("src/auth/login.py")
        assert sb.is_file_in_scope("src/auth/deep/nested.py")
        assert not sb.is_file_in_scope("src/api/routes.py")

    def test_file_in_scope_dir_trailing_slash(self):
        sb = ScopeBoundary(dirs_in_scope=["src/auth/"])
        assert sb.is_file_in_scope("src/auth/login.py")

    def test_expand_scope(self):
        sb = ScopeBoundary(files_in_scope=["a.py"])
        sb.expand_scope(files=["b.py"], reason="user requested")
        assert sb.is_file_in_scope("b.py")
        assert len(sb.revisions) == 1
        assert sb.revisions[0]["action"] == "expand"
        assert sb.revisions[0]["reason"] == "user requested"

    def test_expand_no_duplicates(self):
        sb = ScopeBoundary(files_in_scope=["a.py"])
        sb.expand_scope(files=["a.py", "b.py"])
        assert len(sb.files_in_scope) == 2

    def test_merge(self):
        a = ScopeBoundary(
            files_in_scope=["a.py"],
            risk_level=RiskLevel.LOW,
            assumptions=[Assumption(text="A exists")],
        )
        b = ScopeBoundary(
            files_in_scope=["b.py"],
            dirs_in_scope=["src/"],
            risk_level=RiskLevel.HIGH,
            assumptions=[Assumption(text="B exists"), Assumption(text="A exists")],
            approval_required=True,
        )
        merged = a.merge(b)
        assert set(merged.files_in_scope) == {"a.py", "b.py"}
        assert merged.dirs_in_scope == ["src/"]
        assert merged.risk_level == RiskLevel.HIGH
        assert merged.approval_required is True
        # No duplicate assumptions
        assert len(merged.assumptions) == 2

    def test_save_load_roundtrip(self):
        sb = ScopeBoundary(
            files_in_scope=["x.py"],
            dirs_in_scope=["src/"],
            assumptions=[Assumption(text="test assumption", verified=True, verification_method="grep")],
            risk_level=RiskLevel.MEDIUM,
            approval_required=True,
            task_summary="test task",
        )
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "scope.json"
            sb.save(path)
            loaded = ScopeBoundary.load(path)

        assert loaded.files_in_scope == ["x.py"]
        assert loaded.dirs_in_scope == ["src/"]
        assert loaded.risk_level == RiskLevel.MEDIUM
        assert loaded.approval_required is True
        assert loaded.task_summary == "test task"
        assert len(loaded.assumptions) == 1
        assert loaded.assumptions[0].verified is True
        assert loaded.assumptions[0].verification_method == "grep"

    def test_load_missing_file_returns_empty(self):
        sb = ScopeBoundary.load("/nonexistent/path/scope.json")
        assert sb.is_empty

    def test_to_dict_from_dict(self):
        sb = ScopeBoundary(
            files_in_scope=["f.py"],
            assumptions=[Assumption(text="hello")],
            risk_level=RiskLevel.HIGH,
        )
        d = sb.to_dict()
        restored = ScopeBoundary.from_dict(d)
        assert restored.files_in_scope == sb.files_in_scope
        assert restored.risk_level == sb.risk_level
        assert restored.assumptions[0].text == "hello"


class TestAssumption:
    def test_to_dict_minimal(self):
        a = Assumption(text="test")
        d = a.to_dict()
        assert d == {"text": "test", "verified": False}

    def test_to_dict_full(self):
        a = Assumption(text="test", verified=True, verification_method="grep")
        d = a.to_dict()
        assert d["verification_method"] == "grep"

    def test_from_dict(self):
        a = Assumption.from_dict({"text": "hello", "verified": True})
        assert a.text == "hello"
        assert a.verified is True
        assert a.verification_method is None
