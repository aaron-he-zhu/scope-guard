"""Tests for ScopeChecker."""

from scope_guard.checker import ScopeChecker, CheckVerdict
from scope_guard.risk import RiskEngine, RiskLevel
from scope_guard.scope import ScopeBoundary


class TestReadOnlyTools:
    """Read-only tools should always be allowed regardless of scope."""

    def setup_method(self):
        self.boundary = ScopeBoundary(files_in_scope=["src/app.py"])
        self.checker = ScopeChecker(self.boundary)

    def test_read_allowed(self):
        result = self.checker.check("Read", {"file_path": "any/file.py"})
        assert result.verdict == CheckVerdict.ALLOW

    def test_glob_allowed(self):
        result = self.checker.check("Glob", {"pattern": "**/*.py"})
        assert result.verdict == CheckVerdict.ALLOW

    def test_grep_allowed(self):
        result = self.checker.check("Grep", {"pattern": "TODO"})
        assert result.verdict == CheckVerdict.ALLOW

    def test_websearch_allowed(self):
        result = self.checker.check("WebSearch", {"query": "python docs"})
        assert result.verdict == CheckVerdict.ALLOW


class TestFileScopeCheck:
    """Edit/Write tools should be checked against the scope boundary."""

    def setup_method(self):
        self.boundary = ScopeBoundary(
            files_in_scope=["src/auth/login.py"],
            dirs_in_scope=["src/auth/"],
        )
        self.checker = ScopeChecker(self.boundary)

    def test_edit_in_scope_allowed(self):
        result = self.checker.check("Edit", {
            "file_path": "src/auth/login.py",
            "old_string": "x",
            "new_string": "y",
        })
        assert result.verdict == CheckVerdict.ALLOW
        assert not result.scope_violation

    def test_edit_in_scope_dir_allowed(self):
        result = self.checker.check("Edit", {
            "file_path": "src/auth/session.py",
            "old_string": "x",
            "new_string": "y",
        })
        assert result.verdict == CheckVerdict.ALLOW

    def test_edit_out_of_scope_warns(self):
        result = self.checker.check("Edit", {
            "file_path": "src/api/routes.py",
            "old_string": "x",
            "new_string": "y",
        })
        assert result.verdict == CheckVerdict.WARN
        assert result.scope_violation

    def test_write_out_of_scope_warns(self):
        # Write is medium risk + out of scope = warn
        result = self.checker.check("Write", {
            "file_path": "src/api/routes.py",
            "content": "new content",
        })
        assert result.verdict == CheckVerdict.WARN
        assert result.scope_violation

    def test_edit_env_out_of_scope_blocks(self):
        # .env = high risk + out of scope = block
        result = self.checker.check("Edit", {
            "file_path": ".env",
            "old_string": "x",
            "new_string": "y",
        })
        assert result.verdict == CheckVerdict.BLOCK
        assert result.scope_violation


class TestBashCheck:
    """Bash commands should be assessed by risk level."""

    def setup_method(self):
        self.boundary = ScopeBoundary(files_in_scope=["src/app.py"])
        self.checker = ScopeChecker(self.boundary)

    def test_low_risk_allowed(self):
        result = self.checker.check("Bash", {"command": "ls -la"})
        assert result.verdict == CheckVerdict.ALLOW

    def test_medium_risk_warns(self):
        result = self.checker.check("Bash", {"command": "pip install requests"})
        assert result.verdict == CheckVerdict.WARN

    def test_high_risk_blocks(self):
        result = self.checker.check("Bash", {"command": "rm -rf /tmp/data"})
        assert result.verdict == CheckVerdict.BLOCK

    def test_force_push_blocks(self):
        result = self.checker.check("Bash", {"command": "git push --force origin main"})
        assert result.verdict == CheckVerdict.BLOCK


class TestEmptyScope:
    """With no scope boundary, fall back to risk-only mode."""

    def setup_method(self):
        self.checker = ScopeChecker(ScopeBoundary())

    def test_edit_any_file_follows_risk(self):
        result = self.checker.check("Edit", {
            "file_path": "any/file.py",
            "old_string": "x",
            "new_string": "y",
        })
        # Normal file, low risk, no scope = allow
        assert result.verdict == CheckVerdict.ALLOW

    def test_edit_env_still_blocks(self):
        result = self.checker.check("Edit", {
            "file_path": ".env",
            "old_string": "x",
            "new_string": "y",
        })
        assert result.verdict == CheckVerdict.BLOCK

    def test_destructive_bash_still_blocks(self):
        result = self.checker.check("Bash", {"command": "rm -rf /"})
        assert result.verdict == CheckVerdict.BLOCK


class TestCheckResultOutput:
    """Verify CheckResult serialisation."""

    def test_to_dict(self):
        boundary = ScopeBoundary(files_in_scope=["a.py"])
        checker = ScopeChecker(boundary)
        result = checker.check("Edit", {"file_path": "b.py", "old_string": "x", "new_string": "y"})
        d = result.to_dict()
        assert "verdict" in d
        assert "tool" in d
        assert "target" in d
        assert "risk_level" in d
        assert "scope_violation" in d
