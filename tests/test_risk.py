"""Tests for RiskEngine."""

from preflight.risk import RiskEngine, RiskLevel, RiskRule


class TestBuiltinRules:
    def setup_method(self):
        self.engine = RiskEngine.default()

    # --- HIGH risk ---

    def test_rm_rf_is_high(self):
        assert self.engine.assess("Bash", {"command": "rm -rf /tmp/old"}) == RiskLevel.HIGH

    def test_rm_recursive_is_high(self):
        assert self.engine.assess("Bash", {"command": "rm -r build/"}) == RiskLevel.HIGH

    def test_force_push_is_high(self):
        assert self.engine.assess("Bash", {"command": "git push origin main --force"}) == RiskLevel.HIGH

    def test_git_reset_hard_is_high(self):
        assert self.engine.assess("Bash", {"command": "git reset --hard HEAD~3"}) == RiskLevel.HIGH

    def test_drop_table_is_high(self):
        assert self.engine.assess("Bash", {"command": "psql -c 'DROP TABLE users'"}) == RiskLevel.HIGH

    def test_env_file_is_high(self):
        assert self.engine.assess("Edit", {"file_path": ".env", "old_string": "x", "new_string": "y"}) == RiskLevel.HIGH

    def test_pem_file_is_high(self):
        assert self.engine.assess("Write", {"file_path": "server.pem", "content": "..."}) == RiskLevel.HIGH

    def test_curl_post_is_high(self):
        assert self.engine.assess("Bash", {"command": "curl -X POST https://api.example.com/data"}) == RiskLevel.HIGH

    def test_npm_publish_is_high(self):
        assert self.engine.assess("Bash", {"command": "npm publish"}) == RiskLevel.HIGH

    def test_docker_push_is_high(self):
        assert self.engine.assess("Bash", {"command": "docker push myimage:latest"}) == RiskLevel.HIGH

    # --- MEDIUM risk ---

    def test_write_tool_is_medium(self):
        assert self.engine.assess("Write", {"file_path": "src/app.py", "content": "..."}) == RiskLevel.MEDIUM

    def test_curl_get_is_medium(self):
        assert self.engine.assess("Bash", {"command": "curl https://example.com"}) == RiskLevel.MEDIUM

    def test_pip_install_is_medium(self):
        assert self.engine.assess("Bash", {"command": "pip install requests"}) == RiskLevel.MEDIUM

    def test_npm_install_is_medium(self):
        assert self.engine.assess("Bash", {"command": "npm install lodash"}) == RiskLevel.MEDIUM

    def test_git_checkout_discard_is_medium(self):
        assert self.engine.assess("Bash", {"command": "git checkout -- src/file.py"}) == RiskLevel.MEDIUM

    def test_chmod_is_medium(self):
        assert self.engine.assess("Bash", {"command": "chmod 755 script.sh"}) == RiskLevel.MEDIUM

    # --- LOW risk ---

    def test_ls_is_low(self):
        assert self.engine.assess("Bash", {"command": "ls -la"}) == RiskLevel.LOW

    def test_echo_is_low(self):
        assert self.engine.assess("Bash", {"command": "echo hello"}) == RiskLevel.LOW

    def test_edit_normal_file_is_low(self):
        assert self.engine.assess("Edit", {"file_path": "src/app.py", "old_string": "x", "new_string": "y"}) == RiskLevel.LOW

    def test_read_tool_is_low(self):
        assert self.engine.assess("Read", {"file_path": "README.md"}) == RiskLevel.LOW

    def test_git_status_is_low(self):
        assert self.engine.assess("Bash", {"command": "git status"}) == RiskLevel.LOW

    def test_python_run_is_low(self):
        assert self.engine.assess("Bash", {"command": "python test.py"}) == RiskLevel.LOW


class TestRiskRule:
    def test_matches_tool_and_pattern(self):
        rule = RiskRule(name="test", tool="Bash", pattern=r"rm\s+-rf", risk=RiskLevel.HIGH)
        assert rule.matches("Bash", "rm -rf /tmp")
        assert not rule.matches("Edit", "rm -rf /tmp")
        assert not rule.matches("Bash", "echo hello")

    def test_wildcard_tool(self):
        rule = RiskRule(name="test", tool="*", pattern=r"\.env", risk=RiskLevel.HIGH)
        assert rule.matches("Edit", '{"file_path": ".env"}')
        assert rule.matches("Write", '{"file_path": ".env"}')

    def test_case_insensitive(self):
        rule = RiskRule(name="test", tool="Bash", pattern=r"DROP TABLE", risk=RiskLevel.HIGH)
        assert rule.matches("Bash", "drop table users")
        assert rule.matches("bash", "DROP TABLE users")


class TestMatchingRules:
    def test_returns_all_matches(self):
        engine = RiskEngine.default()
        rules = engine.matching_rules("Bash", {"command": "rm -rf .env"})
        names = {r.name for r in rules}
        assert "destructive_bash" in names or "destructive_rm" in names
        assert "sensitive_file_edit" in names or "secret_files" in names


class TestCustomRules:
    def test_custom_rule_overrides(self):
        custom = RiskRule(
            name="custom_high",
            tool="Bash",
            pattern=r"my-special-command",
            risk=RiskLevel.HIGH,
        )
        engine = RiskEngine(rules=[custom])
        assert engine.assess("Bash", {"command": "my-special-command --flag"}) == RiskLevel.HIGH
        assert engine.assess("Bash", {"command": "echo hello"}) == RiskLevel.LOW
