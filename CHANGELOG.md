# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-04-07

### Added
- ScopeChecker with 4-verdict matrix: ALLOW / WARN / ESCALATE / BLOCK
- RiskEngine with 38 built-in risk rules covering shell, MCP, compliance, and industry-specific risk patterns
- ScopeBoundary with path normalization and traversal prevention
- AuditLog with append-only JSONL and HMAC integrity signing
- Claude hook entry points for PreToolUse and PostToolUse
- OpenClaw plugin entry point (`index.ts`) — `before_tool_call` hook
- SKILL.md for prompt-level enforcement (AgentSkills open standard)
- Dual-platform support: Claude Code (.claude-plugin) + OpenClaw (openclaw.plugin.json)
- 200+ tests across policy, audit, hook, MCP, and packaging paths using Node built-in test runner
- scope-boundary.schema.json for editor autocompletion
- GitHub Actions CI (test on every push/PR)

### Security
- Fail-closed on all error paths (empty input, malformed JSON, null payload)
- Windows backslash path traversal prevention
- Non-greedy regex patterns to prevent ReDoS
- Sensitive file read detection (cat /etc/shadow, head .env)
- Empty tool name returns WARN (not silent ALLOW)
- HMAC-SHA256 audit log integrity verification
