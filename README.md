# Preflight

Scope guard for agentic AI systems. Prevents scope drift, enforces risk-based approval gates, and surfaces hidden assumptions — automatically.

## The problem

When AI agents work on your code, they sometimes:

- **Drift**: edit files unrelated to your request
- **Escalate**: run destructive commands without confirmation
- **Assume**: make silent assumptions that lead to wrong changes

Preflight catches these before they happen.

## How it works

```
User request
    ↓
Claude Code + Preflight SKILL.md
    ↓  generates
.claude/scope-boundary.json
    ├── files_in_scope: ["src/auth/login.py", ...]
    ├── assumptions: [{text, verified}]
    ├── risk_level: low | medium | high
    └── approval_required: true | false
    ↓
PreToolUse hook (every tool call)
    ├── In scope + low risk  →  ALLOW (silent)
    ├── Out of scope         →  WARN  (expand scope?)
    └── High risk            →  BLOCK (confirm first)
```

## Install

```bash
pip install preflight-scope
preflight init
```

This creates:
- `.claude/scope-boundary.json` — scope state (auto-generated per task)
- `.claude/preflight-rules.yaml` — risk rules (customisable)
- `.claude/commands/preflight.md` — Claude Code skill

Then add the hook to `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [{"type": "command", "command": "python -m preflight.checker"}]
      }
    ]
  }
}
```

## What happens in practice

### Low risk (silent)
```
You: "Fix the typo in src/auth/login.py"
→ Preflight writes scope boundary, proceeds silently. You notice nothing.
```

### Medium risk (one-line confirmation)
```
You: "Refactor the auth module"
→ "Scope: src/auth/ (8 files). Assuming all endpoints use JWT. Proceeding."
```

### High risk (explicit approval)
```
You: "Delete the old migration files and push"
→ "This involves file deletion + git push. Scope: db/migrations/. Proceed? [Y/n]"
```

## CLI

```bash
preflight status    # Show current scope boundary + audit summary
preflight check Edit '{"file_path": "src/api.py"}'  # Test a tool call
```

## Customising risk rules

Edit `.claude/preflight-rules.yaml`:

```yaml
rules:
  - name: our_deploy_script
    tool: Bash
    pattern: 'deploy\.sh'
    risk: high
    description: Production deploy script

  - name: test_files_ok
    tool: Edit
    pattern: 'tests?/'
    risk: low
    description: Test files are low risk
```

## Audit log

Every scope check is logged to `.claude/preflight-audit.jsonl`:

```json
{"timestamp": "2026-04-06T10:15:00", "tool": "Edit", "target": "src/api/routes.py", "verdict": "warn", "risk_level": "medium", "scope_violation": true, "reason": "out of scope"}
```

View summary: `preflight status`

## Design principles

1. **Invisible when possible.** Low-risk, in-scope work proceeds without interruption.
2. **Code enforces, not prompts.** Risk rules run as a Python hook — not as LLM instructions that can be ignored.
3. **Scope only expands with consent.** The agent cannot unilaterally broaden its own scope.

## Origin

This project evolved from [Work Contract OS](https://github.com/example/work-contract-os), a design exploration of task contract layers for agentic systems. The core insight — that agents need explicit scope boundaries before execution — was preserved. The implementation was rebuilt from pure documentation into a working tool with code-enforced guarantees.

## License

MIT
