# Scope Guard

Scope guard for agentic AI systems. Prevents scope drift, enforces risk-based approval gates, and surfaces hidden assumptions — automatically.

## The problem

When AI agents work on your code, they sometimes:

- **Drift**: edit files unrelated to your request
- **Escalate**: run destructive commands without confirmation
- **Assume**: make silent assumptions that lead to wrong changes

Scope Guard catches these before they happen.

## How it works

```
User request
    |
Claude Code + Scope Guard SKILL.md
    |  generates
.claude/scope-boundary.json
    |-- files_in_scope: ["src/auth/login.ts", ...]
    |-- assumptions: [{text, verified}]
    |-- risk_level: low | medium | high
    +-- approval_required: true | false
    |
PreToolUse hook (every tool call)
    |-- In scope + low risk  ->  ALLOW (silent)
    |-- Out of scope         ->  WARN  (expand scope?)
    +-- High risk            ->  BLOCK (confirm first)
```

## Quickstart

```bash
# 1. Install
npm install scope-guard

# 2. Build
npm run build

# 3. Add hook to .claude/settings.json
cat <<'EOF' >> .claude/settings.json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [{"type": "command", "command": "node dist/hook.js"}]
      }
    ]
  }
}
EOF

# 4. Done — every tool call is now guarded
```

Or install the SKILL.md only (prompt-level, no code hook):

```bash
mkdir -p .claude/skills/scope-guard
cp SKILL.md .claude/skills/scope-guard/
```

## What happens in practice

### Low risk (silent)
```
You: "Fix the typo in src/auth/login.ts"
-> Scope Guard writes scope boundary, proceeds silently. You notice nothing.
```

### Medium risk (one-line confirmation)
```
You: "Refactor the auth module"
-> "Scope: src/auth/ (8 files). Assuming all endpoints use JWT. Proceeding."
```

### High risk (explicit approval)
```
You: "Delete the old migration files and push"
-> "This involves file deletion + git push. Scope: db/migrations/. Proceed? [Y/n]"
```

## Audit log

Every scope check is logged to `.claude/scope-guard-audit.jsonl`:

```json
{"timestamp": "2026-04-06T10:15:00", "tool": "Edit", "target": "src/api/routes.ts", "verdict": "warn", "risk_level": "medium", "scope_violation": true, "reason": "out of scope"}
```

## Design principles

1. **Invisible when possible.** Low-risk, in-scope work proceeds without interruption.
2. **Code enforces, not prompts.** Risk rules run as a Node.js hook — not as LLM instructions that can be ignored.
3. **Scope only expands with consent.** The agent cannot unilaterally broaden its own scope.

## Issues & feedback

Report bugs or request features at [github.com/aaron-he-zhu/preflight-scope/issues](https://github.com/aaron-he-zhu/preflight-scope/issues).

## License

MIT
