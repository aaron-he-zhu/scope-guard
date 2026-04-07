# Scope Guard

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node.js >= 22](https://img.shields.io/badge/Node.js-%3E%3D22-green.svg)](https://nodejs.org)
[![Tests: 104+](https://img.shields.io/badge/Tests-104%2B-brightgreen.svg)](src/test.ts)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-0-brightgreen.svg)](package.json)

Deterministic safety guardrail for AI coding agents. Prevents scope drift, enforces risk-based approval gates, and surfaces hidden assumptions — with code that the model can't override.

## Why scope-guard?

When AI agents work on your code, they sometimes:

- **Drift**: edit files unrelated to your request
- **Escalate**: run destructive commands without asking
- **Assume**: make silent assumptions that lead to wrong changes

Prompt-level instructions help, but the model can ignore them. **Scope Guard enforces boundaries with deterministic code hooks** — exit code 2 means BLOCK, no negotiation.

### Dual-layer enforcement

| Layer | How | Strength |
|-------|-----|----------|
| **SKILL.md** (prompt) | Guides the model to generate scope boundaries and check before acting | Covers ~80% of cases, flexible |
| **Code hook** (deterministic) | Intercepts every tool call, pattern-matches risk, enforces exit codes | 100% enforcement, cannot be overridden |

Use one layer or both. SKILL.md alone is a good start. Add the code hook for hard guarantees.

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

# 3. Auto-setup (hook + SKILL.md)
npx scope-guard-init

# Done — every tool call is now guarded
```

The init command is idempotent — safe to run multiple times. It:
- Adds the `PreToolUse` hook to `.claude/settings.json` (merges with existing hooks)
- Copies `SKILL.md` to `.claude/skills/scope-guard/`

<details>
<summary>Manual setup (alternative)</summary>

```bash
# Add hook to .claude/settings.json
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

# Copy SKILL.md
mkdir -p .claude/skills/scope-guard
cp SKILL.md .claude/skills/scope-guard/
```
</details>

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

## Built-in risk rules

14 rules covering common dangerous operations:

| Risk | Operations |
|------|-----------|
| **HIGH** | `rm -rf`, `git push --force`, `git reset --hard`, `DROP TABLE`, `.env`/`.pem`/`.key` files, `npm publish`, `docker push`, `curl -X POST`, `wget --post` |
| **MEDIUM** | `Write` tool, `curl`/`wget` (read), `npm install`/`pip install`, `chmod`/`chown`, `git checkout --`/`restore`/`clean -f`, reading sensitive system files |
| **LOW** | `Read`, `Glob`, `Grep`, `ls`, `echo`, `git status`, test commands |

## Custom risk rules

Extend the risk engine with your own rules in code:

```typescript
import { RiskEngine, RiskRule, RiskLevel } from "scope-guard/risk";

const engine = new RiskEngine([
  ...builtinRules(),
  new RiskRule({
    name: "deploy_script",
    tool: "Bash",
    pattern: "deploy\\.sh",
    risk: RiskLevel.HIGH,
    description: "Production deploy script",
  }),
  new RiskRule({
    name: "test_files",
    tool: "Edit",
    pattern: "tests?/",
    risk: RiskLevel.LOW,
    description: "Test files are low risk",
  }),
]);
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add built-in rules.

## Audit log

Every scope check is logged to `.claude/scope-guard-audit.jsonl` with HMAC integrity:

```json
{"timestamp": "2026-04-06T10:15:00", "tool": "Edit", "target": "src/api/routes.ts", "verdict": "warn", "risk_level": "medium", "scope_violation": true, "reason": "out of scope", "hmac": "a1b2c3..."}
```

Verify audit integrity:

```typescript
import { AuditLog } from "scope-guard/audit";
const log = new AuditLog(".claude/scope-guard-audit.jsonl");
const { valid, tampered } = log.verify();
```

## Scope boundary schema

A [JSON Schema](scope-boundary.schema.json) is provided for editor autocompletion. Add to your `.vscode/settings.json`:

```json
{
  "json.schemas": [{
    "fileMatch": ["**/scope-boundary.json"],
    "url": "./scope-boundary.schema.json"
  }]
}
```

## Design principles

1. **Invisible when possible.** Low-risk, in-scope work proceeds without interruption.
2. **Code enforces, not prompts.** Risk rules run as a Node.js hook — deterministic, not LLM-dependent.
3. **Scope only expands with consent.** The agent cannot unilaterally broaden its own scope.
4. **Fail closed.** On any error — bad input, missing config, internal crash — the verdict is BLOCK.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, project structure, and how to add risk rules.

## Issues & feedback

Report bugs or request features at [github.com/aaron-he-zhu/preflight-scope/issues](https://github.com/aaron-he-zhu/preflight-scope/issues).

## License

MIT
