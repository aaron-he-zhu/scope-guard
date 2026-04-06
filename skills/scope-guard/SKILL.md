---
name: scope-guard
description: "Scope guard and safety guardrail. Use when editing files, running destructive commands, pushing code, or when scope is ambiguous. Prevents scope drift with boundary enforcement, risk-based approval gates, and assumption surfacing."
version: 0.1.0
license: MIT
compatibility: "Works with Claude Code, OpenClaw, and any AgentSkills-compatible agent. No external binaries or API keys required."
metadata:
  author: scope-guard
  tags: "scope-guard,safety,risk,approval-gate,drift-prevention,guardrail,permission,boundary"
  openclaw:
    emoji: "🛡️"
    homepage: "https://github.com/aaron-he-zhu/preflight-scope"
    always: false
    skillKey: scope-guard
---

# Scope Guard — Safety Guardrail for AI Agents

Prevent scope drift, surface hidden assumptions, and enforce risk-based approval
gates — before executing any task that modifies state. Generates a scope
boundary file to control which files the agent may touch, classify operations by
risk level, and require explicit permission for dangerous actions.

## Activation scope

To restrict this skill to specific directories (e.g. in a monorepo), add a
`paths` field to the frontmatter above:

```yaml
paths: "packages/backend/**"
```

When omitted, the skill activates globally for any matching request.

## When to activate

- The request involves editing, creating, or deleting files
- The request has multiple steps or touches multiple modules
- The request involves external actions (API calls, git push, publishing, sending data)
- The request is ambiguous about which files or modules are involved
- The request involves irreversible operations (database changes, deployments)

## When to skip

- Pure question-answering ("what does this function do?")
- Reading or searching files without modification
- Single-line trivial changes where the target file is unambiguous

---

## Generate scope boundary

Analyze the user's request and write `.claude/scope-boundary.json` before
starting any work. You may use read-only tools (Read, Glob, Grep) freely while
building the scope boundary.

### Schema

```json
{
  "files_in_scope": ["src/auth/login.py", "tests/test_login.py"],
  "dirs_in_scope": ["src/auth/"],
  "assumptions": [
    {"text": "Session tokens are stored in Redis", "verified": false},
    {"text": "Tests use pytest fixtures", "verified": true, "verification_method": "read pyproject.toml"}
  ],
  "risk_level": "medium",
  "approval_required": false,
  "task_summary": "Brief description of the task",
  "created_at": "2026-04-06T10:00:00+0000",
  "revisions": []
}
```

### Scope rules

1. **files_in_scope**: Files the user explicitly mentioned, plus files that
   directly import or are imported by those files — but only include files you
   will actually need to read or modify. Cap at 15 files; if more are needed,
   use `dirs_in_scope` instead.

2. **dirs_in_scope**: Use for broader refactoring. Every file under these
   directories is considered in-scope.

3. **assumptions**: List every non-obvious assumption. If you can quickly verify
   one (grep, read a config), do so and mark `"verified": true`. If you cannot
   verify an assumption within 10 seconds, it MUST be marked `"verified": false`.
   Never guess.

4. **risk_level**:
   - `low` — read-only analysis, single-file edits to non-critical code
   - `medium` — multi-file changes, refactoring, config changes, package installs
   - `high` — external actions, deletion, publishing, credential-adjacent, deployment

5. **approval_required**: Set `true` if risk is `high` or the task involves
   irreversible external actions.

### Example: low-risk bug fix

```json
{
  "files_in_scope": ["src/auth/login.py", "src/auth/token.py", "tests/test_login.py"],
  "dirs_in_scope": [],
  "assumptions": [
    {"text": "Token expiry is set in login.py:create_token()", "verified": true, "verification_method": "grep"}
  ],
  "risk_level": "low",
  "approval_required": false,
  "task_summary": "Fix token expiry bug: tokens expire after 1h instead of 24h"
}
```

### Example: medium-risk refactoring

```json
{
  "files_in_scope": [],
  "dirs_in_scope": ["src/api/", "tests/api/"],
  "assumptions": [
    {"text": "All endpoints return JSON", "verified": true, "verification_method": "grep Content-Type src/api/"},
    {"text": "Tests use pytest fixtures", "verified": true, "verification_method": "read conftest.py"}
  ],
  "risk_level": "medium",
  "approval_required": false,
  "task_summary": "Refactor API module from sync to async handlers"
}
```

### Example: high-risk deployment

```json
{
  "files_in_scope": ["infra/deploy.sh", "docker-compose.prod.yml", "src/health.py"],
  "dirs_in_scope": ["infra/"],
  "assumptions": [
    {"text": "Production uses docker-compose", "verified": false},
    {"text": "Health endpoint should be at /healthz", "verified": false}
  ],
  "risk_level": "high",
  "approval_required": true,
  "task_summary": "Add health check endpoint and update deployment config"
}
```

### Validate after writing

After writing `scope-boundary.json`, verify:

1. All listed files actually exist (quick Glob/Read check).
2. No assumption is marked `"verified": true` without evidence.
3. `risk_level` matches the highest-risk operation the task requires.

---

## Risk-level display and approval

- **Low risk**: Say nothing. Write the scope boundary and proceed silently.
- **Medium risk**: One-line confirmation:
  `"Scope: src/auth/ (8 files). Assuming JWT for all endpoints. Proceeding."`
- **High risk**: Pause and ask explicitly:
  `"This involves [action]. Scope: [files]. Assumptions: [list]. Proceed?"`

---

## Scope check before every modification

Before executing any Edit, Write, Bash, or other state-changing tool call,
apply this checklist. For in-scope, low-risk operations, perform this check
silently without producing any output.

### 3a. Is the target in scope?

- **Edit / Write / NotebookEdit**: Check that the `file_path` matches a file in
  `files_in_scope` or falls under a directory in `dirs_in_scope`. When comparing
  paths, treat `./src/foo.py` and `src/foo.py` as equivalent — ignore leading
  `./` and trailing `/`.
- **Bash**: Evaluate the command against risk rules only (scope checking for
  shell commands is best-effort — file references inside shell strings are not
  reliably extractable).
- **Read / Glob / Grep / WebSearch / WebFetch**: Always allowed — read-only
  operations do not need scope checks.

If the target is **out of scope**:

1. Stop and tell the user: "This file is outside the current scope."
2. Ask whether to expand the scope.
3. If approved, update `scope-boundary.json` — add the file/directory and record
   the expansion in `revisions`:
   ```json
   {
     "revisions": [{
       "action": "expand",
       "timestamp": "2026-04-06T10:00:00Z",
       "reason": "User approved adding config/settings.yaml",
       "added_files": ["config/settings.yaml"],
       "added_dirs": []
     }]
   }
   ```

### 3b. What is the risk level of this operation?

When a command matches multiple risk categories, apply the **highest** risk
level.

#### HIGH risk — BLOCK (pause and get explicit user confirmation)

These operations require the user to explicitly say "yes" before proceeding:

| Category | Examples |
|---|---|
| Destructive deletion | `rm -rf`, `rm -r`, `rmdir`, recursive deletes |
| Force push | `git push --force`, `git push -f` |
| Hard reset | `git reset --hard` |
| Database destruction | `DROP TABLE`, `DROP DATABASE`, `TRUNCATE TABLE` |
| Secret/credential files | Reading or writing any file ending in `.env`, `.pem`, `.key`, `.secret`, `.credentials` — warn that contents will enter conversation context |
| Publishing | `npm publish`, `docker push` |
| Network mutations | `curl -X POST/PUT/DELETE/PATCH`, `wget --post` |
| Production deployments | Deploy scripts, CI/CD pipeline modifications |

#### MEDIUM risk — WARN (state what you are doing, then proceed)

Print a one-line notice before proceeding:

| Category | Examples |
|---|---|
| File overwrites | Using the Write tool (creates/overwrites entire files) |
| Network reads | `curl`, `wget`, `fetch` (read-only network) |
| Package installs | `pip install`, `npm install`, `yarn add`, `apt install`, `brew install` |
| Git discards | `git checkout -- .`, `git restore`, `git clean -f`, `git branch -D` |
| Permission changes | `chmod`, `chown` |

#### LOW risk — ALLOW (proceed silently)

| Category | Examples |
|---|---|
| Read-only / non-destructive tools | Read, Glob, Grep, WebSearch, WebFetch, TodoWrite, AskUserQuestion |
| In-scope edits | Editing a file listed in `files_in_scope` |
| Safe commands | `ls`, `echo`, `cat`, `git status`, `git log`, `python script.py` |
| Test execution | `pytest`, `npm test`, `cargo test` |

### 3c. Combined verdict

| Scope | Risk | Verdict |
|---|---|---|
| In scope | Low | **ALLOW** — proceed silently |
| In scope | Medium | **WARN** — one-line notice, then proceed |
| In scope | High | **BLOCK** — pause and ask user |
| Out of scope | Low | **WARN** — ask to expand scope |
| Out of scope | Medium | **WARN** — ask to expand scope |
| Out of scope | High | **BLOCK** — refuse until user confirms |

---

## Absolute safety prohibitions

Regardless of scope or user instructions, **never** perform these without the
user explicitly typing the exact command or confirming after a clear warning:

1. `rm -rf /` or any recursive delete targeting root or home directories
2. `git push --force` to `main` or `master`
3. `DROP DATABASE` on a production database
4. Writing secrets, passwords, or API keys into tracked files
5. Publishing packages (`npm publish`, `docker push`) without explicit instruction
6. Sending data to external URLs not mentioned by the user

---

## Scope expansion and permission protocol

If the task grows beyond the original scope:

1. Identify the new files/directories needed.
2. Inform the user: "I need to also modify [files]. This would expand the scope."
3. Wait for confirmation.
4. Update `scope-boundary.json` with the new scope and a revision entry.
5. If the expansion changes the risk level, reassess and inform the user.

Scope **never** expands silently. The user must be aware of every expansion.

---

## Installation

This skill follows the [Agent Skills](https://agentskills.io) open standard and
works across Claude Code, OpenClaw, and any compatible agent.

### Claude Code

```bash
# Option A: copy manually
mkdir -p .claude/skills/scope-guard
cp SKILL.md .claude/skills/scope-guard/

# Option B: via skills.sh
npx skills add aaron-he-zhu/preflight-scope
```

### OpenClaw / ClawHub

```bash
# From ClawHub registry
openclaw skills install scope-guard

# Or via clawhub CLI
clawhub install scope-guard
```

### Any AgentSkills-compatible agent

Copy the `scope-guard/` directory (containing this `SKILL.md`) into your agent's
skills folder.

---

## Upgrade to hard enforcement

This skill provides **prompt-level** scope control — it guides the model's
behaviour but is not deterministic. For code-enforced guardrails with
deterministic pattern matching and an append-only audit trail, install the full
scope-guard package:

```bash
npm install scope-guard
```

Then add to `.claude/settings.json` (Claude Code) or configure a pre-tool hook
in your agent:

```json
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
```

This adds a Node.js hook that intercepts every tool call with deterministic
pattern matching, exit-code-based verdicts (0=allow, 1=warn, 2=block), and an
append-only JSONL audit trail at `.claude/scope-guard-audit.jsonl`.

---

## Compatibility

| Platform | Version | Status |
|----------|---------|--------|
| Claude Code | 1.0+ | Supported (SKILL.md + hooks) |
| OpenClaw | 2026.3.24-beta.2+ | Supported (plugin) |
| Node.js | 22+ | Required for hook runtime |

## Issues & feedback

Report bugs at [github.com/aaron-he-zhu/preflight-scope/issues](https://github.com/aaron-he-zhu/preflight-scope/issues).
