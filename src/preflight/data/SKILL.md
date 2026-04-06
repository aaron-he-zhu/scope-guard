---
name: preflight
description: Generate a scope boundary before task execution. Prevents scope drift, surfaces assumptions, and enforces risk-based approval gates. Activates automatically for file-modifying or multi-step tasks.
---

# Preflight

Before executing a task that modifies files, runs commands, or takes external actions, generate a scope boundary.

## When to activate

- The request involves editing, creating, or deleting files
- The request has multiple steps
- The request involves external actions (API calls, git push, sending data)
- The request is ambiguous about which files or modules are involved

## When to skip

- Pure question-answering ("what does this function do?")
- Reading or searching files without modification
- Single-line trivial changes where the target is unambiguous

## What to do

Analyze the user's request and write `.claude/scope-boundary.json`:

```json
{
  "files_in_scope": ["src/auth/login.py", "src/auth/session.py"],
  "dirs_in_scope": ["src/auth/"],
  "assumptions": [
    {"text": "Session tokens are stored in Redis", "verified": false}
  ],
  "risk_level": "medium",
  "approval_required": false,
  "task_summary": "Refactor login flow to use JWT"
}
```

## Rules

1. **Scope files**: Include files the user mentioned + their direct imports. Cap at 15 files; if more are needed, use `dirs_in_scope` instead.

2. **Assumptions**: List any non-obvious assumptions you are making. If you can quickly verify an assumption (grep, read a file), do so and mark `verified: true`.

3. **Risk level**:
   - `low`: read-only analysis, single-file edits to non-critical code
   - `medium`: multi-file changes, refactoring, config changes
   - `high`: external actions, deletion, publishing, credential-adjacent

4. **Approval required**: Set `true` if risk is high or the task involves irreversible external actions.

5. **Show the user** (medium/high risk only): One line summarising scope + any unverified assumptions. Do not show the full JSON.

6. **Update on scope change**: If the user asks you to do something outside current scope, update `scope-boundary.json` before proceeding. Note the expansion in `revisions`.

## Display levels

- **low risk**: Say nothing. Just write the boundary file and proceed.
- **medium risk**: One-line confirmation: "Scope: [dirs/files]. Assuming [X]. Proceeding."
- **high risk**: Pause and ask: "This involves [action]. Scope: [files]. Assumptions: [list]. Proceed?"
