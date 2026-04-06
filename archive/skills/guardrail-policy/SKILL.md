---
name: guardrail-policy
description: Apply risk-aware execution boundaries for tasks involving external communication, irreversible actions, sensitive data, or uncertain targets. Use to preserve approval requirements, narrow scope, and prevent unsafe execution.
user-invocable: true
---

# Guardrail Policy

Use this skill when tasks involve medium or high risk.

## Responsibilities
- preserve scope boundaries
- preserve approval requirements
- narrow targets before action
- prevent hidden escalation from draft/preview to irreversible execution
- surface uncertainty around identity, destination, or sensitive content

## Rules

1. If the target object, recipient, destination, or identity is unclear, stop and ask.
2. If approval is required, allow draft/preview but do not commit.
3. Prefer the smallest bounded action over broad or batch action.
4. Prefer reversible actions over irreversible ones.
5. Do not silently expand the user's requested scope.
6. Make risk-relevant assumptions visible.

## Typical high-risk categories
- external messaging
- deletion or overwrite
- booking or purchasing
- form submission
- publication
- sensitive data sharing

## Output
Return a compact safety decision:
- safe to proceed
- safe to draft only
- blocked pending clarification
- blocked pending approval
