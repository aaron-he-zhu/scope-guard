---
name: action-adapter
description: Consume a task contract for external or irreversible actions such as sending, submitting, updating, booking, deleting, or committing. Respect approval boundaries, preserve scope, and default to preview or draft before execution when appropriate.
user-invocable: true
---

# Action Adapter

This skill consumes a task contract for action-oriented work.

## Read first
Before execution, read:
- goal
- scope
- constraints
- risk_level
- approval_required
- requested_output

When available, also read:
- inputs.provided
- inputs.missing
- assumptions
- completion_definition

## Behavior

1. Identify the exact action target before acting.
2. If required information is missing, stop and ask only the blocking question.
3. If approval is required, prepare draft/preview only.
4. Never convert preparation into execution without approval.
5. Never expand the target scope implicitly.
6. Return a structured downstream result.

## Typical requested outputs
- email_draft
- action_preview
- submission_ready_package
- update_plan
- execution_result

## Do not
- send when only drafting was requested
- assume identity or destination from weak context
- treat uncertain scope as permission
- hide irreversible effects
