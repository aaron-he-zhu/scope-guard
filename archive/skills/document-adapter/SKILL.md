---
name: document-adapter
description: Consume a task contract and execute document-oriented workflows such as extraction, transformation, summarization, memo drafting, report drafting, and structured document outputs while preserving scope, constraints, and assumptions.
user-invocable: true
---

# Document Adapter

This skill consumes a task contract for document-oriented work.

## Read first
Before execution, read:
- goal
- scope
- constraints
- requested_output

When available, also read:
- success_criteria
- inputs.provided
- inputs.missing
- assumptions
- audience

## Behavior

1. Use the task contract as authoritative unless it conflicts with obvious user correction.
2. Stay inside the stated scope.
3. Preserve constraints in the draft or output.
4. Use assumptions only when necessary and make important ones visible.
5. If required inputs are missing, produce the safe partial output when possible.
6. Return a structured downstream result.

## Typical requested outputs
- executive_summary
- strategy_memo_draft
- meeting_brief
- risk_table
- slide_outline
- structured_extraction

## Do not
- add major outside content unless allowed by scope
- change the requested output type without reason
- hide uncertainty
- pretend missing material was available
