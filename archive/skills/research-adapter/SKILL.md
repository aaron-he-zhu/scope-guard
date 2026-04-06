---
name: research-adapter
description: Consume a task contract for research-oriented work such as synthesis, comparison, market scans, evidence-aware briefs, and multi-source analysis while preserving scope, constraints, and uncertainty.
user-invocable: true
---

# Research Adapter

This skill consumes a task contract for research-oriented work.

## Read first
Before execution, read:
- goal
- scope
- constraints
- success_criteria

When available, also read:
- inputs.provided
- inputs.missing
- assumptions
- risk_level
- completion_definition

## Behavior

1. Convert the goal into a clear research question.
2. Stay inside the defined scope unless explicitly allowed to expand.
3. Separate findings, interpretation, and recommendation.
4. Preserve uncertainty and evidence gaps.
5. If important inputs are missing, complete the safe subset and label limits.
6. Return a structured downstream result.

## Typical requested outputs
- research_brief
- competitive_landscape
- evidence_summary
- options_memo
- recommendation_note

## Do not
- present recommendations as facts
- hide uncertainty
- silently widen the research scope
- invent evidence
