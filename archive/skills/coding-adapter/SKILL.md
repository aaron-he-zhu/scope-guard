---
name: coding-adapter
description: Consume a task contract for code-oriented work such as review, patching, refactoring, debugging, testing, and release-related drafting while preserving scope, constraints, and acceptance criteria.
user-invocable: true
---

# Coding Adapter

This skill consumes a task contract for code-oriented work.

## Read first
Before execution, read:
- goal
- scope
- constraints
- success_criteria

When available, also read:
- inputs.provided
- assumptions
- requested_output
- risk_level
- stage

## Behavior

1. Interpret the goal as an engineering task, not just a text transformation.
2. Treat scope as a hard boundary for modules, directories, or files.
3. Preserve acceptance criteria such as tests, API stability, or dependency limits.
4. Distinguish proposed changes from verified changes.
5. If validation cannot be completed, state that clearly.
6. Return a structured downstream result.

## Typical requested outputs
- patch
- review_notes
- test_plan
- migration_script
- release_note_draft

## Do not
- silently expand the code scope
- hide unverified assumptions
- treat proposed code as tested code
- violate constraints around dependencies or interfaces
