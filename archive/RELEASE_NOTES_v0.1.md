# v0.1 — Minimal Reference Package

This is the first public release of **Work Contract OS** — a minimal reference package for building a task contract layer in agentic AI systems.

## What this project is about

As agentic systems become more capable, the bottleneck shifts.

The hard part is no longer only:
- generating outputs
- calling tools
- chaining skills

It is increasingly:
- preserving intent across handoffs
- keeping scope bounded
- making assumptions visible
- preventing approval boundaries from disappearing
- turning vague user requests into reliable executable work

Work Contract OS is a small reference package for that layer.

## What’s included in v0.1

### Core ideas
- a protocol-first approach to agentic work
- a shared task contract schema
- a shared downstream result shape
- structured handoff between skills

### Included components
- `delegation-protocol` — first-hop task normalization skill
- `guardrail-policy` — policy companion for risk-sensitive work
- `document-adapter` — reference adapter for document workflows
- `action-adapter` — reference adapter for external / irreversible actions

### Supporting material
- spec document
- examples
- anti-patterns
- evaluation guidance
- roadmap

## Why this release exists

Most agentic systems today are strong at **capabilities** but weak at **contracts**.

That often leads to:
- repeated clarification
- inconsistent downstream behavior
- hidden assumptions
- brittle multi-step workflows
- accidental loss of approval boundaries

This release is an attempt to make the contract layer explicit.

## What this release is not

This is **not**:
- a full workflow engine
- a security framework
- a universal standard
- a complete interoperability layer

It is a minimal public reference package designed to make one idea legible:

> agentic work becomes more reliable when vague intent is normalized into a shared task contract before execution.

## Best place to start

1. Read `README.md`
2. Read `SPEC.md`
3. Look at `shared/task-contract.schema.json`
4. Inspect the examples in `examples/`
5. Review `skills/delegation-protocol/SKILL.md`

## Current status

Early reference package / design prototype.

The goal of v0.1 is clarity, legibility, and usefulness — not completeness.

## What’s next

Planned next steps include:
- research adapter
- coding adapter
- more canonical examples
- blocked / partial result examples
- stronger evaluation guidance
- clearer orchestration semantics

## Feedback welcome

The most useful feedback at this stage is about:
- naming
- clarity
- whether the task contract concept feels real and useful
- whether the examples reflect real agentic workflows
- where the package feels too heavy or too light
