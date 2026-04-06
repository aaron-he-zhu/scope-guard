# FAQ

## Is this a standard?
Not yet. v0.1 is a reference package and design prototype.

## Is this only for one agent platform?
No. The intent is to define a portable task contract layer above tools and below user intent.

## Is this just prompt engineering?
No. The core idea is not better phrasing, but shared task contracts, handoff payloads, adapters, and result shapes.

## Does this replace permissions or auth?
No. It complements them by preserving scope, assumptions, and approval boundaries in task structure.

## Why start with `delegation-protocol`?
Because early agent failures often come from vague intent and poor handoff, not lack of raw capability.

## Why not make the action skill the first skill?
Because the first skill should usually improve the reliability of later skills, not just add impressive capability.

## What is the smallest useful adoption path?
1. Use the task contract schema
2. Add `delegation-protocol`
3. Add one adapter for your most common workflow
4. Enforce `approval_required` in action flows
