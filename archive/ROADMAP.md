# Roadmap

This roadmap outlines how Work Contract OS can evolve from a minimal reference package into a broader agentic interoperability layer.

---

## Current version: v0.1

### Included
- delegation-protocol
- guardrail-policy
- document-adapter
- action-adapter
- shared task contract schema
- shared downstream result schema
- example payloads and results
- anti-patterns
- evaluation guidance

### Purpose
Prove the value of a task contract layer with the smallest useful package.

---

## v0.2 — Better examples and stronger adapters

### Goals
- add more canonical examples
- make adapters more concrete
- improve downstream result consistency

### Planned additions
- research-adapter
- coding-adapter
- more example flows
- example blocked-result cases
- example partial-result cases
- more audience-aware requested_output patterns

### Why it matters
At v0.1, the package explains the architecture.
At v0.2, it starts demonstrating breadth.

---

## v0.3 — Stronger orchestration semantics

### Goals
- make multi-step routing more explicit
- improve contract propagation across stages
- formalize orchestration behavior

### Planned additions
- orchestration profiles
- nested handoff patterns
- stage transition semantics
- multi-artifact flow examples
- unified approval propagation across chains

### Why it matters
At this stage, the package evolves from a set of pieces into a stronger workflow runtime pattern.

---

## v0.4 — Policy overlays

### Goals
- support organization-specific policy behavior
- separate generic contract semantics from local governance

### Planned additions
- policy overlay format
- team / enterprise policy examples
- sensitive-data handling conventions
- audit-friendly metadata fields
- stricter action profiles

### Why it matters
This makes the package more useful for real internal deployment where trust and compliance matter.

---

## v0.5 — Reference implementation helpers

### Goals
- reduce implementation ambiguity
- make it easier for others to adopt the pattern

### Planned additions
- validation helpers for task contracts
- normalization examples
- adapter checklists
- result-shape validation examples
- contract linting rules

### Why it matters
This turns the spec from “interesting design” into something easier to operationalize.

---

## v0.6 — Interoperability profile

### Goals
- position the task contract layer as a broader interoperability pattern
- make it easier for different skill ecosystems to exchange work

### Planned additions
- capability declarations
- adapter compatibility profiles
- optional field support levels
- version negotiation notes
- recommended extension points

### Why it matters
This is the first step toward a true ecosystem language rather than a repo-local pattern.

---

## v0.7 — Evaluation maturity

### Goals
- make performance improvements more measurable
- compare task-contract systems with ad hoc orchestration

### Planned additions
- benchmark task suite
- scoring rubric
- sample human evaluation sheets
- error taxonomy
- regression testing prompts

### Why it matters
Without evaluation maturity, the project remains conceptual.
With it, the project becomes testable and defensible.

---

## v1.0 — Stable public reference

### Goals
- stabilize the minimal standard
- make the package suitable for broad public reference

### Target deliverables
- stable core schema
- stable protocol guidance
- stable adapter requirements
- canonical examples
- evaluation kit
- policy overlay guidance
- extension guidance

### Success condition
A third party can read the package and build:
- a compatible protocol layer
- at least one compatible adapter
- a valid downstream result flow

without needing hidden implementation assumptions.

---

## Out of scope for now

The project is not currently trying to become:
- a full workflow engine
- a permission system
- an auth standard
- a full security framework
- a complete enterprise governance product
- a universal agent API

Those may connect later, but they are not the current mission.

---

## Strategic direction

This package should evolve along three axes:

### 1. Practicality
Can people actually use it in real agentic systems?

### 2. Composability
Can skills exchange work more reliably?

### 3. Legibility
Can humans understand where the task is, what assumptions were made, and what still requires approval?

If future additions do not improve at least one of these three, they should probably not be added.

---

## Long-term ambition

The long-term ambition is not to create “more prompts.”

It is to define a minimal task contract layer for agentic work:
- above tools
- below user intent
- portable across skills
- compatible with different agent ecosystems
- strong enough to preserve trust, scope, and composability
