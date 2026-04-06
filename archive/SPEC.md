# Agentic Task Contract Spec v0.1

A minimal protocol for turning vague user intent into safe, composable, executable work across agent skills.

## 1. Scope

This specification defines a minimal task contract layer for agentic systems that use reusable skills, tools, or workflow modules.

It does not define:
- model architecture
- tool transport
- UI behavior in detail
- authentication systems
- vendor-specific APIs

It does define:
- how ambiguous user intent should be normalized
- how task handoff should be represented
- how downstream skills should consume task contracts
- how risk and approval boundaries should propagate across skills

## 2. Problem Statement

In agentic systems, user requests are often:
- underspecified
- outcome-oriented rather than operation-oriented
- multi-step
- cross-skill
- mixed-risk

Without a shared task contract:
- each skill redoes intake inconsistently
- risk boundaries get lost across handoffs
- downstream skills receive vague instructions
- orchestration becomes brittle
- user trust declines due to hidden assumptions and uncontrolled actions

This specification introduces a minimal, shared contract layer to address these problems.

## 3. Design Principles

### 3.1 Result orientation
Contracts should describe desired outcomes, not only operations.

### 3.2 Explicit boundaries
Scope, assumptions, and approval requirements must be made explicit.

### 3.3 Minimal sufficient structure
The contract should be as small as possible while still enabling reliable handoff.

### 3.4 Reversible-first execution
Systems should prefer reversible, inspectable, and draft-first actions before irreversible execution.

### 3.5 Graceful degradation
If a task cannot be fully completed, systems should complete the safe/useful subset and clearly surface blockers.

### 3.6 Adaptive visibility
Internal task structure may be richer than what is shown to the user; however, critical risk and assumption boundaries must remain inspectable.

## 4. The Protocol Layer

A compliant system SHOULD include a protocol layer that:
- classifies the task
- defines the task contract
- identifies blocking vs non-blocking missing inputs
- determines risk level
- inserts approval checkpoints
- routes the task to an appropriate downstream skill or capability

This layer MAY be implemented as:
- a dedicated skill
- a built-in orchestrator
- a workflow preprocessor
- a policy layer inside an agent runtime

The protocol layer MUST NOT:
- expose unnecessary internal structure for trivial tasks
- bypass approval requirements for high-risk tasks
- hand off vague requests when a clean contract can first be formed

## 5. Task Contract Requirements

Each task contract MUST define:
- goal
- scope
- constraints
- success criteria
- inputs provided
- inputs missing
- assumptions
- risk level
- approval requirement
- requested output

The contract MAY additionally define:
- task type
- audience
- priority
- stage
- completion definition
- fallback if blocked
- suggested next actor

## 6. Handoff Payload Schema

### 6.1 Minimal schema

```json
{
  "goal": "",
  "scope": "",
  "constraints": [],
  "success_criteria": [],
  "inputs": {
    "provided": [],
    "missing": []
  },
  "assumptions": [],
  "risk_level": "low",
  "approval_required": false,
  "requested_output": "",
  "next_actor": ""
}
```

### 6.2 Extended schema

```json
{
  "goal": "",
  "scope": "",
  "constraints": [],
  "success_criteria": [],
  "inputs": {
    "provided": [],
    "missing": []
  },
  "assumptions": [],
  "risk_level": "low",
  "approval_required": false,
  "requested_output": "",
  "next_actor": "",
  "task_type": [],
  "audience": "",
  "priority": "normal",
  "stage": "",
  "completion_definition": "",
  "fallback_if_blocked": ""
}
```

### 6.3 Field semantics

#### goal
The intended outcome of the task.

#### scope
The operational boundary of the task, including exclusions.

#### constraints
Requirements the downstream skill MUST preserve.

#### success_criteria
Conditions under which the handoff is considered successful.

#### inputs
Inputs already available and inputs still missing.

#### assumptions
Explicit assumptions that permit progress without full certainty.

#### risk_level
A coarse risk label: `low`, `medium`, or `high`.

#### approval_required
Whether the downstream skill may fully commit irreversible or external actions.

#### requested_output
The intended deliverable type.

#### next_actor
A routing hint for the next skill or capability.

## 7. Risk and Approval Semantics

### 7.1 Risk levels

#### low
Drafting, summarization, organization, analysis, or other reversible work with no significant external consequence.

#### medium
Work with meaningful business, operational, or file-level consequences, but not yet externally committed.

#### high
External communication, deletion, submission, purchase, booking, sensitive sharing, or irreversible action.

### 7.2 Approval rule

If `approval_required = true`, downstream skills MAY:
- prepare
- draft
- preview
- validate

but MUST NOT:
- send
- submit
- publish
- delete
- overwrite
- commit irreversible external actions

unless approval is explicitly lifted by the orchestrating layer or the user.

## 8. Orchestration Rules

The protocol layer SHOULD act as the default first-hop for:
- ambiguous requests
- multi-step tasks
- cross-skill tasks
- risk-sensitive tasks
- outcome-oriented tasks without a clearly defined operation

The protocol layer MAY remain mostly invisible for:
- clear
- low-risk
- single-step
- self-contained tasks

When multiple specialized skills are required, the protocol layer SHOULD:
- build one coherent task contract
- preserve constraints across handoffs
- unify approval semantics
- coordinate one final deliverable

## 9. Adapter Requirements

A compliant downstream skill adapter MUST:
- consume relevant fields from the task contract
- preserve `scope`, `constraints`, and `approval_required`
- return outputs in a structured, composable form
- surface blockers explicitly
- avoid redoing full intake if the contract is already sufficient

A compliant adapter SHOULD:
- preserve critical assumptions in its output
- map `requested_output` to its local workflow template
- interpret `success_criteria` as the local acceptance standard

A compliant adapter MAY:
- ignore irrelevant optional fields
- enrich the output with skill-specific metadata
- request clarification only when the contract remains insufficient for safe execution

## 10. Standard Adapter Categories

This specification recognizes four common adapter categories:

### 10.1 Document Adapter
For transformation, extraction, drafting, and structured document outputs.

### 10.2 Research Adapter
For synthesis, comparison, analysis, and evidence-aware briefs.

### 10.3 Action Adapter
For external or irreversible system actions.

### 10.4 Coding Adapter
For code generation, review, patching, refactoring, and validation flows.

This list is not exhaustive.

## 11. Standard Downstream Result Shape

Downstream skills SHOULD return results in a structured shape such as:

```json
{
  "status": "completed",
  "result_type": "",
  "artifacts": [],
  "summary": "",
  "open_questions": [],
  "assumptions_used": [],
  "approval_pending": false,
  "next_recommended_action": ""
}
```

This allows orchestrators to:
- continue multi-step flows
- merge outputs from multiple skills
- ask for approval at the correct boundary
- explain progress to the user

## 12. Failure Handling

If a downstream skill is blocked, it MUST:
- identify the blocker
- distinguish blocking vs non-blocking gaps when possible
- complete the safe subset if feasible
- return the smallest recommended next action to unblock progress

Systems MUST NOT fail vaguely.

## 13. User Experience Guidance

Implementations SHOULD distinguish:
- internal protocol strictness
- user-visible communication style

Simple low-risk tasks SHOULD remain fast and natural.

Complex or risky tasks SHOULD surface:
- task understanding
- important assumptions
- approval checkpoints
- blockers

only to the degree required for trust and steering.

## 14. Security Non-Goals

This specification does not replace:
- identity systems
- permission systems
- sandboxing
- secret management
- audit logging infrastructure

It is a task-structure standard, not a full security framework.

However, it improves safety by making:
- boundaries
- assumptions
- approval requirements
- downstream scope

more explicit and portable across skills.

## 15. Example Flow

### User request
“Analyze these notes, turn them into a strategy memo, and send it to the client.”

### Protocol layer output
- separates analysis from external send
- marks send as approval-gated
- creates one contract for memo drafting
- creates one gated follow-up action for email send

### Downstream sequence
1. Document adapter consumes memo-draft task
2. Returns memo draft artifact
3. Action adapter prepares email draft
4. System pauses for approval before send

This preserves:
- one coherent user intent
- explicit boundary between draft and send
- reusable artifacts
- controlled risk propagation

## 16. Compliance Levels

### Level 0 — Ad hoc
No standardized contract layer.

### Level 1 — Minimal contract
Supports the minimal payload schema.

### Level 2 — Composable workflows
Supports adapters and structured downstream results.

### Level 3 — Full orchestration
Supports cross-skill routing, approval propagation, and unified result handling.

## 17. Future Extensions

Possible future extensions include:
- richer risk taxonomies
- user preference inheritance
- provenance and evidence references
- multi-actor delegation chains
- machine-readable validation rules
- organization-wide policy overlays
