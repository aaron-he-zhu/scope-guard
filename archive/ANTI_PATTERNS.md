# Anti-Patterns

This document describes common failure modes in agentic skill systems that lack a proper task contract layer.

## 1. Re-doing Intake Everywhere

### Bad pattern
Each downstream skill re-interprets the user request from scratch.

### Why it fails
- repeated clarification
- inconsistent scope
- duplicated reasoning
- brittle multi-skill orchestration

### Better pattern
Normalize once at the protocol layer, then hand off a structured task contract.

---

## 2. Hidden Assumptions

### Bad pattern
A skill silently fills gaps and presents the result as if all inputs were known.

### Why it fails
- users cannot inspect the real basis of the output
- trust collapses when errors surface
- downstream actions may rely on false certainty

### Better pattern
Make assumptions explicit in the task contract and preserve important assumptions in downstream results.

---

## 3. Scope Drift

### Bad pattern
A downstream skill expands the task beyond what was requested.

### Examples
- adds outside research when scope said to use only provided files
- modifies more files than specified
- sends when the request was only to draft
- broadens the audience or objective implicitly

### Why it fails
- surprises the user
- creates hidden risk
- weakens composability

### Better pattern
Treat `scope` as a hard operational boundary unless explicitly revised.

---

## 4. Approval Bypass

### Bad pattern
A system prepares a draft and then executes the final action without a clear approval boundary.

### Why it fails
- violates user trust
- creates external consequences
- turns preparation into commitment

### Better pattern
If `approval_required = true`, downstream skills may draft or preview, but must not commit the final action.

---

## 5. Vague Failure

### Bad pattern
The system stops with generic language such as:
- "I need more information"
- "This is unclear"
- "I can't complete that yet"

### Why it fails
- user does not know what is actually missing
- safe partial progress is lost
- orchestration stalls

### Better pattern
State:
- what is missing
- whether it is blocking
- what safe partial work was completed
- the smallest next action that would unblock progress

---

## 6. Over-ceremonial Simple Tasks

### Bad pattern
The protocol layer turns simple low-risk requests into long planning rituals.

### Why it fails
- creates friction
- makes the system feel bureaucratic
- trains users to avoid the protocol

### Better pattern
Use adaptive visibility:
- keep the internal contract strict
- keep the user-visible layer light
- let simple tasks remain fast and natural

---

## 7. Handoff as Raw Natural Language

### Bad pattern
A skill hands work to another skill using vague prose instead of a structured payload.

### Why it fails
- fields are lost
- risk boundaries disappear
- output quality becomes inconsistent
- adapters cannot reliably consume the task

### Better pattern
Use a standard handoff payload with explicit fields such as:
- goal
- scope
- constraints
- success_criteria
- assumptions
- risk_level
- approval_required
- requested_output

---

## 8. Result Shapes That Cannot Be Chained

### Bad pattern
A downstream skill returns an unstructured blob that cannot be routed onward.

### Why it fails
- orchestrators cannot merge outputs
- approval handling becomes manual and inconsistent
- multi-step flows become fragile

### Better pattern
Return a structured downstream result with:
- status
- result_type
- artifacts
- summary
- open_questions
- assumptions_used
- approval_pending
- next_recommended_action

---

## 9. Treating All Tasks as the Same Risk Class

### Bad pattern
The system applies the same behavior to:
- summarization
- client email send
- file deletion
- calendar submission

### Why it fails
- low-risk work becomes slow
- high-risk work becomes unsafe
- user trust becomes unstable

### Better pattern
Use coarse but explicit risk levels:
- low
- medium
- high

Then map risk to execution and approval behavior.

---

## 10. Letting Specialized Skills Overwrite the Contract

### Bad pattern
A powerful downstream skill ignores the incoming task contract and substitutes its own interpretation.

### Why it fails
- breaks orchestration guarantees
- loses shared assumptions
- creates incompatible behavior across the ecosystem

### Better pattern
Specialized skills should extend the contract locally, not discard it globally.

---

## 11. Mistaking Tool Access for Task Readiness

### Bad pattern
A system assumes that because tools are available, the task is sufficiently specified.

### Why it fails
- action begins before the intent is normalized
- missing constraints surface too late
- wrong artifacts get produced or acted on

### Better pattern
Tool availability does not replace a task contract.
Normalize first, then execute.

---

## 12. Treating This Spec as a Verbose Prompting Style

### Bad pattern
Implementers copy the structure but expose every internal step to the user every time.

### Why it fails
- the system feels heavy
- useful work slows down
- the protocol becomes visible overhead rather than invisible infrastructure

### Better pattern
Keep the protocol strict internally and adaptive externally.
Show only the structure needed for trust, steering, and approval.
