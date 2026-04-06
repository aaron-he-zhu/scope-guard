# v0.1 Release Checklist

This checklist defines the minimum required work to publish Work Contract OS as a coherent public v0.1 reference package.

---

## 1. Naming and positioning

### Required
- [ ] Confirm public project name
- [ ] Confirm short tagline
- [ ] Confirm repo description sentence
- [ ] Confirm whether the project is positioned as:
  - [ ] reference package
  - [ ] protocol proposal
  - [ ] starter kit
  - [ ] all of the above, with one primary framing

### Recommended defaults
- Project name: `work-contract-os`
- Tagline: `A task contract layer for agentic work`
- Repo description: `A minimal reference package for turning vague user intent into safe, composable, executable work across skills.`

---

## 2. Top-level repo files

### Must-have
- [ ] `README.md`
- [ ] `SPEC.md`
- [ ] `EVALUATION.md`
- [ ] `ROADMAP.md`
- [ ] `ANTI_PATTERNS.md`
- [ ] `LICENSE`

### Should-have
- [ ] `CONTRIBUTING.md`
- [ ] `RELEASE_CHECKLIST.md`
- [ ] `CHANGELOG.md`

### Nice-to-have
- [ ] `FAQ.md`
- [ ] `DESIGN_NOTES.md`
- [ ] `GLOSSARY.md` (if not merged into `shared/terminology.md`)

---

## 3. Shared schema files

### Must-have
- [ ] `shared/task-contract.schema.json`
- [ ] `shared/downstream-result.schema.json`
- [ ] `shared/terminology.md`

### Validation check
- [ ] Required fields match `SPEC.md`
- [ ] Example payloads validate against `task-contract.schema.json`
- [ ] Example results validate against `downstream-result.schema.json`
- [ ] Risk level enum is consistent everywhere
- [ ] Result status enum is consistent everywhere

---

## 4. Core skill files

### Must-have
- [ ] `skills/delegation-protocol/SKILL.md`
- [ ] `skills/guardrail-policy/SKILL.md`
- [ ] `skills/document-adapter/SKILL.md`
- [ ] `skills/action-adapter/SKILL.md`

### Review criteria
- [ ] Skill descriptions are clear and triggerable
- [ ] No skill duplicates the full job of another skill unnecessarily
- [ ] `delegation-protocol` clearly acts as first-hop / intake layer
- [ ] `guardrail-policy` is clearly governance-oriented
- [ ] adapters clearly consume task contracts rather than redo intake
- [ ] simple tasks are not over-burdened by protocol language

---

## 5. Examples directory

### Must-have
- [ ] `examples/memo-draft-handoff.json`
- [ ] `examples/email-draft-handoff.json`
- [ ] `examples/document-result.json`
- [ ] `examples/action-preview-result.json`

### Strongly recommended additions
- [ ] `examples/blocked-action-result.json`
- [ ] `examples/partial-document-result.json`
- [ ] `examples/research-handoff.json`
- [ ] `examples/coding-handoff.json`

### Review criteria
- [ ] Every example demonstrates one clear concept
- [ ] Examples align with schemas
- [ ] Examples are realistic but compact
- [ ] High-risk example clearly preserves approval boundary
- [ ] Low-risk example clearly shows lightweight composability

---

## 6. Public narrative quality

### README checks
- [ ] Explains the problem in plain language
- [ ] Clearly states what the project is
- [ ] Clearly states what the project is not
- [ ] Includes a simple architecture diagram
- [ ] Includes one compelling example
- [ ] Explains “why now”
- [ ] Makes the “task contract layer” idea memorable

### Messaging checks
- [ ] Avoids sounding like generic prompt engineering
- [ ] Avoids overstating maturity
- [ ] Avoids claiming to be a full standard too early
- [ ] Makes the project feel like infrastructure, not just a template collection

---

## 7. Spec coherence

### Must check
- [ ] `SPEC.md` matches actual repo structure
- [ ] schema names match file names
- [ ] adapter terminology is consistent
- [ ] “approval_required” semantics are stable across docs
- [ ] “scope” is used consistently as an operational boundary
- [ ] “requested_output” semantics are consistent across examples

### Common coherence failures to avoid
- [ ] README says one thing, skill files imply another
- [ ] examples use fields not described in the spec
- [ ] schema permits structures the spec discourages
- [ ] anti-patterns contradict evaluation guidance

---

## 8. Evaluation readiness

### Must-have
- [ ] At least one low-risk simple task scenario
- [ ] At least one low-risk multi-step scenario
- [ ] At least one high-risk approval-gated scenario
- [ ] At least one cross-skill workflow scenario

### Should-have
- [ ] A simple scoring rubric
- [ ] A “baseline A vs baseline B vs system under test” framing
- [ ] At least one documented expected failure mode
- [ ] At least one “what good looks like” section

---

## 9. Minimal release quality bar

A public v0.1 release is ready only if:
- [ ] a new reader can understand the project in under 5 minutes
- [ ] a builder can find the schema and core skill quickly
- [ ] the examples tell a coherent story
- [ ] the project has one memorable central claim
- [ ] the package feels minimal rather than bloated
- [ ] the release does not promise more than it delivers

---

## 10. Open-source hygiene

### Must-have
- [ ] License selected
- [ ] Copyright / author attribution added if desired
- [ ] No private notes or internal placeholders remain
- [ ] No inconsistent filenames
- [ ] No broken relative links in markdown files

### Recommended
- [ ] Add repo topics
- [ ] Add one or two issue templates
- [ ] Add a lightweight pull request template

---

## 11. Suggested first-release defaults

### Release title
- [ ] `v0.1 — Minimal Reference Package`

### Release summary
- [ ] Introduces the core task contract concept
- [ ] Includes first-hop protocol skill
- [ ] Includes basic guardrail and adapter examples
- [ ] Includes schemas, examples, anti-patterns, and evaluation guidance
- [ ] Positions the project as a reference package, not a final standard

---

## 12. Post-release immediate follow-ups

### Recommended next work after release
- [ ] Add research adapter
- [ ] Add coding adapter
- [ ] Add more canonical examples
- [ ] Add blocked / partial result examples
- [ ] Add evaluation rubric
- [ ] Collect feedback on naming, scope, and clarity

---

## 13. Non-goals for v0.1

Do not block release on:
- [ ] full benchmark suite
- [ ] advanced governance model
- [ ] enterprise policy overlays
- [ ] implementation-specific tooling
- [ ] interoperability negotiations with other ecosystems
- [ ] perfect naming

The goal of v0.1 is clarity and legibility, not completeness.

---

## 14. Final release gate

Ship v0.1 when these are true:
- [ ] The repo has one clear idea
- [ ] That idea is visible in README, spec, skills, and examples
- [ ] The package is small enough to understand
- [ ] The examples are strong enough to demonstrate value
- [ ] The project can survive first contact with skeptical technical readers
