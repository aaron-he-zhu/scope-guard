# Terminology

## Task Contract
A normalized representation of user intent that can be safely handed to downstream skills.

## Protocol Layer
The layer responsible for intake, clarification, risk gating, and handoff preparation.

## Handoff Payload
The structured object used to transfer work from the protocol layer to a downstream skill.

## Adapter
A translation layer that maps a shared handoff payload to a specialized skill workflow.

## Approval Boundary
A point beyond which a system must not perform irreversible or external actions without explicit confirmation.

## Scope
The operational boundary of a task, including what is in-bounds and out-of-bounds.

## Requested Output
The intended deliverable type expected from downstream execution.

## Downstream Result
A structured output returned by a specialized skill after execution, preview, or partial progress.
