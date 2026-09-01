# Gap-Pause Draft Semantic Contract (v0.1)

**Status:** DRAFT — design only; not a native language feature
**Execution:** S7001 remains closed; no runtime behavior is defined or enabled.

This document records a candidate contract for review. It does not select source
syntax and must not be treated as an implementation authorization.

## Open decisions

- Whether Gap-Pause is source syntax, a governor result, or an IDE/orchestration event.
- Canonical spelling and glyph mapping, operand shape, and legal source locations.
- Whether nested pauses are legal and how re-entry ownership is represented.
- Bounded wait/timeout behavior, persistence, resume authorization, and abort semantics.
- Required capabilities/effects and deterministic diagnostics.

## Proposed state model for review

`active → paused → resumed` or `active → paused → aborted`; timeout is a bounded
transition to `aborted` unless a ratified contract says otherwise. A pause cannot
grant execution, external I/O, or broader capability authority.

## Relationship to Shortfall

Shortfall is an operational/reporting state in `THE_ANNEX_SYSTEM.md`: an Actuator
reports unresolved work to its Satellite, with mission state, approvals, reports,
and provenance checkpointed for continuity. Gap-Pause is currently described as a
computational concept in the Stellar Script material. They remain distinct until
an authority decision explicitly relates them.

## Promotion gate

Do not add parser tokens, AST nodes, runtime scheduling, S7001, FFI, or adapter
execution from this draft. Promotion requires a ratified contract, positive and
negative conformance fixtures, effect/capability rules, deterministic diagnostics,
and fresh native evidence.
