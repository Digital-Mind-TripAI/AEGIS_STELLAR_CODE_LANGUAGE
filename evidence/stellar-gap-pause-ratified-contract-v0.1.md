# Stellar Gap-Pause Ratified Design Contract v0.1

**Status:** RATIFIED DESIGN — declaration and orchestration contract only.
**Runtime:** `executionEnabled: false`; S7001, FFI, adapters, and native scheduling remain closed.

## Canonical source form

The ratified source shape is:

```text
gap-pause <pause-id> / <reason> ( timeout_ms: <1..86400000>, resume: <authorized|manual>, abort: <explicit|timeout> ) ·
```

The form is reserved for an orchestration boundary. It is not an expression,
loop body, capability declaration, import, or native runtime command in v0.1.

## State and transitions

The initial state is `active`. The only transitions are:

`active -> paused -> resumed`

`active -> paused -> aborted`

`active -> paused -> expired`

`paused -> resumed` requires the declared resume mode: `authorized` requires a
matching approval record, while `manual` requires an explicit operator action.
`paused -> aborted` requires an explicit abort decision. When the bounded timeout
is reached, the state becomes `expired`; expiration never resumes work and never
grants authority. Terminal states cannot transition again.

## Effects, capabilities, and persistence

Gap-Pause carries only the `pause-control` effect and no capabilities. It cannot
grant execution, I/O, network, GUI, child-process, FFI, or adapter authority.
State is represented by an append-only continuity record with provenance and an
integrity hash. Persistence is evidence, not permission.

## Diagnostics and refusal rules

The reserved diagnostics are `S6101` invalid shape, `S6102` illegal context,
`S6103` invalid timeout, `S6104` invalid transition, `S6105` missing resume
authorization, `S6106` terminal-state transition, and `S6107` capability/effect
expansion. Unknown fields, duplicate transitions, undeclared capabilities,
runtime requests, and malformed identifiers are refused deterministically.

This contract ratifies meaning and boundaries. Native parser/AST support and
runtime behavior require a separate implementation tranche and acceptance report.
