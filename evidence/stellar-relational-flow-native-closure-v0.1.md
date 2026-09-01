# Relational Flow Native Closure Review v0.1

**Status:** Prepared, not implemented.

The relational-flow contract is ratified as a passive, declaration-only graph
record. The native compiler currently has no source spelling for that record.
The TypeScript validator defines the data contract, but it does not authorize
native syntax or runtime evaluation.

## Remaining shortfall

The native language still needs a canonical spelling for:

- a flow identifier and state;
- ordered nodes for Elements, Orbs, Field Layers, and Tethers;
- ordered, unique, acyclic edges;
- relation names and bounded `eq`, `drift`, `capture`, and `witness` conditions;
- passive Shortfall and Gap-Pause references.

## Smallest safe implementation slice

Ratify and implement one declaration-only form, for example:

```stellar
flow name / Kind (
  node: element-id / element,
  node: orb-id / orb,
  edge: edge-id / supports ( from: element-id, to: orb-id, order: 1 ),
  state: declared,
  shortfall: shortfall-id,
  gap_pause: pause-id
) ·
```

Before implementation, the language authority must decide whether repeated
`node` and `edge` metadata is the canonical spelling, whether node type is
written before or after the identifier, and how conditions are encoded. No
runtime graph evaluation, adapter dispatch, FFI, I/O, or S7001 transition is
part of this slice.

## Acceptance target

The native slice is ready only when valid declarations produce deterministic
passive trace evidence and malformed, duplicate, unknown-reference, cyclic,
out-of-order, and non-empty-effect variants are refused with stable diagnostics.

This review is intentionally uncommitted pending source-spelling ratification.
