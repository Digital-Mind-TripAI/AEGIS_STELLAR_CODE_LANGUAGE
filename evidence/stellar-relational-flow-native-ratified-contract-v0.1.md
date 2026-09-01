# Stellar Native Relational Flow Source Contract v0.1

**Status:** Ratified design contract; declaration-only and not yet admitted by the native parser.

The canonical source spelling is a `flow` declaration with repeated entries:

```stellar
flow name / Kind (
  node: element-id / element,
  node: orb-id / orb,
  edge: edge-id / supports (
    from: element-id,
    to: orb-id,
    order: 1,
    condition: eq >= 0.8,
    condition: witness == true
  ),
  state: declared,
  shortfall: shortfall-id,
  gap_pause: pause-id
) ·
```

`node` and `edge` entries may repeat. Node spelling is `identifier / type`; edge
spelling is `identifier / relation` followed by bounded metadata. Conditions
are repeated in source order as `condition: metric operator value`. `eq`,
`drift`, and `capture` require a finite number in `[0,1]`; `witness` requires a
boolean. Operators are `>=`, `<=`, and `==`.

The declaration is passive: nodes and edges are unique, edge order is a unique
positive integer, the graph is acyclic, and references must resolve within the
declaration. `state`, `shortfall`, and `gap_pause` are continuity metadata.
Effects and capabilities are empty and `executionEnabled:false`. Runtime graph
evaluation, FFI, adapters, I/O, GUI, network, repair dispatch, and S7001 remain
closed gates.
