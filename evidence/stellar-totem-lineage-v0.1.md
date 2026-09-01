# Stellar Totem Lineage (v0.1)

This tranche adds declaration-only Totem records to the native Stellar parser.
Totems are passive communication and illumination records only. They describe
state, lineage, observations, Shortfalls, evidence, and recommendations. A
Totem cannot authorize, dispatch, repair, mutate, schedule, or execute an
operation. The machine-readable passive-record contract is
`stellar.totem-continuity/v0.1` in
`native/stellar/v0_1/schemas/stellar-totem-continuity-v0.1.schema.json`.
The form is:

```stellar
totem mission / Orb ( parent: none, child: scout, shortfall: missing-approval ) ·
```

`parent`, `child`, and `shortfall` values are stable identifiers. Parents and
children are resolved across the unit, every child must point back to its
declared parent, and duplicate references are refused. Shortfall identifiers
are recorded as references only; their operational continuity records remain
governed by the Shortfall contract.

The checker emits `totem-lineage` trace records with `executionEnabled:false`.
No scheduling, repair execution, persistence, FFI, or S7001 behavior is
enabled by this syntax.
