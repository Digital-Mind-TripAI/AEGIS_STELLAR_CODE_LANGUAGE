# Stellar non-force continuity memory v0.1

This contract makes continuity memory inspectable without turning memory into control flow. A memory record is passive, append-only, descriptive data for communication and illumination.

## Semantics

- `target` states the condition the record is tracking.
- `shortfallIds` identifies measured distance from that Target.
- `totemIds` links the communication and illumination lineage.
- `observations` records what is known; `recommendations` records suggested next steps.
- `artifactRefs` binds supporting evidence by path and SHA-256.
- `sequence`, `previousIntegrityHash`, and `integrityHash` preserve append-only continuity.

No field authorizes, dispatches, repairs, mutates, or executes. A Totem or memory record cannot cause an Actuator to run. Any closure action remains outside this record and requires the separate governor/authorization boundary. `S7001` remains closed.

The native compiler receives no new runtime syntax in this tranche. This is a versioned schema and TypeScript validation seam for later native adoption after compatibility review.
