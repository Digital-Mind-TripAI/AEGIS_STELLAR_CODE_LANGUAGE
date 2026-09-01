# Stellar v0.1 Actuator Proposal Slice

This slice adds declaration-only `actuator` proposals for bounded Repair Actuator planning.

```stellar
actuator repair / RepairActuator ( target: dependency-approval, totem: scout, shortfall: missing-approval, authorization: required ) ·
```

The native checker requires all four metadata values. The Totem must already be declared and must list the referenced Shortfall. `target` is a stable identifier; it is descriptive and does not authorize an operation. `authorization: required` records that a later governed transition needs authorization.

The checker emits `actuator-proposal` evidence with `authorizationRequired:true` and `executionEnabled:false`. Totems remain passive communication/illumination records. No proposal dispatch, repair, mutation, FFI, adapter invocation, installation, or S7001 behavior is enabled.

The syntax is an explicit v0.1 proposal contract because the source authority describes Actuator roles and production manifests but does not ratify a concrete source grammar.
