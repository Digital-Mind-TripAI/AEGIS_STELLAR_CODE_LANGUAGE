# Stellar Field Layer Ratified Contract v0.1

**Status:** ratified design contract; declaration-only; no native syntax promoted
**Date:** 2026-08-31

The Field Layer is a passive, snapshot-bound runtime-context description. It
communicates and illuminates conditions; it does not execute work, authorize
capabilities, dispatch an Actuator, or mutate state. Its contract is represented
by `stellar.field-layer/v0.1` and validated before any future native syntax is
considered.

## Boundaries

- **Element:** atomic relational object; a Field Layer describes its surrounding
  conditions and is not an Element declaration.
- **Orb:** executable capsule/container; `parentOrbId` is lineage only and does
  not grant execution or capability authority.
- **Harmonic Signature:** owns drift and capture metadata. The Field Layer may
  reference a `harmonicSignatureId`, but cannot redefine either property.
- **Totem:** passive continuity record. A Field Layer snapshot may be recorded
  by a Totem, but persistence does not authorize an update.
- **Actuator:** action proposal/execution boundary. Field Layers contain no
  dispatch, authorization, repair, or mutation fields.

## Typed model and lifecycle

The identity is `fieldId`, with optional Orb and Harmonic lineage references.
Observations are typed as boolean, finite number, text, or identifier and have
unique IDs and declared sources. `snapshot.sequence` and a SHA-256 `inputHash`
make evaluation inputs explicit and reproducible. EQ(Range) is represented by
finite `minimum`, `maximum`, and `value`, with the value inside the range.

The declaration-only lifecycle is `declared -> active -> paused -> active`,
`active -> stale`, and `stale -> closed`. It has no implicit scheduler or
clock; updates require a new snapshot. Persistence is append-only continuity
evidence.

## Drift, capture, and refusal rules

`driftPolicy` and `capturePolicy` are fixed to `harmonic-metadata-only`; drift
and capture remain Harmonic concerns until their own typed semantics are
ratified. The Field Layer is `snapshot-bound`, has empty effects and
capabilities, is limited to the orchestration boundary, and is permanently
`executionEnabled: false` in v0.1.

The validator refuses unknown/action fields, malformed IDs or hashes, duplicate
observations, invalid typed values, invalid ranges, out-of-range EQ values,
invalid lifecycle transitions, non-empty capabilities/effects, and any attempt
to enable execution. These are descriptive diagnostics, not runtime failure
semantics. S7001, FFI, I/O, network, GUI, child process, and adapter execution
remain closed.

## Promotion path

This contract and its schema/validator evidence precede native AST/parser
support. A future syntax tranche requires explicit source spelling, positive and
negative conformance fixtures, deterministic diagnostics, and proof that the
governor boundary remains closed.
