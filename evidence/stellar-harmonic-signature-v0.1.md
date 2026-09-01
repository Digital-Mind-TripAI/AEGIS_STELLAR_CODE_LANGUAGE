# Stellar Harmonic Signature v0.1

Status: ratified declaration-only semantic contract.

The Harmonic Signature is the affectual metadata channel described by the
Stellar Script authority. v0.1 admits exactly five parameters: `purity`,
`drift`, `capture`, `witness`, and `eq`. Numeric parameters are finite values
in the closed range 0 through 1; `witness` is boolean. Parameter names are
unique and no unknown keys are accepted.

This contract is descriptive and hashable. It has empty effects and
capabilities and `executionEnabled: false`; it does not evaluate drift,
capture, witness alignment, or optimization and cannot dispatch an adapter.
The native parser's declaration-only syntax is therefore represented by a
strict typed contract while runtime meaning remains a future gated tranche.

The validator and schema reject missing or extra parameters, malformed values,
out-of-range numbers, non-empty effects/capabilities, and attempts to enable
execution. These are deterministic diagnostics, not runtime failure semantics.
