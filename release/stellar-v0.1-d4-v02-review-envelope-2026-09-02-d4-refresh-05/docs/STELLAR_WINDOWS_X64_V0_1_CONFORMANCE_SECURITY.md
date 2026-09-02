# Stellar Windows x64 v0.1 Conformance and Security

Tranche 6 is a bounded, non-executing assurance corpus. It does not load or run a user package and it does not authorize a capability.

## Acceptance corpus

- Reviewed golden hashes bind grammar tokens, typed HIR, static layout, ABI symbols, and MIR lowering.
- Three overlapping `stellar-lab-v0` programs are checked by the independent native front end and the TypeScript Reference Preview oracle.
- A fixed seed drives 72 bounded valid and invalid programs. Each compiler result must be byte-identical on repetition and complete within its per-case timeout.
- Package attacks cover cycles, duplicate symbols, target and ABI mismatch, RELIC effects/imports, traversal, and resolved junction escape.
- Input attacks cover malformed UTF-8, NUL, out-of-range numeric literals, malformed JSON, schema mismatch, argument injection, response bounds, and forbidden flags.
- Build attacks cover output confinement and cleanup after stale-lock fault injection.

The fixed release-acceptance generator runs T0 through T6 plus the Phase A/C legacy regressions. It writes a new canonical report and exits unsuccessfully if any gate fails. Its assessment-only mode exists to test fail-closed report semantics; a supplied assessment is not release evidence.

## Closed boundary

`run`, native loading, ConsoleWrite, and all other capabilities remain unavailable. SHA-256 evidence is integrity evidence, not authorization. An authenticated Custodian/Steward-issued Relation Contract and independently verified OS-enforced isolation remain mandatory before arbitrary native execution.
