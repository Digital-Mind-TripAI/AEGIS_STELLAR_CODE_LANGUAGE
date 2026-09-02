# Stellar Windows x64 v0.1 — T7d offline install-readiness

Status: **REJECTED FOR INSTALL; OFFLINE WORK ONLY; S7001 CLOSED**.

No elevated dry-run, SCM mutation, key provisioning, protected-root creation, firewall mutation, pipe activation, native fixed-probe dispatch, or arbitrary Stellar execution is authorized. Passing source tests or compilation is not installation approval.

## Mandatory A–L acceptance gates

- **A — Release authenticity:** one authenticated release manifest binds every service EXE, fixed broker/runner, static-import manifest, dynamic-module policy, schema, canonical value, adapter, lifecycle script, OS/architecture and signer. `PackageRoot` is locally handle-resolved. UNC, ADS, reparse points, hardlinks, unsigned files and every mismatch are refused.
- **B — SCM lifecycle:** both OWN_PROCESS workers are linked. START_PENDING checkpoints cover key, config, ACL, pipe and self-attestation. Required privileges, preshutdown/stop cancellation, overlapped I/O, failure actions and restart reconciliation are exact.
- **C — Pipe authentication:** exact SYSTEM/server/client SID topology and live ACL/owner readback, local first-instance quotas, server challenge then sole client reply then mandatory impersonation, held process and no-write/no-delete-share image handles, PID creation time, image volume/file ID/hash/signer and exact RUNNING SCM identity, mutual server identity, atomic canonical signature/replay verification, one consumed client request per connection, framed trailing-byte refusal and one monotonic handshake deadline.
- **D — Key custody:** one-shot provision never overwrites; normal operation opens an existing versioned key. Provider/name/algorithm/curve/machine scope/export policy/DACL/SPKI `kid`/TPM evidence are checked. Private export fails. Issuer and Broker keys are distinct. Software custody requires explicit policy.
- **E — Rotation/revocation:** atomic signed crash-safe registry, exactly one active issuer, bounded overlap, immediate revocation refusal and retained history.
- **F — Dual authorization:** Custodian parses and rederives the capability contract and enforces Steward authority rather than acting as a generic signer. Broker independently verifies every field.
- **G — Adapter completeness:** schema/canonical/aggregate integrity and retained-handle reads; exact target, effects, imports, policy, resources, invocation input and installed-release binding; reservation binds contract hash, nonce, action and release; expiry is rechecked before dispatch.
- **H — Durable outbox:** operation/lease/dispatch are durable. Restart reconciles a signed Broker receipt and never reruns. Receipt persists before terminal transition; identical retry returns it.
- **I — Native receipt:** Broker CNG signs a Broker-constructed canonical receipt binding the complete reviewed identity/effect/probe/job/cleanup/chain context.
- **J — Module evidence:** module handles remain held through checks; final System32 identity and revocation/servicing invalidation are enforced; actual loaded modules and service static imports are bound.
- **K — Transactional install:** `-WhatIf` emits exact proposed state with zero mutation. Every native exit is checked. Install journal restores prior services/files/ACLs/keys/firewall; deletion is awaited; repeated install/uninstall is idempotent; services remain stopped until readback succeeds.
- **L — Negative corpus and review:** signer/hash/path/reparse/ACL/pipe SID/image/challenge/expiry/replay/revocation/rotation/Redis/signing/crash-transition and zero-mutation tests pass. Independent review is mandatory before elevation.

## Current verified subset

The D2 runtime replaces synchronous pipe I/O with deadline-bounded, stop/preshutdown-aware overlapped operations and cancellation drain. It implements the exact Custodian/Broker pipe topology, one server challenge/one consumed client request/at-most-one terminal response framing, post-reply OS/SCM identity binding, mutual server fields, cached-only fail-closed WinTrust, atomic verifier interface, CNG ES256 primitive, and ordered checked START_PENDING checkpoints. The offline behavioral harness covers framing, cancellation, timeout, identity replacement/mismatch, replay and server-authentication refusal. Both service sources compile reproducibly under strict MSVC settings.

This remains a subset only. The authenticated installed Gateway pin/key registry, strict canonical envelope parser, durable replay implementation, complete startup gate implementations, and independent target-host tests do not yet exist. The checked-in registry adapter therefore refuses startup before RUNNING. All A–L controls above remain blocking, not deferred acceptance.
