# Stellar Windows x64 v0.1 — Durable Journal v0.2

The sole current D3 v0.2 evidence authority is `native/stellar/v0_1/evidence/d3-v02-build/t7d-d3-offline-build.json`. The sibling `d3-build` directory is retained historical pre-v0.2 evidence and must not be used to attest this format.

The only Broker receipt authority is `stellar-broker-receipt-envelope-v0.1`: strict canonical envelope bytes containing protected header, payload, and a 64-byte P-1363 ES256 signature. The legacy `stellar.execution-broker-receipt/v0.1` shape is not accepted.

Status: **OFFLINE LAB EVIDENCE ONLY — REJECTED FOR INSTALL — S7001 CLOSED**

Durable Journal v0.2 replaces the uninstalled v0.1 format. No backward-compatibility reader is provided because no v0.1 journal was installed or activated.

## Transaction invariant

Every mutation holds one Windows cross-process byte-range lock for the complete transaction: recover and select the valid main/`.new` candidate; strictly parse the whole canonical journal; verify every journal-record signature and hash-chain edge; reload the latest operation binding and state; perform the compare-and-set decision; calculate sequence and predecessor hash; serialize a complete replacement to `.new`; use write-through I/O and `FlushFileBuffers`; atomically replace the main journal; reopen and revalidate the result; then publish the new in-memory view. A stale object therefore cannot append from stale state.

`RESERVED` definitively means that no external dispatch has occurred. A restart may safely advance `RESERVED` to `DISPATCHED`. The driver durably commits and reopens the `DISPATCHED` record before invoking its external callback. Once `DISPATCHED` is visible, no later driver invocation may call the external target again; it enters `RECONCILING` and recovers the target's prior signed receipt. This deliberately prefers reconciliation over duplicate execution when a process is lost after dispatch authorization.

## Evidence separation

The record has three distinct evidence values:

- `brokerCanonicalReceipt`: canonical base64url encoding of the exact original Broker envelope bytes.
- `brokerSignature`: the original 64-byte ES256 Broker signature, byte-identical to the signature embedded in that envelope.
- `journalRecordSignature`: the independent signature over the unsigned v0.2 journal record.

`PriorReceipt` decodes and returns the original Broker envelope and signature byte-for-byte. It never returns the journal signature as Broker evidence.

## Consume gate

Consume accepts only `DISPATCHED` or `RECONCILING`. It parses the strict canonical Broker receipt, resolves its `kid` through the active signed Broker registry at the supplied event time, imports that registered SPKI, verifies ES256, and requires exact equality for request ID/hash, contract ID/hash, nonce, operation, release, action, host, target service, Broker service/image, runner, completed status, evidence hash, cleanup hash, and receipt validity time. Any mismatch leaves the operation unresolved; it cannot be reserved or executed again.

## Recovery driver

The driver returns a prior receipt for a terminal identical retry, refuses a conflicting request binding, dispatches a newly won reservation once, routes an already-dispatched operation into `RECONCILING`, and treats `REFUSED` as permanent. Reconciliation consumes only a verified prior signed Broker receipt. A permanently unresolvable operation is quarantined through the signed `REFUSED` transition; it is never silently rerun.

## Offline evidence

The native self-test races twelve real processes against one operation and requires exactly one reservation and one dispatch. It then verifies restart, byte-identical prior receipt recovery, idempotency, truncated journal refusal, corrupt journal-signature refusal, and stale invalid `.new` cleanup. The Broker receipt fixture carries a real P-256 signature verified through the active registry key. The verifier builds every source and both services twice with `/W4 /WX /Brepro`.

No installation, protected-root mutation, key creation, service mutation, live execution, or S7001 opening is authorized by this evidence.
