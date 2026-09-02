# Stellar Windows x64 v0.1 — T7d D3 offline completion

Status: **OFFLINE IMPLEMENTED; REJECTED FOR INSTALL; S7001 CLOSED**.

The sole current D3 v0.2 evidence authority is `native/stellar/v0_1/evidence/d3-v02-build/t7d-d3-offline-build.json`. Evidence under the sibling `d3-build` directory predates v0.2 and is historical only; it must not be used to attest the current durable journal or dispatch invariant.

D3 closes the source-level gaps identified by the accepted independent D2 verdict without changing the operational boundary. No elevation, service installation, SCM mutation, protected-root mutation, key creation, pipe activation, fixed-probe execution, or arbitrary native execution was performed.

## Implemented offline

- The wire protocol is explicitly ASCII. A bounded native canonical JSON parser rejects non-ASCII, duplicate or unordered keys, whitespace/noncanonical escapes, `-0`, floating/exponential numbers, unsafe integers, excessive members/depth/size, invalid schemas, and trailing data. Typed entry points enforce exact fields, types, ranges, canonical base64url, and 64-byte P-1363 signatures for challenges, signed requests, capability contracts, Broker receipt envelopes, registry records, and replay records. Broker receipts bind request, contract, nonce, operation, release, action, outcome/evidence, time, host, target service, Broker image/service, and runner.
- Normal service custody opens an existing machine P-256 key in the Microsoft Platform Crypto Provider, verifies algorithm/export policy, derives a `kid` from canonical P-256 SubjectPublicKeyInfo, signs SHA-256 digests using NCrypt, reads the key DACL, and records a negative private-export probe.
- Key creation is isolated in a separate one-shot provisioning executable. It refuses an existing key and has no overwrite flag. Platform KSP is the default; software custody requires the explicit `--allow-software-custody` policy switch.
- The signed registry parses exact canonical records, verifies the SPKI-derived `kid`, root/active-key signatures, hash chain, monotonic sequence, bounded overlap, immediate revocation and retained history. Atomic replace is write-through, recovery validates both main and `.new`, and every write is reopened and fully revalidated.
- The replay/outbox store durably writes reservation before dispatch and a signed native receipt before terminal transition. `RESERVED` definitively means no external dispatch has occurred, so a restart may safely advance it to a durably reopened `DISPATCHED` record and invoke the callback once. An identical retry returns the prior signed receipt. A request-ID/hash conflict is refused; an unresolved `DISPATCHED` operation is reconciled rather than rerun.
- The Gateway helper opens the exact pipe with `GENERIC_READ | FILE_WRITE_DATA`, reads and validates the server challenge before signing, holds the server process and image handles, and checks SID/PID/creation time/path/hash/file ID/volume/signer plus exact SCM identity. One monotonic budget covers challenge, request and response; request signing and reply validation are mandatory. Concrete helpers import the active registry SPKI and verify P-256/P-1363 request and Broker-receipt signatures before applying exact receipt bindings.
- START_PENDING checkpoints accept only an actual gate predicate and stop immediately on failure; the unconditional overload was removed. The SCM verifier checks both services for exact OWN_PROCESS, delayed-auto start, account, quoted no-argument path, unrestricted SID mode, required-privilege set, failure flag/actions, service DACL, state and PID coherence.
- The five-second transport deadline still bounds overlapped pipe I/O. Synchronous identity/trust evaluation is explicitly a separate live acceptance concern; D3 does not claim that `CancelIoEx` can cancel synchronous Windows trust or SCM calls.

## Lost-response invariant

The durable order is `RESERVED -> DISPATCHED/RECONCILING -> SIGNED_RECEIPT_PERSISTED -> TERMINAL`. `RESERVED` carries no external-dispatch authority already exercised: after restart it may be advanced to `DISPATCHED`, persisted and reopened, and then dispatched once. Once `DISPATCHED` exists, a crash or lost response is indeterminate and requires signed Broker reconciliation; it never authorizes another callback. Retrying the same `(requestId, requestHash)` after terminal persistence returns the byte-identical prior signed receipt. A different hash for that request ID is a binding conflict.

## Live-only gates

These remain blocking and were not simulated as acceptance:

1. administrator-reviewed `-WhatIf`, install journal, rollback, and zero-mutation proof;
2. real TPM key creation/attestation/DACL/private-export-negative evidence on the target host;
3. authenticated signed release/config/key registry installed under protected ACLs;
4. real SCM readback for both installed services, failure actions, binary paths, accounts, and running PIDs;
5. real named-pipe kernel owner/DACL, exact Gateway rights, mutual held-image identity, and deadline behavior under hostile clients;
6. cached whole-chain Authenticode/revocation evidence under the declared embedded-signature policy;
7. power-loss/crash injection across every replay/outbox transition and recovery of a real Broker-signed receipt;
8. independent target-host negative corpus and assurance review;
9. explicit authorization before any installation or S7001 transition.

The D2 service binaries remain startup-refusing when authenticated installed state is absent. Offline mocks and behavioral harnesses are evidence about logic only, not live SCM, pipe, TPM, or filesystem acceptance.

The offline verifier compiles every D3 native module under `/W4 /WX /Brepro`, runs native canonical-schema and durable rotation/revocation/restart/idempotency/corruption tests, links every D3 module into both service binaries, and retains equality hashes from two complete linked builds. The corruption test is not described as a kill or power-loss test; those remain live gate 7. These results remain offline evidence only.
