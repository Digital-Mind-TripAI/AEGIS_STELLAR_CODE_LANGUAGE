# Stellar Windows x64 v0.1 — T7 Authorization Foundation

Status: T7a implemented; native launch remains closed.

## Enforced boundary

- `POST /api/admin/stellar-native/compile-run` always returns `STELLAR_T7_GATE_CLOSED`. It cannot invoke the legacy full-token compiler service in development, test, LAB, or production.
- Browser-generated ConsoleWrite checksums are display-only provenance. They are not authorization and are refused by accepted request validation.
- No T7a route launches, loads, links, or executes native code. Homeostasis remains `NOT_EVALUATED`.

## Contract authority

Contracts use ECDSA P-256 with SHA-256 (`ES256`) and a 64-byte CNG-compatible `r || s` signature. Signed protected and payload values are strict canonical JSON: sorted keys, integer-only numbers, bounded structures, exact field sets, and canonical byte equality. Duplicate fields, floats, unknown fields, noncanonical encodings, invalid keys, tampering, audience mismatch, and expired contracts are refused.

The signed payload binds the service, machine, install, request, source, package, build lock, toolchain, runner, image, input, target, ABI, entry symbol, imports, effects, sandbox policy, inherited standard handles, resource limits, nonce, issuer, and validity window. Launch expiry is at most 60 seconds.

Issuance requires `service.stellar.contract.issue`. Reservation requires the distinct `service.stellar.execute` role. `service.operations.read` grants neither authority.

Ephemeral private keys require explicit test-only injection. Production and LAB configuration require a provisioned non-exportable Windows CNG key reference, fixed machine/install identity, and durable Redis. If those dependencies are unavailable, startup/issuance fails closed; no in-memory fallback is permitted.

## Replay and evidence

The replay ledger has a separate Redis namespace and atomic compare-and-set transitions:

`ISSUED -> RESERVED -> CONSUMED | REFUSED`

A reservation is never reusable. An identical retry after finalization returns only the prior receipt. Conflicting nonce, request, executor, contract, or durable bytes are refused. Every transition appends a chained SHA-256 evidence record; aggregate state and evidence must retain canonical bytes.

T7a reservations are immediately finalized as `REFUSED` with `STELLAR_T7_SANDBOX_PENDING_REVIEW`. This records attempted authority without enabling execution.

## Mandatory next gate

Native launch remains prohibited until the deny-by-default Windows runner (restricted token, Job Object, mitigation policy, explicit inheritable standard handles, confined temporary ACLs, network/process denial, time/output/resource enforcement, cleanup) is implemented, tested, and independently reviewed. Checksum integrity is not authorization, and a valid signed contract alone is not sufficient to bypass OS isolation.
