# Stellar Windows x64 v0.1 — T7c service boundary

Status: **offline implementation; S7001 CLOSED**. No arbitrary Stellar, package, DLL, callback, plugin, COM activation, source-derived code, or uploaded executable is accepted. T7c names one fixed, hash-pinned action: `stellar.t7b.fixed-security-probe-suite/v0.1`.

## Identities and custody

`AegisStellarCustodian` is the distinct contract issuer. It prefers the Microsoft Platform Crypto Provider and records `TPM_BOUND`; if unavailable it may use Microsoft Software Key Storage Provider only while recording `SOFTWARE_BOUND`. Its ECDSA P-256 issuer key is machine-scoped, non-exportable, and its key DACL is SYSTEM plus the Custodian service SID. Rotation publishes the public SPKI-derived `kid`, activation time, retirement time, revocation state, provider, and custody classification; the private key is never placed in config or returned on the pipe.

`AegisStellarExecutionBroker` has public Custodian keys only and a separate non-exportable P-256 evidence-attestation key. Its pipe and staging/evidence trees have protected DACLs. The staging root must be local NTFS, non-reparse at every ancestor, owned by SYSTEM or installation authority, and writable only by SYSTEM, installation authority during reviewed servicing, and the Broker service SID. Browser and interactive-user write, delete, owner, and DACL rights are refused.

Both image paths are fixed, absolute, quoted paths below `C:\Program Files\AEGIS\Stellar\v0.1`. Safe DLL search is set before other work. Service DACLs do not grant interactive users start/change/configure rights. The installer has `-WhatIf`, runs elevation/NTFS/reparse preflight first, and rolls back any service created by a failed attempt.

## Contract adapter and evidence

The adapter verifies strict canonical JSON and ES256, exact audience, expiry (maximum 60 seconds), contract/request/nonce, and every locally rederived retained T7b hash. A SHA-256 is canonical only as lowercase `sha256:` followed by 64 lowercase hexadecimal characters; a bare lowercase digest may be normalized once at the local retained-evidence seam. Prefix nesting, uppercase, alternate algorithms, floats, unknown fields, and duplicate JSON fields are refused.

Production/LAB requires the durable Redis replay store. Reservation is atomic and one-way: `ISSUED → RESERVED → CONSUMED|REFUSED`; a reserved nonce is never reusable. An identical retry after finalization returns the prior receipt and does not invoke the broker. Expiry is checked at signature verification, reservation, and immediately before invocation. All refusal and cleanup outcomes are finalized in the same ledger and correlated with a Broker-signed receipt.

The static PE import manifest remains separate from runtime dynamic-module evidence. The only runtime module names allowed for the fixed probes are `advapi32.dll`, `ws2_32.dll`, and `user32.dll`; each must resolve to System32 and have its canonical name, full path, volume/file ID, file version, SHA-256, and Authenticode result recorded. Any mismatch is fail-closed.

## Installation gate

Compilation and `--offline-self-test` do not register or start services and do not provision keys. Installation requires an elevated, independently reviewed invocation. Until that review, the native service mains intentionally expose no SCM execution dispatch, the server is not integrated, and S7001 remains closed.

The retained offline acceptance report is deliberately unsigned: the Broker attestation key cannot exist before reviewed elevated provisioning. A signed aggregate, live pipe ACL proof, live key ACL proof, restart recovery, and installed-service attack corpus are installation acceptance requirements, not claims made by the offline build.
