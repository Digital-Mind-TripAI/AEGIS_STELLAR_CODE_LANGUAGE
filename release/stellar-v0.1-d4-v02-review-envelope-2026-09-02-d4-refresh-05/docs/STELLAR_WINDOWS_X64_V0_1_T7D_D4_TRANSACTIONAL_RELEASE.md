# Stellar Windows x64 v0.1 — T7d D4 transactional release package

Status: **OFFLINE IMPLEMENTED; RE-REVIEW READY; REVIEW ENVELOPE NONINSTALLABLE; S7001 CLOSED**.

D4 replaces the prior mutation-capable draft installer with a zero-mutation proposed-state planner. No administrator token, service-control operation, protected-root write, ACL change, key creation, certificate minting or trust, firewall change, pipe activation, S7001 transition, or native execution occurred.

## Release boundary

The v0.2 release manifest covers the complete reviewed set by role: Custodian service, Execution Broker, fixed Runner, compiler, standard library, every schema, canonical policies, installed configuration, contract adapter, lifecycle/release scripts, documentation, and static-import evidence. Every entry binds its normalized relative path, exact byte length, SHA-256 digest, imports, and signer identities. The signed envelope binds a Windows x64 ABI target and exactly one policy:

- `LAB_SELF_SIGNED` permits a separately authorized Lab signer. It does not mint a certificate, install a root, or modify trust.
- `EXTERNAL_SIGNER` requires a separately supplied external release signer.

The signing API accepts an already-custodied private key. It cannot create a key or certificate. Verification rejects an unknown key identifier, signature mismatch, malformed or noncanonical manifest, missing artifact class, case-colliding or escaping path, UNC/ADS path, reparse point, hardlink, identity race, hash/length mismatch, import mismatch, signer mismatch, and unreviewed or elevation-unknown ACL evidence. File handles remain held after verification and through the caller's transaction boundary.

The checked-in `release/stellar-v0.1-d4-reviewed-unsigned` directory is intentionally unsigned and non-installable. `UNSIGNED-RELEASE-MANIFEST.json` hashes its reviewed inputs, while `IMMUTABILITY.json` binds that manifest. Its read-only bit is convenience evidence, not a security boundary. A signed release must be produced into a new directory; this directory is never rewritten in place.

The superseding `release/stellar-v0.1-d4-v02-review-envelope` is a canonical v0.2 offline review envelope. It contains the exact accepted `stellar-t7b-sandbox.exe` (`215672560dca8e0dafe2d6e76540f4f054d6c97ff937328fcd5f7dd89fd0c6da`) and fixed-probe runner (`1d1197fe1b7aa86e0fd12db1e4bac8a0b532c1c22ff5f0a491acdffa6eb9f123`), both Windows services, native compiler and legacy native runner, and every runtime-bound T7b policy/import/effect/input/resource/acceptance file. Its dependency-closure record names every runtime-referenced installed file and evidence directory. Native `dumpbin` evidence provides nonempty imports for every PE.

The current PE files have no valid embedded Authenticode signatures. Their explicit policy is therefore `UNSIGNED_REVIEW_ONLY`, their signer observation is `AUTHENTICODE:UNSIGNED`, and the manifest derives `installable: false`. The envelope has an ephemeral offline Lab review signature whose public key is retained for review; its private key was not retained. No certificate was minted and no trust was changed. This envelope proves integrity and completeness for review, not install authorization.

The public key carried in the package is informational review material and is never a trust source. Plan discovery requires an operator-pinned authority PEM and canonical pin file at absolute paths outside `PackageRoot`; the pin binds the key bytes and key identifier. The emitter calls `verifySignedRelease` with that external authority and performs full structure, signature, hash, PE import/signer, ACL, ADS, link, file-identity, and post-inspection checks before it may construct a plan.

## Transaction model

Planning is pure and reports `ZERO_MUTATION_PROPOSED_STATE` and `mutationsPerformed: 0`. Every undiscovered resource—not merely privileged resources—is `unknown_not_queried`; a future privileged discovery may instead report `unknown_requires_elevation`. Unknown state is never treated as absent. The planner enumerates every release file plus directories, installed configuration, resource identities, services, ACLs, registry state, keys, certificates, and firewall rules. It derives canonical desired-state/readback hashes rather than using a caller assertion. Accurate prestate is mandatory before apply.

Every manifest artifact has an explicit destination mapping: services, broker, fixed runner, sandbox, compiler, and native runner use exact `bin` paths; standard library uses `stdlib`; schemas use `schemas`; policies and installed configuration use `config`; adapters and lifecycle scripts use `tools`; documentation uses `docs`; and native inspection evidence uses `inspection`. Both service desired states bind the fully quoted executable path, virtual service account, `SERVICE_WIN32_OWN_PROCESS`, stopped/manual start, required privileges, dependency list, unrestricted service SID, failure actions, and service SDDL.

Before any future authorized mutation, a durable hash-chained journal must snapshot the exact preexisting state of:

1. services and their SCM configuration;
2. files, directories, content, metadata and identity;
3. protected ACLs and owners;
4. key records and custody descriptors;
5. certificate and trust-store records;
6. firewall rules;
7. installed configuration.

Every native operation has an explicit success-code set, and every result is checked exactly. Each change is followed immediately by canonical desired-state readback. Both services remain stopped until all readbacks succeed. A failure at the current stage triggers readback and restoration of that stage as well as reverse rollback of earlier stages, unless the driver supplies an explicit atomic-no-mutation proof. A rollback failure produces `rollback_incomplete`; it is never reported as success. Deletion completion must be awaited before journal closure.

Before invoking any driver, the transaction executor revalidates exact schema/version, plan hash, expected release hash, external authority hashes, ordered contiguous sequences, unique snapshot/proposal identities, complete snapshot/proposal correspondence, canonical desired hashes, manifest-to-destination closure, success codes, and explicit driver authorization. File-copy apply accepts only a `VerifiedD4Release`, rechecks the retained source descriptor's device/file ID/size/hash immediately before copy, and passes that held descriptor to the driver. A caller-supplied zero/default release hash is not accepted.

Discovery and apply are deliberately split. `discover-d4-install-plan.ps1` is non-elevating, uses a fixed Node invocation rather than `npx`, requires external pinned authority inputs, and emits the canonical proposed-state plan. Its verified handles are closed after serialization; consequently, a serialized plan is not apply authority. The apply entrypoint remains closed. Any future separately approved in-process apply executable must call `verifySignedRelease` again and keep its handles open for the entire transaction.

An identical already-satisfied plan has no proposed mutations and returns `no_change`. Repeated install and uninstall therefore require state comparison, not blind recreation or deletion.

## Offline fault corpus

The D4 model injects failure at every planned resource stage and covers apply failures, readback mismatch, exact nonzero native exits, reverse restoration, rollback failure, signer mismatch, content/hash mismatch, escaping path, reparse root, hardlink, import mismatch, ACL unknown, missing artifact class, idempotent no-change, and stopped-after-install invariants. SCM/key/certificate/firewall behavior is represented only as an effect-driver boundary; it is not claimed as live Windows evidence.

## Remaining live gates

Independent review must accept this package before any elevation is requested. A separately authorized target-host phase must then supply genuine elevated discovery, signature and Authenticode evidence, ACL/owner reads, SCM reads, key/certificate custody evidence, firewall reads, crash-durable journal storage, stop-state verification, rollback/recovery drills, hostile filesystem tests including ADS, and post-install readback. No elevation or `WhatIf` request is part of D4 discovery. Until that approval exists, `install-services.ps1` refuses unconditionally.
