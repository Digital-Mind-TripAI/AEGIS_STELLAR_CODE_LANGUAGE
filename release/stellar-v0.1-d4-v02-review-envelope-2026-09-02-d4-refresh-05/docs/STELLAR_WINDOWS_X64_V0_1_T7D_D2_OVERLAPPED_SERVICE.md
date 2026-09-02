# Stellar Windows x64 v0.1 — T7d D2 overlapped service foundation

Status: **OFFLINE IMPLEMENTED; REJECTED FOR INSTALL; S7001 CLOSED**.

D2 replaces the synchronous T7c pipe loop. It does not authorize installation, service registration, key provisioning, named-pipe activation, fixed-probe dispatch, or arbitrary Stellar execution.

## Exact topology

| Service | Pipe | Owning service SID | Sole application client |
|---|---|---|---|
| Custodian | `\\.\pipe\AegisStellarCustodian.v0.1` | `NT SERVICE\AegisStellarCustodian` | `NT SERVICE\AegisStellarLabGateway` |
| Execution Broker | `\\.\pipe\AegisStellarExecutionBroker.v0.1` | `NT SERVICE\AegisStellarExecutionBroker` | `NT SERVICE\AegisStellarLabGateway` |

Each pipe DACL contains only SYSTEM, its owning service SID, and the Gateway SID, and the live kernel-object owner/DACL is read back and compared after creation. Gateway opens with `GENERIC_READ | FILE_WRITE_DATA`; its mapped DACL mask is `0x0012008b`, intentionally excluding `FILE_CREATE_PIPE_INSTANCE`. SYSTEM and the owner retain administration rights. SYSTEM is an installation/health administrator, never an application issuer or dispatcher: the post-reply identity policy still admits only the Gateway service. The Gateway calls Custodian only for issuance after independently verified Steward authority. The Gateway calls Broker only for the fixed action `stellar.t7b.fixed-security-probe-suite/v0.1`. Custodian never dispatches.

## Atomic stop-aware transport

The server uses one local-only, first-instance, message-mode pipe instance. This deliberately bounds concurrency to one until an independently reviewed multi-instance design exists. `ConnectNamedPipe`, `ReadFile`, and `WriteFile` are issued with `OVERLAPPED` structures whose events are unique to the operation. Each wait includes both the operation event and the SCM stop event. Once connected, one monotonic five-second budget covers the complete challenge/reply/authentication handshake; individual operations receive only the remaining budget. Stop, preshutdown, timeout, or error calls `CancelIoEx` and drains completion with `GetOverlappedResult` before releasing the event or pipe.

Every application connection carries one server challenge, exactly one consumed client request, and at most one terminal server response. One pipe message contains a four-byte little-endian length followed by 1–32,768 bytes. Truncation, `ERROR_MORE_DATA`, a zero/oversized length, a byte-count mismatch, or any trailing byte inside that framed message is refused. A second client message is never consumed or dispatched; the server closes the connection after the first request/terminal result. This is the intentionally narrow one-request guarantee—it does not claim that an adversarially raced second message can always be observed before the first request is evaluated.

## OS identity and challenge

The explicit state order is `connected → challenge-sent → reply-received → identity-bound → accepted/refused`. The server sends its challenge and receives the sole signed reply first. It then requires successful `ImpersonateNamedPipeClient` and, still before signature verification or dispatch, rederives and holds:

- exact Gateway SID and named-pipe client PID;
- process creation time and an open process handle;
- exact image path and an open image handle;
- volume serial/file ID, SHA-256 and Authenticode signer thumbprint while an image handle denying write/delete sharing remains held;
- SCM RUNNING state, `OWN_PROCESS` type, unrestricted service-SID type, exact account, exact quoted no-arguments binary path, live PID, exact required-privilege set, and exact failure policy.

The server creates 32 random bytes with the system CNG RNG and sends strict canonical JSON with schema `stellar-pipe-challenge-v0.1`, exact pipe/protocol/server service SID/name, PID, process creation time, image hash, volume/file ID, signer, server-instance bindings, a base64url nonce, and a validity interval no longer than five seconds. Before signing, Gateway must independently rederive those server fields from Windows, verify the expected Custodian or Broker SCM identity and held image identity, and refuse any mismatch. This is the mutual server-authentication half of the contract.

The client reply is one strict canonical ES256 envelope. Its signed payload binds the challenge hash, request ID/hash, exact action, client service SID/PID/creation time/image hash/volume/file ID/signer, key ID, and issued/expiry times. After receipt, current time is sampled again and expiry is checked. A single strict verifier operation validates canonical form/signature/all OS bindings and atomically consumes `(challengeHash, requestId)`; there is no substring prefilter or separate boolean replay seam. An injected authenticated key registry/parser must reject noncanonical encoding, unknown/revoked keys, any OS mismatch, expiry, replay, unsupported action, malformed P-1363 signature, or extra bytes. The native runtime provides CNG P-256/SHA-256 verification; no installed key or identity pin is invented by this offline tranche.

Authenticode verification requests whole-chain revocation with `WTD_CACHE_ONLY_URL_RETRIEVAL`. D2 performs no network retrieval: missing or insufficient cached revocation evidence fails closed. File identity is reread from the same held handle after trust evaluation so the trusted path cannot silently name a replacement file.

## SCM readiness

Both binaries remain `SERVICE_START_PENDING` while reporting checkpoints in this order:

1. authenticated configuration;
2. authenticated release manifest;
3. key/public registry;
4. protected ACL roots;
5. pipe DACL and first-instance creation;
6. service self-attestation and static-import verification;
7. worker ready.

Only then may the service report `SERVICE_RUNNING`. Every `SetServiceStatus` transition is checked. A failed gate returns `SERVICE_STOPPED` with a nonzero error and no pipe action; an unexpected clean worker return without a stop request is converted to `ERROR_SERVICE_NOT_ACTIVE`. STOP, SHUTDOWN, and PRESHUTDOWN signal the shared stop event and cancel pending I/O. Both services remain `SERVICE_WIN32_OWN_PROCESS`; their required privilege set is exactly `SeChangeNotifyPrivilege` and `SeImpersonatePrivilege`.

## Offline evidence and remaining blockers

The source/static negative corpus, behavioral transport model, and strict MSVC x64 `/W4 /WX /Brepro` compilation are authorized offline. The behavioral model covers partial/oversized/multiple messages, `ERROR_PIPE_CONNECTED`, stop/timeout, client exit, image replacement, wrong OS/SCM identity, stale replay, and Gateway server-identity refusal. The current service entrypoints deliberately use a closed registry adapter: authenticated installed configuration, Gateway image pins, signing keys, and durable replay storage do not yet exist. Custodian only opens the named, pre-provisioned TPM P-256 issuer key; startup never creates a key and has no software-provider fallback. Consequently an installed service cannot pass the first readiness gate, cannot report RUNNING, and cannot accept an application request. This is a truthful fail-closed boundary, not install readiness.

No elevation, SCM mutation, key creation, protected-root creation, pipe activation, or S7001 opening is part of D2.
