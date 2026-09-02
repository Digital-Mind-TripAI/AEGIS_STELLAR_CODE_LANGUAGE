# Stellar Windows x64 v0.1 — T7b Fixed-Probe Sandbox

Status: fixed security probes only. `S7001` remains closed for Stellar programs and packages.

T7b implements a regular zero-capability AppContainer. LPAC is not claimed because the available documented process/token queries do not provide an exact pre-resume proof of LPAC group semantics. This is an explicit boundary, not a silent downgrade to an unsandboxed process.

The broker accepts only seventeen compiled-in probe names and locates one build-time SHA-256-pinned fixed runner image beside itself. It accepts no executable path, package, source, uploaded binary, DLL, callback, plug-in, COM activation, working directory, environment, linker flag, or arbitrary command line. There is no arbitrary Stellar or package execution and ConsoleWrite v0.1 remains inactive.

Before resume, the broker requires:

- `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` with the unique profile SID and zero capability SIDs;
- an exact three-entry standard-I/O `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`;
- `PROC_THREAD_ATTRIBUTE_JOB_LIST` and an exact comparison of all Job limit flags: active-process limit 1, kill-on-close, die-on-unhandled-exception, process-memory limit, process-time limit, and a 20-percent CPU hard cap;
- compatible creation mitigations, including DEP and Win32k disable;
- `TokenIsAppContainer`, exact AppContainer SID, low integrity, and zero token capabilities;
- verified Job membership, exact CPU/memory/kill/die limit values, no breakaway flags, DEP, and Win32k mitigation policy;
- a unique, reparse-refused temporary directory with a protected DACL granting the profile SID read/execute only;
- an AppContainer-profile-local minimal broker-created environment and fixed working directory.

The fixed runner's first application operation sets `ProcessChildProcessPolicy` with exactly `NoChildProcessCreation=1`, self-queries the exact flag word, and emits a bounded readiness marker. It then blocks on standard input. The broker independently queries the child policy and confirms exactly one process in the Job before sending the one-byte fixed-probe authorization. No denial or containment probe can execute before both checks succeed. Any set/query/readiness ambiguity returns `S7001` and closes the Job.

The broker creates the process suspended and without a window, then bounds readiness, wall time, stdout, stderr, and their combined total separately. Fixed probes cover the exact workspace `package.json` read, a unique workspace write target, a broker-created user-data sentinel read, a unique user-data write target, registry/shared-temp/device/GUI access, external network and loopback, normal `CreateProcessW`, `CREATE_BREAKAWAY_FROM_JOB`, crash, infinite loop, memory pressure, and output flooding. These are precise fixed-target observations; the evidence does not claim blanket filesystem denial. Child probes target only the same hash-pinned runner and must report `created=false`, PID zero; the broker samples the Job PID list throughout and records final total/active/terminated Job accounting. `NtCreateUserProcess` is not called because its structures are not a stable documented Win32 contract. COM/WMI and shell activation are not loaded in this tranche, preserving the reviewed fixed-runner-only boundary.

For network evidence, the broker creates a unique live loopback listener and passes only its numeric port. The runner performs a nonblocking connect, waits through `WSAPoll`, and checks `SO_ERROR`; the initial `WSAEWOULDBLOCK` is never accepted as denial. When the broker-owned WFP lease returns Winsock 10013, the fixed probe records `loopback-completion-classification-error-10013`; this is an explicit policy-denial classification and is accepted only when the broker independently verifies that its listener received no connection. The reviewed-host bounded-pending classification `loopback-completion-classification-error--1` remains allowlisted under the same no-connection check. The external documentation-only endpoint `192.0.2.1:9` is accepted as policy denial only with explicit `WSAEACCES`; timeout, unreachable, refused, or ambiguous completion fails closed.

The fixed runner is linked as a Windows-subsystem executable while retaining only the three broker-specified standard-I/O handles. Every inheritance-clearing call is checked. This is deliberately narrower wording than claiming a complete child handle-table enumeration. A console-subsystem diagnostic build caused Windows to place `conhost.exe` in the Job before readiness, violating the exact one-PID invariant even though no probe had been authorized. That build was refused. The Windows-subsystem runner produces no console host. The complete canonical PE import manifest records every imported DLL and symbol, is SHA-256-bound into the broker evidence, and currently contains only `KERNEL32.DLL`; it is not a partial denylist. System libraries used by individual denial probes are loaded only after the runtime child policy and broker authorization gate. The GUI probe is accepted only for the expected zero exit with a recognized User32-load, Win32k-entrypoint, or Win32k-call denial while the broker independently confirms the Win32k mitigation bit.

## Image identity and service boundary

The probe image is copied into a unique reparse-refused AppContainer-profile root. The broker opens it read-only with neither write nor delete sharing, hashes that retained handle, records its volume serial and 128-bit file ID, verifies the file and every ancestor beneath the unique root are reparse-free and confined, applies read/execute-only staged ACLs, and retains the handle through process completion. It then re-hashes and re-compares the same file identity before cleanup. Because documented `CreateProcessW` accepts an image path rather than an already-open image handle, a path-to-handle binding residual remains between verification and loader open.

Production integration therefore requires a dedicated least-privilege service identity with a service SID owning the staging root. Interactive users and the web process must have no write, delete, ownership, DACL, reparse, or traversal-changing rights there; only the service SID may stage and clean, while the AppContainer SID receives read/execute. The current same-user laboratory broker can narrow the DACL and retain a no-write/no-delete-share handle, but the file owner can ultimately rewrite its DACL. That is an explicit integration blocker. Checksum integrity is not authorization, and T7a/server integration remains prohibited until the service-identity boundary is independently verified.

Every run creates a unique AppContainer profile and temporary directory. Both must be deleted before success evidence is returned. Cleanup failure produces `S7001`; remaining material is reported as quarantined rather than treated as success.

Every success document is validated against the strict evidence schema. It binds the runner, complete imports, zero-effect declaration, policy, fixed input set, and resource bounds. The retained target-host acceptance report additionally binds OS identity and broker hash, requires all seventeen primary probes with zero failures/skips, and preserves repeated child-denial counts. “No second process” is reported as sampled Job PID evidence plus final Job accounting, not continuous kernel-wide observation.

This tranche does not connect the sandbox to the gateway, accept a signed execution contract, or reopen `stellar run`. Independent review of the native implementation and evidence is mandatory before any such integration.

## Creation-time incompatibility evidence (2026-08-17)

The fixed probe image starts under `SECURITY_CAPABILITIES` plus the exact handle list. Adding `PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED` at creation causes the suspended child to terminate during initialization with NT status `0xC0000142` (`STATUS_DLL_INIT_FAILED`) on Windows build 26200. Removing Job-list assignment and removing exploit mitigations did not change that result. This cell remains recorded as a creation-time executable/OS incompatibility; it is not described as a weakened policy or silently retried.

The independently reviewed corrective candidate omits only that incompatible creation-time attribute. It retains AppContainer, the exact handle list, creation-time Job assignment, active-process limit 1, kill-on-close, no breakaway, memory/CPU limits, DEP, and Win32k disable. Runtime child-process policy is mandatory and must be set and independently verified before the broker releases a fixed probe. This does not open Stellar/package execution: `S7001` remains closed pending successful fixed-probe evidence and subsequent independent review.
