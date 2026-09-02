# Stellar Windows x64 v0.1 Core Standard-Library RELICs

## Scope

Tranche 3 packages three versioned, pure Windows x64 COFF RELICs for `stellar-lab-v0` and ABI `stellar-win64-v0.1`:

- `core.checked`: checked and explicitly wrapping `i32` addition, subtraction, and multiplication;
- `core.memory`: bounded caller-owned `u32`-slice copy, fill, and equality operations, with a maximum element count of 65,536 (the retained `*_u8` export spelling is a legacy symbol identity, not a byte-layout override);
- `core.result`: bounded `Result`/status construction, preservation, and success testing.

Their MASM implementations allocate no heap, import no OS symbol, declare no effect, link no executable, and are never run by the Tranche 3 verifier. `stellar-win64-v0.1` is explicitly decomposed as `win64-ordinal-expanded/v1` arguments and `eax-status+caller-out-pointer/v1` results in every pure RELIC interface. `EAX == 0` means the typed result was written to the next ordinal caller-owned output pointer; a negative `EAX` is a status and leaves the result unavailable. Each interface export is bound to a deterministic mangled symbol. The verifier assembles each source twice, inspects symbols and disassembly independently, refuses unexpected imports or symbol/interface differences, and emits hash-bound package evidence.

## Reproducibility boundary

The verification report states raw COFF byte identity as an observed boolean. It does not claim byte reproducibility when the pinned MSVC/MASM toolchain embeds differing object metadata. Normalized symbol and disassembly evidence must always be identical across the two builds or verification fails. The lock records a raw object hash only when that byte identity was observed; otherwise it binds normalized object evidence.

## ConsoleWrite boundary

`windows.console` is a separate capability RELIC descriptor and unassembled source. It declares only `KERNEL32.dll!WriteFile`, `windows.console.write`, and the required Relation Contract. It remains `authorized: false`, `compiled: false`, and `executionEnabled: false`.

Checksum or package integrity is not authorization. ConsoleWrite and arbitrary user-defined native execution remain blocked until authenticated Custodian/Steward-issued capability contracts and independently verified OS-enforced native process isolation are implemented. Tranche 3 neither grants that authority nor runs native code.

## Produced evidence

`build-stdlib.ps1` emits an output-local canonical `stellar.stdlib.lock.json` and `stdlib-verification.json`. Evidence binds the manifest, interfaces, sources, ABI, target, profile, inspected symbols, normalized disassembly, toolchain identity, and the separate ConsoleWrite descriptor/source. Paths are confined beneath the supplied standard-library root; tamper, duplicates, symbol collisions, compatibility mismatches, imports, and lock drift are refused.
