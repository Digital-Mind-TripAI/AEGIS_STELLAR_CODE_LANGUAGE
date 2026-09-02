# Stellar Windows x64 v0.1 Package Format

`stellar.package.json` is a closed, canonicalizable manifest. Required fields are `schema`, `name`, `version`, `target`, `profile`, `entry`, `modules`, `relics`, and `capabilities`. Tranche 0 accepts schema `stellar.package/v0.1`, target `windows-x86_64-msvc`, and profile `stellar-lab-v0` only. Unknown or duplicate fields fail closed.

Module and entry paths are normalized relative paths contained within the package root. Absolute paths, `..` traversal, missing/non-regular files, duplicate modules, more than 128 modules, and resolved paths outside the root are refused. Later module resolution must also refuse symlink/junction escapes and cycles before link.

Canonical JSON uses lexicographically ordered object keys, original array order, UTF-8, and no insignificant whitespace. `integrity` is a real SHA-256 digest of the canonical manifest. Each module has its own SHA-256 digest. `stellar.lock.json` records schema `stellar.lock/v0.1`, package integrity, and module hashes. Lock verification checks all reviewed bytes before later compilation or execution.

Integrity is evidence of byte identity, not identity, authorization, consent, capability, safety, or runtime isolation. The mandatory capability-contract and OS-isolation gate in the language contract remains independent.

## Module graph and symbols

A module file begins with exactly one `module NAME ·` directive, followed by zero or more `import PROVIDER / SYMBOL ·` and `export SYMBOL ·` directives. Directives precede struct/function declarations. Module identities are unique. Imports name an explicitly exported function from another package module or declared RELIC interface; there is no wildcard import, implicit search path, alias, ambient symbol, or network resolution. The dependency graph must be acyclic. Deterministic topological order selects the lexicographically smallest ready module while always placing dependencies before consumers.

Linkable interfaces accept fixed-width scalar types and bounded scalar `array(TYPE,N)` or caller-owned `slice(TYPE,N)` types. Functions use explicit `Result(TYPE)` status behavior and the `stellar-win64-v0.1` ABI. Package and RELIC versions must be `0.1.x`; target is `windows-x86_64-msvc`; profile is `stellar-lab-v0`. Any version, target, profile, ABI, signature, duplicate identity/export/import, symbol conflict, or missing export mismatch fails closed.

The deterministic COFF symbol form is `stellar_v01_m<module-utf8-hex>_s<symbol-utf8-hex>_h<signature-sha256-16>`. The final component is the first 16 lowercase hexadecimal characters of SHA-256 over the canonical signature `name(param,...)->Result(type)`. UTF-8 hexadecimal identities prevent separator ambiguity; duplicate final symbols are refused.

## RELIC interfaces and dependency lock

`stellar.relic-interface/v0.1` is a closed interface schema containing name, `0.1.x` version, target, profile, ABI, exports, effects, and imports. Tranche 2 permits only capability-free, import-free RELIC interfaces. It does not accept object files, DLLs, archives, linker flags, arbitrary paths, or executable payloads.

`stellar.dependency.lock.json` uses schema `stellar.dependency-lock/v0.1`. Its canonical evidence binds the base package integrity, dependency-graph hash, symbol-table hash, every module source hash, every module typed-evidence hash, and every RELIC-interface content hash. Its own `integrity` is SHA-256 of the canonical lock fields excluding `integrity`. Verification recomputes the complete expected lock and compares exact canonical bytes.

## COFF planning and mandatory execution boundary

Tranche 2 produces deterministic per-module COFF-x64 planning evidence: module, fixed target and format, confined planned object name, source hash, typed-evidence hash, and resolved symbol/interface evidence. It deliberately records `objectEmitted: false` and `executableLinked: false`. No object, executable, DLL, archive, command line, host process, capability, or OS import is produced by this package path.

Checksum integrity is not authorization. Authenticated Custodian/Steward-issued capability contracts plus OS-enforced native process isolation remain mandatory before arbitrary user-defined native execution. Package, dependency-lock, source, symbol, or RELIC hashes cannot bypass that gate.
