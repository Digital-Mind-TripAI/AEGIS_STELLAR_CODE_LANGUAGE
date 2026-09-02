# Stellar Windows x64 v0.1 Language Contract

Status: implementation contract for a bounded native language release. Target: Windows x64 PE/COFF only (`windows-x86_64-msvc`). Profile: `stellar-lab-v0`.

## Truthful claim boundary

Stellar v0.1 is a machine-near, inspectable Windows x64 language package under active construction. Tranche 0 supplies the deterministic front-end, formatting, diagnostic, and package-integrity foundation. Phase A/B/C are real native vertical slices, but Stellar is not a general-purpose language at this stage. A v0.1 completion claim requires every acceptance gate in this document and the package-format contract to pass.

The five Luminators are deliberate language-design punctuation: Dot `·` (ASCII `;`), Chevron `›` (ASCII `>`), paired Crescents `( )`, Wave `~`, and Angular Stroke `/`. Their roles are not inferred from morphology. The official 34 glyphs remain identity and provenance records only; they do not imply operations or opcodes.

## Bounded model targeted by v0.1 completion

- Types: `bool`, `i32`, `i64`, `u32`, `u64`, and `f64`; integer literals default to `i32`; no implicit narrowing or widening; explicit `convert_TYPE` operations carry a range-check/status edge; checked integer arithmetic emits overflow status (`-12` i32, `-13` i64, `-14` unsigned) by default, while explicitly named wrapping operations have modulo two-to-the-width behavior.
- Memory: stack locals, statically laid-out structures and arrays, immutable static data, and caller-owned bounded slices. There is no hidden heap or garbage collector.
- Control: named nonrecursive functions, assignment, lexically scoped branches, compiler-proven bounded loops with loop-scoped `break`/`continue`, explicit return on all proven paths, and Result/status behavior.
- Modules: a package-root-confined acyclic module graph. Linkable RELICs expose versioned ABI, symbol, effect, import-allowlist, and content-integrity metadata.
- Capability-safe core: pure checked arithmetic/memory/result RELICs have no OS imports. Windows console output is a separate capability RELIC limited to its reviewed import contract.
- Inspection: source spans trace through typed AST, HIR, MIR, layouts, stack slots, symbols, assembly, object sections, machine bytes, effects, imports, and results.

Cross-platform targets, optimization, arbitrary FFI and raw pointer arithmetic, dynamic allocation/GC, recursion/exceptions, concurrency/atomics, self-hosting, a native assembler/linker/debugger, and a network package registry are post-v0.1 work.

## Tranche 0 deterministic limits

Source is well-formed UTF-8 without NUL bytes and is at most 262,144 bytes per module. The lexer accepts at most 16,384 tokens, the parser at most 2,048 statements, and a package at most 128 modules. Canonical formatting uses Unicode Luminators and LF endings. Diagnostics use stable codes: `S000x` source/limit, `S100x` lexical/syntax, `S200x` type, `S300x` memory/control, `S400x` module/RELIC, and `S500x` package/capability/integrity.

## Mandatory native execution authorization gate

Checksum integrity is not authorization. Hashes demonstrate byte identity only.

Authenticated Custodian/Steward-issued capability contracts plus OS-enforced native process isolation must land and pass security acceptance before arbitrary user-defined native execution is enabled. The isolation boundary must constrain process identity, filesystem and registry access, network access, child-process creation, memory/CPU/time, handles, job membership, and output. Capability contracts must be independently authenticated, source/package-bound, target-bound, narrow, expiring or revocable, auditable, and verified before compile/link/run. Browser code never invokes the native host directly, and there is no silent fallback when authorization or isolation is unavailable.

Until that gate passes, native execution is restricted to reviewed fixed fixtures and RELIC allowlists through the existing protected local-development gateway. A valid package checksum must never bypass identity, capability, Relation Contract, origin/CSRF, or isolation checks.

## v0.1 acceptance gates

1. Deterministic CLI, parser, typed model, formatter, package/lock integrity, and structured diagnostics pass conformance tests.
2. Explicit type, layout, memory, ABI, control, module, RELIC, effect, and import contracts are machine-verifiable.
3. Pure generated objects have zero unexpected imports; capability RELIC imports exactly match allowlists.
4. Tamper, conflict, path escape, module cycle, limit breach, type/layout error, overflow, unbounded loop, and unauthorized capability all fail closed.
5. Native results match the independent semantic reference for conformance fixtures without silent fallback.
6. Source-to-machine trace evidence and toolchain constraints are inspectable.
7. The mandatory native execution authorization and OS-isolation gate above is implemented and verified before arbitrary user-defined native execution.
8. Lab integration labels Reference Preview and Native Windows x64 distinctly and keeps Homeostasis `NOT_EVALUATED`.

These gates authorize a bounded Windows x64 v0.1 claim only, not an all-platform, optimizing, arbitrary-code or general-purpose claim.
