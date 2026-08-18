# Stellar Windows x64 v0.1 Closure Tranches

This plan closes a bounded Windows x64 package. It does not authorize claims beyond the language contract.

1. **Tranche 0 — deterministic foundation:** standalone `version`, `check`, `fmt`, and `inspect-manifest`; bounded source/lexer/parser skeleton; stable diagnostics; canonical package and lock integrity.
2. **Tranche 1 — language core:** general typed AST/HIR/MIR for the contracted fixed-width types, layouts, stack/caller-owned memory, named calls, branches, bounded loops, and Result/status.
3. **Tranche 2 — modules and linkable RELICs:** confined acyclic module graph, ABI/interface packages, deterministic symbol resolution, canonical dependency lock, and non-emitting per-module COFF plans. General object emission and linking remain closed.
4. **Tranche 3 — capability-safe core library (implemented):** versioned zero-import checked/wrapping arithmetic, bounded memory/slice, and Result/status COFF RELIC evidence; separately contracted and deliberately uncompiled Windows ConsoleWrite.
5. **Tranche 4 — bounded native build/link evidence (implemented):** deterministic typed MASM/COFF emission, exact symbol/relocation/import verification, and a fixed non-entering PE inspection link. There is no `run`, load, or user-package process execution; unsupported native ABI types refuse without fallback.
6. **Tranche 5 — non-executing developer tooling (implemented):** stable version/check/fmt/build/inspect/test/package commands; staged diagnostics with primary/secondary spans; full-grammar canonical formatting; source/package/build inspection; deterministic source-only conformance; canonical bundle/provenance verification. `run` is an explicit coded refusal.
7. **Tranche 6 — conformance and security (implemented):** golden grammar/type/layout/ABI/lowering suites; fixed-seed differential/property corpus; malformed input, traversal/junction, cycle, tamper, conflict, import/effect, argument, bound, output-confinement, and cleanup refusals; raw-versus-normalized reproducibility matrix; and a fail-closed non-executing release-acceptance report.
8. **Mandatory authorization/isolation gate:** checksum integrity is not authorization. Authenticated Custodian/Steward-issued capability contracts and OS-enforced native process isolation must be implemented and independently verified. This gate blocks arbitrary user-defined native execution until it passes.
9. **Tranche 7 — protected Lab integration:** package-aware gateway and Workbench inspection, distinct Reference Preview and Native Windows x64 labels, no browser host call and no silent fallback.
10. **Tranche 8 — distribution and acceptance:** versioned compiler/RELIC/schema/documentation bundle and complete Windows x64 acceptance evidence.

The mandatory gate is ordered before any arbitrary user-defined native execution regardless of the progress of other tranches. Until then, reviewed fixed fixtures and allowlisted RELICs remain the only native execution surface.
