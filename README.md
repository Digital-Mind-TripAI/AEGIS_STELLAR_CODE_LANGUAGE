# AEGIS Stellar Code Language

Stellar is a small, deterministic programming language and native compiler for Windows x64, built for the AEGIS Initiative. Its toolchain is designed so that no step quietly does something other than what was asked: every build is reproducible, every refusal is explicit, and nothing falls back silently.

Stellar also lets AEGIS architectural concepts (Orbs, Totems, Fields, Actuators, Gap-Pauses) be written as declarations the compiler checks, so a program's governance structure is validated along with its code.

> **Status: v0.1, Windows x64, in progress.** Stellar can check, format, build and inspect programs, and emit verified native objects. Running arbitrary user-written native code is deliberately closed until the authorization and isolation gate described below passes independent verification.

## A first look

```stellar
function adjust ( value / i32, enabled / bool ) / Result ( i64 ) (
  let wide / i64 ( convert_i64 ( value ) ) ·
  let answer / i64 ( convert_i64 ( 0 ) ) ·
  if equal ( enabled, true ) ( set answer ( add ( wide, convert_i64 ( 10 ) ) ) · ) ~ otherwise ( set answer ( sub ( wide, convert_i64 ( 10 ) ) ) · ) ·
  return ok ( answer ) ·
) ·
function main ( seed / i32 ) / Result ( i64 ) (
  let total / i64 ( convert_i64 ( 0 ) ) ·
  let adjusted / i64 ( try_value ( adjust ( seed, true ) ) ) ·
  loop step / i32 ( from: 0, max: 3 ) (
    set total ( add ( total, convert_i64 ( step ) ) ) ·
  ) ·
  return ok ( wrapping_add ( total, adjusted ) ) ·
) ·
```

- `name / Type` declares a typed name. Functions return `Result`, so success (`ok`) and failure (`err`) are always explicit.
- `·` ends a statement. `~ otherwise` gives an `if` its alternative branch.
- Integers are fixed width (`i32`, `i64`, and so on). Overflow is either checked (`add`) or explicitly wrapping (`wrapping_add`), never implicit.
- Loops are bounded: every loop states its maximum.

## Semantic declarations

Alongside ordinary code, Stellar checks declarations that describe how a system is structured and governed:

```stellar
element bridge / SignalBridge ( ) ·
orb signal-orb / Signal ( bridge ) ·
field runtime / Observation ( orb: signal-orb, target: workspace, state: active ) ·

totem scout / Satellite ( parent: mission, shortfall: missing-approval ) ·
totem mission / Orb ( child: scout ) ·
actuator repair / RepairActuator ( target: dependency-approval, totem: scout, shortfall: missing-approval, authorization: required ) ·
```

| Declaration | Purpose |
|---|---|
| `element` | A basic building block that other declarations refer to |
| `orb` | A capability attached to the system |
| `field` | An observation layer bound to an Orb, with a declared target and state |
| `totem` | A recorded point in the system's structure, including any open shortfall |
| `actuator` | A proposed action linked to a Totem and its shortfall, carrying its authorization state |
| `gap-pause` | A bounded wait (such as awaiting approval) with declared resume and abort conditions |
| `harmonic` | A declared signature with bounded parameters |
| Relational flow | The connections between declarations, checked for cycles and unknown references |

The compiler refuses inconsistent declarations, such as an Actuator pointing at an unknown Totem, a missing authorization, a duplicate field, or a Gap-Pause timeout outside its allowed range.

## Toolchain

The `stellar` command-line tool provides:

| Command | What it does |
|---|---|
| `version` | Print the compiler version |
| `check` | Parse and type-check a package, with stable diagnostics |
| `fmt` | Canonical formatting across the full grammar |
| `build` | Deterministic native build (typed MASM to verified COFF objects) |
| `inspect`, `inspect-manifest` | Inspect source, packages and build output |
| `test` | Deterministic, source-only conformance tests |
| `package` | Produce a canonical package bundle with provenance |
| `run` | Refused with an explicit error code until the execution gate passes |

A package is described by a `stellar.package.json` manifest:

```json
{
  "schema": "stellar.package/v0.1",
  "name": "minimal",
  "version": "0.1.0",
  "target": "windows-x86_64-msvc",
  "profile": "stellar-lab-v0",
  "entry": "main.stellar",
  "modules": ["main.stellar"],
  "relics": [],
  "capabilities": []
}
```

**RELICs** are versioned, linkable library units with a declared interface. The core library (`stdlib/`) provides checked and wrapping arithmetic, bounded memory and slices, and Result/status handling as RELICs.

## Design principles

- **Deterministic.** The same input produces byte-identical output. Reproducibility is tested across raw and normalized builds.
- **No silent fallback.** Unsupported features are refused with a coded diagnostic, never approximated.
- **Checksums are not authorization.** Native execution requires authenticated capability contracts issued by a Custodian service, plus OS-enforced process isolation.
- **Evidence over claims.** Each milestone produces machine-checkable evidence, and the release-acceptance report fails closed.

## Roadmap

| Tranche | Scope | Status |
|---|---|---|
| 0 | Deterministic foundation: `version`, `check`, `fmt`, `inspect-manifest`, lexer and parser, stable diagnostics | Implemented |
| 1 | Language core: typed AST/HIR/MIR, fixed-width types, layouts, calls, branches, bounded loops, Result | Implemented |
| 2 | Modules and linkable RELICs: acyclic module graph, ABI interfaces, deterministic symbols, dependency lock | Implemented |
| 3 | Capability-safe core library | Implemented |
| 4 | Bounded native build and link evidence (MASM/COFF, verified symbols and relocations) | Implemented |
| 5 | Non-executing developer tooling | Implemented |
| 6 | Conformance and security suites, reproducibility matrix, release-acceptance report | Implemented |
| Gate | Authenticated Custodian capability contracts and OS-enforced isolation, independently verified | In progress |
| 7 | Protected Lab integration: gateway, Workbench inspection, Reference Preview and Native labels | In progress |
| 8 | Distribution and full Windows x64 acceptance evidence | Planned |

The full plan is in [`TRANCHE_PLAN.md`](TRANCHE_PLAN.md). Until the gate passes, reviewed fixed fixtures and allowlisted RELICs are the only native execution surface.

## Repository layout

| Path | Contents |
|---|---|
| `src/`, `include/stellar/` | Compiler and CLI (C++20): lexer, parser, types, package graph, semantic declarations, relational flow |
| `stdlib/` | Core library RELICs: x64 MASM sources and their interface definitions |
| `service/` | Custodian service: capability policy, request signing, key custody, durable state, execution broker |
| `sandbox/` | Execution sandbox broker and network-isolation (WFP) boundary |
| `schemas/` | JSON schemas for packages, locks, diagnostics, build evidence, capability contracts and more |
| `tests/` | Conformance suites by tranche, golden outputs, fixtures |
| `tools/` | Build, packaging, stdlib and release-acceptance scripts |
| `evidence/`, `reports/`, `release/` | Recorded verification evidence and review bundles |

## Building

You'll need Windows x64 and Visual Studio 2022 with the **MSVC x64 C++ tools** (the build uses `cl.exe` and `ml64.exe`).

```powershell
./tools/build-cli.ps1 -Output out/stellar.exe
```

This builds the CLI with `/std:c++20 /W4 /WX` and reproducible-build flags, and copies the packaging scripts and schemas next to it. `tools/build-stdlib.ps1` and `tools/build-package.ps1` build the core library and packages.

## Testing

The conformance suites in `tests/` are TypeScript tests run with Node.js and `tsx`. They were written to run inside the larger AEGIS workspace, where this package sits at `native/stellar/v0_1/`. `tools/release-acceptance.mjs` runs the fixed suite set and writes a release-acceptance report.
