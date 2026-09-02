# Stellar Windows x64 v0.1 Reproducibility Matrix

This matrix distinguishes reproducible source evidence from toolchain-qualified native evidence. Reproducibility and checksum integrity are not authorization to execute.

| Layer | Comparison | v0.1 evidence boundary |
| --- | --- | --- |
| Source, canonical manifest, locks, RELIC interfaces | Raw UTF-8 bytes and SHA-256 | Byte-deterministic across directories when reviewed inputs are identical. |
| Tokens, AST, HIR, MIR, layouts, module DAG, symbols, effects | Canonical JSON bytes and SHA-256 | Byte-deterministic under Stellar 0.1.0. Source spans remain module-relative evidence. |
| Generated MASM | Raw UTF-8 bytes and SHA-256 | Byte-deterministic; contains deterministic mangled symbols and no host path. |
| Raw COFF object bytes | SHA-256 from two independent assemblies | `/Brepro` identity is checked. The result is toolchain-qualified and may change with an MSVC/MASM version change. |
| Normalized symbol, relocation, and disassembly evidence | Canonical text after removing the artifact display path | Must be identical across the two assemblies. Raw `dumpbin` display paths are intentionally not claimed reproducible. |
| Raw inspection-only PE bytes | SHA-256 from two independent links | `/Brepro`, `/noentry`, and `/nodefaultlib` identity is checked and is toolchain-qualified. It is never loaded or run. |
| Release acceptance report | Canonical gate names and Boolean outcomes | Timings and temporary paths are excluded so the report structure is deterministic. The report attests only to non-executing gates. |

The release report cannot authorize a capability, Relation Contract, native load, or process. Authenticated Custodian/Steward authorization and independently verified OS-enforced isolation remain mandatory before arbitrary execution.
