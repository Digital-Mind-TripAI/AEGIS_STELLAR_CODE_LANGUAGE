# Stellar Windows x64 v0.1 Developer Tooling

## Stable non-executing command surface

- `stellar version`
- `stellar check FILE`
- `stellar fmt FILE [--check]`
- `stellar inspect TARGET [--view VIEW]`
- `stellar test MANIFEST`
- `stellar package MANIFEST (--output FILE | --verify FILE)`
- `stellar build MANIFEST --output NEW_DIR --stdlib DIR [--verify-build-lock FILE]`

`inspect` exposes deterministic tokens, typed AST, HIR, MIR, layouts/source traces, module graph, symbols, relocations, generated assembly, bounded machine-byte hex, effects, and hashes for the applicable source, package, or completed build target. `test` repeats manifest, lock, front-end, graph, symbol, source-map, and native-plan analysis without assembling, linking, loading, or executing user code. `package` emits a canonical JSON bundle containing exact module/RELIC bytes, manifest and lock hashes, installed schema hashes, and grounded provenance; verification regenerates the expected bundle and refuses any difference.

`stellar run` is deliberately present only as coded refusal `S7001`. It cannot execute a fixture, package, object, DLL, or capability.

## Diagnostics

Human and JSON diagnostics retain stable codes, primary spans, zero or more labelled secondary spans, stage, and help. Code families are: `S000x` source limits; `S100x` lex/parse; `S200x` type; `S300x` layout/control; `S400x` module/RELIC; `S500x` package/integrity; `S600x` native lowering/link; and `S700x` developer tooling/security. Build-driver failures honor `--diagnostic-format json` and do not expose arbitrary tool invocation.

## Authority and execution boundary

Formatting is token-canonical, Unicode-Luminator normalized, LF-only, roundtrippable, and idempotent across the complete accepted v0.1 grammar. The five punctuation decisions remain language design, never morphology-derived opcodes. Official glyphs remain identity/provenance only.

All tooling reports Homeostasis `NOT_EVALUATED`. No command in this tranche authorizes capability use or arbitrary user-defined native execution. Checksum or bundle integrity is not authorization. The mandatory authenticated Custodian/Steward Relation Contract and OS-enforced process-isolation gate remains closed.
