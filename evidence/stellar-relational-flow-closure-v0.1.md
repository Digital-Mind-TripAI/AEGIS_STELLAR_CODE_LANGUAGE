# Stellar Relational Flow Closure Contract v0.1

**Status:** Shortfall identified; native syntax is not ratified.

## Target

Represent condition-expressed relational flow in Stellar without importing
forceful control-flow semantics. A future construct must describe how declared
Elements, Orbs, Harmonic Signatures, and Field Layers relate under conditions,
while preserving passive Totem communication and the closed S7001 gate.

## Authority finding

The governing Stellar Script material describes relational flow conceptually:
relational conditions, harmonic gradients, Witness alignment, and drift/capture
dynamics. It explicitly labels the syntax examples as draft and gives only a
shape, not a grammar. The Annex material describes Orb/Tether state and
continuity context, but does not define a compiler construct or evaluator.
Font definitions describe semantic/execution posture and capture/drift values,
but are glyph metadata rather than relational-flow grammar.

## Shortfall

The current native v0.1 parser has no ratified relational-flow declaration. The
following are unspecified and must not be inferred from the conceptual prose:

- source spelling, token boundaries, and declaration placement;
- whether a flow links Elements, Orbs, Field Layers, or Tethers;
- condition and gradient value types, bounds, and comparison semantics;
- Witness alignment and drift/capture representation;
- ordering, cycles, convergence, and pressure-minimization semantics;
- whether a flow is passive data, a proposal, or executable behavior;
- diagnostics, canonical formatting, serialization, and version migration.

Existing `flow` examples in older conformance/security tests are adapter-style
pipeline fixtures and are not evidence that the governing Stellar Script
relational-flow syntax has been ratified. They must not be silently promoted to
the native language contract.

## Required ratification questions

1. Ratify a declaration-only relation model and its named endpoints.
2. Define a canonical grammar and bounded cardinality for relations and
   conditions.
3. Define the allowed condition vocabulary and numeric ranges, including the
   relationship to Harmonic Signature and Field Layer metadata.
4. Define whether cycles are legal and how duplicate/reverse relations behave.
5. Define deterministic diagnostics and canonical output.
6. Confirm that relational-flow declarations have empty effects/capabilities,
   cannot dispatch Actuators, and cannot open FFI, I/O, GUI, network, child
   process, or S7001 execution.

## Closure path

After ratification, implement the smallest declaration-only slice:

1. Add an AST node and parser production for the ratified form.
2. Validate stable endpoint references, uniqueness, bounds, and reserved keys.
3. Emit hash-independent relational-flow trace evidence with
   `executionEnabled:false`.
4. Add positive, unknown-endpoint, duplicate, malformed, cycle, and
   action-field refusal fixtures as applicable.
5. Add a versioned JSON schema and focused native CLI tests.
6. Update the language inventory and compatibility matrix only with evidence
   from the ratified form.

Runtime evaluation, adapters, FFI, persistence mutation, repair dispatch, and
S7001 remain separate future gates.

## Evidence sources

| Source | Role | SHA-256 |
|---|---|---|
| `G:/AEGIS_STELLAR_SCRIPT/AEGIS_NEW_STELLAR_SCRIPT.md` | Relational-flow concept and explicit draft-syntax boundary | `ED048585E5073106E33AC368464FA41E7E3AB0613815992EB3390819417E1E0C` |
| `G:/AEGIS_STELLAR_SCRIPT/THE_ANNEX_SYSTEM.md` | Orb/Tether/continuity semantics; no flow grammar | `A43DBEAD497F6CA2049FA59E2B72E337C0F1CFE4A7961ABA7D9578C3A07F8C9C` |
| `G:/AEGIS_STELLAR_SCRIPT/NEW_STELLAR_FONT_DEFINITIONS.md` | Glyph-level drift/capture and execution-posture metadata | `A459E677DD93BF9A907215256CEED047D7D56E77017C222E8EC63C577C980644` |

