# Stellar Relational Flow Contract v0.1

**Status:** Ratified declaration-only contract.

Relational flow describes a bounded graph of declared Elements, Orbs,
Field Layers, and Tethers. Nodes are linked by ordered, named edges. Conditions
use only `eq`, `drift`, `capture`, and `witness`; numeric values are bounded to
`[0,1]`, and witness values are boolean. Edge order is unique and ascending.

v0.1 graphs are acyclic so review, ordering, and closure remain deterministic.
Shortfall and Gap-Pause identifiers provide passive continuity context; they do
not dispatch, authorize, or execute anything. Totems remain communication and
illumination records only.

The contract has empty effects and capabilities, append-only persistence, and
`executionEnabled:false`. FFI, adapters, I/O, GUI, network, child processes,
repair dispatch, runtime evaluation, and S7001 remain separate closed gates.
