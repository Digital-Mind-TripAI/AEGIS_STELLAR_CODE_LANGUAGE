# Stellar Native Relational Flow Evidence v0.1

The ratified `flow` declaration is admitted by the native parser as a passive,
declaration-only graph. Nodes and edges are bounded, uniquely identified, and
resolved within the flow; edge order is unique and the graph is acyclic.

The focused acceptance test runs the same source twice and compares the complete
inspect output byte-for-byte. It verifies `executionEnabled:false`, empty
effects/capabilities, passive trace evidence, and deterministic refusal of graph
cycles, duplicate edge order, and unresolved endpoints.

Runtime graph evaluation, FFI, adapters, I/O, GUI, network, repair dispatch, and
S7001 remain closed gates.
