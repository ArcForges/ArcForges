<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# ArcForges.Tests.ContractCompatibilityTests

Holds the assertions that need to reach *inside* a contract assembly. It is one of the four projects
`eng/build/contracts.props` grants `InternalsVisibleTo`, so it can use the source-generated
`JsonSerializerContext` types, which are `internal` by design.

Owned by Step 02 and grown by each of its substeps. Step 02.00 contributes the Foundation layer:

- **Golden round-trip** — every wire type serialises to its committed bytes under `golden/foundation/v1/`,
  deserialises back structurally equal, and re-serialises identically. Fixtures are entirely literal, with no
  generated GUID or clock reading, because a golden sample that is not reproducible is not a golden sample.
- **Source-generation coverage** — every public wire type has generated metadata in *both* contexts. This is
  the assertion that keeps "no reflection serialisation anywhere" true rather than aspirational, and by the
  standing decision it lives here rather than in `ContractSchemaTests`, which has no grant.
- **Evolution behaviour** — what the strict and inbound contexts do differently, and where tolerance stops.
- **Validation** — the cross-property invariants a reference must satisfy, each with its violating twin.
- **Identity wire format** — identities are bare scalars, never wrapper objects.

`golden/foundation/v1/` also sits here so it is beside the baseline contract packages Step 02.05 adds at
`baselines/<contract-set-version>/`. `ArcForges.Tests.ContractSchemaTests` reads the same files from the
outside and asserts their shape without touching the C# types.
