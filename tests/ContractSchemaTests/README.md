<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# ArcForges.Tests.ContractSchemaTests

Validates generated schema artifacts and golden files **as documents**. This project deliberately holds no
`InternalsVisibleTo` grant into the contract assemblies, so it cannot reach a source-generated context and
cannot round-trip anything through the C# types.

That constraint is the point. These assertions read the committed JSON with `JsonDocument` and describe the
wire the way a consumer written in another language would see it: field sets, frozen enum spellings, bare
scalar identities, numeric revisions, and the negative rules — no absolute path, no inline bytes, no
`hasMore` on the public page shape. A refactor that changed the shape and updated the C# round-trip in the
same breath would still be caught here.

Round-trip, source-generation coverage and evolution behaviour belong to
`ArcForges.Tests.ContractCompatibilityTests`, which is one of the four granted assemblies. Generated JSON
Schema and OpenAPI diffing arrive with Step 02.04/02.05 and land here.
