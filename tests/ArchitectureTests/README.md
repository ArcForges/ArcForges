<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# ArcForges.Tests.ArchitectureTests

Machine enforcement for `implementation-repository-layout.md` §11 and `architecture-and-communications.md`
§14. Owned by Step 01.04; every later step's completion gate may reference a rule by its `ARC-0XX` number.

## Two engines

Reference-direction rules run over [`ProjectGraph`](ProjectGraph.cs), the **transitive closure** of the
declared `ProjectReference`/`PackageReference` edges under `src/`. Emitted assembly metadata is not a sound
source for these: the compiler prunes references a project declares but never uses, so a project can
reference a database provider and still emit no reference to it. The graph also makes an *indirect*
forbidden edge fail — `ARC001DomainHasNoExternalDependenciesTests.AnIndirectForbiddenEdgeAlsoFailsAndNamesThePath`
is the regression for that, and failures name the whole carrying path.

Rules about what a type may touch run over the loaded assemblies with `NetArchTest.Rules`, which layout §12
pins as the only architecture-test framework for V1. Three rules cannot use it and say why in their own
doc comments: ARC-007 (member signatures) and ARC-009 (assembly attributes) reflect; ARC-010 and ARC-011
read metadata tables directly, because a violating type is often in the global namespace or shares an
assembly identity with a real one, and NetArchTest reaches neither.

Two behaviours of `NetArchTest.Rules 1.3.2` are load-bearing here and were established empirically:

- it materialises Cecil definitions into runtime `Type`s and **silently drops** the ones the CLR cannot
  resolve, so a rule run over an unloaded file reports success having analysed nothing. Assemblies are
  therefore loaded, and `ArchitectureSurfaceTests` fails if the analysed surface is implausibly small;
- its dependency search does not match a term ending in `.`; `"Android"` matches, `"Android."` never does.

## Fixtures

One pair per rule in [`Fixtures/`](Fixtures): `ARC0XXValid.cs` is a compliant sample that participates in
this project's compilation, and `ARC0XXViolation.cs.txt` is stored as text so it never does. Graph-rule
fixtures hold synthetic `.csproj` shapes, optionally several per file separated by `<!-- file: Name.csproj -->`;
type-rule fixtures hold C# that [`FixtureCompiler`](FixtureCompiler.cs) compiles at test time through the
.NET SDK into a throwaway assembly outside the repository. Each rule asserts both directions: production
satisfies it, and the violation fixture fails it with a message carrying the rule ID and the offending path.
