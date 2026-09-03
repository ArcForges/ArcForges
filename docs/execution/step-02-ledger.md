# Step 02 — Contracts & Code Generation — execution ledger

Authority: `ArchitectureDesign/ArcForgesReWrite-AllCsharp - Paddle/02-contracts-and-code-generation.md`.
This ledger is the durable resume state for Step 02. Where it disagrees with a pull-request body or a
completion claim, Git objects and test artifacts win.

## Status

**Step 02 is OPEN.** Substeps 02.00 and 02.01 are complete; 02.02 through 02.06 have not started.

Step 01 closed before this began. Every Required Input 02.00 names was verified present on `main` at
`6e3bc0f`: the seven contract shells, the `InternalsVisibleTo` grant to four test assemblies, the AOT and
trim analyzers, `eng/build/rpc-attach.props`, ARC-005/007/008/009 as real enforcement, the
`architecture-tests` and `locked-restore` job names, and the `docs/deviations.md` ruling that
`ArcForges.Contracts.Foundation` is the single serialized-ID owner.

## Owning substeps

| Substep | State | Evidence |
|---|---|---|
| 02.00 Contracts.Foundation stable primitives + dual source-generation context | Complete | 14 identity types, `Revision`/`Sequence`, `ArcError`/`ArcResult`, `ResourceRef`/`ArtifactRef`/`LocalResourceLocator`, the closed `ArtifactProvenance` union, paging, four wire enums, and both `JsonSerializerContext` types. 14 golden samples; 180 contract tests across the two contract test projects; purity asserted from emitted metadata as well as the declared graph |
| 02.01 Contracts.LocalRpc StreamJsonRpc interfaces | Complete | 96 RPC methods across 4 interfaces (ILocalHubControlRpc, IArcNotesRpcV1, IArcScopeRpcV1, IArcSlateRpcV1), IArcForgesProviderProxyGroup composite proxy, typed connection notices, dual STJ context (LocalRpcJsonContext, LocalRpcInboundJsonContext), PolyType shape witness, canonical contracts manifest (contracts/localrpc/v1/localrpc-contracts.v1.json), 18 golden JSON samples, 162 passing contract compatibility tests, 75 passing contract schema tests, 48 passing architecture tests |
| 02.02 Contracts.PublicApi Refit generated-only | Not started | — |
| 02.03 Contracts.Realtime SignalR | Not started | — |
| 02.04 Agent / Remote Tool Bridge / Sync shared contracts | Not started | — |
| 02.05 Compatibility baseline | Not started | — |
| 02.06 Error model and Security Reason Codes | Not started | — |

## 02.00 completion gate

> Stable primitives and STJ context coverage complete; JSON goldens, unknown/additive, illegal reference and
> unregistered-type tests all carry positive and negative evidence.

| Requirement | Verdict |
|---|---|
| Stable primitives complete | **Met** — `ProductId` plus the 13 GUID identities the substep enumerates, `Revision`, `Sequence`, `ArcError`, `ArcResult`/`ArcResult<T>`, `ResourceRef`, `ArtifactRef`, `LocalResourceLocator`, `ArtifactProvenance` (4 branches), `LocalPageQuery`, `LocalPage<T>`, `CursorPageDto<T>`, `ResourceAvailability`, `ResourceSensitivity`, `PreviewAvailability`, `ErrorCategory`, `WellKnownProducts` |
| STJ context coverage complete | **Met** — `FoundationJsonContext` (strict) and `FoundationInboundJsonContext` (additive-tolerant); every public wire type has generated metadata in both, asserted per type |
| JSON goldens, positive and negative | **Met** — 14 committed samples; byte equality, structural round-trip and repeatability asserted; tampering one byte fails the gate (drill recorded) |
| unknown / additive, positive and negative | **Met** — the inbound context ignores an unknown field, the strict context refuses it; duplicate key, mis-cased name, explicit null, missing required member, unknown enum, numeric enum, unknown union discriminator and unknown product identity are each refused by both |
| illegal reference, positive and negative | **Met** — every locator/availability combination has a passing and a failing case; content hash, owner product, size and blank text likewise |
| unregistered type, positive and negative | **Met** — coverage asserted per type; `UnregisteredProbe` is permanent counter-evidence, and the gate genuinely caught `ErrorCategory` during development |

## Decisions taken in this substep

**The source-generation coverage assertion lives in `ArcForges.Tests.ContractCompatibilityTests`.**
`ContractSchemaTests` stays scoped to generated schema and golden-file validation and receives no
`InternalsVisibleTo` grant; the grantee set stays at four. This was the open question Step 01 recorded and is
now settled. It works cleanly because the two projects check genuinely different things: one round-trips
through the internal contexts, the other reads the same committed files as documents and would still catch a
shape change that the C# side had been updated to match.

**`PendingResourceRef` was not created.** The plan names it once, in a sentence explaining what to use
instead of a hash-less `ResourceRef`, and defines no fields for it anywhere. The enforceable half of that
rule — a `ResourceRef` cannot exist without a real lower-case hex SHA-256 — is implemented and tested from
both directions. Inventing a wire shape for the other half would freeze a guess. See the design conflicts
below.

**Enum wire spellings are lower-case snake_case**, derived from the plan's own literals rather than chosen:
Step 13 writes `availability=local_online|local_offline` verbatim, and the data catalog uses the same
convention throughout (`capability_call`, `deletion_pending`). The provenance discriminator property is
`kind`, which the data catalog fixes as `provenance.kind`.

## Findings

1. **`Revision` and `Sequence` were serialising as objects.** The first generated goldens read
   `"revision":{"value":7,"exists":true}` — the wrong wire shape, and a derived property leaked into the
   contract. Both now carry transparent converters and travel as bare numbers, which is what every store
   holding a revision already assumes. Found by reading the generated bytes, not by a test.
2. **`ErrorCategory` had no generated metadata.** It is declared by this substep but nothing references it
   yet, so the generator emitted nothing for it. The coverage gate caught it on its first run; it is now
   registered explicitly so it is serialisable the moment Step 02.06 uses it.
3. **A `const` reference emits no assembly reference.** While drilling the purity assertion, a probe that
   read `AssemblyPlaceholder.Name` (a `const`) did not fail it, because the compiler inlines constants. The
   drill was redone with a `typeof`, which does emit a reference, and both purity gates then fired. This is
   recorded because it is exactly why the declared-graph rule is the primary gate and the emitted-reference
   check only complements it.

## Design conflicts requiring a planning writeback

| Conflict | Detail |
|---|---|
| The substep is titled "dual source-generation context" but sketches one | The title and the `.NET 10 strict baseline` testing requirement both call for two contexts — a strict one and a public/inbound one — while the body sketches only `FoundationJsonContext` and defers "the two option semantics" to a later substep. Implemented as `FoundationJsonContext` (`UnmappedMemberHandling.Disallow`) and `FoundationInboundJsonContext` (`Skip`), identical in every other option. The plan should name the second context. |
| `PendingResourceRef` is named but never defined | No field list exists anywhere in the plan. Not created here. The substep that first needs to describe a resource whose digest is not yet known should define it, or the plan should drop the name. |
| `ResourceRef` versus `ResourceRefDto` | Step 02.00 and architecture §5.2 call the type `ResourceRef`; the data catalog and Step 02.01's LocalRpc sketches call the same wire shape `ResourceRefDto`. This assembly uses `ResourceRef`. Step 02.01 has to settle whether the `Dto` suffix is a second name for one type or a separate projection. |
| Layout §3 root namespace for `ArcForges.Contracts.Foundation` | Still open from Step 01. §3's table assigns the namespace `ArcForges.Contracts`; the project and this substep's body both use `ArcForges.Contracts.Foundation`, which is what is implemented. |

## Build-system change carried on this branch, 2026-08-30

Not part of the 02.00 completion gate and not a substep. A user instruction on 2026-08-30 asked for the
Ninja/`sccache` build split to land on the existing branch, so it is a **separate commit** on
`feat/af02-00-contracts-foundation` and updates PR #32 rather than opening a second pull request. It touches
no contract source, so the 02.00 verdicts above stand unchanged.

What changed:

- Every CMake preset is Ninja and is named for the RID it produces (`win-x64-runtime-shared`,
  `linux-x64-shim-static-asan`, ...), so configure, build and test share one preset name. The Visual Studio
  generators and all VS-only preset settings are gone.
- Both platforms compile through `sccache` (`CMAKE_C_COMPILER_LAUNCHER`/`CMAKE_CXX_COMPILER_LAUNCHER`), pinned
  to 0.17.0 — Scoop on Windows, a SHA-256-verified tarball on Linux — with a real `actions/cache` entry per
  platform. Windows sets `CMAKE_MSVC_DEBUG_INFORMATION_FORMAT` to `Embedded`, without which every MSVC
  compilation is non-cacheable.
- `pr-gate.yml` keeps the Windows CMake/CTest/P-Invoke job and loses the `msbuild win.slnx` and pure-MSBuild
  ABI-test steps. `win.slnx` is now built by the Windows-only `win-slnx-release-x64` `pre-push` hook, which
  skips itself on non-Windows so the Ubuntu repository-hooks job is unaffected. No `win.slnx` CI hook was
  added.
- The standalone managed `build` job was removed from `pr-gate.yml`; Debug is not a required PR gate.
  `unit-tests` and `integration-tests` retain their Release build immediately before `--no-build`, and the
  aggregate `ci` job no longer lists the removed job.

Evidence is in [`docs/coverage/ci-evidence.md`](../coverage/ci-evidence.md) under *Step 02.00 — Ninja/sccache
build split*: both Windows presets configure, build, install and pass CTest (1/1 and 4/4); `sccache` goes from
15 misses / 0 hits cold to 15 hits / 0 misses warm with zero non-cacheable compilations; managed P/Invoke
passes over the staged artifacts; and the `pre-push` hook builds all five `.vcxproj` with 0 warnings.

**No Linux host was available.** The `linux-x64-*` presets were validated by parsing and `cmake
--list-presets` only. Their compile, CTest and `sccache` behaviour is asserted by `deep-check.yml` and is not
claimed here. Six deviation rows are recorded in [`docs/deviations.md`](../deviations.md): the preset
renaming, the Ninja generator, the unlocked `sccache` tool, the `win.slnx` move out of CI, the standalone
build-gate removal, and this branch-sharing decision.

## 02.01 completion gate

> Strongly typed StreamJsonRpc interface contracts complete; proxy group interface generated; ARC-007 interface
> purity and ARC-009 proxy metadata asserted; write mutation envelopes complete; absence of NotImplementedException
> verified; dual STJ context and PolyType shape witness registered; 18 JSON goldens committed and asserted.

| Requirement | Verdict |
|---|---|
| StreamJsonRpc interface contracts complete | **Met** — 96 RPC methods across 4 interfaces (`ILocalHubControlRpc` 7 methods + 2 events, `IArcNotesRpcV1` 23 methods, `IArcScopeRpcV1` 27 methods, `IArcSlateRpcV1` 39 methods). All interfaces decorated with `[JsonRpcContract]`, `[GenerateShape(IncludeMethods = MethodShapeFlags.PublicInstance)]`, `partial`, and inherit `IDisposable` |
| Composite proxy group | **Met** — `IArcForgesProviderProxyGroup` interface decorated with `[JsonRpcContract]`, `[GenerateShape]`, and `[JsonRpcProxyInterfaceGroup(typeof(IArcNotesRpcV1), typeof(IArcScopeRpcV1), typeof(IArcSlateRpcV1))]` |
| Assembly proxy export & ARC-009 | **Met** — `[assembly: ExportRpcContractProxies]` in `Properties/AssemblyInfo.cs`; ARC-009 asserted by `ArchitectureTests` and `ContractCompatibilityTests` (with counter-evidence) |
| Interface shape purity & ARC-007 | **Met** — No properties on contracts, no generic methods, no method overloads, return types `Task<ArcResult<T>>` or `ValueTask`/`ValueTask<T>`, last parameter `CancellationToken`, events `EventHandler<T>`, zero banned types (`object`, `dynamic`, `Type`, `JsonElement`, `Dictionary<*, object>`); counter-evidence tests pass |
| Write mutation envelope & `ExpectedRevision` | **Met** — Every write mutation request on product interfaces carries `CommandId`, `Actor` (`ActorContextDto`), `TargetResource` (`ResourceRef`), `ExpectedRevision` (`long`), `IssuedAtUtc`, `DeadlineUtc`, `CorrelationId`; counter-evidence tests pass |
| Absence of `NotImplementedException` | **Met** — Zero occurrences of `NotImplementedException` in `src/Contracts/ArcForges.Contracts.LocalRpc/` |
| Dual STJ context and PolyType witness | **Met** — `LocalRpcJsonContext` (strict, Disallow unmapped members) and `LocalRpcInboundJsonContext` (tolerant, Skip unmapped members); `LocalRpcShapeWitness` PolyType shape witness for reflection-free formatting |
| LocalRpc JSON goldens & schema validation | **Met** — 18 committed golden JSON samples under `tests/ContractCompatibilityTests/golden/localrpc/v1/`; byte equality, structural round-trip and repeatability asserted; independent schema parsing without internals access verified in `ArcForges.Tests.ContractSchemaTests` |
| Canonical contract catalog manifest | **Met** — Committed at `contracts/localrpc/v1/localrpc-contracts.v1.json` cataloging all 96 methods, capabilities, risk levels (R0-R4), and operation flags matching `protocol-contract-catalog.md` §3.4 |

## Decisions taken in 02.01

**`ResourceRef` versus `ResourceRefDto` is settled.**
`ArcForges.Contracts.Foundation.ResourceRef` is used directly across all LocalRpc contracts and DTOs.
Creating a duplicate `ResourceRefDto` with identical fields would fragment type identity and require redundant
mapping layers.

**`IArcForgesProviderProxyGroup` is declared as an `interface`.**
`StreamJsonRpc.JsonRpcProxyInterfaceGroupAttribute` enforces `AttributeTargets.Interface` at compile time.
The design sketch in `02-contracts-and-code-generation.md` illustrated a class; declaring an interface extending
the three product interfaces satisfies both StreamJsonRpc Roslyn analyzers and compile-time proxy generation.

**`NEVER` compilation symbol defined in `ArcForges.Contracts.LocalRpc.csproj`.**
PolyType's `GenerateShapeAttribute` carries `[Conditional("NEVER")]`, causing Roslyn to omit the attribute from
IL metadata by default. Defining `NEVER` in the csproj ensures the attribute is emitted into assembly metadata,
satisfying `ArchitectureRules.Arc009` and reflection assertions.

## Exact next action

Step 02.02 — `Contracts.PublicApi` Refit generated-only contracts on branch `feat/af02-02-contracts-publicapi`.

