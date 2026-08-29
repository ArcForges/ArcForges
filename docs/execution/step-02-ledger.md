# Step 02 — Contracts & Code Generation — execution ledger

Authority: `ArchitectureDesign/ArcForgesReWrite-AllCsharp - Paddle/02-contracts-and-code-generation.md`.
This ledger is the durable resume state for Step 02. Where it disagrees with a pull-request body or a
completion claim, Git objects and test artifacts win.

## Status

**Step 02 is OPEN.** Substep 02.00 is complete; 02.01 through 02.06 have not started.

Step 01 closed before this began. Every Required Input 02.00 names was verified present on `main` at
`6e3bc0f`: the seven contract shells, the `InternalsVisibleTo` grant to four test assemblies, the AOT and
trim analyzers, `eng/build/rpc-attach.props`, ARC-005/007/008/009 as real enforcement, the
`architecture-tests` and `locked-restore` job names, and the `docs/deviations.md` ruling that
`ArcForges.Contracts.Foundation` is the single serialized-ID owner.

## Owning substeps

| Substep | State | Evidence |
|---|---|---|
| 02.00 Contracts.Foundation stable primitives + dual source-generation context | Complete | 14 identity types, `Revision`/`Sequence`, `ArcError`/`ArcResult`, `ResourceRef`/`ArtifactRef`/`LocalResourceLocator`, the closed `ArtifactProvenance` union, paging, four wire enums, and both `JsonSerializerContext` types. 14 golden samples; 180 contract tests across the two contract test projects; purity asserted from emitted metadata as well as the declared graph |
| 02.01 Contracts.LocalRpc StreamJsonRpc interfaces | Not started | — |
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

## Exact next action

Step 02.01 — `Contracts.LocalRpc` StreamJsonRpc interface contracts — on its own branch and worktree. It
consumes the primitives this substep froze and must settle the `ResourceRef`/`ResourceRefDto` naming before
it declares its DTOs.
