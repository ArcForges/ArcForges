# Traceability Seed & Feature/Coverage Bridge Contract

> Seeds the traceability chain that will run end-to-end across 00–31. The authoritative big table lives in
> `ArcForgesReWrite-AllCsharp - Paddle\traceability-matrix.md` (plan, read-only). This doc records the seeding
> rules and the machine-readable bridge contract that Step-00 makes authoritative, so every later PR links each
> feature through a unique primary requirement owner and at least one owning step, without hand-copying feature
> counts into Markdown.

## 1. Requirement summary (TR-*) seeding

- `TR-*` IDs are stable requirement summaries in `traceability-matrix.md` §2 grouped by domain
  (`ARC,IPC,PERSIST,SEC,QUAL,CHAT,NOTE,SCOPE,SLATE,CLOUD,MOB`). A TR row is a requirement owner, **not** a
  replacement for the Feature/Coverage foreign keys defined below.
- Each `TR-*` has OwningStep (∈ 00–31), a test, and a Final-Gate (FG.N) so the human-readable summary and the
  machine bridge stay consistent.

## 2. Machine-readable Feature/Coverage bridge contract

`eng/traceability/generate-feature-trace-bridge` consumes the Feature inventory, Source Coverage register, this
file's TR summaries, the protocol/data registries, the step-heading registry and `final-production-gate.md`, and
emits exactly one bridge:

```text
docs/evidence/traceability/feature-trace-bridge.json   (planning seed)
artifacts/evidence/traceability/feature-trace-bridge.json  (implementation/release evidence)
```

Every record is fixed-shape:

```json
{
  "traceId": "...",
  "featureIds": [],
  "coverageIds": [],
  "requirementId": null,
  "arcForgesRequirementId": null,
  "targetProduct": "",
  "targetProjects": [],
  "targetTypes": [],
  "contractIds": [],
  "dataIds": [],
  "uiSurfaceIds": [],
  "owningSteps": [],
  "testIds": [],
  "gateIds": [],
  "sourceBaselines": [],
  "closureStatus": "BridgeGenerationRequired",
  "missingFields": [],
  "evidenceHash": ""
}
```

`closureStatus` allowed values (matching `traceability-matrix.md` §0.1):

- `Closed` — all foreign keys exist and are non-empty or a stable `NotApplicable(reasonCode)`; no associated
  Feature/Coverage is `NeedsRecheck`; same-release test and gate evidence exist.
- `NeedsRecheck` — any associated Feature/Coverage is `NeedsRecheck`.
- `MissingFeatureBridge` / `MissingTarget` / `MissingContractOrData` / `MissingUiOrReason` / `MissingTest` /
  `MissingGate` — the indicated gap; never `—`.
- `Dropped` — all associated Features are Drop with a negative TestId/GateId.
- `BridgeGenerationRequired` — the **initial, honest state** for Step 00: the planning documents are decided but
  no implementation/gate/test evidence exists yet. It is a blocker, never silently flipped to `Closed`.

Gate: `bridge.featureIds` must equal the current unique `AF-F-*` set; `bridge.coverageIds` must equal the
Coverage register's expandable set; both foreign-key bidirectional diffs must be empty. `NeedsRecheck` /
`Missing*` remain blocking; a successful generation run does NOT auto-`Closed` them.

## 3. Primary-requirement-owner rule

Each non-`Drop` Feature enters **at least one** TR, and has a **unique primary** requirement owner
(`requirementId`). A Feature may appear in several TR rows but must pick exactly one `arcForgesRequirementId`.
The generator assigns this deterministically from the mapping; no Markdown copy is required.

## 4. Generator contract (Step 00 scaffold)

`eng/traceability/generate-feature-trace-bridge.ps1`:

- Reads `feature-inventory-and-mapping.md` (plan) for the unique `AF-F-*` set and their
  TargetProduct/OwningStep/Oracle; reads `source-coverage-register.md` (plan) for `SC-*` coverage IDs; reads
  `traceability-matrix.md` (plan) for TR summaries and their OwningStep/Test/FG.
- Emits one record per TR (or per seeded requirement), populating `featureIds[]`/`coverageIds[]` from the
  registries when resolvable and otherwise leaving them empty with `missingFields` + `closureStatus`.
- Write path for the Step-00 planning seed = `docs/evidence/traceability/feature-trace-bridge.json`; the
  production path documented above is used by implementation runs.
- Deterministic, read-only against sources; never fabricates foreign keys or sets `Closed`.