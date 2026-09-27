# Current repository reconciliation

The [WP01.00 Design profile](https://github.com/ArcForges/ArcForges-Design/blob/33bcddd9508ec60c0a2b0d7b53901ee7f50d0a70/docs/assurance/wp01-00-inventory-policy.md) governs `eng/policy/reconciliation/`.

- `source.json` binds the Design authority, WP00 candidate receipt and historical tree.
- `current.json` records nine clean primary commits, their worktrees, 75 build projects and exact published candidate identities. Worktree observations are historical local state, not instructions to read adjacent sources during a build.
- `historical.json` gives all 166 ede43db C# projects an owner, target, reason and disposition, including already absent projects. Absence never means the feature is complete.
- `directories.json` assigns current and planned directories to one repository and scheduled producer. Keep can mean required future content; no empty placeholder is authorized.
- `native.json` keeps historical native admission decisions separate from project counts.

Run `python -m unittest discover -s eng -p test_reconciliation.py -v`, then `python eng/reconciliation.py`. CI checks Windows and Linux before packing. The default run fetches eight immutable owner snapshots plus pinned Design, audits this DesktopPlatform checkout, and verifies all historical/current paths and recorded candidate identities. It does not build adjacent source or call a provider. A fresh read-only family audit accepts all nine `--repository Owner=absolute-root` arguments and an optional local `--design-root`; its report states actual commits, cleanliness and whether each snapshot is current.

The WP00 receipt supplies the already verified public NuGet/npm/Maven/native/desktop/Web/Android/Cloud/AI evidence. The checker validates its exact hash and source identities, not current registry availability or new runtime behavior. Changes to the inventory require review against actual Git trees and the producing step; do not edit a count to hide a missing entry. The existing runtime, licence and provenance checks remain required. Full contract assignment, shared content review, native surface work, test-family mapping and physical moves remain WP01.01 through WP01.05.

Reviewed implementation changes to an existing DesktopPlatform project use `project-updates.json`: retain the original snapshot blob, record the exact reviewed replacement blob, producing step and merged Design authority. The checker still verifies every original snapshot and rejects other project content drift, new/missing projects and source escapes. WP01.03 records only the NativeAbiTests oracle relocation.

WP02.04 records the reviewed native CMake changes for build-identity generation and explicit target
dependencies, under Design commit `257f77ce8d476a4efd8746fc0b7e4e6358c32a67`. Original snapshots and
all unrelated project blobs remain checked.

## Reduced-family adoption (GOV.18)

`current.json`, `native.json`, `directories.json` and the original source identities are historical accepted snapshot evidence, filtered to retained repository owners for audit. They do not authorize restoring deleted families. `eng/policy/reconciliation/active-projects.json` is the reviewed current DesktopPlatform path/blob allowlist; each producer appends or updates only its own project inputs in coordination with licence/runtime inventories. CI still checks historical receipt/tree identities, while current DesktopPlatform checks compare every actual project against the active inventory and reject retired native roots. Published historical candidate identities are never rewritten to describe unpublished source.
