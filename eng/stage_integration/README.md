<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Cross-repository stage integration (WP-05.90)

`stage_integration.py` evaluates the published package and dependency metadata of the seven implementation
repositories (DesktopPlatform, Contracts, ArcScope, Cloud, AI, Web, Mobile), one pinned commit each, against
`policy.json`. It reads lock files, package manifests, producer package registries, wrangler configuration and
workflow declarations. It never clones a repository and never reads source code.

| Rule | Assertion |
|---|---|
| SI-01 | every ArcForges-owned coordinate consumed has exactly one registered producer |
| SI-02 | no cross-repository project, source, submodule, link or include-build dependency |
| SI-03 / SI-04 | direct and transitive consumption follows the producer access matrix; every owned package a lock lists is checked, including one reached only through a third-party package (path then unknown); a registry package that is not public needs an audience in `policy.json` (fail closed) |
| SI-05 | no AGPL-produced package in an Apache closure without an owned, unexpired RP-03 exception in the consumer |
| SI-06 | Cloud has no desktop native or UI asset in its closure |
| SI-07 | Mobile imports no AGPL implementation |
| SI-08 | exactly one Harness owner |
| SI-09 | each repository's own policy host runs in a pull-request workflow (no `paths`/`branches`/`types` filter), unconditionally; print-only text does not count and `; true`, `|| echo`, `set +e` suppression is refused |
| SI-10 | the snapshot is complete, pinned, bound to the policy hash and not older than 45 days |
| SI-11 | exception data is owned and unexpired |

- `verify` (the pull-request gate) is offline and deterministic: it evaluates the committed `snapshot.json`.
- `snapshot` (local opt-in, public HTTPS reads of one tree listing and the metadata files per repository) rewrites
  the snapshot for explicit commits. Review the diff like the design-policy pin; refresh it when a repository's
  published metadata changes. `drift` compares the pinned snapshot, or `--current` main heads, with live metadata.
  `observe` lists the hosted CI runs of a commit (provider status only).
- The snapshot is therefore a pin, not a live view: a forbidden edge merged in another repository after the pin is
  found at the next refresh (and by that repository's own host), not by this pull-request gate. The tool states no
  runtime, device or live-service result.
- Negative fixtures in `test_stage_integration.py` build synthetic seven-repository worlds and prove every rule
  fails when violated; they are fixtures, not observations of the real repositories.

## Limits and ownership

- Currency: the snapshot records `collectedOn`; `verify` fails SI-10 once it is older than `freshness.maxAgeDays`
  (45). The owner is the DesktopPlatform integration owner (holder of `roles/integration-desktopplatform`): run
  `snapshot` and review the diff after any merge that changes a repository's published metadata, and at least
  every 45 days. Between refreshes a forbidden edge merged elsewhere is caught by that repository's own host,
  not by this gate. The time bound makes `verify` depend on the calendar by design.
- Integrity: `verify` checks the snapshot's internal consistency (policy hash, coverage, shapes, source digest
  shape); it does not re-read the providers, so edited facts pass offline. `drift` re-reads the pins and finds that.
- SI-02 reads lock files, package manifests and `settings.gradle*` only. It does not read `*.csproj`,
  `build.gradle.kts` or `NuGet.config`; a cross-repository reference declared only there but absent from the
  locks is not seen.
- SI-06 recognises desktop UI and native packages by name pattern (`policy.json` `desktopOnly`, `foreignWatch`)
  and by the producer's `native` kind; an unlisted vendor package is not recognised.
- SI-08 reads every `wrangler.json`, `wrangler.jsonc` and `wrangler.toml` in the tree.
