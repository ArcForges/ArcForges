# DesktopPlatform contributor instructions

This repository owns shared desktop mechanisms, C# interop, CMake/vcpkg and capability NuGet production.
The product applications, Cloud, AI, Web, Mobile and business RPC schemas have separate repositories.
The accepted architecture lives in [ArcForges-Design](https://github.com/ArcForges/ArcForges-Design).

- Work on a focused branch in `.worktree/`. Preserve the primary checkout and unrelated repositories.
- Use C# 14 / .NET 10 from `global.json`, C++20 and C17-compatible public C ABI headers.
- Keep native toolchains here. Consumers use exact published package versions and committed lock files;
  never add Git submodules or sibling source dependencies. Business proto generation belongs to Contracts.
- Put dependency versions in `Directory.Packages.props`, restore locked, retain warnings-as-errors and
  AOT/trim diagnostics. Native interop uses owned C ABI / LibraryImport, never a C++ ABI.
- Add SPDX headers to source/configuration; preserve third-party notices and source provenance.
- New projects are non-packable by default. Admit a package explicitly in `eng/packaging/packages.json`
  only when its behavior and dependency closure are verified. Never publish placeholders as capabilities.
- Keep build inputs declarative; executable packaging verification is the portable Python tool under `eng/`.
  Do not add tracked PowerShell or shell helper scripts.
- Record what actually ran. A successful package-policy smoke does not prove native capability AOT,
  product behavior, release signing or NuGet publication. Run the checks documented in the README.

## Delivery model (P2-018)

Work is scheduled as delivery tasks in the [delivery graph](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/planning/delivery/README.md) and executed through the [Plan execution entry](https://github.com/ArcForges/Plan/blob/main/arcforges-implementation.md). The local authorities are `C:\MyFile\Projects\ArcForges-Design` and `C:\MyFile\Projects\Plan`; use `python C:\MyFile\Projects\Plan\tools\delivery.py` for delivery state. There is no Current task, numbered substep order or single main context.

- Baseline: WP00–WP02 are accepted (build governance, dependency admission, lockstep NuGet publication and the design-policy exports). Building blocks are placeholders and native families are probe-level; every platform, native, assistant and updater capability is an open task. This repository's tasks are in the [platform](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/planning/delivery/lanes/platform.md), [native](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/planning/delivery/lanes/native.md), [foundation](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/planning/delivery/lanes/foundation.md), [assistant](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/planning/delivery/lanes/assistant.md), [execution](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/planning/delivery/lanes/execution.md), [updater](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/planning/delivery/lanes/updater.md), [app-composition](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/planning/delivery/lanes/app-composition.md), [device-bridge](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/planning/delivery/lanes/device-bridge.md), [extensions](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/planning/delivery/lanes/extensions.md), [runtime-proofs](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/planning/delivery/lanes/runtime-proofs.md), [governance](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/planning/delivery/lanes/governance.md) lanes and parts of the Cloud-core, policy and release lanes.
- Start only a task that Plan's `python tools/delivery.py ready` lists and whose claim you hold (`python tools/delivery.py claim <TASK-ID> --worker <name>`, recorded as `claims/<key>`, the ID in lower case with dots replaced by hyphens, such as `claims/plt-11`); continue interrupted work from its handoff record (`python tools/delivery.py show <TASK-ID>`) rather than restarting it. A task here becomes ready only after the adoption slice for its lane (`ADOPT.02.<lane>`) is recorded.
- Several workers may work here at once, each on a different claimed task in its own retained worktree and `task/<key>` branch, inside the task's write scope. Each native family adds its own CMake targets, wrapper project and workflow entries, and each managed mechanism its own project, so families and mechanisms proceed in parallel.
- Shared files follow their [declared protocols](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/planning/delivery/shared-resources.md): solution and project lists, `Directory.Packages.props` and CI job lists are appended by the task that adds a project, dependency or job, and lock files are regenerated after rebase, never hand-merged; `eng/packaging/packages.json` gains one entry per producer task and every merge to main publishes all packages at one version; the vcpkg baseline and overlay ports change only through a dependency-admission change; generated policy data is regenerated from its pinned source and the reason-code registry is append-only; assistant store migrations are numbered at merge. The DesktopPlatform integration owner (the holder of `roles/integration-desktopplatform`) orders merges and merges only at the head commit reviewed for the claimant at the current claim epoch, keeping the task IDs in the merge title.
- Title pull requests `[<TASK-ID>] <summary>`; a bundle of compatible ready tasks lists each ID, and planning alignment uses `[P2-018]`.
- The design-policy check still validates the retired package graph at the pinned Design commit. Keep `eng/policy/design-source.json` at a pre-P2-018 Design commit until the cleanup task `GOV.18` replaces that check with delivery-graph validation and re-pins the export; `GOV.14` then performs the broader integrity audit; see [design policy](docs/design-policy.md).
- Earlier `docs/` records named after work packages or substeps describe their original scope; they are evidence, not execution instructions.

## Validation policy (P2-017)

Follow the [current CI/local authority](https://github.com/ArcForges/ArcForges-Design/blob/47db6670a727317939b91245e8c0b288834acf99/docs/assurance/ci-and-local-validation-policy.md).
- Never add or execute macOS CI, native/runtime/package-consumer execution, GUI, browser, device, live-service or published-package installation tests in any CI trigger or nested build script.
- Keep necessary Windows/Linux compilation, packaging, targeted offline unit/static checks and non-duplicated security checks. Runtime diagnostics are explicit local opt-in only for affected behavior using existing tools. Do not silently build/test from commit or push hooks.
- Preserve locks, required signatures, licence/provenance and one identity/integrity check at each real trust handoff. Do not routinely download public artifacts or repeat archive/hash/consumer verification after publication. Narrow FFmpeg licence/configuration and Windows signature inspection remain legal admission checks.
- Do not reinstall vcpkg, SDKs or toolchains to expand validation. Do not create tags or republish solely for verification. Stop on a network failure and report the exact operation; no proxy configuration, port 7890, wsl.exe or WSL wrappers.
- Record removed coverage honestly. Review the complete latest PR and merge only after applicable checks succeed. Post-merge work stops after commit/job/publication status and a clean primary fast-forward; retain branches/worktrees.

## Dependency admission (WP02.05)

- Keep `eng/policy/dependency-policy.json` bound to the complete actual dependency inputs. A dependency or framework change requires a reviewed replacement receipt, closure/licence and maintenance review and every upgrade checklist item. Hash refresh alone is insufficient.
- Preserve existing source/native provenance and public/internal import gates. Stable closures cannot import prerelease dependencies; only recorded exact foundation candidates are permitted in development.
- Framework major upgrades require explicit runtime/AOT/trim and affected Android Kotlin/JVM/ART/R8 assessment under VG-08. Record conditional local coverage honestly without adding forbidden CI or provisioning tools.
