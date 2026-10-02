# PRF.05 generated gRPC-Web Native AOT probe: bindings and observed evidence

This record states only what was observed by the PRF.05 claimant `w-c20261002-prf05` (claim epoch 1) on 2026-10-02.
It claims nothing about the PRF.07 `env.proof` ingress, which does not exist, and the live run below is not a result
for it.

## Supporting bindings (Design ADP-07), declared in the claim handoff before editing

All paths are inside the task write scope. DesktopPlatform has no dedicated provenance or source-inventory resource, so
the policy, test and provenance rows use `RES-desktopplatform-policy-data` (append) and the solution, central package
and workflow entries use `RES-desktopplatform-build-config` (append).

- `DesktopPlatform.slnx`: one folder with the project `tests/ReleaseArtifactTests/GrpcWeb/GrpcWebAotProbe.csproj`.
- `Directory.Packages.props`: one appended pin, `Grpc.Net.Client.Web` 2.84.0 (shared with PRF.06). No existing pin changes.
- `tests/ReleaseArtifactTests/GrpcWeb/Directory.Packages.props`: imports the root file and selects the already-admitted
  `ArcForges.Contracts.PublicApi` and `ArcForges.Contracts.Foundation` `1.0.0-ci.216.1` for this project only (the pattern
  of the PRF.09 probe). The generated `HelloService` client is in that published candidate.
- `tests/ReleaseArtifactTests/GrpcWeb/packages.lock.json`: the locked graph. Against main it adds exactly one coordinate,
  `Grpc.Net.Client.Web` 2.84.0, which has no net10.0 dependency.
- `.github/workflows/package-validation.yml`: job `grpc-web-aot` (linux-x64 and win-x64), locked restore and
  `dotnet publish` only. It never runs the executable and contacts no endpoint.
- `eng/policy/dependency-policy.json` and the new immutable `eng/policy/dependency-reviews/prf-05-r1.json`, produced by
  `eng/verification/create_prf05_dependency_receipt.py` (chained from the receipt that is active on main at the time of the
  run; rerun it after every rebase): input hashes, the one new coordinate and the corrected classification text of the
  PublicApi row, which now has a direct reference.
- `eng/policy/licence-boundary.json` (`msbuild`), `eng/policy/runtime-ownership.json` (`test-or-build-tool`),
  `eng/policy/architecture-projects.json` (`Test`, owner DesktopPlatform, empty module, production false, aot false) and
  `eng/policy/reconciliation/active-projects.json` (the exact blob): one appended row for the probe project each.
- `eng/provenance/files.json`: `firstParty` rows for the task-owned files only.

No `.gitleaks.toml`, Contracts, Cloud or other dependency change was made.

## What was run (Windows 11 Pro for Workstations build 26300, pinned .NET SDK 10.0.400, through the build slot)

- Locked-mode-compatible restore and Release build of the probe: 0 warnings, 0 errors.
- `dotnet publish -c Release -r win-x64` (Native AOT, IL2026 and IL3050 as errors): no warning or error output; the
  executable of the final source is 8,439,296 bytes.
- `GrpcWebAotProbe.exe --self-test` as the published Native AOT executable: exit code 0 (the process reports PASS only when every check passed), including the verifier
  against 21 fixture and client misbehaviors. This is a test of the probe, not of any ingress.
- One `--live https://arcforges.com/api` run of the published Native AOT executable while holding the lease
  `RES-cloud-deployment` (released immediately afterwards): 23 of 23 checks passed. The health endpoint reported Native AOT
  and the revision of the Cloud merge commit of PR 31 (`1a001eae...`), and the worker revision response header matched it.
  The target is the existing production Hello Worker/Container ingress of the Cloud repository, reached without any
  credential. It is not the PRF.07 proof environment.

## Not observed

- Linux and macOS: the Linux executable is only compiled in hosted CI; no Linux or macOS process was run.
- Any deployed ingress other than the production Hello route; any exact int64, uint64 or decimal value sent over the wire
  to an ingress (the Hello service carries strings only; the `codec.*` checks are in process); scope, permission, session
  expiry, server-side observation of a cancellation, induced loss or boundary failures on a real ingress (those run only
  against the fixture); native UI cases.
