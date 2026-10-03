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

## What was run (Windows 11 Pro for Workstations build 26300, pinned .NET SDK 10.0.400)

- Locked-mode restore, format verification and Release build of the probe: 0 warnings, 0 errors. Policy checks (dependency,
  reconciliation, provenance, runtime ownership, licence, design) and their tests passed. The architecture tests passed 99 of
  100 locally; the one failure is AT-09, the missing native-evidence artifact that only CI supplies. Hosted CI at the reviewed
  head passed 17 of 17 checks, including both `grpc-web-aot` compile jobs.
- `dotnet publish -c Release -r win-x64` (Native AOT, IL2026 and IL3050 as errors): no warning or error output; the
  executable of the final source is about 8.4 MB. `GrpcWebAotProbe.exe --self-test` as the published Native AOT executable
  exits 0 (the process reports PASS only when every check passed). It is a test of the probe, not of any ingress.
- Live runs of the published Native AOT executable against the existing production Hello Worker/Container ingress
  `https://arcforges.com/api`, reached without any credential. It is **not** the PRF.07 `env.proof` ingress.
  - Run 1, 2026-10-02T22:05:20Z, lease `RES-cloud-deployment` 22:04:47Z to 22:05:35Z, executable built from commit
    `ad21244` (an earlier state of this branch; the cancellation checks of that build had the weaker meaning corrected below).
    23 checks passed. Evidence file sha256 `44be6aed6997f4e67d586236475c98d45c02d71eb8f5d6160f37ad07bb4244ed`.
  - Run 2, 2026-10-03T09:20:46Z to 09:20:59Z, lease 09:09:26Z to its release after the run, executable built from the code
    of commit `856163db` (the later commits only change documentation). `--expect-revision` was passed with the
    revision run 1 had observed. 26 checks passed. Evidence file sha256
    `82eace9de45ddea90eabc3a631f675080224d7e8634c521d834f77f767c09a2d`. The evidence files are not committed (they live in the
    ignored `artifacts/prf-05` folder of the claimant's worktree); the hashes and the check table are carried by the ledger record.
  - Both runs: the health endpoint reported Native AOT and the revision of the Cloud merge commit of PR 31 (`1a001eae...`), and
    the worker revision response header matched it. Only 21 of the 26 checks describe the ingress (identity 2, unary 4, exact
    3, error 4, cancel 5, deadline 2, unknown method 1); `local.closed-port-unavailable` talks only to a closed loopback port
    and the four `codec.*` checks run in process. The negotiated HTTP version of the production calls was not recorded.
- What the cancellation checks observe: `cancel.at-handoff` cancels as the request is handed to the transport. The real
  socket handler then refuses it before writing anything, so this is client-side cancellation and no server saw that request
  (an independent review confirmed this on a loopback listener). `cancel.after-response-headers` cancels after the ingress
  has answered (HTTP 200 with the worker revision header), so the ingress had the request; the caller sees CANCELLED.
  A cancellation observed by a server is not checked.
- Source mutation of the probe (build slot): of the first 53, 49 were caught by the self-test, 3 survived (the closed-port
  status, and two loss-count conditions that the status checks already cover) and 1 did not build (as reconstructed from the
  retained logs). After the review, 12 more: 7 caught, 4 survived (a dropped no-response condition that a pre-cancel mutant
  does catch while the check is intact, two conditions that other conditions in the same check already cover, and a proxy
  setting with no proxy on the machine) and 1 did not build. The self-test does not discriminate `RuntimeIdentity.IsNativeAot`
  (the JIT refusal of `--live` was run by hand: exit 2, nothing contacted) or the status code of `deadline.expired`.

## Not observed

- Linux and macOS: the Linux executable is only compiled in hosted CI; no Linux or macOS process was run. Other RIDs.
- Any deployed ingress other than the production Hello route; any exact int64, uint64 or decimal value sent over a wire to an
  ingress (the Hello service carries strings only; the `codec.*` checks are in process); scope, permission, session expiry;
  server-side observation of a cancellation; induced loss and boundary failures on a real ingress (they run only against the
  fixture); a stale target on a live ingress (`--expect-revision` passed with the matching revision only); native UI cases.
