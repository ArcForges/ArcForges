# PRF.06 realtime Native AOT probe: supporting bindings and what was observed

Task PRF.06 (claim `w-c20261002-prf06`, epoch 1) adds the non-packable probe
`tests/ReleaseArtifactTests/Realtime/RealtimeAotProbe.csproj`. See its `README.md` for what it holds and for what it
does not prove: **no deployed Worker, Container or Durable Object result of any kind exists**, because no task has built a
public `EventService.Watch` or `ExecutionService.WatchOutput` server yet.

## Supporting bindings (Design ADP-07)

Every entry below serves the one artifact above, inside the task's write scope, and each registry is append-only under
`RES-desktopplatform-build-config` or `RES-desktopplatform-policy-data`. The repository's own gates fail closed on an
unregistered project, so none of these is optional.

| Path | Appended | Why it is necessary |
|---|---|---|
| `DesktopPlatform.slnx` | the project in its own folder | the default solution selection must equal the classified inventory |
| `Directory.Packages.props` | `ArcForges.Contracts.Events`, `ArcForges.Contracts.PublicApi` and the `ArcForges.Contracts.Foundation` update at `1.0.0-ci.270.1`, each conditioned on the project name | central, exact versions (RP-05); the `Grpc.Net.Client.Web` pin is reused from PRF.05 and not duplicated; the conditioned pins are the Design write-scope repair of this task |
| `eng/policy/architecture-projects.json` | `Test`, owner DesktopPlatform, no module, not production, not AOT | runtime-owned `.csproj` entries must equal the classified rows |
| `eng/policy/runtime-ownership.json` | `test-or-build-tool` | same inventory invariant |
| `eng/policy/licence-boundary.json` | `msbuild` | the licence audit reads every declared project |
| `eng/policy/reconciliation/active-projects.json` | the exact Git blob of the project file | current project set equals the active manifest |
| `eng/provenance/files.json` | `firstParty` rows for the task-owned files only | every tracked file is classified |
| `eng/policy/dependency-policy.json`, `eng/policy/dependency-reviews/prf-06-r1.json` | input hashes, three new closure rows (`Grpc.Net.Client.Web` 2.84.0 and its row are reused from PRF.05), the active review binding, one immutable successor chained from the active receipt on main | the admission gate binds every dependency input; `eng/verification/create_prf06_dependency_receipt.py` regenerates both after a rebase |
| `.github/workflows/package-validation.yml` | one `realtime-aot` job (locked restore, `dotnet publish`, win-x64 and linux-x64) | the continuous main-branch AOT compile of BR-06; it never executes the binary |

No Gitleaks allowlist, secret-scan behavior, package inventory or `eng/policy/exceptions.json` row was changed.
