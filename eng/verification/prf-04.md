# PRF.04 Windows Native AOT runtime evidence

## Project inventory supporting binding

Claim `af-20260928-p02`, PRF.04 claim epoch 1. A pre-PR policy check (`python eng/reconciliation.py`) first failed with `current project set drift: DesktopPlatform` because this task's new test project was not in the active project manifest; after that manifest entry was added, it exposed a matching project-classification drift. Under the narrowly approved ADP-07 supporting binding, these exact task-owned entries were appended:

- `eng/policy/reconciliation/active-projects.json`: `{ "path": "tests/LocalRpcAotTests/LocalRpcAotTests.csproj", "blob": "a73b6437ccd042ad624b324e0324ada56f2f223a" }` — registers the current project blob so active inventory matches this task's solution.
- `eng/policy/licence-boundary.json`: `{ "path": "tests/LocalRpcAotTests/LocalRpcAotTests.csproj", "kind": "msbuild" }` — declares the existing AGPL-owned test project to the source/license audit.
- `eng/policy/runtime-ownership.json`: `{ "path": "tests/LocalRpcAotTests/LocalRpcAotTests.csproj", "role": "test-or-build-tool" }` — classifies the probe as non-production test/build tooling, not a product runtime.
- `eng/policy/architecture-projects.json`: `{ "path": "tests/LocalRpcAotTests/LocalRpcAotTests.csproj", "role": "Test", "owner": "DesktopPlatform", "module": "", "production": false, "aot": false }` — classifies the project as a non-production test project; its separate executable's AOT proof does not claim that this test project is a production AOT artifact.

The project file explicitly declares its existing AGPL-3.0-only licence and AGPL boundary, matching repository policy. `eng/policy/reconciliation/project-updates.json` was evaluated and intentionally left unchanged: its immutable successor schema applies only to projects already present in the frozen inventory, requiring a truthful original blob and a different reviewed blob; this task adds a new project and has no original blob. No prior project/history/classification or reconciliation logic changed.

Run date: 2026-09-28 UTC  
Source revision: `9ae3a8a1deb8875504c39e5ce1f2b1ebd8ee8ce8`, rebased on DesktopPlatform `main` at `497263e3f2cea3056a502e8f956b099f13a173f7`  
Machine: Windows 11 Pro for Workstations, version `10.0.26200`, build `26200`, 64-bit  
Pinned SDK: .NET SDK `10.0.400` (`C:\Users\J7Rdm\.dotnet\dotnet.exe`)  
Runtime ID: `win-x64`

The project restored with `--locked-mode` and published as Native AOT with the pinned SDK:

```powershell
C:\Users\J7Rdm\.dotnet\dotnet.exe restore C:\MyFile\Projects\ArcForges\DesktopPlatform\.worktree\prf-04\tests\LocalRpcAotTests\LocalRpcAotTests.csproj --locked-mode -p:NuGetAudit=false --ignore-failed-sources
C:\Users\J7Rdm\.dotnet\dotnet.exe publish C:\MyFile\Projects\ArcForges\DesktopPlatform\.worktree\prf-04\tests\LocalRpcAotTests\LocalRpcAotTests.csproj -c Release -r win-x64 --no-restore -p:NuGetAudit=false -o C:\MyFile\Projects\ArcForges\DesktopPlatform\.worktree\prf-04\artifacts\prf-04\win-x64
```

The locked restore and Native AOT publish both exited `0`; publish produced the native `LocalRpcAotTests.exe`. The executable was run while holding the Plan workstation build slot:

```powershell
python C:\MyFile\Projects\Plan\tools\delivery.py build-slot run --worker af-20260928-p02 --task PRF.04 --minutes 30 --wait-minutes 1 -- C:\MyFile\Projects\ArcForges\DesktopPlatform\.worktree\prf-04\artifacts\prf-04\win-x64\LocalRpcAotTests.exe
```

Runtime exit code: `0`. Output:

```text
PASS: two Native AOT processes completed bidirectional LocalBootstrap, generated gRPC calls, cancellation, disconnect/re-attach, malformed-input, unauthorized-peer and bounded-message checks.
Evidence: pipe; reattached process IDs [23276,3752]; fresh instance IDs [2ECCB4C3A86C4D75994536C78DB2760A,E9395A0F7DA94E28B4ABB375307CBD12].
```

This run used Kestrel HTTP/2 over Windows named pipes with `CurrentUserOnly=true`; no TCP listener was configured. The same-user rogue peer's wrong HMAC proof was refused as an authentication error. A one-byte malformed protobuf was rejected with bounded, sanitized status metadata, did not reach the generated `Challenge` service method, and was followed by a successful generated challenge on the same channel. The over-limit request was rejected at the configured 4 MiB receive bound. Two process pairs completed bidirectional bootstrap and renewal; the reattached pair reported fresh instance identities. The private test harness passed the one-use bootstrap secret only over inherited process stdin and kept it out of arguments/output.

Linux and macOS runtime execution was not performed on this Windows machine and is not claimed here. Hosted package-validation CI publishes/compiles its permitted Linux and Windows AOT targets but does not claim or perform hosted runtime acceptance.
