# PRF.04 Windows Native AOT runtime evidence

## Project inventory supporting binding

Claim `af-20260928-p02`, PRF.04 claim epoch 1. A pre-PR policy check (`python eng/reconciliation.py`) first failed with `current project set drift: DesktopPlatform` because this task's new test project was not in the active project manifest; after that manifest entry was added, it exposed a matching project-classification drift. Under the narrowly approved ADP-07 supporting binding, these exact task-owned entries were appended:

- `eng/policy/reconciliation/active-projects.json`: `{ "path": "tests/LocalRpcAotTests/LocalRpcAotTests.csproj", "blob": "b4e4c919be86f1bb758d89ee1f867bb34160cdcd" }` — registers the current project blob so active inventory matches this task's solution.
- `eng/policy/licence-boundary.json`: `{ "path": "tests/LocalRpcAotTests/LocalRpcAotTests.csproj", "kind": "msbuild" }` — declares the existing AGPL-owned test project to the source/license audit.
- `eng/policy/runtime-ownership.json`: `{ "path": "tests/LocalRpcAotTests/LocalRpcAotTests.csproj", "role": "test-or-build-tool" }` — classifies the probe as non-production test/build tooling, not a product runtime.
- `eng/policy/architecture-projects.json`: `{ "path": "tests/LocalRpcAotTests/LocalRpcAotTests.csproj", "role": "Test", "owner": "DesktopPlatform", "module": "", "production": false, "aot": false }` — classifies the project as a non-production test project; its separate executable's AOT proof does not claim that this test project is a production AOT artifact.

The project file explicitly declares its existing AGPL-3.0-only licence and AGPL boundary, matching repository policy. `eng/policy/reconciliation/project-updates.json` was evaluated and intentionally left unchanged: its immutable successor schema applies only to projects already present in the frozen inventory, requiring a truthful original blob and a different reviewed blob; this task adds a new project and has no original blob. No prior project/history/classification or reconciliation logic changed.

Run date: 2026-09-28 UTC

Implementation revision: `80698e81eb4aea5c971f731e22f7c282ae12f46d`
Base: DesktopPlatform `main` at `3f9a226779b9196ad3e3f1746f549b9a38eec456` (PLT.03 snapshot-recovery provenance preserved)
Machine: Windows 11 Pro for Workstations, version `10.0.26200`, build `26200`, 64-bit
Pinned SDK: .NET SDK `10.0.400` (`C:\Users\J7Rdm\.dotnet\dotnet.exe`)
Runtime ID: `win-x64`

After rebasing on the current main and refreshing the exact dependency closure receipt, the project passed locked restore, formatting, build and Native AOT publish with the pinned SDK and build-slot:

```powershell
python C:\MyFile\Projects\Plan\tools\delivery.py build-slot run --worker af-20260928-p02 --task PRF.04 --minutes 30 --wait-minutes 2 -- C:\Users\J7Rdm\.dotnet\dotnet.exe restore tests/LocalRpcAotTests/LocalRpcAotTests.csproj --locked-mode
python C:\MyFile\Projects\Plan\tools\delivery.py build-slot run --worker af-20260928-p02 --task PRF.04 --minutes 30 --wait-minutes 2 -- C:\Users\J7Rdm\.dotnet\dotnet.exe format tests/LocalRpcAotTests/LocalRpcAotTests.csproj --no-restore --verify-no-changes
python C:\MyFile\Projects\Plan\tools\delivery.py build-slot run --worker af-20260928-p02 --task PRF.04 --minutes 30 --wait-minutes 2 -- C:\Users\J7Rdm\.dotnet\dotnet.exe build tests/LocalRpcAotTests/LocalRpcAotTests.csproj -c Release --no-restore
python C:\MyFile\Projects\Plan\tools\delivery.py build-slot run --worker af-20260928-p02 --task PRF.04 --minutes 30 --wait-minutes 2 -- C:\Users\J7Rdm\.dotnet\dotnet.exe publish tests/LocalRpcAotTests/LocalRpcAotTests.csproj -c Release -r win-x64 -o artifacts/prf-04/win-x64 --no-restore
python C:\MyFile\Projects\Plan\tools\delivery.py build-slot run --worker af-20260928-p02 --task PRF.04 --minutes 30 --wait-minutes 2 -- artifacts/prf-04/win-x64/LocalRpcAotTests.exe
```

All five commands exited `0`. The published win-x64 Native AOT executable completed the two-process named-pipe probe, including retaining owner A and its owner session while B restarted as B2 at the same endpoint:

```text
PASS: retained owner session completed bidirectional LocalBootstrap, OS-bound peer identity, concurrent/fenced/expiry renewal, cancellation, malformed-input recovery, same-user spoof refusal, PID-reuse-tolerant reconnect and bounded-message checks.
Evidence: pipe; owner process 36280 / instance 5E8FAA167AD54AB0ABC3375B570C1E62; peer restarted 33104 / instance FE4E40B706DE42E3A88659C738146180; PID equality is allowed and B2 is rebound by a fresh instance/launch tuple; owner session a946a9c996334244b22aea2d7db772ac.
```

The server binds the expected named-pipe client PID using `GetNamedPipeClientProcessId` on the accepted pipe handle; the connecting process observes the server PID using `GetNamedPipeServerProcessId`. The immutable test launch nonce and installation ID are provisioned through private inherited stdin, and caller claims are checked against OS-observed PID plus the parent-provisioned instance/installation/launch tuple. A same-user rogue child receives the real test secret but claims a different PID/instance and is refused. Reattach preserves installation identity but rotates the instance ID and one-use launch nonce; equal or different OS PIDs are both accepted only when the fresh tuple is authenticated. No generated contract DTO was changed.

Lease renewal is serialized against current lease ID, epoch, fence, and expiry in the test service. Concurrent renewal attempts and a barrier-controlled expiry-boundary race are exercised. The reattach check keeps A and its owner session alive, observes B's old lease/channel become unusable, starts B2 with a new process and instance identity, then authenticates B2 through the retained A session. These are test-fixture proofs only; they do not claim a production lease/session service.

This run used Kestrel HTTP/2 over Windows named pipes with `CurrentUserOnly=true`; no TCP listener was configured. The authorized owner sent a one-byte raw malformed protobuf and then, on the same `GrpcChannel`, successfully completed the normal generated `Challenge`/`Confirm` admission using its parent-provisioned peer identity and launch nonce. The server dispatch counter proved the malformed request did not reach generated service dispatch while the following valid challenge dispatched exactly once. Bounded, sanitized refusal metadata and the configured 4 MiB receive bound were also checked. The private probe harness passed the one-use bootstrap secret only over inherited process stdin and kept it out of arguments and output.

Linux and macOS runtime execution was not performed on this Windows machine and is not claimed here. Hosted CI compiles/publishes its permitted Linux and Windows targets but does not claim or perform hosted runtime acceptance.

## Darwin UDS peer identity backend

The review follow-up adds a macOS backend for both the connecting-client and accepted-server socket paths. Linux continues to use `getsockopt(SOL_SOCKET, SO_PEERCRED)` and its `ucred` PID; macOS uses `getsockopt(SOL_LOCAL, LOCAL_PEERPID)` and an `int32` `pid_t` output. The values are from Apple's XNU `<sys/un.h>` (`SOL_LOCAL=0`, `LOCAL_PEERPID=0x002`): [Apple XNU header](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/un.h#L81-L89). Platform backend selection is isolated in a pure selector so the supported Linux/macOS routes and unsupported-platform fail-closed route can be checked without invoking a native socket call.

This host is Windows and has no macOS runtime. No Mac host was installed, provisioned, simulated, or claimed. The actual macOS local-opt-in two-process run remains unobserved; this code/API path and the Windows/Linux compilation evidence do not replace that runtime evidence. PRF.04 must remain `delivered`, not `complete`, until the required macOS process run is recorded on a real macOS host.

Darwin follow-up source revision: `00668b557f405dcc102deba8f963fedbbb41bf5a`.

After this source change, pinned SDK 10.0.400 restore, formatting, Release build,
the platform-dispatch check, Windows Native AOT publish, and the published
Windows process probe all exited `0`, each build/publish/run performed through
the task build-slot. The dispatch check was run against both the managed build
and the published Native AOT binary:

```powershell
C:\Users\J7Rdm\.dotnet\dotnet.exe exec artifacts/bin/dotnet/windows/LocalRpcAotTests/Release/net10.0/LocalRpcAotTests.dll --verify-unix-peer-pid-backends
artifacts/prf-04/win-x64/LocalRpcAotTests.exe --verify-unix-peer-pid-backends
```

```text
PASS: Linux SO_PEERCRED and macOS SOL_LOCAL/LOCAL_PEERPID dispatch; unsupported platforms fail closed.
```

The repeated Native AOT `win-x64` two-process run also passed:

```text
PASS: retained owner session completed bidirectional LocalBootstrap, OS-bound peer identity, concurrent/fenced/expiry renewal, cancellation, malformed-input recovery, same-user spoof refusal, PID-reuse-tolerant reconnect and bounded-message checks.
Evidence: pipe; owner process 25284 / instance B75D7185207E40779BE84606C9F149BA; peer restarted 27756 / instance F2642D60C263413E81EE017DA59E059E; PID equality is allowed and B2 is rebound by a fresh instance/launch tuple; owner session 290550f604ec4966bc6c282bbd30e0e8.
```

Post-follow-up policy checks passed: dependency policy (47 NuGet coordinates,
225 inputs), all 16 dependency-policy tests, provenance (499 tracked files),
reconciliation (7 owners, 67 projects, 166 historical projects, 326
directories, 7 native records), and `git diff --check`. No package or lock
file changed. These checks validate the supported native backend selection and
Windows transport but do not constitute macOS runtime execution.
