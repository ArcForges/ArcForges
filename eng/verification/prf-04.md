# PRF.04 Windows Native AOT runtime evidence

## Project inventory supporting binding

Claim `af-20260928-p02`, PRF.04 claim epoch 1. A pre-PR policy check (`python eng/reconciliation.py`) first failed with `current project set drift: DesktopPlatform` because this task's new test project was not in the active project manifest; after that manifest entry was added, it exposed a matching project-classification drift. Under the narrowly approved ADP-07 supporting binding, these exact task-owned entries were appended:

- `eng/policy/reconciliation/active-projects.json`: `{ "path": "tests/LocalRpcAotTests/LocalRpcAotTests.csproj", "blob": "b4e4c919be86f1bb758d89ee1f867bb34160cdcd" }` — registers the current project blob so active inventory matches this task's solution.
- `eng/policy/licence-boundary.json`: `{ "path": "tests/LocalRpcAotTests/LocalRpcAotTests.csproj", "kind": "msbuild" }` — declares the existing AGPL-owned test project to the source/license audit.
- `eng/policy/runtime-ownership.json`: `{ "path": "tests/LocalRpcAotTests/LocalRpcAotTests.csproj", "role": "test-or-build-tool" }` — classifies the probe as non-production test/build tooling, not a product runtime.
- `eng/policy/architecture-projects.json`: `{ "path": "tests/LocalRpcAotTests/LocalRpcAotTests.csproj", "role": "Test", "owner": "DesktopPlatform", "module": "", "production": false, "aot": false }` — classifies the project as a non-production test project; its separate executable's AOT proof does not claim that this test project is a production AOT artifact.

The project file explicitly declares its existing AGPL-3.0-only licence and AGPL boundary, matching repository policy. `eng/policy/reconciliation/project-updates.json` was evaluated and intentionally left unchanged: its immutable successor schema applies only to projects already present in the frozen inventory, requiring a truthful original blob and a different reviewed blob; this task adds a new project and has no original blob. No prior project/history/classification or reconciliation logic changed.

Run date: 2026-09-28 UTC  
Implementation revision before final main rebase: `1191ffd31022c86e0ddfc71d3d4381869fcade98`  
Base at that point: DesktopPlatform `main` at `0ba78d58cb31c1226d8e0b70f2879ecc42d00699`  
Machine: Windows 11 Pro for Workstations, version `10.0.26200`, build `26200`, 64-bit  
Pinned SDK: .NET SDK `10.0.400` (`C:\Users\J7Rdm\.dotnet\dotnet.exe`)  
Runtime ID: `win-x64`

The project had already passed locked restore with the pinned SDK and the final dependency graph was unchanged by the runtime-test correction. After the final source edit, formatting verification and Native AOT publish were rerun with the pinned SDK and build-slot:

```powershell
python C:\MyFile\Projects\Plan\tools\delivery.py build-slot run --worker af-20260928-p02 --task PRF.04 --minutes 30 --wait-minutes 2 -- C:\Users\J7Rdm\.dotnet\dotnet.exe format tests/LocalRpcAotTests/LocalRpcAotTests.csproj --no-restore --verify-no-changes --include tests/LocalRpcAotTests/Program.cs
python C:\MyFile\Projects\Plan\tools\delivery.py build-slot run --worker af-20260928-p02 --task PRF.04 --minutes 30 --wait-minutes 2 -- C:\Users\J7Rdm\.dotnet\dotnet.exe publish tests/LocalRpcAotTests/LocalRpcAotTests.csproj -c Release -r win-x64 -o artifacts/prf-04/win-x64 --no-restore
python C:\MyFile\Projects\Plan\tools\delivery.py build-slot run --worker af-20260928-p02 --task PRF.04 --minutes 30 --wait-minutes 2 -- artifacts/prf-04/win-x64/LocalRpcAotTests.exe
```

All three commands exited `0`. The published win-x64 Native AOT executable completed the two-process named-pipe probe, including retaining owner A and its owner session while B restarted as B2 at the same endpoint:

```text
PASS: retained owner session completed bidirectional LocalBootstrap, OS-bound peer identity, concurrent/fenced/expiry renewal, cancellation, malformed-input, same-user spoof refusal, reconnect and bounded-message checks.
Evidence: pipe; owner process 20632 / instance 32CFD631E2724ED4894E2015803F0407; peer restarted 15628 / instance A83DFB865C354E238CE79CFF64C54634; owner session bebbf7003d534b958e2c66e37851a678.
```

The server binds the expected named-pipe client PID using `GetNamedPipeClientProcessId` on the accepted pipe handle; the connecting process observes the server PID using `GetNamedPipeServerProcessId`. The immutable test launch nonce and installation ID are provisioned through private inherited stdin, and caller claims are checked against OS-observed PID plus the parent-provisioned instance/installation/launch tuple. A same-user rogue child receives the real test secret but claims a different PID/instance and is refused. No generated contract DTO was changed.

Lease renewal is serialized against current lease ID, epoch, fence, and expiry in the test service. Concurrent renewal attempts and a barrier-controlled expiry-boundary race are exercised. The reattach check keeps A and its owner session alive, observes B's old lease/channel become unusable, starts B2 with a new process and instance identity, then authenticates B2 through the retained A session. These are test-fixture proofs only; they do not claim a production lease/session service.

This run used Kestrel HTTP/2 over Windows named pipes with `CurrentUserOnly=true`; no TCP listener was configured. A one-byte malformed protobuf was rejected with bounded, sanitized status metadata before generated service dispatch, the connection recovered for a normal generated challenge, and the over-limit request was rejected at the configured 4 MiB receive bound. The private probe harness passed the one-use bootstrap secret only over inherited process stdin and kept it out of arguments and output.

Linux and macOS runtime execution was not performed on this Windows machine and is not claimed here. Hosted CI compiles/publishes its permitted Linux and Windows targets but does not claim or perform hosted runtime acceptance.
