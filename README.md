# ArcForges

**Your machine. Your rules.**

ArcForges is migrating to a general CLI Sandbox/Run platform with a local Node
and CLI and optional remote management. C# and Native AOT provide the local
runtime. The existing Windows supervisor and Linux systemd infrastructure remain
during the cutover. The package contains the Node and CLI.

The `arcforges` executable hosts the Node and the CLI. This development candidate
includes the V2 offline Core and administration commands described in the
[offline CLI guide](docs/cli/offline.md). The delivery plan records verification,
migration and release status. [ArcForges-Design](https://github.com/ArcForges/ArcForges-Design) ·
[Plan](https://github.com/ArcForges/Plan).

The repository has no separate product MCP adapter, hook-handler, cache-platform
or toolchain-registry project to delete. Legacy client kinds, roles and dormant
schema are handled by their later cutover tasks; this removal creates no replacement
modules. Shared DesktopPlatform/Contracts and independent applications stay intact.

## Layout

| Path | Contents |
|---|---|
| `src/ArcForges.Host` | `arcforges`, the multi-role node/CLI executable |
| `src/ArcForges.Node.Core` | The node's core: configuration and data root, single instance, logging with redaction, command processor, event journal and stream hub, lifecycle, settings, notifications, jobs |
| `src/ArcForges.Node.Api` | The node's API on the LocalRpc service endpoint (NodeService, NodeEventService) and the node host (startup and shutdown) |
| `src/ArcForges.Node.Platform` | The execution platform contract and the helper file formats (exit, launch, guard, heartbeat, output index) |
| `src/ArcForges.Node.Platform.Windows` | Windows execution: job objects, command resolution and quoting, the `node exec-wrap` holder and disk guard, the `node signal` helper |
| `src/ArcForges.Node.Platform.Linux` | Linux execution: transient user units through the user manager's D-Bus API, the slice's limits, freeze and kill, the `node exec-launch`, `node exec-stop`, `node exit-record` and `node guard` roles |
| `src/ArcForges.Client` | The client library of the CLI: endpoint resolution, auto-start, hello, NodeStreamCache, command IDs, connection state |
| `src/ArcForges.CommandLine` | The CLI (System.CommandLine): global options, human and JSON output, exit codes |
| `src/ArcForges.RunSupervisor` | Per-Run ownership, official MXC execution, terminal and output |
| `src/ArcForges.Supervisor` | `arcforges-supervisor.exe`: the Windows GUI-subsystem supervisor that starts the node and restarts it after a crash |
| `src/ArcForges.Node.Store` | The node store: SQLite schema, migrations, backups, idempotency, sealed task secrets, default policy |
| `tools/ArcForges.TestLoad` | `arcforges-testload`: deterministic CPU, memory, output and process-tree workloads |
| `tools/ArcForges.Bench` | `arcforges-bench`: binary size, startup and node store growth benchmarks (JSON results) |
| `tests/` | xUnit v3 test applications; suites selected by trait |
| `eng/` | test, publish, benchmark and packaging scripts; dependency admissions; the development systemd user unit (`eng/systemd`) |
| `packaging/linux` | The systemd user units the Linux installers ship (13 section 3.4): `arcforges-node.service`, `arcforges.slice`, `arcforges-guard.service` |

## Build and test

Use the .NET SDK in `global.json` (11.0.100), C# 15 and Python 3.15.2 from
`.python-version` on Windows 11 or Linux. Select the same SDK/Python roots as CI.

```sh
python eng/check_toolchain.py
dotnet restore ArcForges.slnx --locked-mode
dotnet build ArcForges.slnx -c Release --no-restore
dotnet format ArcForges.slnx --verify-no-changes --no-restore
./eng/test.ps1 -Suite ci          # or: eng/test.sh --suite ci   (-List / --list shows every suite)
```

The toolchain preflight checks invoking/PATH Python, the actual SDK and effective
MSBuild roots, and records every committed lock hash. A conflicting SDK override
fails. The startup regression gate retains the merge base's own exact SDK through
`eng/baseline_sdk.py`; that immutable baseline is not the current build selector.
The [dependency upgrade inventory](docs/dependency-upgrade/current.json) records
current selections and pending qualification; it does not replace native checks.

Native AOT publish (fails on any build, trim or AOT warning), benchmarks and the Node/CLI package:

```powershell
./eng/publish.ps1 -RuntimeIdentifier win-x64   # in a Visual Studio developer shell on Windows
./eng/bench.ps1 -RuntimeIdentifier win-x64     # size gates and startup -> artifacts/bench/
./eng/package.ps1 -RuntimeIdentifier win-x64   # artifacts/packages/arcforges-win-x64.zip
```

The archive contains the host publish tree, Windows supervisor or Linux systemd
units, exact dependency locks, licenses/notices, build identity and file digests.
Packaging reads only those component outputs; old desktop publish caches are excluded.

Linux executables are published on Linux, for example
`dotnet publish src/ArcForges.Host -c Release -r linux-x64 -warnaserror`.

## The Node and the CLI

The local CLI uses the current user's Node. Sandbox creation, Run execution,
resource management and operation inspection work without a Center account or
connection. Use a configuration for the installed MXC profile. The guide includes
the exact JSON fields and profile names for Windows and Linux.
[Offline CLI guide](docs/cli/offline.md).

```sh
arcforges node start
arcforges node status --json
arcforges doctor
arcforges sandbox create build --file sandbox.json --json
arcforges sandbox list
arcforges resources show
arcforges resources watch --once --json
```

Use the Sandbox ID returned by `sandbox create`. This Linux example passes
`two words` as one argument and prints the Start receipt. Inspect the Run ID in
that receipt to check the outcome.

```sh
arcforges run start "$SANDBOX_ID" --terminal off -- /usr/bin/dash -c 'printf "%s\n" "$1"' _ 'two words'
arcforges run inspect "$RUN_ID"
arcforges operation inspect "$COMMAND_ID" --owner-epoch "$OWNER_EPOCH" --json
arcforges node stop
```

A durable mutation prints its command ID and owner epoch. It also reports the
expected revision when one was sent, and the resolved terminal option for
`run start`. If a reply is lost, inspect the original operation with those IDs.
`node stop` leaves active Runs under their existing supervisors.
`node stop --stop-runs` stops and checks Runs found in its inventory before
requesting service shutdown. A concurrent Start can remain active.

Windows startup uses `arcforges-supervisor.exe` beside `arcforges.exe`. Linux
startup uses the systemd user service when available. The existing bootstrap can
start the Node using `setsid` without a user manager. The Linux MXC Run profile
requires its qualified user manager and cgroup controllers. The development unit
is shipped in [eng/systemd](eng/systemd). The test fixtures isolate each Node
using the existing `--test-mode`, `ARCFORGES_ENDPOINT` and `ARCFORGES_CONFIG_DIR`
hooks.

## Tools

```sh
arcforges-testload cpu --threads 4 --iterations 200000000 --seed 42
arcforges-testload mem-ramp --target-mb 512 --step-mb 64 --step-ms 50 --hold-ms 500
arcforges-testload output --bytes 268435456 --line-bytes 120 --report out.json > captured.txt
arcforges-testload fork --width 4 --depth 2 --hold-ms 1000
arcforges-testload signal --hold-ms 60000 --marker m.txt --on-break exit   # Windows console/GUI stop behaviour
arcforges-testload args "two words" 'a"b'                                     # prints its argv and working directory as JSON
arcforges-bench size --target arcforges --path artifacts/publish/win-x64/host/arcforges.exe
arcforges-bench startup --exe artifacts/publish/win-x64/host/arcforges.exe --arg --version --runs 50 --output now.json
arcforges-bench compare-startup --baseline-exe main/arcforges.exe --current-exe artifacts/publish/win-x64/host/arcforges.exe --arg --version
                                       # both measured here, interleaved; a p50 increase >25% and >5 ms fails
./eng/compare-startup.ps1 -RuntimeIdentifier win-x64 -BaselineExecutable base/arcforges.exe   # the startup gate (base commit's CLI)
arcforges-bench store-growth --environment tests/ArcForges.Node.Store.Tests/Fixtures/environments/env-wsl-debian-bash.json --attempts 10000
```

Equal parameters give equal bytes and digests on every run and platform; `--help` lists the options.

Every pushed head is verified after the push on the owner's two hosts (`python eng/verify.py run-and-report` in a worktree at the
commit; [AGENTS.md](AGENTS.md) §5): a Windows leg on native Windows and a Linux leg on a real Linux host, reported as the commit
statuses `arcforges/windows` and `arcforges/linux` that `main` requires. CI verifies external pull requests the same way on Windows and Ubuntu
(the closed-loop node and CLI tests on the JIT build and on the native binaries), publishes Native AOT for
**win-x64, win-arm64, linux-x64 and linux-arm64**, gates binary sizes, node store growth and CLI cold-start regressions against
the base commit, checks that the node store schema only expands, and checks formatting, analyzers, dependencies, secrets and
CodeQL. Node/CLI archives are unsigned development previews, not releases.

[Agent and contributor rules](AGENTS.md) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) ·
[AGPL-3.0-only](LICENSE) · [Third-party notices](THIRD_PARTY_NOTICES.md)
