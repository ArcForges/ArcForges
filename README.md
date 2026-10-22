# ArcForges

**Your machine. Your rules.**

ArcForges puts AI-driven and heavy local work under your control: a local node that runs, schedules
and records commands, a CLI and MCP adapter for people and AI agents, and an optional desktop.
C# · Native AOT · Avalonia. Local and LAN use need no account.

The `arcforges` executable runs the node (`arcforges node run`) and the CLI: the node host with its
per-user endpoint, lifecycle, event journal and streams, the Windows supervisor, the shared client library
the CLI (`status`, `node`, `config`, `events`, `jobs`, `run`, `tasks`, `version`, `completion`), Windows
execution (managed commands in nested job objects with exec-wrap holders that survive a node restart) and Linux execution
(transient systemd user units in `arcforges.slice` with durable exit records, a disk guard unit and the systemd watchdog).
Scheduling and the other node subsystems arrive with their delivery tasks, and
`arcforges-desktop` still shows the bootstrap **Hello World** view until the desktop shell task
replaces it. Product design: [ArcForges-Design](https://github.com/ArcForges/ArcForges-Design);
delivery plan: [Plan](https://github.com/ArcForges/Plan).

## Layout

| Path | Contents |
|---|---|
| `src/ArcForges.Host` | `arcforges`, the multi-role node/CLI executable |
| `src/ArcForges.Node.Core` | The node's core: configuration and data root, single instance, logging with redaction, command processor, event journal and stream hub, lifecycle, settings, notifications, jobs |
| `src/ArcForges.Node.Api` | The node's API on the LocalRpc service endpoint (NodeService, NodeEventService) and the node host (startup and shutdown) |
| `src/ArcForges.Node.Platform` | The execution platform contract and the helper file formats (exit, launch, guard, heartbeat, output index) |
| `src/ArcForges.Node.Platform.Windows` | Windows execution: job objects, command resolution and quoting, the `node exec-wrap` holder and disk guard, the `node signal` helper |
| `src/ArcForges.Node.Platform.Linux` | Linux execution: transient user units through the user manager's D-Bus API, the slice's limits, freeze and kill, the `node exec-launch`, `node exec-stop`, `node exit-record` and `node guard` roles |
| `src/ArcForges.Client` | The client library of the CLI, Desktop and MCP adapter: endpoint resolution, auto-start, hello, NodeStreamCache, command IDs, connection state |
| `src/ArcForges.CommandLine` | The CLI (System.CommandLine): global options, human and JSON output, exit codes |
| `src/ArcForges.Supervisor` | `arcforges-supervisor.exe`: the Windows GUI-subsystem supervisor that starts the node and restarts it after a crash |
| `src/ArcForges.Desktop` | `arcforges-desktop`, the optional Avalonia desktop |
| `src/ArcForges.Node.Store` | The node store: SQLite schema, migrations, backups, idempotency, sealed task secrets, default policy |
| `tools/ArcForges.TestLoad` | `arcforges-testload`: deterministic CPU, memory, output and process-tree workloads |
| `tools/ArcForges.Bench` | `arcforges-bench`: binary size, startup and node store growth benchmarks (JSON results) |
| `tests/` | xUnit v3 test applications; suites selected by trait |
| `eng/` | test, publish, benchmark and packaging scripts; dependency admissions; the development systemd user unit (`eng/systemd`) |
| `packaging/linux` | The systemd user units the Linux installers ship (13 section 3.4): `arcforges-node.service`, `arcforges.slice`, `arcforges-guard.service` |

## Build and test

Use the .NET SDK in `global.json` (10.0.401) on Windows 11 or Linux.

```sh
dotnet restore ArcForges.slnx --locked-mode
dotnet build ArcForges.slnx -c Release --no-restore
dotnet format ArcForges.slnx --verify-no-changes --no-restore
./eng/test.ps1 -Suite ci          # or: eng/test.sh --suite ci   (-List / --list shows every suite)
```

Native AOT publish (fails on any build, trim or AOT warning), benchmarks and the desktop package:

```powershell
./eng/publish.ps1 -RuntimeIdentifier win-x64   # in a Visual Studio developer shell on Windows
./eng/bench.ps1 -RuntimeIdentifier win-x64     # size gates and startup -> artifacts/bench/
./eng/package.ps1 -RuntimeIdentifier win-x64   # artifacts/packages/arcforges-desktop-win-x64.zip
```

Linux executables are published on Linux, for example
`dotnet publish src/ArcForges.Host -c Release -r linux-x64 -warnaserror`.

## The node and the CLI

```sh
arcforges status                 # starts the node when it is absent (not in CI jobs or sandboxes), then reports it
arcforges status --json          # one JSON document (canonical protobuf JSON mapping; IDs as base32)
arcforges node run               # run the node in this terminal (exit 3 if one already runs)
arcforges node stop
arcforges node info | health | capabilities [--reevaluate] | rename <name> | wait-ready [--timeout 30s]
arcforges config list | get <key> | set logLevel debug
arcforges events --topic node --since <cursor>    # JSON Lines; resumes after the cursor
arcforges jobs list | show <id> | cancel <id>
arcforges run -- dotnet build    # a managed task: output mirrored byte for byte, the task's exit code (125/126/127 when not started)
arcforges run --detach -- cmake --build out          # prints the task ID
arcforges run --client-timeout 10m -- cargo test    # hands off with exit 124 before the caller's own timeout
arcforges tasks list | show | wait [--output tail|all|none] | attach | logs | cancel | retry | pin | unpin | purge | attempts
arcforges version
eval "$(arcforges completion bash)"                # also zsh, fish, pwsh
```

On Windows the auto-start launches `arcforges-supervisor.exe` beside `arcforges.exe`; on Linux it runs
`systemctl --user start arcforges-node.service` (see `eng/systemd/arcforges-node.service` for a development unit),
or a `setsid` launch when no systemd user manager runs. On Linux every task runs as its own transient unit
`arcforges-a-<attempt>.service` in `arcforges.slice` (the user manager is its parent, so it survives a node crash or
`systemctl --user restart`, and `exit.json` is written by the unit's `ExecStopPost`); without a user manager the node is
DEGRADED (observe only): tasks that require enforcement are refused and the others run as child processes, labelled `unenforced`. Exit codes follow ArcForges-Design `experience/cli.md` section 3.
Tests isolate each node with `--test-mode` and the `ARCFORGES_ENDPOINT` / `ARCFORGES_CONFIG_DIR` test hooks.

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
CodeQL. Desktop archives are unsigned development previews, not releases.

[Agent and contributor rules](AGENTS.md) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) ·
[AGPL-3.0-only](LICENSE) · [Third-party notices](THIRD_PARTY_NOTICES.md)
