# ArcForges

**Your machine. Your rules.**

ArcForges puts AI-driven and heavy local work under your control: a local node that runs, schedules
and records commands, a CLI and MCP adapter for people and AI agents, and an optional desktop.
C# · Native AOT · Avalonia. Local and LAN use need no account.

This repository is at its foundation stage: the solution layout, build policy, CI and test
harness that later tasks fill with behaviour. The `arcforges` executable has no roles yet, and
`arcforges-desktop` still shows the bootstrap **Hello World** view until the desktop shell task
replaces it. Product design: [ArcForges-Design](https://github.com/ArcForges/ArcForges-Design);
delivery plan: [Plan](https://github.com/ArcForges/Plan).

## Layout

| Path | Contents |
|---|---|
| `src/ArcForges.Host` | `arcforges`, the multi-role node/CLI executable (empty composition root for now) |
| `src/ArcForges.Desktop` | `arcforges-desktop`, the optional Avalonia desktop |
| `tools/ArcForges.TestLoad` | `arcforges-testload`: deterministic CPU, memory, output and process-tree workloads |
| `tools/ArcForges.Bench` | `arcforges-bench`: binary size and startup benchmarks (JSON results) |
| `tests/` | xUnit v3 test applications; suites selected by trait |
| `eng/` | test, publish, benchmark and packaging scripts; dependency admissions |

## Build and test

Use the .NET SDK in `global.json` (10.0.401) on Windows 11 or Linux (WSL2 Debian for development).

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

Linux executables are published on Linux or WSL, for example
`dotnet publish src/ArcForges.Host -c Release -r linux-x64 -warnaserror`.

## Tools

```sh
arcforges-testload cpu --threads 4 --iterations 200000000 --seed 42
arcforges-testload mem-ramp --target-mb 512 --step-mb 64 --step-ms 50 --hold-ms 500
arcforges-testload output --bytes 268435456 --line-bytes 120 --report out.json > captured.txt
arcforges-testload fork --width 4 --depth 2 --hold-ms 1000
arcforges-bench size --target arcforges --path artifacts/publish/win-x64/host/arcforges.exe
arcforges-bench startup --exe artifacts/publish/win-x64/host/arcforges.exe --runs 50
```

Equal parameters give equal bytes and digests on every run and platform; `--help` lists the options.

CI builds and tests on Windows and Ubuntu, publishes Native AOT for **win-x64, win-arm64 and
linux-x64**, gates binary sizes, and checks formatting, analyzers, dependencies, secrets and
CodeQL. Desktop archives are unsigned development previews, not releases.

[Agent and contributor rules](AGENTS.md) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) ·
[AGPL-3.0-only](LICENSE) · [Third-party notices](THIRD_PARTY_NOTICES.md)
