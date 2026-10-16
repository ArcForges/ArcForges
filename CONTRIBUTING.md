# Contributing

Read [AGENTS.md](AGENTS.md) first: delivery is serial and follows the
[Plan](https://github.com/ArcForges/Plan), and the product design is
[ArcForges-Design](https://github.com/ArcForges/ArcForges-Design). Keep changes compatible with
Native AOT, offline by default, and limited to the active task. Do not add sibling source
references or private package feeds.

## Environment

- Use the SDK in `global.json`. Dependency versions are centralized in `Directory.Packages.props`;
  commit every project lock file and update `eng/policy/dependency-admissions.json` with them.
- Windows Native AOT publishing requires Visual Studio C++ build tools and a Windows SDK.
  Use a Developer PowerShell (`Launch-VsDevShell.ps1`) if the linker is not discoverable;
  ARM64 targets also need the C++ ARM64 build tools.
- Linux Native AOT publishing requires `clang` and `zlib1g-dev` (Debian/Ubuntu names).
  Publish Linux executables on Linux or in WSL, not directly on Windows.
- Desktop Linux needs an X11/XWayland session, fontconfig, standard system fonts,
  libX11, libICE and libSM. WSL compilation alone is not native Linux desktop validation.
- Reuse installed SDKs, package caches and toolchains. Avalonia build telemetry is disabled in
  `Directory.Build.targets`; the `eng/` scripts and CI also set `AVALONIA_TELEMETRY_OPTOUT=1`.

Run the restore, build, format and test commands in the README. `eng/test.ps1` / `eng/test.sh`
select suites by trait (`-List` / `--list`). Desktop tests run the real view in Avalonia's headless
platform; they do not launch a native window or contact any service.

To try the desktop, publish it (`./eng/publish.ps1 -RuntimeIdentifier <rid> -Component desktop`)
and run `arcforges-desktop` / `arcforges-desktop.exe` from the complete publish directory on a
matching machine. No macOS support or verification is claimed.

## Pull requests

Create branches and worktrees beneath `.worktree/`; it is intentionally ignored.
Do not commit build output, local settings, secrets or signing keys. Explain what changed
and what you actually verified, with exact commands. CI publishes build artifacts only: no
automatic release, deployment, privileged code execution or merge. The expected checks on a contributor's pull request are
`Native (win-x64)`, `Native (win-arm64)`, `Native (linux-x64)`, `Native (linux-arm64)`, `Verify`, `Workflow lint`,
`Secret scan`, `Dependency review`, and both `CodeQL` jobs; contributors need no local hook. The maintainer's own pull
requests are verified by the local pre-push hook instead ([AGENTS.md](AGENTS.md) §5).

Do not bypass failing security checks or silence AOT and trim warnings without investigating them.
Do not rerun the whole build matrix locally just to duplicate hosted CI.

Project contributions use **AGPL-3.0-only**. Preserve SPDX headers and third-party notices.
