# Contributing

Read [AGENTS.md](AGENTS.md) first: delivery is serial and follows the
[Plan](https://github.com/ArcForges/Plan), and the product design is
[ArcForges-Design](https://github.com/ArcForges/ArcForges-Design). Keep changes compatible with
Native AOT, offline by default, and limited to the active task. Do not add sibling source
references or private package feeds.

## Environment

- Use SDK 11.0.100 from `global.json`, explicit C# 15 and Python 3.15.2 from
  `.python-version`. Run `python eng/check_toolchain.py` before the current build.
  Dependency versions are centralized in `Directory.Packages.props`;
  commit every project lock file and update `eng/policy/dependency-admissions.json` with them.
- Windows Native AOT publishing requires Visual Studio C++ build tools and a Windows SDK.
  Use a Developer PowerShell (`Launch-VsDevShell.ps1`) if the linker is not discoverable;
  ARM64 targets also need the C++ ARM64 build tools.
- Linux Native AOT publishing uses the LLVM23.1.5/binutils2.47 selector in
  `eng/native-toolchain.json`, plus the host's zlib development library. The
  reviewed private tools are provisioned explicitly with `python
  eng/native_toolchain.py install`; ordinary publishing only selects and checks
  an existing installation in child processes. x64 and ARM64 archives/caches
  are distinct. Publish Linux executables on the matching native Linux venue.
- Reuse installed SDKs, package caches and toolchains.
- The startup regression gate builds the immutable merge base with its own retained
  SDK. `eng/baseline_sdk.py` selects that installed root without editing the baseline
  or installing a replacement; current source still selects the new SDK.

Run the restore, build, format and test commands in the README. `eng/test.ps1` / `eng/test.sh`
select suites by trait (`-List` / `--list`). Package the Node/CLI host with the Windows
supervisor or the existing Linux systemd unit files through `eng/package.ps1`.
No standalone desktop is built or packaged.

## Pull requests

Create branches and worktrees beneath `.worktree/`; it is intentionally ignored.
Do not commit build output, local settings, secrets or signing keys. Explain what changed
and what you actually verified, with exact commands. CI publishes build artifacts only: no
automatic release, deployment, privileged code execution or merge. The expected checks on a contributor's pull request are
`Native (win-x64)`, `Native (win-arm64)`, `Native (linux-x64)`, `Native (linux-arm64)`, `Verify`, `Workflow lint`,
`Secret scan`, `Dependency review`, and both `CodeQL` jobs; contributors need no local hook. Every pull request, the maintainer's included,
also needs the `arcforges/windows` and `arcforges/linux` statuses of the maintainer's verification hosts, which run it
after the push ([AGENTS.md](AGENTS.md) §5); for the maintainer's own pull requests they replace the hosted jobs.

Do not bypass failing security checks or silence AOT and trim warnings without investigating them.
Do not rerun the whole build matrix locally just to duplicate hosted CI.

Project contributions use **AGPL-3.0-only**. Preserve SPDX headers and third-party notices.
