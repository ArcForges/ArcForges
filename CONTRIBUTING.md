# Contributing

Keep changes small, offline by default, and compatible with Native AOT. This repository
is the ArcForges desktop bootstrap, not the ArcScope application or an implementation
of the entire product plan. Do not add sibling source references or private package feeds.

## Environment

- Use the SDK in `global.json`. Dependency versions are centralized in
  `Directory.Packages.props`; commit both project lock files when changing them.
- Windows Native AOT publishing requires Visual Studio C++ build tools and a Windows SDK.
  Use a Developer PowerShell/command prompt if the linker is not already discoverable.
- Linux Native AOT publishing requires `clang` and `zlib1g-dev` (Debian/Ubuntu names).
  Compile Linux artifacts on Linux or WSL, not directly on Windows.
- Desktop Linux needs an X11/XWayland session, fontconfig, standard system fonts,
  libX11, libICE and libSM. WSL compilation alone is not native Linux desktop validation.
- Reuse installed SDKs, package caches and toolchains. This bootstrap needs no vcpkg,
  Node, Java, Rust or system-wide setup script.

Run the restore/build/test/format commands in the README. `dotnet test` runs offline
view-model tests and an Avalonia headless test of the actual XAML and button bindings;
it does not launch a native window or contact any service.

To try a native build locally, publish the desktop project for `win-x64`, `win-arm64`
or `linux-x64`, then run its `ArcForges.exe` / `ArcForges` on a matching machine.
Keep the complete publish directory together; native rendering libraries are separate files.
Check first launch, typing, the greeting button, keyboard activation, resizing and closing.
No macOS support or verification is claimed by this bootstrap.

## Pull requests

Create branches and worktrees beneath `.worktree/`; it is intentionally ignored.
Do not commit build output, local settings, secrets or signing keys. Explain what changed
and what you actually verified. CI publishes build artifacts only—no automatic release,
deployment, privileged code execution or merge. The expected checks are `Verify`,
`Workflow lint`, `Secret scan`, `Dependency review`, and both `CodeQL` jobs.

Do not bypass failing security checks or silence AOT warnings without investigating them.
Do not rerun the whole build matrix locally just to duplicate hosted CI.

Project contributions use **AGPL-3.0-only**. Preserve SPDX headers and third-party notices.
