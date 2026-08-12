# Contributing to ArcForges

Thank you for helping build ArcForges. Keep changes focused, evidence-backed, and inside the documented
architecture boundary.

1. Create a branch and Git worktree from the current reviewed base.
2. Add the SPDX identifier to every source/configuration file that supports comments.
3. Keep package versions in `Directory.Packages.props`; never add inline versions.
4. Run `eng/build/build-all.ps1` on Windows or `eng/build/build-all.sh` on Linux/macOS.
5. For native changes, run both CMake and the independent Windows MSBuild entry where applicable.
6. Update tests, notices, architecture evidence, and the pull-request checklist with the same change.

Do not commit secrets, generated build output, credentials, user data, or unlicensed third-party material.
