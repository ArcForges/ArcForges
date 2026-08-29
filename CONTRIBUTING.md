# Contributing to ArcForges

Thank you for helping build ArcForges. Keep changes focused, evidence-backed, and inside the documented
architecture boundary.

1. Create a branch and Git worktree from the current reviewed base.
2. Add the SPDX identifier to every source/configuration file that supports comments.
3. Keep package versions in `Directory.Packages.props`; never add inline versions.
4. Run the locked restore, build, test, and CMake commands documented in the root README for your platform.
   The CMake presets are Ninja-based and named for their RID (`win-x64-runtime-shared`,
   `linux-x64-shim-static`, ...); the configure, build and test preset share one name.
5. For native changes on Windows, initialise MSVC with `vcvars64.bat` and then restore `VCPKG_ROOT` — vcvars64
   overwrites it with the vcpkg bundled inside Visual Studio, which is not the pinned baseline the repository
   locks. Run both CMake profiles, and let the `pre-push` hook build `win.slnx`; CI does not build it.
6. Both platforms compile through `sccache`. Check `sccache --show-stats` if a build is unexpectedly slow;
   a non-zero "Non-cacheable compilations" count means something reintroduced separate PDB debug info.
7. Update tests, notices, architecture evidence, and the pull-request checklist with the same change.

Do not commit secrets, generated build output, credentials, user data, or unlicensed third-party material.
