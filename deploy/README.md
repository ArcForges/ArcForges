# Native producer builds

DesktopPlatform owns native compilation and capability packaging. Application deployment belongs to each
product repository. These instructions build the existing ABI used by the Windows x64 NuGet release.
Product API and installer acceptance remain separate.

## Native dependency toolchain

ArcForges uses classic vcpkg with standard triplet semantics and a pinned source checkout. The reviewed Windows toolchain is `C:\vcpkg` at commit
`36677bbd0b3bf11da7376e62e14bffcc54d2eaeb`.
Windows dependencies install into this checkout's ignored `artifacts/vcpkg-installed` directory.
Both CMake and the x64 Visual Studio projects use that directory, so unrelated global installations
cannot supply stale dependency versions. Binary caches still accelerate installation. Native package
staging checks installed versions and recipe hashes against the pinned checkout and reviewed overlay.
The reviewed dependency generator is CMake 4.4.0 from that checkout's
`scripts/vcpkg-tools.json`; `vcpkg fetch cmake` reports the executable it selects.
Use that exact version for dependency installation. A newer system CMake may otherwise
be selected and produce a different binary-cache identity. Package staging requires
each installed `vcpkg_abi_info.txt` to match the reviewed generator. The owned wrapper
presets separately use CMake 4.3.3 with Ninja 1.13.1; configure them with `--fresh` after
changing tools or the installed tree. See the [immutable provenance profile](../docs/provenance.md).
The two owning overlays include the unchanged standard definitions and select MSVC
`14.51.36231`; their exact hashes and included definitions are verified in each installed
ABI record. They prevent vcpkg from selecting a newer side-by-side toolset implicitly.

```powershell
git -C C:\vcpkg checkout --detach 36677bbd0b3bf11da7376e62e14bffcc54d2eaeb
& C:\vcpkg\bootstrap-vcpkg.bat -disableMetrics
```

Install the static implementation dependencies used inside the retained image ABI:

```powershell
& C:\vcpkg\vcpkg.exe install `
  'opencolorio[core]:x64-windows-static-md' `
  'openimageio[core]:x64-windows-static-md' `
  'openexr[core]:x64-windows-static-md' `
  'imath[core]:x64-windows-static-md' `
  "--x-install-root=$PWD/artifacts/vcpkg-installed" `
  '--overlay-triplets=eng/native/vcpkg/triplets'
```

Then enable Visual Studio/MSBuild once for the current Windows user:

```powershell
[Environment]::SetEnvironmentVariable('VCPKG_ROOT', 'C:\vcpkg', 'User')
& C:\vcpkg\vcpkg.exe integrate install
```

Restart Visual Studio and terminals after changing the user environment. `win.slnx` consumes this user-wide
integration. CMake remains independent of the Visual Studio integration and reads the toolchain from
`$env:VCPKG_ROOT` through `CMakePresets.json`. Configure with `--fresh` once when moving an existing
CMake build from the global installed tree to this isolated tree.

The CMake presets use Ninja, so a Windows CMake build has to run from an MSVC environment. `vcvars64.bat`
overwrites `VCPKG_ROOT` with the vcpkg copy bundled inside Visual Studio, which is not the pinned baseline
this repository locks, so capture the pinned value before calling it and restore it afterwards:

```bat
set "PINNED_VCPKG=%VCPKG_ROOT%"
call "<VS install>\VC\Auxiliary\Build\vcvars64.bat" -vcvars_ver=14.51.36231
set "VCPKG_ROOT=%PINNED_VCPKG%"
```

Other operating systems use the retained image dependency group under the standard triplets named by their local presets.

`win.slnx` builds the owned ABI projects before the managed native ABI test and deploys their complete DLL runtime
app-local for both Debug and Release. The generated test executable therefore runs directly from its output
directory without native-runtime path or build-mode environment variables.

CI builds the Windows CMake presets only. `win.slnx` remains a local IDE entry point;
its full build is an explicit command when relevant, not an automatic pre-push hook.
CTest and native ABI execution are local opt-in diagnostics, never CI gates.

Build and stage the retained profile from the existing configured compiler shell:

```powershell
cmake --preset win-x64-shim-static
cmake --build --preset win-x64-shim-static
cmake --install artifacts/cmake/win-x64/shim-static
python eng/packaging/native.py stage --vcpkg-root C:/vcpkg
```

The final command audits the PE import/export closure, supplies app-local Visual C++ runtime files,
copies licences/SBOMs and matching upstream sources, then seals `artifacts/native-packages` with hashes
and the source commit. It rejects an existing populated output; use a new `--directory` for another
development candidate. Continue with [package production](../eng/packaging/README.md). This stage is
an input to NuGet packing; public upload waits for the reduced build/static/package gate.
Run CTest manually only for a relevant native behavior change. No macOS CI is produced.
