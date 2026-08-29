# Deployment

Aspire development topology, containers, Azure, static Web, self-host, promotion, and rollback definitions are
owned here. Production deployment content arrives only with its tested release step.

## Native dependency toolchain

ArcForges uses a normal vcpkg installation. It does not use repository manifests, custom triplets, or
repository-local installed trees. The reviewed Windows toolchain is `C:\vcpkg` at commit
`9e593bb18ea69cc5095e012465dcd675a822ed0d`.

```powershell
git -C C:\vcpkg checkout --detach 9e593bb18ea69cc5095e012465dcd675a822ed0d
& C:\vcpkg\bootstrap-vcpkg.bat -disableMetrics
```

Install the shared runtime dependencies:

```powershell
& C:\vcpkg\vcpkg.exe install `
  'ffmpeg[core,avcodec,avfilter,avformat,swresample,swscale,vulkan,qsv,nvcodec,amf]:x64-windows' `
  'libusb[core]:x64-windows' `
  'miniaudio[core]:x64-windows'
```

Install the static implementation dependencies used inside the owned ABI shims:

```powershell
& C:\vcpkg\vcpkg.exe install `
  'opentimelineio[core]:x64-windows-static-md' `
  'opencolorio[core]:x64-windows-static-md' `
  'openimageio[core]:x64-windows-static-md' `
  'openexr[core]:x64-windows-static-md' `
  'imath[core]:x64-windows-static-md' `
  'mdflib[core]:x64-windows-static-md' `
  '--overlay-ports=eng/native/vcpkg/ports'
```

Then enable Visual Studio/MSBuild once for the current Windows user:

```powershell
[Environment]::SetEnvironmentVariable('VCPKG_ROOT', 'C:\vcpkg', 'User')
& C:\vcpkg\vcpkg.exe integrate install
```

Restart Visual Studio and terminals after changing the user environment. `win.slnx` consumes this user-wide
integration. CMake remains independent of the Visual Studio integration and reads the toolchain from
`$env:VCPKG_ROOT` through `CMakePresets.json`.

The CMake presets use Ninja, so a Windows CMake build has to run from an MSVC environment. `vcvars64.bat`
overwrites `VCPKG_ROOT` with the vcpkg copy bundled inside Visual Studio, which is not the pinned baseline
this repository locks, so capture the pinned value before calling it and restore it afterwards:

```bat
set "PINNED_VCPKG=%VCPKG_ROOT%"
call "<VS install>\VC\Auxiliary\Build\vcvars64.bat"
set "VCPKG_ROOT=%PINNED_VCPKG%"
```

Other operating systems install the same two dependency groups
under the standard triplets named by their presets. The optional macOS shader-tool preset additionally requires
`glslang[tools]` and `spirv-cross` for its host triplet.

`win.slnx` builds the owned ABI projects before the managed native ABI test and deploys their complete DLL runtime
app-local for both Debug and Release. The generated test executable therefore runs directly from its output
directory without native-runtime path or build-mode environment variables.

CI never builds `win.slnx`; the hosted Windows job builds the CMake presets only. The Windows-only
`win-slnx-release-x64` `pre-push` hook in [.pre-commit-config.yaml](../.pre-commit-config.yaml) builds it as
`Release|x64` locally, which is what keeps the two Windows entry points from drifting apart. It locates
MSBuild through `vswhere` and skips itself on non-Windows hosts, so the Ubuntu repository-hooks job is
unaffected.
