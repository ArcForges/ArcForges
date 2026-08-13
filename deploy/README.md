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
`$env:VCPKG_ROOT` through `CMakePresets.json`. Other operating systems install the same two dependency groups
under the standard triplets named by their presets. The optional macOS shader-tool preset additionally requires
`glslang[tools]` and `spirv-cross` for its host triplet.
