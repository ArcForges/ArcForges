# ArcForges.Native.Image.Runtime.win-x64

Actual Windows x64 `ArcImageNative.dll`, its non-system DLL dependencies, public C headers and import
library. Pair with `ArcForges.Native.Image` at the same exact version and set `RuntimeIdentifier` to `win-x64`.
Native assets deploy through `runtimes/win-x64/native`; ordinary consumer builds never invoke CMake or
vcpkg. The existing ABI consists only of version, build-information and error queries.

`native-manifest.json` records source commit, RID, exports/imports and DLL hashes. `sbom.json`,
`licenses/`, `recipes/` and source records describe the actual dependency closure, including static
inputs. Redistributed Visual C++ runtime files are app-local; Windows API sets remain system inputs.
Final application signing, installation permissions and future content-parser isolation belong to the
product deployment. The package does not implement hostile-content parsing or claim those product gates.
