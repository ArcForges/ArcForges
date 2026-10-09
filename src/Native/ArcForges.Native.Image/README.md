# ArcForges.Native.Image

Source-generated bindings for the ABI preamble (version, dependency build information and thread-local error
queries) and for the functional still-image exports `arc_image_open`, `arc_image_read` and `arc_image_close`
(ABI 1.1, decision D2). The image path reads PNG, TIFF and EXR after content probing (decision D10); every
other content is refused as `NativeStatus.Unsupported`. No timeline, video or product image-editing API is claimed.

Public surface, all in namespace `ArcForges.Native.Image`:

- `ImageReader.OpenAsync(ImageByteSource, ImageOpenOptions?, CancellationToken)` opens one level and parses the
  immutable `ImageMetadata`. `ImageReader.ProbeAsync` returns the metadata and closes again.
- `ImageReader.ReadRegionAsync(ImageRegion, CancellationToken)` returns an `ImagePixelRegion` with packed pixels.
  Regions must be disjoint and arrive in raster order (decision D3).
- `ImageReader.CompleteAsync(CancellationToken)` returns `ImageCompletion` only when every pixel was covered, and
  otherwise throws `ImageCoverageIncompleteException`.
- `ImageReader` implements `IAsyncDisposable`. Disposal cancels an in-flight read at its next boundary and then
  closes the native handle.
- `ImageByteSource` is the caller's byte source. `ImageByteSource.FromStream` wraps a seekable stream.
- Failures are `ImageNativeException` with the `NativeStatus` from the ABI.

Native handles are owned by a dedicated `SafeHandle`, and no pointer or raw options dictionary is exposed.
Callbacks never throw across the ABI. The binding is AOT and trim compatible (`IsAotCompatible`).

Pin the exact package version centrally and commit package locks. Also reference `ArcForges.Native.Image.Runtime.win-x64` at the same exact version and build/publish for `win-x64`. Call `ImageAbi.GetAbiVersion()`, `GetBuildInfo()` or `GetLastError()` in namespace `ArcForges.Native.Image`.
The runtime package supplies app-local DLLs and a hash manifest. Loading never searches PATH or the current working directory. Final product installation owns signing, read-only application paths and any later hostile-content sandbox. This binding decodes image bytes in-process and provides no sandbox: hostile input is contained only inside the WP11 helper (NAT.31), not here.
