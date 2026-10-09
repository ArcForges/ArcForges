# ArcImageNative

C++20 implementation behind the owned C17 ABI. No upstream C++ type, allocator, exception or pointer
ownership crosses the boundary. The library reports ABI 1.1 (functional minor, decision D2) and exports
`arc_image_open`, `arc_image_read` and `arc_image_close` over OpenImageIO 3.1.14.0 with OpenEXR and Imath.

- Formats: PNG, TIFF and EXR, selected by content probing of the first bytes (decision D10). Every other
  content is `ARC_UNSUPPORTED`. Opening never resolves a path: all bytes come from the caller's `arc_io_v1`
  `read_at` callback through an OpenImageIO `IOProxy` adapter.
- Bounds: dimensions, pixel count, channel count, tile memory and scanline memory are checked before any
  decode allocation. Region output is capped at 64 MiB, and at most 64 handles are open per library.
- Size authority: the shim's own bounds decide image size, not the host. OpenImageIO refuses a header whose
  uncompressed size exceeds its process global `limits:imagesize_MB`, whose default is min(32 GiB, physical
  memory). The shim pins that global once, before the first OpenImageIO open (`image_session.cpp`,
  `pin_openimageio_size_limit`), to 131072 MiB (128 GiB). That value is `hard_max_pixels` (2^28) x
  `max_channels` (64) x 8 bytes (double, the widest sample type), the largest uncompressed image the hard
  profile admits. OpenImageIO therefore never refuses an image the shim admits, and the shim's RESOURCE_LIMIT
  answers everything it bounds. Before the pin, a 65535 x 65535 RGBA8 header (about 16 GiB) was refused by
  the shim on a host with large physical memory, but by OpenImageIO at open on a smaller host, so the status
  depended on memory. A header larger than 128 GiB by OpenImageIO's count, such as 65535 x 65535 with 64
  double channels, still gets OpenImageIO's CORRUPT answer rather than the shim's RESOURCE_LIMIT.
  `limits:channels` keeps OpenImageIO's default of 1024. That constant is above the shim's 64-channel bound,
  so it never refuses a count the shim admits, and it does not depend on the host, so it is not pinned.
  The shim links OpenImageIO statically (`x64-windows-static-md`), so the global is private to
  ArcImageNative. The codec test executable has its own OpenImageIO copy and cannot read that global, so
  `arcslate_image_abi.codec.oiio_size_pin` checks the pin through `arc_image_open` instead: a 16384 x 16384
  header of 64 double channels (128 GiB) must open on every host.
- Coverage: a handle accepts regions only in raster order without overlap (decision D3). A refused region
  changes no state.
- Conversion: `rgba8` (straight alpha, no transfer change), `rgba32fLinearPremultiplied` (sRGB to linear
  only when OpenImageIO reports sRGB, premultiply only for unassociated alpha) and `float32Interleaved`
  (source channels kept). Every lossy step is listed in the metadata `loss` array (decision D4).
- Straight alpha: the PNG and TIFF readers are opened with the callback proxy as the `oiio:ioproxy`
  pointer attribute and `oiio:UnassociatedAlpha` = 1 in the open configuration (OpenImageIO 3.1.14.0,
  `ImageInput::open` with an `ImageSpec` config). The readers then return straight alpha, so `rgba8`
  output is byte exact. Without the request OpenImageIO premultiplies straight alpha as it reads, and
  8-bit output is inexact. The request is honoured for both formats, so no direct libpng or libtiff decode
  is used. An associated source (EXR, or a TIFF whose file marks its alpha associated) is unpremultiplied
  only where straight colour is needed. The TIFF reader reports the association only when the alpha is
  unassociated, so its association is read from that attribute.
- Cancellation and the per-call timeout are observed at callback and tile boundaries. An in-flight codec
  call is not interruptible.
- Build information is a closed JSON object that lists the capabilities and formats and embeds the build
  identity.
- Metadata is a closed JSON document (`arc.image.metadata.v1`) returned by `arc_image_open`.

Probe, build and error exports keep their shipped signatures. The shim's own tests are the CTest target
`arcslate_image_abi.hello` (probe, `arcslate_image_abi_tests`) and one CTest target per functional case,
`arcslate_image_abi.codec.<name>` (`arcslate_image_codec_tests`, 34 cases, 374 checks on win-x64). The
codec tests generate their fixtures in test code and ship none (decision D1). Production containment of
untrusted decode is the WP11 helper (NAT.31), not this library.

Codec test coverage:

- Bit depth and metadata: PNG 8 and 16 bit, TIFF 8, 16 and float, EXR half and float round trips. rgba8
  clamps to [0, 1] and rounds to nearest, and every conversion or loss is reported in the metadata.
- Edges: partial tiles, one-pixel reads, and a region that crosses a tile boundary into a one-pixel edge tile.
  Each pixel is covered once in raster order.
- Limits: pixel-count and tile or scanline memory limits are refused before decode. A read whose row band
  exceeds the memory limit is refused before any row decodes. A read that passes its deadline between tiles is
  RESOURCE_LIMIT. A 65535 x 65535 PNG header is refused from the header alone (`limits_bomb`). A 128 GiB header
  at the admitted maximum opens, which shows the OpenImageIO size pin is in effect (`oiio_size_pin`).
- Corrupt input: truncated, bad-header-CRC and damaged-pixel PNG, truncated TIFF and EXR, and an invalid EXR
  version are CORRUPT. Each writes no pixels.
- Failed codec: a callback failure during decode is IO, writes no pixels and consumes no coverage.
- Cancellation (decision D9): a read cancelled at each of its cancellation boundaries (every tile and every
  source callback) is CANCELLED, writes no pixels and consumes no coverage.
- Coverage (decision D3): overlapping, out-of-raster-order, empty and out-of-bounds regions are refused and
  leave the cursor unchanged.
- Buffers: a buffer one byte short reports the exact required size and is not written.
- Formats (decision D10): GIF, WebP, JPEG 2000 and empty input are UNSUPPORTED. Content decides the codec,
  never the name.
- Subimages: EXR multipart and mip levels are read within the item limit. OpenImageIO's EXR writer accepts
  multipart parts only when they share one size, so the multipart fixture uses equal-sized parts. Multipart
  fixtures are written through a temporary file because the EXR writer does not append subimages through an
  IOProxy. Mip fixtures come from OpenImageIO's texture writer, and each level is checked against OpenImageIO's
  own reader. The shim only ever sees bytes through the callback.

Not run: linux-x64 (decision D8). The WSL cmake and ninja install is not present, so the Linux CTest targets
are recorded as not run.

Local win-x64 validation (NAT.11 unit 5; decision D12). The clean shim-static build used the CI sequence on
Visual Studio 2026 Community (MSVC 19.51.36257, toolset 14.51.36231) with the vcpkg commit 36677bbd and the four
pinned packages installed under the worktree artifacts root:

- CTest with the CI filter: 37 of 37 pass (NAT.11 unit 6, after the OpenImageIO size pin). The codec test
  executable reports 374 checks with no failures. A mutation check that lowers the pin to the 32 GiB default
  fails `oiio_size_pin` (2 of 3 checks), which shows the test depends on the pin.
- `dotnet restore DesktopPlatform.slnx --locked-mode`, NativeAbiLayout 3 of 3, NativeAbi functional 16 of 16, and
  a zero-warning build of ArcForges.Native.Abstractions, ArcForges.Native.Image, the Image runtime project and the
  NativeAbi test project. `dotnet format DesktopPlatform.slnx --verify-no-changes` passes.
- The functional managed tests load a manifest-checked `ArcImageNative.dll` beside the test assembly. Locally that
  pair is the cmake install output with a manifest written from the same bytes. It is a test prerequisite, not
  staged provenance.
- Toolchain drift from the CI owned build: the local CMake is 4.4.3 (owned 4.3.3; vcpkg uses 4.4.0) and the local
  Ninja is 1.13.2 (owned 1.13.1). `eng/packaging/native.py stage` refuses the owned generator with "Unreviewed owned
  CMake build generator", so the staged packages, the managed Runtime pack and the package-guard tests are not run
  locally (13 of 25 package-guard tests error on the missing `artifacts/packages` tree). The hosted native workflow
  is the authority for them. The other 12 package tests and the dependency-policy, desktop-RID, licence-boundary and
  provenance checks pass locally.
- Two clean builds of the same commit gave different `ArcImageNative.dll` hashes. The cause was not investigated.
- linux-x64 is still not run (decision D8).
