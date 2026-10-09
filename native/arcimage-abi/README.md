# ArcImageNative

C++20 implementation behind the owned C17 ABI. No upstream C++ type, allocator, exception or pointer
ownership crosses the boundary. The library reports ABI 1.1 (functional minor, decision D2) and exports
`arc_image_open`, `arc_image_read` and `arc_image_close` over OpenImageIO 3.1.14.0 with OpenEXR and Imath.

- Formats: PNG, TIFF and EXR, selected by content probing of the first bytes (decision D10). Every other
  content is `ARC_UNSUPPORTED`. Opening never resolves a path: all bytes come from the caller's `arc_io_v1`
  `read_at` callback through an OpenImageIO `IOProxy` adapter.
- Bounds: dimensions, pixel count, channel count, tile memory and scanline memory are checked before any
  decode allocation. Region output is capped at 64 MiB, and at most 64 handles are open per library.
- Coverage: a handle accepts regions only in raster order without overlap (decision D3). A refused region
  changes no state.
- Conversion: `rgba8` (straight alpha, no transfer change), `rgba32fLinearPremultiplied` (sRGB to linear
  only when OpenImageIO reports sRGB, premultiply only for unassociated alpha) and `float32Interleaved`
  (source channels kept). Every lossy step is listed in the metadata `loss` array (decision D4).
- Cancellation and the per-call timeout are observed at callback and tile boundaries. An in-flight codec
  call is not interruptible.
- Build information is a closed JSON object that lists the capabilities and formats and embeds the build
  identity.
- Metadata is a closed JSON document (`arc.image.metadata.v1`) returned by `arc_image_open`.

Probe, build and error exports keep their shipped signatures. The shim's own tests are
`arcslate_image_abi_tests` (probe) and `arcslate_image_codec_tests` (functional). The codec tests generate
their fixtures in memory and ship none (decision D1). Production containment of untrusted decode is the
WP11 helper (NAT.31), not this library.
