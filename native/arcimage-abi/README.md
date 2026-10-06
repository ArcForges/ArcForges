# ArcImageNative

Hello-world C++20 implementation behind an owned C17 ABI. No upstream C++ type, allocator, exception, or
pointer ownership crosses this boundary. Capability implementation and per-RID package admission replace the hello exports with real adapters.

## Functional still-image reader (NAT.11)

ABI 1.1 adds arc_image_open/read/close while retaining the shipped preamble signatures
and its existing library identity. Only built-in PNG/TIFF/OpenEXR readers are selected by
signature; no caller path or plugin search is accepted. Callback input, item counts,
dimensions, metadata, channels, scratch and output are bounded before caller-visible
output. Failures leak no handle or partial pixel buffer. Buffer sizing is repeatable.
Generation checked handles are capped to 64, single caller; close drains active leases.
Cancellation/deadline checks do not claim to interrupt every upstream codec instruction.
Hostile reads run in the supervised restricted helper.

The local opt-in arcslate_image_codec_tests target exercises actual OIIO PNG/TIFF/EXR 16-bit
inputs, unaligned edge tiles, RGBA32F, metadata, malformed content, dimensions, failed
or short I/O, cancellation, insufficient buffers, 64 handles, stale/double close and
borrowed-call draining. It is compiled by the existing native build, outside CTest/CI
runtime execution. Run affected diagnostics through the workstation build slot after
building in an admitted environment. These tests prove codec behavior, not OS isolation,
other RID packages or whole-series acceptance.
