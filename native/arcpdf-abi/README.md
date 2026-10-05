# ArcPdfNative

The owned `arc_pdf_*` C17 ABI (annex 06) for bounded PDF page geometry, text with geometry and RGBA8 tile rendering. It is
loaded only inside the ContentSandbox helper process (`src/DesktopHelpers/ArcForges.ContentSandbox`); a product process never
parses PDF bytes.

## What is here

- `src/pdf_engine.cpp`: the whole exported surface. It validates every argument and every value a backend returns, applies the
  signed hard limits (input, memory, output, dimensions, items, deadline), serialises each document (PDFium is not thread
  safe), keeps opaque generation handles (at most 64 open), honours cancellation and the call deadline, encodes text as the
  closed JSON of annex 06 and never leaves partial pixels in a caller buffer after a failure.
- `src/pdf_backend.hpp`: the seam to whatever parses PDF bytes (`backend`, `document`, `byte_source`). Scripts and actions are
  disabled by contract. A backend is never trusted: it may throw, hang, return non-finite geometry or boxes outside the text
  and the engine fails the call closed.
- `src/backend_none.cpp`: **the only backend this build links is none.** `arc_pdf_open` returns `ARC_UNSUPPORTED`, outputs stay
  zero, and `arc_pdf_get_build_info` reports `backend=none`. There is no fallback parser. The PDFium (chromium/8044) binding,
  its source/licence admission and the `Runtime.<rid>` packages are separate, later work; nothing here downloads, builds or
  vendors PDFium, and the library is not an admitted package.
- `tests/`: `arcpdf_abi_engine_tests` compiles the engine with a scripted fake backend (`tests/fake_pdf_backend.hpp`, TEST ONLY,
  never part of the library target) and drives it with hostile behaviour; `arcpdf_abi_unsupported_tests` links the real library
  target and checks the fail-closed configuration. Both are CTest targets run by `native-abi.yml`. They prove the engine, not
  PDFium.

## Semantics fixed by this library

- `arc_pdf_text`: `start` and `count` are UTF-16 code-unit offsets into the full page text, at most 65536 units per call. A
  chunk never splits a surrogate pair; a start inside a pair is refused. Box offsets are absolute offsets into the page text and
  a chunk carries only the boxes wholly inside it (a box that crosses a chunk end is carried by neither chunk), at most
  `max_items` per chunk. Lone surrogates are replaced by U+FFFD in the UTF-8 output.
- `arc_pdf_render`: the page record must equal the geometry the document reports; the tile lies inside the full pixel grid; the
  required size is `(height - 1) * stride + width * 4`; grids above 268435456 pixels or tiles above 64 MiB are refused.
- `arc_pdf_open`: the `arc_io_v1` callbacks and context must stay valid until `arc_pdf_close`. A password that is required but
  missing or wrong is `ARC_PERMISSION_DENIED`.
