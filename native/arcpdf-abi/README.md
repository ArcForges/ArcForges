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
  a chunk carries only the boxes wholly inside it. A box that would straddle the chunk end moves whole into the next chunk (the
  chunk ends where the box starts); only a box that already straddles the requested start (the caller started inside it) is not
  carried. At most `max_items` boxes per chunk. Lone surrogates are replaced by U+FFFD in the UTF-8 output.
- `arc_pdf_render`: the page record must equal the geometry the document reports; the tile lies inside the full pixel grid; the
  required size is `(height - 1) * stride + width * 4`; grids above 268435456 pixels or tiles above 64 MiB are refused.
- `arc_pdf_open`: the `arc_io_v1` callbacks and context must stay valid until `arc_pdf_close`. A password that is required but
  missing or wrong is `ARC_PERMISSION_DENIED`.
- `arc_io_v1.read_at`: the engine clamps every request to the input length and treats any short read (including a zero-length
  OK read) as `ARC_IO`: a short read is allowed only if the callback reports the end of the input, which the clamped window
  already excludes.

## Obligations this library leaves to the real backend (NAT.15)

- A real backend must read the input in a loop with a progress guard and must call `call_context::check()` regularly. Deadlines
  and cancellation are cooperative here: a backend that never checks is bounded only by the helper's own deadline and the
  operating-system containment, and `arc_pdf_close` blocks until a running call returns.
- A box that spans more than a whole chunk window, or that begins before a caller-chosen start, is not carried by any chunk.
- Scripts and actions must be disabled in the real library, fonts must not be read from the file system inside the sandbox, and
  the real library must be proven under hostile PDFs (malformed, crashing, hanging) inside the real containment.

## Sanitizer check

The engine test passes unmodified under MSVC AddressSanitizer (`/fsanitize=address`, debug). A first ASan run showed six
failures that were a test defect, not an engine defect: the concurrent-close test legitimately saw `ARC_CLOSED` between the size
query and the fetch of `arc_pdf_text` when ASan slowed the worker threads, and the helper then checked the response size on a
failed call. The test helper now checks it only on success. No ASan or UBSan job is wired into CI (a hosted sanitizer job is a
follow-up).
