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
- `src/backend_pdfium.cpp`: the real no-V8/no-XFA chromium/8044 backend. It owns its input buffer for the full PDFium document
  lifetime, disables system-font access, serialises all PDFium calls across documents, extracts Unicode and character geometry,
  and renders cancellable progressive RGBA8 tiles. It never creates a form environment or dispatches document actions.
- `src/backend_none.cpp`: the explicitly selected parserless ABI fixture configuration. It refuses open with `ARC_UNSUPPORTED`.
  Production builds select `ARCFORGES_PDFIUM=ON` and the verified producer prefix; no dependency is downloaded by a consumer.
- `tests/`: `arcpdf_abi_engine_tests` compiles the engine with a scripted fake backend (`tests/fake_pdf_backend.hpp`, TEST ONLY,
  never part of the library target) and drives it with hostile behaviour; `arcpdf_abi_unsupported_tests` links the real library
  target in the parserless fixture configuration. `arcpdf_abi_pdfium_tests` instead links the real production library and tests
  first-party PDF page/text/pixels, malformed input, cancellation and concurrent documents. Real parser execution is local
  opt-in only; the hosted workflow compiles the production library and runs the isolated engine tests.

## Reproducible producer

`python eng/native_provenance.py --acquire-pdfium artifacts/pdfium` verifies the admitted archive and its Sigstore/SLSA
attestation before exposing `artifacts/pdfium/pdfium`. The immutable profile in `eng/native/vcpkg/pdfium-build.v1.json` pins
every archive member and all legal texts. The attestation binds the upstream build recipe and invocation; it does not attest
the separately observed PDFium source commit. Configure with `ARCFORGES_PDFIUM=ON` and `PDFium_DIR` set to that prefix.
`Runtime.<rid>` publication is a separately admitted producer closure; this library alone is not a distributable package.

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

## Containment and acceptance limits

- The backend checks every input chunk, text character and rendered row and every progressive rendering callback. PDFium
  opening and individual third-party operations cannot be interrupted mid-call; the helper deadline and OS containment bound
  those operations. `arc_pdf_close` drains running calls and borrowed caller callbacks before returning.
- A box that spans more than a whole chunk window, or that begins before a caller-chosen start, is not carried by any chunk.
- Local `RealPdfIsolationTests` exercises the production Native AOT helper with real PDFium in Windows AppContainer/Job
  containment. Broad hostile-corpus crash/hang acceptance, Linux OS observations and whole-product acceptance remain distinct
  from the component implementation and require their own recorded evidence.

## Sanitizer check

The engine test passes unmodified under MSVC AddressSanitizer (`/fsanitize=address`, debug). A first ASan run showed six
failures that were a test defect, not an engine defect: the concurrent-close test legitimately saw `ARC_CLOSED` between the size
query and the fetch of `arc_pdf_text` when ASan slowed the worker threads, and the helper then checked the response size on a
failed call. The test helper now checks it only on success. No ASan or UBSan job is wired into CI (a hosted sanitizer job is a
follow-up).
