# ArcForges.Native.Pdf

Source-generated binding of the `arc_pdf_*` ABI of `ArcPdfNative` (`native/arcpdf-abi`): open a PDF through caller-supplied
read callbacks, read page geometry, extract bounded text with geometry, and render RGBA8 tiles. Every call is bounded by the
document limits and a cancellation token, and every native failure is a `PdfNativeException` with the closed ABI status.
No native pointer or handle value leaves this assembly.

**Not packable and not a capability yet.** `native/arcpdf-abi` links no PDF parser in this delivery: a library built from it
reports `backend=none` in its build information and refuses every open with `NativeStatus.Unsupported`. The real PDFium
backend, the `Runtime.<rid>` packages and the package entry are separate, later work. Do not publish this project as a package
before that.

Text encoding: `start` and `count` of `arc_pdf_text` are UTF-16 code-unit offsets into the full page text (at most 65536 per
call); a chunk never splits a surrogate pair; box offsets are absolute offsets into the page text, and a chunk carries only the
boxes wholly inside it.

The binding is consumed only by the ContentSandbox helper (`src/DesktopHelpers/ArcForges.ContentSandbox`): PDFium belongs
inside the restricted helper process, never in a product process.
