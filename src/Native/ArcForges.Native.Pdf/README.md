# ArcForges.Native.Pdf

Source-generated binding of the `arc_pdf_*` ABI of `ArcPdfNative` (`native/arcpdf-abi`): open a PDF through caller-supplied
read callbacks, read page geometry, extract bounded text with geometry, and render RGBA8 tiles. Every call is bounded by the
document limits and a cancellation token, and every native failure is a `PdfNativeException` with the closed ABI status.
No native pointer or handle value leaves this assembly.

The production `ArcPdfNative` build links the admitted no-V8/no-XFA PDFium chromium/8044 backend. The explicitly selected
parserless fixture build reports `backend=none` and refuses open. The helper validates production build information before
admitting PDF work. This managed project remains nonpackable until the separately reviewed runtime package closure supplies
the native ABI, dependency DLL, legal texts, hashes and producer receipts; no parser downloads occur at consumption time.

Text encoding: `start` and `count` of `arc_pdf_text` are UTF-16 code-unit offsets into the full page text (at most 65536 per
call); a chunk never splits a surrogate pair; box offsets are absolute offsets into the page text, and a chunk carries only the
boxes wholly inside it.

The binding is consumed only by the ContentSandbox helper (`src/DesktopHelpers/ArcForges.ContentSandbox`): PDFium belongs
inside the restricted helper process, never in a product process.
