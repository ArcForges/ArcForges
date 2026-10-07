# ArcForges.Native.Pdf.Runtime.osx-arm64

This container carries the actual source-bound osx-arm64 ArcPdfNative ABI1.1 and pinned PDFium8044 engine. It has no managed implementation assembly. Page metadata, bounded text and tile rendering are exposed only through the restricted ContentSandbox helper and the product Broker facade.

Publication selects only actual verified producer artifacts. Registering this container does not activate an unbuilt RID. Consumers use the exact same-version ArcForges.Native.Pdf binding, the signed canonical manifest and an application-approved publisher key/cohort; a self-declared artifact key never grants trust. The loader verifies and retains the complete closure before loading any entry point, with no current-directory fallback.

The package retains original engine headers, upstream admission/SBOM/legal evidence, owned compiler recipe and CRT redistribution grants when bundled. AGPL-3.0-only applies to the owned implementation. Cross compilation, a valid upstream signature and ordinary component tests do not certify target OS isolation, signed whole-product installation or full acceptance.
