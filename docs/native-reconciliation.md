# Native family reconciliation

P2-019/P2-020 and GOV.17 retire the native families consumed only by products outside the retained ArcScope system. Historical WP01.03 evidence remains in Git history and immutable provenance records; it does not authorize current publication of removed families.

| Surface | Current disposition |
|---|---|
| Media, Colour, Otio wrappers and runtime projects | Removed from source, solutions and package allowlist; existing published versions remain immutable. |
| macOS Metal graphics probe | Removed; no graphics capability or macOS artifact is claimed. |
| Still-image shim | Moved to `native/arcimage-abi`; logical library `ArcImageNative`; the published `arc_image_*` exports, POD layouts and ABI 1.0 are unchanged. |
| Native.Abstractions and Native.Image | Retained managed packages; Image consumes the neutral native library. |
| Independent ABI oracle | Retains image version/build/error/layout/null checks in `tests/NativeAbiTests/Oracle`; explicit local opt-in only. |
| NativeInterop and ContentSandbox scaffolds | Not published capabilities; no hostile-input isolation acceptance implied. |

The retained image dependency closure still includes OpenColorIO through OpenImageIO. Removing the owned Colour wrapper does not permit stripping dependencies or notices required by Image. New profile/record revisions bind only retained artifacts; original provenance and published versions remain unchanged.

Packaging guards reject tampered or missing Image/CRT DLLs, wrong RID, altered headers, incorrect package pairs and missing upstream notices. No native functionality beyond existing metadata/error probes is introduced. Instruments, functional image previews and sandbox composition remain their named delivery tasks; the PDF engine and local PDF parsing are retired by NAT.32 under P2-022 (recorded as retired, not completed).
