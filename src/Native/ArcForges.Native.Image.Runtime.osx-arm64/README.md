# ArcForges.Native.Image.Runtime.osx-arm64

This runtime project implements the osx-arm64 production packaging contract for the six callable Image ABI1.1 exports. Its immutable producer recipe is in `eng/native/image-runtime-producers.v1.json`.

The project is non-packable by default. Actual clean source-bound binaries, the complete dependency/compiler-runtime/legal/source closure, headers and an independently verified `image-production-input.json` are required before package admission. A recipe or structural test fixture never activates publication. The packer supplies `ArcForgesVerifiedImageRuntime=true` only for an admitted verified artifact.

No osx-arm64 Image publication or operating-system acceptance is asserted by this project. Unsupported host, missing input, wrong architecture, malformed ABI, escaped dependency/search path and integrity failures refuse staging. macOS has no hosted CI; real runtime/consumer and isolation evidence remains separately recorded.

Owned source: AGPL-3.0-only. Original dependency notices and selected source/recipe material accompany actual produced packages.
