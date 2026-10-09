# Native ABI probes

After staging ArcImageNative app-local, this explicit local opt-in suite exercises the retained image ABI/version/build-info/error calls through LibraryImport. It verifies the ABI foundation, not image decoding, sandbox containment or product acceptance. CI compiles the producer and packages it but does not execute this runtime suite.

The `NativeAbi` category also covers the functional image path (`ImageReaderTests`): PNG and TIFF round trips
generated in test code (`ImageFixtures`, decision D1), coverage and completion, refusals, cancellation and
disposal. It needs `ArcImageNative.dll` and `ArcImageNative.manifest.json` beside the test assembly. The CI
`NativeAbiLayout` filter never runs this category.
