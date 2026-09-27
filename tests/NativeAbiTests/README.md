# Native ABI probes

After staging ArcImageNative app-local, this explicit local opt-in suite exercises the retained image ABI/version/build-info/error calls through LibraryImport. It verifies the ABI foundation, not image decoding, sandbox containment or product acceptance. CI compiles the producer and packages it but does not execute this runtime suite.
