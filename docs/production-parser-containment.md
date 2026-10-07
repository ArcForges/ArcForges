# Production parser containment

PLT.54 uses the existing ContentSandbox Native AOT host, generated Sandbox/Platform controls,
production Image/Pdf factories and OS launcher. PNG, TIFF and EXR fixtures are authored small
binary images. No decoder, protocol or full-trust fallback is introduced by the harness.

The ordinary harness tests exercise bounded operator configuration, immutable approved-key/pin
composition, duplicate/foreign/missing authority refusal and finite fixture snapshots. These are
component checks. They launch no process and establish no operating-system containment.

The local Image scenarios launch separate real children, open actual codecs, check dimensions,
exact red RGBA pixels and copied-byte SHA-256, reject out-of-bounds and unknown/closed handles,
refuse truncated format headers and dimension budgets, recover in a new invocation, cancel an
active invocation and recover after parent-induced abrupt child loss. Parent-induced process loss
is not evidence of a particular malicious input crashing the native codec. Existing PDF page,
text, tile, malformed recovery and parent-death checks remain maintained; prior PDF observations
must not be relabelled as evidence for a newly composed source or signed closure.

`ARCFORGES_CONTENTSANDBOX_OS=1` and `ARCFORGES_CONTENTSANDBOX_PRODUCTION` select the explicitly
local unsigned-component Image scenarios. Their existing friend-only fixture option allows an
owned local Native AOT composition to be tested. This mode is never product release trust and
never closes PG-12/PG-22 or an authenticated installed-helper acceptance gate.

`ARCFORGES_CONTENTSANDBOX_NATIVE_HOSTILE=1`, alongside the existing OS/Fixture opt-ins, reuses
all maintained hostile OS scenarios with the separate fixture's production-loading profile.
The fixture must preload both actual admitted Image/Pdf libraries through the production
preparer before OS restrictions; unavailable or invalid bytes refuse launch. Its parser bodies
remain the existing first-party attacks for files, secrets, network, processes, native fault,
hang, memory exhaustion, cancellation, private-storage cleanup and parent death. The parent-death
entry point selects the same profile. This is actual OS boundary evidence with those libraries
loaded, never evidence that a genuine format exploit triggered the first-party scripted attack
or that the nonpackable fixture is an authenticated installed production helper. The default
hostile fixture mode is preserved, and real-codec checks use the production helper separately.

`ARCFORGES_CONTENTSANDBOX_RELEASE_CONFIG` selects a separate operator/application-owned JSON
configuration for `AuthenticatedProductionContainmentTests`. The harness accepts at most 8192
bytes, exact fields with no duplicates, canonical absolute locators, an exact helper SHA-256,
one through four externally approved P-256 publisher SPKI keys, and exactly one Image and one
Pdf identity. It supplies the actual `ContentSandboxReleaseTrust` to the normal launcher without
setting `LocalUnsignedFixture`. The helper and libraries must pass the existing held-file,
signature, source/version/RID and OS restrictions; a missing or invalid release cannot become
a successful local fixture. Keys in downloaded package/profile material are never an authority.

The configuration has schemaVersion 1 and fields `helperPath`, `helperSha256`, `nativeDirectory`,
`runtimeRoot`, `rid`, `packageVersion`, `sourceCommit`, `approvedPublisherKeys` (each exact
`keyId`/base64 `spki`) and `libraries` (each exact `library`/`profileSha256`/`manifestSha256`).
The harness emits bounded scenario evidence naming the selected source/version/RID/helper digest,
actual parent/child PID and OS build only after the actual operation passes. It emits no approval
private key, input payload or file locator. The JSON configuration format is a test/operator input,
not a second product wire contract or helper manifest owner.

These runtime entry points are local opt-ins only. Hosted CI compiles them and runs their ordinary
components; it must never execute native consumers or OS isolation. Available real installed
cohorts are exercised once per affected change, with raw output retained under ignored artifacts.

Remaining acceptance owners are explicit: NAT.25 supplies the authenticated paired Image/Pdf and
signed helper bundle; PLT.54 records actual per-RID denied file/secret/network/process/descriptor
access, native-crash/hang/resource/overflow, parent-death and cleanup observations with both real
libraries loaded; PLT.46 and release tasks own combined installed-product acceptance. An unbuilt
or unsupported RID remains refused. No structural fixture, mocked boundary or earlier-source
run removes a deferred check. This document is an implementation record, not a passing receipt.
